package state

import (
	"errors"
	"fmt"
	"log"
	"sync"

	"github.com/cpu/vitrum/internal/witness"
)

// ErrHalted is returned by Put after the store has refused to advance, due to
// rollback or tamper evidence detected at boot or a commit that failed after
// it may have touched the medium. It never clears without an operator (a
// fresh boot with consistent storage).
var ErrHalted = errors.New("state store halted: rollback or tamper detected")

// RollbackStore is a witness.Store whose persisted state cannot be rolled
// back across boots.
//
// Each committed generation is written as an encrypted+authenticated blob to
// the microSD A/B slots. Its generation and digest are anchored in hardware-
// monotonic storage (eMMC RPMB). See ROLLBACK.md.
type RollbackStore struct {
	mu     sync.Mutex
	mem    *witness.MemStore
	dev    BlockDevice
	off    int64
	key    []byte
	anchor Anchor
	gen    uint32
	halted bool
}

// Open loads and validates persisted state, returning a ready RollbackStore.
//
// It performs the boot decision: normal start, benign off-by-one recovery, or
// halt on rollback/tamper. A halted store answers Get/All with whatever it
// could load but refuses every Put; callers should additionally refuse to
// serve (see Halted).
func Open(dev BlockDevice, offset int64, key []byte, anchor Anchor) (*RollbackStore, error) {
	s := &RollbackStore{
		mem:    witness.NewMemStore(),
		dev:    dev,
		off:    offset,
		key:    key,
		anchor: anchor,
	}

	anchored, err := anchor.Anchor()
	if err != nil {
		return nil, fmt.Errorf("state: reading anchor: %w", err)
	}

	blob, loadErr := load(dev, offset, key)
	haveBlob := loadErr == nil

	switch {
	case !haveBlob && anchored.Generation == 0 && !anchored.Bound:
		// Fresh unit: no committed generation, no state. Start empty.
		log.Printf("state: fresh start (anchor 0, no blob)")
		s.gen = 0

	case !haveBlob:
		// The anchor records a committed generation we cannot produce:
		// storage was erased or corrupted. Treat as tamper.
		s.halt("anchor at generation %d but no valid state blob (load: %v)", anchored.Generation, loadErr)
		return s, nil

	case blob.gen == anchored.Generation:
		// Normal: blob matches the anchor.
		if anchored.Bound && blob.hash != anchored.BlobHash {
			s.halt("state blob at generation %d does not match anchored digest", blob.gen)
			return s, nil
		}
		s.gen = blob.gen
		if err := s.admit(blob.states); err != nil {
			s.halt("invalid persisted state: %v", err)
			return s, nil
		}
		if !anchored.Bound {
			log.Printf("state: binding legacy anchor at generation %d", blob.gen)
			if err := anchor.SetAnchor(anchorFor(blob)); err != nil {
				s.halt("binding legacy anchor at generation %d failed: %v", blob.gen, err)
				return s, nil
			}
		}

	case anchored.Generation != ^uint32(0) && blob.gen == anchored.Generation+1:
		// Benign off-by-one: crash after the blob write, before the
		// anchor advanced. No cosignature for this generation escaped
		// (it is released only after anchoring). Re-anchor and adopt it.
		s.gen = blob.gen
		if err := s.admit(blob.states); err != nil {
			s.halt("invalid persisted state: %v", err)
			return s, nil
		}
		log.Printf("state: recovering interrupted commit (blob %d, anchor %d)", blob.gen, anchored.Generation)
		if err := anchor.SetAnchor(anchorFor(blob)); err != nil {
			s.halt("re-anchoring generation %d failed: %v", blob.gen, err)
			return s, nil
		}

	case anchored.Generation != ^uint32(0) && blob.gen > anchored.Generation+1:
		// More than one un-anchored generation cannot occur in a normal
		// sequence: tamper.
		s.halt("state generation %d more than one ahead of anchor %d", blob.gen, anchored.Generation)
		return s, nil

	default: // blob.gen < anchored.Generation
		// Storage was rolled back to an older generation.
		s.halt("rollback: state generation %d behind anchor %d", blob.gen, anchored.Generation)
		return s, nil
	}

	if blob.legacy {
		if err := s.upgradeLegacyBlob(blob.states); err != nil {
			s.halt("upgrading legacy state blob failed: %v", err)
			return s, nil
		}
	}

	return s, nil
}

func anchorFor(blob loadedBlob) AnchorState {
	return AnchorState{
		Generation: blob.gen,
		BlobHash:   blob.hash,
		Bound:      true,
	}
}

// upgradeLegacyBlob commits the admitted state as VITRUMW2 before serving.
// This makes older signed firmware fail closed: it sees only the preceding
// VITRUMW1 generation, behind the RPMB anchor.
func (s *RollbackStore) upgradeLegacyBlob(states map[string][]byte) error {
	if s.gen == ^uint32(0) {
		return fmt.Errorf("generation counter exhausted")
	}

	next := s.gen + 1
	log.Printf("state: upgrading legacy blob at generation %d to generation %d", s.gen, next)
	hash, err := save(s.dev, s.off, s.key, next, states)
	if err != nil {
		return fmt.Errorf("persisting generation %d: %w", next, err)
	}
	if err := s.anchor.SetAnchor(AnchorState{
		Generation: next,
		BlobHash:   hash,
		Bound:      true,
	}); err != nil {
		return fmt.Errorf("anchoring generation %d: %w", next, err)
	}

	s.gen = next
	return nil
}

// admit validates every persisted note before restoring any state.
func (s *RollbackStore) admit(states map[string][]byte) error {
	restored := make(map[string]witness.LogState, len(states))
	for origin, noteBytes := range states {
		o, st, err := witness.RestoreNote(noteBytes)
		if err != nil {
			return fmt.Errorf("entry %q: %w", origin, err)
		}
		if o != origin {
			return fmt.Errorf("entry %q contains origin %q", origin, o)
		}
		restored[o] = st
	}

	for o, st := range restored {
		if err := s.mem.PutBatch(map[string]witness.LogState{o: st}); err != nil {
			return err
		}
		log.Printf("state: restored %q at size %d (generation %d)", o, st.Size, s.gen)
	}

	return nil
}

func (s *RollbackStore) halt(format string, args ...any) {
	s.halted = true
	log.Printf("state: HALT: "+format, args...)
}

// Halted reports whether the store has refused to advance (at boot, or after
// a failed commit at runtime). When true the witness must not cosign; the
// firmware surfaces this loudly (error body + LED).
func (s *RollbackStore) Halted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.halted
}

// Generation returns the current committed state generation.
func (s *RollbackStore) Generation() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gen
}

func (s *RollbackStore) Get(origin string) (witness.LogState, bool) {
	return s.mem.Get(origin)
}

func (s *RollbackStore) All() map[string]witness.LogState {
	return s.mem.All()
}

// Put commits a new generation following the ROLLBACK.md update sequence:
// write the blob (S1), advance the anchor (S2), then return so the caller may
// release the cosignature (S3). The cosignature must not leave the device
// before Put returns nil.
//
// A commit that fails after it may have touched the medium halts the store; a
// reboot resolves the interrupted commit through the boot decision. See
// ROLLBACK.md, soft failures.
func (s *RollbackStore) Put(origin string, st witness.LogState) error {
	return s.PutBatch(map[string]witness.LogState{origin: st})
}

// PutBatch commits a set of per-log updates as one generation.
func (s *RollbackStore) PutBatch(updates map[string]witness.LogState) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.halted {
		return ErrHalted
	}

	if s.gen == ^uint32(0) {
		// The generation is exhausted. Halt rather than wrap, which
		// would break monotonicity.
		s.halt("generation counter exhausted")
		return ErrHalted
	}

	next := s.gen + 1
	// A generation may be written more than once after reboot. Fresh nonces
	// keep those Seals distinct; the RPMB digest selects the committed blob.

	// Build the next state without mutating s.mem: RAM must never run
	// ahead of the committed generation.
	states := make(map[string][]byte)
	for o, x := range s.mem.All() {
		states[o] = x.Note
	}
	for origin, st := range updates {
		states[origin] = st.Note
	}

	// S1: persist the blob for the new generation. A failure before the
	// slot write was issued (validation, oversize) leaves the medium
	// untouched and `next` unused, so serving continues. Once the write
	// itself fails the slot contents are unknown, so halt until reboot.
	blobHash, err := save(s.dev, s.off, s.key, next, states)
	if err != nil {
		if errors.Is(err, ErrWriteFailed) {
			s.halt("persisting generation %d failed: %v", next, err)
		}
		return fmt.Errorf("state: persist failed: %w", err)
	}

	// S2: bind the generation and exact blob in the hardware anchor. No
	// cosignature for `next` may be released until this succeeds. On failure
	// halt; a reboot resolves it through the boot decision.
	if err := s.anchor.SetAnchor(AnchorState{
		Generation: next,
		BlobHash:   blobHash,
		Bound:      true,
	}); err != nil {
		s.halt("anchoring generation %d failed: %v", next, err)
		return fmt.Errorf("state: anchoring generation %d failed: %w", next, err)
	}

	// S1 and S2 committed: now make the new state visible.
	if err := s.mem.PutBatch(updates); err != nil {
		return err
	}
	s.gen = next

	return nil
}
