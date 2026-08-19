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
// the microSD A/B slots and anchored in a hardware-monotonic counter (eMMC
// RPMB). At boot the blob generation is cross-checked against the anchor; a
// stale blob (anchor ahead) or missing state (anchor non-zero, no blob) halts
// the store. See ROLLBACK.md.
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

	gRPMB, err := anchor.Anchor()
	if err != nil {
		return nil, fmt.Errorf("state: reading anchor: %w", err)
	}

	states, gBlob, loadErr := Load(dev, offset, key)
	haveBlob := loadErr == nil

	switch {
	case !haveBlob && gRPMB == 0:
		// Fresh unit: no committed generation, no state. Start empty.
		log.Printf("state: fresh start (anchor 0, no blob)")
		s.gen = 0

	case !haveBlob:
		// The anchor records a committed generation we cannot produce:
		// storage was erased or corrupted. Treat as tamper.
		s.halt("anchor at generation %d but no valid state blob (load: %v)", gRPMB, loadErr)
		return s, nil

	case gBlob == gRPMB:
		// Normal: blob matches the anchor.
		s.gen = gBlob
		if err := s.admit(states); err != nil {
			s.halt("invalid persisted state: %v", err)
			return s, nil
		}

	case gBlob == gRPMB+1:
		// Benign off-by-one: crash after the blob write, before the
		// anchor advanced. No cosignature for this generation escaped
		// (it is released only after anchoring). Re-anchor and adopt it.
		s.gen = gBlob
		if err := s.admit(states); err != nil {
			s.halt("invalid persisted state: %v", err)
			return s, nil
		}
		log.Printf("state: recovering interrupted commit (blob %d, anchor %d)", gBlob, gRPMB)
		if err := anchor.SetAnchor(gBlob); err != nil {
			s.halt("re-anchoring generation %d failed: %v", gBlob, err)
			return s, nil
		}

	case gBlob > gRPMB+1:
		// More than one un-anchored generation cannot occur in a normal
		// sequence: tamper.
		s.halt("state generation %d more than one ahead of anchor %d", gBlob, gRPMB)
		return s, nil

	default: // gBlob < gRPMB
		// Storage was rolled back to an older generation.
		s.halt("rollback: state generation %d behind anchor %d", gBlob, gRPMB)
		return s, nil
	}

	return s, nil
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
// A commit that fails after it may have touched the medium halts the store
// (the generation is burned and must never be re-Sealed); a reboot resolves
// the interrupted commit through the boot decision. See ROLLBACK.md, soft
// failures.
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
		// The anchor counter is exhausted (~136 years at 1 write/s). Halt
		// rather than wrap, which would break monotonicity.
		s.halt("generation counter exhausted")
		return ErrHalted
	}

	// SECURITY INVARIANT: each generation value is written at most once,
	// which is why a failed commit below halts instead of retrying `next`.
	// ROLLBACK.md, soft failures, covers what reuse would break.
	next := s.gen + 1

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
	// itself fails the slot contents are unknown and `next` is burned,
	// so halt.
	if err := Save(s.dev, s.off, s.key, next, states); err != nil {
		if errors.Is(err, ErrWriteFailed) {
			s.halt("persisting generation %d failed: %v", next, err)
		}
		return fmt.Errorf("state: persist failed: %w", err)
	}

	// S2: advance the hardware anchor. No cosignature for `next` may be
	// released until this succeeds. On failure the blob at `next` is on
	// the medium and the generation is burned, so halt; a reboot resolves
	// it through the boot decision (benign off-by-one).
	if err := s.anchor.SetAnchor(next); err != nil {
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
