package state

import (
	"bytes"
	"fmt"
	"testing"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/cpu/vitrum/internal/witness"
)

var testKey = bytes.Repeat([]byte{0x11}, StateKeyLen)

func TestRollbackStoreRoundTrip(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := NewMemAnchor()

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() {
		t.Fatal("fresh store halted")
	}
	if _, ok := s.Get(testOrigin); ok {
		t.Fatal("fresh store has state")
	}

	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != nil {
		t.Fatal(err)
	}
	if s.Generation() != 1 {
		t.Errorf("generation = %d, want 1", s.Generation())
	}
	if a, _ := anchor.Anchor(); a.Generation != 1 {
		t.Errorf("anchor = %d, want 1", a.Generation)
	}

	// A reboot: a new store over the same device + anchor restores state.
	s2, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Halted() {
		t.Fatal("store halted on clean reload")
	}
	got, ok := s2.Get(testOrigin)
	if !ok || got.Size != 7 || !bytes.Equal(got.Note, signed) {
		t.Fatalf("restored state = %+v ok=%v, want size 7 with original note", got, ok)
	}
	if s2.Generation() != 1 {
		t.Errorf("restored generation = %d, want 1", s2.Generation())
	}
	if all := s2.All(); len(all) != 1 || all[testOrigin].Size != 7 {
		t.Errorf("All() = %v, want the single restored entry", all)
	}
}

func TestRollbackStoreBatchIsOneGeneration(t *testing.T) {
	dev := testDevice()
	anchor := NewMemAnchor()
	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	const otherOrigin = "other.vitrum.invalid/log"
	updates := map[string]witness.LogState{
		testOrigin:  {Size: 7, Note: testSignedNoteFor(t, testOrigin, 7)},
		otherOrigin: {Size: 11, Note: testSignedNoteFor(t, otherOrigin, 11)},
	}
	if err := s.PutBatch(updates); err != nil {
		t.Fatal(err)
	}
	if got := s.Generation(); got != 1 {
		t.Fatalf("generation = %d, want 1", got)
	}
	if got, _ := anchor.Anchor(); got.Generation != 1 {
		t.Fatalf("anchor = %d, want 1", got.Generation)
	}

	s2, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if got := s2.All(); len(got) != 2 || got[testOrigin].Size != 7 || got[otherOrigin].Size != 11 {
		t.Fatalf("restored batch = %v", got)
	}
}

// TestRollbackRefused is the core rollback resistance property: restoring an
// older storage snapshot after the witness advanced must halt the store.
func TestRollbackRefused(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := NewMemAnchor()

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	// Commit generation 1, then snapshot storage.
	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != nil {
		t.Fatal(err)
	}
	snapshot := dev.snapshot()

	// Advance to generation 2 (anchor now 2, storage holds gen 2).
	signed8 := testSignedNote(t, 8)
	if err := s.Put(testOrigin, witness.LogState{Size: 8, Note: signed8}); err != nil {
		t.Fatal(err)
	}
	if a, _ := anchor.Anchor(); a.Generation != 2 {
		t.Fatalf("anchor = %d, want 2", a.Generation)
	}

	// Adversary restores the older storage snapshot (generation 1) and
	// reboots. The anchor (2) is ahead of the restored blob (1).
	dev.restore(snapshot)

	s2, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Halted() {
		t.Fatal("store did not halt on a rolled-back storage snapshot")
	}
	// A halted store refuses to commit anything new.
	if err := s2.Put(testOrigin, witness.LogState{Size: 9, Note: signed}); err != ErrHalted {
		t.Fatalf("Put on halted store = %v, want ErrHalted", err)
	}
}

// TestBenignOffByOne covers a crash between the blob write (S1) and the anchor
// advance (S2): the blob is one generation ahead of the anchor; the store
// recovers and re-anchors rather than halting.
func TestBenignOffByOne(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := NewMemAnchor()

	// Simulate: blob for generation 1 was written, but power was lost
	// before the anchor advanced (anchor still 0).
	if err := Save(dev, Offset, testKey, 1, map[string][]byte{testOrigin: signed}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() {
		t.Fatal("store halted on a benign off-by-one")
	}
	if s.Generation() != 1 {
		t.Errorf("recovered generation = %d, want 1", s.Generation())
	}
	if a, _ := anchor.Anchor(); a.Generation != 1 {
		t.Errorf("anchor after recovery = %d, want 1 (re-anchored)", a.Generation)
	}
	if _, ok := s.Get(testOrigin); !ok {
		t.Error("recovered state not present")
	}
}

// TestAnchorAheadNoBlob covers erased/corrupt storage while the anchor records
// a committed generation: tamper, halt.
func TestAnchorAheadNoBlob(t *testing.T) {
	dev := testDevice()
	anchor := NewMemAnchor()
	if err := anchor.SetAnchor(testAnchorState(5)); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store did not halt with anchor ahead of (missing) storage")
	}
}

// TestImpossibleGapHalts: a blob more than one generation ahead of the anchor
// cannot arise from the update sequence, so it is treated as tamper.
func TestImpossibleGapHalts(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := NewMemAnchor()
	if err := anchor.SetAnchor(testAnchorState(1)); err != nil {
		t.Fatal(err)
	}
	if err := Save(dev, Offset, testKey, 3, map[string][]byte{testOrigin: signed}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store did not halt on an impossible generation gap")
	}
}

// failAnchor is an Anchor whose SetAnchor fails after the first n successful
// calls, to exercise the S2 (anchor advance) failure path.
type failAnchor struct {
	*MemAnchor
	failAfter int
	sets      int
}

func (a *failAnchor) SetAnchor(next AnchorState) error {
	a.sets++
	if a.sets > a.failAfter {
		return fmt.Errorf("injected anchor failure")
	}
	return a.MemAnchor.SetAnchor(next)
}

// TestPutRamNeverAheadOnAnchorFailure: if the blob write (S1) succeeds but the
// anchor advance (S2) fails, the in-RAM view must not reflect the uncommitted
// checkpoint; otherwise the witness could report a size it never anchored.
func TestPutRamNeverAheadOnAnchorFailure(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := &failAnchor{MemAnchor: NewMemAnchor(), failAfter: 0} // fail on the first set

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	err = s.Put(testOrigin, witness.LogState{Size: 7, Note: signed})
	if err == nil {
		t.Fatal("Put succeeded despite anchor failure")
	}

	// RAM must be unchanged (still empty) and generation must not advance.
	if _, ok := s.Get(testOrigin); ok {
		t.Error("RAM shows an uncommitted checkpoint after anchor failure")
	}
	if s.Generation() != 0 {
		t.Errorf("generation = %d, want 0 (no commit)", s.Generation())
	}
	if a, _ := anchor.Anchor(); a.Generation != 0 {
		t.Errorf("anchor = %d, want 0", a.Generation)
	}
}

// TestAnchorFailureHaltsUntilReboot: the durable result of an anchor failure
// is unknown, so the running store halts. A reboot recovers the interrupted
// commit via the benign off-by-one.
func TestAnchorFailureHaltsUntilReboot(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := &failAnchor{MemAnchor: NewMemAnchor(), failAfter: 0}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err == nil {
		t.Fatal("Put succeeded despite anchor failure")
	}
	if !s.Halted() {
		t.Fatal("store not halted after S2 failure")
	}

	// A retry (possibly with different content) must be refused, not
	// committed under the same generation.
	signed8 := testSignedNote(t, 8)
	if err := s.Put(testOrigin, witness.LogState{Size: 8, Note: signed8}); err != ErrHalted {
		t.Fatalf("Put after halt = %v, want ErrHalted", err)
	}

	// Reboot with the anchor healthy again: the boot decision adopts the
	// interrupted commit (benign off-by-one) with its original content.
	anchor.failAfter = 99
	s2, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Halted() {
		t.Fatal("store halted on reboot after an interrupted commit")
	}
	if s2.Generation() != 1 {
		t.Errorf("recovered generation = %d, want 1", s2.Generation())
	}
	got, ok := s2.Get(testOrigin)
	if !ok || got.Size != 7 || !bytes.Equal(got.Note, signed) {
		t.Fatalf("recovered state = %+v ok=%v, want the size-7 commit", got, ok)
	}
	if a, _ := anchor.Anchor(); a.Generation != 1 {
		t.Errorf("anchor after recovery = %d, want 1", a.Generation)
	}
}

// TestInterruptedGenerationCannotReplaceCommittedState covers the attack where
// an adversary hides a blob written before an anchor failure, lets the device
// commit different contents at the same generation, then restores the first
// authentic blob.
func TestInterruptedGenerationCannotReplaceCommittedState(t *testing.T) {
	dev := testDevice()
	anchor := &failAnchor{MemAnchor: NewMemAnchor(), failAfter: 1}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: testSignedNote(t, 7)}); err != nil {
		t.Fatal(err)
	}
	committed := dev.snapshot()

	if err := s.Put(testOrigin, witness.LogState{Size: 8, Note: testSignedNote(t, 8)}); err == nil {
		t.Fatal("Put succeeded despite anchor failure")
	}
	interrupted := dev.snapshot()

	// Hide the interrupted generation-2 blob and reboot at the still-anchored
	// generation 1. The replacement generation 2 contains different state.
	dev.restore(committed)
	anchor.failAfter = 99
	s, err = Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() {
		t.Fatal("store halted after the interrupted blob was removed")
	}
	if err := s.Put(testOrigin, witness.LogState{Size: 9, Note: testSignedNote(t, 9)}); err != nil {
		t.Fatal(err)
	}

	// Restoring the first authentic generation-2 blob must not replace the
	// different generation-2 state the anchor committed.
	dev.restore(interrupted)
	s, err = Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store accepted a different authentic blob at the anchored generation")
	}
}

func TestLegacyStateMigrates(t *testing.T) {
	dev := testDevice()
	want := testSignedNote(t, 7)
	_, err := saveLegacy(dev, Offset, testKey, 1, map[string][]byte{testOrigin: want})
	if err != nil {
		t.Fatal(err)
	}
	anchor := NewMemAnchor()
	anchor.state.Generation = 1

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() {
		t.Fatal("store halted while migrating legacy state")
	}
	got, ok := s.Get(testOrigin)
	if !ok || !bytes.Equal(got.Note, want) {
		t.Fatalf("migrated state = %+v ok=%v, want original note", got, ok)
	}
	if s.Generation() != 2 {
		t.Fatalf("migrated generation = %d, want 2", s.Generation())
	}
	anchored, err := anchor.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := load(dev, Offset, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if anchored.Generation != 2 || !anchored.Bound || anchored.BlobHash != blob.hash || blob.legacy {
		t.Fatalf("migrated anchor = %+v, blob = %+v, want generation 2 VITRUMW2 state", anchored, blob)
	}
	// An old reader ignores VITRUMW2 and can only recover this preceding
	// VITRUMW1 blob, whose generation is now behind the anchor.
	previous, err := loadSlot(dev, Offset, 1, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if previous.gen != 1 || !previous.legacy {
		t.Fatalf("previous blob = %+v, want generation 1 VITRUMW1 state", previous)
	}
}

func TestLegacyInterruptedStateMigrates(t *testing.T) {
	dev := testDevice()
	_, err := saveLegacy(dev, Offset, testKey, 1, map[string][]byte{
		testOrigin: testSignedNote(t, 7),
	})
	if err != nil {
		t.Fatal(err)
	}
	anchor := NewMemAnchor()

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() || s.Generation() != 2 {
		t.Fatalf("interrupted migration halted=%v generation=%d, want false, 2", s.Halted(), s.Generation())
	}
	anchored, err := anchor.Anchor()
	if err != nil {
		t.Fatal(err)
	}
	blob, err := load(dev, Offset, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if anchored.Generation != 2 || !anchored.Bound || anchored.BlobHash != blob.hash || blob.legacy {
		t.Fatalf("migrated anchor = %+v, blob = %+v, want generation 2 VITRUMW2 state", anchored, blob)
	}
}

func TestLegacyMigrationFailureHalts(t *testing.T) {
	dev := testDevice()
	if _, err := saveLegacy(dev, Offset, testKey, 1, map[string][]byte{
		testOrigin: testSignedNote(t, 7),
	}); err != nil {
		t.Fatal(err)
	}
	mem := NewMemAnchor()
	mem.state.Generation = 1
	anchor := &failAnchor{MemAnchor: mem, failAfter: 0}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store served without binding the legacy anchor")
	}
}

func TestLegacyFormatUpgradeFailureHaltsAndRecovers(t *testing.T) {
	dev := testDevice()
	if _, err := saveLegacy(dev, Offset, testKey, 1, map[string][]byte{
		testOrigin: testSignedNote(t, 7),
	}); err != nil {
		t.Fatal(err)
	}
	mem := NewMemAnchor()
	mem.state.Generation = 1
	anchor := &failAnchor{MemAnchor: mem, failAfter: 1}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store served after the VITRUMW2 anchor write failed")
	}

	anchor.failAfter = 99
	s, err = Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() || s.Generation() != 2 {
		t.Fatalf("upgrade recovery halted=%v generation=%d, want false, 2", s.Halted(), s.Generation())
	}
}

// TestWriteFailureHalts: once the S1 slot write is issued and fails, the slot
// contents (and hence the generation) are unknown, so the store halts. A
// reboot over the untouched previous state recovers normally.
func TestWriteFailureHalts(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := &failDevice{memDevice: testDevice()}
	anchor := NewMemAnchor()

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	dev.failWrites = true
	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err == nil {
		t.Fatal("Put succeeded despite write failure")
	}
	if !s.Halted() {
		t.Fatal("store not halted after a failed slot write")
	}
	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != ErrHalted {
		t.Fatalf("Put after halt = %v, want ErrHalted", err)
	}

	// Reboot: nothing reached the medium, so this is a normal fresh start,
	// and the store can commit again.
	dev.failWrites = false
	s2, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Halted() {
		t.Fatal("store halted on reboot after a failed (never-landed) write")
	}
	if err := s2.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != nil {
		t.Fatal(err)
	}
	if s2.Generation() != 1 {
		t.Errorf("generation = %d, want 1", s2.Generation())
	}
}

// TestOversizePutDoesNotHalt: a state too large for the slot fails before
// anything touches the medium and the generation is unused, so the store
// keeps serving and a well-sized commit still succeeds.
func TestOversizePutDoesNotHalt(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := NewMemAnchor()

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	huge := witness.LogState{Size: 7, Note: make([]byte, SlotSize)}
	if err := s.Put(testOrigin, huge); err == nil {
		t.Fatal("Put accepted an oversize state")
	}
	if s.Halted() {
		t.Fatal("store halted on a pre-write validation failure")
	}

	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != nil {
		t.Fatalf("Put after oversize rejection: %v", err)
	}
	if s.Generation() != 1 {
		t.Errorf("generation = %d, want 1", s.Generation())
	}
}

// failDevice wraps memDevice with switchable write failures.
type failDevice struct {
	*memDevice
	failWrites bool
}

func (d *failDevice) WriteBlocks(lba int64, buf []byte) error {
	if d.failWrites {
		return fmt.Errorf("injected write failure")
	}
	return d.memDevice.WriteBlocks(lba, buf)
}

// TestReanchorFailureHaltsAtBoot: recovering the benign off-by-one requires
// re-anchoring; if that anchor write fails the store must halt, not serve an
// un-anchored generation.
func TestReanchorFailureHaltsAtBoot(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	if err := Save(dev, Offset, testKey, 1, map[string][]byte{testOrigin: signed}); err != nil {
		t.Fatal(err)
	}
	anchor := &failAnchor{MemAnchor: NewMemAnchor(), failAfter: 0}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store did not halt when off-by-one re-anchoring failed")
	}
}

// TestCounterExhaustionHalts: the generation must never wrap the uint32
// anchor; the store halts at the last representable generation.
func TestCounterExhaustionHalts(t *testing.T) {
	signed := testSignedNote(t, 7)
	s, err := Open(testDevice(), Offset, testKey, NewMemAnchor())
	if err != nil {
		t.Fatal(err)
	}

	s.gen = ^uint32(0)

	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != ErrHalted {
		t.Fatalf("Put at exhausted counter = %v, want ErrHalted", err)
	}
	if !s.Halted() {
		t.Fatal("store not halted after counter exhaustion")
	}
}

// brokenAnchor fails every read: a boot that cannot authenticate its anchor
// has no basis for the rollback decision.
type brokenAnchor struct{}

func (brokenAnchor) Anchor() (AnchorState, error) {
	return AnchorState{}, fmt.Errorf("injected anchor read failure")
}
func (brokenAnchor) SetAnchor(AnchorState) error { return nil }

func TestOpenAnchorReadFailure(t *testing.T) {
	if _, err := Open(testDevice(), Offset, testKey, brokenAnchor{}); err == nil {
		t.Fatal("Open with an unreadable anchor succeeded, want error")
	}
}

func TestInvalidPersistedNotesHalt(t *testing.T) {
	signed := testSignedNote(t, 7)
	tests := map[string]map[string][]byte{
		"origin mismatch": {
			"other.vitrum.invalid/log": signed,
		},
		"malformed note": {
			testOrigin: []byte("not a signed note"),
		},
		"atomic admission": {
			testOrigin:                       signed,
			"other.vitrum.invalid/malformed": []byte("not a signed note"),
		},
	}

	for name, states := range tests {
		t.Run(name, func(t *testing.T) {
			dev := testDevice()
			anchor := NewMemAnchor()
			hash, err := save(dev, Offset, testKey, 1, states)
			if err != nil {
				t.Fatal(err)
			}
			if err := anchor.SetAnchor(AnchorState{Generation: 1, BlobHash: hash, Bound: true}); err != nil {
				t.Fatal(err)
			}

			s, err := Open(dev, Offset, testKey, anchor)
			if err != nil {
				t.Fatal(err)
			}
			if !s.Halted() {
				t.Fatal("store did not halt on invalid persisted state")
			}
			if all := s.All(); len(all) != 0 {
				t.Fatalf("state partially admitted: %v", all)
			}
			if err := s.Put(testOrigin, witness.LogState{Size: 8, Note: signed}); err != ErrHalted {
				t.Fatalf("Put after invalid persisted state = %v, want ErrHalted", err)
			}
		})
	}
}

func TestInvalidInterruptedStateDoesNotReanchor(t *testing.T) {
	dev := testDevice()
	anchor := NewMemAnchor()
	if err := Save(dev, Offset, testKey, 1, map[string][]byte{
		testOrigin: []byte("not a signed note"),
	}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Halted() {
		t.Fatal("store did not halt on invalid interrupted state")
	}
	if got, _ := anchor.Anchor(); got.Generation != 0 {
		t.Fatalf("anchor advanced to %d for invalid state", got.Generation)
	}
}

// TestAdmitsUnverifiedNotes documents the re-admission model: note-level
// signatures are not re-verified, because the authenticated blob is what
// makes persisted state trustworthy (SECURITY.md). A structurally valid
// note is admitted even when its text matches no signature.
func TestAdmitsUnverifiedNotes(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := NewMemAnchor()

	// Persist a note whose text was altered after signing, at generation 1.
	altered := bytes.Replace(signed, []byte("\n7\n"), []byte("\n8\n"), 1)
	hash, err := save(dev, Offset, testKey, 1, map[string][]byte{testOrigin: altered})
	if err != nil {
		t.Fatal(err)
	}
	if err := anchor.SetAnchor(AnchorState{Generation: 1, BlobHash: hash, Bound: true}); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if s.Halted() {
		t.Fatal("store halted on a structurally valid note")
	}
	got, ok := s.Get(testOrigin)
	if !ok || got.Size != 8 {
		t.Fatalf("Get = %+v ok=%v, want the altered note admitted at size 8", got, ok)
	}
}

// testSignedNote returns a checkpoint note for testOrigin at the given size,
// signed under a deterministic throwaway key (zeroReader seed). Signatures
// are not verified on re-admission (SECURITY.md); signing here just keeps
// the fixtures shaped like real notes.
func testSignedNote(t *testing.T, size int64) []byte {
	return testSignedNoteFor(t, testOrigin, size)
}

func testSignedNoteFor(t *testing.T, origin string, size int64) []byte {
	t.Helper()

	skey, _, err := note.GenerateKey(zeroReader{}, origin)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatal(err)
	}
	text := fmt.Sprintf("%s\n%d\n%s\n", origin, size, tlog.Hash{})
	signed, err := note.Sign(&note.Note{Text: text}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

const testOrigin = "test.vitrum.invalid/log"

func testAnchorState(gen uint32) AnchorState {
	var hash BlobHash
	hash[0] = byte(gen)
	return AnchorState{Generation: gen, BlobHash: hash, Bound: true}
}

// zeroReader is a deterministic io.Reader so tests never require committed key
// material.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0x42
	}
	return len(p), nil
}
