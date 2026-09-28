package state

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cpu/vitrum/internal/rpmbtest"
	"github.com/cpu/vitrum/internal/witness"
	"github.com/usbarmory/rpmb"
)

func TestRPMBAnchorRoundTrip(t *testing.T) {
	a := newTestRPMBAnchor(t)

	if got, err := a.Anchor(); err != nil || got.Generation != 0 || got.Bound {
		t.Fatalf("fresh anchor = %+v, %v, want unbound generation 0", got, err)
	}

	for _, g := range []uint32{1, 2, 5} {
		want := testAnchorState(g)
		if err := a.SetAnchor(want); err != nil {
			t.Fatalf("SetAnchor(%d): %v", g, err)
		}
		if got, err := a.Anchor(); err != nil || got != want {
			t.Fatalf("Anchor after SetAnchor(%d) = %+v, %v", g, got, err)
		}
	}
}

// TestRPMBAnchorMonotonic: the anchor must refuse to move backwards or stand
// still; the store's rollback cross-check depends on it only ever advancing.
func TestRPMBAnchorMonotonic(t *testing.T) {
	a := newTestRPMBAnchor(t)

	if err := a.SetAnchor(testAnchorState(0)); err == nil {
		t.Fatal("SetAnchor(0) over a fresh anchor succeeded")
	}
	if err := a.SetAnchor(testAnchorState(2)); err != nil {
		t.Fatal(err)
	}

	for _, g := range []uint32{2, 1, 0} {
		if err := a.SetAnchor(testAnchorState(g)); err == nil {
			t.Errorf("SetAnchor(%d) over 2 succeeded, want monotonicity refusal", g)
		}
	}
	if got, err := a.Anchor(); err != nil || got.Generation != 2 {
		t.Fatalf("anchor after refused sets = %+v, %v, want generation 2", got, err)
	}
}

func TestRPMBAnchorUnprogrammedCard(t *testing.T) {
	key := bytes.Repeat([]byte{0xA7}, 32)
	p, err := rpmb.InitWithTransport(rpmbtest.NewFakeCard(), key, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewRPMBAnchor(p).Anchor(); err == nil {
		t.Fatal("Anchor over an unprogrammed card succeeded, want error")
	}
}

// TestRollbackRefusedOverRPMBAnchor runs the core rollback lifecycle over the
// real RPMB anchor (JESD84 frames against the fake card) instead of
// MemAnchor: commit twice, restore a storage snapshot, reboot, halt. This
// covers the store-to-RPMB seam end to end on the host; hardware validation
// is left checking only the usdhc transport.
func TestRollbackRefusedOverRPMBAnchor(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := newTestRPMBAnchor(t)

	s, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: signed}); err != nil {
		t.Fatal(err)
	}
	snapshot := dev.snapshot()

	signed8 := testSignedNote(t, 8)
	if err := s.Put(testOrigin, witness.LogState{Size: 8, Note: signed8}); err != nil {
		t.Fatal(err)
	}
	if got, err := anchor.Anchor(); err != nil || got.Generation != 2 {
		t.Fatalf("anchor = %+v, %v, want generation 2 after two commits", got, err)
	}

	// Adversary restores the generation-1 snapshot and power-cycles; the
	// RPMB anchor still reads 2.
	dev.restore(snapshot)

	s2, err := Open(dev, Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if !s2.Halted() {
		t.Fatal("store did not halt on rollback over the RPMB anchor")
	}
	if err := s2.Put(testOrigin, witness.LogState{Size: 9, Note: signed}); err != ErrHalted {
		t.Fatalf("Put on halted store = %v, want ErrHalted", err)
	}
}

// TestBenignOffByOneOverRPMBAnchor: boot-time recovery of an interrupted
// commit re-anchors through a real authenticated RPMB write.
func TestBenignOffByOneOverRPMBAnchor(t *testing.T) {
	signed := testSignedNote(t, 7)
	dev := testDevice()
	anchor := newTestRPMBAnchor(t)

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
	if got, err := anchor.Anchor(); err != nil || got.Generation != 1 {
		t.Errorf("anchor after recovery = %+v, %v, want generation 1 (re-anchored)", got, err)
	}
}

func TestRPMBAnchorRejectsGenerationOnlyRecord(t *testing.T) {
	p := newTestRPMB(t)
	record := make([]byte, anchorGenerationLen)
	binary.BigEndian.PutUint32(record, 1)
	if err := p.Write(rpmbAnchorSector, record); err != nil {
		t.Fatal(err)
	}

	if _, err := NewRPMBAnchor(p).Anchor(); err == nil {
		t.Fatal("generation-only RPMB record accepted")
	}
}

func TestRPMBCommitConsumesOneWrite(t *testing.T) {
	p := newTestRPMB(t)
	before, err := p.Counter(true)
	if err != nil {
		t.Fatal(err)
	}
	anchor := NewRPMBAnchor(p)

	s, err := Open(testDevice(), Offset, testKey, anchor)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(testOrigin, witness.LogState{Size: 7, Note: testSignedNote(t, 7)}); err != nil {
		t.Fatal(err)
	}
	after, err := p.Counter(true)
	if err != nil {
		t.Fatal(err)
	}
	if after != before+1 {
		t.Fatalf("commit consumed %d RPMB writes, want 1", after-before)
	}
}

// newTestRPMBAnchor returns an RPMBAnchor over a FakeCard with the
// authentication key programmed, mirroring the production layout (dummy
// sector 0, anchor sector 1).
func newTestRPMBAnchor(t *testing.T) *RPMBAnchor {
	t.Helper()
	return NewRPMBAnchor(newTestRPMB(t))
}

func newTestRPMB(t *testing.T) *rpmb.RPMB {
	t.Helper()

	key := bytes.Repeat([]byte{0xA7}, 32)
	card := rpmbtest.NewFakeCard()

	programmer, err := rpmb.InitWithTransport(card, key, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := programmer.ProgramKey(); err != nil {
		t.Fatalf("ProgramKey: %v", err)
	}

	p, err := rpmb.InitWithTransport(card, key, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	return p
}
