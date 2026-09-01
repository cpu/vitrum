package state

import (
	"bytes"
	"testing"

	"github.com/cpu/vitrum/internal/rpmbtest"
	"github.com/cpu/vitrum/internal/witness"
	"github.com/usbarmory/rpmb"
)

func TestRPMBAnchorRoundTrip(t *testing.T) {
	a := newTestRPMBAnchor(t)

	if g, err := a.Anchor(); err != nil || g != 0 {
		t.Fatalf("fresh anchor = %d, %v, want 0", g, err)
	}

	for _, g := range []uint32{1, 2, 5} {
		if err := a.SetAnchor(g); err != nil {
			t.Fatalf("SetAnchor(%d): %v", g, err)
		}
		if got, err := a.Anchor(); err != nil || got != g {
			t.Fatalf("Anchor after SetAnchor(%d) = %d, %v", g, got, err)
		}
	}
}

// TestRPMBAnchorMonotonic: the anchor must refuse to move backwards or stand
// still; the store's rollback cross-check depends on it only ever advancing.
func TestRPMBAnchorMonotonic(t *testing.T) {
	a := newTestRPMBAnchor(t)

	if err := a.SetAnchor(2); err != nil {
		t.Fatal(err)
	}

	for _, g := range []uint32{2, 1, 0} {
		if err := a.SetAnchor(g); err == nil {
			t.Errorf("SetAnchor(%d) over 2 succeeded, want monotonicity refusal", g)
		}
	}
	if g, err := a.Anchor(); err != nil || g != 2 {
		t.Fatalf("anchor after refused sets = %d, %v, want 2", g, err)
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
	if g, err := anchor.Anchor(); err != nil || g != 2 {
		t.Fatalf("anchor = %d, %v, want 2 after two commits", g, err)
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
	if g, err := anchor.Anchor(); err != nil || g != 1 {
		t.Errorf("anchor after recovery = %d, %v, want 1 (re-anchored)", g, err)
	}
}

// newTestRPMBAnchor returns an RPMBAnchor over a FakeCard with the
// authentication key programmed, mirroring the production layout (dummy
// sector 0, anchor sector 1).
func newTestRPMBAnchor(t *testing.T) *RPMBAnchor {
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

	return NewRPMBAnchor(p)
}
