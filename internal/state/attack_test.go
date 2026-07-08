package state

import (
	"bytes"
	"crypto/ed25519"
	"net/http"
	"testing"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/cpu/vitrum/internal/testlog"
	"github.com/cpu/vitrum/internal/witness"
)

// TestRollbackAttackRefusedEndToEnd snapshots storage, advances the
// witness, restores the snapshot, "reboot"s, and confirms the witness
// refuses to serve, observed at the add-checkpoint layer rather than just
// the store's Halted flag.
//
// The shared MemAnchor stands in for the hardware-monotonic RPMB counter
// that the adversary cannot roll back.
func TestRollbackAttackRefusedEndToEnd(t *testing.T) {
	const origin = "attack.vitrum.invalid/log"

	// A real tlog we can grow and prove consistency against.
	l, err := testlog.New(zeroReader{}, origin)
	if err != nil {
		t.Fatal(err)
	}

	// A witness cosignature signer.
	wsigner, err := torchwood.NewCosignatureSigner(
		"attack-witness.invalid", ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		t.Fatal(err)
	}

	dev := testDevice()
	anchor := NewMemAnchor() // survives "reboot"; cannot be rolled back

	// newWitness builds a witness over a freshly Opened store, as a boot would.
	newWitness := func(t *testing.T) *witness.Witness {
		t.Helper()
		s, err := Open(dev, Offset, testKey, anchor)
		if err != nil {
			t.Fatal(err)
		}
		w := witness.New(s)
		w.SetSigner(wsigner)
		return w
	}

	submit := func(t *testing.T, w *witness.Witness, old int64, proof tlog.TreeProof, cpNote []byte) (int, []byte) {
		t.Helper()
		return w.AddCheckpoint(witness.EncodeAddCheckpoint(old, proof, cpNote))
	}

	// Boot 1: cosign the log at size 3.
	l.Append("a", "b", "c")
	cp3Note := mustCP(t, l)
	_, cp3, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}

	w1 := newWitness(t)
	if code, resp := submit(t, w1, 0, nil, cp3Note); code != http.StatusOK {
		t.Fatalf("cosign @3 = %d (%q), want 200", code, resp)
	}

	// The adversary snapshots storage right after generation 1 is committed.
	snapshot := dev.snapshot()

	// The witness legitimately advances: grow the log to size 5 and cosign
	// with a real consistency proof (generation 2, anchor 2).
	l.Append("d", "e")
	cp5Note := mustCP(t, l)
	_, cp5, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := l.ProveTree(cp5.N, cp3.N)
	if err != nil {
		t.Fatal(err)
	}
	if code, resp := submit(t, w1, cp3.N, proof, cp5Note); code != http.StatusOK {
		t.Fatalf("cosign @5 = %d (%q), want 200", code, resp)
	}
	if g, _ := anchor.Anchor(); g != 2 {
		t.Fatalf("anchor = %d, want 2 after two commits", g)
	}

	// The adversary restores the older storage snapshot (generation 1) and
	// power-cycles the device. The anchor still reads 2.
	dev.restore(snapshot)

	// Boot 2: the store detects the rollback and halts.
	w2 := newWitness(t)
	if !w2.Halted() {
		t.Fatal("witness not halted after storage rollback")
	}

	// The witness now refuses every submission, even a benign resubmission
	// of the checkpoint it had already cosigned at generation 1.
	code, resp := submit(t, w2, 0, nil, cp3Note)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("post-rollback submit = %d (%q), want 503", code, resp)
	}
	if want := []byte("witness halted"); !bytes.Contains(resp, want) {
		t.Errorf("post-rollback body = %q, want it to mention %q", resp, want)
	}
}

func mustCP(t *testing.T, l *testlog.Log) []byte {
	t.Helper()
	n, _, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	return n
}
