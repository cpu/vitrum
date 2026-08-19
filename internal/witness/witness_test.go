package witness

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/cpu/vitrum/internal/testlog"
)

func TestFirstSubmission(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, v := newTestWitness(t)

	cpNote := mustCheckpoint(t, l)
	cosig := mustCosign(t, w, 0, nil, cpNote)
	verifyCosig(t, v, cpNote, cosig)

	// The monitoring view serves the checkpoint text plus our cosignature,
	// never the submitted log signatures.
	h := sha256.Sum256([]byte(testOrigin))
	stored, ok := w.Checkpoint(hex.EncodeToString(h[:]))
	if !ok {
		t.Fatal("Checkpoint: no state stored")
	}
	if want := append(checkpointText(t, cpNote), cosig...); !bytes.Equal(stored, want) {
		t.Errorf("stored note = %q, want %q", stored, want)
	}
}

// checkpointText returns the text portion of a signed note including the
// blank separator line, i.e. everything a stored note carries before the
// witness's own signature lines.
func checkpointText(t *testing.T, cpNote []byte) []byte {
	t.Helper()

	sep := bytes.Index(cpNote, []byte("\n\n"))
	if sep < 0 {
		t.Fatal("note has no signature separator")
	}
	return bytes.Clone(cpNote[:sep+2])
}

// TestPaddedSubmissionNotStored verifies that padding in the unverified
// signature section (up to almost MaxRequestSize) never reaches persistent
// state; stored notes carry only the checkpoint text and our cosignature.
func TestPaddedSubmissionNotStored(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, v := newTestWitness(t)

	cpNote := mustCheckpoint(t, l)

	// A handful of huge junk signature lines, ~56 KiB total.
	padded := bytes.Clone(cpNote)
	for i := 0; i < 4; i++ {
		blob := bytes.Repeat([]byte{0xA5, byte(i)}, 5<<10)
		padded = append(padded, "— pad.invalid "+base64.StdEncoding.EncodeToString(blob)+"\n"...)
	}
	if len(padded) >= MaxRequestSize {
		t.Fatal("test padding overshot MaxRequestSize")
	}

	cosig := mustCosign(t, w, 0, nil, padded)
	verifyCosig(t, v, cpNote, cosig)

	h := sha256.Sum256([]byte(testOrigin))
	stored, ok := w.Checkpoint(hex.EncodeToString(h[:]))
	if !ok {
		t.Fatal("Checkpoint: no state stored")
	}
	if bytes.Contains(stored, []byte("pad.invalid")) {
		t.Fatal("stored note carries submitted padding")
	}
	if want := append(checkpointText(t, cpNote), cosig...); !bytes.Equal(stored, want) {
		t.Errorf("stored note = %d bytes, want the %d-byte re-serialized note (text + cosig)",
			len(stored), len(want))
	}

	// The bounded note still restores across a reboot.
	origin, restored, err := RestoreNote(stored)
	if err != nil || origin != testOrigin || restored.Size != 3 {
		t.Fatalf("RestoreNote on stored note = %q size=%d err=%v, want %q size=3",
			origin, restored.Size, err, testOrigin)
	}
}

func TestGrow(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, v := newTestWitness(t)

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))

	l.Append("d", "e")
	cpNote := mustCheckpoint(t, l)
	cosig := mustCosign(t, w, 3, mustProveTree(t, l, 5, 3), cpNote)
	verifyCosig(t, v, cpNote, cosig)
}

func TestResubmissionSameSize(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, v := newTestWitness(t)

	cpNote := mustCheckpoint(t, l)
	mustCosign(t, w, 0, nil, cpNote)

	// idempotent feeders: latest checkpoint is re-cosigned
	cosig := mustCosign(t, w, 3, nil, cpNote)
	verifyCosig(t, v, cpNote, cosig)
}

func TestConflict(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, _ := newTestWitness(t)

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))

	l.Append("d", "e")
	code, resp := w.AddCheckpoint(EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l)))
	if code != http.StatusConflict {
		t.Fatalf("AddCheckpoint = %d, want 409", code)
	}
	if string(resp) != "3\n" {
		t.Errorf("conflict body = %q, want \"3\\n\"", resp)
	}

	// the conflict body enables a stateless retry
	mustCosign(t, w, 3, mustProveTree(t, l, 5, 3), mustCheckpoint(t, l))
}

// TestAnyOriginCosigned verifies that a never-seen origin is cosigned on
// first sighting (no origin allowlist, SECURITY.md) and then shows up in
// the monitoring surface.
func TestAnyOriginCosigned(t *testing.T) {
	other := newTestLog(t, "unknown.vitrum.invalid/log")
	other.Append("a")
	w, v := newTestWitness(t)

	cpNote := mustCheckpoint(t, other)
	cosig := mustCosign(t, w, 0, nil, cpNote)
	verifyCosig(t, v, cpNote, cosig)

	if _, ok := w.Logs()[other.Origin]; !ok {
		t.Errorf("Logs() = %v, want it to list the newly seen origin", w.Logs())
	}
}

// TestUnauthenticatedSubmissionAccepted documents the deliberate protocol
// deviation: a checkpoint signed by the wrong key, or not signed at all,
// is cosigned (SECURITY.md).
func TestUnauthenticatedSubmissionAccepted(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")

	t.Run("wrong key", func(t *testing.T) {
		// same origin, different key
		imposter := newTestLog(t, testOrigin)
		imposter.Append("a", "b", "c")

		w, v := newTestWitness(t)

		cpNote := mustCheckpoint(t, imposter)
		cosig := mustCosign(t, w, 0, nil, cpNote)
		verifyCosig(t, v, cpNote, cosig)
	})

	t.Run("no signature at all", func(t *testing.T) {
		w, v := newTestWitness(t)

		unsigned := []byte(fmt.Sprintf("%s\n3\n%s\n\n", testOrigin, mustTreeHash(t, l, 3)))
		cosig := mustCosign(t, w, 0, nil, unsigned)
		verifyCosig(t, v, unsigned, cosig)
	})
}

func TestOldLargerThanCheckpoint(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c", "d", "e")
	w, _ := newTestWitness(t)

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))

	// re-checkpoint at size 3 (rewound) - synthesized to trigger old > new
	cpAt3, _, err := l.CheckpointWithHash(3, mustTreeHash(t, l, 3))
	if err != nil {
		t.Fatal(err)
	}
	code, _ := w.AddCheckpoint(EncodeAddCheckpoint(5, nil, cpAt3))
	if code != http.StatusBadRequest {
		t.Fatalf("AddCheckpoint = %d, want 400", code)
	}
}

func TestForkSameSize(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, _ := newTestWitness(t)

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))

	// same size, same signing key, different root: a forked view.
	// Reuse l's signer over a fork's root so the log signature stays valid.
	forkTree := newTestLog(t, testOrigin)
	forkTree.Append("a", "b", "X")
	forkNote := mustSignAs(t, l, forkTree, 3)

	code, _ := w.AddCheckpoint(EncodeAddCheckpoint(3, nil, forkNote))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("AddCheckpoint = %d, want 422", code)
	}
}

func TestForkGrowth(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, _ := newTestWitness(t)

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))

	// a fork that grew: the proof cannot connect our stored hash
	forkTree := newTestLog(t, testOrigin)
	forkTree.Append("a", "b", "X", "d", "e")
	forkNote := mustSignAs(t, l, forkTree, 5)
	proof := mustProveTree(t, forkTree, 5, 3)

	code, _ := w.AddCheckpoint(EncodeAddCheckpoint(3, proof, forkNote))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("AddCheckpoint = %d, want 422", code)
	}
}

func TestBadProof(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, _ := newTestWitness(t)

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))
	l.Append("d", "e")

	// tampered proof
	proof := mustProveTree(t, l, 5, 3)
	proof[0][0] ^= 0xff

	code, _ := w.AddCheckpoint(EncodeAddCheckpoint(3, proof, mustCheckpoint(t, l)))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("AddCheckpoint (tampered proof) = %d, want 422", code)
	}

	// missing proof
	code, _ = w.AddCheckpoint(EncodeAddCheckpoint(3, nil, mustCheckpoint(t, l)))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("AddCheckpoint (missing proof) = %d, want 422", code)
	}
}

func TestZeroSize(t *testing.T) {
	l := newTestLog(t, testOrigin)
	w, v := newTestWitness(t)

	cpNote, _, err := l.CheckpointWithHash(0, emptyTreeHash)
	if err != nil {
		t.Fatal(err)
	}
	cosig := mustCosign(t, w, 0, nil, cpNote)
	verifyCosig(t, v, cpNote, cosig)

	// size 0 with a non-empty-tree hash is invalid
	w2, _ := newTestWitness(t)
	bad, _, err := l.CheckpointWithHash(0, tlog.Hash(sha256.Sum256([]byte("x"))))
	if err != nil {
		t.Fatal(err)
	}

	code, _ := w2.AddCheckpoint(EncodeAddCheckpoint(0, nil, bad))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("AddCheckpoint = %d, want 422", code)
	}
}

func TestMalformedRequests(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, _ := newTestWitness(t)

	cpNote := mustCheckpoint(t, l)

	var tooManyProofLines bytes.Buffer
	tooManyProofLines.WriteString("old 0\n")
	for range maxProofLines + 1 {
		fmt.Fprintln(&tooManyProofLines, tlog.Hash{})
	}
	tooManyProofLines.WriteString("\n")
	tooManyProofLines.Write(cpNote)

	for name, body := range map[string][]byte{
		"empty":              nil,
		"no old line":        []byte("3\n\n" + string(cpNote)),
		"negative old":       []byte("old -1\n\n" + string(cpNote)),
		"non-canonical old":  []byte("old 03\n\n" + string(cpNote)),
		"bad proof hash":     []byte("old 0\nnot-a-hash\n\n" + string(cpNote)),
		"missing checkpoint": []byte("old 0\n"),
		"empty checkpoint":   []byte("old 0\n\n"),
		"unsigned note":      []byte("old 0\n\n" + testOrigin + "\n3\n" + tlog.Hash{}.String() + "\n"),
		"too many proofs":    tooManyProofLines.Bytes(),
	} {
		code, _ := w.AddCheckpoint(body)
		if code != http.StatusBadRequest {
			t.Errorf("%s: AddCheckpoint = %d, want 400", name, code)
		}
	}
}

func TestCosignatureName(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a")
	w, _ := newTestWitness(t)

	cosig := mustCosign(t, w, 0, nil, mustCheckpoint(t, l))
	if !bytes.Contains(cosig, []byte(testWitnessName)) {
		t.Errorf("cosignature %q does not carry the witness key name", cosig)
	}
}

func TestVerifierAndLogs(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b")
	w, _ := newTestWitness(t)

	if v := w.Verifier(); v == "" {
		t.Error("Verifier() is empty")
	}

	if got := w.Logs()[testOrigin].Size; got != 0 {
		t.Errorf("Logs()[%q].Size = %d before submission, want 0", testOrigin, got)
	}

	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))

	if got := w.Logs()[testOrigin].Size; got != 2 {
		t.Errorf("Logs()[%q].Size = %d, want 2", testOrigin, got)
	}
}

func TestUnprovisioned(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a")
	w, _ := newTestWitness(t)

	// after ClearSigner, submissions are refused and Verifier is empty
	w.ClearSigner()

	if w.Provisioned() {
		t.Error("Provisioned() = true after ClearSigner")
	}
	if v := w.Verifier(); v != "" {
		t.Errorf("Verifier() = %q after ClearSigner, want empty", v)
	}

	code, resp := w.AddCheckpoint(EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l)))
	if code != http.StatusServiceUnavailable {
		t.Fatalf("AddCheckpoint = %d, want 503", code)
	}
	if !bytes.Contains(resp, []byte("not provisioned")) {
		t.Errorf("503 body = %q, want a 'not provisioned' explanation", resp)
	}

	// re-provisioning brings the witness back up
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := torchwood.NewCosignatureSigner(testWitnessName, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	w.SetSigner(signer)

	if !w.Provisioned() {
		t.Error("Provisioned() = false after SetSigner")
	}
	mustCosign(t, w, 0, nil, mustCheckpoint(t, l))
}

func TestStoreFailureWithholdsCosignature(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a")
	w, _ := newTestWitness(t)
	w.store = failStore{}

	code, resp := w.AddCheckpoint(EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l)))
	if code != http.StatusInternalServerError {
		t.Fatalf("AddCheckpoint = %d, want 500", code)
	}
	if len(resp) != 0 {
		t.Errorf("cosignature released despite store failure: %q", resp)
	}
}

func TestPoolCommitsMultipleOriginsAsOneBatch(t *testing.T) {
	store := &countStore{MemStore: NewMemStore()}
	w, v := newTestWitnessWithStore(t, store)

	logA := newTestLog(t, "a.vitrum.invalid/log")
	logA.Append("a")
	logB := newTestLog(t, "b.vitrum.invalid/log")
	logB.Append("b")
	noteA, noteB := mustCheckpoint(t, logA), mustCheckpoint(t, logB)

	type response struct {
		code int
		body []byte
		note []byte
	}
	responses := make(chan response, 2)
	for _, cpNote := range [][]byte{noteA, noteB} {
		go func() {
			code, body := w.AddCheckpoint(EncodeAddCheckpoint(0, nil, cpNote))
			responses <- response{code, body, cpNote}
		}()
	}
	waitForPoolSize(t, w, 2)
	w.sequence()

	for range 2 {
		resp := <-responses
		if resp.code != http.StatusOK {
			t.Fatalf("AddCheckpoint = %d (%q), want 200", resp.code, resp.body)
		}
		verifyCosig(t, v, resp.note, resp.body)
	}
	if store.batches != 1 || store.entries != 2 {
		t.Fatalf("store commits = %d batches, %d entries; want 1 batch, 2 entries", store.batches, store.entries)
	}

	w.sequence()
	if store.batches != 1 {
		t.Fatalf("empty sequence committed another batch: %d", store.batches)
	}
}

func TestPoolDeduplicatesPendingCheckpoint(t *testing.T) {
	store := &countStore{MemStore: NewMemStore()}
	w, _ := newTestWitnessWithStore(t, store)
	l := newTestLog(t, testOrigin)
	l.Append("a")
	body := EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l))

	responses := make(chan result, 2)
	for range 2 {
		go func() {
			code, resp := w.AddCheckpoint(body)
			responses <- result{code, resp}
		}()
	}
	waitForPoolSize(t, w, 1)
	w.sequence()

	a, b := <-responses, <-responses
	if a.code != http.StatusOK || b.code != http.StatusOK || !bytes.Equal(a.resp, b.resp) {
		t.Fatalf("duplicate results = (%d, %q), (%d, %q)", a.code, a.resp, b.code, b.resp)
	}
	if store.batches != 1 || store.entries != 1 {
		t.Fatalf("store commits = %d batches, %d entries; want 1 batch, 1 entry", store.batches, store.entries)
	}
}

func TestPoolRefusesDifferentCheckpointForPendingOrigin(t *testing.T) {
	w, _ := newTestWitnessWithStore(t, NewMemStore())
	l := newTestLog(t, testOrigin)
	l.Append("a")
	first := EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l))
	l.Append("b")
	second := EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l))

	done := make(chan struct{})
	go func() {
		w.AddCheckpoint(first)
		close(done)
	}()
	waitForPoolSize(t, w, 1)
	if code, resp := w.AddCheckpoint(second); code != http.StatusConflict || string(resp) != "0\n" {
		t.Fatalf("second checkpoint = %d (%q), want 409 (0)", code, resp)
	}
	w.sequence()
	<-done
}

func TestPoolWithholdsResponsesAndDeduplicatesWhilePersisting(t *testing.T) {
	store := &blockingStore{
		MemStore: NewMemStore(),
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	w, _ := newTestWitnessWithStore(t, store)
	l := newTestLog(t, testOrigin)
	l.Append("a")
	body := EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l))

	responses := make(chan result, 2)
	go func() {
		code, resp := w.AddCheckpoint(body)
		responses <- result{code, resp}
	}()
	waitForPoolSize(t, w, 1)
	sequenceDone := make(chan struct{})
	go func() {
		w.sequence()
		close(sequenceDone)
	}()
	<-store.entered

	// The first request is waiting on persistence. An identical request
	// must find the detached pool and wait on the same result.
	go func() {
		code, resp := w.AddCheckpoint(body)
		responses <- result{code, resp}
	}()
	select {
	case resp := <-responses:
		t.Fatalf("response escaped before persistence: %d (%q)", resp.code, resp.resp)
	case <-time.After(10 * time.Millisecond):
	}

	close(store.release)
	<-sequenceDone
	a, b := <-responses, <-responses
	if a.code != http.StatusOK || b.code != http.StatusOK || !bytes.Equal(a.resp, b.resp) {
		t.Fatalf("in-flight duplicate results = (%d, %q), (%d, %q)", a.code, a.resp, b.code, b.resp)
	}
	if store.batches != 1 || store.entries != 1 {
		t.Fatalf("store commits = %d batches, %d entries; want 1 batch, 1 entry", store.batches, store.entries)
	}
}

func TestPoolFailureRejectsWholeBatch(t *testing.T) {
	w, _ := newTestWitnessWithStore(t, failStore{})
	responses := make(chan result, 2)
	for i := range 2 {
		l := newTestLog(t, fmt.Sprintf("failure-%d.vitrum.invalid/log", i))
		l.Append("a")
		body := EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l))
		go func() {
			code, resp := w.AddCheckpoint(body)
			responses <- result{code, resp}
		}()
	}
	waitForPoolSize(t, w, 2)
	w.sequence()

	for range 2 {
		resp := <-responses
		if resp.code != http.StatusInternalServerError || len(resp.resp) != 0 {
			t.Fatalf("failed batch response = %d (%q), want empty 500", resp.code, resp.resp)
		}
	}
	if got := w.Logs(); len(got) != 0 {
		t.Fatalf("failed batch published state: %v", got)
	}
}

func TestPoolRejectsCheckpointAfterSignerChange(t *testing.T) {
	store := NewMemStore()
	w, _ := newTestWitnessWithStore(t, store)
	l := newTestLog(t, testOrigin)
	l.Append("a")
	body := EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l))

	response := make(chan result, 1)
	go func() {
		code, resp := w.AddCheckpoint(body)
		response <- result{code, resp}
	}()
	waitForPoolSize(t, w, 1)
	w.SetSigner(newTestSigner(t))
	w.sequence()

	resp := <-response
	if resp.code != http.StatusServiceUnavailable || !bytes.Contains(resp.resp, []byte("key changed")) {
		t.Fatalf("pending checkpoint after signer change = %d (%q), want key-changed 503", resp.code, resp.resp)
	}
	if got := store.All(); len(got) != 0 {
		t.Fatalf("signer-invalidated checkpoint published state: %v", got)
	}
}

func TestPoolCapacity(t *testing.T) {
	w, _ := newTestWitnessWithStore(t, NewMemStore())
	signer := w.signer.Load()
	epoch := w.epoch.Load()

	w.poolMu.Lock()
	defer w.poolMu.Unlock()
	var first *candidate
	for i := range maxPoolSize {
		origin := fmt.Sprintf("capacity-%d.vitrum.invalid/log", i)
		text := []byte(fmt.Sprintf("%s\n0\n%s\n", origin, emptyTreeHash))
		c := &candidate{
			cp:     torchwood.Checkpoint{Origin: origin, Tree: tlog.Tree{N: 0, Hash: emptyTreeHash}},
			text:   text,
			signer: signer,
			epoch:  epoch,
		}
		entry, code, resp := w.addToPool(&request{}, c)
		if entry == nil || code != 0 || resp != nil {
			t.Fatalf("candidate %d admission = entry %v, %d (%q)", i, entry != nil, code, resp)
		}
		if i == 0 {
			first = c
		}
	}

	// Existing work remains deduplicatable even when the pool is full.
	if entry, code, _ := w.addToPool(&request{}, first); entry == nil || code != 0 {
		t.Fatalf("duplicate at capacity = entry %v, code %d", entry != nil, code)
	}
	extraOrigin := "capacity-extra.vitrum.invalid/log"
	extra := &candidate{
		cp:     torchwood.Checkpoint{Origin: extraOrigin, Tree: tlog.Tree{N: 0, Hash: emptyTreeHash}},
		text:   []byte(fmt.Sprintf("%s\n0\n%s\n", extraOrigin, emptyTreeHash)),
		signer: signer,
		epoch:  epoch,
	}
	if entry, code, _ := w.addToPool(&request{}, extra); entry != nil || code != http.StatusTooManyRequests {
		t.Fatalf("extra candidate = entry %v, code %d; want nil, 429", entry != nil, code)
	}
}

type countStore struct {
	*MemStore
	batches int
	entries int
}

type blockingStore struct {
	*MemStore
	entered chan struct{}
	release chan struct{}
	batches int
	entries int
}

func (s *blockingStore) PutBatch(states map[string]LogState) error {
	s.batches++
	s.entries += len(states)
	close(s.entered)
	<-s.release
	return s.MemStore.PutBatch(states)
}

func (s *countStore) PutBatch(states map[string]LogState) error {
	s.batches++
	s.entries += len(states)
	return s.MemStore.PutBatch(states)
}

func newTestWitnessWithStore(t *testing.T, store Store) (*Witness, *torchwood.CosignatureVerifier) {
	t.Helper()
	signer := newTestSigner(t)
	w := New(store)
	w.SetSigner(signer)
	return w, signer.Verifier()
}

func newTestSigner(t *testing.T) *torchwood.CosignatureSigner {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := torchwood.NewCosignatureSigner(testWitnessName, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	return signer
}

func waitForPoolSize(t *testing.T, w *Witness, size int) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		w.poolMu.Lock()
		got := len(w.currentPool.entries)
		w.poolMu.Unlock()
		if got == size {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("checkpoint pool did not reach size %d", size)
}

// TestConcurrentSubmitAndProvisionChurn fans submissions in against
// provision/deprovision churn (run with -race to check the signer
// lifecycle). Every response must be a clean protocol outcome; the signer
// re-load under the witness lock is what keeps a cleared key from signing.
func TestConcurrentSubmitAndProvisionChurn(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	signer, err := torchwood.NewCosignatureSigner(testWitnessName, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	v := signer.Verifier()

	w := New(NewMemStore())
	w.SetSigner(signer)
	runTestSequencer(t, w)

	cpNote := mustCheckpoint(t, l)
	body := EncodeAddCheckpoint(0, nil, cpNote)

	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				switch code, resp := w.AddCheckpoint(body); code {
				case http.StatusOK:
					verifyCosig(t, v, cpNote, resp)
				case http.StatusConflict, http.StatusServiceUnavailable:
				default:
					t.Errorf("AddCheckpoint = %d (%q)", code, resp)
				}
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 50 {
			w.ClearSigner()
			w.SetSigner(signer)
		}
	}()

	wg.Wait()
}

// TestRestoreNoteRejects verifies that re-admission checks structure only:
// malformed notes are refused, and signatures are never re-verified.
func TestRestoreNoteRejects(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")

	valid := mustCheckpoint(t, l)

	cases := map[string][]byte{
		"no signature separator": []byte("garbage with no separator"),
		"invalid checkpoint":     []byte("not-a-checkpoint\n\n— k AAAABBBB\n"),
	}

	for name, noteBytes := range cases {
		if _, _, err := RestoreNote(noteBytes); err == nil {
			t.Errorf("%s: RestoreNote accepted the note", name)
		}
	}

	// The valid note still restores (guards against an over-strict table).
	if origin, st, err := RestoreNote(valid); err != nil || origin != testOrigin || st.Size != 3 {
		t.Fatalf("RestoreNote(valid) = %q size=%d err=%v, want %q size=3", origin, st.Size, err, testOrigin)
	}

	// A note whose text no longer matches any signature restores anyway:
	// by the time RestoreNote runs, the bytes were authenticated by the
	// blob layer, so only structure matters.
	tampered := bytes.Replace(valid, []byte("\n3\n"), []byte("\n4\n"), 1)
	if origin, st, err := RestoreNote(tampered); err != nil || origin != testOrigin || st.Size != 4 {
		t.Fatalf("RestoreNote(tampered) = %q size=%d err=%v, want %q size=4 (no signature check)",
			origin, st.Size, err, testOrigin)
	}
}

// TestCheckpointNoState: an origin with nothing submitted yet has no
// checkpoint to serve.
func TestCheckpointNoState(t *testing.T) {
	w, _ := newTestWitness(t)

	h := sha256.Sum256([]byte(testOrigin))
	if _, ok := w.Checkpoint(hex.EncodeToString(h[:])); ok {
		t.Fatal("Checkpoint returned state for a never-submitted origin")
	}
}

// TestBadCheckpointTextRejected: a well-framed signed note whose text is not
// a checkpoint is malformed (400), before any signature verification.
func TestBadCheckpointTextRejected(t *testing.T) {
	w, _ := newTestWitness(t)

	body := EncodeAddCheckpoint(0, nil, []byte("not-a-checkpoint\n\n— k AAAABBBB\n"))
	if code, resp := w.AddCheckpoint(body); code != http.StatusBadRequest {
		t.Fatalf("AddCheckpoint = %d (%q), want 400", code, resp)
	}
}

// TestFirstSightingWithProofRejected: a first sighting (old 0) has nothing to
// be consistent with, so proof lines are unprocessable (422).
func TestFirstSightingWithProofRejected(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, _ := newTestWitness(t)

	code, resp := w.AddCheckpoint(EncodeAddCheckpoint(0, tlog.TreeProof{tlog.Hash{}}, mustCheckpoint(t, l)))
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("AddCheckpoint = %d (%q), want 422", code, resp)
	}
}

const (
	testOrigin      = "test.vitrum.invalid/log"
	testWitnessName = "witness.vitrum.invalid"
)

func newTestLog(t *testing.T, origin string) *testlog.Log {
	t.Helper()

	l, err := testlog.New(rand.Reader, origin)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func mustCheckpoint(t *testing.T, l *testlog.Log) []byte {
	t.Helper()

	note, _, err := l.Checkpoint()
	if err != nil {
		t.Fatal(err)
	}
	return note
}

func mustTreeHash(t *testing.T, l *testlog.Log, size int64) tlog.Hash {
	t.Helper()

	th, err := l.TreeHash(size)
	if err != nil {
		t.Fatal(err)
	}
	return th
}

func mustProveTree(t *testing.T, l *testlog.Log, newer, older int64) tlog.TreeProof {
	t.Helper()

	p, err := l.ProveTree(newer, older)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// mustSignAs signs `size` and the root of `over` under `l`'s key, so tests
// can synthesize forks that still verify as coming from l.
func mustSignAs(t *testing.T, l *testlog.Log, over *testlog.Log, size int64) []byte {
	t.Helper()

	root, err := over.TreeHash(size)
	if err != nil {
		t.Fatal(err)
	}
	signed, _, err := l.CheckpointWithHash(size, root)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func newTestWitness(t *testing.T) (*Witness, *torchwood.CosignatureVerifier) {
	t.Helper()
	w, verifier := newTestWitnessWithStore(t, NewMemStore())
	runTestSequencer(t, w)

	return w, verifier
}

func runTestSequencer(t *testing.T, w *Witness) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go w.RunSequencer(ctx, time.Millisecond)
}

// mustCosign submits and asserts 200, returning the cosignature lines.
func mustCosign(t *testing.T, w *Witness, old int64, proof tlog.TreeProof, cpNote []byte) []byte {
	t.Helper()

	code, resp := w.AddCheckpoint(EncodeAddCheckpoint(old, proof, cpNote))
	if code != http.StatusOK {
		t.Fatalf("AddCheckpoint = %d (%q), want 200", code, resp)
	}
	return resp
}

// verifyCosig checks the returned cosignature lines against the submitted
// checkpoint note and returns the cosignature timestamp.
func verifyCosig(t *testing.T, v *torchwood.CosignatureVerifier, cpNote, cosig []byte) int64 {
	t.Helper()

	full := append(bytes.Clone(cpNote), cosig...)

	n, err := note.Open(full, note.VerifierList(v))
	if err != nil {
		t.Fatalf("cosignature does not verify: %v", err)
	}

	for _, sig := range n.Sigs {
		if sig.Name == v.Name() {
			ts, err := torchwood.CosignatureTimestamp(sig)
			if err != nil {
				t.Fatalf("CosignatureTimestamp: %v", err)
			}
			return ts
		}
	}

	t.Fatal("cosignature missing from verified note")
	return 0
}

type failStore struct{}

func (failStore) Get(string) (LogState, bool)        { return LogState{}, false }
func (failStore) PutBatch(map[string]LogState) error { return fmt.Errorf("store failed") }
func (failStore) All() map[string]LogState           { return nil }
