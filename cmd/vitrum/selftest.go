package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/cpu/vitrum/internal/config"
	"github.com/cpu/vitrum/internal/testlog"
	"github.com/cpu/vitrum/internal/witness"
)

// cmdSelftest verifies witness wiring end-to-end without needing a live
// external log.
//
// It synthesizes checkpoints locally, submits them, and checks that
// cosignatures verify and consistency violations are refused.
func cmdSelftest(args []string) {
	fs := flag.NewFlagSet("selftest", flag.ExitOnError)
	witnessURL := fs.String("witness", "http://127.0.0.1:8080", "witness base URL")
	seed := fs.String("seed", config.SelftestSeed, "synthetic log key seed")
	fs.Parse(args)

	l, err := newSelftestLog(*seed, config.SelftestOrigin)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("selftest log: %s (vkey %s)", config.SelftestOrigin, l.VKey)

	wc := newWitnessClient(*witnessURL)

	// The witness must already be provisioned (and its clock set) via
	// `vitrum provision`. selftest only drives the HTTP endpoint.

	// discover the witness's cosignature verifier key
	health, err := wc.healthz()
	if err != nil {
		log.Fatal(err)
	}
	wvkey, _ := health["witness_key"].(string)
	if wvkey == "" {
		log.Fatal("witness /healthz did not report a witness_key")
	}

	verifier, err := torchwood.NewCosignatureVerifier(wvkey)
	if err != nil {
		log.Fatal(err)
	}

	if err := l.Append("a", "b", "c"); err != nil {
		log.Fatal(err)
	}

	must := func(step string, expected int, old int64, proof tlog.TreeProof, cpNote []byte) []byte {
		code, resp, err := wc.submit(witness.EncodeAddCheckpoint(old, proof, cpNote))
		if err != nil {
			log.Fatalf("%s: %v", step, err)
		}
		if code != expected {
			log.Fatalf("%s: got %d, want %d (body %q)", step, code, expected, resp)
		}
		fmt.Printf("PASS: %s (%d)\n", step, code)

		return resp
	}

	cp1Note, cp1, err := l.Checkpoint()
	if err != nil {
		log.Fatal(err)
	}

	cosig := must("submit@3, first sighting", http.StatusOK, 0, nil, cp1Note)

	ts, err := verifyCosignature(verifier, cp1Note, cosig)
	if err != nil {
		log.Fatalf("cosignature: %v", err)
	}
	fmt.Printf("PASS: cosignature verified, timestamp=%s\n",
		time.Unix(ts, 0).UTC().Format(time.RFC3339))

	// stale replay should get 409 with our current size
	code, resp, err := wc.submit(witness.EncodeAddCheckpoint(0, nil, cp1Note))
	if err != nil {
		log.Fatal(err)
	}
	if code != http.StatusConflict {
		log.Fatalf("stale replay: got %d, want 409", code)
	}
	if strings.TrimSpace(string(resp)) != strconv.FormatInt(cp1.N, 10) {
		log.Fatalf("stale replay body = %q, want %d", resp, cp1.N)
	}
	fmt.Printf("PASS: stale replay 409 with body %q\n", resp)

	// grow the log and submit a real consistency proof
	if err := l.Append("d", "e"); err != nil {
		log.Fatal(err)
	}
	cp2Note, cp2, err := l.Checkpoint()
	if err != nil {
		log.Fatal(err)
	}
	proof, err := l.ProveTree(cp2.N, cp1.N)
	if err != nil {
		log.Fatal(err)
	}
	must("submit@5, growth with proof", http.StatusOK, cp1.N, proof, cp2Note)

	// consistency violation: submit a fork that grows past our current
	// state. The proof will not connect the stored hash to the fork.
	fork, err := newSelftestLog(*seed+"-fork", config.SelftestOrigin)
	if err != nil {
		log.Fatal(err)
	}
	fork.Append("a", "b", "X", "d", "e", "f", "g")
	_, forkCP, err := fork.Checkpoint()
	if err != nil {
		log.Fatal(err)
	}
	forkProof, err := fork.ProveTree(forkCP.N, cp2.N)
	if err != nil {
		log.Fatal(err)
	}
	// re-sign the fork's root with the real log's key so the log signature
	// is valid, modeling a log that equivocates about its own tree
	forkRoot, err := fork.TreeHash(forkCP.N)
	if err != nil {
		log.Fatal(err)
	}
	forkNote, _, err := signAs(l, forkCP.N, forkRoot)
	if err != nil {
		log.Fatal(err)
	}
	must("fork growth refused", http.StatusUnprocessableEntity, cp2.N, forkProof, forkNote)

	// There is no origin allowlist (SECURITY.md): a never-seen origin is
	// cosigned on first sighting, and the cosignature verifies.
	orig := []byte("unknown.invalid/log")
	freshNote := bytes.Replace(cp1Note, []byte(config.SelftestOrigin), orig, 1)
	freshCosig := must("fresh origin cosigned on first sighting", http.StatusOK, 0, nil, freshNote)
	if _, err := verifyCosignature(verifier, freshNote, freshCosig); err != nil {
		log.Fatalf("fresh-origin cosignature: %v", err)
	}

	fmt.Printf("\nvitrum selftest: OK\n")
}

// newSelftestLog derives a testlog.Log from a text seed, so repeated runs
// produce the same log keypair without checked-in key material.
func newSelftestLog(seed, origin string) (*testlog.Log, error) {
	return testlog.New(testlog.NewSeedReader(seed), origin)
}

// signAs signs (size, root) as if `l` had produced it, to craft a bad-view
// checkpoint that has a valid log signature but disagrees with the honest
// tree.
func signAs(l *testlog.Log, size int64, root tlog.Hash) ([]byte, torchwood.Checkpoint, error) {
	cp := torchwood.Checkpoint{Origin: l.Origin, Tree: tlog.Tree{N: size, Hash: root}}
	signed, err := note.Sign(&note.Note{Text: cp.String()}, l.Signer)
	return signed, cp, err
}
