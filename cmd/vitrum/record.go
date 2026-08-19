package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/cpu/vitrum/internal/witness"
)

// cmdRecord captures live checkpoints from a log as deterministic witness
// test fixtures, including synthetic violation cases a live honest log
// never produces.
func cmdRecord(args []string) {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	logName := fs.String("log-name", "", "fetchable log handle to look up (alternative to -log/-origin/-log-key)")
	logURL := fs.String("log", "", "log monitoring prefix URL")
	origin := fs.String("origin", "", "log origin line")
	logKey := fs.String("log-key", "", "log verifier key")
	outDir := fs.String("o", "", "output directory (default internal/witness/testdata/<origin>)")
	wait := fs.Duration("wait", 2*time.Minute, "how long to wait for the log to grow")
	poll := fs.Duration("poll", 10*time.Second, "growth poll interval")
	fs.Parse(args)

	logCfg, err := resolveLog(*logName, *logURL, *origin, *logKey)
	if err != nil {
		log.Fatalf("record: %v", err)
	}

	if *outDir == "" {
		safe := strings.NewReplacer("/", "_", ":", "_").Replace(logCfg.Origin)
		*outDir = filepath.Join("internal", "witness", "testdata", safe)
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		log.Fatal(err)
	}

	ctx := context.Background()

	lc, err := newLogClient(logCfg.MonitoringURL, logCfg.Origin, logCfg.VKey)
	if err != nil {
		log.Fatal(err)
	}

	manifest := fixtureManifest{Origin: logCfg.Origin, VKey: logCfg.VKey}

	step := func(name string, status int, body []byte) {
		file := name + ".req"
		if err := os.WriteFile(filepath.Join(*outDir, file), body, 0o644); err != nil {
			log.Fatal(err)
		}
		manifest.Steps = append(manifest.Steps, fixtureStep{File: file, Status: status})
		log.Printf("recorded %s (expect %d)", file, status)
	}

	cp1, cpNote1, err := lc.checkpoint(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("checkpoint 1: size %d", cp1.N)

	// first sighting, then idempotent re-submission
	step("00-first", http.StatusOK, witness.EncodeAddCheckpoint(0, nil, cpNote1))
	step("01-resubmit", http.StatusOK, witness.EncodeAddCheckpoint(cp1.N, nil, cpNote1))

	// wait for the log to grow so a real consistency proof exists
	cp2, cpNote2 := cp1, cpNote1
	for deadline := time.Now().Add(*wait); cp2.N <= cp1.N; {
		if time.Now().After(deadline) {
			log.Printf("log did not grow within %s; skipping proof fixtures", wait)
			break
		}
		time.Sleep(*poll)

		if cp2, cpNote2, err = lc.checkpoint(ctx); err != nil {
			log.Fatal(err)
		}
	}

	if cp2.N > cp1.N {
		log.Printf("checkpoint 2: size %d", cp2.N)

		proof, err := lc.proveTree(ctx, cp2, cp1.N)
		if err != nil {
			log.Fatal(err)
		}

		// Submit a tampered proof first when the proof is non-empty.
		if len(proof) > 0 {
			bad := slices.Clone(proof)
			bad[0][0] ^= 0xff
			step("02-badproof", http.StatusUnprocessableEntity, witness.EncodeAddCheckpoint(cp1.N, bad, cpNote2))
		}
		step("03-grow", http.StatusOK, witness.EncodeAddCheckpoint(cp1.N, proof, cpNote2))
	}

	// stale replay of the first submission
	step("99-stale", http.StatusConflict, witness.EncodeAddCheckpoint(0, nil, cpNote1))

	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "manifest.json"), append(data, '\n'), 0o644); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("fixtures written to %s\n", *outDir)
}

// fixtureManifest describes a recorded fixture sequence: request bodies
// replayed in order against a fresh witness must produce the listed
// statuses. Mirrored by internal/witness's fixture test.
type fixtureManifest struct {
	Origin string        `json:"origin"`
	VKey   string        `json:"vkey"`
	Steps  []fixtureStep `json:"steps"`
}

type fixtureStep struct {
	File   string `json:"file"`
	Status int    `json:"status"`
}
