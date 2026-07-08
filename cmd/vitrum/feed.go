package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/cpu/vitrum/internal/witness"
)

func cmdFeed(args []string) {
	fs := flag.NewFlagSet("feed", flag.ExitOnError)
	witnessURL := fs.String("witness", "http://10.0.0.1", "witness base URL")
	logName := fs.String("log-name", "", "fetchable log handle to look up (alternative to -log/-origin/-log-key)")
	logURL := fs.String("log", "", "log monitoring prefix URL")
	origin := fs.String("origin", "", "log origin line")
	logKey := fs.String("log-key", "", "log verifier key")
	witnessKey := fs.String("witness-key", "", "witness cosignature verifier key (default: from /healthz)")
	fs.Parse(args)

	logCfg, err := resolveLog(*logName, *logURL, *origin, *logKey)
	if err != nil {
		log.Fatalf("feed: %v", err)
	}

	ctx := context.Background()

	lc, err := newLogClient(logCfg.MonitoringURL, logCfg.Origin, logCfg.VKey)
	if err != nil {
		log.Fatal(err)
	}
	wc := newWitnessClient(*witnessURL)

	if *witnessKey == "" {
		health, err := wc.healthz()
		if err != nil {
			log.Fatalf("fetching witness key: %v", err)
		}
		k, _ := health["witness_key"].(string)
		if k == "" {
			log.Fatal("witness /healthz did not report a witness_key; pass -witness-key")
		}
		*witnessKey = k
	}

	verifier, err := torchwood.NewCosignatureVerifier(*witnessKey)
	if err != nil {
		log.Fatalf("bad witness verifier key: %v", err)
	}

	cp, cpNote, err := lc.checkpoint(ctx)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("log checkpoint: %s at size %d", cp.Origin, cp.N)

	// Try old 0 first; a 409 carries the witness's latest size, so the
	// retry can supply the right consistency proof.
	code, resp, err := wc.submit(witness.EncodeAddCheckpoint(0, nil, cpNote))
	if err != nil {
		log.Fatal(err)
	}

	if code == http.StatusConflict {
		latest, perr := strconv.ParseInt(strings.TrimSpace(string(resp)), 10, 64)
		if perr != nil {
			log.Fatalf("unparseable conflict body %q", resp)
		}
		log.Printf("witness knows size %d, building proof", latest)

		if latest > cp.N {
			log.Fatalf("witness is at size %d, ahead of the log checkpoint (%d)", latest, cp.N)
		}

		var proof tlog.TreeProof
		if latest > 0 && latest < cp.N {
			if proof, err = lc.proveTree(ctx, cp, latest); err != nil {
				log.Fatal(err)
			}
		}

		code, resp, err = wc.submit(witness.EncodeAddCheckpoint(latest, proof, cpNote))
		if err != nil {
			log.Fatal(err)
		}
	}

	if code != http.StatusOK {
		log.Fatalf("witness refused checkpoint: status %d, body %q", code, resp)
	}

	ts, err := verifyCosignature(verifier, cpNote, resp)
	if err != nil {
		log.Fatalf("cosignature: %v", err)
	}

	fmt.Printf("cosigned: %s size %d by %q at %s\n",
		cp.Origin, cp.N, verifier.Name(), time.Unix(ts, 0).UTC().Format(time.RFC3339))
}
