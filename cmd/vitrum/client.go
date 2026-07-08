package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// logClient reads checkpoints and tiles from a tlog monitoring prefix.
type logClient struct {
	origin   string
	verifier note.Verifier
	fetcher  *torchwood.TileFetcher
}

func newLogClient(monitoringURL, origin, vkey string) (*logClient, error) {
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("bad log verifier key: %w", err)
	}

	fetcher, err := torchwood.NewTileFetcher(monitoringURL)
	if err != nil {
		return nil, err
	}

	return &logClient{origin: origin, verifier: verifier, fetcher: fetcher}, nil
}

// checkpoint fetches and verifies the log's latest checkpoint, returning it
// parsed alongside the verbatim signed note.
func (c *logClient) checkpoint(ctx context.Context) (torchwood.Checkpoint, []byte, error) {
	data, err := c.fetcher.ReadEndpoint(ctx, "checkpoint")
	if err != nil {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("fetching checkpoint: %w", err)
	}

	n, err := note.Open(data, note.VerifierList(c.verifier))
	if err != nil {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("verifying log checkpoint: %w", err)
	}

	cp, err := torchwood.ParseCheckpoint(n.Text)
	if err != nil {
		return torchwood.Checkpoint{}, nil, err
	}

	if cp.Origin != c.origin {
		return torchwood.Checkpoint{}, nil, fmt.Errorf("checkpoint origin %q, expected %q", cp.Origin, c.origin)
	}

	return cp, data, nil
}

func (c *logClient) proveTree(ctx context.Context, cp torchwood.Checkpoint, older int64) (tlog.TreeProof, error) {
	hr := torchwood.TileHashReaderWithContext(ctx, cp.Tree, c.fetcher)

	proof, err := tlog.ProveTree(cp.N, older, hr)
	if err != nil {
		return nil, fmt.Errorf("building consistency proof %d -> %d: %w", older, cp.N, err)
	}

	return proof, nil
}

// witnessClient talks to a vitrum witness endpoint.
type witnessClient struct {
	base string
	hc   http.Client
}

func newWitnessClient(base string) *witnessClient {
	return &witnessClient{
		base: strings.TrimRight(base, "/"),
		hc:   http.Client{Timeout: 30 * time.Second},
	}
}

func (w *witnessClient) post(path string, body []byte) (int, []byte, error) {
	resp, err := w.hc.Post(w.base+path, "text/plain", bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(http.MaxBytesReader(nil, resp.Body, maxWitnessResponse))
	if err != nil {
		return 0, nil, err
	}

	return resp.StatusCode, data, nil
}

func (w *witnessClient) submit(body []byte) (int, []byte, error) {
	return w.post("/add-checkpoint", body)
}

func (w *witnessClient) healthz() (map[string]any, error) {
	resp, err := w.hc.Get(w.base + "/healthz")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("healthz: status %d", resp.StatusCode)
	}

	var health map[string]any
	if err := json.NewDecoder(http.MaxBytesReader(nil, resp.Body, maxWitnessResponse)).Decode(&health); err != nil {
		return nil, err
	}

	return health, nil
}

// maxWitnessResponse caps witness response bodies.
const maxWitnessResponse = 1 << 20
