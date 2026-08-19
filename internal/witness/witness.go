// Package witness implements the server side of the c2sp.org/tlog-witness
// protocol.
//
// It verifies a submitted checkpoint for consistency against the last known
// view of the log, cosigns it per c2sp.org/tlog-cosignature, and remembers
// the new view.
//
// Deviation from c2sp.org/tlog-witness: submissions are NOT authenticated,
// there is NO origin allowlist, and log signatures are never verified (the
// protocol's 403 and unknown-log 404 outcomes never occur). The witness
// enforces one property, per-origin consistency, and trusts everything that
// can reach it for the rest. See SECURITY.md for the analysis, the accepted
// risks, and the invariants this trade rests on.
package witness

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

const (
	// MaxRequestSize bounds an add-checkpoint request body.
	MaxRequestSize = 64 * 1024

	// maxProofLines is the c2sp.org/tlog-witness limit on consistency
	// proof hashes per request.
	maxProofLines = 63

	// SequencerPeriod is the maximum frequency of persistent state commits.
	SequencerPeriod = 200 * time.Millisecond

	// maxPoolSize bounds the number of distinct origins waiting for a commit.
	maxPoolSize = 256
)

// LogState is the witness's view of a single log.
type LogState struct {
	Size int64
	Hash tlog.Hash

	// Note is the full serialized note for the latest cosigned checkpoint
	// (checkpoint text plus our cosignature), served verbatim by the
	// monitoring endpoint. Submitted log signatures are never stored.
	Note []byte
}

// Store persists per-log state. PutBatch must atomically commit every state
// before any cosignature over the batch is released to a client.
type Store interface {
	Get(origin string) (LogState, bool)
	PutBatch(states map[string]LogState) error
	All() map[string]LogState
}

// HaltableStore is an optional Store capability: a store that has detected
// rollback or tamper evidence and refuses to advance. The witness refuses to
// cosign while Halted reports true. Persistent, rollback-protected stores
// implement it; the in-RAM store does not (nothing to roll back).
type HaltableStore interface {
	Halted() bool
}

// Halted reports whether the store has refused to serve due to rollback or
// tamper evidence.
func (w *Witness) Halted() bool {
	h, ok := w.store.(HaltableStore)
	return ok && h.Halted()
}

// MemStore is an in-RAM Store.
type MemStore struct {
	mu     sync.RWMutex
	states map[string]LogState
}

func NewMemStore() *MemStore {
	return &MemStore{states: make(map[string]LogState)}
}

func (m *MemStore) Get(origin string) (LogState, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.states[origin]
	return s, ok
}

func (m *MemStore) PutBatch(states map[string]LogState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for origin, s := range states {
		m.states[origin] = s
	}
	return nil
}

func (m *MemStore) All() map[string]LogState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := make(map[string]LogState, len(m.states))
	for k, v := range m.states {
		all[k] = v
	}
	return all
}

// Witness verifies and cosigns checkpoints for any origin, enforcing only
// per-origin consistency.
//
// A Witness starts unprovisioned: submissions are refused with 503 until
// SetSigner installs a cosignature key (over the provisioning channel).
type Witness struct {
	signer atomic.Pointer[torchwood.CosignatureSigner]
	epoch  atomic.Uint64
	store  Store

	// mu serializes signer changes with batch signing and persistence.
	mu sync.Mutex

	poolMu       sync.Mutex
	currentPool  *pool
	inSequencing map[string]*poolEntry
	running      atomic.Bool
}

func New(store Store) *Witness {
	return &Witness{store: store, currentPool: newPool()}
}

// SetSigner installs the witness cosignature key, bringing the witness up.
//
// It serializes with in-flight submissions: once SetSigner returns, no
// signing operation can still be reading a previously installed signer, so
// the caller may destroy that key's material.
func (w *Witness) SetSigner(s *torchwood.CosignatureSigner) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.signer.Store(s)
	w.epoch.Add(1)
}

// ClearSigner de-provisions the witness.
//
// Submissions are refused until the next SetSigner. Like SetSigner it
// serializes with in-flight submissions; the caller owns (and zeroes) the
// underlying key material once it returns.
func (w *Witness) ClearSigner() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.signer.Store(nil)
	w.epoch.Add(1)
}

// Provisioned reports whether a signer is installed.
func (w *Witness) Provisioned() bool {
	return w.signer.Load() != nil
}

// Verifier returns the cosignature verifier key for this witness, or ""
// when unprovisioned.
func (w *Witness) Verifier() string {
	s := w.signer.Load()
	if s == nil {
		return ""
	}

	return s.Verifier().String()
}

// Logs returns the current state of every log seen so far, keyed by origin.
//
// There is no configured log set; an origin appears here once a checkpoint
// for it has been cosigned.
func (w *Witness) Logs() map[string]LogState {
	return w.store.All()
}

// Checkpoint returns the latest cosigned checkpoint note for the log whose
// origin has the given lowercase hex SHA-256 hash.
func (w *Witness) Checkpoint(originHash string) ([]byte, bool) {
	for origin, s := range w.store.All() {
		h := sha256.Sum256([]byte(origin))
		if hex.EncodeToString(h[:]) == originHash {
			return s.Note, true
		}
	}

	return nil, false
}

// RestoreNote re-admits a persisted cosigned checkpoint note, converting it
// to a LogState keyed by the returned origin.
//
// Only structure is checked; the integrity of persisted state comes from
// the authenticated blob layer (see internal/state), not from re-verifying
// signatures.
func RestoreNote(noteBytes []byte) (string, LogState, error) {
	sep := bytes.Index(noteBytes, []byte("\n\n"))
	if sep < 0 {
		return "", LogState{}, errors.New("not a signed note")
	}
	text := noteBytes[:sep+1]

	cp, err := torchwood.ParseCheckpoint(string(text))
	if err != nil {
		return "", LogState{}, err
	}

	return cp.Origin, LogState{
		Size: cp.N,
		Hash: cp.Hash,
		Note: bytes.Clone(noteBytes),
	}, nil
}

type request struct {
	old   int64
	proof tlog.TreeProof
	note  []byte // signed checkpoint note, verbatim
}

type candidate struct {
	cp     torchwood.Checkpoint
	text   []byte
	signer *torchwood.CosignatureSigner
	epoch  uint64
}

type result struct {
	code int
	resp []byte
}

type poolEntry struct {
	candidate *candidate
	done      chan struct{}
	result    result
}

type pool struct {
	entries map[string]*poolEntry
}

func newPool() *pool {
	return &pool{entries: make(map[string]*poolEntry)}
}

func parseRequest(body []byte) (*request, error) {
	line, rest, ok := bytes.Cut(body, []byte("\n"))
	if !ok {
		return nil, errors.New("malformed request: missing old size line")
	}

	sizeStr, ok := strings.CutPrefix(string(line), "old ")
	if !ok {
		return nil, errors.New("malformed request: first line must be \"old <size>\"")
	}

	old, err := strconv.ParseInt(sizeStr, 10, 64)
	if err != nil || old < 0 || sizeStr != strconv.FormatInt(old, 10) {
		return nil, errors.New("malformed request: invalid old size")
	}

	var proof tlog.TreeProof

	for {
		line, rest, ok = bytes.Cut(rest, []byte("\n"))
		if !ok {
			return nil, errors.New("malformed request: missing checkpoint")
		}

		if len(line) == 0 {
			break
		}

		if len(proof) == maxProofLines {
			return nil, fmt.Errorf("malformed request: more than %d proof lines", maxProofLines)
		}

		h, err := tlog.ParseHash(string(line))
		if err != nil {
			return nil, errors.New("malformed request: invalid proof hash")
		}

		proof = append(proof, h)
	}

	if len(rest) == 0 {
		return nil, errors.New("malformed request: empty checkpoint")
	}

	return &request{old: old, proof: proof, note: rest}, nil
}

// AddCheckpoint implements the c2sp.org/tlog-witness add-checkpoint state
// machine.
//
// It returns the HTTP status code and response body.
func (w *Witness) AddCheckpoint(body []byte) (code int, resp []byte) {
	signer := w.signer.Load()
	if signer == nil {
		return http.StatusServiceUnavailable, []byte("witness key not provisioned\n")
	}

	// A halted store must never advance its view; check before doing any
	// verification work.
	if w.Halted() {
		return http.StatusServiceUnavailable, []byte("witness halted: storage rollback or tamper detected\n")
	}

	req, err := parseRequest(body)
	if err != nil {
		return http.StatusBadRequest, []byte(err.Error() + "\n")
	}

	// Split the note into checkpoint text and (ignored) signature lines.
	sep := bytes.Index(req.note, []byte("\n\n"))
	if sep < 0 {
		return http.StatusBadRequest, []byte("malformed request: not a signed note\n")
	}
	text := req.note[:sep+1]

	cp, err := torchwood.ParseCheckpoint(string(text))
	if err != nil {
		return http.StatusBadRequest, []byte("malformed request: invalid checkpoint\n")
	}

	if req.old > cp.N {
		return http.StatusBadRequest, nil
	}

	c := &candidate{cp: cp, text: bytes.Clone(text), signer: signer, epoch: w.epoch.Load()}

	w.poolMu.Lock()
	entry, code, resp := w.addToPool(req, c)
	w.poolMu.Unlock()
	if entry == nil {
		return code, resp
	}

	<-entry.done
	return entry.result.code, entry.result.resp
}

// addToPool validates and admits a candidate. w.poolMu must be held.
func (w *Witness) addToPool(req *request, c *candidate) (*poolEntry, int, []byte) {
	cp := c.cp

	if entry := w.currentPool.entries[cp.Origin]; entry != nil {
		return w.matchPending(entry, c)
	}
	if entry := w.inSequencing[cp.Origin]; entry != nil {
		return w.matchPending(entry, c)
	}
	if len(w.currentPool.entries) >= maxPoolSize {
		return nil, http.StatusTooManyRequests, []byte("checkpoint pool full\n")
	}

	prev, known := w.store.Get(cp.Origin)

	var latest int64
	if known {
		latest = prev.Size
	}

	if req.old != latest {
		resp := strconv.FormatInt(latest, 10) + "\n"
		return nil, http.StatusConflict, []byte(resp)
	}

	// The consistency checks compare against the stored hash, never
	// client input.
	switch {
	case cp.N == 0:
		if len(req.proof) != 0 || cp.Hash != emptyTreeHash {
			return nil, http.StatusUnprocessableEntity, nil
		}
	case req.old == cp.N:
		if len(req.proof) != 0 || cp.Hash != prev.Hash {
			return nil, http.StatusUnprocessableEntity, nil
		}
	case req.old == 0:
		// First sighting of this log: nothing to be consistent with.
		if len(req.proof) != 0 {
			return nil, http.StatusUnprocessableEntity, nil
		}
	default:
		if err := tlog.CheckTree(req.proof, cp.N, cp.Hash, req.old, prev.Hash); err != nil {
			return nil, http.StatusUnprocessableEntity, nil
		}
	}

	entry := &poolEntry{candidate: c, done: make(chan struct{})}
	w.currentPool.entries[cp.Origin] = entry
	return entry, 0, nil
}

func (w *Witness) matchPending(entry *poolEntry, c *candidate) (*poolEntry, int, []byte) {
	pending := entry.candidate
	if pending.signer == c.signer && pending.epoch == c.epoch && pending.cp.N == c.cp.N &&
		pending.cp.Hash == c.cp.Hash && bytes.Equal(pending.text, c.text) {
		return entry, 0, nil
	}

	prev, known := w.store.Get(c.cp.Origin)
	var latest int64
	if known {
		latest = prev.Size
	}
	return nil, http.StatusConflict, []byte(strconv.FormatInt(latest, 10) + "\n")
}

// RunSequencer commits one non-empty checkpoint pool per period.
func (w *Witness) RunSequencer(ctx context.Context, period time.Duration) error {
	if !w.running.CompareAndSwap(false, true) {
		return errors.New("witness sequencer already running")
	}
	defer w.running.Store(false)

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			w.stopPools()
			return ctx.Err()
		case <-ticker.C:
			w.sequence()
		}
	}
}

func (w *Witness) sequence() {
	w.poolMu.Lock()
	p := w.currentPool
	w.currentPool = newPool()
	w.inSequencing = p.entries
	w.poolMu.Unlock()

	w.sequencePool(p)

	w.poolMu.Lock()
	w.inSequencing = nil
	w.poolMu.Unlock()
}

func (w *Witness) sequencePool(p *pool) {
	if len(p.entries) == 0 {
		return
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	signer := w.signer.Load()
	epoch := w.epoch.Load()
	if signer == nil {
		w.finishPool(p, http.StatusServiceUnavailable, []byte("witness key not provisioned\n"))
		return
	}
	if w.Halted() {
		w.finishPool(p, http.StatusServiceUnavailable, []byte("witness halted: storage rollback or tamper detected\n"))
		return
	}

	states := make(map[string]LogState, len(p.entries))
	signFailed := false
	for origin, entry := range p.entries {
		if entry.candidate.signer != signer || entry.candidate.epoch != epoch {
			entry.result = result{http.StatusServiceUnavailable, []byte("witness key changed while checkpoint was pending\n")}
			continue
		}

		signed, err := note.Sign(&note.Note{Text: string(entry.candidate.text)}, signer)
		if err != nil {
			entry.result = result{code: http.StatusInternalServerError}
			signFailed = true
			continue
		}
		entry.result = result{code: http.StatusOK, resp: signed[len(entry.candidate.text)+1:]}
		states[origin] = LogState{
			Size: entry.candidate.cp.N,
			Hash: entry.candidate.cp.Hash,
			Note: signed,
		}
	}
	if signFailed {
		w.finishPool(p, http.StatusInternalServerError, nil)
		return
	}

	if len(states) != 0 {
		if err := w.store.PutBatch(states); err != nil {
			w.finishPool(p, http.StatusInternalServerError, nil)
			return
		}
	}
	for _, entry := range p.entries {
		close(entry.done)
	}
}

func (w *Witness) finishPool(p *pool, code int, resp []byte) {
	for _, entry := range p.entries {
		entry.result = result{code: code, resp: resp}
		close(entry.done)
	}
}

func (w *Witness) stopPools() {
	w.poolMu.Lock()
	defer w.poolMu.Unlock()
	w.finishPool(w.currentPool, http.StatusServiceUnavailable, []byte("witness sequencer stopped\n"))
	w.currentPool = newPool()
}

var emptyTreeHash = tlog.Hash(sha256.Sum256(nil))
