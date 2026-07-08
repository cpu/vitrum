package provision

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/crypto/ssh"

	"github.com/cpu/vitrum/internal/witness"
)

func TestProvisionFlow(t *testing.T) {
	h := newHarness(t)
	client, err := h.dial(t)
	if err != nil {
		t.Fatal(err)
	}

	out, err := run(t, client, "status", "")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !strings.Contains(out, "provisioned=false") {
		t.Errorf("pre-provision status = %q, want provisioned=false", out)
	}

	seedHex, wantVKey := testSeedHex(t)
	out, err = run(t, client, "provision "+testKeyName, seedHex+"\n")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if got := strings.TrimSpace(out); got != wantVKey {
		t.Errorf("provision returned %q, want %q", got, wantVKey)
	}

	if !h.w.Provisioned() {
		t.Fatal("witness unprovisioned after provision command")
	}
	if got := h.w.Verifier(); got != wantVKey {
		t.Errorf("witness verifier = %q, want %q", got, wantVKey)
	}

	out, err = run(t, client, "status", "")
	if err != nil || !strings.Contains(out, "provisioned=true") || !strings.Contains(out, wantVKey) {
		t.Errorf("post-provision status = %q (%v), want provisioned=true with verifier", out, err)
	}

	if _, err := run(t, client, "deprovision", ""); err != nil {
		t.Fatalf("deprovision: %v", err)
	}
	if h.w.Provisioned() {
		t.Error("witness still provisioned after deprovision")
	}
}

func TestProvisionBadInput(t *testing.T) {
	h := newHarness(t)
	client, err := h.dial(t)
	if err != nil {
		t.Fatal(err)
	}

	for name, stdin := range map[string]string{
		"short":     "abcd\n",
		"not hex":   strings.Repeat("zz", 32) + "\n",
		"too large": strings.Repeat("a", maxSeedInput+16),
	} {
		if _, err := run(t, client, "provision "+testKeyName, stdin); err == nil {
			t.Errorf("provision with %s seed input succeeded, want failure", name)
		}
	}

	if _, err := run(t, client, "provision", ""); err == nil {
		t.Error("provision without a key name succeeded, want usage failure")
	}

	if h.w.Provisioned() {
		t.Error("witness provisioned despite bad inputs")
	}
}

func TestSettime(t *testing.T) {
	h := newHarness(t)
	client, err := h.dial(t)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, client, "settime 1752537600", ""); err != nil {
		t.Fatalf("settime: %v", err)
	}
	if len(h.setTimes) != 1 || h.setTimes[0] != 1752537600 {
		t.Errorf("SetTime calls = %v, want [1752537600]", h.setTimes)
	}

	for _, bad := range []string{"settime", "settime abc", "settime -5"} {
		if _, err := run(t, client, bad, ""); err == nil {
			t.Errorf("%q succeeded, want failure", bad)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	h := newHarness(t)
	client, err := h.dial(t)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := run(t, client, "reboot", ""); err == nil {
		t.Error("unknown command succeeded, want failure")
	}
}

func TestShellRejected(t *testing.T) {
	h := newHarness(t)
	client, err := h.dial(t)
	if err != nil {
		t.Fatal(err)
	}

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.Shell(); err == nil {
		t.Error("shell request accepted, want rejection")
	}
}

// TestAnyClientAccepted documents the open channel (SECURITY.md): clients
// are not authenticated, so a connection with no credentials (or offering
// an arbitrary key) gets a working session.
func TestAnyClientAccepted(t *testing.T) {
	h := newHarness(t)

	// The default harness client sends no credentials at all.
	client, err := h.dial(t)
	if err != nil {
		t.Fatalf("credential-less dial: %v", err)
	}
	if _, err := run(t, client, "status", ""); err != nil {
		t.Fatalf("status over credential-less session: %v", err)
	}

	// A client offering some arbitrary key is accepted too.
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	strangerSigner, err := ssh.NewSignerFromSigner(stranger)
	if err != nil {
		t.Fatal(err)
	}

	client, err = h.dial(t, func(cfg *ssh.ClientConfig) {
		cfg.Auth = []ssh.AuthMethod{ssh.PublicKeys(strangerSigner)}
	})
	if err != nil {
		t.Fatalf("dial with an arbitrary key: %v", err)
	}
	if _, err := run(t, client, "status", ""); err != nil {
		t.Fatalf("status over arbitrary-key session: %v", err)
	}
}

func TestClientRefusesWrongHostKey(t *testing.T) {
	h := newHarness(t)

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := ssh.NewPublicKey(wrongPub)
	if err != nil {
		t.Fatal(err)
	}

	_, err = h.dial(t, func(cfg *ssh.ClientConfig) {
		cfg.HostKeyCallback = ssh.FixedHostKey(wrong)
	})
	if err == nil {
		t.Fatal("dial pinned to the wrong host key succeeded, want refusal")
	}
}

// The handshake deadline must be cleared after auth or every session dies
// handshakeTimeout after connect — too slow for a test to observe directly,
// so record SetDeadline calls instead: a completed command proves handleConn
// reached its channel loop, past the point where the clear must have run.
func TestDeadlineClearedAfterHandshake(t *testing.T) {
	h := newServerHarness(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	cli, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	srv, err := l.Accept()
	if err != nil {
		t.Fatal(err)
	}

	rec := &deadlineRecorder{Conn: srv}
	go h.srv.handleConn(rec)

	conn, chans, reqs, err := ssh.NewClientConn(cli, l.Addr().String(), h.clientConfig())
	if err != nil {
		t.Fatal(err)
	}
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()

	if _, err := run(t, client, "status", ""); err != nil {
		t.Fatalf("status: %v", err)
	}

	got := rec.calls()
	if len(got) != 2 || got[0].IsZero() || !got[1].IsZero() {
		t.Fatalf("SetDeadline calls = %v, want [handshake deadline, zero clear]", got)
	}
}

// deadlineRecorder records the times passed to SetDeadline on a net.Conn.
type deadlineRecorder struct {
	net.Conn

	mu    sync.Mutex
	times []time.Time
}

func (r *deadlineRecorder) SetDeadline(t time.Time) error {
	r.mu.Lock()
	r.times = append(r.times, t)
	r.mu.Unlock()
	return r.Conn.SetDeadline(t)
}

func (r *deadlineRecorder) calls() []time.Time {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.times)
}

func TestNewServerValidation(t *testing.T) {
	w := witness.New(witness.NewMemStore())
	seed := make([]byte, ed25519.SeedSize)

	if _, err := NewServer(Config{HostSeed: seed[:16], Witness: w}); err == nil {
		t.Error("short host seed accepted")
	}
	if _, err := NewServer(Config{HostSeed: seed}); err == nil {
		t.Error("nil witness accepted")
	}
}

func testSeedHex(t *testing.T) (string, string) {
	t.Helper()

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}

	signer, err := torchwood.NewCosignatureSigner(testKeyName, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}

	return hex.EncodeToString(seed), signer.Verifier().String()
}

func run(t *testing.T, client *ssh.Client, cmd, stdin string) (string, error) {
	t.Helper()

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}

	var out strings.Builder
	sess.Stdout = &out
	err = sess.Run(cmd)

	return out.String(), err
}

type harness struct {
	srv  *Server
	w    *witness.Witness
	addr string

	setTimes []int64
}

// newServerHarness builds a Server with no listener, for tests that drive
// handleConn directly.
func newServerHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{w: witness.New(witness.NewMemStore())}

	hostSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(hostSeed); err != nil {
		t.Fatal(err)
	}

	var err error
	h.srv, err = NewServer(Config{
		HostSeed: hostSeed,
		Witness:  h.w,
		SetTime:  func(sec int64) { h.setTimes = append(h.setTimes, sec) },
	})
	if err != nil {
		t.Fatal(err)
	}

	return h
}

// newHarness is newServerHarness plus a real TCP listener.
func newHarness(t *testing.T) *harness {
	t.Helper()

	h := newServerHarness(t)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	h.addr = l.Addr().String()

	go h.srv.Serve(l)

	return h
}

func (h *harness) clientConfig(opts ...func(*ssh.ClientConfig)) *ssh.ClientConfig {
	// No Auth methods: the server accepts anyone (SECURITY.md).
	cfg := &ssh.ClientConfig{
		User:            "vitrum",
		HostKeyCallback: ssh.FixedHostKey(h.srv.HostPublicKey()),
		Timeout:         5 * time.Second,
	}
	for _, o := range opts {
		o(cfg)
	}

	return cfg
}

func (h *harness) dial(t *testing.T, opts ...func(*ssh.ClientConfig)) (*ssh.Client, error) {
	t.Helper()

	client, err := ssh.Dial("tcp", h.addr, h.clientConfig(opts...))
	if err == nil {
		t.Cleanup(func() { client.Close() })
	}

	return client, err
}

const testKeyName = "witness.vitrum.invalid"
