package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/cpu/vitrum/internal/provision"
	"github.com/cpu/vitrum/internal/witness"
)

// The TOFU pin logic is security-relevant client behavior: a missing pin is
// refused without -tofu, -tofu pairs exactly once, and an existing pin is
// never overwritten. These tests drive dialPinned against a real provision
// server on a local listener.

// startTestServer runs a provisioning SSH server on 127.0.0.1, returning its
// address and host public key.
func startTestServer(t *testing.T) (addr string, hostPub ssh.PublicKey) {
	return startTestServerSetTime(t, nil)
}

// startTestServerSetTime is startTestServer with a settable-clock hook.
func startTestServerSetTime(t *testing.T, setTime func(int64)) (addr string, hostPub ssh.PublicKey) {
	t.Helper()

	hostSeed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(hostSeed); err != nil {
		t.Fatal(err)
	}

	srv, err := provision.NewServer(provision.Config{
		HostSeed: hostSeed,
		Witness:  witness.New(witness.NewMemStore()),
		SetTime:  setTime,
	})
	if err != nil {
		t.Fatal(err)
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go srv.Serve(l)

	return l.Addr().String(), srv.HostPublicKey()
}

func testFlags(addr, hostKeyPath string, tofu bool) *sshFlags {
	return &sshFlags{
		addr:    &addr,
		hostKey: &hostKeyPath,
		tofu:    &tofu,
	}
}

func TestDialRefusesWithoutPin(t *testing.T) {
	addr, _ := startTestServer(t)
	pin := filepath.Join(t.TempDir(), "pin.pub")

	_, err := testFlags(addr, pin, false).dialPinned()
	if err == nil {
		t.Fatal("dial with no pin and no -tofu succeeded")
	}
	if !strings.Contains(err.Error(), "-tofu") {
		t.Errorf("refusal does not point at -tofu: %v", err)
	}
	if _, statErr := os.Stat(pin); !os.IsNotExist(statErr) {
		t.Error("refused dial still created a pin file")
	}
}

func TestDialTOFUPairsThenPins(t *testing.T) {
	addr, hostPub := startTestServer(t)
	pin := filepath.Join(t.TempDir(), "pin.pub")

	client, err := testFlags(addr, pin, true).dialPinned()
	if err != nil {
		t.Fatalf("TOFU dial: %v", err)
	}
	client.Close()

	pinned, err := os.ReadFile(pin)
	if err != nil {
		t.Fatal(err)
	}
	if want := ssh.MarshalAuthorizedKey(hostPub); !bytes.Equal(pinned, want) {
		t.Errorf("pinned %q, want the presented host key %q", pinned, want)
	}

	// Paired: subsequent dials go through the strict pin path and succeed
	// against the same server.
	client, err = testFlags(addr, pin, true).dialPinned()
	if err != nil {
		t.Fatalf("re-dial with matching pin: %v", err)
	}
	client.Close()
}

// The settime sacrificial-connection dance: a warm device replies promptly,
// a cold device applies the clock jump and wedges the connection before the
// reply escapes, which must read as success (bounded by the reply timeout),
// with verifyClock as the backstop over a fresh connection.

func TestSettimeWarmReply(t *testing.T) {
	var got atomic.Int64
	addr, _ := startTestServerSetTime(t, func(sec int64) { got.Store(sec) })
	pin := filepath.Join(t.TempDir(), "pin.pub")

	if err := testFlags(addr, pin, true).settime(3 * time.Second); err != nil {
		t.Fatalf("settime: %v", err)
	}

	if d := time.Now().Unix() - got.Load(); d < 0 || d > 60 {
		t.Errorf("device received unix time %d, host is at %d", got.Load(), time.Now().Unix())
	}
}

func TestSettimeLostReplyIsSuccess(t *testing.T) {
	// A SetTime that never returns models the cold-boot wedge: the reply
	// cannot arrive while it blocks.
	unblock := make(chan struct{})
	t.Cleanup(func() { close(unblock) })
	addr, _ := startTestServerSetTime(t, func(int64) { <-unblock })
	pin := filepath.Join(t.TempDir(), "pin.pub")

	start := time.Now()
	if err := testFlags(addr, pin, true).settime(100 * time.Millisecond); err != nil {
		t.Fatalf("settime with a lost reply: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("settime returned after %s, want promptly after the reply timeout", elapsed)
	}
}

func TestVerifyClock(t *testing.T) {
	addr, _ := startTestServer(t)
	pin := filepath.Join(t.TempDir(), "pin.pub")

	client, err := testFlags(addr, pin, true).dialPinned()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	if err := verifyClock(client, time.Now(), 5*time.Minute); err != nil {
		t.Errorf("in-tolerance clock rejected: %v", err)
	}
	if err := verifyClock(client, time.Now().Add(time.Hour), 5*time.Minute); err == nil {
		t.Error("hour-off clock accepted")
	}
}

func TestDialNeverOverwritesExistingPin(t *testing.T) {
	addr, _ := startTestServer(t)

	// An existing pin for a different key: even with -tofu the pin is
	// authoritative; the mismatched server is refused and the pin file
	// stays untouched.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSSH, err := ssh.NewPublicKey(otherPub)
	if err != nil {
		t.Fatal(err)
	}
	pin := filepath.Join(t.TempDir(), "pin.pub")
	stale := ssh.MarshalAuthorizedKey(otherSSH)
	if err := os.WriteFile(pin, stale, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := testFlags(addr, pin, true).dialPinned(); err == nil {
		t.Fatal("dial succeeded against a mismatched pin")
	}

	got, err := os.ReadFile(pin)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, stale) {
		t.Error("mismatched dial modified the pin file")
	}
}
