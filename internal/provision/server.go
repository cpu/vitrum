// Package provision implements vitrum's provisioning channel.
//
// A minimal, exec-only SSH server through which an operator uploads the
// witness signing key (held in RAM only), sets the device clock, and inspects
// witness status.
//
// Clients are NOT authenticated: anyone who can reach the port may run every
// command (SECURITY.md; the accepted outcomes are re-keying, deprovisioning,
// and clock control). The host key still authenticates the DEVICE to the
// operator (TOFU + pinning), keeping an uploaded seed confidential in
// transit.
//
// The surface is deliberately tiny: session channels only, no shell, no PTY,
// no subsystems. Commands also work with a plain OpenSSH client:
//
//	ssh 10.0.0.1 provision <key-name> < seed.hex
//	ssh 10.0.0.1 deprovision
//	ssh 10.0.0.1 settime <unix-seconds>
//	ssh 10.0.0.1 status
package provision

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"filippo.io/torchwood"
	"golang.org/x/crypto/ssh"

	"github.com/cpu/vitrum/internal/witness"
)

// Config assembles a Server's dependencies.
type Config struct {
	// HostSeed is the 32-byte ed25519 seed for the SSH host key.
	//
	// On hardware it is derived from the hardware-unique key, a stable
	// per-unit identity the client pairs with once (TOFU) and pins. The
	// emulated target passes a build-time seed instead.
	HostSeed []byte

	// Witness receives the provisioned signer.
	Witness *witness.Witness

	// SetTime sets the device wall clock, if the platform has one.
	SetTime func(sec int64)

	// Start anchors the status command's uptime report. Zero means
	// NewServer's call time.
	Start time.Time
}

// Server is the provisioning SSH server.
type Server struct {
	cfg     Config
	sshCfg  *ssh.ServerConfig
	hostKey ssh.PublicKey

	// mu guards priv, the reference through which the provisioned witness
	// key is destroyed: zeroed on rotation and deprovision, nil when
	// unprovisioned. Zeroing destroys the working key only because the
	// torchwood signer closes over this same slice rather than copying it;
	// if that ever changes, the key would outlive deprovisioning.
	mu   sync.Mutex
	priv ed25519.PrivateKey
}

// NewServer validates cfg and builds the SSH server state.
func NewServer(cfg Config) (*Server, error) {
	if len(cfg.HostSeed) != ed25519.SeedSize {
		return nil, fmt.Errorf("host key seed is %d bytes, want %d", len(cfg.HostSeed), ed25519.SeedSize)
	}

	if cfg.Witness == nil {
		return nil, errors.New("nil witness")
	}

	if cfg.Start.IsZero() {
		cfg.Start = time.Now()
	}

	sshCfg := &ssh.ServerConfig{
		// Deliberately open: clients are not authenticated (see the
		// package comment and SECURITY.md).
		NoClientAuth: true,
	}

	hostSigner, err := ssh.NewSignerFromSigner(ed25519.NewKeyFromSeed(cfg.HostSeed))
	if err != nil {
		return nil, err
	}
	sshCfg.AddHostKey(hostSigner)

	return &Server{cfg: cfg, sshCfg: sshCfg, hostKey: hostSigner.PublicKey()}, nil
}

func (s *Server) HostPublicKey() ssh.PublicKey {
	return s.hostKey
}

// Serve accepts and services connections on l until Accept fails.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}

		go s.handleConn(conn)
	}
}

// handshakeTimeout bounds the unauthenticated pre-auth window so stalled
// clients cannot hold connection goroutines open indefinitely.
const handshakeTimeout = 30 * time.Second

func (s *Server) handleConn(c net.Conn) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))

	sconn, chans, reqs, err := ssh.NewServerConn(c, s.sshCfg)
	if err != nil {
		log.Printf("ssh: handshake from %s failed: %v", c.RemoteAddr(), err)
		c.Close()
		return
	}
	defer sconn.Close()

	c.SetDeadline(time.Time{})

	log.Printf("ssh: %s connected from %s", sconn.User(), sconn.RemoteAddr())

	go ssh.DiscardRequests(reqs)

	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, "session channels only")
			continue
		}

		ch, chReqs, err := newCh.Accept()
		if err != nil {
			continue
		}

		go s.handleSession(ch, chReqs)
	}
}

// handleSession services one session channel.
//
// Each channel is expected to deliver only exec requests. All
// other request types (shell, pty-req, subsystem, ...) are refused.
func (s *Server) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()

	for req := range reqs {
		switch req.Type {
		case "exec":
			var p struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &p); err != nil {
				req.Reply(false, nil)
				return
			}
			req.Reply(true, nil)

			status := s.exec(ch, p.Command)
			ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))

			return
		default:
			req.Reply(false, nil)
		}
	}
}

func (s *Server) exec(ch ssh.Channel, command string) uint32 {
	args := strings.Fields(command)
	if len(args) == 0 {
		return fail(ch, "empty command")
	}

	switch args[0] {
	case "provision":
		if len(args) != 2 {
			return fail(ch, "usage: provision <key-name> (32-byte seed, hex, on stdin)")
		}

		return s.provision(ch, args[1])
	case "deprovision":
		s.deprovision()
		fmt.Fprintf(ch, "deprovisioned\n")

		return 0
	case "settime":
		if len(args) != 2 {
			return fail(ch, "usage: settime <unix-seconds>")
		}
		sec, err := strconv.ParseInt(args[1], 10, 64)
		if err != nil || sec < 0 {
			return fail(ch, "settime: bad unix-seconds value")
		}

		if s.cfg.SetTime == nil {
			return fail(ch, "settime: no settable clock on this platform")
		}

		s.cfg.SetTime(sec)
		log.Printf("ssh: time set to %s", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(ch, "time %s\n", time.Now().UTC().Format(time.RFC3339))

		return 0
	case "status":
		fmt.Fprintf(ch, "provisioned=%v\n", s.cfg.Witness.Provisioned())
		if v := s.cfg.Witness.Verifier(); v != "" {
			fmt.Fprintf(ch, "verifier=%s\n", v)
		}
		fmt.Fprintf(ch, "time=%s\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(ch, "uptime=%s\n", time.Since(s.cfg.Start).Round(time.Second))

		return 0
	default:
		return fail(ch, "unknown command %q (provision, deprovision, settime, status)", args[0])
	}
}

// provision reads a hex seed from the channel, installs the signer, and
// echoes the derived verifier key for the client to cross-check.
func (s *Server) provision(ch ssh.Channel, name string) uint32 {
	buf := make([]byte, maxSeedInput+1)
	n := 0
	for n < len(buf) {
		r, err := ch.Read(buf[n:])
		n += r
		if err != nil {
			break
		}
	}
	defer zero(buf)

	if n > maxSeedInput {
		return fail(ch, "provision: seed input too large")
	}

	// Trim in place: string conversions would copy the seed somewhere
	// we cannot zero.
	hexSeed := bytes.TrimSpace(buf[:n])
	seed := make([]byte, ed25519.SeedSize)
	defer zero(seed)

	if len(hexSeed) != hex.EncodedLen(ed25519.SeedSize) {
		return fail(ch, "provision: want %d hex chars on stdin, got %d", hex.EncodedLen(ed25519.SeedSize), len(hexSeed))
	}
	if _, err := hex.Decode(seed, hexSeed); err != nil {
		return fail(ch, "provision: bad hex seed")
	}

	priv := ed25519.NewKeyFromSeed(seed)

	signer, err := torchwood.NewCosignatureSigner(name, priv)
	if err != nil {
		zero(priv)
		return fail(ch, "provision: %v", err)
	}

	s.mu.Lock()
	// Keep signer installation and key ownership atomic with respect to
	// concurrent provisioning and deprovisioning sessions.
	s.cfg.Witness.SetSigner(signer)
	zero(s.priv) // rotating replaces (and destroys) any previous key
	s.priv = priv
	s.mu.Unlock()

	log.Printf("ssh: witness key %q provisioned", name)
	fmt.Fprintf(ch, "%s\n", signer.Verifier().String())

	return 0
}

func (s *Server) deprovision() {
	s.mu.Lock()
	// ClearSigner waits for in-flight signing before the key is zeroed.
	s.cfg.Witness.ClearSigner()
	zero(s.priv)
	s.priv = nil
	s.mu.Unlock()

	log.Printf("ssh: witness key deprovisioned")
}

func fail(ch ssh.Channel, format string, args ...any) uint32 {
	fmt.Fprintf(ch.Stderr(), format+"\n", args...)
	return 1
}

func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// maxSeedInput bounds the provision command's stdin (64 hex chars plus
// whitespace slack).
const maxSeedInput = 128
