package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/torchwood"
	"github.com/cpu/vitrum/internal/config"
	"golang.org/x/crypto/ssh"
)

// cmdProvision uploads the witness key over the pinned SSH channel and
// cross-checks the verifier key the device reports.
func cmdProvision(args []string) {
	fs := flag.NewFlagSet("provision", flag.ExitOnError)
	conn := addCommonSSHFlags(fs)
	seedPath := fs.String("seed", "keys/witness.seed", "witness key seed file")
	name := fs.String("name", config.WitnessKeyName, "witness key name")
	setTime := fs.Bool("settime", true, "set the device clock first")
	fs.Parse(args)

	seed, err := os.ReadFile(*seedPath)
	if err != nil {
		log.Fatalf("reading witness seed: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		log.Fatalf("%s is %d bytes, want %d", *seedPath, len(seed), ed25519.SeedSize)
	}

	// The vkey the device must echo back after installing the key.
	signer, err := torchwood.NewCosignatureSigner(*name, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		log.Fatal(err)
	}
	want := signer.Verifier().String()

	if *setTime {
		if err := conn.settime(settimeReplyTimeout); err != nil {
			log.Fatal(err)
		}
	}

	client := conn.dial()
	defer client.Close()

	if *setTime {
		if err := verifyClock(client, time.Now(), clockTolerance); err != nil {
			log.Fatal(err)
		}
	}

	out, err := sshRun(client, "provision "+*name, hex.EncodeToString(seed)+"\n")
	if err != nil {
		log.Fatal(err)
	}

	got := strings.TrimSpace(out)
	if got != want {
		log.Fatalf("device reported verifier key %q, expected %q; refusing to trust this provisioning", got, want)
	}

	fmt.Printf("provisioned %s\nwitness verifier key: %s\n", *conn.addr, got)
}

// cmdDeprovision clears the witness key; the device refuses submissions
// until the next provision.
func cmdDeprovision(args []string) {
	fs := flag.NewFlagSet("deprovision", flag.ExitOnError)
	conn := addCommonSSHFlags(fs)
	fs.Parse(args)

	client := conn.dial()
	defer client.Close()

	if _, err := sshRun(client, "deprovision", ""); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("deprovisioned %s\n", *conn.addr)
}

// settime sets the device clock over a sacrificial connection.
//
// A lost reply is expected, based on the system wedging the TCP counters
// after updating the clock. The caller reconnects fresh and cross-checks with
// verifyClock.
func (f *sshFlags) settime(timeout time.Duration) error {
	client, err := f.dialPinned()
	if err != nil {
		return err
	}
	defer client.Close()

	type reply struct {
		out string
		err error
	}
	ch := make(chan reply, 1)
	go func() {
		out, err := sshRun(client, fmt.Sprintf("settime %d", time.Now().Unix()), "")
		ch <- reply{out, err}
	}()

	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		fmt.Printf("device %s", r.out)
	case <-time.After(timeout):
		fmt.Printf("settime reply lost (cold-boot clock jump), reconnecting\n")
	}

	return nil
}

// verifyClock confirms via the status command that the device clock is within
// tol of now. It backstops settime's lost-reply assumption
func verifyClock(client *ssh.Client, now time.Time, tol time.Duration) error {
	out, err := sshRun(client, "status", "")
	if err != nil {
		return err
	}

	for _, line := range strings.Split(out, "\n") {
		ts, ok := strings.CutPrefix(strings.TrimSpace(line), "time=")
		if !ok {
			continue
		}

		devTime, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return fmt.Errorf("unparseable device time %q: %v", ts, err)
		}
		if d := devTime.Sub(now).Abs(); d > tol {
			return fmt.Errorf("device clock %s is %s off the host clock after settime", ts, d.Round(time.Second))
		}

		return nil
	}

	return errors.New("device status reported no time")
}

// settimeReplyTimeout bounds the wait for a settime reply.
//
// On a cold device the jump from the epoch moves TamaGo's monotonic clock
// with the wall clock, wedging every established TCP connection, including
// the one carrying the settime command, whose reply is written after the
// jump and never escapes.
const settimeReplyTimeout = 3 * time.Second

// clockTolerance is how far the device clock may sit from the host's after
// provisioning has set it.
const clockTolerance = 5 * time.Minute

// sshFlags are the common connection options shared by provision and
// deprovision. The device does not authenticate clients (SECURITY.md), so
// there is no operator identity to configure, only the pinned host key
// that authenticates the device to us.
type sshFlags struct {
	addr    *string
	hostKey *string
	tofu    *bool
}

func addCommonSSHFlags(fs *flag.FlagSet) *sshFlags {
	return &sshFlags{
		addr:    fs.String("addr", "10.0.0.1:22", "device SSH address"),
		hostKey: fs.String("hostkey", "keys/ssh_host.pub", "pinned device host public key file"),
		tofu:    fs.Bool("tofu", false, "pair on first use: if the -hostkey file is missing, accept the presented host key and pin it there (only over a trusted first contact)"),
	}
}

// dial connects with the host key pinned in the -hostkey file; anything else
// is refused. With -tofu and no pin file yet, the presented key is accepted
// and pinned instead (one-time pairing); an existing pin is never overwritten.
func (f *sshFlags) dial() *ssh.Client {
	client, err := f.dialPinned()
	if err != nil {
		log.Fatal(err)
	}

	return client
}

// dialPinned implements dial's pin/TOFU decision, returning errors instead of
// exiting so the security-relevant client behavior is unit-testable.
func (f *sshFlags) dialPinned() (*ssh.Client, error) {
	pinned, err := os.ReadFile(*f.hostKey)
	if errors.Is(err, os.ErrNotExist) && *f.tofu {
		return f.dialTOFU()
	}
	if err != nil {
		return nil, fmt.Errorf("reading pinned host key: %v (no pin yet? pass -tofu to pair on first use)", err)
	}

	hostKey, _, _, _, err := ssh.ParseAuthorizedKey(pinned)
	if err != nil {
		return nil, fmt.Errorf("parsing pinned host key %s: %v", *f.hostKey, err)
	}

	client, err := f.dialCallback(ssh.FixedHostKey(hostKey))
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %v", *f.addr, err)
	}

	return client, nil
}

// dialTOFU accepts whatever host key the device presents and pins it to the
// -hostkey file, so every subsequent connection is strict.
func (f *sshFlags) dialTOFU() (*ssh.Client, error) {
	var presented ssh.PublicKey
	client, err := f.dialCallback(func(_ string, _ net.Addr, key ssh.PublicKey) error {
		presented = key
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ssh %s: %v", *f.addr, err)
	}

	if err := os.MkdirAll(filepath.Dir(*f.hostKey), 0o755); err != nil {
		client.Close()
		return nil, err
	}
	if err := os.WriteFile(*f.hostKey, ssh.MarshalAuthorizedKey(presented), 0o600); err != nil {
		client.Close()
		return nil, fmt.Errorf("pinning host key: %v", err)
	}

	fmt.Printf("TOFU: pinned host key %s to %s\n", ssh.FingerprintSHA256(presented), *f.hostKey)

	return client, nil
}

// dialCallback connects, verifying the host key with cb. No client
// credentials are sent: the device accepts any client.
func (f *sshFlags) dialCallback(cb ssh.HostKeyCallback) (*ssh.Client, error) {
	client, err := ssh.Dial("tcp", *f.addr, &ssh.ClientConfig{
		User:            "vitrum",
		HostKeyCallback: cb,
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}

// sshRun executes cmd on the device, returning stdout.
func sshRun(client *ssh.Client, cmd, stdin string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()

	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}

	var out, errOut strings.Builder
	sess.Stdout = &out
	sess.Stderr = &errOut

	if err := sess.Run(cmd); err != nil {
		return "", fmt.Errorf("%q failed: %v (%s)", cmd, err, strings.TrimSpace(errOut.String()))
	}

	return out.String(), nil
}
