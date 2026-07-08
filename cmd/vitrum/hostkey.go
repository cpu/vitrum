package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// cmdHostkey generates the build-time SSH host key for the *emulated* target
// (QEMU has no HUK): a seed baked into the mx6ullevk image plus the derived
// public key for client-side pinning. Hardware derives its host key on-device
// from the HUK instead and embeds no key material.
func cmdHostkey(args []string) {
	fs := flag.NewFlagSet("hostkey", flag.ExitOnError)
	seedPath := fs.String("seed", "fw/ssh_host.seed", "output path for the host key seed (emulated-target build input)")
	pubPath := fs.String("pub", "keys/ssh_host.pub", "output path for the host public key (pinned by `vitrum provision`)")
	force := fs.Bool("force", false, "overwrite an existing seed (changes the emulated image hash and the pinned host key)")
	fs.Parse(args)

	if _, err := os.Stat(*seedPath); err == nil && !*force {
		log.Fatalf("%s already exists; pass -force to regenerate (warning: this changes the image hash and the pinned host key)", *seedPath)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}

	pub, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	if err != nil {
		log.Fatal(err)
	}

	for path, data := range map[string][]byte{
		*seedPath: seed,
		*pubPath:  ssh.MarshalAuthorizedKey(pub),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("wrote %s (host key seed, firmware build input)\n", *seedPath)
	fmt.Printf("wrote %s\n", *pubPath)
	fmt.Printf("host key fingerprint: %s\n", ssh.FingerprintSHA256(pub))
}
