package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"filippo.io/torchwood"

	"github.com/cpu/vitrum/internal/config"
)

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	seedPath := fs.String("seed", "keys/witness.seed", "output path for the private key seed")
	vkeyPath := fs.String("vkey", "keys/witness.vkey", "output path for the verifier key")
	name := fs.String("name", config.WitnessKeyName, "witness key name")
	force := fs.Bool("force", false, "overwrite an existing seed")
	fs.Parse(args)

	if _, err := os.Stat(*seedPath); err == nil && !*force {
		log.Fatalf("%s already exists; pass -force to regenerate", *seedPath)
	}

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatal(err)
	}

	signer, err := torchwood.NewCosignatureSigner(*name, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		log.Fatal(err)
	}
	vkey := signer.Verifier().String()

	for path, data := range map[string][]byte{
		*seedPath: seed,
		*vkeyPath: []byte(vkey + "\n"),
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			log.Fatal(err)
		}
	}

	fmt.Printf("wrote %s (private seed)\n", *seedPath)
	fmt.Printf("wrote %s\n", *vkeyPath)
	fmt.Printf("witness verifier key: %s\n", vkey)
}
