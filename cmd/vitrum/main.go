// vitrum is the host-side companion CLI for the vitrum witness firmware.
package main

import (
	"fmt"
	"log"
	"os"
)

func main() {
	log.SetFlags(0)

	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "hostkey":
		cmdHostkey(os.Args[2:])
	case "provision":
		cmdProvision(os.Args[2:])
	case "deprovision":
		cmdDeprovision(os.Args[2:])
	case "feed":
		cmdFeed(os.Args[2:])
	case "record":
		cmdRecord(os.Args[2:])
	case "selftest":
		cmdSelftest(os.Args[2:])
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `usage: vitrum <command> [flags]

commands:
  keygen       generate a witness signing key (operator-held)
  hostkey      generate the emulated target's SSH host key seed (build input)
  provision    upload the witness key over pinned SSH; sets the clock too
  deprovision  clear the witness key over pinned SSH
  feed         feed a log checkpoint to a witness and verify the cosignature
  record       capture live checkpoints as witness test fixtures
  selftest     end-to-end test against a running witness using a synthetic log
`)
	os.Exit(2)
}
