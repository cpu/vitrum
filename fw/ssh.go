//go:build usbarmory || mx6ullevk

package main

import (
	"log"
	"net"
	"time"

	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"golang.org/x/crypto/ssh"

	"github.com/cpu/vitrum/internal/provision"
	"github.com/cpu/vitrum/internal/witness"
)

// startSSH serves the provisioning channel on :22.
//
// The channel does not authenticate clients: network reachability is the
// privilege boundary (see SECURITY.md and the provision package comment).
func startSSH(w *witness.Witness) error {
	seed, src, err := hostKeySeed()
	if err != nil {
		return err
	}

	srv, err := provision.NewServer(provision.Config{
		HostSeed: seed,
		Witness:  w,
		SetTime: func(sec int64) {
			imx6ul.ARM.SetTime(sec * int64(time.Second))
		},
		Start: start,
	})
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp4", ":22")
	if err != nil {
		return err
	}

	log.Printf("ssh provisioning on %s:22, host key %s (%s)", IP, ssh.FingerprintSHA256(srv.HostPublicKey()), src)

	go func() {
		fatal(srv.Serve(listener))
	}()

	return nil
}
