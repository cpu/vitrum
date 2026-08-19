//go:build usbarmory

package devicekey

import (
	"errors"
	"log"

	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
)

// The imx6ul package constructs the DCP instance (with a default
// DeriveKeyMemory region) but leaves clock and channel bring-up to the
// application; without Init every DeriveKey faults on unset registers.
// CAAM needs no equivalent (its instance is fully usable as constructed).
func init() {
	if imx6ul.Native && imx6ul.DCP != nil {
		imx6ul.DCP.Init()
	}
}

// deriveKey returns a 32-byte device-bound key for the given diversifier,
// derived from the SoC hardware-unique key (CAAM preferred, DCP fallback) and
// salted with the SoC unique ID via PBKDF2-HMAC-SHA256.
//
// The returned dev flag is true when SNVS is not in a secure state: pre-fuse,
// the HUK derivation uses a non-unique test vector and any firmware on any
// unit derives the same key, so the result binds to nothing. Callers must
// mark such keys/identities as DEV.
func Derive(diversifier string) (key []byte, dev bool, err error) {
	dev = imx6ul.SNVS == nil || !imx6ul.SNVS.Available()

	var dk []byte
	switch {
	case imx6ul.CAAM != nil:
		dk = make([]byte, keyLen)
		err = imx6ul.CAAM.DeriveKey([]byte(diversifier), dk)
	case imx6ul.DCP != nil:
		// DCP diversifier is AES-128-CBC-encrypted; determinism requires a
		// fixed IV, safe as diversifiers differ within their first AES
		// block. index -1 returns the key.
		dk, err = imx6ul.DCP.DeriveKey([]byte(diversifier), make([]byte, 16), -1)
	default:
		err = errors.New("no CAAM or DCP available for key derivation")
	}
	if err != nil {
		return nil, dev, err
	}

	uid := imx6ul.UniqueID()
	key, err = stretchKey(dk, uid[:])
	if err != nil {
		return nil, dev, err
	}

	if dev {
		log.Printf("WARNING: SNVS not secure: %q key is a non-unique DEV key (unfused unit)", diversifier)
	}

	return key, dev, nil
}
