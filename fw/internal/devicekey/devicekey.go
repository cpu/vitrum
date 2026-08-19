//go:build usbarmory

package devicekey

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"errors"
	"log"

	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
)

// Diversifiers for the device-bound keys. Distinct strings domain-separate
// the state-blob encryption key, the RPMB authentication key, and the SSH
// host key seed so none can be substituted for another.
const (
	State   = "vitrum-state-v1"
	RPMB    = "vitrum-rpmb-v1"
	HostKey = "vitrum-hostkey-v1"
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

// pbkdfIter matches armored-witness's RPMB key stretch; cheap at boot (a
// handful of derivations).
const pbkdfIter = 4096

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
		dk = make([]byte, sha256.Size)
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
	key, err = pbkdf2.Key(sha256.New, string(dk), uid[:], pbkdfIter, sha256.Size)
	if err != nil {
		return nil, dev, err
	}

	if dev {
		log.Printf("WARNING: SNVS not secure: %q key is a non-unique DEV key (unfused unit)", diversifier)
	}

	return key, dev, nil
}
