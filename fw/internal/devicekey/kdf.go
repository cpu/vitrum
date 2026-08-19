package devicekey

import (
	"crypto/pbkdf2"
	"crypto/sha256"
)

// These values and the PBKDF2 construction are permanent compatibility
// contracts. Changing them orphans RPMB, state, or the pinned SSH identity.
const (
	State   = "vitrum-state-v1"
	RPMB    = "vitrum-rpmb-v1"
	HostKey = "vitrum-hostkey-v1"

	pbkdfIter = 4096
	keyLen    = sha256.Size
)

func stretchKey(dk, uid []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(dk), uid, pbkdfIter, keyLen)
}
