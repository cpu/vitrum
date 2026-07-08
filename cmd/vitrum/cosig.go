package main

import (
	"bytes"
	"fmt"

	"filippo.io/torchwood"
	"golang.org/x/mod/sumdb/note"
)

// verifyCosignature opens the concatenation of cpNote and cosig, checks
// that the witness's cosignature verifies, and returns its Unix timestamp.
func verifyCosignature(v *torchwood.CosignatureVerifier, cpNote, cosig []byte) (int64, error) {
	full := append(bytes.Clone(cpNote), cosig...)

	n, err := note.Open(full, note.VerifierList(v))
	if err != nil {
		return 0, fmt.Errorf("open cosigned note: %w", err)
	}

	for _, sig := range n.Sigs {
		if sig.Name != v.Name() {
			continue
		}

		return torchwood.CosignatureTimestamp(sig)
	}

	return 0, fmt.Errorf("verified note is missing the witness cosignature")
}
