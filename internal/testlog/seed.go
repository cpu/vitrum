package testlog

import (
	"crypto/sha256"
	"encoding/binary"
)

// SeedReader yields deterministic SHA-256(seed || counter) blocks.
type SeedReader struct {
	seed []byte
	ctr  uint64
	buf  []byte
}

// NewSeedReader returns a SeedReader for the given seed string.
func NewSeedReader(seed string) *SeedReader {
	return &SeedReader{seed: []byte(seed)}
}

func (r *SeedReader) Read(p []byte) (int, error) {
	for len(r.buf) < len(p) {
		h := sha256.New()
		h.Write(r.seed)
		binary.Write(h, binary.BigEndian, r.ctr)
		r.ctr++
		r.buf = append(r.buf, h.Sum(nil)...)
	}

	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}
