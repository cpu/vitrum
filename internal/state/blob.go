// Package state persists rollback-protected witness checkpoint state.
//
// State is serialized, encrypted and authenticated under a device-bound key
// (AES-256-GCM), and written to two alternating raw A/B slots on the microSD
// (no filesystem). Each blob embeds a monotonic generation counter that is
// cross-checked at boot against a hardware anchor (eMMC RPMB), so a storage
// rollback is detected and refused. See ROLLBACK.md for the crash-safety
// analysis and the boot decision.
package state

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
)

const (
	// Offset is the byte offset of the first slot on the microSD (16 MiB).
	// The Makefile refuses to produce boot images that reach this offset,
	// so image and state can never collide.
	Offset = 16 * 1024 * 1024

	// SlotSize is the size of each of the two alternating slots.
	SlotSize = 64 * 1024

	// StateKeyLen is the required length of the blob encryption key
	// (AES-256).
	StateKeyLen = 32

	magicLen  = 8
	nonceLen  = 12                          // AES-GCM standard nonce
	tagLen    = 16                          // AES-GCM tag
	headerLen = magicLen + 8 + 4 + nonceLen // magic | gen | ciphertext-len | nonce
)

var magic = []byte("VITRUMW1") // W1: encrypted+authenticated, generation-tagged

// ErrNoState reports that no valid slot was found (fresh card, both slots
// corrupt, or none authenticated under the current key).
var ErrNoState = errors.New("no valid state found")

// ErrWriteFailed marks a Save failure at or after the point where the slot
// write was issued: the slot contents are unknown and the generation is
// burned (ROLLBACK.md, soft failures). Errors before this point leave the
// medium untouched and the generation unused.
var ErrWriteFailed = errors.New("state: slot write failed")

// BlockDevice is the storage interface Save and Load operate on.
//
// The firmware wraps usdhc cards and tests use an in-memory fake.
type BlockDevice interface {
	Info() (blockSize int, blocks int64)
	ReadBlocks(lba int64, buf []byte) error
	WriteBlocks(lba int64, buf []byte) error
}

// Save encrypts and authenticates states (origin -> serialized checkpoint
// note) under key, tags the blob with generation gen, and writes it to the
// slot selected by gen.
//
// The generation is uint32 to match the hardware anchor (the eMMC RPMB write
// counter). Alternating slots by gen means a torn write can only destroy the
// newer slot and the previous generation remains loadable. The generation is
// bound into the AEAD as additional data, so a blob cannot be relabeled to a
// different generation without detection.
func Save(d BlockDevice, offset int64, key []byte, gen uint32, states map[string][]byte) error {
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}

	plaintext, err := encode(states)
	if err != nil {
		return err
	}

	nonce := deriveNonce(gen)
	ciphertext := aead.Seal(nil, nonce, plaintext, genAAD(gen))

	if headerLen+len(ciphertext) > SlotSize {
		return fmt.Errorf("state blob (%d bytes) exceeds slot size", len(ciphertext))
	}

	buf := make([]byte, SlotSize)
	copy(buf, magic)
	binary.LittleEndian.PutUint64(buf[magicLen:], uint64(gen))
	binary.LittleEndian.PutUint32(buf[magicLen+8:], uint32(len(ciphertext)))
	copy(buf[magicLen+12:], nonce)
	copy(buf[headerLen:], ciphertext)

	lba, err := slotLBA(d, offset, uint64(gen)%2)
	if err != nil {
		return err
	}

	if err := d.WriteBlocks(lba, buf); err != nil {
		return fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	return nil
}

// Load reads both slots and returns the states and generation of the valid
// slot (decrypts and authenticates under key) with the highest generation.
//
// It returns ErrNoState if neither slot is valid.
func Load(d BlockDevice, offset int64, key []byte) (states map[string][]byte, gen uint32, err error) {
	aead, err := newAEAD(key)
	if err != nil {
		return nil, 0, err
	}

	var found bool

	for slot := uint64(0); slot < 2; slot++ {
		s, g, err := loadSlot(d, offset, slot, aead)
		if err != nil {
			continue
		}

		if !found || g > gen {
			states, gen, found = s, g, true
		}
	}

	if !found {
		return nil, 0, ErrNoState
	}

	return states, gen, nil
}

func loadSlot(d BlockDevice, offset int64, slot uint64, aead cipher.AEAD) (map[string][]byte, uint32, error) {
	lba, err := slotLBA(d, offset, slot)
	if err != nil {
		return nil, 0, err
	}

	buf := make([]byte, SlotSize)
	if err := d.ReadBlocks(lba, buf); err != nil {
		return nil, 0, err
	}

	if !bytes.Equal(buf[:magicLen], magic) {
		return nil, 0, errors.New("bad magic")
	}

	gen64 := binary.LittleEndian.Uint64(buf[magicLen:])
	if gen64 > math.MaxUint32 {
		return nil, 0, errors.New("generation out of range")
	}
	gen := uint32(gen64)
	length := binary.LittleEndian.Uint32(buf[magicLen+8:])

	if int(length) < tagLen || int(length) > SlotSize-headerLen {
		return nil, 0, errors.New("bad ciphertext length")
	}

	nonce := buf[magicLen+12 : headerLen]
	ciphertext := buf[headerLen : headerLen+int(length)]

	// The nonce is derived deterministically from the generation; a slot
	// whose stored nonce disagrees has a forged or corrupt header.
	if !bytes.Equal(nonce, deriveNonce(gen)) {
		return nil, 0, errors.New("nonce/generation mismatch")
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, genAAD(gen))
	if err != nil {
		return nil, 0, fmt.Errorf("authentication failed: %w", err)
	}

	states, err := decode(plaintext)
	if err != nil {
		return nil, 0, err
	}

	return states, gen, nil
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	if len(key) != StateKeyLen {
		return nil, fmt.Errorf("state key is %d bytes, want %d", len(key), StateKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// genAAD binds the generation into the AEAD so a valid blob cannot be
// relabeled to a different generation.
func genAAD(gen uint32) []byte {
	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, gen)
	return aad
}

// deriveNonce produces a unique GCM nonce per generation. The blob key is
// device-bound and generations never repeat under a given key (they only
// increase, and RollbackStore halts rather than re-Seal a generation whose
// first write may have reached the medium), so a generation-derived nonce is
// unique for every Seal an adversary can observe.
func deriveNonce(gen uint32) []byte {
	nonce := make([]byte, nonceLen)
	copy(nonce, magic[:4]) // domain-separate from any other GCM use of this key
	binary.LittleEndian.PutUint32(nonce[4:], gen)
	return nonce
}

func slotLBA(d BlockDevice, offset int64, slot uint64) (int64, error) {
	blockSize, blocks := d.Info()

	if blockSize <= 0 || SlotSize%blockSize != 0 || offset%int64(blockSize) != 0 {
		return 0, fmt.Errorf("unsupported block size %d", blockSize)
	}

	slotOffset := offset + int64(slot)*SlotSize

	if (slotOffset+SlotSize)/int64(blockSize) > blocks {
		return 0, fmt.Errorf("device too small for state region")
	}

	return slotOffset / int64(blockSize), nil
}

func encode(states map[string][]byte) ([]byte, error) {
	var b bytes.Buffer

	for _, origin := range slices.Sorted(maps.Keys(states)) {
		note := states[origin]

		if len(origin) > math.MaxUint16 {
			return nil, fmt.Errorf("origin too long: %q", origin)
		}
		if uint64(len(note)) > math.MaxUint32 {
			return nil, fmt.Errorf("note too long for origin %q", origin)
		}

		binary.Write(&b, binary.LittleEndian, uint16(len(origin)))
		b.WriteString(origin)
		binary.Write(&b, binary.LittleEndian, uint32(len(note)))
		b.Write(note)
	}

	return b.Bytes(), nil
}

func decode(payload []byte) (map[string][]byte, error) {
	states := make(map[string][]byte)

	for len(payload) > 0 {
		if len(payload) < 2 {
			return nil, errors.New("truncated origin length")
		}
		originLen := int(binary.LittleEndian.Uint16(payload))
		payload = payload[2:]

		if len(payload) < originLen+4 {
			return nil, errors.New("truncated origin")
		}
		origin := string(payload[:originLen])
		payload = payload[originLen:]

		noteLen := int(binary.LittleEndian.Uint32(payload))
		payload = payload[4:]

		if len(payload) < noteLen {
			return nil, errors.New("truncated note")
		}
		states[origin] = bytes.Clone(payload[:noteLen])
		payload = payload[noteLen:]
	}

	return states, nil
}
