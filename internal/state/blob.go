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
	"crypto/rand"
	"crypto/sha256"
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

	magicLen            = 8
	generationLen       = 4
	legacyGenerationLen = 8
	lengthLen           = 4
	legacyNonceLen      = 12
	nonceLen            = 16
	tagLen              = 16 // AES-GCM tag
	nonceOffset         = magicLen + generationLen + lengthLen
	legacyNonceOffset   = magicLen + legacyGenerationLen + lengthLen
	headerLen           = nonceOffset + nonceLen
	legacyHeaderLen     = legacyNonceOffset + legacyNonceLen
)

var (
	legacyMagic = []byte("VITRUMW1")
	magic       = []byte("VITRUMW2")
)

// BlobHash identifies an encoded state blob.
type BlobHash [sha256.Size]byte

// ErrNoState reports that no valid slot was found (fresh card, both slots
// corrupt, or none authenticated under the current key).
var ErrNoState = errors.New("no valid state found")

// ErrWriteFailed marks a Save failure at or after the point where the slot
// write was issued: the slot contents are unknown. Errors before this point
// leave the medium untouched.
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
// The generation is uint32 to match the hardware anchor. Alternating slots by
// gen means a torn write can only destroy the newer slot and the previous
// generation remains loadable. The generation is bound into the AEAD as
// additional data, so a blob cannot be relabeled without detection.
func Save(d BlockDevice, offset int64, key []byte, gen uint32, states map[string][]byte) error {
	_, err := save(d, offset, key, gen, states)
	return err
}

func save(d BlockDevice, offset int64, key []byte, gen uint32, states map[string][]byte) (BlobHash, error) {
	aead, err := newAEAD(key, nonceLen)
	if err != nil {
		return BlobHash{}, err
	}

	plaintext, err := encode(states)
	if err != nil {
		return BlobHash{}, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return BlobHash{}, fmt.Errorf("state nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, genAAD(gen))

	if headerLen+len(ciphertext) > SlotSize {
		return BlobHash{}, fmt.Errorf("state blob (%d bytes) exceeds slot size", len(ciphertext))
	}

	buf := make([]byte, SlotSize)
	copy(buf, magic)
	binary.LittleEndian.PutUint32(buf[magicLen:], gen)
	binary.LittleEndian.PutUint32(buf[magicLen+generationLen:], uint32(len(ciphertext)))
	copy(buf[nonceOffset:], nonce)
	copy(buf[headerLen:], ciphertext)

	lba, err := slotLBA(d, offset, uint64(gen)%2)
	if err != nil {
		return BlobHash{}, err
	}

	if err := d.WriteBlocks(lba, buf); err != nil {
		return BlobHash{}, fmt.Errorf("%w: %w", ErrWriteFailed, err)
	}

	return sha256.Sum256(buf[:headerLen+len(ciphertext)]), nil
}

// Load reads both slots and returns the states and generation of the valid
// slot (decrypts and authenticates under key) with the highest generation.
//
// It returns ErrNoState if neither slot is valid.
func Load(d BlockDevice, offset int64, key []byte) (states map[string][]byte, gen uint32, err error) {
	blob, err := load(d, offset, key)
	if err != nil {
		return nil, 0, err
	}
	return blob.states, blob.gen, nil
}

type loadedBlob struct {
	states map[string][]byte
	gen    uint32
	hash   BlobHash
	legacy bool
}

func load(d BlockDevice, offset int64, key []byte) (loadedBlob, error) {
	if len(key) != StateKeyLen {
		return loadedBlob{}, fmt.Errorf("state key is %d bytes, want %d", len(key), StateKeyLen)
	}

	var newest loadedBlob
	var found bool

	for slot := uint64(0); slot < 2; slot++ {
		blob, err := loadSlot(d, offset, slot, key)
		if err != nil {
			continue
		}

		if !found || blob.gen > newest.gen {
			newest, found = blob, true
		}
	}

	if !found {
		return loadedBlob{}, ErrNoState
	}

	return newest, nil
}

func loadSlot(d BlockDevice, offset int64, slot uint64, key []byte) (loadedBlob, error) {
	lba, err := slotLBA(d, offset, slot)
	if err != nil {
		return loadedBlob{}, err
	}

	buf := make([]byte, SlotSize)
	if err := d.ReadBlocks(lba, buf); err != nil {
		return loadedBlob{}, err
	}

	var gen uint32
	var length uint32
	var nonce []byte
	var hLen int
	var legacy bool
	switch {
	case bytes.Equal(buf[:magicLen], magic):
		gen = binary.LittleEndian.Uint32(buf[magicLen:])
		length = binary.LittleEndian.Uint32(buf[magicLen+generationLen:])
		nonce = buf[nonceOffset:headerLen]
		hLen = headerLen
	case bytes.Equal(buf[:magicLen], legacyMagic):
		legacy = true
		gen64 := binary.LittleEndian.Uint64(buf[magicLen:])
		if gen64 > math.MaxUint32 {
			return loadedBlob{}, errors.New("generation out of range")
		}
		gen = uint32(gen64)
		length = binary.LittleEndian.Uint32(buf[magicLen+legacyGenerationLen:])
		nonce = buf[legacyNonceOffset:legacyHeaderLen]
		hLen = legacyHeaderLen
	default:
		return loadedBlob{}, errors.New("bad magic")
	}

	if int(length) < tagLen || int(length) > SlotSize-hLen {
		return loadedBlob{}, errors.New("bad ciphertext length")
	}

	ciphertext := buf[hLen : hLen+int(length)]

	if legacy && !bytes.Equal(nonce, deriveLegacyNonce(gen)) {
		return loadedBlob{}, errors.New("nonce/generation mismatch")
	}

	aead, err := newAEAD(key, len(nonce))
	if err != nil {
		return loadedBlob{}, err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, genAAD(gen))
	if err != nil {
		return loadedBlob{}, fmt.Errorf("authentication failed: %w", err)
	}

	states, err := decode(plaintext)
	if err != nil {
		return loadedBlob{}, err
	}

	return loadedBlob{
		states: states,
		gen:    gen,
		hash:   sha256.Sum256(buf[:hLen+int(length)]),
		legacy: legacy,
	}, nil
}

func newAEAD(key []byte, nonceSize int) (cipher.AEAD, error) {
	if len(key) != StateKeyLen {
		return nil, fmt.Errorf("state key is %d bytes, want %d", len(key), StateKeyLen)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithNonceSize(block, nonceSize)
}

// genAAD binds the generation into the AEAD so a valid blob cannot be
// relabeled to a different generation.
func genAAD(gen uint32) []byte {
	aad := make([]byte, 4)
	binary.LittleEndian.PutUint32(aad, gen)
	return aad
}

func deriveLegacyNonce(gen uint32) []byte {
	nonce := make([]byte, legacyNonceLen)
	copy(nonce, legacyMagic[:4])
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
