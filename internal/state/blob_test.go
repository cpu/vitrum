package state

import (
	"bytes"
	"errors"
	"fmt"
	"maps"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	d := testDevice()
	want := testStates(1)

	if err := Save(d, Offset, testKey, 1, want); err != nil {
		t.Fatal(err)
	}

	got, gen, err := Load(d, Offset, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 1 {
		t.Errorf("gen = %d, want 1", gen)
	}
	if !maps.EqualFunc(got, want, bytes.Equal) {
		t.Errorf("states = %v, want %v", got, want)
	}
}

func TestEmptyDevice(t *testing.T) {
	if _, _, err := Load(testDevice(), Offset, testKey); !errors.Is(err, ErrNoState) {
		t.Fatalf("Load on empty device = %v, want ErrNoState", err)
	}
}

func TestEmptyStates(t *testing.T) {
	d := testDevice()

	if err := Save(d, Offset, testKey, 1, nil); err != nil {
		t.Fatal(err)
	}

	got, gen, err := Load(d, Offset, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 1 || len(got) != 0 {
		t.Errorf("Load = %v gen %d, want empty map gen 1", got, gen)
	}
}

func TestNewerSlotWins(t *testing.T) {
	d := testDevice()

	if err := Save(d, Offset, testKey, 1, testStates(1)); err != nil {
		t.Fatal(err)
	}
	if err := Save(d, Offset, testKey, 2, testStates(2)); err != nil {
		t.Fatal(err)
	}

	got, gen, err := Load(d, Offset, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 2 {
		t.Errorf("gen = %d, want 2", gen)
	}
	if !maps.EqualFunc(got, testStates(2), bytes.Equal) {
		t.Errorf("states = %v, want generation 2", got)
	}
}

func TestTornWriteFallsBack(t *testing.T) {
	d := testDevice()

	if err := Save(d, Offset, testKey, 1, testStates(1)); err != nil {
		t.Fatal(err)
	}
	if err := Save(d, Offset, testKey, 2, testStates(2)); err != nil {
		t.Fatal(err)
	}

	// Corrupt the newer write (gen 2 lives in slot 0) mid-ciphertext,
	// simulating a torn write; authentication of that slot fails and Load
	// falls back to generation 1.
	copy(d.data[Offset+headerLen+4:], []byte("garbage"))

	got, gen, err := Load(d, Offset, testKey)
	if err != nil {
		t.Fatal(err)
	}
	if gen != 1 {
		t.Errorf("gen = %d, want fallback to 1", gen)
	}
	if !maps.EqualFunc(got, testStates(1), bytes.Equal) {
		t.Errorf("states = %v, want generation 1", got)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	d := testDevice()
	if err := Save(d, Offset, testKey, 1, testStates(1)); err != nil {
		t.Fatal(err)
	}

	otherKey := bytes.Repeat([]byte{0x22}, StateKeyLen)
	if _, _, err := Load(d, Offset, otherKey); !errors.Is(err, ErrNoState) {
		t.Fatalf("Load under wrong key = %v, want ErrNoState", err)
	}
}

// TestRelabelRejected: an authentic blob at generation g cannot be presented
// as a different generation. Rewriting only the header generation must fail
// authentication (generation is bound into the AEAD and the nonce).
func TestRelabelRejected(t *testing.T) {
	d := testDevice()
	if err := Save(d, Offset, testKey, 1, testStates(1)); err != nil {
		t.Fatal(err)
	}

	// Bump the stored generation in the slot-1 header from 1 to 9 without
	// re-encrypting.
	d.data[Offset+SlotSize+magicLen] = 9 // little-endian low byte of gen

	if _, _, err := Load(d, Offset, testKey); !errors.Is(err, ErrNoState) {
		t.Fatalf("Load of a relabeled blob = %v, want ErrNoState", err)
	}
}

func TestOversizedPayload(t *testing.T) {
	states := map[string][]byte{
		"example.invalid/log": make([]byte, SlotSize),
	}

	err := Save(testDevice(), Offset, testKey, 1, states)
	if err == nil {
		t.Fatal("Save accepted a payload larger than the slot")
	}
	// Pre-write validation failures must not read as medium-touching ones:
	// RollbackStore halts on ErrWriteFailed but keeps serving on these.
	if errors.Is(err, ErrWriteFailed) {
		t.Fatalf("oversize rejection reported as a write failure: %v", err)
	}
}

// TestWriteFailureClassified pins the Save error classification: only a
// failure of the slot write itself carries ErrWriteFailed.
func TestWriteFailureClassified(t *testing.T) {
	d := &failDevice{memDevice: testDevice(), failWrites: true}

	err := Save(d, Offset, testKey, 1, testStates(1))
	if !errors.Is(err, ErrWriteFailed) {
		t.Fatalf("Save over a failing device = %v, want ErrWriteFailed", err)
	}
}

func TestKeySizeValidated(t *testing.T) {
	if err := Save(testDevice(), Offset, testKey[:16], 1, testStates(1)); err == nil {
		t.Fatal("Save accepted a short key")
	}
	if _, _, err := Load(testDevice(), Offset, testKey[:16]); err == nil {
		t.Fatal("Load accepted a short key")
	}
}

func TestDeviceTooSmall(t *testing.T) {
	d := newMemDevice(512, Offset+SlotSize) // room for one slot only

	if err := Save(d, Offset, testKey, 1, testStates(1)); err == nil {
		t.Fatal("Save accepted gen 1 (slot 1) on a device with room for slot 0 only")
	}
	if err := Save(d, Offset, testKey, 2, testStates(2)); err != nil {
		t.Fatalf("Save gen 2 (slot 0) should fit: %v", err)
	}
}

func TestCorruptHeaders(t *testing.T) {
	corruptions := map[string]func(d *memDevice){
		"magic":  func(d *memDevice) { d.data[Offset] ^= 0xff },
		"length": func(d *memDevice) { copy(d.data[Offset+magicLen+8:], []byte{0xff, 0xff, 0xff, 0xff}) },
		"nonce":  func(d *memDevice) { d.data[Offset+magicLen+12] ^= 0xff },
	}

	for name, corrupt := range corruptions {
		d := testDevice()

		if err := Save(d, Offset, testKey, 0, testStates(1)); err != nil {
			t.Fatal(err)
		}
		corrupt(d)

		if _, _, err := Load(d, Offset, testKey); !errors.Is(err, ErrNoState) {
			t.Errorf("%s corruption: Load = %v, want ErrNoState", name, err)
		}
	}
}

func testStates(gen int) map[string][]byte {
	return map[string][]byte{
		"example.invalid/log-a": fmt.Appendf(nil, "note a generation %d\n", gen),
		"example.invalid/log-b": fmt.Appendf(nil, "note b generation %d\n", gen),
	}
}

func testDevice() *memDevice {
	return newMemDevice(512, Offset+4*SlotSize)
}

// memDevice is an in-memory BlockDevice.
type memDevice struct {
	blockSize int
	data      []byte
}

func newMemDevice(blockSize int, size int64) *memDevice {
	return &memDevice{blockSize: blockSize, data: make([]byte, size)}
}

// snapshot/restore let tests model an adversary capturing and later replaying
// the raw storage contents (a rollback).
func (d *memDevice) snapshot() []byte { return bytes.Clone(d.data) }
func (d *memDevice) restore(b []byte) { copy(d.data, b) }

func (d *memDevice) Info() (int, int64) {
	return d.blockSize, int64(len(d.data)) / int64(d.blockSize)
}

func (d *memDevice) ReadBlocks(lba int64, buf []byte) error {
	off := lba * int64(d.blockSize)
	if off < 0 || off+int64(len(buf)) > int64(len(d.data)) {
		return fmt.Errorf("read out of range")
	}
	copy(buf, d.data[off:])

	return nil
}

func (d *memDevice) WriteBlocks(lba int64, buf []byte) error {
	off := lba * int64(d.blockSize)
	if off < 0 || off+int64(len(buf)) > int64(len(d.data)) {
		return fmt.Errorf("write out of range")
	}
	copy(d.data[off:], buf)

	return nil
}
