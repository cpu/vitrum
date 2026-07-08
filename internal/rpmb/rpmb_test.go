package rpmb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
)

var testKey = bytes.Repeat([]byte{0xA5}, keyLen)

// newProgrammed returns a card with testKey already programmed and an RPMB
// instance bound to it.
func newProgrammed(t *testing.T) (*FakeCard, *RPMB) {
	t.Helper()

	card := NewFakeCard()

	// A separate instance programs the key (the firmware never does this
	// automatically; tests stand in for the one-time provisioning step).
	programmer, err := Init(card, testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := programmer.ProgramKey(); err != nil {
		t.Fatalf("ProgramKey: %v", err)
	}

	p, err := Init(card, testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	return card, p
}

func TestInitValidation(t *testing.T) {
	if _, err := Init(nil, testKey, 0, false); err == nil {
		t.Error("Init accepted nil transport")
	}
	if _, err := Init(NewFakeCard(), testKey[:16], 0, false); err == nil {
		t.Error("Init accepted a short key")
	}
}

func TestCounterRequiresProgrammedKey(t *testing.T) {
	p, err := Init(NewFakeCard(), testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	// Unauthenticated read surfaces the not-programmed result.
	_, err = p.Counter(false)
	var opErr *OperationError
	if !errors.As(err, &opErr) || opErr.Result != AuthenticationKeyNotYetProgrammed {
		t.Fatalf("Counter on unprogrammed card = %v, want AuthenticationKeyNotYetProgrammed", err)
	}
}

func TestProgramKeyOnce(t *testing.T) {
	card := NewFakeCard()
	p, err := Init(card, testKey, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	if err := p.ProgramKey(); err != nil {
		t.Fatalf("first ProgramKey: %v", err)
	}
	if !card.Programmed() {
		t.Fatal("card not marked programmed")
	}

	// Re-programming a programmed card fails (irreversible on hardware).
	if err := p.ProgramKey(); err == nil {
		t.Fatal("second ProgramKey unexpectedly succeeded")
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	_, p := newProgrammed(t)

	want := bytes.Repeat([]byte("vitrum!!"), 32) // 256 bytes
	if err := p.Write(2, want); err != nil {
		t.Fatalf("Write: %v", err)
	}

	got := make([]byte, maxData)
	if err := p.Read(2, got); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("Read returned %x…, want %x…", got[:8], want[:8])
	}
}

func TestWriteAdvancesCounter(t *testing.T) {
	card, p := newProgrammed(t)

	if c := card.Counter(); c != 0 {
		t.Fatalf("fresh counter = %d, want 0", c)
	}

	for i := uint32(1); i <= 3; i++ {
		if err := p.Write(1, []byte{byte(i)}); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}

		n, err := p.Counter(true)
		if err != nil {
			t.Fatalf("Counter after write %d: %v", i, err)
		}
		if n != i {
			t.Errorf("counter after %d writes = %d, want %d", i, n, i)
		}
	}
}

func TestReadTooLarge(t *testing.T) {
	_, p := newProgrammed(t)

	if err := p.Write(0, make([]byte, maxData+1)); err == nil {
		t.Error("Write accepted more than 256 bytes")
	}
}

// TestTamperedResponseMACRejected confirms the client rejects a response
// whose contents were altered after the card signed it.
func TestTamperedResponseMACRejected(t *testing.T) {
	card, p := newProgrammed(t)

	tc := &tamperCard{FakeCard: card, flip: true}
	p.card = tc

	_, err := p.Counter(true)
	if err == nil || err.Error() != "invalid response MAC" {
		t.Fatalf("authenticated Counter over tampered transport = %v, want invalid response MAC", err)
	}
}

// tamperCard flips a data byte of every response frame, invalidating the MAC.
type tamperCard struct {
	*FakeCard
	flip bool
}

func (t *tamperCard) ReadRPMB(buf []byte) error {
	if err := t.FakeCard.ReadRPMB(buf); err != nil {
		return err
	}
	if t.flip {
		buf[300] ^= 0xff // inside the MAC-covered region
	}
	return nil
}

// TestReadAddressMismatchRejected: a response for a different sector than
// requested must be refused, even if it is otherwise well-formed and MAC'd.
func TestReadAddressMismatchRejected(t *testing.T) {
	card, p := newProgrammed(t)
	if err := p.Write(2, []byte("data")); err != nil {
		t.Fatal(err)
	}

	// Wrap the card so read responses come back stamped with the wrong
	// address (re-MAC'd so the MAC check passes and the address check is
	// what must catch it).
	p.card = &misaddrCard{FakeCard: card}

	if err := p.Read(2, make([]byte, maxData)); err == nil || err.Error() != "response address mismatch" {
		t.Fatalf("Read of a misaddressed response = %v, want response address mismatch", err)
	}
}

// misaddrCard rewrites the response Address to a different sector and re-signs.
type misaddrCard struct {
	*FakeCard
}

func (m *misaddrCard) ReadRPMB(buf []byte) error {
	if err := m.FakeCard.ReadRPMB(buf); err != nil {
		return err
	}
	var res DataFrame
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &res); err != nil {
		return err
	}
	if res.Resp == AuthenticatedDataRead {
		binary.BigEndian.PutUint16(res.Address[:], 999) // wrong sector
		copy(buf, m.FakeCard.sign(&res))
	}
	return nil
}

// TestStaleWriteResponseRejected: an authenticated write's response must
// echo exactly counter+1 (the CVE-2020-13799 verification). A stale response
// frame captured from an earlier write is validly MAC'd by the card itself,
// so only the counter check can catch it; this is the property ROLLBACK.md
// relies on to skip the boot-time dummy write.
func TestStaleWriteResponseRejected(t *testing.T) {
	card, p := newProgrammed(t)

	rc := &replayCard{FakeCard: card}
	p.card = rc

	// First write: capture the card's genuine result response (counter 1).
	rc.mode = captureResponse
	if err := p.Write(2, []byte("first")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// Second write: the card processes it (its counter advances), but the
	// client is served the held-back stale response instead.
	rc.mode = replayResponse
	err := p.Write(2, []byte("second"))
	if err == nil || err.Error() != "write counter mismatch" {
		t.Fatalf("Write with a replayed stale response = %v, want write counter mismatch", err)
	}
}

const (
	captureResponse = iota + 1
	replayResponse
)

// replayCard passes traffic through to the FakeCard but can capture the
// response to a write's result read and later serve it in place of a fresh
// one (a held-back stale response, MAC'd by the card itself).
type replayCard struct {
	*FakeCard
	mode       int // 0 passthrough, captureResponse, replayResponse
	resultRead bool
	captured   []byte
}

func (c *replayCard) WriteRPMB(buf []byte, rel bool) error {
	var req DataFrame
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &req); err == nil && req.Req == ResultRead {
		c.resultRead = true
	}
	return c.FakeCard.WriteRPMB(buf, rel)
}

func (c *replayCard) ReadRPMB(buf []byte) error {
	if err := c.FakeCard.ReadRPMB(buf); err != nil {
		return err
	}
	if !c.resultRead {
		return nil // e.g. a counter-read response: pass through
	}
	c.resultRead = false

	switch c.mode {
	case captureResponse:
		c.captured = bytes.Clone(buf)
	case replayResponse:
		copy(buf, c.captured)
	}

	return nil
}

// TestMACCoversExpectedBytes pins the MAC input to frame[228:512], guarding
// against an accidental offset change.
func TestMACCoversExpectedBytes(t *testing.T) {
	if FrameLength-macOffset != 228 {
		t.Fatalf("MAC start offset = %d, want 228", FrameLength-macOffset)
	}

	var f DataFrame
	f.Data[0] = 0x11
	frame := f.Bytes()
	if len(frame) != FrameLength {
		t.Fatalf("frame length %d, want %d", len(frame), FrameLength)
	}

	mac := hmac.New(sha256.New, testKey)
	mac.Write(frame[228:])
	sum := mac.Sum(nil)

	// A change before offset 228 (in KeyMAC/StuffBytes) must not affect it;
	// a change at/after 228 must.
	f.KeyMAC[0] ^= 0xff
	mac.Reset()
	mac.Write(f.Bytes()[228:])
	if !hmac.Equal(sum, mac.Sum(nil)) {
		t.Error("MAC changed when a byte before offset 228 changed")
	}

	f.Data[0] ^= 0xff
	mac.Reset()
	mac.Write(f.Bytes()[228:])
	if hmac.Equal(sum, mac.Sum(nil)) {
		t.Error("MAC unchanged when a byte at offset 228 changed")
	}
}

func TestFrameLayoutOffsets(t *testing.T) {
	// Guard the wire layout: total size and the counter field position.
	var f DataFrame
	binary.BigEndian.PutUint32(f.WriteCounter[:], 0xdeadbeef)
	frame := f.Bytes()

	if len(frame) != 512 {
		t.Fatalf("frame size %d, want 512", len(frame))
	}
	// WriteCounter is at offset 500 (196+32+256+16).
	if got := binary.BigEndian.Uint32(frame[500:504]); got != 0xdeadbeef {
		t.Errorf("WriteCounter at [500:504] = %x, want deadbeef", got)
	}
}
