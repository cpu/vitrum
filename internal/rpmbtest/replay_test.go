package rpmbtest

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/usbarmory/rpmb"
)

// TestClientRejectsStaleWriteResponse preserves the response-replay coverage
// Vitrum's rollback design relies on. The replay is a genuine, previously
// authenticated card response, so only the client's counter check rejects it.
func TestClientRejectsStaleWriteResponse(t *testing.T) {
	key := bytes.Repeat([]byte{0xa5}, 32)
	card := NewFakeCard()

	programmer, err := rpmb.InitWithTransport(card, key, 0, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := programmer.ProgramKey(); err != nil {
		t.Fatalf("ProgramKey: %v", err)
	}

	transport := &replayTransport{FakeCard: card}
	p, err := rpmb.InitWithTransport(transport, key, 0, false)
	if err != nil {
		t.Fatal(err)
	}

	transport.mode = captureResponse
	if err := p.Write(2, []byte("first")); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	transport.mode = replayResponse
	if err := p.Write(2, []byte("second")); err == nil || err.Error() != "write counter mismatch" {
		t.Fatalf("Write with stale response = %v, want write counter mismatch", err)
	}
}

const (
	captureResponse = iota + 1
	replayResponse
)

// replayTransport captures a write result and can substitute it for a later
// result without altering its valid MAC.
type replayTransport struct {
	*FakeCard
	mode       int
	resultRead bool
	captured   []byte
}

func (c *replayTransport) WriteRPMB(buf []byte, reliable bool) error {
	var req rpmb.DataFrame
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &req); err == nil && req.Req == rpmb.ResultRead {
		c.resultRead = true
	}
	return c.FakeCard.WriteRPMB(buf, reliable)
}

func (c *replayTransport) ReadRPMB(buf []byte) error {
	if err := c.FakeCard.ReadRPMB(buf); err != nil {
		return err
	}
	if !c.resultRead {
		return nil
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
