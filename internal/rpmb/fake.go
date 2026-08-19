package rpmb

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
)

// FakeCard is an in-memory eMMC RPMB partition for tests and QEMU.
//
// It models the parts of JESD84-B51 the protocol relies on: a
// monotonic write counter, HMAC-SHA256 request/response authentication keyed
// by the programmed key, nonce echo on reads, result-read framing, and the
// key-not-yet-programmed state. Its counter and contents survive across
// [RPMB] instances built over the same FakeCard, so a test can simulate a
// reboot (new RPMB over the same card) and a storage rollback (restore a
// snapshot of unrelated storage) independently; the RPMB counter cannot be
// rolled back.
//
// FakeCard is safe for the single-goroutine use the witness makes of it; its
// mutex only guards against the RPMB instance's own concurrency.
type FakeCard struct {
	mu         sync.Mutex
	programmed bool
	key        [keyLen]byte
	counter    uint32
	sectors    map[uint16][maxData]byte

	// pending holds the response to the last request until the RPMB
	// instance reads it (directly, or after a ResultRead frame).
	pending []byte
}

// NewFakeCard returns an empty, unprogrammed fake RPMB partition.
func NewFakeCard() *FakeCard {
	return &FakeCard{sectors: make(map[uint16][maxData]byte)}
}

// Counter reports the current write counter without going through the
// protocol; for test assertions.
func (c *FakeCard) Counter() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counter
}

// Programmed reports whether a key has been programmed.
func (c *FakeCard) Programmed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.programmed
}

// WriteRPMB consumes a request frame and stages the corresponding response.
func (c *FakeCard) WriteRPMB(buf []byte, _ bool) error {
	if len(buf) != FrameLength {
		return errors.New("frame must be 512 bytes")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var req DataFrame
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &req); err != nil {
		return err
	}

	switch req.Req {
	case ResultRead:
		// The response was already staged by the preceding request.
		return nil
	case AuthenticationKeyProgramming:
		c.stageKeyProgram(&req)
	case WriteCounterRead:
		c.stageCounterRead(&req)
	case AuthenticatedDataWrite:
		c.stageWrite(&req)
	case AuthenticatedDataRead:
		c.stageRead(&req)
	default:
		c.pending = c.errFrame(&req, GeneralFailure)
	}

	return nil
}

// ReadRPMB returns the staged response frame.
func (c *FakeCard) ReadRPMB(buf []byte) error {
	if len(buf) != FrameLength {
		return errors.New("frame must be 512 bytes")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.pending == nil {
		return errors.New("no staged RPMB response")
	}

	copy(buf, c.pending)
	c.pending = nil

	return nil
}

func (c *FakeCard) stageKeyProgram(req *DataFrame) {
	if c.programmed {
		c.pending = c.errFrame(req, GeneralFailure)
		return
	}

	c.key = req.KeyMAC
	c.programmed = true

	// Key-program response is unauthenticated (no key existed to MAC the
	// request) and carries no nonce.
	c.pending = (&DataFrame{Resp: req.Req}).Bytes()
}

func (c *FakeCard) stageCounterRead(req *DataFrame) {
	if !c.programmed {
		c.pending = c.errFrame(req, AuthenticationKeyNotYetProgrammed)
		return
	}

	res := &DataFrame{Resp: req.Req, Nonce: req.Nonce}
	binary.BigEndian.PutUint32(res.WriteCounter[:], c.counter)
	c.pending = c.sign(res)
}

func (c *FakeCard) stageWrite(req *DataFrame) {
	if !c.programmed {
		c.pending = c.errFrame(req, AuthenticationKeyNotYetProgrammed)
		return
	}
	if !c.verify(req) {
		c.pending = c.errFrame(req, AuthenticationFailure)
		return
	}
	if req.Counter() != c.counter {
		c.pending = c.errFrame(req, CounterFailure)
		return
	}

	c.sectors[binary.BigEndian.Uint16(req.Address[:])] = req.Data
	c.counter++

	// The write response echoes the request address and the new counter.
	res := &DataFrame{Resp: req.Req}
	binary.BigEndian.PutUint32(res.WriteCounter[:], c.counter)
	copy(res.Address[:], req.Address[:])
	c.pending = c.sign(res)
}

func (c *FakeCard) stageRead(req *DataFrame) {
	if !c.programmed {
		c.pending = c.errFrame(req, AuthenticationKeyNotYetProgrammed)
		return
	}

	res := &DataFrame{Resp: req.Req, Nonce: req.Nonce}
	copy(res.Address[:], req.Address[:])
	res.Data = c.sectors[binary.BigEndian.Uint16(req.Address[:])]
	c.pending = c.sign(res)
}

// verify checks the request MAC against the programmed key.
func (c *FakeCard) verify(req *DataFrame) bool {
	frame := req.Bytes()
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(frame[FrameLength-macOffset:])
	return hmac.Equal(req.KeyMAC[:], mac.Sum(nil))
}

// sign returns res as bytes with a valid response MAC.
func (c *FakeCard) sign(res *DataFrame) []byte {
	frame := res.Bytes()
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(frame[FrameLength-macOffset:])
	copy(res.KeyMAC[:], mac.Sum(nil))
	return res.Bytes()
}

// errFrame stages an error response echoing the request nonce.
//
// The RPMB client validates the response MAC before it reads the Result
// field, so error responses to authenticated requests must themselves be
// MAC'd or the client reports "invalid response MAC" instead of the real
// result. With no key programmed there is nothing to MAC and the client
// does not check.
func (c *FakeCard) errFrame(req *DataFrame, result uint16) []byte {
	res := &DataFrame{Resp: req.Req, Nonce: req.Nonce}
	binary.BigEndian.PutUint16(res.Result[:], result)
	if c.programmed {
		return c.sign(res)
	}
	return res.Bytes()
}
