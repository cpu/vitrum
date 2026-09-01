// Package rpmbtest provides test support for Vitrum's RPMB users.
package rpmbtest

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"

	"github.com/usbarmory/rpmb"
)

const (
	keyLen    = 32
	maxData   = rpmb.FrameLength / 2
	macOffset = 284
)

// FakeCard is an in-memory eMMC RPMB partition for tests.
//
// It models the parts of JESD84-B51 Vitrum relies on: reliable writes, a
// monotonic write counter, HMAC-SHA256 request and response authentication,
// nonce echo on reads, result-read framing, and the unprogrammed-key state.
// Its counter and contents survive across RPMB instances built over the same
// card, allowing tests to model a reboot independently from a storage rollback.
type FakeCard struct {
	mu         sync.Mutex
	programmed bool
	key        [keyLen]byte
	counter    uint32
	sectors    map[uint16][maxData]byte
	pending    []byte
}

// NewFakeCard returns an empty, unprogrammed fake RPMB partition.
func NewFakeCard() *FakeCard {
	return &FakeCard{sectors: make(map[uint16][maxData]byte)}
}

// Counter reports the write counter without going through the protocol.
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

// WriteRPMB consumes a request frame and stages its response.
func (c *FakeCard) WriteRPMB(buf []byte, reliable bool) error {
	if len(buf) != rpmb.FrameLength {
		return errors.New("frame must be 512 bytes")
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	var req rpmb.DataFrame
	if err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &req); err != nil {
		return err
	}

	wantReliable := req.Req == rpmb.AuthenticationKeyProgramming || req.Req == rpmb.AuthenticatedDataWrite
	if reliable != wantReliable {
		return errors.New("invalid reliable write setting")
	}

	switch req.Req {
	case rpmb.ResultRead:
		// The preceding operation already staged its response.
		return nil
	case rpmb.AuthenticationKeyProgramming:
		c.stageKeyProgram(&req)
	case rpmb.WriteCounterRead:
		c.stageCounterRead(&req)
	case rpmb.AuthenticatedDataWrite:
		c.stageWrite(&req)
	case rpmb.AuthenticatedDataRead:
		c.stageRead(&req)
	default:
		c.pending = c.errFrame(&req, rpmb.GeneralFailure)
	}

	return nil
}

// ReadRPMB returns the staged response frame.
func (c *FakeCard) ReadRPMB(buf []byte) error {
	if len(buf) != rpmb.FrameLength {
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

func (c *FakeCard) stageKeyProgram(req *rpmb.DataFrame) {
	if c.programmed {
		c.pending = c.errFrame(req, rpmb.GeneralFailure)
		return
	}

	c.key = req.KeyMAC
	c.programmed = true
	c.pending = (&rpmb.DataFrame{Resp: req.Req}).Bytes()
}

func (c *FakeCard) stageCounterRead(req *rpmb.DataFrame) {
	if !c.programmed {
		c.pending = c.errFrame(req, rpmb.AuthenticationKeyNotYetProgrammed)
		return
	}

	res := &rpmb.DataFrame{Resp: req.Req, Nonce: req.Nonce}
	binary.BigEndian.PutUint32(res.WriteCounter[:], c.counter)
	c.pending = c.sign(res)
}

func (c *FakeCard) stageWrite(req *rpmb.DataFrame) {
	if !c.programmed {
		c.pending = c.errFrame(req, rpmb.AuthenticationKeyNotYetProgrammed)
		return
	}
	if !c.verify(req) {
		c.pending = c.errFrame(req, rpmb.AuthenticationFailure)
		return
	}
	if req.Counter() != c.counter {
		c.pending = c.errFrame(req, rpmb.CounterFailure)
		return
	}

	c.sectors[binary.BigEndian.Uint16(req.Address[:])] = req.Data
	c.counter++

	res := &rpmb.DataFrame{Resp: req.Req}
	binary.BigEndian.PutUint32(res.WriteCounter[:], c.counter)
	copy(res.Address[:], req.Address[:])
	c.pending = c.sign(res)
}

func (c *FakeCard) stageRead(req *rpmb.DataFrame) {
	if !c.programmed {
		c.pending = c.errFrame(req, rpmb.AuthenticationKeyNotYetProgrammed)
		return
	}

	res := &rpmb.DataFrame{Resp: req.Req, Nonce: req.Nonce}
	copy(res.Address[:], req.Address[:])
	res.Data = c.sectors[binary.BigEndian.Uint16(req.Address[:])]
	c.pending = c.sign(res)
}

func (c *FakeCard) verify(req *rpmb.DataFrame) bool {
	frame := req.Bytes()
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(frame[rpmb.FrameLength-macOffset:])
	return hmac.Equal(req.KeyMAC[:], mac.Sum(nil))
}

func (c *FakeCard) sign(res *rpmb.DataFrame) []byte {
	frame := res.Bytes()
	mac := hmac.New(sha256.New, c.key[:])
	mac.Write(frame[rpmb.FrameLength-macOffset:])
	copy(res.KeyMAC[:], mac.Sum(nil))
	return res.Bytes()
}

func (c *FakeCard) errFrame(req *rpmb.DataFrame, result uint16) []byte {
	res := &rpmb.DataFrame{Resp: req.Req, Nonce: req.Nonce}
	binary.BigEndian.PutUint16(res.Result[:], result)
	if c.programmed {
		return c.sign(res)
	}
	return res.Bytes()
}
