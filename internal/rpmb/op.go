// Copyright 2022 The Armored Witness OS authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Adapted from github.com/usbarmory/rpmb; see rpmb.go for the list of vitrum
// modifications.

package rpmb

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrInvalidResponseMAC reports that an authenticated response was not signed
// by the key supplied to Init.
var ErrInvalidResponseMAC = errors.New("invalid response MAC")

const (
	// FrameLength is the fixed RPMB data frame size.
	FrameLength = 512

	// macOffset is measured from the end of the frame: the MAC covers the
	// trailing 284 bytes (Data through Req), excluding StuffBytes and
	// KeyMAC. JESD84-B51 bytes [228..511].
	macOffset = 284

	// maxData is the data payload per frame.
	maxData = 256
)

// p99, Table 18, RPMB Request/Response Message Types, JESD84-B51.
const (
	AuthenticationKeyProgramming = iota + 1
	WriteCounterRead
	AuthenticatedDataWrite
	AuthenticatedDataRead
	ResultRead
)

// p100, Table 20, RPMB Operation Results, JESD84-B51.
const (
	OperationOK = iota
	GeneralFailure
	AuthenticationFailure
	CounterFailure
	AddressFailure
	WriteFailure
	ReadFailure
	AuthenticationKeyNotYetProgrammed
)

// OperationError is a non-OK RPMB operation result reported by the card.
type OperationError struct {
	Result uint16
}

func (e *OperationError) Error() string {
	return fmt.Sprintf("RPMB operation failed (result 0x%x)", e.Result)
}

// Config selects the per-operation frame protections.
type Config struct {
	// RequestMAC computes the request MAC before sending.
	RequestMAC bool
	// ResponseMAC validates the response MAC after receiving.
	ResponseMAC bool
	// RandomNonce sets the Nonce field to a fresh random value.
	RandomNonce bool
	// ResultRead fetches the response via a follow-up result-read frame.
	ResultRead bool
}

// DataFrame is the 512-byte RPMB frame (p98, Table 17, JESD84-B51). Field
// order and sizes are the wire layout; multi-byte semantic fields
// (WriteCounter, Address, BlockCount, Result) are big-endian.
type DataFrame struct {
	StuffBytes   [196]byte
	KeyMAC       [32]byte
	Data         [256]byte
	Nonce        [16]byte
	WriteCounter [4]byte
	Address      [2]byte
	BlockCount   [2]byte
	Result       [2]byte
	Resp         byte
	Req          byte
}

// Counter returns the frame's WriteCounter as a uint32.
func (d *DataFrame) Counter() uint32 {
	return binary.BigEndian.Uint32(d.WriteCounter[:])
}

// Bytes serializes the frame to its 512-byte wire form.
//
// The struct is all byte arrays and single bytes, so serialization
// endianness does not affect field order; the semantic big-endian fields are
// already stored big-endian.
func (d *DataFrame) Bytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, d)
	return buf.Bytes()
}

func (p *RPMB) op(req *DataFrame, cfg *Config) (res *DataFrame, err error) {
	p.Lock()
	defer p.Unlock()

	if !p.init {
		return nil, errors.New("RPMB instance not initialized")
	}

	mac := hmac.New(sha256.New, p.key[:])

	if cfg.RequestMAC {
		mac.Write(req.Bytes()[FrameLength-macOffset:])
		copy(req.KeyMAC[:], mac.Sum(nil))
		mac.Reset()
	}

	if cfg.RandomNonce {
		if _, err = rand.Read(req.Nonce[:]); err != nil {
			return nil, err
		}
	}

	var rel bool
	switch req.Req {
	case AuthenticationKeyProgramming, AuthenticatedDataWrite:
		rel = true
	}

	// send request
	if err = p.card.WriteRPMB(req.Bytes(), rel); err != nil {
		return
	}

	// result read: the response to a write / key program is only returned
	// after a follow-up ResultRead request frame.
	if cfg.ResultRead {
		resReq := DataFrame{Req: ResultRead}
		if err = p.card.WriteRPMB(resReq.Bytes(), false); err != nil {
			return
		}
	}

	buf := make([]byte, FrameLength)
	if err = p.card.ReadRPMB(buf); err != nil {
		return
	}

	res = &DataFrame{}
	if err = binary.Read(bytes.NewReader(buf), binary.LittleEndian, res); err != nil {
		return
	}

	if cfg.ResponseMAC {
		mac.Write(buf[FrameLength-macOffset:])
		if !hmac.Equal(res.KeyMAC[:], mac.Sum(nil)) {
			return nil, ErrInvalidResponseMAC
		}
	}

	if req.Req != res.Resp {
		return nil, errors.New("request/response type mismatch")
	}

	if req.Nonce != res.Nonce {
		return nil, errors.New("nonce mismatch")
	}

	if result := binary.BigEndian.Uint16(res.Result[:]); result != OperationOK {
		return nil, &OperationError{result}
	}

	return
}

func (p *RPMB) transfer(kind byte, offset uint16, buf []byte) (err error) {
	if len(buf) > maxData {
		return fmt.Errorf("transfer size %d exceeds %d bytes", len(buf), maxData)
	}

	cfg := &Config{
		RequestMAC:  true,
		ResponseMAC: true,
	}

	req := &DataFrame{Req: kind}

	if kind == AuthenticatedDataWrite {
		// An authenticated write must carry the current write counter;
		// the card increments it and echoes counter+1, which we verify
		// below (CVE-2020-13799).
		counter, err := p.Counter(true)
		if err != nil {
			return err
		}

		binary.BigEndian.PutUint32(req.WriteCounter[:], counter)
		cfg.ResultRead = true
	} else {
		cfg.RandomNonce = true
	}

	binary.BigEndian.PutUint16(req.BlockCount[:], 1)
	binary.BigEndian.PutUint16(req.Address[:], offset)
	copy(req.Data[:], buf)

	res, err := p.op(req, cfg)
	if err != nil {
		return
	}

	if kind == AuthenticatedDataRead {
		// Bind the response to the requested sector: defense in depth over
		// the nonce+MAC binding, and required if a caller ever reads a
		// variable sector.
		if !bytes.Equal(res.Address[:], req.Address[:]) {
			return errors.New("response address mismatch")
		}
		copy(buf, res.Data[:])
	} else if res.Counter() != req.Counter()+1 {
		return errors.New("write counter mismatch")
	}

	return
}
