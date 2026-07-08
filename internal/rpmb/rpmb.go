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

// Package rpmb implements the eMMC Replay Protected Memory Block (RPMB)
// protocol: authenticated, hardware-monotonic-counter-backed storage.
//
// It is adapted from github.com/usbarmory/rpmb (Apache-2.0, "The Armored
// Witness OS authors"). vitrum's modifications:
//
//   - The dependency on the concrete *usdhc.USDHC is replaced by the small
//     [Transport] interface (the two single-512-byte-frame primitives), so
//     the whole protocol (HMAC, counter reads, result reads) is exercisable
//     off-hardware by host tests against a faithful fake eMMC ([FakeCard]).
//   - The unused AuthenticatedDeviceConfiguration{Write,Read} message types
//     are dropped.
//   - No key derivation, fuse gating, or ProgramKey automation lives here: the
//     32-byte MAC key is supplied by the caller. Programming the RPMB key is a
//     one-time-per-eMMC operation with the same handling rules as fuses. It is
//     deliberately gated to an explicit, separate call the firmware never
//     invokes on its own.
package rpmb

import (
	"errors"
	"fmt"
	"sync"
)

// keyLen is the RPMB authentication key / HMAC-SHA256 key length.
const keyLen = 32

// Transport transfers single 512-byte RPMB data frames to and from the eMMC
// RPMB partition.
//
// It is satisfied by tamago's *usdhc.USDHC (WriteRPMB/ReadRPMB) on hardware
// and by [FakeCard] in tests. Both frame buffers are exactly [FrameLength]
// bytes; rel requests an eMMC reliable write (required for authenticated
// writes and key programming).
type Transport interface {
	WriteRPMB(buf []byte, rel bool) error
	ReadRPMB(buf []byte) error
}

// RPMB is an authenticated RPMB partition access instance.
type RPMB struct {
	sync.Mutex

	card Transport
	key  [keyLen]byte
	init bool
}

// Init returns a new RPMB instance bound to card and MAC key.
//
// dummyBlock is an otherwise-unused sector; when writeDummy is set Init
// performs a throwaway authenticated write to it to invalidate any
// uncommitted prior write (CVE-2020-13799 mitigation). Pass writeDummy only
// when the RPMB key is already programmed; an authenticated write against an
// unprogrammed partition fails.
func Init(card Transport, key []byte, dummyBlock uint16, writeDummy bool) (p *RPMB, err error) {
	if card == nil {
		return nil, errors.New("no RPMB transport set")
	}

	if len(key) != keyLen {
		return nil, fmt.Errorf("MAC key is %d bytes, want %d", len(key), keyLen)
	}

	p = &RPMB{
		card: card,
		init: true,
	}

	copy(p.key[:], key)

	if writeDummy {
		if err = p.Write(dummyBlock, nil); err != nil {
			return nil, err
		}
	}

	return
}

// ProgramKey programs the RPMB partition authentication key.
//
// *WARNING*: this is a one-time, irreversible operation for the eMMC. Same
// handling rules as fuses: the firmware never calls this on its
// own; it exists only for an explicit, human-approved provisioning path.
func (p *RPMB) ProgramKey() (err error) {
	cfg := &Config{
		ResultRead: true,
	}

	req := &DataFrame{
		KeyMAC: p.key,
		Req:    AuthenticationKeyProgramming,
	}

	_, err = p.op(req, cfg)

	return
}

// Counter returns the RPMB partition write counter. When auth is set the
// response MAC and nonce are validated (an authenticated read); when clear it
// is a bare counter read, usable to probe whether the key is programmed.
func (p *RPMB) Counter(auth bool) (n uint32, err error) {
	cfg := &Config{
		RandomNonce: auth,
		ResponseMAC: auth,
	}

	req := &DataFrame{
		Req: WriteCounterRead,
	}

	res, err := p.op(req, cfg)
	if err != nil {
		return
	}

	return res.Counter(), nil
}

// Write performs an authenticated write of up to 256 bytes to the RPMB
// partition sector at offset.
//
// It mitigates CVE-2020-13799 by requiring the response counter to be exactly
// one greater than the request counter.
func (p *RPMB) Write(offset uint16, buf []byte) (err error) {
	return p.transfer(AuthenticatedDataWrite, offset, buf)
}

// Read performs an authenticated read of up to 256 bytes from the RPMB
// partition sector at offset into buf.
func (p *RPMB) Read(offset uint16, buf []byte) (err error) {
	return p.transfer(AuthenticatedDataRead, offset, buf)
}
