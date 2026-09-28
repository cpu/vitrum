package state

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/usbarmory/rpmb"
)

// RPMBAnchor is an Anchor backed by an eMMC RPMB sector.
//
// SetAnchor performs an authenticated RPMB write, which the eMMC controller
// gates on its hardware-monotonic write counter; the record it stores can
// therefore never be rolled back by an adversary with storage access.
type RPMBAnchor struct {
	p *rpmb.RPMB
}

const (
	anchorGenerationLen = 4
	anchorMagic         = "VITRUMA2"
	anchorRecordLen     = anchorGenerationLen + len(anchorMagic) + len(BlobHash{})
)

// NewRPMBAnchor returns an anchor over p at the reserved anchor sector.
func NewRPMBAnchor(p *rpmb.RPMB) *RPMBAnchor {
	return &RPMBAnchor{p: p}
}

func (a *RPMBAnchor) Anchor() (AnchorState, error) {
	buf := make([]byte, anchorRecordLen)
	if err := a.p.Read(rpmbAnchorSector, buf); err != nil {
		return AnchorState{}, fmt.Errorf("rpmb anchor read: %w", err)
	}

	if bytes.Equal(buf, make([]byte, anchorRecordLen)) {
		return AnchorState{}, nil
	}

	state := AnchorState{Generation: binary.BigEndian.Uint32(buf)}
	magic := buf[anchorGenerationLen : anchorGenerationLen+len(anchorMagic)]
	if !bytes.Equal(magic, []byte(anchorMagic)) {
		return AnchorState{}, fmt.Errorf("rpmb anchor has unknown format")
	}
	copy(state.BlobHash[:], buf[anchorGenerationLen+len(anchorMagic):])
	state.Bound = true

	return state, nil
}

func (a *RPMBAnchor) SetAnchor(next AnchorState) error {
	cur, err := a.Anchor()
	if err != nil {
		return err
	}
	if !next.Bound {
		return fmt.Errorf("anchor state is not bound to a blob")
	}
	if next.Generation <= cur.Generation {
		return fmt.Errorf("anchor not monotonic: setting %d over %d", next.Generation, cur.Generation)
	}

	buf := make([]byte, anchorRecordLen)
	binary.BigEndian.PutUint32(buf, next.Generation)
	copy(buf[anchorGenerationLen:], anchorMagic)
	copy(buf[anchorGenerationLen+len(anchorMagic):], next.BlobHash[:])
	if err := a.p.Write(rpmbAnchorSector, buf); err != nil {
		return fmt.Errorf("rpmb anchor write: %w", err)
	}

	return nil
}
