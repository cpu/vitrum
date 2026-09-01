package state

import (
	"encoding/binary"
	"fmt"

	"github.com/usbarmory/rpmb"
)

// RPMBAnchor is an Anchor backed by an eMMC RPMB sector.
//
// SetAnchor performs an authenticated RPMB write, which the eMMC controller
// gates on its hardware-monotonic write counter; the generation it stores can
// therefore never be rolled back by an adversary with storage access. The
// stored generation and the RPMB write counter advance together.
type RPMBAnchor struct {
	p *rpmb.RPMB
}

// NewRPMBAnchor returns an anchor over p at the reserved anchor sector.
func NewRPMBAnchor(p *rpmb.RPMB) *RPMBAnchor {
	return &RPMBAnchor{p: p}
}

func (a *RPMBAnchor) Anchor() (uint32, error) {
	buf := make([]byte, 4)
	if err := a.p.Read(rpmbAnchorSector, buf); err != nil {
		return 0, fmt.Errorf("rpmb anchor read: %w", err)
	}
	return binary.BigEndian.Uint32(buf), nil
}

func (a *RPMBAnchor) SetAnchor(g uint32) error {
	cur, err := a.Anchor()
	if err != nil {
		return err
	}
	if g <= cur {
		return fmt.Errorf("anchor not monotonic: setting %d over %d", g, cur)
	}

	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, g)
	if err := a.p.Write(rpmbAnchorSector, buf); err != nil {
		return fmt.Errorf("rpmb anchor write: %w", err)
	}

	return nil
}
