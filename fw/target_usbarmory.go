//go:build usbarmory

package main

import (
	"errors"
	"fmt"
	"log"
	"net"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/enet"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"github.com/usbarmory/tamago/soc/nxp/usb"
	"github.com/usbarmory/tamago/soc/nxp/usdhc"

	gnet "github.com/usbarmory/go-net"
	usbnet "github.com/usbarmory/go-net/imx-usb"

	"github.com/cpu/vitrum/fw/internal/devicekey"
	"github.com/cpu/vitrum/internal/rpmb"
	"github.com/cpu/vitrum/internal/state"
)

const target = "usbarmory"

// netInit brings up CDC-ECM Ethernet-over-USB on USB1.
func netInit() (*usb.USB, *enet.ENET, *gnet.Interface, error) {
	iface, err := newInterface(nil)
	if err != nil {
		return nil, nil, nil, err
	}

	ecm := &usbnet.ECM{
		Stack: iface.Stack,
	}

	ecm.HostMAC, _ = net.ParseMAC(HostMAC)
	ecm.DeviceMAC, _ = net.ParseMAC(MAC)

	if err := ecm.Init(); err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize Ethernet over USB, %v", err)
	}

	port := imx6ul.USB1
	port.Device = ecm.Device
	port.Init()
	port.DeviceMode()

	port.EnableInterrupt(usb.IRQ_URI) // reset
	port.EnableInterrupt(usb.IRQ_PCI) // port change detect
	port.EnableInterrupt(usb.IRQ_UI)  // transfer completion

	return port, nil, iface, nil
}

func led(name string, on bool) {
	usbarmory.LED(name, on)
}

// hostKeySeed derives the SSH host key seed from the hardware-unique key:
// KDF(HUK, diversifierHostKey). The identity is stable across boots and
// firmware updates and never present in the image or on storage; clients
// pair with it once and pin it.
//
// No fallback: a unit that cannot derive its identity must not present a
// weaker one (an embedded seed could be read straight off the boot card).
//
// Pre-fuse the HUK is a non-unique test vector; deriveKey logs this and the
// source string carries a DEV mark.
func hostKeySeed() (seed []byte, source string, err error) {
	seed, dev, err := devicekey.Derive(devicekey.HostKey)
	if err != nil {
		return nil, "", fmt.Errorf("host key derivation: %w", err)
	}

	source = "HUK-derived"
	if dev {
		source += " [DEV: unfused, non-unique HUK]"
	}

	return seed, source, nil
}

// newStorage assembles the rollback-protected persistence layer: the microSD
// boot card holds the encrypted state blob, the eMMC RPMB write counter is
// the hardware anchor, and the keys are device-bound (CAAM/DCP + unique ID).
// See internal/state/ROLLBACK.md.
//
// On emulation, or when an unfused (DEV) unit cannot bring up the microSD or
// RPMB, it returns an empty storage{} (RAM-only, no rollback protection) and
// logs a warning. On a fused unit the same degradation would silently drop
// rollback protection, so storage bring-up failure is fatal instead (fail
// closed). Programming the RPMB key is never attempted here (one-way op).
func newStorage() storage {
	if !imx6ul.Native {
		return storage{}
	}

	// The same SNVS signal deriveKey uses for its DEV marker: on a fused
	// unit the derived keys are real, so a RAM-only fallback is not
	// acceptable.
	fused := imx6ul.SNVS != nil && imx6ul.SNVS.Available()
	degrade := func(format string, args ...any) storage {
		msg := fmt.Sprintf(format, args...)
		if fused {
			fatal(errors.New("storage bring-up failed on fused unit, refusing RAM-only fallback: " + msg))
		}
		log.Printf("%s - running RAM-only, no rollback protection (unfused DEV unit)", msg)
		return storage{}
	}

	if err := usbarmory.SD.Detect(); err != nil {
		return degrade("microSD detect failed: %v", err)
	}
	dev := &sdDevice{card: usbarmory.SD}

	stateKey, devKeys, err := devicekey.Derive(devicekey.State)
	if err != nil {
		return degrade("state key derivation failed: %v", err)
	}

	anchor, anchorDesc, rpmbDev, err := newRPMBAnchor()
	if err != nil {
		// No usable RPMB (e.g. key not programmed on this unfused unit).
		// Never program the key here: that is a one-way operation
		// reserved for an explicit, human-approved path.
		return degrade("RPMB anchor unavailable: %v", err)
	}
	if rpmbDev != devKeys {
		// Both derive from the same SNVS secure state, so they must agree;
		// a disagreement signals a key-derivation logic bug.
		log.Printf("WARNING: state key DEV=%v but RPMB key DEV=%v (derivation inconsistency)", devKeys, rpmbDev)
	}

	mark := ""
	if devKeys {
		mark = " [DEV keys: unfused unit]"
	}

	return storage{
		dev:    dev,
		anchor: anchor,
		key:    stateKey,
		desc:   "microSD blob + " + anchorDesc + " anchor" + mark,
	}
}

// newRPMBAnchor brings up the internal eMMC and returns an RPMB-backed anchor.
//
// It requires the RPMB authentication key to already be programmed (this
// firmware never programs it). If the key is unprogrammed an error is
// returned and the caller degrades to RAM-only.
func newRPMBAnchor() (anchor state.Anchor, desc string, dev bool, err error) {
	if err := usbarmory.MMC.Detect(); err != nil {
		return nil, "", false, fmt.Errorf("eMMC detect: %w", err)
	}

	rpmbKey, dev, err := devicekey.Derive(devicekey.RPMB)
	if err != nil {
		return nil, "", dev, fmt.Errorf("rpmb key derivation: %w", err)
	}

	// writeDummy=false: an authenticated dummy write requires a programmed
	// key; the unauthenticated counter read below probes programming state
	// instead.
	p, err := rpmb.Init(&rpmbCard{card: usbarmory.MMC}, rpmbKey, rpmbDummySector, false)
	if err != nil {
		return nil, "", dev, err
	}

	if _, err := p.Counter(false); err != nil {
		return nil, "", dev, fmt.Errorf("rpmb not usable (key likely unprogrammed): %w", err)
	}

	return state.NewRPMBAnchor(p), "eMMC RPMB", dev, nil
}

const rpmbDummySector = 0

type sdDevice struct {
	card *usdhc.USDHC
}

func (d *sdDevice) Info() (int, int64) {
	info := d.card.Info()
	return info.BlockSize, int64(info.Blocks)
}

func (d *sdDevice) ReadBlocks(lba int64, buf []byte) error {
	return d.card.ReadBlocks(int(lba), buf)
}

func (d *sdDevice) WriteBlocks(lba int64, buf []byte) error {
	return d.card.WriteBlocks(int(lba), buf)
}

// rpmbCard adapts *usdhc.USDHC to the rpmb.Transport interface.
type rpmbCard struct {
	card *usdhc.USDHC
}

func (c *rpmbCard) WriteRPMB(buf []byte, rel bool) error { return c.card.WriteRPMB(buf, rel) }
func (c *rpmbCard) ReadRPMB(buf []byte) error            { return c.card.ReadRPMB(buf) }
