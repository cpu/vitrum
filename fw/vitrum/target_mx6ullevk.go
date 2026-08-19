//go:build mx6ullevk

package main

import (
	_ "embed"
	"fmt"
	"net"

	// the board package provides the TamaGo runtime hooks (hwinit,
	// UART1 console for log output)
	_ "github.com/usbarmory/tamago/board/nxp/mx6ullevk"
	"github.com/usbarmory/tamago/soc/nxp/enet"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"github.com/usbarmory/tamago/soc/nxp/usb"

	gnet "github.com/usbarmory/go-net"
)

const target = "mx6ullevk"

func securityStatus() (secure, dev bool) { return false, true }

// netInit brings up ENET networking (ENET2 on hardware, ENET1 in QEMU).
func netInit() (*usb.USB, *enet.ENET, *gnet.Interface, error) {
	eth := imx6ul.ENET2

	if !imx6ul.Native {
		eth = imx6ul.ENET1
	}

	eth.MAC, _ = net.ParseMAC(MAC)

	if err := eth.Init(); err != nil {
		return nil, nil, nil, fmt.Errorf("could not initialize Ethernet, %v", err)
	}

	iface, err := newInterface(eth)
	if err != nil {
		return nil, nil, nil, err
	}

	eth.Start()
	eth.EnableInterrupt(enet.IRQ_RXF)

	return nil, eth, iface, nil
}

// This target has no armory LEDs.
func led(_ string, _ bool) {}

// newStorage returns no persistence: the QEMU machine emulates no MMC
// (imx6ul.Native is false there), so emulated runs are RAM-only with no
// rollback protection.
func newStorage() storage {
	return storage{}
}

// This target has no usable HUK (QEMU), so the host key comes from a
// build-time seed (`vitrum hostkey`, Makefile generate-if-missing) and e2e
// clients pin keys/ssh_host.pub. Emulation-only: the usbarmory image embeds
// no key material and derives its host key from the HUK instead.
//
//go:embed ssh_host.seed
var sshHostSeed []byte

func hostKeySeed() (seed []byte, source string, err error) {
	return sshHostSeed, "build-time seed (emulation)", nil
}
