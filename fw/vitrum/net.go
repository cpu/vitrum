//go:build usbarmory || mx6ullevk

package main

import (
	"fmt"
	"log"
	"net"
	"runtime/goos"

	"github.com/usbarmory/tamago/arm"
	"github.com/usbarmory/tamago/soc/nxp/enet"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"github.com/usbarmory/tamago/soc/nxp/usb"

	gnet "github.com/usbarmory/go-net"
)

// Addressing per the usbarmory wiki "Host communication" conventions:
// device 10.0.0.1, host 10.0.0.2. The MACs are the fixed,
// locally-administered pair tamago-example uses; the ECM link is a
// point-to-point two-node segment, so they only need to be unique on it.
const (
	MAC     = "1a:55:89:a2:69:41"
	HostMAC = "1a:55:89:a2:69:42"
	IP      = "10.0.0.1"
	CIDR    = "/24"
	Gateway = "10.0.0.2"
)

func newInterface(dev gnet.NetworkDevice) (*gnet.Interface, error) {
	iface := &gnet.Interface{
		NetworkDevice: dev,
		Stack:         gnet.NewGVisorStack(1),
	}

	if err := iface.Init(IP+CIDR, MAC, Gateway); err != nil {
		return nil, fmt.Errorf("could not initialize network stack, %v", err)
	}

	iface.HandleStackErr = func(err error, tx bool) {
		log.Printf("network stack error (tx:%v), %v", tx, err)
	}

	iface.Stack.EnableICMP()

	// hook the stack into the Go runtime
	net.SocketFunc = iface.Stack.Socket

	return iface, nil
}

// serviceInterrupts runs the GIC interrupt service loop as the program
// foreground; it never returns.
func serviceInterrupts(usbPort *usb.USB, eth *enet.ENET, iface *gnet.Interface) {
	var buf []byte

	imx6ul.GIC.Init()
	imx6ul.GIC.EnableInterrupt(arm.TIMER_IRQ)

	if usbPort != nil {
		imx6ul.GIC.EnableInterrupt(usbPort.IRQ)
	}

	if eth != nil {
		buf = make([]byte, gnet.EthernetMaximumSize+gnet.MTU)
		imx6ul.GIC.EnableInterrupt(eth.IRQ)
	}

	isr := func() {
		irq := imx6ul.GIC.GetInterrupt()

		switch {
		case irq == arm.TIMER_IRQ:
			imx6ul.ARM.SetAlarm(0)
		case usbPort != nil && irq == usbPort.IRQ:
			usbPort.ServiceInterrupts()
		case eth != nil && irq == eth.IRQ:
			for {
				if n, err := eth.Receive(buf); err != nil || n == 0 {
					break
				}

				iface.Stack.RecvInboundPacket(buf)
				eth.ClearInterrupt(enet.IRQ_RXF)
			}
		default:
			log.Printf("unexpected IRQ %d", irq)
		}
	}

	// idle in WFI between alarms now that IRQs are enabled
	goos.Idle = func(pollUntil int64) {
		if pollUntil == 0 {
			return
		}

		imx6ul.ARM.SetAlarm(pollUntil)
		imx6ul.ARM.WaitInterrupt()
	}

	imx6ul.ARM.ServiceInterrupts(isr)
}
