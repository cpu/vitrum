//go:build usbarmory

package main

import (
	"fmt"
	"log"
	"net"
	"runtime/goos"

	gnet "github.com/usbarmory/go-net"
	usbnet "github.com/usbarmory/go-net/imx-usb"
	"github.com/usbarmory/tamago/arm"
	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
	"github.com/usbarmory/tamago/soc/nxp/usb"
	"github.com/usbarmory/tamago/soc/nxp/usdhc"
)

const (
	deviceMAC = "1a:55:89:a2:69:41"
	hostMAC   = "1a:55:89:a2:69:42"
)

func netInit() (*usb.USB, error) {
	iface := &gnet.Interface{Stack: gnet.NewGVisorStack(1)}
	if err := iface.Init("10.0.0.1/24", deviceMAC, "10.0.0.2"); err != nil {
		return nil, fmt.Errorf("network stack: %w", err)
	}
	iface.HandleStackErr = func(err error, tx bool) {
		log.Printf("network stack error (tx:%v), %v", tx, err)
	}
	iface.Stack.EnableICMP()
	net.SocketFunc = iface.Stack.Socket

	ecm := &usbnet.ECM{Stack: iface.Stack}
	ecm.HostMAC, _ = net.ParseMAC(hostMAC)
	ecm.DeviceMAC, _ = net.ParseMAC(deviceMAC)
	if err := ecm.Init(); err != nil {
		return nil, fmt.Errorf("Ethernet over USB: %w", err)
	}

	port := imx6ul.USB1
	port.Device = ecm.Device
	port.Init()
	port.DeviceMode()
	port.EnableInterrupt(usb.IRQ_URI)
	port.EnableInterrupt(usb.IRQ_PCI)
	port.EnableInterrupt(usb.IRQ_UI)
	return port, nil
}

func serviceInterrupts(port *usb.USB) {
	imx6ul.GIC.Init()
	imx6ul.GIC.EnableInterrupt(arm.TIMER_IRQ)
	imx6ul.GIC.EnableInterrupt(port.IRQ)

	goos.Idle = func(pollUntil int64) {
		if pollUntil == 0 {
			return
		}
		imx6ul.ARM.SetAlarm(pollUntil - imx6ul.ARM.TimerOffset)
		imx6ul.ARM.WaitInterrupt()
	}

	imx6ul.ARM.ServiceInterrupts(func() {
		switch irq := imx6ul.GIC.GetInterrupt(); irq {
		case arm.TIMER_IRQ:
			imx6ul.ARM.SetAlarm(0)
		case port.IRQ:
			port.ServiceInterrupts()
		default:
			log.Printf("unexpected IRQ %d", irq)
		}
	})
}

func led(name string, on bool) { usbarmory.LED(name, on) }

type rpmbCard struct{ card *usdhc.USDHC }

func (c *rpmbCard) WriteRPMB(buf []byte, rel bool) error { return c.card.WriteRPMB(buf, rel) }
func (c *rpmbCard) ReadRPMB(buf []byte) error            { return c.card.ReadRPMB(buf) }
