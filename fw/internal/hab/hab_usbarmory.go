//go:build usbarmory

package hab

import (
	"encoding/hex"
	"sync"
	"unsafe"

	"github.com/usbarmory/tamago/arm"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"
)

func eventStatus(event []byte) byte {
	if len(event) < 5 {
		return 0
	}
	return event[4]
}

func makeHABEvent(event []byte) Event {
	return Event{Status: habStatusName(eventStatus(event)), Data: hex.EncodeToString(event)}
}

func habStatusName(v byte) string {
	switch v {
	case 0x00:
		return "any"
	case 0x33:
		return "failure"
	case 0x69:
		return "warning"
	case 0xf0:
		return "success"
	default:
		return "unknown"
	}
}

func habConfigName(v byte) string {
	switch v {
	case 0x33:
		return "return"
	case 0xf0:
		return "open"
	case 0xcc:
		return "closed"
	default:
		return "unknown"
	}
}

func habStateName(v byte) string {
	switch v {
	case 0x33:
		return "initial"
	case 0x55:
		return "check"
	case 0x66:
		return "nonsecure"
	case 0x99:
		return "trusted"
	case 0xaa:
		return "secure"
	case 0xcc:
		return "fail-soft"
	case 0xff:
		return "fail-hard"
	default:
		return "unknown"
	}
}

const (
	habSuccess         = 0xf0
	habFailure         = 0x33
	habReportEventRVT  = 0x00000120
	habReportStatusRVT = 0x00000124
	habEventMax        = 128
)

var (
	habOnce sync.Once
	habBoot Status
)

// The i.MX6 ROM vector table contains ARM EABI function pointers.
func habCallStatus(fn, config, state uintptr) byte
func habCallEvent(fn uintptr, status byte, index uint32, event, size uintptr) byte

func Report() Status {
	habOnce.Do(readHABReport)
	return habBoot
}

func readHABReport() {
	// TamaGo leaves the first page unmapped to trap nil pointers.
	imx6ul.ARM.ConfigureMMU(0, 1<<20, 0, arm.DeviceRegion)
	defer imx6ul.ARM.InitMMU()

	var config, state uint32
	statusFn := *(*uintptr)(unsafe.Pointer(uintptr(habReportStatusRVT)))
	status := habCallStatus(statusFn, uintptr(unsafe.Pointer(&config)), uintptr(unsafe.Pointer(&state)))
	habBoot = Status{
		Status: habStatusName(status), Config: habConfigName(byte(config)), State: habStateName(byte(state)),
		Events: make([]Event, 0),
	}

	eventFn := *(*uintptr)(unsafe.Pointer(uintptr(habReportEventRVT)))
	for index := uint32(0); ; index++ {
		buf := make([]byte, habEventMax)
		size := uint32(len(buf))
		if habCallEvent(eventFn, 0, index, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size))) != habSuccess {
			break
		}
		if size > uint32(len(buf)) {
			size = uint32(len(buf))
		}
		event := makeHABEvent(buf[:size])
		if event.Status == habStatusName(habFailure) {
			habBoot.Failures++
		}
		habBoot.Events = append(habBoot.Events, event)
	}
}
