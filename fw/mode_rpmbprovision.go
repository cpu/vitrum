//go:build usbarmory && rpmbprovision

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"time"

	usbarmory "github.com/usbarmory/tamago/board/usbarmory/mk2"
	"github.com/usbarmory/tamago/soc/nxp/imx6ul"

	"github.com/cpu/vitrum/fw/internal/devicekey"
	"github.com/cpu/vitrum/fw/internal/hab"
	"github.com/cpu/vitrum/internal/rpmb"
)

func main() {
	log.SetFlags(0)
	log.SetOutput(io.MultiWriter(os.Stderr, &logz))
	log.Printf("vitrum RPMB provisioner %s/%s (%s)", runtime.GOOS, runtime.GOARCH, runtime.Version())
	led("white", false)

	boot := hab.Report()
	secure := imx6ul.SNVS != nil && imx6ul.SNVS.Available()
	var card rpmb.Transport
	if err := usbarmory.MMC.Detect(); err != nil {
		serveProvisionStatus(rpmbProvisionStatus{HAB: boot, SNVSSecure: secure, Error: fmt.Sprintf("eMMC detect: %v", err)})
	}
	card = &rpmbCard{card: usbarmory.MMC}
	status := provisionRPMB(card, secure, boot, func() ([]byte, error) {
		key, dev, err := devicekey.Derive(devicekey.RPMB)
		if dev && err == nil {
			return nil, fmt.Errorf("derived RPMB key is marked DEV")
		}
		return key, err
	})
	serveProvisionStatus(status)
}

func serveProvisionStatus(status rpmbProvisionStatus) {
	if status.Success {
		log.Printf("RPMB PROVISIONING SUCCEEDED: authenticated counter=%d", status.Counter)
		led("blue", true)
		led("white", true)
	} else {
		log.Printf("RPMB PROVISIONING REFUSED/FAILED: %s", status.Error)
		go fatalPattern()
	}

	usbPort, eth, iface, err := netInit()
	if err != nil {
		fatal(fmt.Errorf("status network: %w", err))
	}
	mux := http.NewServeMux()
	write := func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(status)
	}
	mux.HandleFunc("GET /healthz", write)
	mux.HandleFunc("GET /status", write)
	mux.Handle("GET /logz", &logz)
	listener, err := net.Listen("tcp4", ":80")
	if err != nil {
		fatal(err)
	}
	go func() { fatal((&http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}).Serve(listener)) }()
	serviceInterrupts(usbPort, eth, iface)
}

func fatalPattern() {
	for {
		led("blue", true)
		led("white", false)
		time.Sleep(250 * time.Millisecond)
		led("blue", false)
		led("white", true)
		time.Sleep(250 * time.Millisecond)
	}
}
