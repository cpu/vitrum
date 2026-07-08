//go:build usbarmory || mx6ullevk

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

	"github.com/cpu/vitrum/internal/state"
	"github.com/cpu/vitrum/internal/witness"
)

var start = time.Now()

// storage bundles the rollback-protected persistence layer a target provides.
// A nil dev means no persistence (RAM-only, e.g. QEMU).
type storage struct {
	dev    state.BlockDevice
	anchor state.Anchor
	key    []byte // AES-256 blob key, device-bound on hardware
	desc   string
}

func main() {
	log.SetFlags(0)
	// Tee the log into the RAM ring behind /logz; the console half needs
	// the debug accessory to be observed on hardware.
	log.SetOutput(io.MultiWriter(os.Stderr, &logz))
	log.Printf("vitrum %s/%s (%s) target=%s", runtime.GOOS, runtime.GOARCH, runtime.Version(), target)

	// The white LED is lit by the hardware power-on default; clear it so a
	// lit white always means something (cosign pulse, halt, fatal).
	led("white", false)

	var store witness.Store
	persistence := "none (RAM only)"

	if p := newStorage(); p.dev != nil {
		rs, err := state.Open(p.dev, state.Offset, p.key, p.anchor)
		if err != nil {
			fatal(err)
		}
		store = rs
		persistence = p.desc

		if rs.Halted() {
			// The store loaded but refuses to advance: rollback or
			// tamper evidence.
			log.Printf("STATE HALTED: rollback/tamper detected, refusing to serve")
			persistence += " - HALTED (rollback/tamper)"
		} else {
			log.Printf("state: generation %d, %s", rs.Generation(), p.desc)
		}
	} else {
		log.Printf("no persistence device, running RAM-only (no rollback protection)")
		store = witness.NewMemStore()
	}

	// The witness starts unprovisioned with no key material in the
	// image. Submissions get 503 until `vitrum provision` uploads a key.
	w := witness.New(store)

	usbPort, eth, iface, err := netInit()
	if err != nil {
		fatal(err)
	}

	listener, err := net.Listen("tcp4", ":80")
	if err != nil {
		fatal(err)
	}

	go func() {
		fatal(http.Serve(listener, handler(w, persistence)))
	}()

	if err := startSSH(w); err != nil {
		fatal(err)
	}

	go provisionLED(w)
	go haltLED(w)
	log.Printf("vitrum witness listening on %s:80, unprovisioned", IP)

	serviceInterrupts(usbPort, eth, iface) // never returns
}

func handler(w *witness.Witness, persistence string) http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", cosignLED(witness.Handler(w)))
	mux.Handle("GET /logz", &logz)

	mux.HandleFunc("GET /healthz", func(rw http.ResponseWriter, r *http.Request) {
		sizes := make(map[string]int64)
		for origin, s := range w.Logs() {
			sizes[origin] = s.Size
		}

		rw.Header().Set("Content-Type", "application/json")
		json.NewEncoder(rw).Encode(map[string]any{
			"banner":      fmt.Sprintf("vitrum %s/%s (%s)", runtime.GOOS, runtime.GOARCH, runtime.Version()),
			"target":      target,
			"provisioned": w.Provisioned(),
			"halted":      w.Halted(),
			"witness_key": w.Verifier(),
			"persistence": persistence,
			"time":        time.Now().UTC().Format(time.RFC3339),
			"uptime":      time.Since(start).String(),
			"logs":        sizes,
		})
	})

	return mux
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (sw *statusWriter) WriteHeader(code int) {
	sw.code = code
	sw.ResponseWriter.WriteHeader(code)
}

// provisionLED blinks blue until a witness key is installed, then holds
// solid.
func provisionLED(w *witness.Witness) {
	on := false

	for {
		if w.Provisioned() {
			if !on {
				led("blue", true)
				on = true
			}
		} else {
			on = !on
			led("blue", on)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// cosignLED pulses the white LED on every accepted checkpoint.
func cosignLED(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: rw, code: http.StatusOK}
		next.ServeHTTP(sw, r)

		if r.Method == http.MethodPost && sw.code == http.StatusOK {
			go func() {
				led("white", true)
				time.Sleep(100 * time.Millisecond)
				led("white", false)
			}()
		}
	})
}

// haltLED blinks both LEDs together once the store halts (at boot, or after
// a failed commit), a pattern distinct from the unprovisioned blink and the
// fatal alternation.
func haltLED(w *witness.Witness) {
	for !w.Halted() {
		time.Sleep(500 * time.Millisecond)
	}

	on := false
	for {
		on = !on
		led("blue", on)
		led("white", on)
		time.Sleep(150 * time.Millisecond)
	}
}

// fatal logs err and signals the failure on the LEDs forever.
func fatal(err error) {
	log.Printf("fatal: %v", err)

	for {
		led("blue", true)
		led("white", false)
		time.Sleep(250 * time.Millisecond)
		led("blue", false)
		led("white", true)
		time.Sleep(250 * time.Millisecond)
	}
}
