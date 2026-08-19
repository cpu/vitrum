//go:build usbarmory || mx6ullevk

package main

import (
	"context"
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
	go func() {
		fatal(w.RunSequencer(context.Background(), witness.SequencerPeriod))
	}()

	usbPort, eth, iface, err := netInit()
	if err != nil {
		fatal(err)
	}

	listener, err := net.Listen("tcp4", ":80")
	if err != nil {
		fatal(err)
	}

	go func() {
		srv := &http.Server{
			Handler:           handler(w, persistence),
			ReadHeaderTimeout: 5 * time.Second,
			ReadTimeout:       10 * time.Second,
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       30 * time.Second,
		}
		fatal(srv.Serve(listener))
	}()

	if err := startSSH(w); err != nil {
		fatal(err)
	}

	go statusLED(w)
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
		status := w.Status()
		lastCommit := ""
		if !status.LastCommit.IsZero() {
			lastCommit = status.LastCommit.UTC().Format(time.RFC3339Nano)
		}

		rw.Header().Set("Content-Type", "application/json")
		health := map[string]any{
			"banner":      fmt.Sprintf("vitrum %s/%s (%s)", runtime.GOOS, runtime.GOARCH, runtime.Version()),
			"target":      target,
			"provisioned": w.Provisioned(),
			"halted":      w.Halted(),
			"witness_key": w.Verifier(),
			"persistence": persistence,
			"time":        time.Now().UTC().Format(time.RFC3339),
			"uptime":      time.Since(start).String(),
			"logs":        sizes,
			"sequencer": map[string]any{
				"running":           status.SequencerRunning,
				"pending":           status.Pending,
				"sequencing":        status.Sequencing,
				"batches_committed": status.BatchesCommitted,
				"batches_failed":    status.BatchesFailed,
				"last_commit":       lastCommit,
			},
		}
		if status.HasGeneration {
			health["generation"] = status.Generation
		}
		json.NewEncoder(rw).Encode(health)
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

var cosignPulse = make(chan struct{}, 1)

// statusLED displays provisioning, cosigning, and halt state. Halt takes
// precedence over all other indications.
func statusLED(w *witness.Witness) {
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	var blue, white, halted, haltOn bool
	lastBlueToggle := time.Now()
	lastHaltToggle := time.Now()
	var whiteUntil time.Time

	set := func(name string, current *bool, on bool) {
		if *current != on {
			led(name, on)
			*current = on
		}
	}

	for {
		select {
		case <-cosignPulse:
			whiteUntil = time.Now().Add(100 * time.Millisecond)

		case now := <-ticker.C:
			if w.Halted() {
				if !halted {
					halted = true
					haltOn = true
					lastHaltToggle = now
				} else if now.Sub(lastHaltToggle) >= 150*time.Millisecond {
					haltOn = !haltOn
					lastHaltToggle = now
				}
				set("blue", &blue, haltOn)
				set("white", &white, haltOn)
				continue
			}

			if w.Provisioned() {
				set("blue", &blue, true)
			} else if now.Sub(lastBlueToggle) >= 500*time.Millisecond {
				set("blue", &blue, !blue)
				lastBlueToggle = now
			}
			set("white", &white, now.Before(whiteUntil))
		}
	}
}

// cosignLED pulses the white LED on every accepted checkpoint.
func cosignLED(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: rw, code: http.StatusOK}
		next.ServeHTTP(sw, r)

		if r.Method == http.MethodPost && sw.code == http.StatusOK {
			select {
			case cosignPulse <- struct{}{}:
			default:
			}
		}
	})
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
