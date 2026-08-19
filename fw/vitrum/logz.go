//go:build usbarmory || mx6ullevk

package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// logRing is a fixed-size ring of recent log lines.
// Writes arrive already serialized by the log package.
// The mutex mediates with HTTP reads.
type logRing struct {
	mu    sync.Mutex
	lines [logRingLines]string
	n     uint64 // total lines ever written. line i lives at i%logRingLines
}

// Write stamps each line with the wall clock: before settime that reads as
// time since boot (the clock starts at the epoch), after it as real UTC.
func (r *logRing) Write(p []byte) (int, error) {
	line := time.Now().UTC().Format(time.RFC3339) + " " + strings.TrimRight(string(p), "\n")

	r.mu.Lock()
	r.lines[r.n%logRingLines] = line
	r.n++
	r.mu.Unlock()

	return len(p), nil
}

func (r *logRing) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	start := uint64(0)
	if r.n > logRingLines {
		start = r.n - logRingLines
	}
	out := make([]string, 0, r.n-start)
	for i := start; i < r.n; i++ {
		out = append(out, r.lines[i%logRingLines])
	}
	r.mu.Unlock()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, line := range out {
		io.WriteString(w, line+"\n")
	}
}

// logRingLines bounds the /logz capture lines.
const logRingLines = 512

// logz is the RAM half of the log surface.
//
// main tees the default logger into this logRing, so it holds everything
// the firmware and internal packages have logged since main()'s first statement.
//
// Served read-only over HTTP, it gives hardware without the debug accessory a
// post-mortem boot log (the console UART cannot be observed without the
// accessory).
var logz logRing
