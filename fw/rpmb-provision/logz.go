//go:build usbarmory

package main

import (
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const logRingLines = 512

type logRing struct {
	mu    sync.Mutex
	lines [logRingLines]string
	n     uint64
}

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

var logz logRing
