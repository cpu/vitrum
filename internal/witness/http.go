package witness

import (
	"io"
	"net/http"
	"regexp"
)

// Handler serves the c2sp.org/tlog-witness endpoints:
//
//	POST /add-checkpoint
//	GET  /<origin-hash>/checkpoint
func Handler(w *Witness) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /add-checkpoint", func(rw http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, MaxRequestSize))
		if err != nil {
			http.Error(rw, "request too large", http.StatusBadRequest)
			return
		}

		code, resp := w.AddCheckpoint(body)

		if code == http.StatusConflict {
			rw.Header().Set("Content-Type", "text/x.tlog.size")
		} else {
			rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}

		rw.WriteHeader(code)
		rw.Write(resp)
	})

	mux.HandleFunc("GET /{originHash}/checkpoint", func(rw http.ResponseWriter, r *http.Request) {
		originHash := r.PathValue("originHash")
		if !originHashRE.MatchString(originHash) {
			http.Error(rw, "malformed origin hash", http.StatusBadRequest)
			return
		}

		n, ok := w.Checkpoint(originHash)
		if !ok {
			http.NotFound(rw, r)
			return
		}

		rw.Header().Set("Content-Type", "text/plain; charset=utf-8")
		rw.Write(n)
	})

	return mux
}

var originHashRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
