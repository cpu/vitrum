package witness

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandler(t *testing.T) {
	l := newTestLog(t, testOrigin)
	l.Append("a", "b", "c")
	w, v := newTestWitness(t)

	srv := httptest.NewServer(Handler(w))
	defer srv.Close()

	post := func(t *testing.T, body []byte) *http.Response {
		t.Helper()
		resp, err := http.Post(srv.URL+"/add-checkpoint", "text/plain", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	t.Run("add-checkpoint", func(t *testing.T) {
		cpNote := mustCheckpoint(t, l)

		resp := post(t, EncodeAddCheckpoint(0, nil, cpNote))
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		cosig, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		verifyCosig(t, v, cpNote, cosig)
	})

	t.Run("conflict content-type", func(t *testing.T) {
		l.Append("d", "e")

		resp := post(t, EncodeAddCheckpoint(0, nil, mustCheckpoint(t, l)))
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusConflict {
			t.Fatalf("status = %d, want 409", resp.StatusCode)
		}
		if ct := resp.Header.Get("Content-Type"); ct != "text/x.tlog.size" {
			t.Errorf("Content-Type = %q, want text/x.tlog.size", ct)
		}

		body, _ := io.ReadAll(resp.Body)
		if string(body) != "3\n" {
			t.Errorf("body = %q, want \"3\\n\"", body)
		}
	})

	t.Run("get checkpoint", func(t *testing.T) {
		h := sha256.Sum256([]byte(testOrigin))

		resp, err := http.Get(srv.URL + "/" + hex.EncodeToString(h[:]) + "/checkpoint")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", resp.StatusCode)
		}

		body, _ := io.ReadAll(resp.Body)
		if !bytes.Contains(body, []byte(testOrigin)) {
			t.Errorf("checkpoint body %q missing origin", body)
		}
	})

	t.Run("get unknown origin", func(t *testing.T) {
		h := sha256.Sum256([]byte("nope"))

		resp, err := http.Get(srv.URL + "/" + hex.EncodeToString(h[:]) + "/checkpoint")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("get malformed origin hash", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/NOT-HEX/checkpoint")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})

	t.Run("oversized request", func(t *testing.T) {
		resp := post(t, bytes.Repeat([]byte("a"), MaxRequestSize+1))
		resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", resp.StatusCode)
		}
	})
}
