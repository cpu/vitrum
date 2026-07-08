package witness

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFixtures replays recorded add-checkpoint request sequences
// (`vitrum record`) against a fresh witness.
func TestFixtures(t *testing.T) {
	manifests, err := filepath.Glob(filepath.Join("testdata", "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Skip("no fixtures recorded (see `vitrum record`)")
	}

	// fixtureManifest mirrors cmd/vitrum's record output format. VKey is
	// recorded for provenance; the witness never verifies log signatures, so
	// the replay does not use it.
	type fixtureManifest struct {
		Origin string `json:"origin"`
		VKey   string `json:"vkey"`
		Steps  []struct {
			File   string `json:"file"`
			Status int    `json:"status"`
		} `json:"steps"`
	}

	for _, path := range manifests {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			var m fixtureManifest
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}

			w, _ := newTestWitness(t)

			for _, step := range m.Steps {
				body, err := os.ReadFile(filepath.Join(filepath.Dir(path), step.File))
				if err != nil {
					t.Fatal(err)
				}

				code, resp := w.AddCheckpoint(body)
				if code != step.Status {
					t.Fatalf("%s: AddCheckpoint = %d (%q), want %d", step.File, code, resp, step.Status)
				}
			}
		})
	}
}
