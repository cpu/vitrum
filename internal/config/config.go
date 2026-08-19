// Package config holds log and key defaults for host tools and tests.
// The firmware does not use this package; see SECURITY.md.
package config

// WitnessKeyName is the default used by `vitrum keygen` and `vitrum provision`.
const WitnessKeyName = "vitrum-UNSAFE-test-key.invalid"

// Selftest configures the synthetic log used by `vitrum selftest`.
const (
	SelftestOrigin = "vitrum-selftest.invalid/log"
	SelftestSeed   = "vitrum-selftest-seed-1"
)

// Log is the identity of a log known to the host tooling.
type Log struct {
	// Origin is the log's checkpoint origin line.
	Origin string

	// VKey is the log's signed-note verifier key.
	VKey string
}

// Logs is the host tooling's known-log registry, not a firmware allowlist.
var Logs = []Log{
	{
		// keyserver.geomys.org (https://words.filippo.io/keyserver-tlog/)
		Origin: "keyserver.geomys.org",
		VKey:   "keyserver.geomys.org+16b31509+ARLJ+pmTj78HzTeBj04V+LVfB+GFAQyrg54CRIju7Nn8",
	},
}
