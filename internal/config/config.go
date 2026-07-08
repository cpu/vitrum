// Package config holds compile-time configuration for the HOST tooling and
// tests: the registry of known logs behind `vitrum feed -log-name`, key
// names, and the selftest log identity. The firmware reads none of it; the
// witness has no origin allowlist and verifies no log signatures
// (SECURITY.md), so witnessing a new log requires no firmware change.
package config

// WitnessKeyName is the default witness key name used by `vitrum keygen`
// and `vitrum provision`. The name travels with the key at provisioning time
// (nothing is baked into the firmware). The operator can override it with
// -name during provisioning once a real identity exists.
const WitnessKeyName = "vitrum-UNSAFE-test-key.invalid"

// Selftest names the synthetic log `vitrum selftest` drives against a
// running witness (any origin is accepted, so no firmware configuration
// is involved). The seed is the harness's `-seed` default; the log
// keypair is derived from it at runtime.
const (
	SelftestOrigin = "vitrum-selftest.invalid/log"
	SelftestSeed   = "vitrum-selftest-seed-1"
)

// Log is the identity of a log known to the host tooling.
type Log struct {
	// Origin is the log's checkpoint origin line.
	Origin string

	// VKey is the log's public verifier key in signed-note format. The
	// host-side tooling (feed, record, selftest) verifies checkpoints
	// against it before submitting them; the firmware deliberately omits
	// that verification (SECURITY.md).
	VKey string
}

// Logs is the registry of known logs for the host tooling. It does not
// gate the witness: the firmware cosigns any origin.
var Logs = []Log{
	{
		// keyserver.geomys.org (https://words.filippo.io/keyserver-tlog/)
		Origin: "keyserver.geomys.org",
		VKey:   "keyserver.geomys.org+16b31509+ARLJ+pmTj78HzTeBj04V+LVfB+GFAQyrg54CRIju7Nn8",
	},
}
