#!/usr/bin/env bash

# Live end-to-end test.
#
# Boots vitrum under QEMU, provisions it, then feeds a *real external log*
# (keyserver.geomys.org by default) through the witness and verifies the
# cosignature.
#
# Unlike `make e2e` which drives a synthetic in-process log this exercises
# the harness's live tile-fetch and consistency-proof path against a foreign
# server.
#
# The witness cosigns any origin (SECURITY.md); the log only needs a
# host-side registry entry. Override with LOG_NAME=<handle from config.Logs>.
set -euo pipefail

WITNESS=${WITNESS:-http://127.0.0.1:8080}
SSH_ADDR=${SSH_ADDR:-127.0.0.1:2222}
LOG_NAME=${LOG_NAME:-keyserver}
QEMU_LOG=$(mktemp -t vitrum-e2e-live-qemu.XXXXXX)
TMP=$(mktemp -d -t vitrum-e2e-live.XXXXXX)
QEMU_PGID=""

cd "$(dirname "$0")/.."

cleanup() {
    [ -n "$QEMU_PGID" ] && kill -- "-$QEMU_PGID" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT

echo "== work dir $TMP (log: $QEMU_LOG)"
[ -f keys/witness.seed ] || go run ./cmd/vitrum keygen

echo "== building mx6ullevk (first build bootstraps the tamago-go toolchain)"
make qemu-build TARGET=mx6ullevk >"$QEMU_LOG" 2>&1

echo "== booting under QEMU"
setsid make qemu TARGET=mx6ullevk >>"$QEMU_LOG" 2>&1 &
QEMU_PGID=$!

for _ in $(seq 1 60); do
    if curl -fsS "$WITNESS/healthz" >/dev/null 2>&1; then
        break
    fi
    if ! kill -0 "$QEMU_PGID" 2>/dev/null; then
        echo "QEMU exited early:" >&2
        tail -20 "$QEMU_LOG" >&2
        exit 1
    fi
    sleep 0.5
done

echo "== provisioning (also sets the device clock, needed for cosig timestamps)"
go run ./cmd/vitrum provision -addr "$SSH_ADDR" -hostkey keys/ssh_host.pub
curl -fsS "$WITNESS/healthz" | grep -q '"provisioned":true'
echo "PASS: provisioned"

echo "== feeding live log '$LOG_NAME' (first sighting)"
go run ./cmd/vitrum feed -witness "$WITNESS" -log-name "$LOG_NAME"

# A second feed exercises the interesting path: the witness now knows a size,
# so the harness gets a 409, fetches tiles, builds a real consistency proof,
# and resubmits. If the log has not grown between the two feeds this is the
# idempotent (old == N) case; either way it must cosign, not error.
echo "== re-feeding (exercises 409 -> consistency proof -> cosign)"
go run ./cmd/vitrum feed -witness "$WITNESS" -log-name "$LOG_NAME"

echo "== live e2e OK"
