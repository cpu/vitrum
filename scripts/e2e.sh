#!/usr/bin/env bash

# End-to-end smoke test: boot vitrum under QEMU (user-mode networking,
# witness on 127.0.0.1:8080, SSH provisioning on 127.0.0.1:2222) and drive
# the provisioning flow plus the selftest harness. Run inside the
# devShell.
#
# Verifies via emulation:
#   - a fresh boot serves nothing (503 until provisioned)
#   - provisioning is refused over a mismatched pinned host key
#   - a missing pin is refused without -tofu; -tofu pairs and pins the
#     presented host key (never overwriting an existing pin)
#   - `vitrum provision` brings the witness up (no client auth: the
#     provisioning channel is open by design, see SECURITY.md)
#   - a fed log is correctly cosigned; consistency violations refused;
#     stale submissions signal 409 with the correct latest size
#   - /logz serves the boot log from the RAM ring
#   - deprovisioning returns the witness to 503
set -euo pipefail

WITNESS=${WITNESS:-http://127.0.0.1:8080}
SSH_ADDR=${SSH_ADDR:-127.0.0.1:2222}
QEMU_LOG=$(mktemp -t vitrum-e2e-qemu.XXXXXX)
TMP=$(mktemp -d -t vitrum-e2e.XXXXXX)
QEMU_PGID=""

cd "$(dirname "$0")/.."

cleanup() {
    [ -n "$QEMU_PGID" ] && kill -- "-$QEMU_PGID" 2>/dev/null || true
    pkill -f qemu-system-arm 2>/dev/null || true
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

echo "== witness up:"
curl -fsS "$WITNESS/healthz"
echo

echo "== unprovisioned: submissions must get 503"
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data 'old 0' "$WITNESS/add-checkpoint")
if [ "$code" != 503 ]; then
    echo "ERROR: unprovisioned add-checkpoint returned $code, want 503" >&2
    exit 1
fi
curl -fsS "$WITNESS/healthz" | grep -q '"provisioned":false'
echo "PASS: unprovisioned witness refuses submissions"

echo "== provisioning over a mismatched pinned host key must be refused"
ssh-keygen -q -t ed25519 -N '' -f "$TMP/wronghost"
if go run ./cmd/vitrum provision -addr "$SSH_ADDR" -hostkey "$TMP/wronghost.pub" 2>"$TMP/wrongpin.log"; then
    echo "ERROR: provisioning succeeded over a mismatched host key" >&2
    exit 1
fi
echo "PASS: mismatched host key refused"

echo "== a missing pin without -tofu must be refused"
if go run ./cmd/vitrum provision -addr "$SSH_ADDR" -hostkey "$TMP/nopin.pub" 2>"$TMP/nopin.log"; then
    echo "ERROR: provisioning succeeded with no pinned host key and no -tofu" >&2
    exit 1
fi
echo "PASS: missing pin refused"

echo "== -tofu with a missing pin must pair and pin the presented key"
go run ./cmd/vitrum provision -tofu -addr "$SSH_ADDR" -hostkey "$TMP/tofu.pub"
# The emulated image embeds the build-time seed, so the TOFU'd pin must be
# byte-identical to the key `vitrum hostkey` derived from it.
cmp "$TMP/tofu.pub" keys/ssh_host.pub
echo "PASS: TOFU paired the expected key"

echo "== -tofu must never override an existing (mismatched) pin"
if go run ./cmd/vitrum provision -tofu -addr "$SSH_ADDR" -hostkey "$TMP/wronghost.pub" 2>"$TMP/wrongtofu.log"; then
    echo "ERROR: -tofu provisioning succeeded over a mismatched existing pin" >&2
    exit 1
fi
echo "PASS: -tofu kept the existing pin and refused"

echo "== provisioning with the pinned host key"
go run ./cmd/vitrum provision -addr "$SSH_ADDR" -hostkey keys/ssh_host.pub
curl -fsS "$WITNESS/healthz" | grep -q '"provisioned":true'
echo "PASS: provisioned"

echo "== /logz must serve the captured boot log"
logz=$(curl -fsS "$WITNESS/logz")
grep -q 'vitrum witness listening' <<<"$logz"
grep -q 'ssh: vitrum connected' <<<"$logz"
echo "PASS: /logz serves the boot log"

echo "== running selftest"
go run ./cmd/vitrum selftest -witness "$WITNESS"

echo "== deprovision: witness must refuse submissions again"
go run ./cmd/vitrum deprovision -addr "$SSH_ADDR" -hostkey keys/ssh_host.pub
code=$(curl -s -o /dev/null -w '%{http_code}' -X POST --data 'old 0' "$WITNESS/add-checkpoint")
if [ "$code" != 503 ]; then
    echo "ERROR: deprovisioned add-checkpoint returned $code, want 503" >&2
    exit 1
fi
echo "PASS: deprovisioned witness refuses submissions"

echo "== e2e OK"
