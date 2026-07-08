# Contributing

## Development environment

Everything runs in the Nix devShell (`nix develop`, or let direnv pick up
`.envrc`). The TamaGo toolchain bootstraps via `go tool`, nothing is
installed globally.

## The loop: emulation first

All firmware logic is developed and verified against the emulated target and
real hardware is not required for day-to-day work:

    go test ./...   # host-side unit tests (RPMB logic runs against a fake card)
    make e2e        # boot the mx6ullevk target under QEMU, drive the full
                    # provisioning + witnessing flow
    make e2e-live   # same, feeding a real third-party log (needs network;
                    # deliberately not part of e2e or CI)
    make repro      # byte-identical rebuild; must pass for firmware changes

What QEMU does *not* cover are the hardware seams in `fw/keys.go` and
`fw/target_usbarmory.go`: HUK key derivation (CAAM/DCP), the usdhc
microSD/eMMC RPMB transport, LEDs, and USB device mode. Changes there need
the real unit, see `HARDWARE_SETUP.md`.

Protocol fixtures under `internal/witness/testdata/` are recorded exchanges
with a real log (`vitrum record`). Regenerate them rather than hand-editing.

CI (`.github/workflows/ci.yml`) runs this same loop on every push and PR,
plus staticcheck and govulncheck (sandboxed with geomys/sandboxed-step) and
an advisory latest-dependencies job, on a weekly schedule as well. The
workflow follows the [Geomys standard of
care](https://words.filippo.io/standard-of-care/): read-only permissions,
no secrets, no caches, actions pinned by hash. Lint any workflow change
with `zizmor` and `actionlint` before pushing.

## Hard rules

1. **Read `SECURITY.md` before touching `internal/witness`,
   `internal/provision`, or `internal/state`.** The invariants section is
   load-bearing, and several "missing" checks (log signatures, origin
   allowlist, SSH client auth) are deliberate design decisions, not bugs.
2. **Never automate one-way hardware operations.** Fuse burning, HAB
   activation, SRK revocation, RPMB key programming, and flashing signed
   images are ⛔ HUMAN-ONLY, executed step by step from `SECURE_BOOT.md`
   and `HARDWARE_SETUP.md`. No script, Makefile target, or firmware code
   path may perform them.
3. **Keep the build reproducible.** `make repro` must pass: no timestamps
   or absolute paths in the image, and `make clean` must never delete
   `fw/ssh_host.seed` (the emulated host key would silently rotate).
