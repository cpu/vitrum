# Contributing

## Development environment

Use the Nix devShell (`nix develop`), optionally with `direnv`. The TamaGo
toolchain bootstraps through `go tool`; nothing is installed globally.

Without Nix, install Go 1.24+, `uboot-tools`, `gcc`, `qemu`, and `gnumake`.

## Testing

Run host-side unit tests with `make test`. Run the pinned analyzers with
`make staticcheck` and `make govulncheck`.

The `Makefile` also provides:

    make e2e        # boot the mx6ullevk target under QEMU, drive the full
                    # provisioning + witnessing flow
    make e2e-live   # same, feeding a real third-party log (needs network;
                    # deliberately not part of e2e or CI)
    make repro      # byte-identical rebuild; must pass for firmware changes

## Hardware

QEMU testing is limited to the `mx6ullevk` build tag. Code such as
`fw/keys.go` and `fw/target_usbarmory.go` is gated by the `usbarmory` build
tag and requires hardware to exercise HUK derivation (CAAM/DCP), microSD/eMMC
RPMB transport, LEDs, and USB device mode. Test changes to this code using
[PRODUCTION_SETUP.md](PRODUCTION_SETUP.md).

## Test Data

Protocol fixtures under `internal/witness/testdata/` are recorded exchanges
with a real log (`vitrum record`). Regenerate them rather than hand-editing.
