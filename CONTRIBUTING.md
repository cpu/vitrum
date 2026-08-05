# Contributing

## Development environment

The quickest path is the Nix devShell (`nix develop`, w/ optional `direnv` 
support). The TamaGo toolchain bootstraps via `go tool`, nothing is
installed globally.

If you prefer to avoid Nix, then your dev environment will need Go 1.24+, 
`uboot-tools`, `gcc`, `qemu` and `gnumake`.

## Testing

Host-side unit tests that don't require hardware (emulated or otherwise) are
run with `go test ./...` like any other Go project.

For more involved testing the `Makefile` offers:

    make e2e        # boot the mx6ullevk target under QEMU, drive the full
                    # provisioning + witnessing flow
    make e2e-live   # same, feeding a real third-party log (needs network;
                    # deliberately not part of e2e or CI)
    make repro      # byte-identical rebuild; must pass for firmware changes

## Hardware

QEMU testing is limited by the `mx6ullevk` build tag. Some code (e.g. 
`fw/keys.go` and `fw/target_usbarmory.go`) are gated by the `usbarmory` build
tag and require real hardware. 

For example, for HUK key derivation (CAAM/DCP), the usdhc microSD/eMMC RPMB 
transport, LEDs, and USB device mode. 

Changes made to this code requires testing with hardware 
([HARDWARE_SETUP.md](HARDWARE_SETUP.md)).

## Test Data

Protocol fixtures under `internal/witness/testdata/` are recorded exchanges
with a real log (`vitrum record`). Regenerate them rather than hand-editing.
