# vitrum

A bare-metal [tlog witness](https://c2sp.org/tlog-witness) for the USB
armory Mk II, built with [TamaGo](https://github.com/usbarmory/tamago).

Vitrum cosigns checkpoints for any origin per
[c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature), promising
not to sign conflicting views of the same log. It uses the USB armory hardware
to enforce this property:

- each per-origin view lives in rollback-protected storage: an
  authenticated blob on microSD, anchored to a monotonic eMMC RPMB
  counter (see [internal/state/ROLLBACK.md](internal/state/ROLLBACK.md)).
- the cosignature key exists only in RAM, uploaded at provisioning time,
  with no read-back path.
- storage and SSH host keys are derived from the SoC's hardware-unique key.

The checkpoint sequencer runs with a 200 ms period. Checkpoints pending at each
sequencing pass are committed as one storage generation, consuming one RPMB
counter increment per non-empty batch.

Witness submissions and SSH provisioning are unauthenticated. The firmware
contains no origin allowlist or log keys, so adding a log requires no firmware
rebuild.

## Build & run

The Nix devShell (`nix develop`) provides the required tools. They can also be
installed manually.

The `Makefile` provides these targets:

    make test         # run host-side unit tests
    make staticcheck  # run the pinned static analyzer
    make govulncheck  # scan reachable code for known vulnerabilities
    make qemu         # build & boot the emulated target (TARGET=mx6ullevk)
    make e2e          # test full provisioning + witness flow under QEMU
    make e2e-live     # feed a live log (keyserver.geomys.org) through QEMU
    make imx          # build bootable image for the armory (TARGET=usbarmory)
    make repro        # verify a reproducible build

`make imx_signed` produces (but never flashes) a HAB-signed image. See
[PRODUCTION_SETUP.md](PRODUCTION_SETUP.md) for the hardware ceremony; it is
not yet ready for execution because the RPMB provisioning image remains to be
implemented and tested.

## Operating

The witness serves `add-checkpoint` and per-log checkpoints on :80 and an
exec-only SSH provisioning channel on :22. It boots unprovisioned (blue LED
blinking, submissions get 503) with no key material in the image. The
signing key must be uploaded at runtime using the `provision` sub-command
and lives only in RAM.

The host-side `vitrum` tool drives these interactions:

    vitrum keygen                    # generate a witness seed
    vitrum provision [-tofu]         # set clock + upload seed over SSH
                                     # (host key pinned; -tofu pairs once)
    vitrum feed -log-name keyserver  # verify a log checkpoint, submit it,
                                     # verify the returned cosignature
    vitrum selftest                  # drive a synthetic log end to end
    vitrum deprovision               # zero the key; submissions get 503

`vitrum record` captures live request fixtures for offline tests. `vitrum
hostkey` generates the emulated target's host key.
