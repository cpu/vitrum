# vitrum

A bare-metal [tlog witness](https://c2sp.org/tlog-witness) for the USB
armory Mk II built with [TamaGo](https://github.com/usbarmory/tamago). 

The scope of vitrum is deliberately small and easy to audit. It's a black
box that reliably enforces that there are no split views of a witnessed log. 

It cosigns checkpoints for any origin per
[c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature), promising
it will never sign two conflicting views of the same log. To help back this
property we rely on the USB armory hardware: 

- the per-origin view lives in rollback-protected storage. An
  authenticated blob on microSD, anchored to a monotonic eMMC RPMB
  counter (see [internal/state/ROLLBACK.md](internal/state/ROLLBACK.md)).
- the cosignature key exists only in RAM, uploaded at provisioning time,
  with no read-back path.
- storage and SSH host keys are derived from the SoC's hardware-unique key.

Submissions to the witness and the SSH provisioning channel are deliberately 
unauthenticated, the firmware carries no log configuration (no origin allowlist, 
no log keys) and witnessing a new log needs no rebuild of the firmware.

## Build & run

For quick setup there's a provided Nix devShell (`nix develop`) but it can be
ignored in favor of manual setup of required tools.

Once pre-req software is installed the `Makefile` offers several helpful 
targets:

    make test      # run host-side unit tests
    make qemu      # build & boot the emulated target (TARGET=mx6ullevk)
    make e2e       # test full provisioning + witness flow under QEMU
    make e2e-live  # test by feed a real log (keyserver.geomys.org) through QEMU
    make imx       # build bootable image for the armory (TARGET=usbarmory)
    make repro     # smoketest verify the build is reproducible

`make imx_signed` produces (but never flashes) a HAB-signed image. The fuse and
flash operations are out of scope.

## Operating

The witness serves `add-checkpoint` and per-log checkpoints on :80 and an
exec-only SSH provisioning channel on :22. It boots unprovisioned (blue LED
blinking, submissions get 503) with no key material in the image. The
signing key must be uploaded at runtime using the `provision` sub-command
and lives only in RAM.

The Go `vitrum` tool run on the host drives these interactions:

    vitrum keygen                    # generate a witness seed
    vitrum provision [-tofu]         # set clock + upload seed over SSH
                                     # (host key pinned; -tofu pairs once)
    vitrum feed -log-name keyserver  # verify a log checkpoint, submit it,
                                     # verify the returned cosignature
    vitrum selftest                  # drive a synthetic log end to end
    vitrum deprovision               # zero the key; submissions get 503

For development purposes `vitrum record` captures live request fixtures for the
offline tests while `vitrum hostkey` derives the emulated target's host key.
