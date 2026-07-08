# vitrum

A bare-metal [tlog witness](https://c2sp.org/tlog-witness) for the USB
armory Mk II, built with [TamaGo](https://github.com/usbarmory/tamago) as
a single Go binary. **The armory enforces there are no split views, and
trusts the host for everything else.**

It cosigns checkpoints for any origin per
[c2sp.org/tlog-cosignature](https://c2sp.org/tlog-cosignature), promising
exactly one thing: it will never sign two conflicting views of the same
log. That promise is backed by hardware the attached host cannot reach:

- the per-origin view lives in rollback-protected storage: an
  authenticated blob on microSD, anchored to a monotonic eMMC RPMB
  counter (`internal/state/ROLLBACK.md`).
- the cosignature key exists only in RAM, uploaded at provisioning time,
  with no read-back path.
- storage and SSH host keys derive from the SoC's hardware-unique key.

Everything else is the host's job: log authenticity, which logs matter,
the clock, availability. Submissions and the SSH provisioning channel are
deliberately unauthenticated, the firmware carries no log configuration
(no origin allowlist, no log keys) and witnessing a new log needs no rebuild
of the firmware. Device reachability is the privilege boundary.

## Build & run

Everything runs inside the Nix devShell (`nix develop`) but can be replicated
outside of nix with manual setup of required tools. The `Makefile` offers
several helpful targets:

    make test      # host-side unit tests
    make qemu      # build & boot the emulated target (TARGET=mx6ullevk)
    make e2e       # full provisioning + witness flow under QEMU
    make e2e-live  # feed a real log (keyserver.geomys.org) through QEMU
    make imx       # bootable image for the armory (TARGET=usbarmory)
    make repro     # verify the build is reproducible

`make imx_signed` produces (but never flashes) a HAB-signed image. The fuse and
flash operations are human-only.

More docs: **SECURITY.md** (threat model and load-bearing invariants),
**CONTRIBUTING.md** (dev workflow and hard rules), **HARDWARE_SETUP.md** and
**SECURE_BOOT.md** (runbooks for bringing up, and irreversibly fusing, a
real unit).

## Operating

The witness serves `add-checkpoint` and per-log checkpoints on :80 and an
exec-only SSH provisioning channel on :22. It boots unprovisioned (blue LED
blinking, submissions get 503) with no key material in the image. The
signing key is uploaded at runtime and lives only in RAM.

The Go `vitrum` host tool drives these interactions:

    vitrum keygen                    # generate a witness seed
    vitrum provision [-tofu]         # set clock + upload seed over SSH
                                     # (host key pinned; -tofu pairs once)
    vitrum feed -log-name keyserver  # verify a log checkpoint, submit it,
                                     # verify the returned cosignature
    vitrum selftest                  # drive a synthetic log end to end
    vitrum deprovision               # zero the key; submissions get 503

`vitrum record` captures live request fixtures for the tests while `vitrum
hostkey` derives the emulated target's host key.
