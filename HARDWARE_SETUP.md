# Hardware setup: bringing up a production witness

Runbook for taking a real USB armory Mk II from factory state to a
provisioned production witness. The emulated target (`make qemu`) needs
none of this; see `CONTRIBUTING.md` for the dev workflow.

> [!WARNING]
> **Ordering is load-bearing.** Every device-bound key (the SSH host
> key, the state-blob key, and the eMMC RPMB authentication key) is
> derived from the SoC hardware-unique key, and the HUK's effective value
> changes when the unit is fused into its secure state. The RPMB key can
> be programmed **exactly once, ever**. Programmed before fusing, the
> fused unit derives a *different* key, RPMB authentication fails
> forever, and the fused firmware fails closed: the unit is permanently
> unusable as a witness. **Fuse first. Program RPMB second. Pair and
> provision last.**

## 0. Prerequisites

- The devShell; `make imx TARGET=usbarmory` builds.
- A microSD card dedicated to the unit. It is used raw: firmware image at
  the 1 KiB offset, witness state slots at the 16 MiB offset. No
  partition table, no filesystem.
- Without the optional debug accessory there is **no serial console**; the
  observation surfaces are the LEDs and the network (`/healthz`, `/logz`,
  SSH). `GET /logz` serves the firmware log since boot from a RAM ring,
  including fatal errors, as long as USB is still up.

LED vocabulary (`fw/main.go`):

| Pattern | Meaning |
|---|---|
| blue blinking | up, unprovisioned (submissions get 503) |
| blue solid | provisioned and serving |
| white pulse | a checkpoint was cosigned |
| blue + white together | store halted (rollback/tamper) |
| blue/white alternating | fatal error |

## 1. DEV bring-up (unfused: safe, reversible)

Flash and boot the unsigned image:

    make imx TARGET=usbarmory
    # ⛔ HUMAN-ONLY: writing a raw block device; double-check /dev/sdX
    dd if=out/vitrum-usbarmory.imx of=/dev/sdX bs=512 seek=2 conv=fsync

Set the boot switch to microSD, attach to the host, and check
`http://10.0.0.1/healthz`. Expected on an unfused unit:

- key derivation works but is marked DEV: the HUK is a non-unique test
  vector, so every derived identity is computable by anyone;
- with the RPMB key unprogrammed, storage degrades to RAM-only
  (`persistence: "none (RAM only)"`): deliberate on an unfused unit,
  fatal on a fused one.

Smoke-test freely (`vitrum provision -tofu`, `selftest`, `feed`), but
treat everything paired or pinned at this stage as disposable: the DEV
host key is not an identity. Delete `keys/ssh_host.pub` pins from this
stage before production pairing.

## 2. ⛔ Secure boot ceremony

Follow `SECURE_BOOT.md` in full: key ceremony offline, signed image
validated on the open unit, then, human-only and in order: SRK hash burn,
verification read-back, and closing `SEC_CONFIG`. From that point only
`*-signed.imx` images boot.

## 3. Re-establish the device identity (post-fuse)

Fusing changed the HUK, so the SSH host key changed with it. Discard any
DEV-era pin, then pair over a **trusted first contact**: the armory
plugged directly into the provisioning host, no other network path:

    rm -f keys/ssh_host.pub
    go run ./cmd/vitrum provision -tofu   # pins the new host key

This pin is the root of the operator's trust in the device (SECURITY.md,
"Device identity"); back `keys/ssh_host.pub` up alongside the witness
seed.

## 4. ⛔ Program the RPMB authentication key

One-way, human-only, and only after step 2. The firmware never programs
it (it probes with an unauthenticated counter read and degrades or fails
instead). Tooling is **TBD**; the intended shape is a dedicated one-shot
maintenance build, kept out of the production image entirely; see
transparency-dev/armored-witness for prior art.

After programming, reboot and confirm `/healthz` reports
`"persistence": "microSD blob + eMMC RPMB anchor"` with **no** DEV mark.

## 5. Provision the witness key

    go run ./cmd/vitrum keygen        # once; writes keys/witness.seed
    go run ./cmd/vitrum provision     # sets the clock, uploads the seed,
                                      # echoes the vkey for cross-check

Back up `keys/witness.seed` offline: it is the witness's private key, and
losing it means losing the witness identity. It is re-uploaded on every
boot (the device holds it in RAM only; a power cycle deprovisions).

## 6. Host-side obligations

The device trusts this host for everything except split views
(SECURITY.md). That trust translates into standing requirements:

- never bridge or forward the armory's network; reachability is the
  privilege boundary;
- feeders verify log signatures before submitting (as `vitrum feed`
  does);
- monitoring pins the expected witness key (`-witness-key`); the
  `/healthz` default would not notice a re-keyed device;
- the clock is set at provisioning (`settime`); keep the host's own
  clock sane.

## 7. Acceptance

- `/healthz`: `target=usbarmory`, `provisioned=true`, RPMB persistence,
  no DEV marks, sane `time`.
- `vitrum selftest` passes end to end.
- Power-cycle, re-provision, re-feed a log: the witness answers from its
  stored size (409 with the stored size, or an idempotent same-size
  cosign), proof that state survived the reboot.

## Halt

Blue and white blinking together means the store refused to advance
(rollback or tamper evidence at boot, or a failed commit). There is
deliberately no reset command on any network surface (SECURITY.md,
invariants). The halt is a boot-time decision: if the cause was a storage
mix-up, restoring the correct card recovers on the next boot. A genuinely
poisoned, lost, or exhausted state needs the (TBD) maintenance build, or
replacement hardware.
