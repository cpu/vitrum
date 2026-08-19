# Hardware setup

Runbook for taking a real USB armory Mk II from factory state to a
provisioned production witness. 

For general development, [CONTRIBUTING.md](CONTRIBUTING.md).

> [!WARNING]
> **Ordering is load-bearing.** Every device-bound key is derived from the 
> SoC hardware-unique key, and the HUK's effective value changes when the unit
> is fused into its secure state. 
> 
> **The RPMB key can be programmed only once**. Programmed before fusing, the
> fused unit derives a *different* key, RPMB authentication fails
> forever, and the fused firmware fails closed: the unit is permanently
> unusable as a witness.

## 0. Prerequisites

- A build environment that can complete `make imx TARGET=usbarmory` builds.
- A microSD card dedicated to the unit.

## 1. Test the hardware with an unsigned dev build

Flash and boot the unsigned image:

    make imx TARGET=usbarmory
    dd if=out/vitrum-usbarmory.imx of=/dev/sdX bs=512 seek=2 conv=fsync

Attach to the host, and check `http://10.0.0.1/healthz`. 
Expected on an unfused unit:

- key derivation works but is marked DEV. The HUK is a non-unique test
  vector, so every derived identity is computable by anyone.
- with the RPMB key unprogrammed, storage degrades to RAM-only
  (`persistence: "none (RAM only)"`).

Smoke-test freely (`vitrum provision -tofu`, `selftest`, `feed`), but
treat everything paired or pinned at this stage as disposable.

Delete `keys/ssh_host.pub` TOFU pins from this stage before production 
provisioning.

## 2. Signed image production & Secure Boot

Follow `SECURE_BOOT.md`. This requires a signing key ceremony, signed image
validated on the open unit, then, in order: SRK hash burn, verification 
read-back, and closing `SEC_CONFIG`. From that point only signed images boot.

## 3. TOFU SSH pinning

If you used the hardware previously for the dev verification then
fusing changed the HUK, so the SSH host key changed with it. Discard any
`.pub` pin data, and then TOFU-connect with the armory plugged directly into
the provisioning host:

    rm -f keys/ssh_host.pub
    go run ./cmd/vitrum provision -tofu   # pins the new host key

Back `keys/ssh_host.pub` up alongside the witness seed. Future runs of
the `vitrum provision` command will expect this identity.

## 4. Program the RPMB authentication key

TODO(XXX): This needs hardware testing.

## 5. Provision the witness key

    go run ./cmd/vitrum keygen        # If a fresh seed is required,
                                      # writes keys/witness.seed
    go run ./cmd/vitrum provision     # sets the clock, uploads the seed,
                                      # echoes the vkey for cross-check

Back up `keys/witness.seed` offline. It is the witness's private key, and
losing it means losing the witness identity. It must be re-uploaded on every
boot (the device holds it in volatile RAM only).

## 6. Verification 

- `/healthz`: should show `target=usbarmory`, `provisioned=true`, 
  RPMB persistence, no DEV marks, sane `time`.
- Running `vitrum selftest` passes end to end.

For maximum assurance, power-cycle, re-provision and then re-feed a log. 
The witness should respond using its stored size (409 with the stored size, 
or an idempotent same-size cosign), offering proof that state survived the 
reboot.

# Halt state

Blue and white blinking together means the store refused to advance
(rollback or tamper evidence at boot, or a failed commit). 

There is deliberately no reset command on any network surface. The halt is a
boot-time decision: if the cause was a storage mix-up, restoring the correct
card recovers on the next boot. A genuinely poisoned, lost, or exhausted state 
needs custom maintenance, or replacement hardware.

# Host-side configuration notes

The device trusts this host for everything except split views
(SECURITY.md). In general one should never;

- never bridge or forward the armory's network. Reachability is the
  privilege boundary and DoS is possible if the device is network
  reachable.
- software submitting checkpoints must verify log signatures before
  submitting.

# LED Reference

| Pattern | Meaning |
|---|---|
| blue blinking | up, unprovisioned (submissions get 503) |
| blue solid | provisioned and serving |
| white pulse | one or more checkpoints were cosigned |
| blue + white together | store halted (rollback/tamper) |
| blue/white alternating | fatal error |
