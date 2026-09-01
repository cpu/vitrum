# Rollback-protected checkpoint storage: crash-safety analysis

## Goal

Storage replay/rollback must not induce a split view, even across boots. An
adversary with full control of the microSD (read, snapshot, restore, rewrite)
and the ability to power-cycle the device must never be able to make the
witness cosign a checkpoint inconsistent with one it has already cosigned.

## Primitives

- **microSD state blob**: the witness's per-log checkpoint state
  (`origin → cosigned note`), serialized, encrypted and authenticated
  under a device-bound key `K_state = KDF(HUK, "vitrum-state-v1")`, written to
  two alternating A/B slots. The authenticated blob embeds a monotonic
  generation counter `g`. The adversary can roll the microSD back to an
  earlier `g`, or corrupt it, but cannot forge a blob at a chosen `g`
  (no `K_state`).
- **RPMB anchor**: a single eMMC RPMB sector holding the latest generation
  `g`, written with an authenticated RPMB write. Each such write advances the
  eMMC's hardware-monotonic write counter (`github.com/usbarmory/rpmb`). The
  RPMB write counter cannot be decremented by any means available to the
  adversary
  (it is enforced in the eMMC controller and keyed by `K_rpmb = KDF(HUK,
  "vitrum-rpmb-v1")`, which never leaves the device). This is the anchor the
  blob generation is cross-checked against.

`K_state` and `K_rpmb` are derived from the SoC hardware-unique key (CAAM/DCP)
with distinct diversifiers. Pre-fuse, HUK derivation uses a non-unique test
vector and any firmware derives the same keys; such boots are marked DEV
(see `fw/internal/devicekey`); the protection matures once fuses are burned.

## Invariant

> Every cosignature for state generation `g` is released to a client only after
> both (1) the blob at generation `g` is durably on the microSD, and (2) the
> RPMB anchor reads `g`.

Equivalently: at rest, `g_rpmb` is the highest generation the witness has
ever committed. A blob whose generation is *below* `g_rpmb` is stale (rolled
back) and must be refused.

## Update sequence (state machine)

The witness sequencer runs with a 200 ms period and rotates its pending
checkpoint pool on each pass. A non-empty pool contains at most one checkpoint
per origin and advances the store from generation `n` to `n+1` as one batch:

```
S0  verified   - all checkpoints passed consistency checks (witness core),
                 committed in-RAM state still reflects generation n.
S1  blob-written - encrypted+authenticated blob for generation n+1 written to
                 the next A/B slot and flushed. RPMB still reads n.
S2  rpmb-anchored - authenticated RPMB write of (n+1) done; RPMB counter and
                 anchor now read n+1. Fully committed.
S3  released   - all batch cosignatures returned to their clients and the
                 committed in-RAM state advances to n+1.
```

Order is fixed: S1 before S2 before S3. The cosignature (S3) never leaves
the device before S2. A crash is a power loss between any two steps.

## Crash matrix

Let `g_rpmb` = generation read back from the RPMB anchor at boot, `g_blob` =
generation of the newest *valid* (decrypts + authenticates) microSD slot.

| Crash point | On-disk result | Boot observes | Recovery |
|---|---|---|---|
| before S1 | blob=n, rpmb=n | `g_blob == g_rpmb` | normal: serve at n. The clients see no cosignatures and resubmit. |
| between S1 and S2 | blob=n+1, rpmb=n | `g_blob == g_rpmb + 1` | **benign off-by-one.** The blob is one ahead but its generation was never anchored, so no batch cosignatures escaped (S3 not reached). Re-anchor: write n+1 to RPMB, then serve at n+1. Safe because the blob is authenticated; the adversary cannot have substituted a forged n+1. |
| between S2 and S3 | blob=n+1, rpmb=n+1 | `g_blob == g_rpmb` | normal: serve at n+1. Some responses may not have reached their clients; those clients resubmit idempotently. |
| after S3 | blob=n+1, rpmb=n+1 | `g_blob == g_rpmb` | normal. |

### Soft failures (I/O error, firmware keeps running)

The crash matrix above covers power loss between steps. A commit can also fail
softly: an S1 slot write or S2 anchor write returns an error while the
firmware keeps running. Retrying the commit on a later submission would be
unsound: the failed attempt's generation may already have a blob (or a torn
one) on the medium, and a retry (possibly with different content) would Seal
a second blob under the same generation. That both breaks the
write-once invariant the counter-only anchor depends on (two authentic blobs
would bear one generation, so the anchor could no longer pin the committed
content) and reuses the generation-derived GCM nonce (classic nonce-reuse:
plaintext XOR leak plus GHASH subkey recovery, i.e. blob forgery).

So a soft failure at or after the point where a write was issued halts the
store immediately: the generation is treated as burned, no cosignature is 
released, and an operator reboot resolves the state through the normal boot 
decision: a failed S1 lands in the "before S1" or "between S1 and S2" row, a 
failed S2 in "between S1 and S2" (benign off-by-one). Failures before anything
touches the medium (key validation, oversize state) do not halt: the generation
was never used and the submitter gets an error.

| Soft failure | On-disk result | Response | After reboot |
|---|---|---|---|
| pre-write validation (e.g. oversize) | unchanged (blob=n, rpmb=n) | error to submitter, keep serving | n/a |
| S1 slot write errors | slot unknown; previous gens intact | **halt** | normal at n, or benign off-by-one if the write landed |
| S2 anchor write errors | blob=n+1, rpmb=n | **halt** | benign off-by-one: re-anchor, serve at n+1 |

### Rollback / tamper cases (adversary, not a crash)

| Adversary action | Boot observes | Response |
|---|---|---|
| restore an older microSD snapshot (blob=k < committed) | `g_blob < g_rpmb` | **rollback detected: refuse to serve, signal loudly.** The RPMB counter proves a higher generation was committed; the presented blob is stale. |
| corrupt / erase both microSD slots | no valid blob, `g_rpmb > 0` | **refuse to serve.** RPMB says we committed generation `g_rpmb` but we cannot produce that state; treat as tamper, require operator. (A genuinely fresh unit has `g_rpmb == 0` and no blob, and starts empty; see below.) |
| forge a blob at a chosen high `g` | fails authentication | dropped as invalid; falls into the "no valid blob" row. |
| roll RPMB back | impossible | hardware-enforced; `K_rpmb` never leaves the device. |

Deliberate deviation from prior art: armored-witness performs an
authenticated dummy RPMB write at every boot (its CVE-2020-13799 mitigation,
invalidating any adversary-held write request frame). vitrum skips it
(`writeDummy=false` at `rpmb.InitWithTransport`): every anchor write already
verifies the response counter is exactly counter+1, which covers response
replay, and a
held-back stale *request* frame replayed later can only advance the hardware
write counter, pushing the system toward the halt rows above (anchor ahead),
never toward a split view. Skipping the dummy write also lets the firmware
probe unprogrammed units without an authenticated operation.

### Off-by-one is only benign upward

`g_blob == g_rpmb + 1` is the single tolerated mismatch (interrupted commit).
`g_blob == g_rpmb + k` for `k >= 2` is not benign: it means more than one
un-anchored commit, which the sequence never produces. We treat this as 
tampering and refuse. Any `g_blob < g_rpmb` is rollback and is refused.

## Boot decision (pseudocode)

```
g_rpmb := rpmb.Anchor()                 // authenticated read; hardware-monotonic
blob, g_blob, ok := loadNewestValidSlot()

switch {
case !ok && g_rpmb == 0:   start empty (fresh unit)
case !ok:                  HALT: committed g_rpmb but no state (tamper/erase)
case g_blob == g_rpmb:     serve at g_blob (normal)
case g_blob == g_rpmb + 1: re-anchor to g_blob, then serve (benign off-by-one)
case g_blob >  g_rpmb + 1: HALT: impossible gap (tamper)
default /* g_blob < g_rpmb */: HALT: rollback
```

HALT means refusing every add-checkpoint.

## Counter budget

The RPMB write counter is uint32. A non-empty checkpoint pool consumes one
increment, regardless of how many origins it contains; empty periods consume
none. The 200 ms sequencing period caps sustained scheduling at five commits
per second, so 2³² increments last about 27 years at the absolute maximum
continuous rate (or about 136 years at one increment per second). A slow pass
can be followed immediately by a pending ticker event; the period is not a
minimum delay between individual writes.
