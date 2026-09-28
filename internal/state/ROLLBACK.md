# Rollback-protected checkpoint storage: crash-safety analysis

## Goal

Storage replay/rollback must not induce a split view, even across boots. An
adversary with full control of the microSD (read, snapshot, restore, rewrite)
and the ability to power-cycle the device must never be able to make the
witness cosign a checkpoint inconsistent with one it has already cosigned.

## Primitives

- **microSD state blob**: the witness's per-log checkpoint state
  (`origin → cosigned note`), serialized, encrypted and authenticated under a
  device-bound key `K_state = KDF(HUK, "vitrum-state-v1")`, and written to two
  alternating A/B slots. The authenticated blob embeds a monotonic generation
  counter `g` and uses a fresh 128-bit AES-GCM nonce. The adversary can roll
  the microSD back, replace a slot with another captured authentic blob, or
  corrupt it, but cannot forge a new blob (no `K_state`).
- **RPMB anchor**: a single eMMC RPMB sector holding `(g, SHA-256(blob))`,
  written with an authenticated RPMB write. The digest binds the generation to
  one exact encrypted blob. Each write advances the eMMC's hardware-monotonic
  write counter (`github.com/usbarmory/rpmb`). The counter cannot be decremented
  by any means available to the adversary (it is enforced in the eMMC
  controller and keyed by `K_rpmb = KDF(HUK, "vitrum-rpmb-v1")`, which never
  leaves the device). A completely zero record represents a fresh unit; every
  initialized record uses the `VITRUMA2` encoding.

`K_state` and `K_rpmb` are derived from the SoC hardware-unique key (CAAM/DCP)
with distinct diversifiers. Pre-fuse, HUK derivation uses a non-unique test
vector and any firmware derives the same keys; such boots are marked DEV (see
`fw/internal/devicekey`); the protection matures once fuses are burned.

## Invariant

> Every cosignature for state generation `g` is released to a client only after
> both (1) the blob at generation `g` is durably on the microSD, and (2) the
> RPMB anchor contains `(g, SHA-256(blob))` for those exact bytes.

Equivalently: at rest, `g_rpmb` is the highest generation the witness has ever
committed, and `h_rpmb` selects its only acceptable blob. A blob whose
generation is below `g_rpmb`, or whose digest differs at the same generation,
must be refused.

## Update sequence (state machine)

The witness sequencer runs with a 200 ms period and rotates its pending
checkpoint pool on each pass. A non-empty pool contains at most one checkpoint
per origin and advances the store from generation `n` to `n+1` as one batch:

```
S0  verified      - all checkpoints passed consistency checks (witness core),
                    committed in-RAM state still reflects generation n.
S1  blob-written  - encrypted+authenticated blob for generation n+1 written
                    to the next A/B slot and flushed. RPMB still holds n.
S2  rpmb-anchored - authenticated RPMB write of
                    (n+1, SHA-256(blob[n+1])) done. Fully committed.
S3  released      - all batch cosignatures returned to their clients and the
                    committed in-RAM state advances to n+1.
```

Order is fixed: S1 before S2 before S3. The cosignature (S3) never leaves the
device before S2. A crash is a power loss between any two steps.

## Crash matrix

Let `(g_rpmb, h_rpmb)` be the RPMB record read at boot, and let `g_blob` and
`h_blob` identify the newest valid (decrypts + authenticates) microSD slot.

| Crash point | On-disk result | Boot observes | Recovery |
|---|---|---|---|
| before S1 | blob=n, rpmb=(n, hash(blob[n])) | generation and digest match | normal: serve at n. The clients see no cosignatures and resubmit. |
| between S1 and S2 | blob=n+1, rpmb=(n, hash(blob[n])) | `g_blob == g_rpmb + 1` | **benign off-by-one.** No batch cosignatures escaped (S3 not reached). Validate the blob, anchor its generation and digest, then serve at n+1. |
| between S2 and S3 | blob=n+1, rpmb=(n+1, hash(blob[n+1])) | generation and digest match | normal: serve at n+1. Some responses may not have reached their clients; those clients resubmit idempotently. |
| after S3 | blob=n+1, rpmb=(n+1, hash(blob[n+1])) | generation and digest match | normal. |

### Soft failures (I/O error, firmware keeps running)

The crash matrix above covers power loss between steps. A commit can also fail
softly: an S1 slot write or S2 anchor write returns an error while the firmware
keeps running. A failed S1 may have put all, some, or none of the new blob on
the card. A failed S2 may have committed either the old or new RPMB record.

Each Seal uses a fresh 128-bit nonce, so rebooting onto generation `n` and
retrying `n+1` does not repeat a GCM key/nonce pair. The RPMB digest also means
that, once one `n+1` blob is committed, another authentic `n+1` blob cannot be
substituted for it. The running store still halts after an issued write reports
failure, because its durable result is unknown. A reboot resolves that result
through the normal boot decision. Failures before anything touches the medium
(randomness, key validation, oversize state) do not halt.

| Soft failure | On-disk result | Response | After reboot |
|---|---|---|---|
| pre-write validation (e.g. oversize) | unchanged | error to submitter, keep serving | n/a |
| S1 slot write errors | slot unknown; previous generation intact | **halt** | normal at n, or benign off-by-one if the write landed |
| S2 anchor write errors | blob=n+1; RPMB result unknown | **halt** | normal match if the anchor write landed, otherwise benign off-by-one |

### Rollback / tamper cases (adversary, not a crash)

| Adversary action | Boot observes | Response |
|---|---|---|
| restore an older microSD snapshot | `g_blob < g_rpmb` | **refuse to serve.** The presented blob is stale. |
| replace the committed blob with a different authentic blob at the same generation | `g_blob == g_rpmb`, `h_blob != h_rpmb` | **refuse to serve.** The RPMB digest pins the exact committed contents. |
| corrupt / erase both microSD slots | no valid blob, anchored state exists | **refuse to serve.** Treat as tamper and require an operator. |
| forge a blob | AEAD authentication fails | dropped as invalid; the remaining state must satisfy the boot decision. |
| roll RPMB back | impossible | hardware-enforced; `K_rpmb` never leaves the device. |

Deliberate deviation from prior art: armored-witness performs an authenticated
dummy RPMB write at every boot (its CVE-2020-13799 mitigation, invalidating any
adversary-held write request frame). vitrum skips it (`writeDummy=false` at
`rpmb.InitWithTransport`): every anchor write already verifies the response
counter is exactly counter+1, which covers response replay, and a held-back
stale request replayed later can only advance the hardware write counter and
push the system toward a halt, never toward a split view. Skipping the dummy
write also lets the firmware probe unprogrammed units without an authenticated
operation.

### Off-by-one is only benign upward

`g_blob == g_rpmb + 1` is the single tolerated mismatch (interrupted commit).
`g_blob == g_rpmb + k` for `k >= 2` is not benign: it means more than one
unanchored commit, which the sequence never produces. Any `g_blob < g_rpmb` is
rollback and is refused.

Writing the RPMB record before the blob would burn the generation before any
Seal, but it would not give safe one-write recovery. At boot, `(rpmb=n+1,
blob=n)` is indistinguishable from an attacker deleting `blob[n+1]` after its
cosignature was released. Recovering downward could therefore roll back a
committed checkpoint. Vitrum therefore retains blob-before-anchor. An
intent/final protocol could make anchor-first recovery unambiguous, but would
cost two RPMB writes per commit. Fresh nonces and exact-blob binding make the
current one-write sequence safe.

## Boot decision (pseudocode)

```
fresh, g_rpmb, h_rpmb := rpmb.Anchor() // authenticated, hardware-monotonic
blob, g_blob, h_blob, ok := loadNewestValidSlot()

switch {
case !ok && fresh:                          start empty (fresh unit)
case !ok:                                   HALT: committed anchor but no state
case !fresh && g_blob == g_rpmb &&
     h_blob == h_rpmb:                      serve (normal)
case g_blob == g_rpmb:                      HALT: missing/mismatched binding
case g_rpmb != max && g_blob == g_rpmb + 1: anchor (g_blob, h_blob), then serve
case g_rpmb != max && g_blob > g_rpmb + 1:  HALT: impossible gap
default /* g_blob < g_rpmb */:              HALT: rollback
}
```

HALT means refusing every add-checkpoint.

## Accepted formats

The blob reader accepts only `VITRUMW2`, with its 32-byte header and fresh
128-bit nonce. The RPMB reader accepts only a completely zero fresh-unit record
or a `VITRUMA2` record containing the generation and exact blob digest. Any
other record, including a nonzero generation-only value, is unsupported or
corrupt and prevents the witness service from booting.

## Counter budget

The RPMB write counter is uint32. A non-empty checkpoint pool consumes one
increment, regardless of how many origins it contains; empty periods consume
none. The 200 ms sequencing period caps sustained scheduling at five commits
per second, so 2³² increments last about 27 years at the absolute maximum
continuous rate (or about 136 years at one increment per second). A slow pass
can be followed immediately by a pending ticker event; the period is not a
minimum delay between individual writes.
