# vitrum security model

vitrum is a bare-metal tlog witness. Its product is a **cosignature**: a
signed statement that a submitted checkpoint is consistent with the
witness's stored view of that log. This document records the trust
decision that shapes the design: the network privilege boundary.

## The privilege boundary: network reachability

**Anything that can reach the device over the network is trusted not to
be malicious.** On the USB armory Mk II the "network" is
Ethernet-over-USB, so the boundary is the attached host and whatever it
forwards. The model in one sentence: *the armory enforces no split views,
and trusts the host for everything else.*

1. **Submissions are not authenticated and there is no origin
   allowlist.** The firmware verifies no log signatures and cosigns a
   consistent checkpoint for any origin; witnessing a new log requires
   no rebuild. Upstream feeders must verify log signatures (`vitrum
   feed` does).
2. **SSH accepts any client.** There is no authorized_keys set; anyone
   who can reach port 22 can run every provisioning command.
3. **Diagnostics are open.** `GET /logz` serves the recent firmware log
   (a RAM ring) to any in-boundary reader. Log lines are operational
   metadata only — key material is never logged; keep it that way.

## What is enforced

Even against in-boundary parties:

- **Consistency.** Same-size resubmissions must match the stored hash;
  growth needs a consistency proof against it (first sightings excepted:
  there is nothing to be consistent with yet). The witness never endorses
  two conflicting views of the same origin. This is the sole property a
  vitrum cosignature attests.
- **Rollback protection.** State is an encrypted, authenticated blob
  anchored to a hardware-monotonic counter
  (`internal/state/ROLLBACK.md`); restoring an old snapshot halts the
  witness.
- **Key confinement.** The signing key is RAM-only, zeroed on rotation
  and deprovision, with no read-back path. On hardware, the storage and
  host keys derive from the hardware-unique key (the emulated target
  embeds a build-time host seed).
- **Device identity.** The SSH host key authenticates the device to the
  operator (TOFU + pinning in `vitrum provision`), keeping an uploaded
  seed confidential in transit despite anonymous clients.

## Accepted risks

### View poisoning (permanent, per origin)

Consistency proofs require no secret, so anyone in-boundary can advance
the witness's view of any origin to a fabricated extension of the real
tree; the honest log's checkpoints are then refused (409/422) forever.
The poisoned view is committed to rollback-protected storage and there is
deliberately no reset command (see invariants), so on hardware recovery
means purpose-built maintenance firmware that rewrites state under the
device-bound key, or replacement hardware. RAM-only builds recover on
reboot.

### Cosigned forks under log-key compromise

A cosignature does not imply the log ever vouched for the tree. If a
trusted log's key is compromised (or the log equivocates), an attacker
with in-boundary access can hold witness cosignatures over a fabricated
fork, the scenario witnessing exists to prevent. Two limits remain:
correct clients verify the log's own signature, and the consistency rule
keeps the witness from ever endorsing two views.

### Timestamp trust

`settime` is open and cosignatures embed the device clock, so clients
must treat cosignature timestamps as no more trustworthy than the
boundary.

### Re-keying and deprovisioning

Anyone in-boundary can replace or clear the witness key. Nothing
persists, nothing can be read back, and a rogue key verifies under no
trusted witness key: DoS, recoverable by re-provisioning. Only feeders
that pin `-witness-key` notice: `vitrum feed`'s default fetches the
current key from `/healthz` and would verify against the rogue key.

### State-slot exhaustion

With no allowlist, every origin ever submitted (a typo'd feed included)
creates a permanent entry (there is no removal path, see invariants), and
checkpoint text is submitter-controlled up to the 64 KiB request limit.
Garbage origins or one inflated entry can fill the 64 KiB slot, at which
point commits fail (500) while already-cosigned state keeps serving;
recovery is maintenance firmware. In-boundary DoS.

## Invariants: do not break these

- **Never add state-mutating recovery commands (reset, forget-log,
  rollback) or key read-back to the HTTP or SSH surfaces.** Both are
  unauthenticated; an open reset turns the DoS risks above into
  split-view attacks (roll the view back, then re-cosign an alternate
  history).
- **Feeders must verify log signatures before submitting.** The firmware
  does not; upstream verification is load-bearing.
- **The consistency check stays.** It is the entirety of what a
  cosignature attests.
- **Revisit this document before widening the boundary.** Forwarding the
  device's ports promotes every "in-boundary" party above to "the
  internet".

## Protocol deviations

- `POST /add-checkpoint` never returns 403 or the unknown-log 404
  (`c2sp.org/tlog-witness`'s invalid-signature and unknown-log outcomes):
  any origin is witnessed, and wrong or absent log signatures are
  cosigned if consistent.
- `GET /<origin-hash>/checkpoint` serves the checkpoint text plus the
  witness cosignature only; submitted signature lines are never
  verified, stored, or re-served.
