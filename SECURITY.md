# vitrum security model

Vitrum enforces per-log consistency. This document defines its trust boundary
and accepted risks.

## Network reachability is privileged

The witness trusts anything that can reach it over the network. On the USB
armory Mk II, that network is Ethernet-over-USB, so the boundary is the
attached host and anything it forwards. The firmware enforces consistency and
trusts the host for everything else.

1. Submissions are not authenticated and there is no origin
   allowlist. The firmware verifies no log signatures and cosigns a
   consistent checkpoint for any origin. This means witnessing a new log
   requires no rebuild but upstream clients must verify log signatures.
   
2. SSH accepts any client. There is no `authorized_keys` set; anyone who can
   reach port 22 can run every provisioning command.

## Armory firmware

The armory firmware is responsible for:

- **Consistency.** Same-size resubmissions must match the stored hash.
  Growth needs a consistency proof against it. The witness never endorses
  two conflicting views of the same origin.
- **Rollback protection.** State is an encrypted, authenticated blob
  anchored to a hardware-monotonic counter
  (See [`internal/state/ROLLBACK.md`](internal/state/ROLLBACK.md)). Restoring 
  an old storage snapshot halts the witness.
- **Key confinement.** The signing key is RAM-only with no read-back path.
  On device, the storage and host keys derive from the hardware-unique key.
- **Device identity.** The SSH host key authenticates the device to the
  operator (TOFU + pinning in `vitrum provision`).

## Accepted risks

### View poisoning (permanent, per origin)

Consistency proofs require no secret, so anyone in-boundary can advance
the witness's view of any origin to a fabricated extension of the real
tree. Afterwards, the honest log's checkpoints are then refused (409/422) 
forever. The poisoned view is committed to rollback-protected storage and 
there is deliberately no reset command.

### Timestamp trust

`settime` is open and cosignatures embed the device clock, so clients
must treat cosignature timestamps as no more trustworthy than the
boundary.

### Re-keying and deprovisioning

Anyone in-boundary can replace or clear the witness key. Nothing
persists, nothing can be read back, and a rogue key verifies under no
trusted witness key. This is a DoS, recoverable by re-provisioning.

### State-slot exhaustion

With no allowlist, every origin ever submitted (a typo'd feed included)
creates a permanent storage entry, and checkpoint text is submitter-controlled 
up to the 64 KiB request limit.

Garbage origins or one inflated entry can fill the 64 KiB slot, at which
point commits fail (500) while already-cosigned state keeps serving.
