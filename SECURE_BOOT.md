# SECURE_BOOT.md: HAB secure boot for vitrum (i.MX6ULZ)

> [!CAUTION]
> **This is a runbook, not an automated procedure.** Every step that burns a
> fuse, programs an SRK hash, activates HAB (`SEC_CONFIG`), or flashes a
> `*-signed.imx` is a **one-way, irreversible** operation on physical silicon.
> A human must execute each such step deliberately, on a designated unit, having
> read this whole document. Fuse/HAB steps below are marked **⛔ HUMAN-ONLY**.

## What HAB gives us (and what it doesn't)

High Assurance Boot (HAB) is the i.MX6 boot ROM's signature check. With our
SRK (Super Root Key) table hash burned into fuses and `SEC_CONFIG` closed, the
ROM refuses to boot any image not signed by one of our four SRKs: booting
arbitrary code on the unit is countered by HAB, with the first three SRK
slots individually revocable.

HAB does **not** distinguish between different *validly signed* images: the
SSH host key is a stable KDF(HUK) identity that survives firmware updates by
design, so a client cannot tell firmware versions apart by the device's SSH
key. The HAB's job here is solely to refuse *unsigned* modification.

## Terminology

| Term | Meaning |
|---|---|
| **SRK** | Super Root Key. Four RSA/ECC CA keypairs. The SoC is fused with `SHA-256(SRK1_pub‖SRK2_pub‖SRK3_pub‖SRK4_pub)`. |
| **CSFK** | Command Sequence File Key: signs the CSF commands; certified by an SRK. |
| **IMG key** | Image key: signs the image data; certified by the CSF chain. |
| **CSF** | Command Sequence File: the block of HAB commands (install keys, authenticate data) appended to the image. |
| **SEC_CONFIG** | The fuse that moves the SoC from *open* (HAB verifies but does not enforce) to *closed* (HAB enforces). |

## Tooling

- **`habtool`** from [`usbarmory/crucible`](https://github.com/usbarmory/crucible)
  (`cmd/habtool`): generates SRK keys/certs, the SRK table, the SRK hash fuse
  table, and signs images. Installed on demand by `make imx_signed`
  (`tamago install .../habtool@latest`).
- **`crucible`** (same repo): reads/writes OTP fuses on a connected armory in
  SDP/recovery mode. **⛔ We use it for reads only; every `blow` is HUMAN-ONLY.**
- **`mkimage`** (`ubootTools`, already in the devShell): builds the base
  `.imx`; the signing step wraps its output.

BSD-3-Clause (crucible, tamago-example) / Apache-2.0 (armored-witness): the
Makefile signing target is adapted from `tamago-example` with attribution.

## Step 1: Generate the SRK key ceremony material (offline, no hardware)

Do this on a trusted, offline machine. Keep the private keys in an
access-controlled store; they are the root of trust for every future image.

```bash
export HAB_KEYS=/secure/vitrum-hab-keys        # NOT in the repo; git-ignored path
mkdir -p "$HAB_KEYS" && chmod 700 "$HAB_KEYS"

# Four SRK CA key/cert pairs (the roots).
for i in 1 2 3 4; do
  habtool -C "$HAB_KEYS/SRK_${i}_key.pem" -c "$HAB_KEYS/SRK_${i}_crt.pem"
done

# One CSF and one IMG key/cert pair (per active SRK; here SRK index 1).
habtool -C "$HAB_KEYS/CSF_1_key.pem" -c "$HAB_KEYS/CSF_1_crt.pem"
habtool -C "$HAB_KEYS/IMG_1_key.pem" -c "$HAB_KEYS/IMG_1_crt.pem"
```

Generate the **SRK table** (consumed at signing time) and the **SRK hash fuse
table** (the 256-bit value that goes into fuses):

```bash
habtool \
  -1 "$HAB_KEYS/SRK_1_crt.pem" -2 "$HAB_KEYS/SRK_2_crt.pem" \
  -3 "$HAB_KEYS/SRK_3_crt.pem" -4 "$HAB_KEYS/SRK_4_crt.pem" \
  -t "$HAB_KEYS/SRK_1_2_3_4_table.bin" \
  -o "$HAB_KEYS/SRK_1_2_3_4_fuse.bin"
```

- `-t`: SRK table (needed by `make imx_signed`).
- `-o`: the SHA-256 fuse image (needed by the ⛔ fuse-burn step).

**Key ceremony hygiene:** four separate keys exist so up to three can be
revoked (Step 5) if compromised. Consider generating each SRK on separate
hardware / in an HSM, recording custodians, and storing an offline backup.
Losing all four with `SEC_CONFIG` closed means no future image can ever be
signed; the unit is permanently stuck on its last image.

## Step 2: Produce a signed image (no hardware, nothing burned)

```bash
make imx_signed TARGET=usbarmory HAB_KEYS=$HAB_KEYS
# → out/vitrum-usbarmory-signed.imx   (base .imx + CSF; NOT flashed, NOT fused)
```

Under the hood (`Makefile` `imx_signed`): `habtool -A/-a` = CSF key/cert,
`-B/-b` = IMG key/cert, `-t` = SRK table, `-x` = SRK index (`HAB_SRK_INDEX`,
default 1), `-i` = the base `.imx`, `-o` = the emitted `.csf`; the CSF is then
concatenated onto the image. `habtool` internally emits a standard HAB4 CSF
with these command blocks, in order: *Header, Install SRK, Install CSFK,
Authenticate CSF, Install Key (IMG), Authenticate Data*.

Reproducibility still applies: the *base* `.imx` is byte-reproducible
(`make repro`); the CSF adds signatures. A verifier rebuilds the base image and
checks the signature over it rather than reproducing the CSF bytes.

## Step 3: Validate the signed image on the UNFUSED unit (safe, reversible)

On an **open** (unfused) device, HAB *verifies but does not enforce*: the image
boots regardless, and HAB records whether verification would have passed. This
is the safe dress rehearsal: **no fuse is touched.**

> [!IMPORTANT]
> Even in Step 3, do **not** `dd` the signed image to the armory casually
> (raw block-device writes are HUMAN-ONLY, `CONTRIBUTING.md`). The intended
> validation path is either (a) load via SDP into RAM (the armory's card stays
> untouched), or (b) a deliberate, reversible card write. Recovery = pull the
> card (the factory eMMC image still boots).

How to read the verification result on this platform: **TamaGo exposes no HAB
event-log API** (there is no `hab` package; the ROM's `hab_rvt.report_event`
is not bound). The practical signals are:

1. **`imx6ul.SNVS.Available()`**: returns true only in the Trusted/Secure
   state, i.e. after HAB has authenticated the image and the OTPMK became
   usable. On an open unit with a *good* signature it can report secure; with a
   bad/absent signature it stays non-secure. This is the same signal vitrum
   already uses to decide whether HUK-derived keys are trustworthy
   (`fw/keys.go`, the `dev` flag). **A DEV-marked boot means HAB did not put
   us in the secure state; treat derived identities as non-unique.**
2. **U-Boot `hab_status` / `hab_auth_img`**: if chainloading through U-Boot,
   its HAB commands print the ROM event log (why an image was rejected). This
   is the richest diagnostic but is outside TamaGo.
3. **NXP offline tooling** (`cst`, HAB log parsers) against a captured boot.

If richer runtime HAB-event reporting is ever needed in vitrum itself, it
requires writing an HAB RVT (ROM Vector Table) `report_event` binding; no
upstream TamaGo code does this.

## Step 4 (⛔ HUMAN-ONLY): Burn the SRK hash and close the device

**Do not run these. They are irreversible.** Documented for the designated
person performing the ceremony on the designated unit, in order, after Steps
1–3 have fully succeeded and been reviewed.

Burn the SRK hash (fuse **bank 3, words 0–7**, 256-bit, little-endian), then
read it back:

```bash
# ⛔ HUMAN-ONLY, irreversible. Armory in SDP/recovery mode.
crucible -m IMX6UL -r 1 -b 16 -e little blow SRK_HASH <64-hex-chars-of-SRK_1_2_3_4_fuse.bin>
crucible -s -m IMX6UL -r 1 -b 16 -e little read SRK_HASH   # verify before proceeding
```

Optionally set **SRK_LOCK** (recommended on production units to prevent the SRK
hash from being altered / the unit bricked):

```bash
# ⛔ HUMAN-ONLY, irreversible.
crucible -m IMX6UL -r 1 -b 2 -e big blow SRK_LOCK 1
crucible -s -m IMX6UL -r 1 -b 2 read SRK_LOCK
```

Close the device (`SEC_CONFIG` closed) **only after** a signed image has
verified in the open state (Step 3) and the SRK hash reads back correct. Once
closed, the ROM enforces signatures and an unsigned or wrongly-signed image
will **not boot**:

```bash
# ⛔ HUMAN-ONLY, irreversible; this is the point of no return.
# The blow command is deliberately not written out here: derive it during
# the ceremony from the i.MX6ULZ Security Reference Manual (exact
# SEC_CONFIG fuse and crucible register name), per the warning below.
```

> [!WARNING]
> Confirm the exact `SEC_CONFIG` fuse location and `crucible` register name
> against the **i.MX6ULZ Security Reference Manual** first. `crucible -m IMX6UL`
> resolves fuse names from its i.MX6UL map; the **SRK_HASH = bank 3, words 0–7**
> location is confirmed, but verify `SEC_CONFIG` / `SRK_REVOKE` offsets against
> the SRM before burning; a wrong offset can brick the unit.

After closing, flashing `out/vitrum-usbarmory-signed.imx` is what boots; the
unsigned `.imx` no longer will. Fusing also changes every HUK-derived key
(the SSH host key identity and the not-yet-programmed RPMB key), so continue
with `HARDWARE_SETUP.md` steps 3–4 in order.

## Step 5 (⛔ HUMAN-ONLY): SRK revocation

Four SRKs exist; **only indices 0–2 (the first three) are individually
revocable** via the `OCOTP_SRK_REVOKE` fuses (effective on a closed unit). The
fourth cannot be revoked; it is the last-resort root. Revoke a compromised SRK
by setting its bit, then re-sign future images with a surviving SRK index
(`make imx_signed HAB_SRK_INDEX=<n>`):

```bash
# ⛔ HUMAN-ONLY, irreversible. Example: revoke SRK index 3 (bit 2).
crucible -m IMX6UL -r 1 -b 2 -e big blow OCOTP_SRK_REVOKE 0b100
```

> Verify the exact `OCOTP_SRK_REVOKE` bank/word against the i.MX6ULZ SRM before
> running (crucible resolves the name, but confirm the mapping).

## Recovery & bricking notes

- **Open unit, bad signed image:** boots anyway (HAB open), no risk. Recover
  by pulling the card (factory eMMC boots) or SDP.
- **Closed unit, no valid signed image on the card:** the ROM refuses the card
  and falls back to SDP (serial download); you can still load a *signed*
  recovery image into RAM. An *unsigned* recovery payload will be refused.
- **Closed unit, all SRKs revoked or lost:** unrecoverable. This is why the
  4th SRK is non-revocable and why offline key backups matter.
- **SRK_LOCK set with a wrong SRK hash:** unrecoverable. Always read back the
  SRK hash (Step 4) before locking or closing.

## Checklist before touching a single fuse

- [ ] Steps 1–3 completed; a signed image verified in the **open** state.
- [ ] `SRK_1_2_3_4_fuse.bin` regenerated and its 64 hex chars double-checked.
- [ ] All four SRK private keys backed up offline, custodians recorded.
- [ ] `SEC_CONFIG` / `SRK_REVOKE` offsets confirmed against the i.MX6ULZ SRM.
- [ ] Designated unit and designated human; approval recorded.
- [ ] Recovery path (SDP + a signed recovery image) prepared and understood.
