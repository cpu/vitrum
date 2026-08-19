# HAB secure boot for vitrum (i.MX6ULZ)

This runbook closes one USB armory Mk II around a vitrum image. It follows the
[USB armory Mk II secure-boot guide][upstream] and uses its `habtool` and
`crucible` conventions.

> [!WARNING]
> This procedure has not yet completed a physical test run in this project.
> Use sacrificial hardware first. OTP fuse writes cannot be undone.

> [!CAUTION]
> Do not improvise past a failed check. In particular, do not write
> `SRK_LOCK` or `SEC_CONFIG` unless every preceding comparison succeeds and
> the signing keys have verified offline backups.

## What becomes permanent

HAB verifies an i.MX image against a table of four RSA Super Root Keys (SRKs).
The SoC stores the SHA-256 hash of the encoded SRK table. `SEC_CONFIG=0b11`
changes HAB from open mode, which records authentication failures but may
continue booting, to closed mode, which rejects unauthenticated images.

The SRK hash, its lock, key-revocation bits, `SEC_CONFIG`, and the hardening
fuses below are one-time-programmable. Writing an image to microSD is
destructive to that card but is not an OTP operation.

The CSF and IMG certificates are both signed by the selected SRK CA. The CSF
key authenticates HAB commands; the IMG key authenticates the image data.

## Preconditions

- Use a standard USB armory Mk II with an i.MX6ULZ revision supported by the
  upstream guide.
- Keep the factory eMMC Linux installation bootable. `crucible` runs there as
  root with `nvmem-imx-ocotp` loaded.
- Use a dedicated microSD card and identify its whole-device path exactly.
- Build from a clean, reviewed commit in `nix develop`.
- Store the HAB directory on encrypted offline-capable storage. Make two
  verified backups before locking any fuse.
- Read the entire runbook before starting. Record every command, output,
  artifact digest, device serial number, and fuse read-back.

Set these shell variables once. Replace both paths; never paste the example
device path unchanged.

```bash
export HAB_KEYS=/secure/vitrum-hab-keys
export ARMORY_CARD=/dev/sdX
test -b "$ARMORY_CARD"
```

## 1. Install the pinned host tool

The Makefile pins Crucible so later upstream changes cannot silently alter the
certificate or CSF format.

```bash
go tool github.com/usbarmory/tamago/cmd/tamago install \
  github.com/usbarmory/crucible/cmd/habtool@v0.0.0-20260105222051-0bd71c72232c
export PATH="$(go tool github.com/usbarmory/tamago/cmd/tamago env GOPATH)/bin:$PATH"
habtool -h
```

Use the same pinned Crucible revision to build the target-side `crucible`
binary installed in the factory Linux environment.

```bash
go install github.com/usbarmory/crucible/cmd/crucible@v0.0.0-20260105222051-0bd71c72232c
```

## 2. Create and back up the PKI

Run this ceremony on the protected host. A new deployment should use a new,
empty directory.

```bash
mkdir -m 700 "$HAB_KEYS"

for i in 1 2 3 4; do
  habtool -C "$HAB_KEYS/SRK_${i}_key.pem" \
          -c "$HAB_KEYS/SRK_${i}_crt.pem"
done

habtool \
  -C "$HAB_KEYS/SRK_1_key.pem" \
  -c "$HAB_KEYS/SRK_1_crt.pem" \
  -A "$HAB_KEYS/CSF_1_key.pem" \
  -a "$HAB_KEYS/CSF_1_crt.pem" \
  -B "$HAB_KEYS/IMG_1_key.pem" \
  -b "$HAB_KEYS/IMG_1_crt.pem"

habtool \
  -1 "$HAB_KEYS/SRK_1_crt.pem" \
  -2 "$HAB_KEYS/SRK_2_crt.pem" \
  -3 "$HAB_KEYS/SRK_3_crt.pem" \
  -4 "$HAB_KEYS/SRK_4_crt.pem" \
  -t "$HAB_KEYS/SRK_1_2_3_4_table.bin" \
  -o "$HAB_KEYS/SRK_1_2_3_4_fuse.bin"

test "$(stat -c %s "$HAB_KEYS/SRK_1_2_3_4_fuse.bin")" -eq 32
sha256sum "$HAB_KEYS"/*
```

Make two offline backups and compare their recorded SHA-256 manifests with
the originals. Losing the private keys prevents signing new firmware;
previously signed images remain usable while their SRK is trusted.

## 3. Build, sign, and inspect the image

```bash
make imx_signed TARGET=usbarmory HAB_KEYS="$HAB_KEYS" HAB_SRK_INDEX=1

test -s out/vitrum-usbarmory.imx
test -s out/vitrum-usbarmory.csf
test -s out/vitrum-usbarmory-signed.imx
test "$(stat -c %s out/vitrum-usbarmory-signed.imx)" -eq \
     "$(( $(stat -c %s out/vitrum-usbarmory.imx) + $(stat -c %s out/vitrum-usbarmory.csf) ))"
sha256sum out/vitrum-usbarmory.imx out/vitrum-usbarmory.csf \
  out/vitrum-usbarmory-signed.imx
```

Archive the signed image, its three digests, the source commit, the Crucible
revision, and the key manifest together.

## 4. Boot the signed image while HAB is open

Confirm the unit is still open from factory Linux before touching OTP:

```bash
crucible -s -m IMX6UL -r 1 -b 2 read SEC_CONFIG
```

Stop unless the `SEC_CONFIG` field is `0`. Also read `SRK_LOCK`,
`OCOTP_SRK_REVOKE`, and every fuse named in section 7; stop if the unit is not
in the expected factory state. Then flash the signed image:

```bash
sudo dd if=out/vitrum-usbarmory-signed.imx of="$ARMORY_CARD" \
  bs=512 seek=2 conv=fsync status=progress
sync
```

Read back exactly the flashed byte range and compare its digest with the
archived image:

```bash
IMAGE_SIZE=$(stat -c %s out/vitrum-usbarmory-signed.imx)
sudo dd if="$ARMORY_CARD" bs=1 skip=1024 count="$IMAGE_SIZE" status=none \
  | sha256sum
sha256sum out/vitrum-usbarmory-signed.imx
```

Boot from microSD and require `/healthz` and `vitrum selftest` to pass. Power
cycle and repeat. This validates the image layout and runtime, but not HAB
authentication: open HAB can continue after an authentication failure.

For a non-sacrificial unit, make pre-close authentication a mandatory extra
gate: boot an instrumented build that calls HAB's `report_status` and
`report_event` ROM APIs, or use a UART-capable HAB diagnostic environment,
and require zero HAB failure events. The current vitrum firmware does not
expose those ROM APIs.

## 5. Prepare the fuse session

Boot factory Linux from eMMC. Confirm the microSD still contains the archived
signed-image digest from the host, then copy the 32-byte fuse file to the unit
over an authenticated channel. On both systems compare:

```bash
sha256sum SRK_1_2_3_4_fuse.bin
```

On the armory, as root:

```bash
modprobe nvmem-imx-ocotp
FUSE_HEX=$(od -An -v -tx1 SRK_1_2_3_4_fuse.bin | tr -d ' \n')
test "${#FUSE_HEX}" -eq 64
printf '%s\n' "$FUSE_HEX"
```

Compare `FUSE_HEX` character-for-character with the protected host's copy.
Keep stable power connected throughout the fuse session.

## 6. Burn and lock the SRK hash

The following writes bank 3, words 0-7 using Crucible's required little-endian
encoding:

```bash
crucible -m IMX6UL -r 1 -b 16 -e little blow SRK_HASH "$FUSE_HEX"
READBACK=$(crucible -s -m IMX6UL -r 1 -b 16 -e little read SRK_HASH)
printf '%s\n' "$READBACK"
```

Stop unless the read-back value matches `FUSE_HEX` exactly. Do not try to
repair a mismatch by setting additional bits.

Lock the verified hash and read the lock back:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow SRK_LOCK 1
crucible -s -m IMX6UL -r 1 -b 2 read SRK_LOCK
```

Stop unless `SRK_LOCK` reads as `1`.

## 7. Apply the test recovery profile

This first-run profile keeps USB SDP enabled so a closed device can accept a
properly signed recovery image. It disables SDP memory reads, UART SDP, direct
reserved boot, JTAG, and trace. Keeping USB SDP permits recovery but leaves
CVE-2022-45163 in scope; production must make and document that tradeoff.

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow DIR_BT_DIS 1
crucible -m IMX6UL -r 1 -b 2 -e big blow SJC_DISABLE 1
crucible -m IMX6UL -r 1 -b 2 -e big blow JTAG_SMODE 0b11
crucible -m IMX6UL -r 1 -b 2 -e big blow JTAG_HEO 1
crucible -m IMX6UL -r 1 -b 2 -e big blow KTE 1
crucible -m IMX6UL -r 1 -b 2 -e big blow SDP_READ_DISABLE 1
crucible -m IMX6UL -r 1 -b 2 -e big blow UART_SERIAL_DOWNLOAD_DISABLE 1
```

Read each fuse back with the corresponding `crucible ... read` command and
record the output. Do not set `SDP_DISABLE` during the sacrificial test run.
Production may set it to mitigate CVE-2022-45163, but doing so permanently
removes USB SDP recovery:

```bash
# Production policy only; not part of the test profile:
# crucible -m IMX6UL -r 1 -b 2 -e big blow SDP_DISABLE 1
```

Use this read-back block and require the selected field in each result to
equal the value just written:

```bash
for fuse in DIR_BT_DIS SJC_DISABLE JTAG_SMODE JTAG_HEO KTE \
  SDP_READ_DISABLE UART_SERIAL_DOWNLOAD_DISABLE; do
  crucible -s -m IMX6UL -r 1 -b 2 read "$fuse"
done
```

## 8. Final gate and close HAB

Before running the next command, confirm all of the following:

- the signed microSD image booted twice while open;
- the archived image on the host still matches the microSD deployment;
- the fused SRK hash matched `FUSE_HEX` before `SRK_LOCK` was set;
- `SRK_LOCK` and every selected hardening fuse read back correctly;
- two verified offline key backups exist; and
- the unit is configured to boot the signed microSD on its next reset.

`SEC_CONFIG` is the point of no return:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow SEC_CONFIG 0b11
crucible -s -m IMX6UL -r 1 -b 2 read SEC_CONFIG
```

Stop unless the read-back is `0b11`. Shut down factory Linux cleanly, select
microSD boot, and power-cycle. Do not rewrite the card between closing and
this boot.

Require the closed unit to enumerate, return a healthy `/healthz`, and pass
`vitrum selftest`. A failure here ends the test; preserve the card, logs, fuse
record, and key material for diagnosis.

When booting a Linux diagnostic image on i.MX6ULZ, the `mxs_dcp` log should
report `Trusted State detected`. That confirms the closed security state; it
does not replace checking HAB events during development.

## Recovery policy

- An open device may execute an image despite HAB authentication errors. It
  can also fail to boot for ordinary image-layout or runtime defects.
- Under the test profile, a closed device may use USB SDP, but every recovery
  image must authenticate against an unrevoked fused SRK. Test this recovery
  path separately before relying on it.
- With `SDP_DISABLE=1`, there is no SDP recovery path.
- Lost private keys do not invalidate existing signed images, but prevent new
  releases. Loss of all usable signed images and signing keys is terminal.
- A wrong locked SRK hash cannot be corrected. Before closure the unit may
  still run unsigned code; after closure it cannot authenticate the intended
  images.

## SRK revocation

`habtool` indices 1-3 correspond to `SRK_REVOKE` fuse bits 0-2. SRK 4 is the
non-revocable last root. Revoke only a compromised key, only after building
and testing an image signed by a surviving SRK, and only after preserving a
known-good recovery image for that SRK.

For example, this permanently revokes `habtool` SRK index 3:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow OCOTP_SRK_REVOKE 0b100
crucible -s -m IMX6UL -r 1 -b 2 read OCOTP_SRK_REVOKE
```

Sign with another key using `make imx_signed HAB_SRK_INDEX=<1-4>`, after
creating that SRK's CSF and IMG certificates with the same ceremony used for
SRK 1.

[upstream]: https://github.com/usbarmory/usbarmory/wiki/Secure-boot-%28Mk-II%29
