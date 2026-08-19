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
- Keep the factory eMMC Linux installation bootable until HAB is closed.
  `crucible` runs there as root with `nvmem-imx-ocotp` loaded.
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

## Boot-media selection

The Mk II [slide switch][boot-modes] selects the primary boot medium. Move it
toward the eMMC package for eMMC boot and toward the microSD slot for microSD
boot. The selection controls the next boot; shut down or power off before
moving the switch except for the explicit final transition in section 8.

The ROM tries eMMC, then microSD, then USB SDP when eMMC boot is selected. It
tries microSD, then USB SDP when microSD boot is selected. MicroSD mode does
not fall back to eMMC.

This runbook uses two environments:

- factory Linux on eMMC runs the target-side `crucible` fuse tool; and
- vitrum boots directly from the microSD as a bare-metal i.MX image.

The factory Linux image is not a post-provisioning recovery environment unless
it is separately HAB-signed by a trusted SRK. Once `SEC_CONFIG` is closed, the
ROM rejects an unsigned eMMC image just as it rejects an unsigned microSD
image.

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

With the switch toward eMMC, boot factory Linux and confirm the unit is still
open before touching OTP:

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

Shut down factory Linux, power off, move the switch toward the microSD slot,
and boot vitrum. Require `/healthz` and `vitrum selftest` to pass. Power-cycle
without moving the switch and repeat. This validates the image layout and
runtime, but not HAB authentication: open HAB can continue after an
authentication failure.

For a non-sacrificial unit, make pre-close authentication a mandatory extra
gate: boot an instrumented build that calls HAB's `report_status` and
`report_event` ROM APIs, or use a UART-capable HAB diagnostic environment,
and require zero HAB failure events. The current vitrum firmware does not
expose those ROM APIs.

## 5. Prepare the fuse session

Shut down vitrum, power off, move the switch toward eMMC, and boot factory
Linux. On the protected host, recompute the expected image size and digest
from the archived artifact:

```bash
IMAGE_SIZE=$(stat -c %s out/vitrum-usbarmory-signed.imx)
IMAGE_SHA256=$(sha256sum out/vitrum-usbarmory-signed.imx | cut -d ' ' -f 1)
printf 'size=%s sha256=%s\n' "$IMAGE_SIZE" "$IMAGE_SHA256"
```

Connect to factory Linux and identify both MMC devices. If the armory Linux host
key has not already been verified in a trusted setup session, stop and establish
that trust before beginning the fuse session. Replace the address and 
known-hosts path as required:

```bash
export ARMORY_SSH=root@10.0.0.1
export ARMORY_KNOWN_HOSTS=/secure/usbarmory-factory-known_hosts
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" "$ARMORY_SSH"
```

In that root shell, find the device backing `/`, then identify the other MMC
device as the microSD. Do not assume whether it is `mmcblk0` or `mmcblk1`:

```bash
findmnt -no SOURCE /
lsblk -o NAME,PATH,SIZE,TYPE,MOUNTPOINT
export ARMORY_SD=/dev/mmcblkX
test -b "$ARMORY_SD"
case "$(findmnt -no SOURCE /)" in
  "$ARMORY_SD"*) echo "refusing root device" >&2; false ;;
esac
```

Still in the root shell, set `IMAGE_SIZE` to the decimal value printed on the
host. Hash exactly the range written in section 4, including neither the 1 KiB
prefix nor the raw state area:

```bash
IMAGE_SIZE=<decimal size printed on host>
dd if="$ARMORY_SD" bs=1 skip=1024 count="$IMAGE_SIZE" status=none |
  sha256sum
```

Stop unless this digest equals `IMAGE_SHA256` from the host. Exit the root
shell, hash the fuse file locally, create a private destination directory, and
copy it using the same pinned SSH identity:

```bash
sha256sum "$HAB_KEYS/SRK_1_2_3_4_fuse.bin"
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" "$ARMORY_SSH" \
  'install -d -m 700 /root/vitrum-hab'
scp -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" \
  "$HAB_KEYS/SRK_1_2_3_4_fuse.bin" \
  "$ARMORY_SSH:/root/vitrum-hab/"
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" "$ARMORY_SSH" \
  'sha256sum /root/vitrum-hab/SRK_1_2_3_4_fuse.bin'
```

Stop unless the local and remote fuse-file digests match. Reconnect with the
same SSH options. On the armory, as root:

```bash
cd /root/vitrum-hab
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

Factory Linux is still running from eMMC at this point. Moving the boot switch
does not replace the running image; it changes the source selected at the next
reset. Before closing HAB, move the switch toward the microSD slot and visually
confirm its position. Do not reboot yet.

Before running the next command, confirm all of the following:

- the signed microSD image booted twice while open;
- the archived image on the host still matches the microSD deployment;
- the fused SRK hash matched `FUSE_HEX` before `SRK_LOCK` was set;
- `SRK_LOCK` and every selected hardening fuse read back correctly;
- two verified offline key backups exist; and
- the switch is toward the microSD slot, so the signed microSD is selected on
  the next reset.

Unless the factory eMMC image was independently HAB-signed by one of these
SRKs, this is the last session in which it can boot. After closure, the ROM
rejects that image. Select microSD directly; do not rely on recovery or
fallback behavior after an eMMC authentication failure.

`SEC_CONFIG` is the point of no return:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow SEC_CONFIG 0b11
crucible -s -m IMX6UL -r 1 -b 2 read SEC_CONFIG
```

Stop unless the read-back is `0b11`. Shut down factory Linux cleanly and
power-cycle without moving the switch. Do not rewrite or remove the card
between closing and this boot.

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
[boot-modes]: https://github.com/usbarmory/usbarmory/wiki/Boot-Modes-%28Mk-II%29
