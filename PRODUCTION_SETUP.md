# Production setup for vitrum

This runbook takes one USB armory Mk II from factory state to a provisioned
production witness. It covers hardware validation, HAB secure boot, RPMB key
programming, witness provisioning, and final verification. The HAB procedure
follows the [USB armory Mk II secure-boot guide][upstream] and uses its
`habtool` and `crucible` conventions.

> [!WARNING]
> The eMMC RPMB authentication key can be programmed only once. It must be
> derived after HAB is closed, when the SoC exposes its unique OTPMK. A key
> programmed while HAB is open is derived from the common test key and makes
> RPMB permanently inaccessible to production vitrum.

> [!CAUTION]
> Do not improvise past a failed check. In particular, do not write
> `SRK_LOCK` or `SEC_CONFIG` unless every preceding comparison succeeds and
> the signing keys have verified offline backups.

## What becomes permanent

HAB verifies an i.MX image against a table of four RSA Super Root Keys (SRKs).
The SoC stores the SHA-256 hash of the encoded SRK table. `SEC_CONFIG=0b11`
changes HAB from open mode, which records authentication failures but may
continue booting, to closed mode, which rejects unauthenticated images.

The SRK hash, its lock, key-revocation bits, `SEC_CONFIG`, the hardening fuses
below, and the eMMC RPMB authentication key are one-time-programmable. The
device-key derivation is also a permanent compatibility contract once RPMB or
state is written: DCP `DeriveKey`, the `"vitrum-rpmb-v1"` and
`"vitrum-state-v1"` diversifiers, the SoC Unique ID salt, and
PBKDF2-HMAC-SHA256 with 4096 iterations must not change. A changed RPMB key
cannot authenticate the eMMC; a changed state key cannot decrypt the state
blob. Writing an image to microSD is destructive to that card but is not an
OTP operation.

The CSF and IMG certificates are both signed by the selected SRK CA. The CSF
key authenticates HAB commands; the IMG key authenticates the image data.

## Preconditions

- Use a standard USB armory Mk II with an i.MX6ULZ revision supported by the
  upstream guide.
- Keep the factory eMMC Linux installation bootable until HAB is closed.
  `crucible` runs there as root with `nvmem-imx-ocotp` loaded.
- Use a dedicated microSD card and identify its whole-device path exactly.
- Build from a clean, reviewed commit in `nix develop`.
- The RPMB provisioning firmware described in section 9 must pass its
  open-mode physical-hardware gate in section 4 before HAB is closed.
- Both production vitrum and the RPMB provisioner must report HAB ROM status
  and events for their own current boot. Do not begin the fuse session unless
  the section 4 checks pass for both exact signed artifacts.
- Store the HAB directory on encrypted offline-capable storage. Make two
  verified backups before locking any fuse.
- Read the entire runbook before starting. Record every command, output,
  artifact digest, device serial number, and fuse read-back.

Set these shell variables once. Replace the placeholder paths and interface;
never paste the example device path unchanged.

```bash
export HAB_KEYS=/secure/vitrum-hab-keys
export ARMORY_CARD=/dev/sdX
export ARMORY_SSH=usbarmory@10.0.0.1
export ARMORY_KNOWN_HOSTS=/secure/usbarmory-factory-known_hosts
test -b "$ARMORY_CARD"
```

### Establish the trusted factory connection

Before section 0, boot factory Linux from eMMC and connect it directly to the
protected host. Keep this USB network isolated and unbridged. Identify the
new USB network interface; do not copy the example name blindly:

```bash
export ARMORY_IF=usb0
sudo ip link set "$ARMORY_IF" up
sudo ip addr replace 10.0.0.2/24 dev "$ARMORY_IF"
ping -c 3 10.0.0.1
```

The physical, isolated connection is the trust basis for this first contact.
Create the factory Linux pin once, record its fingerprint in the ceremony
log, and verify that strict reuse works:

```bash
install -m 600 /dev/null "$ARMORY_KNOWN_HOSTS"
ssh-keyscan -H 10.0.0.1 >>"$ARMORY_KNOWN_HOSTS"
ssh-keygen -lf "$ARMORY_KNOWN_HOSTS"
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" "$ARMORY_SSH" true
```

If the protected host cannot guarantee that isolated first contact, obtain
and verify the factory host-key fingerprint through a separate trusted
channel before continuing. Do not enable forwarding or connection sharing;
neither factory Linux nor vitrum needs Internet access during the ceremony.

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

## 0. Validate the unfused hardware

Build and flash an unsigned development image:

```bash
make imx TARGET=usbarmory
sudo dd if=out/vitrum-usbarmory.imx of="$ARMORY_CARD" \
  bs=512 seek=2 conv=fsync status=progress
```

Power off, move the switch toward the microSD slot, and boot vitrum. Check
`http://10.0.0.1/healthz`. Require `target=usbarmory`, `snvs_secure=false`,
`dev=true`, `hab.config=open`, and `hab.state=nonsecure`. An unsigned image is
not authenticated even while HAB is open, so require `hab.status=failure`,
`hab.failures=5`, and exactly five failure events:

- one `HAB_INV_CSF` event in `HAB_CTX_CSF`, whose raw record is
  `db0008423311cf00`;
- four `HAB_INV_ASSERTION` events in `HAB_CTX_ASSERT`, whose raw records begin
  with `db001442330ca000`.

The remaining assertion-event bytes identify image regions and therefore
depend on the exact image layout. Record the complete `hab` object as the
unsigned control for the ROM-reporting path. Any different count, status,
reason, or context is a stop condition. An unprogrammed RPMB causes storage to
degrade to RAM-only.

Check `/logz`. Require the device-key warning and the SSH host-key source to
be marked DEV, and require the RPMB probe failure to contain exactly
`result 0x7` (authentication key not yet programmed). Any other RPMB error is
a transport or protocol failure that must be resolved before fusing.

Smoke-test provisioning and checkpoint submission using a throwaway directory
so no key or pin from unsigned firmware can become the production identity:

```bash
DEV_KEYS=$(mktemp -d)
go run ./cmd/vitrum keygen \
  -seed "$DEV_KEYS/witness.seed" -vkey "$DEV_KEYS/witness.vkey"
go run ./cmd/vitrum provision -tofu \
  -seed "$DEV_KEYS/witness.seed" -hostkey "$DEV_KEYS/ssh_host.pub"
go run ./cmd/vitrum selftest -witness http://10.0.0.1
rm -rf "$DEV_KEYS"
unset DEV_KEYS
```

Confirm that `keys/witness.seed` and `keys/ssh_host.pub` were not created by
this DEV-phase test.

Power-cycle without moving the switch and repeat `/healthz` and `/logz`.
Require the complete `hab` object to match the first boot of the same image.

Power off and move the switch toward eMMC before continuing.

## 1. Install the pinned host tool

The Makefile pins Crucible so later upstream changes cannot silently alter the
certificate or CSF format.

```bash
go tool github.com/usbarmory/tamago/cmd/tamago install \
  github.com/usbarmory/crucible/cmd/habtool@v0.0.0-20260105222051-0bd71c72232c
export PATH="$(go tool github.com/usbarmory/tamago/cmd/tamago env GOPATH)/bin:$PATH"
habtool -h
```

Cross-compile the same pinned Crucible revision for the armory's 32-bit ARM
factory Linux. Do not use an unqualified `go install`, which builds for the
host by default:

```bash
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go install \
  github.com/usbarmory/crucible/cmd/crucible@v0.0.0-20260105222051-0bd71c72232c
CRUCIBLE_ARM="$(go env GOPATH)/bin/linux_arm/crucible"
test -x "$CRUCIBLE_ARM"
file "$CRUCIBLE_ARM"
sha256sum "$CRUCIBLE_ARM"
```

Require `file` to identify a 32-bit ARM Linux executable. Using the factory
Linux SSH identity established before section 0, copy the binary to a
temporary path, compare its digest, then install it as root:

```bash
scp -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" \
  "$CRUCIBLE_ARM" "$ARMORY_SSH:/tmp/crucible-pinned"
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" "$ARMORY_SSH" \
  'sha256sum /tmp/crucible-pinned'
```

Stop unless the remote digest matches the host digest. Then install it and
require the embedded fuse-map list to include `IMX6UL`:

```bash
ssh -o StrictHostKeyChecking=yes \
  -o UserKnownHostsFile="$ARMORY_KNOWN_HOSTS" "$ARMORY_SSH" \
  'sudo install -m 0755 /tmp/crucible-pinned /usr/local/sbin/crucible && \
   sudo /usr/local/sbin/crucible -l'
```

Record the binary digest with the ceremony log.

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

## 3. Build, sign, and inspect the images

Two signed images are required:

- the normal production vitrum image; and
- a minimal RPMB provisioning image used exactly once after HAB closure.

Do not substitute normal vitrum for the dedicated provisioner: on a closed
unit normal vitrum deliberately fails before starting the network when RPMB is
unprogrammed.

Require a clean tree, record its revision, and reproduce each unsigned image
before signing it:

```bash
test -z "$(git status --porcelain)"
SOURCE_REVISION=$(git rev-parse HEAD)
make repro TARGET=usbarmory
make repro APP=vitrum-rpmb-provision FWPKG=./fw/rpmb-provision \
  TARGET=usbarmory
```

The signed targets run the pinned `tamago install habtool@...` command on every
invocation. Go 1.26 performs a module deprecation lookup even when the module
is already cached, so `GOPROXY=off` rejects this command. Point the Go command
at the warm local download cache with no fallback and disable remote checksum
lookups. Stop if either offline build fails:

```bash
TAMAGO_BIN=$(go tool -n github.com/usbarmory/tamago/cmd/tamago)
MODCACHE=$("$TAMAGO_BIN" env GOMODCACHE)
LOCAL_GOPROXY="file://$MODCACHE/cache/download"
test -d "$MODCACHE/cache/download"
```

Build the production image:

```bash
GOSUMDB=off GOPROXY="$LOCAL_GOPROXY" \
  make imx_signed TARGET=usbarmory \
  HAB_KEYS="$HAB_KEYS" HAB_SRK_INDEX=1

test -s out/vitrum-usbarmory.imx
test -s out/vitrum-usbarmory.csf
test -s out/vitrum-usbarmory-signed.imx
test "$(stat -c %s out/vitrum-usbarmory-signed.imx)" -eq \
     "$(( $(stat -c %s out/vitrum-usbarmory.imx) + $(stat -c %s out/vitrum-usbarmory.csf) ))"
sha256sum out/vitrum-usbarmory.imx out/vitrum-usbarmory.csf \
  out/vitrum-usbarmory-signed.imx
```

Build and inspect the one-off provisioner with the same keys and SRK index:

```bash
GOSUMDB=off GOPROXY="$LOCAL_GOPROXY" \
  make rpmb_provision_signed \
  HAB_KEYS="$HAB_KEYS" HAB_SRK_INDEX=1

test -s out/vitrum-rpmb-provision-usbarmory.imx
test -s out/vitrum-rpmb-provision-usbarmory.csf
test -s out/vitrum-rpmb-provision-usbarmory-signed.imx
RPMB_IMX_SIZE=$(stat -c %s out/vitrum-rpmb-provision-usbarmory.imx)
RPMB_CSF_SIZE=$(stat -c %s out/vitrum-rpmb-provision-usbarmory.csf)
test "$(stat -c %s out/vitrum-rpmb-provision-usbarmory-signed.imx)" -eq \
  "$((RPMB_IMX_SIZE + RPMB_CSF_SIZE))"
sha256sum out/vitrum-rpmb-provision-usbarmory.imx \
  out/vitrum-rpmb-provision-usbarmory.csf \
  out/vitrum-rpmb-provision-usbarmory-signed.imx
```

Open-mode HAB does not prove that the SRK table inside a CSF matches the
fused-hash input. Regenerate both public artifacts offline from the four SRK
certificates and compare them byte-for-byte with the stored copies:

```bash
HAB_CHECK=$(mktemp -d)
trap 'rm -rf "$HAB_CHECK"' EXIT
habtool \
  -1 "$HAB_KEYS/SRK_1_crt.pem" \
  -2 "$HAB_KEYS/SRK_2_crt.pem" \
  -3 "$HAB_KEYS/SRK_3_crt.pem" \
  -4 "$HAB_KEYS/SRK_4_crt.pem" \
  -t "$HAB_CHECK/SRK_1_2_3_4_table.bin" \
  -o "$HAB_CHECK/SRK_1_2_3_4_fuse.bin"
cmp "$HAB_CHECK/SRK_1_2_3_4_table.bin" \
  "$HAB_KEYS/SRK_1_2_3_4_table.bin"
cmp "$HAB_CHECK/SRK_1_2_3_4_fuse.bin" \
  "$HAB_KEYS/SRK_1_2_3_4_fuse.bin"
```

Crucible places the SRK table at the byte offset stored in the CSF header's
big-endian length field. Extract that exact range from both CSFs and compare
it with the verified table:

```bash
TABLE="$HAB_KEYS/SRK_1_2_3_4_table.bin"
TABLE_SIZE=$(stat -c %s "$TABLE")
for CSF in out/vitrum-usbarmory.csf \
  out/vitrum-rpmb-provision-usbarmory.csf; do
  read -r CSF_HI CSF_LO < <(od -An -tu1 -j1 -N2 "$CSF")
  TABLE_OFFSET=$((CSF_HI * 256 + CSF_LO))
  dd if="$CSF" bs=64K iflag=skip_bytes,count_bytes \
    skip="$TABLE_OFFSET" count="$TABLE_SIZE" status=none |
    cmp - "$TABLE"
done
rm -rf "$HAB_CHECK"
trap - EXIT
```

Archive both signed images, their component digests, the source commit, the
Crucible revision, and the key manifest together. Require `SOURCE_REVISION` to
equal the archived commit.

## 4. Boot the signed image while HAB is open

With the switch toward eMMC, boot factory Linux and confirm the unit is still
open before touching OTP:

```bash
SEC_CONFIG=$(crucible -s -m IMX6UL -r 1 -b 2 read SEC_CONFIG)
printf '%s\n' "$SEC_CONFIG"
case "$SEC_CONFIG" in
  00|01) ;;
  *) echo "SEC_CONFIG closed bit is already set" >&2; false ;;
esac
```

`SEC_CONFIG` is two bits: `00` is FAB, `01` is Open, and `1x` is Closed. A
shipped Mk II is expected to print `01`, but verify the actual unit rather
than assuming its factory value. The gate is that the closed bit is clear;
the later vitrum boot must independently report `hab.config=open`.

Read and record the rest of the expected factory state:

```bash
crucible -s -m IMX6UL -r 1 -b 16 -e little read SRK_HASH
crucible -s -m IMX6UL -r 1 -b 2 read SRK_LOCK
crucible -s -m IMX6UL -r 1 -b 2 read OCOTP_SRK_REVOKE
for fuse in DIR_BT_DIS SJC_DISABLE JTAG_SMODE JTAG_HEO KTE \
  SDP_DISABLE SDP_READ_DISABLE UART_SERIAL_DOWNLOAD_DISABLE BT_FUSE_SEL; do
  crucible -s -m IMX6UL -r 1 -b 2 read "$fuse"
done
```

| Field | Expected quiet output |
|---|---|
| `SRK_HASH` | 64 zeroes |
| `SRK_LOCK` | `0` |
| `SEC_CONFIG` | normally `01`; only `00` or `01` is admissible |
| `OCOTP_SRK_REVOKE` | 32 zeroes |
| `JTAG_SMODE` | `00` |
| `UART_SERIAL_DOWNLOAD_DISABLE` | normally `0`; a documented factory workaround may make `1` admissible |
| every other listed hardening fuse | `0` |
| `BT_FUSE_SEL` | `0` |

If `UART_SERIAL_DOWNLOAD_DISABLE` is already `1`, require the factory record
to identify it as the known USB armory workaround and record that exception;
do not attempt to clear or reprogram it. Stop if any other field differs.
Then flash the signed image:

```bash
sudo dd if=out/vitrum-usbarmory-signed.imx of="$ARMORY_CARD" \
  bs=512 seek=2 conv=fsync status=progress
sync
```

Read back exactly the flashed byte range and compare its digest with the
archived image:

```bash
IMAGE_SIZE=$(stat -c %s out/vitrum-usbarmory-signed.imx)
sudo dd if="$ARMORY_CARD" bs=4M iflag=skip_bytes,count_bytes \
  skip=1024 count="$IMAGE_SIZE" status=none \
  | sha256sum
sha256sum out/vitrum-usbarmory-signed.imx
```

Shut down factory Linux, power off, move the switch toward the microSD slot,
and boot vitrum. Require `/healthz`, the firmware's HAB report, and the
throwaway provisioning and `selftest` procedure from section 0 to pass.
`/healthz` must report `revision=SOURCE_REVISION`, `snvs_secure=false`,
`dev=true`, `hab.config=open`, and `hab.state=nonsecure`. The HAB report must
identify a successful current boot and contain zero failure events, replacing
the five-event unsigned control from section 0.
Power-cycle without moving the switch and repeat all three checks against the
same installed artifact, again keeping its keys and pin outside `keys/`.

This open-mode result is necessary but weak: HAB does not establish that the
CSF's SRK table hashes to the fuse file while the device is open. The offline
table/fuse/CSF comparisons in section 3 are the pre-close gate for that
relationship.

Also boot the exact signed RPMB provisioning artifact while HAB is open. Its
own HAB report must identify a successful current boot with zero failure
events and report `config=open`, `state=nonsecure`. Require
`revision=SOURCE_REVISION`, `snvs_secure=false`,
`unprogrammed_before=true`, and `probe="unprogrammed (result 0x7)"`. It must
refuse to program RPMB. This exercises `rpmb.Init` and the unauthenticated
counter read on the real eMMC before closure. Power off, restore the archived
signed production image with the same bounded flash and read-back procedure,
and boot it again. Verify that it still reports result `0x7` in `/logz` and
RAM-only storage.

An instrumented substitute does not satisfy these gates: different image
bytes can have different HAB layout or signing failures. Normal vitrum reports
the ROM status and raw events in the `hab` object returned by `/healthz`. The
provisioner returns the same object from `/healthz` and `/status`.

## 5. Prepare the fuse session

Shut down vitrum, power off, move the switch toward eMMC, and boot factory
Linux. On the protected host, recompute the expected image size and digest
from the archived artifact:

```bash
IMAGE_SIZE=$(stat -c %s out/vitrum-usbarmory-signed.imx)
IMAGE_SHA256=$(sha256sum out/vitrum-usbarmory-signed.imx | cut -d ' ' -f 1)
printf 'size=%s sha256=%s\n' "$IMAGE_SIZE" "$IMAGE_SHA256"
```

Connect to factory Linux using the pin established before section 0 and
identify both MMC devices:

```bash
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
dd if="$ARMORY_SD" bs=4M iflag=skip_bytes,count_bytes \
  skip=1024 count="$IMAGE_SIZE" status=none |
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
encoding. Every `blow` command in this runbook prompts for literal uppercase
`YES`. Read the displayed fuse name and value before answering. Do not use
`-Y` to suppress this gate.

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

## 7. Apply the production hardening profile

This ceremony is running on the sole production unit, so there is no separate
sacrificial profile. The supported recovery path is a removable microSD card
reflashed on a host with any known-good image signed by an unrevoked SRK.

The archived media-boot images are not SDP recovery images. `habtool -s`
clears the IVT DCD pointer and adds separate authentication for the DCD at its
OCRAM address; this repository neither builds nor tests that artifact. Disable
SDP in production to mitigate CVE-2022-45163, along with memory reads, UART
SDP, direct reserved boot, JTAG, and trace:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow DIR_BT_DIS 1
crucible -m IMX6UL -r 1 -b 2 -e big blow SJC_DISABLE 1
crucible -m IMX6UL -r 1 -b 2 -e big blow JTAG_SMODE 0b11
crucible -m IMX6UL -r 1 -b 2 -e big blow JTAG_HEO 1
crucible -m IMX6UL -r 1 -b 2 -e big blow KTE 1
crucible -m IMX6UL -r 1 -b 2 -e big blow SDP_DISABLE 1
crucible -m IMX6UL -r 1 -b 2 -e big blow SDP_READ_DISABLE 1
if test "$(crucible -s -m IMX6UL -r 1 -b 2 \
  read UART_SERIAL_DOWNLOAD_DISABLE)" = 0; then
  crucible -m IMX6UL -r 1 -b 2 -e big \
    blow UART_SERIAL_DOWNLOAD_DISABLE 1
fi
```

Read each fuse back with the corresponding `crucible ... read` command and
record the output. `SDP_DISABLE=1` permanently removes USB SDP recovery. Use
this read-back block and require `JTAG_SMODE` to print `11` and every other
field to print `1`:

```bash
for fuse in DIR_BT_DIS SJC_DISABLE JTAG_SMODE JTAG_HEO KTE \
  SDP_DISABLE SDP_READ_DISABLE UART_SERIAL_DOWNLOAD_DISABLE; do
  crucible -s -m IMX6UL -r 1 -b 2 read "$fuse"
done
```

## 8. Final gate and close HAB

Factory Linux is still running from eMMC at this point. Shut it down cleanly
without writing `SEC_CONFIG`, power off, remove the microSD, and move it to the
protected host's card reader. Replace its boot image with the archived signed
RPMB provisioning image:

```bash
RPMB_IMAGE=out/vitrum-rpmb-provision-usbarmory-signed.imx
test -s "$RPMB_IMAGE"
RPMB_IMAGE_SIZE=$(stat -c %s "$RPMB_IMAGE")
RPMB_IMAGE_SHA256=$(sha256sum "$RPMB_IMAGE" | cut -d ' ' -f 1)
test "$RPMB_IMAGE_SIZE" -lt 16777216
printf 'size=%s sha256=%s\n' "$RPMB_IMAGE_SIZE" "$RPMB_IMAGE_SHA256"
sudo dd if="$RPMB_IMAGE" of="$ARMORY_CARD" \
  bs=512 seek=2 conv=fsync status=progress
sync
```

Read back exactly the provisioner image range and compare it with the archived
artifact:

```bash
sudo dd if="$ARMORY_CARD" bs=4M iflag=skip_bytes,count_bytes \
  skip=1024 count="$RPMB_IMAGE_SIZE" \
  status=none | sha256sum
printf '%s  %s\n' "$RPMB_IMAGE_SHA256" "$RPMB_IMAGE"
```

Stop unless the two digests match.

Reinsert the microSD, leave the switch toward eMMC, and boot factory Linux.
Repeat every fuse read-back required by sections 6 and 7. In the root shell,
identify the microSD again as in section 5; do not reuse an earlier device-name
assumption. Set `ARMORY_SD` to that verified whole-device path and
`RPMB_IMAGE_SIZE` to the decimal size printed by the host, then hash the exact
installed range:

```bash
export ARMORY_SD=/dev/mmcblkX
RPMB_IMAGE_SIZE=<decimal size printed on host>
test -b "$ARMORY_SD"
dd if="$ARMORY_SD" bs=4M iflag=skip_bytes,count_bytes \
  skip=1024 count="$RPMB_IMAGE_SIZE" status=none |
  sha256sum
```

Stop unless this digest equals `RPMB_IMAGE_SHA256` recorded on the host.

Factory Linux is running from eMMC. Moving the boot switch does not replace
the running image; it changes the source selected at the next reset. Move the
switch toward the microSD slot and visually confirm its position. Do not reboot
yet.

Before running the next command, confirm all of the following:

- the exact signed production image booted twice while open and reported a
  successful HAB boot with zero failure events each time;
- the exact signed RPMB provisioning image reported a successful HAB boot
  with zero failure events, but refused RPMB programming while HAB was open;
- the regenerated SRK table and fuse file matched their stored copies, and
  the table matched the exact bytes embedded in both CSFs;
- the archived signed RPMB provisioning image matches the microSD deployment;
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

Stop unless the read-back is exactly `11`. Shut down factory Linux cleanly and
power-cycle without moving the switch. Do not rewrite or remove the card
between closing and this boot.

The next image is the RPMB provisioner, not normal vitrum. Continue directly
to section 9. A boot or status failure before RPMB programming does not undo
the fuses, but it is recoverable by diagnosing the event and reflashing a
corrected, signed microSD image. Preserve the card, logs, fuse record, and key
material; never respond by attempting another fuse value.

## 9. Program the RPMB authentication key

Crucible cannot perform this step. It manages SoC OTP fuses, while RPMB is a
special eMMC partition using authenticated JEDEC request frames. Factory Linux
also cannot provide the key before closure: until a cold boot after
`SEC_CONFIG` is set, the unique OTPMK is unavailable.

The signed provisioning firmware must:

1. detect the internal eMMC and perform the read-only RPMB probe before any
   HAB or SNVS refusal;
2. distinguish result `0x7` (unprogrammed) from a transport or protocol error;
3. when already programmed, authenticate a counter with the derived key and
   report matching, foreign, or inconclusive without writing;
4. require `imx6ul.SNVS.Available()` to report Trusted or Secure state before
   programming;
5. derive `K_rpmb` with the production `Derive("vitrum-rpmb-v1")` path;
6. call `RPMB.ProgramKey()` only when RPMB is conclusively unprogrammed;
7. immediately verify an authenticated counter read with the derived key;
8. never expose the derived key; and
9. report an unambiguous success or failure through the available network and
   LED interfaces, then halt.

Booting this narrowly scoped image, authenticated by HAB, is the operator's
authorization for the irreversible write. It must not expose RPMB programming
through normal vitrum's network API.

Record the provisioner's status and require all of the following before
continuing:

- `revision` equals `SOURCE_REVISION`;
- HAB reports `status=success`, `config=closed`, `state=trusted`, and zero
  failure events;
- SNVS reported Trusted or Secure state;
- RPMB was conclusively unprogrammed before the write;
- key programming reported success; and
- an authenticated counter read with the same derived key succeeded.

Fetch the machine-readable result from the directly connected host:

```bash
curl --fail --show-error http://10.0.0.1/status
```

Require `success`, `snvs_secure`, `unprogrammed_before`, `key_programmed`, and
`authenticated_counter` all to be `true`. Both LEDs remain solid on success;
alternating blue and white indicates refusal or failure. `/logz` contains the
corresponding diagnostic without key material.

Failures before `key_programmed=true` are recoverable without another
one-shot write. Preserve the status and HAB events, correct the firmware or
signature, reflash the microSD on the host, and boot the signed provisioner
again. In particular, `status=warning` is a refusal: investigate the raw HAB
event and produce a clean signed image; do not weaken the gate.

The TamaGo v1.26.6 uSDHC driver cannot issue an RPMB reliable write without
the local reliable-write correction. Its uncorrected pre-write failure is
`transfer size cannot exceed 65535 blocks`. If that exact error occurs with
`key_programmed=false`, preserve the powered state, build and sign a new
committed revision containing the correction, archive both new signed images,
then power off only to reflash the corrected provisioner. Do not retry the
unchanged image.

Once `key_programmed=true`, never retry programming. If the immediate
authenticated read failed, power-cycle the unchanged provisioner for its
read-only diagnostic. `programmed_before=true`, `derived_key_matches=true`,
and `authenticated_counter=true` proves that RPMB contains this unit's
derived key and permits continuing. `foreign_key=true`, or an inconclusive
diagnostic that persists, is terminal because the one-time key cannot be
replaced. Do not boot normal vitrum merely to probe an uncertain outcome.
After a verified success, treat the provisioner as a ceremony-only artifact:
restore production vitrum immediately and do not boot the provisioner during
normal operation.

## 10. Install and boot production vitrum

Power off and remove the microSD. On the protected host, restore the archived
signed production image using the bounded flash and read-back procedure from
section 4. This overwrites only the boot-image range beginning at 1 KiB;
it must not touch the raw state slots beginning at 16 MiB.

Reinsert the card, keep the switch toward the microSD slot, and power on.
Require the unit to enumerate and `/healthz` to show:

- `target=usbarmory`;
- `revision=SOURCE_REVISION`;
- `snvs_secure=true` and `dev=false`;
- `hab.status=success`, `hab.config=closed`, `hab.state=trusted`, and zero HAB
  failure events;
- RPMB-backed persistence;
- generation zero with fresh microSD state.

The SSH host identity is different from the pre-close DEV identity because it
is now derived from the unique OTPMK.

## 11. Pin the production SSH identity

Choose the permanent public witness name before generating its key. Use a
stable name controlled by the operator; the built-in
`vitrum-UNSAFE-test-key.invalid` default is forbidden in production. Set the
same name for every future provisioning command:

```bash
export WITNESS_NAME=witness.example.com
case "$WITNESS_NAME" in
  ""|vitrum-UNSAFE-test-key.invalid)
    echo "invalid production witness name" >&2
    false
    ;;
esac
```

Do not overwrite or silently reuse old development keys. Fail closed if any
default or legacy identity path already exists; quarantine and identify stale
material before restarting this gate:

```bash
test ! -e keys/witness.seed && \
  test ! -e keys/witness.vkey && \
  test ! -e keys/ssh_host.pub && \
  test ! -e keys/armory_host.pub && \
  echo "production identity paths are unused: OK"
```

Generate the production identity and require the public verifier to begin
with the selected name:

```bash
go run ./cmd/vitrum keygen -name "$WITNESS_NAME"
test "$(stat -c %a keys/witness.seed)" = 600
case "$(cat keys/witness.vkey)" in
  "$WITNESS_NAME"+*) ;;
  *) echo "witness verifier has the wrong name" >&2; false ;;
esac
```

The first production boot logs the HUK-derived SSH fingerprint. Scan the
offered key over the isolated link and stop unless its fingerprint exactly
matches that trusted boot log:

```bash
SSH_SCAN=$(mktemp)
trap 'rm -f "$SSH_SCAN"' EXIT
ssh-keyscan -T 5 -t ed25519 10.0.0.1 >"$SSH_SCAN" 2>/dev/null
ssh-keygen -lf "$SSH_SCAN"
```

Pair once, passing the permanent witness name explicitly:

```bash
go run ./cmd/vitrum provision -tofu -name "$WITNESS_NAME"
ssh-keygen -lf keys/ssh_host.pub
```

Require the saved SSH fingerprint to match the pre-pairing scan and the
provisioning output to reproduce `keys/witness.vkey`. The command pins the
production SSH identity, sets the clock, and uploads the witness seed.

Before any cold boot, store `witness.seed`, `witness.vkey`, and
`ssh_host.pub` together in a mode-0700 directory on encrypted storage. Create
and verify a SHA-256 manifest, then independently verify two offline backups.
The seed is the witness private key and is required after every cold boot.

## 12. Provision and verify the witness

Verify the newly provisioned witness:

```bash
go run ./cmd/vitrum selftest -witness http://10.0.0.1
```

Require `/healthz` to show `provisioned=true`, `revision=SOURCE_REVISION`,
`snvs_secure=true`, `dev=false`, closed/trusted HAB, RPMB persistence, a sane
time, a generation greater than zero, and a running sequencer with zero failed
batches.

Do not rerun `selftest` after a reboot: it deliberately begins with a fresh
synthetic-log submission. Instead, submit a live checkpoint and record the
generation and complete `logs` map:

```bash
go run ./cmd/vitrum feed -log-name keyserver \
  -witness http://10.0.0.1
curl -fsS http://10.0.0.1/healthz > production-pre-reboot.json
jq '{generation,logs,persistence,provisioned,witness_key,hab,snvs_secure,halted}' \
  production-pre-reboot.json
```

Perform a real cold boot: remove every power source, require both LEDs to go
dark, and reconnect the same card without moving the microSD switch. Before
reprovisioning, require low uptime, `provisioned=false`, an empty
`witness_key`, and the exact pre-reboot generation and log sizes. `/logz` must
report restoration of that generation from the RPMB-backed state.

Reprovision through the existing pin without `-tofu`, then resubmit the same
live log:

```bash
go run ./cmd/vitrum provision -name "$WITNESS_NAME"
go run ./cmd/vitrum feed -log-name keyserver \
  -witness http://10.0.0.1
```

The feed must report the size already held by the witness, construct a
consistency proof if the live log grew, and return a verified cosignature.
Require the final health report to retain closed/trusted HAB, secure SNVS,
RPMB persistence, the named witness key, monotonic generation, and zero failed
batches. Archive the pre- and post-reboot reports and refresh both encrypted
backups before declaring the ceremony complete.

## Halt state

Blue and white blinking together means the store refused to advance because
of rollback or tamper evidence at boot, or a failed commit. There is no reset
command on a network surface. If the cause was a card mix-up, restore the
correct card and reboot. Poisoned, lost, or exhausted state requires custom
maintenance or replacement hardware.

## Host-side policy

The device trusts the directly connected host for everything except split
views described in [SECURITY.md](SECURITY.md):

- never bridge or forward the armory network; reachability is the privilege
  boundary and permits denial of service; and
- checkpoint submitters must verify log signatures before submission.

## LED reference

| Pattern | Meaning |
|---|---|
| blue blinking | up, unprovisioned (submissions get 503) |
| blue solid | provisioned and serving |
| white pulse | one or more checkpoints were cosigned |
| blue + white together | store halted (rollback/tamper) |
| blue/white alternating | fatal error |

## Recovery policy

- An open device may execute an image despite HAB authentication errors. It
  can also fail to boot for ordinary image-layout or runtime defects.
- The production profile sets `SDP_DISABLE=1`; there is no USB SDP recovery
  path, and the archived media-boot images were not signed for SDP.
- The primary recovery path is the removable microSD. Reflash it on a host
  with a known-good image signed by an unrevoked fused SRK. Preserve at least
  one such image with the offline key backups.
- Lost private keys do not invalidate existing signed images, but prevent new
  releases. Loss of all usable signed images and signing keys is terminal.
- A wrong locked SRK hash cannot be corrected. Before closure the unit may
  still run unsigned code; after closure it cannot authenticate the intended
  images.

The upstream `mxs_dcp: Trusted State detected` check applies only when booting
a HAB-signed Linux diagnostic image. The unsigned factory Linux image cannot
boot after closure, so its pre-close log cannot establish the production
state. Prefer vitrum's closed/trusted HAB and SNVS reports unless a separately
signed Linux image has been prepared and verified.

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
