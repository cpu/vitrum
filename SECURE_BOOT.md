# HAB secure boot for vitrum (i.MX6ULZ)

> [!WARNING]
> Not yet tested end-to-end w/ physical hardware.
>

> [!CAUTION]
> Every step that burns a fuse, programs an SRK hash, activates HAB 
> (`SEC_CONFIG`), or flashes a `*-signed.imx` is a one-way, irreversible 
> operation.

## Background

High Assurance Boot (HAB) is the i.MX6 boot ROM's signature check. With our
SRK (Super Root Key) table hash burned into fuses and `SEC_CONFIG` closed, the
ROM refuses to boot any image not signed by one of the four SRKs.

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
- **`crucible`** (same repo): reads/writes OTP fuses via the Linux NVMEM
  framework (`nvmem-imx-ocotp`). It runs *on* the armory itself (as root).
- **`mkimage`** (`ubootTools`, already in the devShell): builds the base
  `.imx`; the signing step wraps its output.

## Step 1: SRK key ceremony

Generate the root of trust for every future image.

```bash
export HAB_KEYS=/secure/vitrum-hab-keys
mkdir -p "$HAB_KEYS" && chmod 700 "$HAB_KEYS"

# Four SRK CA key/cert pairs (the roots).
for i in 1 2 3 4; do
  habtool -C "$HAB_KEYS/SRK_${i}_key.pem" -c "$HAB_KEYS/SRK_${i}_crt.pem"
done

# One CSF and one IMG key/cert pair (per active SRK; here SRK index 1).
habtool -C "$HAB_KEYS/CSF_1_key.pem" -c "$HAB_KEYS/CSF_1_crt.pem"
habtool -C "$HAB_KEYS/IMG_1_key.pem" -c "$HAB_KEYS/IMG_1_crt.pem"
```

Generate the SRK table (consumed at signing time) and the SRK hash fuse
table (the 256-bit value that goes into fuses):

```bash
habtool \
  -1 "$HAB_KEYS/SRK_1_crt.pem" -2 "$HAB_KEYS/SRK_2_crt.pem" \
  -3 "$HAB_KEYS/SRK_3_crt.pem" -4 "$HAB_KEYS/SRK_4_crt.pem" \
  -t "$HAB_KEYS/SRK_1_2_3_4_table.bin" \
  -o "$HAB_KEYS/SRK_1_2_3_4_fuse.bin"
```

- `-t`: SRK table (needed by `make imx_signed`).
- `-o`: the SHA-256 fuse image

Four separate keys exist so up to three can be revoked if compromised.
Losing all four with `SEC_CONFIG` closed means no future image can ever be
signed and the unit is permanently stuck on its last image.

## Step 2: Sign an image

```bash
make imx_signed TARGET=usbarmory HAB_KEYS=$HAB_KEYS
# → out/vitrum-usbarmory-signed.imx   (base .imx + CSF; NOT flashed, NOT fused)
```

## Step 3: Burn the SRK hash and close the device

Burn the SRK hash (fuse bank 3, words 0–7, 256-bit, little-endian), then
read it back:

```bash
crucible -m IMX6UL -r 1 -b 16 -e little blow SRK_HASH <64-hex-chars-of-SRK_1_2_3_4_fuse.bin>
crucible -s -m IMX6UL -r 1 -b 16 -e little read SRK_HASH   # verify before proceeding
```

Optionally set SRK_LOCK (recommended on production units to prevent the SRK
hash from being altered / the unit bricked):

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow SRK_LOCK 1
crucible -s -m IMX6UL -r 1 -b 2 read SRK_LOCK
```

Optionally blow the debug/trace hardening fuses the
[upstream Mk II secure boot guide](https://github.com/usbarmory/usbarmory/wiki/Secure-boot-(Mk-II))
recommends alongside HAB activation:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow DIR_BT_DIS 1    # disable direct (unauthenticated) boot modes
crucible -m IMX6UL -r 1 -b 2 -e big blow SJC_DISABLE 1   # disable the Secure JTAG Controller
crucible -m IMX6UL -r 1 -b 2 -e big blow JTAG_SMODE 0b11 # JTAG security mode: no debug
crucible -m IMX6UL -r 1 -b 2 -e big blow JTAG_HEO 1      # disable HAB JTAG enable override
crucible -m IMX6UL -r 1 -b 2 -e big blow KTE 1           # kill trace
```

Finally, close `SEC_CONFIG` (`OCOTP_CFG5`, bank 0 word 6, bits 1:0;
`SEC_CONFIG[1]` is the enforcement bit). This is the point of no return. 
From the next reset the ROM only boots images signed by the fused SRKs:

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow SEC_CONFIG 0b11
crucible -s -m IMX6UL -r 1 -b 2 read SEC_CONFIG   # expect 0b11
```

After closing, flash `out/vitrum-usbarmory-signed.imx`, continuing with
[HARDWARE_SETUP.md](HARDWARE_SETUP.md).

## SRK revocation

Four SRKs exist but only indices 0–2 (the first three) are individually
revocable via the `OCOTP_SRK_REVOKE` fuses. The fourth cannot be revoked, 
it is the last-resort root. Revoke a compromised SRK by setting its bit

```bash
crucible -m IMX6UL -r 1 -b 2 -e big blow OCOTP_SRK_REVOKE 0b100
```

Then re-sign future images with a surviving SRK index 
(`make imx_signed HAB_SRK_INDEX=<n>`).

## Recovery & bricking notes

- **Open unit, bad signed image:** boots anyway (HAB open), no risk. Recover
  by pulling the card (factory eMMC boots) or SDP.
- **Closed unit, no valid signed image on the card:** the ROM refuses the card
  and falls back to SDP (serial download); you can still load a *signed*
  recovery image into RAM. An *unsigned* recovery payload will be refused.
- **Closed unit, all SRKs revoked or lost:** unrecoverable. This is why the
  4th SRK is non-revocable and why offline key backups matter.
- **SRK_LOCK set with a wrong SRK hash:** unrecoverable. Always read back the
  SRK hash before locking or closing.
