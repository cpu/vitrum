# Firmware build based on usbarmory/tamago-example.

SHELL := $(shell command -v bash)

APP := vitrum
TARGET ?= usbarmory
OUT ?= out
TEXT_START := 0x80010000 # ramStart (mem.go in tamago soc/nxp/imx6ul) + 0x10000
GOOSPKG ?= github.com/usbarmory/tamago
TAMAGO ?= $(shell go tool -n github.com/usbarmory/tamago/cmd/tamago)
REVISION ?= $(shell git rev-parse HEAD 2>/dev/null || echo unknown)

# Persistence slots live at a 16 MiB offset on the microSD.
# The boot image (written at 1 KiB) must never grow into them.
IMAGE_SIZE_LIMIT := 16777216

ifeq ($(TARGET),usbarmory)
UART1 := null
UART2 := stdio
else ifeq ($(TARGET),mx6ullevk)
UART1 := stdio
UART2 := null
# Rootless user-mode networking: the witness answers on 127.0.0.1:8080,
# SSH provisioning on 127.0.0.1:2222. Override NET for tap networking.
NET ?= nic,model=imx.enet,netdev=net0 -netdev user,id=net0,net=10.0.0.0/24,host=10.0.0.2,hostfwd=tcp:127.0.0.1:8080-10.0.0.1:80,hostfwd=tcp:127.0.0.1:2222-10.0.0.1:22
# Only the emulated target embeds a build-time host key seed; hardware
# derives its host key from the HUK.
HOSTSEED := fw/ssh_host.seed
else
$(error invalid TARGET "$(TARGET)" - options are: usbarmory, mx6ullevk)
endif

ELF := $(OUT)/$(APP)-$(TARGET)

GOENV := GOOS=tamago GOOSPKG=$(GOOSPKG) GOARM=7 GOARCH=arm
# Build tags:
#   $(TARGET) - selects the fw/target_*.go file (usbarmory | mx6ullevk)
#   gvisor    - selects the gvisor network stack
#   native    - tamago runtime for real hardware; swapped to
#               semihosting under `make qemu` (maps time/exit hooks to
#               QEMU semihosting calls)
#
# -trimpath & -buildvcs=false make the built image reproducible, only depending
#  on source + toolchain
#
# NOTE: we do NOT set `linkramsize`. Setting it disables the board's
# default ramSize (mx6ullevk/mem.go, usbarmory/mk2/mem.go) and requires
# the app to define its own `//go:linkname ramSize` variable. That's
# useful once we need a DMA reservation; until then the board defaults
# (512MB) are what we want.
GOFLAGS := -tags $(TARGET),gvisor,native -trimpath -buildvcs=false \
           -ldflags "-s -w -T $(TEXT_START) -R 0x1000 -X main.revision=$(REVISION)"

QEMU ?= qemu-system-arm -machine mcimx6ul-evk -cpu cortex-a7 -m 512M \
        -nographic -monitor none -semihosting \
        -serial $(UART1) -serial $(UART2) -net $(NET)

.PHONY: all elf imx imx_signed qemu qemu-build repro test staticcheck govulncheck e2e e2e-live clean check_tamago check_hab_keys

all: elf

elf: $(ELF)

imx: $(ELF).imx

test:
	go test ./...

staticcheck:
	go tool staticcheck ./...

govulncheck:
	go tool govulncheck ./...

check_tamago:
	@if [ "$(TAMAGO)" == "" ] || [ ! -f "$(TAMAGO)" ]; then \
		echo 'tamago toolchain not found - run inside the devShell (nix develop)'; \
		exit 1; \
	fi

# Generate-if-missing (mx6ullevk only): a fresh clone builds with a fresh
# emulated host key.
#
# NOTE: reproducibility comparisons of the emulated image require the same
# seed file; `make clean` must never remove it.
fw/ssh_host.seed:
	go run ./cmd/vitrum hostkey -seed fw/ssh_host.seed -pub keys/ssh_host.pub

$(ELF): check_tamago $(HOSTSEED)
	@mkdir -p $(OUT)
	$(GOENV) $(TAMAGO) build $(GOFLAGS) -o $(ELF) ./fw

$(ELF).bin: CROSS_COMPILE=arm-none-eabi-
$(ELF).bin: $(ELF)
	$(CROSS_COMPILE)objcopy -j .text -j .rodata -j .shstrtab -j .typelink \
	    -j .itablink -j .gopclntab -j .go.buildinfo -j .go.module -j .noptrdata -j .data \
	    -j .bss --set-section-flags .bss=alloc,load,contents \
	    -j .noptrbss --set-section-flags .noptrbss=alloc,load,contents \
	    $(ELF) -O binary $(ELF).bin

$(ELF).dcd: check_tamago
$(ELF).dcd: GOMODCACHE=$(shell $(TAMAGO) env GOMODCACHE)
$(ELF).dcd: TAMAGO_PKG=$(shell $(TAMAGO) list -m -f '{{.Path}}@{{.Version}}' github.com/usbarmory/tamago)
$(ELF).dcd:
	@mkdir -p $(OUT)
	@if test "$(TARGET)" = "usbarmory"; then \
		cp -f $(GOMODCACHE)/$(TAMAGO_PKG)/board/usbarmory/mk2/imximage.cfg $(ELF).dcd; \
	else \
		cp -f $(GOMODCACHE)/$(TAMAGO_PKG)/board/nxp/mx6ullevk/imximage.cfg $(ELF).dcd; \
	fi

$(ELF).imx: $(ELF).bin $(ELF).dcd
	mkimage -n $(ELF).dcd -T imximage -e $(TEXT_START) -d $(ELF).bin $(ELF).imx
	# Copy entry point from ELF file
	dd if=$(ELF) of=$(ELF).imx bs=1 count=4 skip=24 seek=4 conv=notrunc
	@size=$$(stat -c %s $(ELF).imx); \
	if [ $$size -ge $(IMAGE_SIZE_LIMIT) ]; then \
		echo "ERROR: $(ELF).imx ($$size bytes) reaches the 16 MiB state region"; \
		exit 1; \
	fi

# HAB-signed image. This PRODUCES a signed artifact; it does NOT burn any fuse,
# does NOT activate HAB, and must never be flashed without explicit human
# approval. On an unfused (HAB-open) unit the signed image boots exactly like
# the unsigned one and HAB records verification events but enforces nothing.
# SECURE_BOOT.md is the full runbook (SRK generation, fuse tables, revocation).
#
# HAB_KEYS must point at a directory holding the CSF/IMG key+cert pairs and the
# SRK table. SRK index selected with HAB_SRK_INDEX (default 1).
HAB_SRK_INDEX ?= 1
CRUCIBLE_VERSION := v0.0.0-20260105222051-0bd71c72232c

check_hab_keys:
	@if [ "$(HAB_KEYS)" == "" ]; then \
		echo 'Set HAB_KEYS to the directory holding the secure-boot keys.'; \
		echo 'See SECURE_BOOT.md (generate them with habtool; do NOT burn fuses).'; \
		exit 1; \
	fi
	@for file in \
		CSF_$(HAB_SRK_INDEX)_key.pem CSF_$(HAB_SRK_INDEX)_crt.pem \
		IMG_$(HAB_SRK_INDEX)_key.pem IMG_$(HAB_SRK_INDEX)_crt.pem \
		SRK_1_2_3_4_table.bin; do \
		if [ ! -s "$(HAB_KEYS)/$$file" ]; then \
			echo "missing or empty HAB file: $(HAB_KEYS)/$$file"; \
			exit 1; \
		fi; \
	done

$(ELF)-signed.imx: check_tamago check_hab_keys $(ELF).imx
	$(TAMAGO) install github.com/usbarmory/crucible/cmd/habtool@$(CRUCIBLE_VERSION)
	$(shell $(TAMAGO) env GOPATH)/bin/habtool \
		-A $(HAB_KEYS)/CSF_$(HAB_SRK_INDEX)_key.pem \
		-a $(HAB_KEYS)/CSF_$(HAB_SRK_INDEX)_crt.pem \
		-B $(HAB_KEYS)/IMG_$(HAB_SRK_INDEX)_key.pem \
		-b $(HAB_KEYS)/IMG_$(HAB_SRK_INDEX)_crt.pem \
		-t $(HAB_KEYS)/SRK_1_2_3_4_table.bin \
		-x $(HAB_SRK_INDEX) \
		-i $(ELF).imx \
		-o $(ELF).csf
	cat $(ELF).imx $(ELF).csf > $(ELF)-signed.imx
	@echo
	@echo "Produced $(ELF)-signed.imx (NOT flashed, NOT fused)."
	@echo "Flashing / fuse burning is a documented, human-only step; see SECURE_BOOT.md."

imx_signed: $(ELF)-signed.imx

ifeq ($(TARGET),mx6ullevk)
# qemu-build exists so the e2e scripts can build in the foreground (the
# first build bootstraps the tamago-go toolchain, which takes minutes)
# before backgrounding the boot.
qemu qemu-build: GOFLAGS := $(GOFLAGS:native=semihosting)
qemu-build: $(ELF)
qemu: qemu-build
	$(QEMU) -kernel $(ELF)
else
qemu qemu-build:
	@echo 'make $@ requires TARGET=mx6ullevk (usbarmory has no emulated networking)'; exit 1
endif

repro:
	@rm -rf $(OUT)/repro-1 $(OUT)/repro-2
	$(MAKE) imx TARGET=$(TARGET) OUT=$(OUT)/repro-1
	$(MAKE) imx TARGET=$(TARGET) OUT=$(OUT)/repro-2
	@cmp $(OUT)/repro-1/$(APP)-$(TARGET).imx $(OUT)/repro-2/$(APP)-$(TARGET).imx && \
		sha256sum $(OUT)/repro-1/$(APP)-$(TARGET).imx && \
		echo reproducible

e2e:
	@scripts/e2e.sh

# Boot the witness under QEMU and feed a *live* external log (keyserver.geomys.org by default).
# Depends on 3rd party log/connectivity, so it is deliberately NOT part of `e2e` or CI.
# Override the target with LOG_NAME=<config.Logs handle>.
e2e-live:
	@scripts/e2e-live.sh

clean:
	@rm -rf $(OUT)
	@rm -f $(APP) # a stray `go build ./cmd/vitrum` in the repo root
