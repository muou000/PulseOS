export A := $(PWD)
export NAME := $(notdir $(A))
export NO_AXSTD := y
export AX_LIB := axfeat

# App options
APP ?= $(A)
APP_FEATURES ?= qemu
export APP_FEATURES

export BLK ?= y
export NET ?= n

SMP ?= 8
MEM ?= 8G
ARCH ?= riscv64
LOG ?= info
MODE ?= release
V ?=
TARGET_DIR ?= $(PWD)/target
EXTRA_CONFIG ?=
OUT_CONFIG ?= $(PWD)/.axconfig.toml
UIMAGE ?= n

GRAPHIC ?= n
BUS ?= pci
ACCEL ?=
QEMU_ARGS ?=
DISK_IMG ?= $(A)/disk.img
QEMU_LOG ?= n
NET_DUMP ?= n
NET_DEV ?= user
VFIO_PCI ?=
VHOST ?= n

IP ?= 10.0.2.15
GW ?= 10.0.2.2

QPERF_RUSTFLAGS := -C debuginfo=2 -C force-frame-pointers=yes -C strip=none

VF2_PLATFORM_CONFIG := $(A)/platforms/axplat-riscv64-visionfive2/axconfig.toml
VF2_IP ?= 192.168.137.2
VF2_GW ?= 192.168.137.1
QEMU_RV_PLATFORM_CONFIG := $(A)/platforms/axplat-riscv64-qemu-virt/axconfig.toml
QEMU_LA_PLATFORM_CONFIG := $(A)/platforms/axplat-loongarch64-qemu-virt/axconfig.toml
LS2K1000_PLATFORM_CONFIG := $(A)/platforms/axplat-loongarch64-ls2k1000/axconfig.toml

# App type
ifneq ($(wildcard $(APP)/Cargo.toml),)
  APP_TYPE := rust
else
  APP_TYPE := c
endif

.DEFAULT_GOAL := rv

ifneq ($(filter $(or $(MAKECMDGOALS), $(.DEFAULT_GOAL)), all build disasm run justrun debug defconfig oldconfig),)
include scripts/make/deps.mk
include scripts/make/platform.mk
include scripts/make/config.mk
include scripts/make/features.mk
endif

# Target
ifeq ($(ARCH), x86_64)
  TARGET := x86_64-unknown-none
else ifeq ($(ARCH), aarch64)
  TARGET := aarch64-unknown-none-softfloat
else ifeq ($(ARCH), riscv64)
  TARGET := riscv64gc-unknown-none-elf
else ifeq ($(ARCH), loongarch64)
  TARGET := loongarch64-unknown-none-softfloat
else
  $(error "ARCH" must be one of "x86_64", "riscv64", "aarch64" or "loongarch64")
endif

export AX_ARCH=$(ARCH)
export AX_PLATFORM=$(PLAT_NAME)
export AX_MODE=$(MODE)
export AX_LOG=$(LOG)
export AX_TARGET=$(TARGET)
export AX_IP=$(IP)
export AX_GW=$(GW)

ifneq ($(filter $(MAKECMDGOALS),unittest unittest_no_fail_fast clippy doc doc_check_missing),)
  unexport AX_CONFIG_PATH
else
  export AX_CONFIG_PATH=$(OUT_CONFIG)
endif

CROSS_COMPILE ?= $(ARCH)-linux-musl-
CC := $(CROSS_COMPILE)gcc
AR := $(CROSS_COMPILE)ar
RANLIB := $(CROSS_COMPILE)ranlib
LD := rust-lld -flavor gnu

OBJDUMP ?= rust-objdump -d --print-imm-hex --x86-asm-syntax=intel
OBJCOPY ?= rust-objcopy --binary-architecture=$(ARCH)
GDB ?= gdb-multiarch

OUT_DIR ?= $(APP)
LD_SCRIPT ?= $(TARGET_DIR)/$(TARGET)/$(MODE)/linker_$(PLAT_NAME).lds

APP_NAME := $(shell basename $(APP))
OUT_ELF := $(OUT_DIR)/$(APP_NAME)_$(PLAT_NAME).elf
OUT_BIN := $(patsubst %.elf,%.bin,$(OUT_ELF))
OUT_UIMG := $(patsubst %.elf,%.uimg,$(OUT_ELF))
ifeq ($(UIMAGE), y)
  FINAL_IMG := $(OUT_UIMG)
else
  FINAL_IMG := $(OUT_BIN)
endif

include scripts/make/utils.mk
include scripts/make/build.mk
include scripts/make/qemu.mk

defconfig:
	$(call defconfig)

oldconfig:
	$(call oldconfig)

build: $(OUT_DIR) $(FINAL_IMG)

justrun:
	$(call run_qemu)

# Build the RISC-V QEMU kernel without starting it.
rv:
	@rm -f "$(A)/.axconfig.toml"
	@$(MAKE) ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=mmio FEATURES="$(FEATURES)" BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=mmio FEATURES="$(FEATURES)" BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" build

# Build the LoongArch64 QEMU kernel without starting it.
la:
	@rm -f "$(A)/.axconfig.toml"
	@$(MAKE) ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=pci FEATURES="bus-pci $(FEATURES)" BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=pci FEATURES="bus-pci $(FEATURES)" BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" build

# Dual-architecture build gate.
test: rv la

# Build the RISC-V kernel, create its disk image on demand, and start QEMU.
run: rv
	@if [ ! -f "$(A)/disk.img" ]; then \
		echo "[run] disk.img is missing; building the RISC-V image"; \
		$(MAKE) ARCH=riscv64 img; \
	fi
	@$(MAKE) ARCH=riscv64 SMP="$(SMP)" MEM="$(MEM)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=mmio BLK="$(BLK)" NET="$(NET)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" DISK_IMG="$(A)/disk.img" OUT_DIR="$(A)" justrun

# Build and install the rootfs image for the selected architecture.
img:
	@set -e; \
	case "$(ARCH)" in \
		riscv64) \
			base_a="$(A)/rootfs/base/alpine-minirootfs-riscv64.tar.gz"; \
			base_b="$(A)/rootfs/base/alpine-minirootfs-riscv64.tar.xz"; \
			disk="$(A)/disk.img"; \
			;; \
		loongarch64) \
			base_a="$(A)/rootfs/base/base-rootfs-loongarch64.tar.xz"; \
			base_b="$(A)/rootfs/base/base-rootfs-loongarch64.tar.gz"; \
			disk="$(A)/disk-la.img"; \
			;; \
		*) \
			echo "Error: img supports ARCH=riscv64 or ARCH=loongarch64." >&2; \
			exit 1; \
			;; \
	esac; \
	if [ ! -f "$$base_a" ] && [ ! -f "$$base_b" ]; then \
		"$(A)/scripts/fetch-rootfs.sh"; \
	fi; \
	"$(A)/scripts/build_img.sh" "$(ARCH)"; \
	cp "$(A)/rootfs-$(ARCH).img" "$$disk"

vf2:
	@command -v mkimage >/dev/null || (echo "Error: VisionFive 2 U-Boot image generation requires mkimage (install u-boot-tools)."; exit 1)
	@ARCH=riscv64 MYPLAT=axplat-riscv64-visionfive2 SMP=4 APP_FEATURES=visionfive2 LOG="$(LOG)" BUS=mmio IP="$(VF2_IP)" GW="$(VF2_GW)" PLAT_CONFIG="$(VF2_PLATFORM_CONFIG)" OUT_DIR="$(A)" UIMAGE=y $(MAKE) defconfig
	@ARCH=riscv64 MYPLAT=axplat-riscv64-visionfive2 SMP=4 APP_FEATURES=visionfive2 LOG="$(LOG)" BUS=mmio IP="$(VF2_IP)" GW="$(VF2_GW)" PLAT_CONFIG="$(VF2_PLATFORM_CONFIG)" OUT_DIR="$(A)" UIMAGE=y $(MAKE) build
	@echo "Built uimg for U-Boot bootm at 0x40200000."

ls2k1000:
	@rm -f "$(A)/.axconfig.toml"
	@ARCH=loongarch64 MYPLAT=axplat-loongarch64-ls2k1000 SMP=2 APP_FEATURES=ls2k1000 LOG="$(LOG)" BUS=mmio PLAT_CONFIG="$(LS2K1000_PLATFORM_CONFIG)" OUT_DIR="$(A)" $(MAKE) defconfig
	@ARCH=loongarch64 MYPLAT=axplat-loongarch64-ls2k1000 SMP=2 APP_FEATURES=ls2k1000 LOG="$(LOG)" BUS=mmio PLAT_CONFIG="$(LS2K1000_PLATFORM_CONFIG)" OUT_DIR="$(A)" $(MAKE) build
	@echo "Built elf for U-Boot go at cached load address 0x9000000098000000."

qperf:
	@$(MAKE) ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=mmio BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=mmio BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" build EXTRA_RUSTFLAGS="$(QPERF_RUSTFLAGS)"
	@cp "$(A)/$(NAME)_riscv64-qemu-virt.bin" "$(A)/kernel-rv-qperf"
	@cp "$(A)/$(NAME)_riscv64-qemu-virt.elf" "$(A)/$(NAME)_riscv64-qemu-virt-qperf.elf"
	@$(MAKE) ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=pci FEATURES=bus-pci BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=pci FEATURES=bus-pci BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" build EXTRA_RUSTFLAGS="$(QPERF_RUSTFLAGS)"
	@cp "$(A)/$(NAME)_loongarch64-qemu-virt.elf" "$(A)/kernel-la-qperf"
	@cp "$(A)/$(NAME)_loongarch64-qemu-virt.elf" "$(A)/$(NAME)_loongarch64-qemu-virt-qperf.elf"
	@for elf in "$(A)/$(NAME)_riscv64-qemu-virt-qperf.elf" "$(A)/$(NAME)_loongarch64-qemu-virt-qperf.elf"; do \
		if ! nm -n "$$elf" | grep -q ' __pulse_qperf_trace_v1$$'; then \
			echo "Error: qperf artifact lacks trace marker: $$elf"; \
			exit 1; \
		fi; \
	done

clean:
	@rm -rf "$(A)/target"
	@rm -f "$(A)"/*.bin "$(A)"/*.elf "$(A)"/*.uimg "$(A)"/kernel-*
	@rm -f "$(A)/.axconfig.toml" "$(A)/.axconfig.old.toml"

.PHONY: rv la run img vf2 ls2k1000 qperf test clean defconfig oldconfig build justrun
