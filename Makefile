export A := $(PWD)
export NAME := $(notdir $(A))
export NO_AXSTD := y
export AX_LIB := axfeat

# Local development builds boot into /bin/sh unless a test feature is added
# explicitly through APP_FEATURES.
APP_FEATURES ?= qemu
export APP_FEATURES

export BLK ?= y
export NET ?= n

SMP ?= 8
MEM ?= 8G
ARCH ?= riscv64
LOG ?= info

QPERF_RUSTFLAGS := -C debuginfo=2 -C force-frame-pointers=yes -C strip=none

VF2_PLATFORM_CONFIG := $(A)/crates/axplat-riscv64-visionfive2/axconfig.toml
VF2_IP ?= 192.168.137.2
VF2_GW ?= 192.168.137.1
VF2_BUILD_EPOCH ?= $(shell date +%s)
QEMU_RV_PLATFORM_CONFIG := $(A)/crates/axplat-riscv64-qemu-virt/axconfig.toml
QEMU_LA_PLATFORM_CONFIG := $(A)/crates/axplat-loongarch64-qemu-virt/axconfig.toml
LS2K1000_PLATFORM_CONFIG := $(A)/crates/axplat-loongarch64-ls2k1000/axconfig.toml

.DEFAULT_GOAL := rv

# Build the RISC-V QEMU kernel without starting it.
rv:
	@rm -f "$(A)/.axconfig.toml"
	@$(MAKE) -C arceos A="$(A)" ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=mmio BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) -C arceos A="$(A)" ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=mmio BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" build
	@cp "$(A)/$(NAME)_riscv64-qemu-virt.bin" "$(A)/kernel-rv"

# Build the LoongArch64 QEMU kernel without starting it.
la:
	@rm -f "$(A)/.axconfig.toml"
	@$(MAKE) -C arceos A="$(A)" ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=pci FEATURES=bus-pci BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) -C arceos A="$(A)" ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=pci FEATURES=bus-pci BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" build
	@cp "$(A)/$(NAME)_loongarch64-qemu-virt.elf" "$(A)/kernel-la"

# Build the RISC-V kernel, create its disk image on demand, and start QEMU.
run: rv
	@if [ ! -f "$(A)/arceos/disk.img" ]; then \
		echo "[run] arceos/disk.img is missing; building the RISC-V image"; \
		$(MAKE) ARCH=riscv64 img; \
	fi
	@$(MAKE) -C arceos A="$(A)" ARCH=riscv64 SMP="$(SMP)" MEM="$(MEM)" APP_FEATURES="$(APP_FEATURES)" LOG="$(LOG)" BUS=mmio BLK="$(BLK)" NET="$(NET)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" DISK_IMG="$(A)/arceos/disk.img" OUT_DIR="$(A)" justrun

# Build and install the rootfs image for the selected architecture.
img:
	@set -e; \
	case "$(ARCH)" in \
		riscv64) \
			base_a="$(A)/rootfs/base/alpine-minirootfs-riscv64.tar.gz"; \
			base_b="$(A)/rootfs/base/alpine-minirootfs-riscv64.tar.xz"; \
			disk="$(A)/disk.img"; \
			arceos_disk="$(A)/arceos/disk.img"; \
			;; \
		loongarch64) \
			base_a="$(A)/rootfs/base/base-rootfs-loongarch64.tar.xz"; \
			base_b="$(A)/rootfs/base/base-rootfs-loongarch64.tar.gz"; \
			disk="$(A)/disk-la.img"; \
			arceos_disk="$(A)/arceos/disk-la.img"; \
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
	cp "$(A)/rootfs-$(ARCH).img" "$$disk"; \
	cp "$$disk" "$$arceos_disk"

# Build the VisionFive 2 U-Boot uImage without QEMU or tracing features.
vf2:
	@command -v mkimage >/dev/null || (echo "Error: VisionFive 2 U-Boot image generation requires mkimage (install u-boot-tools)."; exit 1)
	@ARCH=riscv64 MYPLAT=axplat-riscv64-visionfive2 SMP=4 APP_FEATURES=visionfive2 LOG="$(LOG)" BUS=mmio IP="$(VF2_IP)" GW="$(VF2_GW)" PULSE_BUILD_EPOCH="$(VF2_BUILD_EPOCH)" PLAT_CONFIG="$(VF2_PLATFORM_CONFIG)" OUT_DIR="$(A)" UIMAGE=y $(MAKE) -C arceos defconfig
	@ARCH=riscv64 MYPLAT=axplat-riscv64-visionfive2 SMP=4 APP_FEATURES=visionfive2 LOG="$(LOG)" BUS=mmio IP="$(VF2_IP)" GW="$(VF2_GW)" PULSE_BUILD_EPOCH="$(VF2_BUILD_EPOCH)" PLAT_CONFIG="$(VF2_PLATFORM_CONFIG)" OUT_DIR="$(A)" UIMAGE=y $(MAKE) -C arceos build
	@cp "$(A)/$(NAME)_riscv64-visionfive2.bin" "$(A)/kernel-vf2"
	@cp "$(A)/$(NAME)_riscv64-visionfive2.uimg" "$(A)/kernel-vf2.uimg"
	@echo "Built kernel-vf2.uimg for U-Boot bootm at 0x40200000."

# Build a raw image for the Loongson 2K1000 U-Boot `go` handoff.
ls2k1000:
	@rm -f "$(A)/.axconfig.toml"
	@ARCH=loongarch64 MYPLAT=axplat-loongarch64-ls2k1000 SMP=2 APP_FEATURES=ls2k1000 LOG="$(LOG)" BUS=mmio PLAT_CONFIG="$(LS2K1000_PLATFORM_CONFIG)" OUT_DIR="$(A)" $(MAKE) -C arceos defconfig
	@ARCH=loongarch64 MYPLAT=axplat-loongarch64-ls2k1000 SMP=2 APP_FEATURES=ls2k1000 LOG="$(LOG)" BUS=mmio PLAT_CONFIG="$(LS2K1000_PLATFORM_CONFIG)" OUT_DIR="$(A)" $(MAKE) -C arceos build
	@cp "$(A)/$(NAME)_loongarch64-ls2k1000.bin" "$(A)/kernel-ls2k1000"
	@cp "$(A)/$(NAME)_loongarch64-ls2k1000.elf" "$(A)/kernel-ls2k1000.elf"
	@echo "Built kernel-ls2k1000 for U-Boot go at cached load address 0x9000000098000000."

# Build matching qperf artifacts for both QEMU architectures.
qperf:
	@$(MAKE) -C arceos A="$(A)" ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=mmio BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) -C arceos A="$(A)" ARCH=riscv64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=mmio BLK="$(BLK)" PLAT_CONFIG="$(QEMU_RV_PLATFORM_CONFIG)" OUT_DIR="$(A)" build EXTRA_RUSTFLAGS="$(QPERF_RUSTFLAGS)"
	@cp "$(A)/$(NAME)_riscv64-qemu-virt.bin" "$(A)/kernel-rv-qperf"
	@cp "$(A)/$(NAME)_riscv64-qemu-virt.elf" "$(A)/$(NAME)_riscv64-qemu-virt-qperf.elf"
	@$(MAKE) -C arceos A="$(A)" ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=pci FEATURES=bus-pci BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" defconfig
	@$(MAKE) -C arceos A="$(A)" ARCH=loongarch64 SMP="$(SMP)" APP_FEATURES="$(APP_FEATURES),qperf-trace" LOG=off BUS=pci FEATURES=bus-pci BLK="$(BLK)" PLAT_CONFIG="$(QEMU_LA_PLATFORM_CONFIG)" OUT_DIR="$(A)" build EXTRA_RUSTFLAGS="$(QPERF_RUSTFLAGS)"
	@cp "$(A)/$(NAME)_loongarch64-qemu-virt.elf" "$(A)/kernel-la-qperf"
	@cp "$(A)/$(NAME)_loongarch64-qemu-virt.elf" "$(A)/$(NAME)_loongarch64-qemu-virt-qperf.elf"
	@for elf in "$(A)/$(NAME)_riscv64-qemu-virt-qperf.elf" "$(A)/$(NAME)_loongarch64-qemu-virt-qperf.elf"; do \
		if ! nm -n "$$elf" | grep -q ' __pulse_qperf_trace_v1$$'; then \
			echo "Error: qperf artifact lacks trace marker: $$elf"; \
			exit 1; \
		fi; \
	done

.PHONY: rv la run img vf2 ls2k1000 qperf
