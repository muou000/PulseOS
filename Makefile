export A := $(PWD)
export NAME := $(notdir $(A))
export PATH := $(A)/bin:$(PATH)
export NO_AXSTD := y
export AX_LIB := axfeat
FEATURE ?= final-testcode
QPERF_TRACE ?= n
comma := ,
QPERF_APP_FEATURE = $(if $(filter y,$(QPERF_TRACE)),$(comma)qperf-trace)
BUILD_OUT_DIR = $(if $(filter y,$(QPERF_TRACE)),$(A)/target/qperf-artifacts,$(A))
export APP_FEATURES = qemu,$(FEATURE)$(QPERF_APP_FEATURE)
export BLK := y

export SMP ?= 8
export MEM := 8G
export ARCH ?= riscv64
export LOG ?= info

EXTRA_RUSTFLAGS := -C debuginfo=2 -C force-frame-pointers=yes -C strip=none

IMG ?= n

prepare-tools:
	@if [ -d cargo ] && [ ! -d .cargo ]; then mv cargo .cargo; fi
	@command -v axconfig-gen >/dev/null || (echo "Error: missing axconfig-gen in PATH (expected in $(A)/bin)"; exit 1)
	@command -v cargo-axplat >/dev/null || (echo "Error: missing cargo-axplat in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objcopy >/dev/null || (echo "Error: missing rust-objcopy in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objdump >/dev/null || (echo "Error: missing rust-objdump in PATH (expected in $(A)/bin)"; exit 1)
	@echo "[tools] Using prebuilt tools from $(A)/bin"

all: prepare-tools
	@ARCH=riscv64 APP_FEATURES=$(APP_FEATURES) LOG=off $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=$(APP_FEATURES) LOG=off BUS=mmio OUT_DIR=$(BUILD_OUT_DIR) $(MAKE) -C arceos build
	@if [ "$(QPERF_TRACE)" = "y" ]; then \
		cp $(BUILD_OUT_DIR)/$(NAME)_riscv64-qemu-virt.bin kernel-rv-qperf; \
		cp $(BUILD_OUT_DIR)/$(NAME)_riscv64-qemu-virt.elf $(NAME)_riscv64-qemu-virt-qperf.elf; \
	else \
		cp $(BUILD_OUT_DIR)/$(NAME)_riscv64-qemu-virt.bin kernel-rv; \
	fi
	@ARCH=loongarch64 APP_FEATURES=$(APP_FEATURES) LOG=off FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=$(APP_FEATURES) LOG=off BUS=pci FEATURES=bus-pci OUT_DIR=$(BUILD_OUT_DIR) $(MAKE) -C arceos build
	@if [ "$(QPERF_TRACE)" = "y" ]; then \
		cp $(BUILD_OUT_DIR)/$(NAME)_loongarch64-qemu-virt.elf kernel-la-qperf; \
		cp $(BUILD_OUT_DIR)/$(NAME)_loongarch64-qemu-virt.elf $(NAME)_loongarch64-qemu-virt-qperf.elf; \
	else \
		cp $(BUILD_OUT_DIR)/$(NAME)_loongarch64-qemu-virt.elf kernel-la; \
	fi
	@if [ "$(FEATURE)" = "pre-testcode" ]; then $(MAKE) img_all; fi

test: prepare-tools
	@ARCH=riscv64 APP_FEATURES=$(APP_FEATURES) LOG=$(LOG) $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=$(APP_FEATURES) LOG=$(LOG) BUS=mmio OUT_DIR=$(BUILD_OUT_DIR) $(MAKE) -C arceos build  EXTRA_RUSTFLAGS="$(EXTRA_RUSTFLAGS)"
	@if [ "$(QPERF_TRACE)" = "y" ]; then \
		cp $(BUILD_OUT_DIR)/$(NAME)_riscv64-qemu-virt.bin kernel-rv-qperf; \
		cp $(BUILD_OUT_DIR)/$(NAME)_riscv64-qemu-virt.elf $(NAME)_riscv64-qemu-virt-qperf.elf; \
	else \
		cp $(BUILD_OUT_DIR)/$(NAME)_riscv64-qemu-virt.bin kernel-rv; \
	fi
	@ARCH=loongarch64 APP_FEATURES=$(APP_FEATURES) LOG=$(LOG) FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=$(APP_FEATURES) LOG=$(LOG) BUS=pci FEATURES=bus-pci OUT_DIR=$(BUILD_OUT_DIR) $(MAKE) -C arceos build  EXTRA_RUSTFLAGS="$(EXTRA_RUSTFLAGS)"
	@if [ "$(QPERF_TRACE)" = "y" ]; then \
		cp $(BUILD_OUT_DIR)/$(NAME)_loongarch64-qemu-virt.elf kernel-la-qperf; \
		cp $(BUILD_OUT_DIR)/$(NAME)_loongarch64-qemu-virt.elf $(NAME)_loongarch64-qemu-virt-qperf.elf; \
	else \
		cp $(BUILD_OUT_DIR)/$(NAME)_loongarch64-qemu-virt.elf kernel-la; \
	fi
	@if [ "$(FEATURE)" = "pre-testcode" -a "$(IMG)" = "y" ]; then $(MAKE) img_all; fi

qperf-test: QPERF_TRACE := y
qperf-test: test

debug: prepare-tools
	@ARCH=riscv64 APP_FEATURES=qemu LOG=$(LOG) $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu LOG=$(LOG) BUS=mmio $(MAKE) -C arceos build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu LOG=$(LOG) FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu LOG=$(LOG) BUS=pci FEATURES=bus-pci $(MAKE) -C arceos build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la

build: prepare-tools defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) $@

clean:
	@$(MAKE) -C arceos A=$(A) $@
	@rm -f .axconfig.toml
	@rm -f kernel-rv kernel-la
	@rm -f kernel-rv-qperf kernel-la-qperf
	@rm -f PulseOS_riscv64-qemu-virt.elf PulseOS_riscv64-qemu-virt.bin
	@rm -f PulseOS_loongarch64-qemu-virt.elf PulseOS_loongarch64-qemu-virt.bin
	@rm -f PulseOS_riscv64-qemu-virt-qperf.elf PulseOS_loongarch64-qemu-virt-qperf.elf
	@rm -f disk.img disk-la.img
	@rm -f rootfs-riscv64.img rootfs-loongarch64.img
	@rm -f arceos/disk.img arceos/disk-la.img

defconfig: prepare-tools
	@rm -f .axconfig.toml
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) $@

img_all:
	@./build_img.sh all
	@cp rootfs-riscv64.img disk.img
	@cp rootfs-loongarch64.img disk-la.img
	@cp disk.img arceos/disk.img
	@cp disk-la.img arceos/disk-la.img

.PHONY: all test qperf-test debug build run justrun clean defconfig img_all la prepare-tools
