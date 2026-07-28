export A := $(PWD)
export NAME := $(notdir $(A))
export PATH := $(A)/bin:$(PATH)
export NO_AXSTD := y
export AX_LIB := axfeat
FEATURE ?= final-testcode
QPERF_TRACE ?= n
SCHED_LOAD_BALANCE ?= y
comma := ,
QPERF_APP_FEATURE = $(if $(filter y,$(QPERF_TRACE)),$(comma)qperf-trace)
SCHED_LOAD_BALANCE_APP_FEATURE = $(if $(filter y,$(SCHED_LOAD_BALANCE)),$(comma)sched-load-balance)
BUILD_OUT_DIR = $(if $(filter y,$(QPERF_TRACE)),$(A)/target/qperf-artifacts,$(A))
export APP_FEATURES = qemu,$(FEATURE)$(QPERF_APP_FEATURE)$(SCHED_LOAD_BALANCE_APP_FEATURE)
ALL_APP_FEATURES = qemu,$(FEATURE)$(SCHED_LOAD_BALANCE_APP_FEATURE)
export BLK := y

export SMP ?= 8
export MEM := 8G
export ARCH ?= riscv64
ALL_RISCV64_SMP := 8
ALL_RISCV64_MEM := 16G
ALL_LOONGARCH64_SMP := 12
ALL_LOONGARCH64_MEM := 36G
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
	@$(MAKE) ARCH=riscv64 SMP=$(ALL_RISCV64_SMP) MEM=$(ALL_RISCV64_MEM) APP_FEATURES=$(ALL_APP_FEATURES) LOG=off defconfig
	@$(MAKE) -C arceos ARCH=riscv64 SMP=$(ALL_RISCV64_SMP) MEM=$(ALL_RISCV64_MEM) APP_FEATURES=$(ALL_APP_FEATURES) LOG=off BUS=mmio OUT_DIR=$(A) build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@$(MAKE) ARCH=loongarch64 SMP=$(ALL_LOONGARCH64_SMP) MEM=$(ALL_LOONGARCH64_MEM) APP_FEATURES=$(ALL_APP_FEATURES) LOG=off FEATURES=bus-pci defconfig
	@$(MAKE) -C arceos ARCH=loongarch64 SMP=$(ALL_LOONGARCH64_SMP) MEM=$(ALL_LOONGARCH64_MEM) APP_FEATURES=$(ALL_APP_FEATURES) LOG=off BUS=pci FEATURES=bus-pci OUT_DIR=$(A) build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la
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

.PHONY: all test qperf-test build run justrun clean defconfig img_all la prepare-tools
