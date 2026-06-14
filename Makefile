export A := $(PWD)
export NAME := $(notdir $(A))
export PATH := $(A)/bin:$(PATH)
export NO_AXSTD := y
export AX_LIB := axfeat
export APP_FEATURES := qemu
export BLK := y

export MEM := 1G
export ARCH ?= riscv64
export LOG ?= info

QPERF ?= n
ifeq ($(QPERF),y)
  EXTRA_RUSTFLAGS := -C debuginfo=2 -C force-frame-pointers=yes -C strip=none
endif

IMG ?= n

prepare-tools:
	@if [ -d cargo ] && [ ! -d .cargo ]; then mv cargo .cargo; fi
	@command -v axconfig-gen >/dev/null || (echo "Error: missing axconfig-gen in PATH (expected in $(A)/bin)"; exit 1)
	@command -v cargo-axplat >/dev/null || (echo "Error: missing cargo-axplat in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objcopy >/dev/null || (echo "Error: missing rust-objcopy in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objdump >/dev/null || (echo "Error: missing rust-objdump in PATH (expected in $(A)/bin)"; exit 1)
	@echo "[tools] Using prebuilt tools from $(A)/bin"

all: prepare-tools
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=off $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=off BUS=mmio $(MAKE) -C arceos build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=off FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=off BUS=pci FEATURES=bus-pci $(MAKE) -C arceos build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la
	@$(MAKE) img_all

test: prepare-tools
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=$(LOG) $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=$(LOG) BUS=mmio $(MAKE) -C arceos build  EXTRA_RUSTFLAGS="$(EXTRA_RUSTFLAGS)"
	@cp PulseOS_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=$(LOG) FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=$(LOG) BUS=pci FEATURES=bus-pci $(MAKE) -C arceos build  EXTRA_RUSTFLAGS="$(EXTRA_RUSTFLAGS)"
	@cp PulseOS_loongarch64-qemu-virt.elf kernel-la
	@if [ "$(IMG)" = "y" ]; then $(MAKE) img_all; fi

debug: prepare-tools
	@ARCH=riscv64 APP_FEATURES=qemu LOG=$(LOG) $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu LOG=$(LOG) BUS=mmio $(MAKE) -C arceos build
	@cp PulseOS_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu LOG=$(LOG) FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu LOG=$(LOG) BUS=pci FEATURES=bus-pci $(MAKE) -C arceos build
	@cp PulseOS_loongarch64-qemu-virt.elf kernel-la

build run justrun: prepare-tools defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) $@

clean:
	@$(MAKE) -C arceos A=$(A) $@
	@rm -f .axconfig.toml
	@rm -f kernel-rv kernel-la
	@rm -f PulseOS_riscv64-qemu-virt.elf PulseOS_riscv64-qemu-virt.bin
	@rm -f PulseOS_loongarch64-qemu-virt.elf PulseOS_loongarch64-qemu-virt.bin
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

la: prepare-tools
	@$(MAKE) ARCH=loongarch64 defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 run
	
analyze: prepare-tools
	@$(MAKE) QPERF=y LOG=$(LOG) test

.PHONY: all test debug build run justrun clean defconfig img_all la analyze prepare-tools
