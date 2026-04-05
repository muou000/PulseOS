export A := $(PWD)
export NAME := $(notdir $(A))
export PATH := $(A)/bin:$(PATH)
export NO_AXSTD := y
export AX_LIB := axfeat
export APP_FEATURES := qemu
export BLK := y

export ARCH ?= riscv64
export LOG ?= info

prepare-cargo-config:
	@if [ -d cargo ] && [ ! -d .cargo ]; then mv cargo .cargo; fi

prepare-tools:
	@command -v axconfig-gen >/dev/null || (echo "Error: missing axconfig-gen in PATH (expected in $(A)/bin)"; exit 1)
	@command -v cargo-axplat >/dev/null || (echo "Error: missing cargo-axplat in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objcopy >/dev/null || (echo "Error: missing rust-objcopy in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objdump >/dev/null || (echo "Error: missing rust-objdump in PATH (expected in $(A)/bin)"; exit 1)
	@echo "[tools] Using prebuilt tools from $(A)/bin"

all: prepare-tools
	@$(MAKE) prepare-cargo-config >/dev/null
	@command -v axconfig-gen >/dev/null || (echo "Error: missing axconfig-gen in PATH"; exit 1)
	@command -v cargo-axplat >/dev/null || (echo "Error: missing cargo-axplat in PATH"; exit 1)
	@command -v rust-objcopy >/dev/null || (echo "Error: missing rust-objcopy in PATH"; exit 1)
	@ARCH=riscv64 APP_FEATURES=qemu,auto-testcode LOG=off $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,auto-testcode LOG=off BUS=mmio $(MAKE) -C arceos build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,auto-testcode LOG=off $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,auto-testcode LOG=off BUS=pci $(MAKE) -C arceos build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la
	@$(MAKE) img_all

test: prepare-tools
	@ARCH=riscv64 APP_FEATURES=qemu,auto-testcode LOG=$(LOG) $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,auto-testcode LOG=$(LOG) BUS=mmio $(MAKE) -C arceos build
	@cp PulseOS_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,auto-testcode LOG=$(LOG) $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,auto-testcode LOG=$(LOG) BUS=pci $(MAKE) -C arceos build
	@cp PulseOS_loongarch64-qemu-virt.elf kernel-la
	@$(MAKE) img_all

build run justrun: prepare-tools defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) $@

clean:
	@$(MAKE) -C arceos A=$(A) $@

defconfig: prepare-tools
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) $@

img:
	@./build_img.sh $(ARCH)
	@cp rootfs-$(ARCH).img arceos/disk.img

img_all:
	@./build_img.sh all
	@cp rootfs-riscv64.img disk.img
	@cp rootfs-loongarch64.img disk-la.img
	@cp disk.img arceos/disk.img
	@cp disk-la.img arceos/disk-la.img

la: prepare-tools
	@$(MAKE) ARCH=loongarch64 defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 run

package: img_all

.PHONY: all oscomp build run justrun clean defconfig img img_all la package prepare-tools prepare-cargo-config
