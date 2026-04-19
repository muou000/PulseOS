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
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=off $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=off BUS=mmio $(MAKE) -C arceos build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=off FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=off BUS=pci FEATURES=bus-pci CARGO_BUILD_ALLOW_LOCK_UPDATE=1 CARGO_BUILD_EXTRA_ARGS='--config patch.crates-io.axplat-loongarch64-qemu-virt.path=\"plat/axplat-loongarch64-qemu-virt\"' $(MAKE) -C arceos build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la
	@$(MAKE) img_all

test: prepare-tools
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=$(LOG) $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,testcode LOG=$(LOG) BUS=mmio $(MAKE) -C arceos build
	@cp PulseOS_riscv64-qemu-virt.bin kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=$(LOG) FEATURES=bus-pci $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,testcode LOG=$(LOG) BUS=pci FEATURES=bus-pci $(MAKE) -C arceos build
	@cp PulseOS_loongarch64-qemu-virt.elf kernel-la
	@$(MAKE) img_all

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

.PHONY: all oscomp build run justrun clean defconfig img img_all la prepare-tools prepare-cargo-config
