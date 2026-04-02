export A := $(PWD)
export NO_AXSTD := y
export AX_LIB := axfeat
export APP_FEATURES := qemu
export BLK := y

export ARCH ?= riscv64
export LOG := info

all: 
	@ARCH=riscv64 APP_FEATURES=qemu,auto-testcode LOG=off $(MAKE) defconfig
	@ARCH=riscv64 APP_FEATURES=qemu,auto-testcode LOG=off $(MAKE) -C arceos build
	@cp PulseOS_riscv64-qemu-virt.elf kernel-rv
	@ARCH=loongarch64 APP_FEATURES=qemu,auto-testcode LOG=off $(MAKE) defconfig
	@ARCH=loongarch64 APP_FEATURES=qemu,auto-testcode LOG=off $(MAKE) -C arceos build
	@cp PulseOS_loongarch64-qemu-virt.elf kernel-la
	@$(MAKE) img_all

build run justrun: defconfig
	@make -C arceos $@

clean defconfig:
	@make -C arceos $@

img:
	@./build_img.sh all
	@cp rootfs-$(ARCH).img arceos/disk.img

img_all:
	@./build_img.sh all
	@cp rootfs-riscv64.img disk.img
	@cp rootfs-loongarch64.img disk-la.img
	@cp disk.img arceos/disk.img
	@cp disk-la.img arceos/disk-la.img

la:
	@ARCH=loongarch64 make defconfig
	@ARCH=loongarch64 make -C arceos run

.PHONY: all oscomp build run justrun clean defconfig img img_all la