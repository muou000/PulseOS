export A := $(PWD)
export NO_AXSTD := y
export AX_LIB := axfeat
export APP_FEATURES := qemu
export BLK := y

export ARCH ?= riscv64
export LOG := info

build run justrun: defconfig
	@make -C arceos $@

clean defconfig:
	@make -C arceos $@

img:
	./build_img.sh all
	mv rootfs-$(ARCH).img arceos/disk.img

la:
	@ARCH=loongarch64 make defconfig
	@ARCH=loongarch64 make -C arceos run