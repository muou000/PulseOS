export A := $(PWD)
export NAME := $(notdir $(A))
export PATH := $(A)/bin:$(PATH)
export NO_AXSTD := y
export AX_LIB := axfeat

# Local development and regular tests use the final-test entrypoint by default.
FEATURE ?= final-testcode
export APP_FEATURES ?= qemu,$(FEATURE)
export BLK := y

export SMP ?= 8
export ARCH ?= riscv64
export LOG ?= info

QPERF_RUSTFLAGS := -C debuginfo=2 -C force-frame-pointers=yes -C strip=none

# Online evaluation provides one contest image per architecture under these names.
SDCARD_RV_IMAGE ?= $(A)/sdcard-rv.img
SDCARD_LA_IMAGE ?= $(A)/sdcard-la.img

VF2_PLATFORM_CONFIG := $(A)/crates/axplat-riscv64-visionfive2/axconfig.toml
VF2_IP ?= 192.168.137.2
VF2_GW ?= 192.168.137.1
VF2_BUILD_EPOCH ?= $(shell date +%s)
LS2K1000_PLATFORM_CONFIG := $(A)/crates/axplat-loongarch64-ls2k1000/axconfig.toml

prepare-tools:
	@if [ -d cargo ] && [ ! -d .cargo ]; then mv cargo .cargo; fi
	@command -v axconfig-gen >/dev/null || (echo "Error: missing axconfig-gen in PATH (expected in $(A)/bin)"; exit 1)
	@command -v cargo-axplat >/dev/null || (echo "Error: missing cargo-axplat in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objcopy >/dev/null || (echo "Error: missing rust-objcopy in PATH (expected in $(A)/bin)"; exit 1)
	@command -v rust-objdump >/dev/null || (echo "Error: missing rust-objdump in PATH (expected in $(A)/bin)"; exit 1)
	@echo "[tools] Using prebuilt tools from $(A)/bin"

# Build quiet kernels for the online submission images. Each architecture's
# image independently chooses its feature and compile-time CPU count. For a
# local checkout without either contest image, use the host CPU count to select
# the preliminary (1 CPU) or final (8/12 CPU) test configuration.
all:
	@set -e; \
	detect_feature() { \
		image="$$1"; arch="$$2"; \
		if [ ! -r "$$image" ]; then \
			echo "Error: cannot read $$arch image $$image." >&2; \
			return 1; \
		elif debugfs -R 'stat /glibc/buildstorm_testcode.sh' "$$image" 2>/dev/null | grep -q '^Inode:'; then \
			printf '%s\n' final-testcode; \
		elif debugfs -R 'stat /glibc/basic_testcode.sh' "$$image" 2>/dev/null | grep -q '^Inode:'; then \
			printf '%s\n' pre-testcode; \
		else \
			echo "Error: cannot identify $$arch image $$image." >&2; \
			echo "Expected /glibc/basic_testcode.sh or /glibc/buildstorm_testcode.sh." >&2; \
			return 1; \
		fi; \
	}; \
	if [ ! -f "$(SDCARD_RV_IMAGE)" ] || [ ! -f "$(SDCARD_LA_IMAGE)" ]; then \
		if ! command -v nproc >/dev/null 2>&1; then \
			echo "Error: make all requires nproc when contest images are missing." >&2; \
			exit 1; \
		fi; \
		cpu_count="$$(nproc)"; \
		case "$$cpu_count" in \
			1) local_feature=pre-testcode;; \
			8|12) local_feature=final-testcode;; \
			*) echo "Warning: unsupported host CPU count $$cpu_count; using final-testcode." >&2; local_feature=final-testcode;; \
		esac; \
		riscv_feature="$$local_feature"; \
		loongarch_feature="$$local_feature"; \
		echo "[submission] contest images missing; host CPUs=$$cpu_count -> $$local_feature"; \
	else \
		if ! command -v debugfs >/dev/null 2>&1; then \
			echo "Error: make all requires debugfs to identify contest images." >&2; \
			exit 1; \
		fi; \
		riscv_feature="$$(detect_feature "$(SDCARD_RV_IMAGE)" riscv64)" || exit 1; \
		loongarch_feature="$$(detect_feature "$(SDCARD_LA_IMAGE)" loongarch64)" || exit 1; \
	fi; \
	case "$$riscv_feature" in final-testcode) riscv_smp=8;; pre-testcode) riscv_smp=1;; esac; \
	case "$$loongarch_feature" in final-testcode) loongarch_smp=12;; pre-testcode) loongarch_smp=1;; esac; \
	echo "[submission] $(SDCARD_RV_IMAGE): $$riscv_feature (riscv64=$$riscv_smp)"; \
	echo "[submission] $(SDCARD_LA_IMAGE): $$loongarch_feature (loongarch64=$$loongarch_smp)"; \
	$(MAKE) submission-build SUBMISSION_RISCV64_FEATURE="$$riscv_feature" SUBMISSION_LOONGARCH64_FEATURE="$$loongarch_feature" SUBMISSION_RISCV64_SMP="$$riscv_smp" SUBMISSION_LOONGARCH64_SMP="$$loongarch_smp"; \
	if [ "$$riscv_feature" = "pre-testcode" ] || [ "$$loongarch_feature" = "pre-testcode" ]; then $(MAKE) img_all FEATURE=pre-testcode; fi

# Internal all-mode builder. `all` is its only intended caller.
submission-build: prepare-tools
	@test -n "$(SUBMISSION_RISCV64_FEATURE)" || { echo "Error: submission-build requires SUBMISSION_RISCV64_FEATURE."; exit 1; }
	@test -n "$(SUBMISSION_LOONGARCH64_FEATURE)" || { echo "Error: submission-build requires SUBMISSION_LOONGARCH64_FEATURE."; exit 1; }
	@test -n "$(SUBMISSION_RISCV64_SMP)" || { echo "Error: submission-build requires SUBMISSION_RISCV64_SMP."; exit 1; }
	@test -n "$(SUBMISSION_LOONGARCH64_SMP)" || { echo "Error: submission-build requires SUBMISSION_LOONGARCH64_SMP."; exit 1; }
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SUBMISSION_RISCV64_SMP) APP_FEATURES=qemu,$(SUBMISSION_RISCV64_FEATURE) LOG=off BUS=mmio OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SUBMISSION_RISCV64_SMP) APP_FEATURES=qemu,$(SUBMISSION_RISCV64_FEATURE) LOG=off BUS=mmio OUT_DIR=$(A) build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SUBMISSION_LOONGARCH64_SMP) APP_FEATURES=qemu,$(SUBMISSION_LOONGARCH64_FEATURE) LOG=off BUS=pci FEATURES=bus-pci OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SUBMISSION_LOONGARCH64_SMP) APP_FEATURES=qemu,$(SUBMISSION_LOONGARCH64_FEATURE) LOG=off BUS=pci FEATURES=bus-pci OUT_DIR=$(A) build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la

# Regular test builds do not inspect an image. They use FEATURE=final-testcode
# and LOG=info unless the caller explicitly overrides either variable.
test: prepare-tools
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE) LOG=$(LOG) BUS=mmio OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE) LOG=$(LOG) BUS=mmio OUT_DIR=$(A) build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE) LOG=$(LOG) BUS=pci FEATURES=bus-pci OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE) LOG=$(LOG) BUS=pci FEATURES=bus-pci OUT_DIR=$(A) build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la

# Performance-only build. Preserve matching trace ELF artifacts with suffixes.
qperf: prepare-tools
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE),qperf-trace LOG=off BUS=mmio OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE),qperf-trace LOG=off BUS=mmio OUT_DIR=$(A) build EXTRA_RUSTFLAGS="$(QPERF_RUSTFLAGS)"
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv-qperf
	@cp $(NAME)_riscv64-qemu-virt.elf $(NAME)_riscv64-qemu-virt-qperf.elf
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE),qperf-trace LOG=off BUS=pci FEATURES=bus-pci OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SMP) APP_FEATURES=qemu,$(FEATURE),qperf-trace LOG=off BUS=pci FEATURES=bus-pci OUT_DIR=$(A) build EXTRA_RUSTFLAGS="$(QPERF_RUSTFLAGS)"
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la-qperf
	@cp $(NAME)_loongarch64-qemu-virt.elf $(NAME)_loongarch64-qemu-virt-qperf.elf
	@for elf in $(NAME)_riscv64-qemu-virt-qperf.elf $(NAME)_loongarch64-qemu-virt-qperf.elf; do \
		if ! nm -n "$$elf" | grep -q ' __pulse_qperf_trace_v1$$'; then \
			echo "Error: qperf artifact lacks trace marker: $$elf"; \
			exit 1; \
		fi; \
	done

# Build shell-only artifacts independently. With no testcode feature,
# src/main.rs launches /bin/sh and does not start any test script.
debug: prepare-tools
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SMP) APP_FEATURES=qemu LOG=$(LOG) BUS=mmio OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=riscv64 SMP=$(SMP) APP_FEATURES=qemu LOG=$(LOG) BUS=mmio OUT_DIR=$(A) build
	@cp $(NAME)_riscv64-qemu-virt.bin kernel-rv-debug
	@cp $(NAME)_riscv64-qemu-virt.elf $(NAME)_riscv64-qemu-virt-debug.elf
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SMP) APP_FEATURES=qemu LOG=$(LOG) BUS=pci FEATURES=bus-pci OUT_DIR=$(A) defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=loongarch64 SMP=$(SMP) APP_FEATURES=qemu LOG=$(LOG) BUS=pci FEATURES=bus-pci OUT_DIR=$(A) build
	@cp $(NAME)_loongarch64-qemu-virt.elf kernel-la-debug
	@cp $(NAME)_loongarch64-qemu-virt.elf $(NAME)_loongarch64-qemu-virt-debug.elf
	@./build_img.sh all

# Build the VisionFive 2 U-Boot uImage without QEMU or tracing features.
vf2: prepare-tools
	@command -v mkimage >/dev/null || (echo "Error: VisionFive 2 U-Boot image generation requires mkimage (install u-boot-tools)."; exit 1)
	@ARCH=riscv64 MYPLAT=axplat-riscv64-visionfive2 SMP=4 APP_FEATURES=visionfive2 LOG=$(LOG) BUS=mmio IP=$(VF2_IP) GW=$(VF2_GW) PULSE_BUILD_EPOCH=$(VF2_BUILD_EPOCH) PLAT_CONFIG=$(VF2_PLATFORM_CONFIG) OUT_DIR=$(A) UIMAGE=y $(MAKE) -C arceos defconfig
	@ARCH=riscv64 MYPLAT=axplat-riscv64-visionfive2 SMP=4 APP_FEATURES=visionfive2 LOG=$(LOG) BUS=mmio IP=$(VF2_IP) GW=$(VF2_GW) PULSE_BUILD_EPOCH=$(VF2_BUILD_EPOCH) PLAT_CONFIG=$(VF2_PLATFORM_CONFIG) OUT_DIR=$(A) UIMAGE=y $(MAKE) -C arceos build
	@cp $(NAME)_riscv64-visionfive2.bin kernel-vf2
	@cp $(NAME)_riscv64-visionfive2.uimg kernel-vf2.uimg
	@echo "Built kernel-vf2.uimg for U-Boot bootm at 0x40200000."

# Build a raw image for the Loongson 2K1000 U-Boot `go` handoff. The board
# copies its live FDT and passes it as the second `go` argument; the platform
# crate parses that ABI before allocator and IRQ initialization.
ls2k1000: prepare-tools
	@rm -f $(A)/.axconfig.toml
	@ARCH=loongarch64 MYPLAT=axplat-loongarch64-ls2k1000 SMP=2 APP_FEATURES=ls2k1000 LOG=$(LOG) BUS=mmio PLAT_CONFIG=$(LS2K1000_PLATFORM_CONFIG) OUT_DIR=$(A) $(MAKE) -C arceos defconfig
	@ARCH=loongarch64 MYPLAT=axplat-loongarch64-ls2k1000 SMP=2 APP_FEATURES=ls2k1000 LOG=$(LOG) BUS=mmio PLAT_CONFIG=$(LS2K1000_PLATFORM_CONFIG) OUT_DIR=$(A) $(MAKE) -C arceos build
	@cp $(NAME)_loongarch64-ls2k1000.bin kernel-ls2k1000
	@cp $(NAME)_loongarch64-ls2k1000.elf kernel-ls2k1000.elf
	@echo "Built kernel-ls2k1000 for U-Boot go at cached load address 0x9000000098000000."

build: prepare-tools defconfig
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) build

clean:
	@$(MAKE) -C arceos A=$(A) clean
	@rm -f .axconfig.toml
	@rm -f kernel-rv kernel-la
	@rm -f kernel-rv-qperf kernel-la-qperf
	@rm -f kernel-rv-debug kernel-la-debug
	@rm -f kernel-vf2 kernel-vf2.uimg
	@rm -f kernel-ls2k1000 kernel-ls2k1000.elf
	@rm -f PulseOS_riscv64-qemu-virt.elf PulseOS_riscv64-qemu-virt.bin
	@rm -f PulseOS_loongarch64-qemu-virt.elf PulseOS_loongarch64-qemu-virt.bin
	@rm -f PulseOS_riscv64-qemu-virt-debug.elf PulseOS_loongarch64-qemu-virt-debug.elf
	@rm -f PulseOS_riscv64-visionfive2.elf
	@rm -f PulseOS_loongarch64-ls2k1000.elf PulseOS_loongarch64-ls2k1000.bin
	@rm -f PulseOS_riscv64-qemu-virt-qperf.elf PulseOS_loongarch64-qemu-virt-qperf.elf
	@rm -f disk.img disk-la.img
	@rm -f rootfs-riscv64.img rootfs-loongarch64.img
	@rm -f arceos/disk.img arceos/disk-la.img

defconfig: prepare-tools
	@rm -f .axconfig.toml
	@$(MAKE) -C arceos A=$(A) ARCH=$(ARCH) defconfig

# This target produces the rootfs images used only by preliminary-test flows.
# `all` invokes it automatically only after detecting a preliminary image.
img_all:
	@./build_img.sh all
	@cp rootfs-riscv64.img disk.img
	@cp rootfs-loongarch64.img disk-la.img
	@cp disk.img arceos/disk.img
	@cp disk-la.img arceos/disk-la.img

.PHONY: all submission-build test qperf debug vf2 ls2k1000 build clean defconfig img_all prepare-tools
