# Necessary dependencies for the build system.
#
# This repository is designed to work offline. Required helper tools must be
# available in PATH before entering the ArceOS build, typically via the top-level
# `make prepare-tools` target and the wrapper scripts in `bin/`.

ifeq ($(shell command -v cargo-axplat >/dev/null 2>&1 && echo y),)
  $(error missing required tool "cargo-axplat" in PATH)
endif

ifeq ($(shell command -v axconfig-gen >/dev/null 2>&1 && echo y),)
  $(error missing required tool "axconfig-gen" in PATH)
endif

ifeq ($(shell command -v rust-objcopy >/dev/null 2>&1 && echo y),)
  $(error missing required tool "rust-objcopy" in PATH)
endif

ifeq ($(shell command -v rust-objdump >/dev/null 2>&1 && echo y),)
  $(error missing required tool "rust-objdump" in PATH)
endif
