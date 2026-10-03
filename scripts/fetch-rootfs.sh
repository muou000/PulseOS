#!/usr/bin/env bash
# Download the PulseOS base rootfs tarballs from the GitHub Release that
# hosts them (they are no longer stored in the git repository). Existing
# files are only verified.
# Usage: scripts/fetch-rootfs.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${REPO_ROOT}/rootfs/base"
mkdir -p "${BASE_DIR}"

REPO="muou000/PulseOS"
TAG="rootfs-base-20260929"
BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"
ALPINE_BASE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/riscv64"

fetch_one() {
    local asset="$1" out="$2" sum="$3" base_url="${4:-${BASE_URL}}"
    if [[ -f "${BASE_DIR}/${out}" ]]; then
        echo "${out} already present, verifying checksum"
    else
        echo "Downloading ${asset} -> rootfs/base/${out}"
        curl -fL --retry 3 -o "${BASE_DIR}/${out}" "${base_url}/${asset}"
    fi
    echo "${sum}  ${BASE_DIR}/${out}" | sha256sum -c -
}

# PulseOS targets riscv64gc-unknown-none-elf and does not save RVV state.
# Use a userland built for RV64GC; the Ubuntu image previously used here
# contains RVV instructions in its dynamic linker and libc.
fetch_one "alpine-minirootfs-3.23.3-riscv64.tar.gz" "alpine-minirootfs-riscv64.tar.gz" \
    "eee00ce9bb795e372d054b059e61c3f2586089227454561c2e0f2fa0454e04c5" \
    "${ALPINE_BASE_URL}"
fetch_one "base-rootfs-loongarch64.tar.xz" "base-rootfs-loongarch64.tar.xz" \
    "3d7768d6c923a7b0fc1b4398ac46dd25a8f298da9daf8006a0e7c52234033752"
# fetch_one "rootfs-riscv64.tar.gz" "base-rootfs-riscv64.tar.gz" \
#     "d63b167e60e1f9b09932645b0e32aa2deca5ae6aba1c29f69b22ca879cfce60b"
