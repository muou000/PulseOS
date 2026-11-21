#!/usr/bin/env bash
# Download the PulseOS rootfs tarballs from GitHub Releases (or upstream Alpine
# for the minimal RISC-V base variant). Existing files are checksum-verified.
# Usage: scripts/fetch-rootfs.sh [--tests|--base] [--arch all|riscv64|loongarch64]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${REPO_ROOT}/rootfs/base"
mkdir -p "${BASE_DIR}"

REPO="muou000/PulseOS"
BASE_TAG="rootfs-base-20260929"
TESTS_TAG="rootfs-tests-20261120"
BASE_URL="https://github.com/${REPO}/releases/download/${BASE_TAG}"
TESTS_URL="https://github.com/${REPO}/releases/download/${TESTS_TAG}"
ALPINE_BASE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/riscv64"

VARIANT="${ROOTFS_VARIANT:-tests}"
ARCH_FILTER="${ARCH_FILTER:-all}"

usage() {
    cat << 'EOF'
Usage:
  scripts/fetch-rootfs.sh [--tests|--base] [--arch all|riscv64|loongarch64]

Options:
  --tests          Fetch Ubuntu/Loongnix rootfs tarballs bundled with lmbench,
                   ltp, sysbench, unixbench, fio, and liburing-tests (default).
  --base           Fetch minimal base rootfs tarballs without bundled tests.
  --arch ARCH      Target architecture to fetch: all (default), riscv64, loongarch64.
  -h, --help       Show this help message.

Env:
  ROOTFS_VARIANT   Same as --tests / --base (tests or base; default: tests)
  ARCH_FILTER      Same as --arch (all, riscv64, loongarch64; default: all)
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --tests)
            VARIANT="tests"
            shift
            ;;
        --base)
            VARIANT="base"
            shift
            ;;
        --arch)
            [[ $# -ge 2 ]] || { echo "Error: --arch requires an argument" >&2; exit 1; }
            ARCH_FILTER="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Error: Unknown option: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
done

case "${VARIANT}" in
    tests|base) ;;
    *)
        echo "Error: Invalid ROOTFS_VARIANT='${VARIANT}' (expected: tests or base)" >&2
        exit 1
        ;;
esac

case "${ARCH_FILTER}" in
    all|riscv64|loongarch64) ;;
    *)
        echo "Error: Invalid arch '${ARCH_FILTER}' (expected: all, riscv64, or loongarch64)" >&2
        exit 1
        ;;
esac

fetch_one() {
    local asset="$1" out="$2" sum="$3" base_url="$4"
    if [[ -f "${BASE_DIR}/${out}" ]]; then
        echo "${out} already present, verifying checksum"
    else
        echo "Downloading ${asset} -> rootfs/base/${out}"
        curl -fL --retry 3 -o "${BASE_DIR}/${out}.tmp" "${base_url}/${asset}"
        mv -f "${BASE_DIR}/${out}.tmp" "${BASE_DIR}/${out}"
    fi
    echo "${sum}  ${BASE_DIR}/${out}" | sha256sum -c -
}

if [[ "${VARIANT}" == "tests" ]]; then
    if [[ "${ARCH_FILTER}" == "all" || "${ARCH_FILTER}" == "riscv64" ]]; then
        fetch_one "rootfs-tests-riscv64.tar.xz" "rootfs-tests-riscv64.tar.xz" \
            "1a95dc30d246a71e6d8a79d52d75e4942c6a958687ca289c7067ead258066285" \
            "${TESTS_URL}"
    fi
    if [[ "${ARCH_FILTER}" == "all" || "${ARCH_FILTER}" == "loongarch64" ]]; then
        fetch_one "rootfs-tests-loongarch64.tar.xz" "rootfs-tests-loongarch64.tar.xz" \
            "e530f99e806cea640df12c482b63128af3131c304cdfd0d5053e661e2efbac1e" \
            "${TESTS_URL}"
    fi
else
    # PulseOS targets riscv64gc-unknown-none-elf and does not save RVV state.
    # Use a minimal userland built for RV64GC.
    if [[ "${ARCH_FILTER}" == "all" || "${ARCH_FILTER}" == "riscv64" ]]; then
        fetch_one "alpine-minirootfs-3.23.3-riscv64.tar.gz" "alpine-minirootfs-riscv64.tar.gz" \
            "eee00ce9bb795e372d054b059e61c3f2586089227454561c2e0f2fa0454e04c5" \
            "${ALPINE_BASE_URL}"
    fi
    if [[ "${ARCH_FILTER}" == "all" || "${ARCH_FILTER}" == "loongarch64" ]]; then
        fetch_one "base-rootfs-loongarch64.tar.xz" "base-rootfs-loongarch64.tar.xz" \
            "3d7768d6c923a7b0fc1b4398ac46dd25a8f298da9daf8006a0e7c52234033752" \
            "${BASE_URL}"
    fi
fi
