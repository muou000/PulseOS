#!/usr/bin/env bash
# Fetch checksum-pinned rootfs archives and test suites for the target platform.
# Usage: scripts/fetch-rootfs.sh [--tests|--base] [--arch all|riscv64|loongarch64]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_DIR="${REPO_ROOT}/rootfs/base"
mkdir -p "${BASE_DIR}"
source "${REPO_ROOT}/scripts/rootfs-archives.sh"

BASE_TAG="rootfs-base-20260929"
TESTS_TAG="rootfs-tests-20261120"
BASE_URL="${release_url}/${BASE_TAG}"
TESTS_URL="${release_url}/${TESTS_TAG}"
ALPINE_BASE_URL="https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/riscv64"

RISCV_PLATFORM="${RISCV_PLATFORM:-qemu-virt}"
VARIANT="${ROOTFS_VARIANT:-tests}"
ARCH_FILTER="${ARCH_FILTER:-all}"

usage() {
    cat << 'EOF'
Usage:
  scripts/fetch-rootfs.sh [--tests|--base] [--arch all|riscv64|loongarch64]

Options:
  --tests          Fetch the test rootfs, bundled benchmark suites, RocksDB
                   tools and (for QEMU targets) network and memory workloads (default).
  --base           Fetch minimal base rootfs tarballs without bundled tests.
  --arch ARCH      Target architecture to fetch: all (default), riscv64, loongarch64.
  -h, --help       Show this help message.

Env:
  RISCV_PLATFORM   riscv64 platform: qemu-virt (Ubuntu 26.10) or visionfive2 (RV64GC)
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

case "${RISCV_PLATFORM}" in
    qemu-virt|visionfive2) ;;
    *) echo "Error: unknown RISCV_PLATFORM '${RISCV_PLATFORM}'" >&2; exit 1 ;;
esac

if [[ "${ARCH_FILTER}" != loongarch64 && "${RISCV_PLATFORM}" == qemu-virt ]]; then
    fetch_one "${rv_ubuntu}" "${rv_ubuntu}" "${rv_ubuntu_sha}" \
        "https://cdimage.ubuntu.com/ubuntu-base/releases/26.10/release"
fi

if [[ "${VARIANT}" == "tests" ]]; then
    if [[ "${ARCH_FILTER}" == "all" || "${ARCH_FILTER}" == "riscv64" ]]; then
        if cached="$(riscv_test_archive)"; then
            echo "Verified ${cached}"
        else
            fetch_one "${rv_tests_asset}" "${rv_tests_cache}" "${rv_tests_sha}" "${TESTS_URL}"
        fi
        "${REPO_ROOT}/scripts/rootfs-rocksdb.sh" fetch riscv64
        if [[ "${RISCV_PLATFORM}" == qemu-virt ]]; then
            fetch_qemu_test_overlays riscv64
        fi
    fi
    if [[ "${ARCH_FILTER}" == "all" || "${ARCH_FILTER}" == "loongarch64" ]]; then
        fetch_one "rootfs-tests-loongarch64.tar.xz" "rootfs-tests-loongarch64.tar.xz" \
            "e530f99e806cea640df12c482b63128af3131c304cdfd0d5053e661e2efbac1e" \
            "${TESTS_URL}"
        "${REPO_ROOT}/scripts/rootfs-rocksdb.sh" fetch loongarch64
        fetch_qemu_test_overlays loongarch64
    fi
else
    if [[ "${ARCH_FILTER}" != loongarch64 && "${RISCV_PLATFORM}" == visionfive2 ]]; then
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
