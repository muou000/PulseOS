#!/usr/bin/env bash
# Build lmbench pipe benchmarks (bw_pipe, lat_pipe, lat_syscall) for riscv64.
# Produces statically linked RISC-V 64 binaries under target/lmbench/riscv64/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/target/lmbench/riscv64"
SRC_DIR="${REPO_ROOT}/tests/lmbench/src"

mkdir -p "${OUTPUT_DIR}"

# Locate toolchain
if command -v riscv64-linux-gnu-gcc >/dev/null 2>&1; then
    CC="riscv64-linux-gnu-gcc"
    AR="riscv64-linux-gnu-ar"
elif [[ -x "${REPO_ROOT}/.tools/riscv64/usr/bin/riscv64-linux-gnu-gcc" ]]; then
    CC="${REPO_ROOT}/.tools/riscv64/usr/bin/riscv64-linux-gnu-gcc"
    AR="${REPO_ROOT}/.tools/riscv64/usr/bin/riscv64-linux-gnu-ar"
    export LD_LIBRARY_PATH="${REPO_ROOT}/.tools/riscv64/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
else
    echo "Error: riscv64-linux-gnu-gcc not found." >&2
    echo "Please run: sudo apt install -y gcc-riscv64-linux-gnu libc6-dev-riscv64-cross" >&2
    exit 1
fi

FAKE_RPC="${REPO_ROOT}/.tools/fake_rpc"
if [[ ! -d "${FAKE_RPC}" ]]; then
    mkdir -p "${FAKE_RPC}/rpc"
    cat << 'EOF' > "${FAKE_RPC}/rpc/rpc.h"
#ifndef _RPC_RPC_H
#define _RPC_RPC_H
typedef struct SVCXPRT SVCXPRT;
typedef struct CLIENT CLIENT;
#endif
EOF
    touch "${FAKE_RPC}/rpc/types.h"
fi

FLAGS="-static -O2 -I${FAKE_RPC} -Wno-implicit-function-declaration"

BUILD_TMP="$(mktemp -d)"
cleanup() {
    rm -rf "${BUILD_TMP}"
}
trap cleanup EXIT

echo "Compiling lmbench library objects..."
cd "${SRC_DIR}"
$CC $FLAGS -c lib_timing.c -o "${BUILD_TMP}/lib_timing.o"
$CC $FLAGS -c lib_mem.c -o "${BUILD_TMP}/lib_mem.o"
$CC $FLAGS -c lib_stats.c -o "${BUILD_TMP}/lib_stats.o"
$CC $FLAGS -c lib_debug.c -o "${BUILD_TMP}/lib_debug.o"
$CC $FLAGS -c getopt.c -o "${BUILD_TMP}/getopt.o"
$CC $FLAGS -c lib_sched.c -o "${BUILD_TMP}/lib_sched.o"
$AR cr "${BUILD_TMP}/lmbench.a" "${BUILD_TMP}"/*.o

echo "Linking bw_pipe..."
$CC $FLAGS bw_pipe.c "${BUILD_TMP}/lmbench.a" -o "${OUTPUT_DIR}/bw_pipe" -lm

echo "Linking lat_pipe..."
$CC $FLAGS lat_pipe.c "${BUILD_TMP}/lmbench.a" -o "${OUTPUT_DIR}/lat_pipe" -lm

echo "Linking lat_syscall..."
$CC $FLAGS lat_syscall.c "${BUILD_TMP}/lmbench.a" -o "${OUTPUT_DIR}/lat_syscall" -lm

echo "Built binaries under ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}"
