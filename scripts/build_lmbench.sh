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
TOOL_DIR="${REPO_ROOT}/.tools/riscv64"
FAKE_RPC="${REPO_ROOT}/.tools/fake_rpc"

if [[ ! -d "${TOOL_DIR}" || ! -f "${TOOL_DIR}/usr/bin/riscv64-linux-gnu-gcc-13" ]]; then
    echo "Downloading riscv64 toolchain into .tools/riscv64..."
    mkdir -p "${TOOL_DIR}"
    TMP_DL="$(mktemp -d)"
    (
        cd "${TMP_DL}"
        apt-get download \
            gcc-13-riscv64-linux-gnu \
            cpp-13-riscv64-linux-gnu \
            binutils-riscv64-linux-gnu \
            libc6-dev-riscv64-cross \
            libc6-riscv64-cross \
            linux-libc-dev-riscv64-cross \
            libgcc-13-dev-riscv64-cross
        for f in *.deb; do dpkg -x "$f" "${TOOL_DIR}"; done
    )
    rm -rf "${TMP_DL}"
fi

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

export LD_LIBRARY_PATH="${TOOL_DIR}/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
CC="${TOOL_DIR}/usr/bin/riscv64-linux-gnu-gcc-13"
FLAGS="-B${TOOL_DIR}/usr/libexec/gcc-cross/riscv64-linux-gnu/13/ \
-B${TOOL_DIR}/usr/lib/gcc-cross/riscv64-linux-gnu/13/ \
-B${TOOL_DIR}/usr/riscv64-linux-gnu/bin/ \
-L${TOOL_DIR}/usr/riscv64-linux-gnu/lib \
-I${FAKE_RPC} \
-I${TOOL_DIR}/usr/riscv64-linux-gnu/include \
-static -O2 -Wno-implicit-function-declaration"

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
ar cr "${BUILD_TMP}/lmbench.a" "${BUILD_TMP}"/*.o

echo "Linking bw_pipe..."
$CC $FLAGS bw_pipe.c "${BUILD_TMP}/lmbench.a" -o "${OUTPUT_DIR}/bw_pipe" -lm

echo "Linking lat_pipe..."
$CC $FLAGS lat_pipe.c "${BUILD_TMP}/lmbench.a" -o "${OUTPUT_DIR}/lat_pipe" -lm

echo "Linking lat_syscall..."
$CC $FLAGS lat_syscall.c "${BUILD_TMP}/lmbench.a" -o "${OUTPUT_DIR}/lat_syscall" -lm

echo "Built binaries under ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}"
