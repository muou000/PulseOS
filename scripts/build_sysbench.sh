#!/usr/bin/env bash
# Build sysbench (both dynamically and statically linked) for riscv64.
# Produces binaries under target/sysbench/riscv64/.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${REPO_ROOT}/target/sysbench/riscv64"
SRC_DIR="${REPO_ROOT}/tests/sysbench"
DEPS_DIR="${REPO_ROOT}/.tools/sysbench-deps/riscv64"

mkdir -p "${OUTPUT_DIR}" "${DEPS_DIR}"

# 1. Check prerequisite tools
if ! command -v riscv64-linux-gnu-gcc >/dev/null 2>&1; then
    echo "Error: riscv64-linux-gnu-gcc not found." >&2
    echo "Please install via: sudo apt install -y gcc-riscv64-linux-gnu libc6-dev-riscv64-cross" >&2
    exit 1
fi

if ! command -v autoreconf >/dev/null 2>&1; then
    echo "Error: autotools (autoreconf) not found." >&2
    echo "Please install via: sudo apt install -y autoconf automake libtool" >&2
    exit 1
fi

CC="riscv64-linux-gnu-gcc"
NPROC="$(nproc)"

# 2. Build ConcurrencyKit (riscv64) if not cached
if [[ ! -f "${DEPS_DIR}/lib/libck.a" ]]; then
    echo "Building ConcurrencyKit (riscv64)..."
    TMP_CK="$(mktemp -d)"
    (
        cd "${TMP_CK}"
        git clone --depth 1 --branch 0.7.2 https://github.com/concurrencykit/ck.git ck
        cd ck
        # Override host compiler execution check during cross-compilation
        sed -i 's|COMPILER=`./.1 2> /dev/null`|COMPILER=gcc; r=0|' configure
        ./configure \
            --prefix="${DEPS_DIR}" \
            --platform=riscv64 \
            CC="${CC}"
        make -j"${NPROC}"
        make install
    )
    rm -rf "${TMP_CK}"
fi

# 3. Build LuaJIT (PLCT riscv64 port) if not cached
if [[ ! -f "${DEPS_DIR}/lib/libluajit-5.1.a" ]]; then
    echo "Building LuaJIT (riscv64 port)..."
    TMP_LUA="$(mktemp -d)"
    (
        cd "${TMP_LUA}"
        git clone --depth 1 --branch v2.1-riscv64-pr https://github.com/plctlab/LuaJIT.git luajit
        cd luajit
        make -j"${NPROC}" \
            HOST_CC="gcc -m64" \
            CROSS="riscv64-linux-gnu-" \
            TARGET_SYS=Linux || true
        mkdir -p "${DEPS_DIR}/include/luajit-2.1" "${DEPS_DIR}/lib"
        cp src/libluajit.a "${DEPS_DIR}/lib/libluajit-5.1.a"
        cp src/lua.h src/luajit.h src/luaconf.h src/lualib.h src/lauxlib.h "${DEPS_DIR}/include/luajit-2.1/"
    )
    rm -rf "${TMP_LUA}"
fi

# 4. Generate internal lua header files in sysbench source if missing
(
    cd "${SRC_DIR}/src/lua/internal"
    for f in sysbench.lua sysbench.rand.lua sysbench.sql.lua sysbench.cmdline.lua sysbench.histogram.lua; do
        var=$(echo "$f" | sed 's/\./_/g')
        ( echo "unsigned char ${var}[] =" && \
          sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' -e 's/^/  "/g' -e 's/$/\\n"/g' "$f" && \
          echo ";" && \
          echo "size_t ${var}_len = sizeof(${var}) - 1;" ) > "${f}.h"
    done
)

# 5. Configure & Build sysbench
cd "${SRC_DIR}"
if [[ ! -f configure ]]; then
    echo "Running autogen.sh..."
    ./autogen.sh
fi

echo "Configuring sysbench..."
./configure \
    --host=riscv64-linux-gnu \
    --without-mysql \
    --without-pgsql \
    --with-system-luajit \
    --with-system-ck \
    CC="${CC}" \
    CK_CFLAGS="-I${DEPS_DIR}/include" \
    CK_LIBS="-L${DEPS_DIR}/lib -lck" \
    LUAJIT_CFLAGS="-I${DEPS_DIR}/include/luajit-2.1" \
    LUAJIT_LIBS="-L${DEPS_DIR}/lib -lluajit-5.1 -lm -ldl"

echo "Building sysbench..."
make -j"${NPROC}"

echo "Linking static sysbench..."
"${CC}" \
    -Wall -Wextra -O3 -funroll-loops \
    -static -o src/sysbench-static \
    src/sysbench.o src/sb_timer.o src/sb_options.o src/sb_logger.o src/db_driver.o \
    src/sb_histogram.o src/sb_rand.o src/sb_thread.o src/sb_barrier.o src/sb_lua.o \
    src/sb_util.o src/sb_counter.o \
    -L"${DEPS_DIR}/lib" \
    src/tests/fileio/libsbfileio.a src/tests/threads/libsbthreads.a src/tests/memory/libsbmemory.a \
    src/tests/cpu/libsbcpu.a src/tests/mutex/libsbmutex.a \
    -lluajit-5.1 -lck -lpthread -ldl -lm

cp src/sysbench "${OUTPUT_DIR}/sysbench"
cp src/sysbench-static "${OUTPUT_DIR}/sysbench-static"
rm -f src/sysbench-static

echo "Build complete. Artifacts placed in ${OUTPUT_DIR}:"
ls -lh "${OUTPUT_DIR}/sysbench" "${OUTPUT_DIR}/sysbench-static"
