#!/usr/bin/env bash
# Reproducible cross-build script for PulseOS io_uring test suites:
#   - Pinned liburing-2.9 (08468cc3): static liburing.a + 54 Tier A/B static tests
#   - Pinned fio-3.39 (a6e474c9): static fio with io_uring engine (zero liburing dep)
#   - Repo C probes: static tests/io_uring/{smp_stress,sqpoll,syscall_count_bench}.c
#   - Runner staging: tests/io_uring/run_all.sh + MANIFEST.txt
#   - Optional incremental rootfs image injection via scripts/install_to_rootfs.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

LIBURING_REPO="${LIBURING_REPO:-https://github.com/axboe/liburing.git}"
LIBURING_TAG="liburing-2.9"
LIBURING_COMMIT="08468cc3830185c75f9e7edefd88aa01e5c2f8ab"

FIO_REPO="${FIO_REPO:-https://github.com/axboe/fio.git}"
FIO_TAG="fio-3.39"
FIO_COMMIT="a6e474c9e896e4ba1eb40066a03402afb040710a"

ARCH_ARG="all"
COMPONENT="all"
OUTPUT_DIR="${REPO_ROOT}/target/iouring-tests"
SRC_CACHE="${REPO_ROOT}/.tools/iouring-src"
INSTALL_IMG=""
NPROC="$(nproc 2>/dev/null || echo 4)"

TIER_A_TESTS=(
    accept-link.t accept-reuse.t accept-test.t cq-full.t cq-peek-batch.t
    cq-ready.t cq-size.t drop-submit.t fifo-nonblock-read.t file-update.t
    files-exit-hang-poll.t files-exit-hang-timeout.t fixed-buf-iter.t
    fixed-buf-merge.t fixed-link.t fsync.t ignore-single-mmap.t
    io_uring_enter.t io_uring_setup.t link-timeout.t link_drain.t
    nop-all-sizes.t nop.t ooo-file-unreg.t pipe-eof.t pipe-reuse.t
    poll-cancel-all.t poll-cancel-ton.t poll-cancel.t poll-link.t poll-ring.t
    poll.t probe.t rw_merge_test.t short-read.t shutdown.t socket-nb.t
    socket-rw-eagain.t socket-rw.t sq-full.t sq-space_left.t stdout.t
    submit-and-wait.t submit-link-fail.t submit-reuse.t version.t
)

TIER_B_TESTS=(
    connect-rep.t connect.t fpos.t io-cancel.t read-write.t send_recv.t
    socket.t timeout.t
)

usage() {
    cat <<'EOF'
Usage:
  scripts/build_iouring_tests.sh [OPTIONS]

Options:
  --arch ARCH          Target architecture: all (default), riscv64, loongarch64
  --component COMP     What to build: all (default), liburing, fio, tests, runner
  --output-dir DIR     Staging directory (default: target/iouring-tests)
  --src-cache DIR      Git cache directory (default: .tools/iouring-src)
  --install IMAGE      Inject built artifacts into ext4 IMAGE via install_to_rootfs.sh
                       (requires --arch riscv64 or --arch loongarch64)
  -h, --help           Show this help message
EOF
}

die() {
    echo "Error: $*" >&2
    exit 1
}

have_cmd() {
    command -v "$1" >/dev/null 2>&1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --arch)
            [[ $# -ge 2 ]] || die "--arch requires an argument"
            ARCH_ARG="$2"
            shift 2
            ;;
        --component)
            [[ $# -ge 2 ]] || die "--component requires an argument"
            COMPONENT="$2"
            shift 2
            ;;
        --output-dir)
            [[ $# -ge 2 ]] || die "--output-dir requires an argument"
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --src-cache)
            [[ $# -ge 2 ]] || die "--src-cache requires an argument"
            SRC_CACHE="$2"
            shift 2
            ;;
        --install)
            [[ $# -ge 2 ]] || die "--install requires an argument"
            INSTALL_IMG="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "Unknown option: $1 (use --help for usage)"
            ;;
    esac
done

case "${ARCH_ARG}" in
    all|riscv64|loongarch64) ;;
    *) die "Invalid --arch '${ARCH_ARG}' (expected: all, riscv64, loongarch64)" ;;
esac

case "${COMPONENT}" in
    all|liburing|fio|tests|runner) ;;
    *) die "Invalid --component '${COMPONENT}' (expected: all, liburing, fio, tests, runner)" ;;
esac

if [[ -n "${INSTALL_IMG}" ]]; then
    [[ "${ARCH_ARG}" != "all" ]] || die "--install requires a single --arch (riscv64 or loongarch64)"
    [[ -f "${INSTALL_IMG}" ]] || die "Rootfs image not found: ${INSTALL_IMG}"
fi

for cmd in git make readelf awk xargs find; do
    have_cmd "${cmd}" || die "Missing required host tool: ${cmd}"
done

resolve_toolchain() {
    local arch="$1"
    TC_CC=""
    TC_CXX=""
    TC_AR=""
    TC_RANLIB=""
    TC_STRIP=""
    TC_NM=""

    if [[ "${arch}" == "riscv64" ]]; then
        if [[ -n "${CC_RISCV64:-}" ]]; then
            TC_CC="${CC_RISCV64}"
            TC_CXX="${CXX_RISCV64:-riscv64-linux-gnu-g++}"
            TC_AR="${AR_RISCV64:-riscv64-linux-gnu-ar}"
            TC_RANLIB="${RANLIB_RISCV64:-riscv64-linux-gnu-ranlib}"
            TC_STRIP="${STRIP_RISCV64:-riscv64-linux-gnu-strip}"
            TC_NM="${NM_RISCV64:-riscv64-linux-gnu-nm}"
        elif have_cmd riscv64-linux-gnu-gcc; then
            TC_CC="riscv64-linux-gnu-gcc"
            TC_CXX="riscv64-linux-gnu-g++"
            TC_AR="riscv64-linux-gnu-ar"
            TC_RANLIB="riscv64-linux-gnu-ranlib"
            TC_STRIP="riscv64-linux-gnu-strip"
            TC_NM="riscv64-linux-gnu-nm"
        elif [[ -x "${REPO_ROOT}/.tools/riscv64/usr/bin/riscv64-linux-gnu-gcc" ]]; then
            local bin_dir="${REPO_ROOT}/.tools/riscv64/usr/bin"
            export LD_LIBRARY_PATH="${REPO_ROOT}/.tools/riscv64/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
            TC_CC="${bin_dir}/riscv64-linux-gnu-gcc"
            TC_CXX="${bin_dir}/riscv64-linux-gnu-g++"
            TC_AR="${bin_dir}/riscv64-linux-gnu-ar"
            TC_RANLIB="${bin_dir}/riscv64-linux-gnu-ranlib"
            TC_STRIP="${bin_dir}/riscv64-linux-gnu-strip"
            TC_NM="${bin_dir}/riscv64-linux-gnu-nm"
        else
            die "riscv64-linux-gnu-gcc not found (install gcc-riscv64-linux-gnu libc6-dev-riscv64-cross)"
        fi
    else
        if [[ -n "${CC_LOONGARCH64:-}" ]]; then
            TC_CC="${CC_LOONGARCH64}"
            TC_CXX="${CXX_LOONGARCH64:-loongarch64-linux-gnu-g++}"
            TC_AR="${AR_LOONGARCH64:-loongarch64-linux-gnu-ar}"
            TC_RANLIB="${RANLIB_LOONGARCH64:-loongarch64-linux-gnu-ranlib}"
            TC_STRIP="${STRIP_LOONGARCH64:-loongarch64-linux-gnu-strip}"
            TC_NM="${NM_LOONGARCH64:-loongarch64-linux-gnu-nm}"
        elif have_cmd loongarch64-linux-gnu-gcc; then
            TC_CC="loongarch64-linux-gnu-gcc"
            TC_CXX="loongarch64-linux-gnu-g++"
            TC_AR="loongarch64-linux-gnu-ar"
            TC_RANLIB="loongarch64-linux-gnu-ranlib"
            TC_STRIP="loongarch64-linux-gnu-strip"
            TC_NM="loongarch64-linux-gnu-nm"
        elif [[ -x "${REPO_ROOT}/.tools/loongarch64/bin/loongarch64-linux-gnu-gcc" ]]; then
            local bin_dir="${REPO_ROOT}/.tools/loongarch64/bin"
            TC_CC="${bin_dir}/loongarch64-linux-gnu-gcc"
            TC_CXX="${bin_dir}/loongarch64-linux-gnu-g++"
            TC_AR="${bin_dir}/loongarch64-linux-gnu-ar"
            TC_RANLIB="${bin_dir}/loongarch64-linux-gnu-ranlib"
            TC_STRIP="${bin_dir}/loongarch64-linux-gnu-strip"
            TC_NM="${bin_dir}/loongarch64-linux-gnu-nm"
        else
            die "loongarch64-linux-gnu-gcc not found in PATH or .tools/loongarch64/bin"
        fi
    fi

    for tool in "${TC_CC}" "${TC_AR}" "${TC_RANLIB}" "${TC_STRIP}" "${TC_NM}"; do
        have_cmd "${tool}" || [[ -x "${tool}" ]] || die "Missing cross tool: ${tool}"
    done
    if [[ -n "${TC_CXX}" ]] && ! have_cmd "${TC_CXX}" && [[ ! -x "${TC_CXX}" ]]; then
        TC_CXX=""
    fi
}

ensure_pinned_repo() {
    local name="$1" url="$2" tag="$3" expected_commit="$4"
    local repo_dir="${SRC_CACHE}/${name}"
    mkdir -p "${SRC_CACHE}"

    if [[ ! -d "${repo_dir}/.git" ]]; then
        echo "[src] Cloning ${name} (${tag})..."
        git clone --branch "${tag}" --depth 1 "${url}" "${repo_dir}"
    fi

    local actual_commit
    actual_commit="$(git -C "${repo_dir}" rev-parse HEAD)"
    if [[ "${actual_commit}" != "${expected_commit}" ]]; then
        echo "[src] Fetching ${tag} in ${repo_dir}..."
        git -C "${repo_dir}" fetch --depth 1 origin "refs/tags/${tag}:refs/tags/${tag}"
        git -C "${repo_dir}" checkout --detach "${expected_commit}"
        actual_commit="$(git -C "${repo_dir}" rev-parse HEAD)"
    fi
    [[ "${actual_commit}" == "${expected_commit}" ]] \
        || die "${name} commit mismatch: got ${actual_commit}, expected ${expected_commit}"
}

emit_liburing_harness_patch() {
    cat <<'PATCH'
diff --git a/test/connect.c b/test/connect.c
index 71f0e39..786d0ae 100644
--- a/test/connect.c
+++ b/test/connect.c
@@ -371,6 +371,10 @@ static int test(int flags)
 	int ret;
 
 	ret = io_uring_queue_init(8, &ring, flags);
+	if (ret == -EINVAL && (flags & IORING_SETUP_DEFER_TASKRUN)) {
+		fprintf(stdout, "flags 0x%x not supported, skipping\n", flags);
+		return T_EXIT_SKIP;
+	}
 	if (ret) {
 		fprintf(stderr, "io_uring_queue_setup() = %d\n", ret);
 		return T_EXIT_FAIL;
diff --git a/test/send_recv.c b/test/send_recv.c
index f68a158..705ddf1 100644
--- a/test/send_recv.c
+++ b/test/send_recv.c
@@ -93,7 +93,7 @@ static int do_recv(struct io_uring *ring, struct iovec *iov, int enobufs)
 		fprintf(stdout, "wait_cqe: %d\n", ret);
 		return 1;
 	}
-	if (cqe->res == -EINVAL) {
+	if (cqe->res == -EINVAL || cqe->res == -EOPNOTSUPP) {
 		fprintf(stdout, "recv not supported, skipping\n");
 		goto out;
 	}
@@ -134,6 +134,7 @@ struct recv_data {
 	int registerfiles;
 	int async;
 	int provide;
+	int skip;
 };
 
 static void *recv_fn(void *data)
@@ -152,10 +153,12 @@ static void *recv_fn(void *data)
 		p.flags = IORING_SETUP_SQPOLL;
 	ret = t_create_ring_params(1, &ring, &p);
 	if (ret == T_SETUP_SKIP) {
+		rd->skip = 1;
 		pthread_mutex_unlock(&rd->mutex);
 		ret = 0;
 		goto err;
 	} else if (ret < 0) {
+		rd->skip = 1;
 		pthread_mutex_unlock(&rd->mutex);
 		goto err;
 	}
@@ -163,6 +166,7 @@ static void *recv_fn(void *data)
 	if (rd->use_sqthread && !rd->registerfiles) {
 		if (!(p.features & IORING_FEAT_SQPOLL_NONFIXED)) {
 			fprintf(stdout, "Non-registered SQPOLL not available, skipping\n");
+			rd->skip = 1;
 			pthread_mutex_unlock(&rd->mutex);
 			goto err;
 		}
@@ -265,6 +269,7 @@ static int test(int use_sqthread, int regfiles, int async, int provide)
 	rd.registerfiles = regfiles;
 	rd.async = async;
 	rd.provide = provide;
+	rd.skip = 0;
 
 	ret = pthread_create(&recv_thread, NULL, recv_fn, &rd);
 	if (ret) {
@@ -274,7 +279,8 @@ static int test(int use_sqthread, int regfiles, int async, int provide)
 	}
 
 	pthread_mutex_lock(&rd.mutex);
-	do_send();
+	if (!rd.skip)
+		do_send();
 	pthread_join(recv_thread, &retval);
 	return (intptr_t)retval;
 }
diff --git a/test/socket.c b/test/socket.c
index a461a5b..317df3e 100644
--- a/test/socket.c
+++ b/test/socket.c
@@ -120,6 +120,7 @@ struct recv_data {
 	pthread_mutex_t mutex;
 	int use_sqthread;
 	int registerfiles;
+	int skip;
 };
 
 static void *recv_fn(void *data)
@@ -138,10 +139,12 @@ static void *recv_fn(void *data)
 		p.flags = IORING_SETUP_SQPOLL;
 	ret = t_create_ring_params(1, &ring, &p);
 	if (ret == T_SETUP_SKIP) {
+		rd->skip = 1;
 		pthread_mutex_unlock(&rd->mutex);
 		ret = 0;
 		goto err;
 	} else if (ret < 0) {
+		rd->skip = 1;
 		pthread_mutex_unlock(&rd->mutex);
 		goto err;
 	}
@@ -149,6 +152,7 @@ static void *recv_fn(void *data)
 	if (rd->use_sqthread && !rd->registerfiles) {
 		if (!(p.features & IORING_FEAT_SQPOLL_NONFIXED)) {
 			fprintf(stdout, "Non-registered SQPOLL not available, skipping\n");
+			rd->skip = 1;
 			pthread_mutex_unlock(&rd->mutex);
 			goto err;
 		}
@@ -351,6 +355,7 @@ static int test(int use_sqthread, int regfiles, int socket_direct, int alloc)
 	pthread_mutex_lock(&rd.mutex);
 	rd.use_sqthread = use_sqthread;
 	rd.registerfiles = regfiles;
+	rd.skip = 0;
 
 	ret = pthread_create(&recv_thread, NULL, recv_fn, &rd);
 	if (ret) {
@@ -360,7 +365,8 @@ static int test(int use_sqthread, int regfiles, int socket_direct, int alloc)
 	}
 
 	pthread_mutex_lock(&rd.mutex);
-	do_send(socket_direct, alloc);
+	if (!rd.skip)
+		do_send(socket_direct, alloc);
 	pthread_join(recv_thread, &retval);
 	return (intptr_t)retval;
 }
diff --git a/test/timeout.c b/test/timeout.c
index ff44478..85703fa 100644
--- a/test/timeout.c
+++ b/test/timeout.c
@@ -1073,6 +1073,9 @@ static int test_update_multishot_timeouts(struct io_uring *ring, unsigned long m
 	int ret, i, nr = 6;
 	__u32 mode = 0;
 
+	if (no_multishot)
+		return 0;
+
 	msec_to_ts(&ts, base_ms);
 
 	msec_to_ts(&ts_upd, ms);
PATCH
}

apply_liburing_harness_patch() {
    local work_dir="$1"
    emit_liburing_harness_patch | git -C "${work_dir}" apply --check -
    emit_liburing_harness_patch | git -C "${work_dir}" apply -
}

validate_static_elf() {
    local arch="$1" elf="$2"
    local expected_machine header segs
    if [[ "${arch}" == "riscv64" ]]; then
        expected_machine="RISC-V"
    else
        expected_machine="LoongArch"
    fi

    header="$(readelf -h "${elf}" 2>/dev/null)" \
        || die "readelf -h failed on ${elf}"
    grep -q "Machine:.*${expected_machine}" <<< "${header}" \
        || die "ELF architecture mismatch for ${arch} (${elf}): expected ${expected_machine}"

    segs="$(readelf -lW "${elf}" 2>/dev/null)" \
        || die "readelf -lW failed on ${elf}"
    if grep -qw "INTERP" <<< "${segs}"; then
        die "ELF must be statically linked (found PT_INTERP): ${elf}"
    fi
}

validate_riscv_elf_isa() {
    local stage_dir="$1" hit
    hit="$(find "${stage_dir}" -type f -print0 \
        | xargs -0 -r -n 128 -P "${NPROC}" sh -c 'readelf -A "$@" 2>/dev/null || true' _ \
        | awk '
            /^File: / { cur = substr($0, 7) }
            /Tag_RISCV_arch:/ {
                split($0, a, "\"")
                if (a[2] ~ /(^|_)(v[0-9]|zv)/ && found == "") {
                    found = (cur ? cur : "<elf>")
                }
            }
            END { if (found != "") print found }
        ')"
    if [[ -n "${hit}" ]]; then
        die "RISC-V binary requires RVV unsupported by PulseOS: ${hit}"
    fi
}

build_liburing_for_arch() {
    local arch="$1" stage_dir="$2" tmp_build="$3"
    ensure_pinned_repo "liburing" "${LIBURING_REPO}" "${LIBURING_TAG}" "${LIBURING_COMMIT}"

    local work_dir="${tmp_build}/liburing-${arch}"
    rm -rf "${work_dir}"
    cp -a "${SRC_CACHE}/liburing" "${work_dir}"
    git -C "${work_dir}" reset --hard "${LIBURING_COMMIT}" >/dev/null
    git -C "${work_dir}" clean -fdx >/dev/null
    apply_liburing_harness_patch "${work_dir}"
    git -C "${work_dir}" diff --quiet src/ \
        || die "liburing src/ must remain unmodified"

    local cflags="-O2 -Wall"
    local cfg_args=("--cc=${TC_CC}")
    if [[ -n "${TC_CXX}" ]]; then
        cfg_args+=("--cxx=${TC_CXX}")
    fi
    if [[ "${arch}" == "riscv64" ]]; then
        cflags="-O2 -march=rv64gc -mabi=lp64d -Wall"
    else
        cfg_args+=("--use-libc")
    fi

    echo "[${arch}] Configuring liburing (${LIBURING_TAG} @ ${LIBURING_COMMIT:0:8})..."
    (
        cd "${work_dir}"
        CC="${TC_CC}" CXX="${TC_CXX}" CFLAGS="${cflags}" LDFLAGS="-static" \
            ./configure "${cfg_args[@]}"
        echo "[${arch}] Building static liburing.a..."
        make -C src -j"${NPROC}" liburing.a \
            CC="${TC_CC}" AR="${TC_AR}" RANLIB="${TC_RANLIB}" \
            ENABLE_SHARED=0 CFLAGS="${cflags}"
        echo "[${arch}] Building v1 tests and sqpoll-sleep.t..."
        make -C test -j"${NPROC}" "${TIER_A_TESTS[@]}" "${TIER_B_TESTS[@]}" sqpoll-sleep.t \
            CC="${TC_CC}" CXX="${TC_CXX}" \
            CFLAGS="${cflags}" LDFLAGS="-static"
    )

    local out_tests="${stage_dir}/liburing-tests"
    rm -rf "${out_tests}"
    mkdir -p "${out_tests}"

    for t in "${TIER_A_TESTS[@]}" "${TIER_B_TESTS[@]}" sqpoll-sleep.t; do
        local bin="${work_dir}/test/${t}"
        [[ -f "${bin}" ]] || die "Missing built test binary: ${bin}"
        "${TC_STRIP}" "${bin}"
        validate_static_elf "${arch}" "${bin}"
        install -m 0755 "${bin}" "${out_tests}/${t}"
    done

    local cc_ver
    cc_ver="$("${TC_CC}" --version | head -n 1)"
    {
        echo "PulseOS io_uring Compatibility Tier v1 — Static Test Suite Manifest"
        echo "=================================================================="
        echo "Architecture:    ${arch}"
        echo "Toolchain:       ${cc_ver}"
        echo "liburing tag:    ${LIBURING_TAG} (${LIBURING_COMMIT})"
        echo "liburing src/:   UNMODIFIED (git diff --quiet src/ verified)"
        echo "CFLAGS:          ${cflags}"
        echo "LDFLAGS:         -static"
        echo "Tests:           ${#TIER_A_TESTS[@]} Tier A + ${#TIER_B_TESTS[@]} Tier B = $(( ${#TIER_A_TESTS[@]} + ${#TIER_B_TESTS[@]} ))"
        echo ""
        echo "Tier A (${#TIER_A_TESTS[@]} unmodified upstream tests):"
        printf '  %s\n' "${TIER_A_TESTS[@]}"
        echo ""
        echo "Tier B (${#TIER_B_TESTS[@]} core tests with OOS skip tolerance in test/ only):"
        printf '  %s\n' "${TIER_B_TESTS[@]}"
        echo ""
        echo "SQPOLL extension: sqpoll-sleep.t (unmodified upstream test)"
        echo "Exact test/ harness diff:"
        git -C "${work_dir}" diff test/
    } > "${out_tests}/MANIFEST.txt"
}

build_fio_for_arch() {
    local arch="$1" stage_dir="$2" tmp_build="$3"
    ensure_pinned_repo "fio" "${FIO_REPO}" "${FIO_TAG}" "${FIO_COMMIT}"

    local work_dir="${tmp_build}/fio-${arch}"
    rm -rf "${work_dir}"
    cp -a "${SRC_CACHE}/fio" "${work_dir}"
    git -C "${work_dir}" reset --hard "${FIO_COMMIT}" >/dev/null
    git -C "${work_dir}" clean -fdx >/dev/null

    local cfg_args=("--cc=${TC_CC}" "--build-static" "--disable-native")
    if [[ "${arch}" == "riscv64" ]]; then
        cfg_args+=("--extra-cflags=-march=rv64gc -mabi=lp64d")
    fi

    echo "[${arch}] Configuring fio (${FIO_TAG} @ ${FIO_COMMIT:0:8})..."
    (
        cd "${work_dir}"
        ./configure "${cfg_args[@]}"
        echo "[${arch}] Building static fio..."
        make -j"${NPROC}" fio
    )

    local fio_bin="${work_dir}/fio" nm_out
    [[ -f "${fio_bin}" ]] || die "Missing built fio binary: ${fio_bin}"
    nm_out="$("${TC_NM}" "${fio_bin}")"
    grep -q "ioengine_uring" <<< "${nm_out}" \
        || die "Built fio binary lacks ioengine_uring symbol (${arch})"

    "${TC_STRIP}" "${fio_bin}"
    validate_static_elf "${arch}" "${fio_bin}"

    mkdir -p "${stage_dir}/bin"
    install -m 0755 "${fio_bin}" "${stage_dir}/bin/fio"
}

build_custom_tests_for_arch() {
    local arch="$1" stage_dir="$2" tmp_build="$3"
    local cflags=("-O2" "-Wall" "-static")
    if [[ "${arch}" == "riscv64" ]]; then
        cflags+=("-march=rv64gc" "-mabi=lp64d")
    fi

    mkdir -p "${stage_dir}/bin"
    local src_dir="${REPO_ROOT}/tests/io_uring"

    for spec in "smp_stress:-pthread" "sqpoll:-pthread" "syscall_count_bench:"; do
        local name="${spec%%:*}"
        local extra_flag="${spec#*:}"
        local src="${src_dir}/${name}.c"
        local out="${tmp_build}/${name}"
        [[ -f "${src}" ]] || die "Missing C probe source: ${src}"

        local cmd=("${TC_CC}" "${cflags[@]}")
        if [[ -n "${extra_flag}" ]]; then
            cmd+=("${extra_flag}")
        fi
        cmd+=("-o" "${out}" "${src}")
        echo "[${arch}] Building static ${name}..."
        "${cmd[@]}"
        "${TC_STRIP}" "${out}"
        validate_static_elf "${arch}" "${out}"
        install -m 0755 "${out}" "${stage_dir}/bin/${name}"
    done
}

install_runner_for_arch() {
    local stage_dir="$1"
    local src_runner="${REPO_ROOT}/tests/io_uring/run_all.sh"
    [[ -f "${src_runner}" ]] || die "Missing runner script: ${src_runner}"
    mkdir -p "${stage_dir}"
    install -m 0755 "${src_runner}" "${stage_dir}/run_all.sh"
}

install_staged_to_image() {
    local arch="$1" stage_dir="$2" image="$3"
    local installer="${REPO_ROOT}/scripts/install_to_rootfs.sh"
    [[ -x "${installer}" ]] || die "Missing installer script: ${installer}"

    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "fio" ]]; then
        "${installer}" "${image}" "${stage_dir}/bin/fio" /usr/bin/fio
    fi
    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "liburing" ]]; then
        "${installer}" "${image}" "${stage_dir}/liburing-tests" /opt/io_uring/liburing-tests
    fi
    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "tests" ]]; then
        "${installer}" "${image}" "${stage_dir}/bin/smp_stress" /opt/io_uring/smp_stress
        "${installer}" "${image}" "${stage_dir}/bin/sqpoll" /opt/io_uring/sqpoll
        "${installer}" "${image}" "${stage_dir}/bin/syscall_count_bench" /opt/io_uring/syscall_count_bench
    fi
    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "runner" ]]; then
        "${installer}" "${image}" "${stage_dir}/run_all.sh" /opt/io_uring/run_all.sh
    fi
}

ACTIVE_TMP_BUILD=""
cleanup_tmp_build() {
    if [[ -n "${ACTIVE_TMP_BUILD}" && -d "${ACTIVE_TMP_BUILD}" ]]; then
        rm -rf "${ACTIVE_TMP_BUILD}"
    fi
}
trap cleanup_tmp_build EXIT

build_arch() {
    local arch="$1"
    local stage_dir="${OUTPUT_DIR}/${arch}"
    ACTIVE_TMP_BUILD="$(mktemp -d "${TMPDIR:-/tmp}/pulseos-iouring-build-${arch}-XXXXXX")"
    local tmp_build="${ACTIVE_TMP_BUILD}"

    mkdir -p "${stage_dir}"
    resolve_toolchain "${arch}"

    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "liburing" ]]; then
        build_liburing_for_arch "${arch}" "${stage_dir}" "${tmp_build}"
    fi
    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "fio" ]]; then
        build_fio_for_arch "${arch}" "${stage_dir}" "${tmp_build}"
    fi
    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "tests" ]]; then
        build_custom_tests_for_arch "${arch}" "${stage_dir}" "${tmp_build}"
    fi
    if [[ "${COMPONENT}" == "all" || "${COMPONENT}" == "runner" ]]; then
        install_runner_for_arch "${stage_dir}"
    fi

    if [[ "${arch}" == "riscv64" ]]; then
        validate_riscv_elf_isa "${stage_dir}"
        echo "[${arch}] Verified zero RVV ISA tags across ${stage_dir}."
    fi

    if [[ -n "${INSTALL_IMG}" ]]; then
        install_staged_to_image "${arch}" "${stage_dir}" "${INSTALL_IMG}"
    fi

    rm -rf "${tmp_build}"
    ACTIVE_TMP_BUILD=""
    echo "[${arch}] Staging complete under ${stage_dir}"
}

if [[ "${ARCH_ARG}" == "all" ]]; then
    for arch in riscv64 loongarch64; do
        build_arch "${arch}"
    done
else
    build_arch "${ARCH_ARG}"
fi
