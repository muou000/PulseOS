#!/bin/sh
# Run the full 54-test liburing-2.9 compatibility tier v1 suite on PulseOS.
# Usage: /opt/io_uring/run_all.sh [TEST_DIR]
set -u

RAW_TEST_DIR="${1:-/opt/io_uring/liburing-tests}"
if [ ! -d "${RAW_TEST_DIR}" ]; then
    echo "Error: test directory not found: ${RAW_TEST_DIR}" >&2
    exit 1
fi
TEST_DIR="$(cd "${RAW_TEST_DIR}" && pwd)" || exit 1
# Must live on ext4 (not tmpfs /tmp) so O_DIRECT tests exercise real block I/O.
WORK_ROOT="${IO_URING_WORK_DIR:-/root/iouring-run-work}"

TIER_A="
accept-link.t
accept-reuse.t
accept-test.t
cq-full.t
cq-peek-batch.t
cq-ready.t
cq-size.t
drop-submit.t
fifo-nonblock-read.t
file-update.t
files-exit-hang-poll.t
files-exit-hang-timeout.t
fixed-buf-iter.t
fixed-buf-merge.t
fixed-link.t
fsync.t
ignore-single-mmap.t
io_uring_enter.t
io_uring_setup.t
link-timeout.t
link_drain.t
nop-all-sizes.t
nop.t
ooo-file-unreg.t
pipe-eof.t
pipe-reuse.t
poll-cancel-all.t
poll-cancel-ton.t
poll-cancel.t
poll-link.t
poll-ring.t
poll.t
probe.t
rw_merge_test.t
short-read.t
shutdown.t
socket-nb.t
socket-rw-eagain.t
socket-rw.t
sq-full.t
sq-space_left.t
stdout.t
submit-and-wait.t
submit-link-fail.t
submit-reuse.t
version.t
"

TIER_B="
connect-rep.t
connect.t
fpos.t
io-cancel.t
read-write.t
send_recv.t
socket.t
timeout.t
"

cleanup() {
    rm -rf "${WORK_ROOT}"
}
trap cleanup EXIT

rm -rf "${WORK_ROOT}"
mkdir -p "${WORK_ROOT}" || exit 1

passed=0
skipped=0
failed=0
total=0
skipped_list=""
failed_list=""

for test in ${TIER_A} ${TIER_B}; do
    total=$((total + 1))
    bin="${TEST_DIR}/${test}"
    if [ ! -x "${bin}" ]; then
        echo "FAIL ${test} missing_or_not_executable=${bin}" >&2
        failed=$((failed + 1))
        failed_list="${failed_list} ${test}(missing)"
        continue
    fi

    case_name="${test%.t}"
    case_dir="${WORK_ROOT}/${case_name}"
    rm -rf "${case_dir}"
    mkdir -p "${case_dir}" || exit 1

    (
        cd "${case_dir}" || exit 1
        "${bin}"
    )
    rc=$?
    rm -rf "${case_dir}"

    if [ "${rc}" -eq 0 ]; then
        passed=$((passed + 1))
        echo "PASS ${test} rc=0"
    elif [ "${rc}" -eq 77 ] && [ "${test}" = "ooo-file-unreg.t" ]; then
        # ADR-0008 / #228 s2.6: IORING_REGISTER_FILES2 returns -EINVAL; upstream test returns T_EXIT_SKIP (77).
        skipped=$((skipped + 1))
        skipped_list="${skipped_list} ${test}(rc=77)"
        echo "SKIP ${test} rc=77"
    else
        failed=$((failed + 1))
        failed_list="${failed_list} ${test}(rc=${rc})"
        echo "FAIL ${test} rc=${rc}"
    fi
done

echo "IO_URING_LIBURING_SUMMARY passed=${passed} skipped=${skipped} failed=${failed} total=${total}"
if [ -n "${skipped_list}" ]; then
    echo "SKIPPED_TESTS:${skipped_list}"
fi
if [ "${failed}" -ne 0 ] || [ "$((passed + skipped))" -ne 54 ]; then
    echo "FAILED_TESTS:${failed_list}" >&2
    exit 1
fi
exit 0
