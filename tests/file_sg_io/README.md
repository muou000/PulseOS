# Ordinary-file scatter/gather syscall checks (#136)

The freestanding C probe uses the real Linux syscall boundary on RV64 and LA64.
The runner compiles it using Clang and Rust's bundled rust-lld, injects it into
a private image copy, and uses the prescribed SMP=8, 8 GiB QEMU snapshot setup.
It verifies the source image SHA-256 after the guest exits. Passing requires
SG_PASS, completed filesystem writeback, poweroff and QEMU exit status zero.
A timeout is a failure.

Build the kernel using the repository entry points. Example invocations:

    python3 tests/file_sg_io/run.py --arch riscv64 --suite bench
    python3 tests/file_sg_io/run.py --arch loongarch64 --suite append

Select inputs/output using --kernel, --image, --timeout and --log-dir.
--build-only compiles the guest without building or booting a kernel.

## Matched baseline measurements

The matrix covers scalar read/write and 64-iovec readv/writev, 64 KiB and
256 KiB requests, and natural versus deliberately fragmented anonymous buffers.
The fragmented fixture faults each target page between two live filler pages,
then uses test-only PSGI QUERY_LAYOUT: every adjacent target PFN must be nonconsecutive.
Failure to establish that layout is a fixture failure. The natural allocation
reports its observed PFN discontinuities; it is physically contiguous only when
that count is zero.

Cases warm the file cache, then record five samples of sixteen operations by
default. Each sample sums CLOCK_MONOTONIC intervals around the actual I/O
syscalls. Rewinds, logging and verification are outside the intervals; the
interval includes the ending clock syscall overhead. These are cached QEMU
microbenchmarks, not cold-storage bandwidth claims.

Reuse the same compiled guest ELF with the base and changed kernels, and run
them sequentially to avoid competing for host CPU time:

    python3 tests/file_sg_io/run.py --suite bench --arch riscv64 \
      --kernel records/issue136/baseline/kernel-rv --log-dir records/issue136/base-rv
    python3 tests/file_sg_io/run.py --suite bench --arch riscv64 \
      --kernel kernel-rv --guest-elf records/issue136/base-rv/guest.elf \
      --log-dir records/issue136/new-rv

command.json records QEMU arguments/version and kernel, guest and source-image
hashes. result.json retains every sample and median/min/max latency and median
throughput per case. Preserve sample/iteration options when reusing a guest;
verify hashes and layout observations before comparing.

## Initial behavioral slice

The append suite releases four forked children together. Each appends forty
16 KiB records with one 64-segment writev per record. It covers an inherited
shared file description and independent opens, then checks every byte, each
writer's record count, file size and record boundaries. An interleaved segment
is an assertion failure. This is the first red/green behavioral slice.

Test-only operation counters are separate from baseline timing. The planned
file-io-test feature uses prctl option 0x50534749 with RESET, SNAPSHOT, DISABLE and QUERY_LAYOUT
scoped to the initiating task, so unrelated tasks cannot pollute measurements.

Both timing kernels must enable file-io-test with the same observation hook.
The pristine baseline needs only the read-only QUERY_LAYOUT hook, not the SG
implementation. The benchmark never RESETs counters. QUERY_LAYOUT uses arg2=3,
arg3=page-aligned start, arg4=page-multiple length and arg5=0, and returns the
number of adjacent PFN discontinuities. This avoids the existing baseline
ELOOP failure when opening either /proc/self/pagemap or /proc/1/pagemap.
