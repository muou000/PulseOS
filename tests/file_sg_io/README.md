# Ordinary-file scatter/gather syscall checks (#136)

This freestanding C probe exercises the real Linux syscall boundary on RV64
and LA64. Clang, Rust's bundled rust-lld, debugfs and the selected QEMU are
required. The runner injects the probe into a private image copy and uses the
AGENTS.md SMP=8, 8 GiB snapshot configuration, including RV64's CPU max.
It verifies the source image SHA-256 afterward. Success requires SG_PASS,
completed filesystem writeback, poweroff and QEMU exit status zero. A timeout,
kernel panic, incomplete measurement matrix or failed assertion is a failure.

Build through the repository entry points, enabling the test-only observation
feature for counters and layout-verified benchmarks:

    make test APP_FEATURES="qemu file-io-test" 2>&1 | tail -30
    python3 tests/file_sg_io/run.py --arch riscv64 --suite counts
    python3 tests/file_sg_io/run.py --arch loongarch64 --suite append

Select inputs/output using --kernel, --image, --timeout and --log-dir.
--build-only compiles the probe without building or booting a kernel.
Semantic suites also run on a pristine kernel without the observation feature;
when RESET is supported they additionally check balanced pin ownership through
SNAPSHOT immediately after the target operation.

## Suites

| Suite | Observed behavior |
| --- | --- |
| bench | Warm scalar and 64-iovec read/write, 64 KiB and 256 KiB, natural and verified fragmented buffers |
| small-bench | The four operations on one physically contiguous 4 KiB page |
| append | Four concurrent writers; each writev is one 16 KiB record, with shared and independent file descriptions |
| shared-position | Concurrent ordinary writes preserve record boundaries; concurrent reads consume every record exactly once and advance the shared position |
| semantics | Partial faults and canaries, scalar/vector and shared/positioned operations, v2 offset selection, EOF/zero lengths, APPEND position behavior, O_DIRECT alignment and errno precedence |
| mappings | Ordered overlapping iovecs, fork CoW isolation, and cross-window append from the target file's own initially untouched mmap |
| unmap-race | Concurrent CLONE_VM munmap during read/readv, replacement-frame canaries, returned progress and file-position consistency |
| counts | 88 operations covering shared/positioned scalar/vector I/O, direct I/O, append, multiple windows, and first reads of separate cold file-cache entries |
| backend | Test-only real File/FileIo/CachedFile execution against a controlled backend returning short, zero-progress and error results |
| device-eof | Nonordinary block-device write at a size confirmed by both fstat and the raw image; a nonempty write at EOF returns EIO |

The concurrent-unmap stress varies a bounded delay and records full, partial
and fault outcomes. It deliberately reallocates pages at another virtual
address to detect stale I/O modifying replacement ownership. It is a race
regression, not a proof of all schedules.

## Matched baseline measurements

The fragmented fixture keeps future pages PROT_NONE while enabling one target
page followed by two live filler pages. This prevents the anonymous fault
path's page batch from populating future target pages together. QUERY_LAYOUT
then requires every adjacent target PFN to be nonconsecutive. A fixture that
cannot establish this layout fails. Natural allocations report the actual
discontinuity count; they are not assumed physically contiguous.

Each case warms the file cache, then records five samples of sixteen operations
by default. Samples sum CLOCK_MONOTONIC intervals around actual I/O syscalls.
Rewinds, buffer poisoning, logging and verification are outside those intervals;
the ending clock syscall overhead is included. These are cached QEMU
microbenchmarks, not cold-storage bandwidth claims.

Use the same compiled guest ELF, sample/iteration settings and QEMU version
for base and changed kernels. Run them sequentially without competing QEMU
instances or heavy host jobs:

    python3 tests/file_sg_io/run.py --suite bench --arch riscv64 \
      --kernel records/issue136/baseline/kernel-layout-rv \
      --log-dir records/issue136/base-rv
    python3 tests/file_sg_io/run.py --suite bench --arch riscv64 \
      --kernel kernel-rv --guest-elf records/issue136/base-rv/guest.elf \
      --log-dir records/issue136/new-rv
    python3 tests/file_sg_io/compare.py records/issue136/base-rv/result.json \
      records/issue136/new-rv/result.json --output records/issue136/compare-rv.md

Repeat with --suite small-bench for the contiguous-page control and with
--arch loongarch64 for the other architecture. Preserve benchmark artifacts
when adding semantic tests; --guest-elf freezes the measured program.

command.json records QEMU arguments/version and kernel, guest and source-image
hashes. result.json retains all samples, median/min/max latency, throughput,
operation counters and race outcomes. compare.py rejects failed or mismatched
guest/configuration runs and marks uncontrolled partial natural layouts as
unmatched even if their discontinuity counts happen to be equal.

## Test-only observation contract

The file-io-test feature provides prctl option 0x50534749 (PSGI):

| arg2 | Operation | Other arguments |
| ---: | --- | --- |
| 0 | RESET and select current task | arg3..5 = 0 |
| 1 | SNAPSHOT and assert all selected-task pins released | arg3 = output pointer, arg4 = 40, arg5 = 0 |
| 2 | DISABLE | arg3..5 = 0 |
| 3 | QUERY_LAYOUT | arg3 = page-aligned start, arg4 = page-multiple length, arg5 = 0 |
| 4 | Controlled backend guest checks | arg3..5 = 0 |

SNAPSHOT writes five native u64 fields: version (1), position_acquires,
operations, pin_peak_pages and staged_bytes. A successful snapshot also proves
the test counter observed balanced acquisitions/releases with no active pins.
QUERY_LAYOUT returns the number of adjacent PFN discontinuities.

The counts suite wraps only the target syscall with RESET/SNAPSHOT/DISABLE;
logging and verification happen after DISABLE. It checks one shared-position
acquisition or zero for positioned I/O, one file-operation entry, bounded
pin windows and recorded staging cost. Cold files are injected before boot,
each read only once: this proves a first File-cache lookup, not cold storage.
The existing fadvise DONTNEED implementation is a no-op and is not used.

Both timing kernels need the same read-only QUERY_LAYOUT observation. Apply
only that test hook to an otherwise pristine baseline, retain its patch/hash,
and keep counters disabled during timing. This avoids the baseline procfs
ELOOP failure for pagemap without modifying production procfs behavior.

The optional device-eof suite never writes an existing disk byte. The runner
embeds the selected raw image's exact size; the guest requires a block-device
fstat with that same positive size before issuing a one-byte pwrite at EOF.
Absent a confirmed device, it records SG_SKIP and does not substitute another
write target. The source image remains protected by the private-copy/snapshot
runner and the post-run hash check.
