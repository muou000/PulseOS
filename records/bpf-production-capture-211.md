# Production stack and mapping capture (#211)

The production guest `bpf-record` now prepares source-bound frame-pointer
capture, an initial mapping journal cut and actual build identities before
enabling sources. It disables and drains every source before taking the final
journal cut and saving the authoritative capture. Targets remain independently
running programs selected by their actual TID; the recorder launches no workload.

Software sources default to `--callchain fp`. The current kernel supports a
depth of 32 and a read budget of 512 bytes. Unsupported depths, budgets and
trace-only stack requests fail before resource preparation. An explicit
`--callchain none` requests single-IP records; missing stack capability only
downgrades with `--allow-fallback`, preserving the requested/effective decision.
Repeated CPU/task sources and tracepoints keep independent source identities.

An optional `--kernel-elf FILE` is accepted only when its actual GNU build-id
matches the note retained in the running kernel. Its complete SHA-256 is then
recorded. Protected mapped ELF files obtain SHA and GNU identity from the
producer journal; unknown and known absence of GNU build-id remain distinct.
Names are labels. The collector reads capture identities and verifies supplied
artifact bytes without rewriting the capture or resolving missing identities
from filenames or terminal maps.

## Failure and evidence boundaries

Initial observation failure rolls back before enable. Final journal failure
retains the original initial cut with an unknown final boundary. Source stop
failure, transport loss, bounded export overflow and output failure keep their
actual counters and partial status; a file without a complete trailer is not
accepted as finalized. A synced guest SHA witness is checked after transfer,
artifact collection and analysis.

The mapping lifecycle fixture exercises actual fork/exec, rename, file pgoff,
mremap, unmap/address reuse and exit. Nonleader exec uses the existing stable
task binding gate. Numeric PID/TID allocation currently follows a monotonic
task identity allocator; no forced allocator wrap or numeric reuse is claimed.
Adversarial mapping tests cover reused numeric labels independently.

## Review

### Standards

The first independent review found no hard documented-standard or unsafe
contract violation. It identified two maintenance concerns: repeated context
format switches and duplicated GNU-note decoding. The source layout lookup
was consolidated; artifact decoding is shared across the producer and host.

### Spec

The first independent review found one gate gap: user-only samples could pass
the new stack suite. The mixed workload now must contain an actual kernel-mode
chain of at least three frames, and a regression test rejects its absence.
Follow-up review caught a valid tab-separated journal footer that could reach
an `unwrap`; checked line-bound extraction now shares the scanner's whitespace
rules. Hardlink/symlink report-output regressions also protect the unchanged
capture and candidate ELF files from accidental overwrite.

## Finalization diagnosis

The first real RV mapping and LA stack attempts reached the workload/stop path
but did not save a capture within the observed interval. LA reported 96 real
samples followed by quiescence and no growth. The attempts were interrupted and
are failed evidence, not successful captures.

The public mapping validation seam reproduced 22,017 allocations for the same
803,707-byte journal plus one artifact. Validation now uses the common decoder
without materializing rows. The host debug microbenchmark measured:

| Same input | Allocations | Elapsed observations |
|---|---:|---|
| Materializing validation | 22,017 | 52.33 ms, 43.52 ms |
| Validation-only shared scan | 0 | 30.19 ms, 27.40 ms |

These are two development measurements, not a statistical speedup claim. The
original guest rerun restored actual STOP/SAVED and byte-identical collection,
but revealed that ordinary recorder allocations still saturated the journal:

| Guest rerun before reusable heap | Samples | Journal records | Journal dropped | Capture SHA-256 |
|---|---:|---:|---:|---|
| LA task | 96 | 10,501 | 3,436 | `ab4f1bf77ee012e675ff0ee18d39a201341a4c92b325bcdd7b56f6874b8374cd` |
| RV mapping lifecycle | 1,020 | 12,681 | 45,456 | `a6d4535ba8775d34b4a5914019f9d724d5602be45f3855267c4bf2d87b4e784c` |

The RV mapping gate failed because required lifecycle rows were absent. These
files prove the failure; they are not positive mapping-coverage evidence.

The recorder now reserves a single reusable 512 MiB process heap, with no
per-object mmap/munmap. Reservation is not resident memory: preparation and
post-serialization logs report live and peak buddy allocation separately from
session FD/ring ownership. Exhaustion does not create another arena. Two public
allocator tests cover 8,000 reuse cycles, alignment, disjointness, coalescing,
exhaustion and unsupported layouts, and an independent unsafe review found no
blocking ownership or arithmetic issue.

The before/after LA task cases used identical kernel, fixture and source rootfs
SHA-256 values and the same one-second task-clock workload/period. Both captured
96 samples. Journal bytes fell from 8,388,743 to 175,318 (97.9% reduction), and
journal drops fell from 3,436 to zero; raw capture bytes fell from 8,465,632 to
252,437. This is a metadata-resource result, not a workload speedup claim.

## Final validation and archived inputs

[The evidence bundle](../tests/bpf_record/evidence/211/README.md) contains 28
passing QEMU runs and independent replays, 52 original finalized partial
captures, two actual truncated write-failure files, matching ELF artifacts,
input hashes, scripts and complete logs. Archive members were extracted and
checked against the SHA-256 index. Source disk images and the rebuildable host
analyzer binary are excluded; their hashes remain in each input manifest.

| QEMU architecture | Task samples | Mixed records / sources | Max user / kernel depth | Production mapping records | Positive coverage journal loss |
|---|---:|---:|---:|---:|---:|
| RV64 | 95 | 3,386 / 73 | 6 / 15 | 1,141 | 0 |
| LA64 | 96 | 13,298 / 73 | 6 / 15 | 1,115 | 0 |

Each architecture passed isolated stack task/mixed/installed-shell/signal/exit/
overflow/observation cases, production mapping, real nonleader exec and stop
failure recovery, load/attach/output failure, lifecycle/dup/close, installed
CPU/scheduler/fault workloads, production smoke and benchmark. RV nonleader
exec retained task 60 while numeric TID changed 60 to 57 (48 samples before,
93 after); LA retained task 72 while TID changed 72 to 70 (31 before, 97 after).

The longer LA installed fault workload exhausted the permanent boot journal
after earlier fork/exec churn: 31,840 dropped entries remain in its raw capture
and report. It is a passing control/real-workload gate with partial mapping
coverage, not a positive mapping-coverage result. Every isolated positive
mapping gate rejects journal loss. All captures retain `IncompleteError` and
actual unwind/loss/unknown facts; verified artifacts never upgrade completeness.

Validation logs retain default and BPF-enabled RV64/LA64 `make test` passes,
274 Rust tests passed with three pre-existing native-perf tests ignored,
17 recorder Python tests, 106 sampling Python tests and five build-provenance
tests. Production recorder binaries built for both architectures. A real
4 MiB subprocess transport check also retained every original output byte after
bounding serial control-marker scans; callbacks still receive complete output.

## Three-stage measurements

QEMU 11.1.50 (`v11.1.0-2112-g2a0ac9c8ac`), TCG, eight CPUs, 8 GiB, snapshot
disks; RV uses `-cpu max`. No other QEMU, build or replay ran during either
measurement. Each row is one external 2.5-second CPU workload, with a nominal
one-second attached/detached window and the same compiled nested-function
fixture. Per-source window overlap, system snapshots, FD/ring ownership and
layered losses are in the original result files.

| Architecture | Baseline iterations/s | Loaded-detached iterations/s | Delta vs baseline | Attached iterations/s | Delta vs baseline |
|---|---:|---:|---:|---:|---:|
| RV64 | 1,042.691 | 1,027.719 | -1.44% | 1,018.703 | -2.30% |
| LA64 | 1,479.073 | 1,539.165 | +4.06% | 1,504.976 | +1.75% |

Attached LA is 2.22% below loaded-detached. These single-run, whole-workload
observations include preparation/teardown margins and approximately 40%
sampling overlap; they do not demonstrate steady-state improvement, a lossless
sampler or an overhead threshold. Nonzero timer/skipped/cancelled counters keep
their overlapping system/source scopes and are not added into one loss total.
