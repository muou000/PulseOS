# Page-fault I/O classification acceptance (#196)

Date: 2026-11-15. Base: `88c0a79115100ab3a5350100c062857fb39d6b69`.
Implementation: `54aa80d5`; review correction: `09a11168`.

## Behavior

Actual target-page data-read evidence now travels from Ext4Disk through
ext4plus, VFS, the page cache, prepared mapping and resolver to the unchanged
ID8/v1/80-byte completion. Successful anonymous, COW and verified cache-only
resolutions become minor; completed target storage reads become major.
Unverified reads remain Unknown. Error outcomes remain separate, and canceled
or nonreturning resolvers do not create successful completions.

[Semantics and Linux comparison](../docs/research/page-fault-io-classification.md)
define waiter behavior, retry accumulation, target-window intersections,
backend coverage and separate diagnostic scopes. A cached target may return a
one-page batch instead of filling optional neighbors. The guest explicitly
faults the still-cold neighbor afterward to verify it owns its own major fault.

## Before and after

The archived baseline kernel actually produced 263 completions and valid
Unknown captures. The independent oracle rejected its classifications while
observing eight target sectors during the cold read and zero during hot/COW
phases. The baseline is preserved, not reconstructed with synthetic events.

The final gate pauses the real guest at each workload boundary. The host saves
QEMU VirtIO request/completion trace cursors before acknowledging progress.
`debugfs bmap` binds fixture pages to device sectors. Neither the emitted class
nor wall time supplies the oracle. RAW bytes, capture records, report groups
and success/error totals must agree independently.

| Guest case | RV64 / LA64 class | Completed fixture-sector reads |
|---|---|---:|
| Anonymous first touch | minor | 0 |
| Cold file target | major | 8 target |
| Hot file remapping | minor | 0 |
| Private-file COW write | minor | 0 |
| Cached target with cold optional neighbor | minor | 0 |
| Separate cold-neighbor first touch | major | 8 neighbor |

Each accepted architecture capture has 264 RAW/normalized records: 262 minor,
2 major, no Unknown or unsuccessful records. The existing isolated anonymous
workload contributes 128 exact-address read and 128 write hits. Captures remain
`IncompleteError` under their existing completeness/diagnostic contract; known
classification does not upgrade overall capture integrity. The runs do not
qualify performance overhead because host build/test activity was concurrent.

[Evidence bundles](../tests/bpf_sampling/evidence/196/README.md) retain the
baseline and both positive runs, matching kernel ELF/build provenance, guest
binaries and source snapshots, fixture bytes/sector maps, device traces,
boundary cursors, original serial logs, captures and analyzer reports. The index
records SHA-256 for archives and each member. Replay verifies these hashes,
safe archive members, RAW-to-capture equivalence and the positive device oracle.
The baseline replay checks its Unknown records and saved rejection; its original
device oracle is archived separately rather than rerun by the index verifier.
`validation.tar.gz` and `validation-index.json` separately retain build/test
logs, both raw6 runs and boot kernels, their source/binaries, default build
provenance, the isolated reader harness, and the rejected LA serial-boundary
run. Every member was read back and checked against its indexed SHA-256.

## Build and test gates

```bash
make test APP_FEATURES=qemu,bpf-trace,mapping-lifecycle-test 2>&1 | tail -30
make test 2>&1 | tail -30
cargo test -p pulse_bpf_schema -p bpf-capture -p bpf-analyzer -p pulse_syscalls -- --test-threads=1
cargo test -p bpf-analyzer --test perf_export_tests -- --ignored --test-threads=1
cargo check -p bpf-capture --no-default-features --features alloc
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
python3 -m unittest discover -s tests/bpf_smoke -p 'test_*.py'
python3 -m unittest discover -s tests/bpf_record -p 'test_*.py'
python3 -m unittest discover -s tests/mapped_lifecycle -p 'test_*.py'
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode fault --archive --fault-classes --timeout 240
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode fault --archive --fault-classes --timeout 240
```

- Host: 460 ordinary Rust tests plus all three optional native Linux perf
  consumer tests; capture no_std check. Python: 101 sampling/import/oracle,
  15 compatibility, 8 recorder and 10 mapped-lifecycle harness tests.
- Both guests run all 20 kernel mapping/cache/shutdown checks, including
  unsupported and failed sources, stale same-VA replacement, canceled prepared
  mappings, deterministic concurrent fill owner/waiter, cancel/error/retry,
  cache-generation retry, and independently counted mixed block-cache I/O.
  The counted in-memory driver proves propagation, not physical storage I/O.
- Existing raw6 mapping/filesystem guest suite: shared alias/readback, private
  COW, fork/pipe shared/private mappings, partial unmap, fixed replacement and
  msync/read-only errors. Both architectures pass all six functional cases.
  The suite's two explicit unsupported cases remain skips; raw6 does not prove
  all concurrent checkpoint or remote-CPU TLB interleavings.
- Default initialized filesystem/DMA/writeback/cache regression assertions
  remain enabled during the guest boots.

Raw6 uses `tests/mapped_lifecycle/run.py build-raw --arch ARCH` on each target.
RV runs with `--primary disk.img --secondary disk.img --suite raw6`; LA uses
`--primary disk-la.img --secondary disk-la.img --suite raw6` and the separately
built `--bootstrap tests/mapped_lifecycle/build/loongarch64/bootstrap.elf`.
Images are copied and QEMU uses snapshot disks. The RV image has a real
`/bin/sh`, so the older harness's `/usr/bin/sh` bootstrap assumption is not
used. The first failed bootstrap setup was an image-layout mismatch.

Two host-only test routes remain unavailable in the existing baseline:
`cargo test -p axmm --lib` hits x86_64 0.15.4's missing nightly `Step` methods;
the ext4plus unit target references six absent vendor `test_data` fixtures.
The required RV/LA builds and initialized kernel lifecycle checks exercise
these modified kernel paths instead. An isolated public Ext4Read harness also
checks unknown defaults and Arc forwarding; it is protocol-only evidence.

The first new resolver check failed to compile before the API existed.
Schema, report, importer and oracle tests recorded independent red/green
failures. In addition to the old Unknown kernel rejection, validation exposed
and fixed a stale available-field parser and an importer accepting only
Unknown. A real LA serial chunk split a timestamp; the oracle rejected its
prematurely acknowledged boundary. A regression now requires the complete
newline-terminated marker before acknowledgment, and the original rejected
run is retained separately from the accepted rerun.
An intermediate build was correctly rejected when HEAD changed
during provenance collection; final builds use stable source snapshots.

## Review

Standards review: no documented-rule violation; one optional duplicated
evidence-precedence observation. The cache now converts backend facts once and
uses `FilePageIo::combine`, preserving ADR-0004's dependency direction. Follow-up
review confirms no remaining Standards finding.

Spec review: no actionable mismatch. Sparse-file, extent-split and journal-remap
provenance branches were inspected but have no dedicated case in the new
six-case physical-device fixture. They remain explicit coverage limits, along
with physical boards, unsupported backends, swap, OOM and every process-exit
interleaving. Map #180 must retain those gaps. No universal Rust soundness or
Linux major/minor counter-parity claim is made.
The final follow-up review also passes the newline regression and replays both
indexed architecture bundles with all six device cases and 20 lifecycle checks.
