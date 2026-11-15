# Unified guest recorder acceptance (#195)

Date: 2026-11-15. Base: `cb2afb09f0313fec24eb94d637c1e5a728919091`.
Implementation: `30953838`; reviewed lifetime/error corrections: `78f1a8d6`.

## Delivered behavior

`tools/bpf-record` is a standalone RV64/LA64 guest executable. Runtime CLI
selection controls existing TIDs, actual online CPUs, CPU/task clocks, the full
scheduler group, fault completion, duration, nominal period/frequency, ring and
retention budgets, and output path. Repeated events produce independent source
instances. Invalid combinations fail before enable. Hardware-cycle fallback
requires explicit permission and retains the changed units and reason.

All maps, sinks, programs, sources and links are prepared disabled. The recorder
then saves each source's actual enable/disable window, waits for accepted VM
work, drains, and checks that output no longer grows. Reverse teardown is
checked against owned FD/mapping counts, process event/program rows and actual
system registry/subscription counts, including a settled snapshot.

Each program stamps version/kind/length/source in a RAW envelope. Capture v5
persists a required source table and one source binding per normalized record.
`PBSRC002` adds stable task identity; old `PBSRC001` remains readable with that
identity unknown. A nonleader exec changing numeric TID does not retarget or
prematurely stop the source. Control failures save a valid partial file when
the boundary is recovered; otherwise original records survive in an explicitly
unfinished prefix without a trailer. Unknown stop times are never invented.

## Verification

- Enabled and default `make test` both pass for RV64/LA64, with build provenance.
- Production guest binaries link on both architectures; capture no_std checks
  pass for both targets.
- Rust: 460 ordinary tests plus all 3 optional native Linux perf consumer tests
  pass. Python: 90 sampling/analyzer, 15 compatibility routing and 8 recorder
  tests pass.
- Both full guest matrices pass: 12 analyzable captures per architecture,
  rejected CLI requests, second load/attach failures, SIGINT/SIGTERM, target exit,
  dup/close, 4 KiB retention overflow, and an actual failed write leaving exactly
  1024 original bytes without a trailer. The final analyzer rejects that prefix.
- Both recovery matrices pass: task sampling, actual nonleader exec, and actual
  rejected stop ioctl followed by successful cleanup and persisted partial data.
- Image-installed `sh/dd/sleep` passes CPU, scheduler and fault capture on both
  architectures. An independent timeline check ties records to the actual
  shell/exec TIDs, rather than accepting events produced only by the recorder.
- The deterministic pending-fault gate rejects an old entry generation after
  disable/re-enable. The existing accepted-VM test proves that disable cannot
  hide a still-running invocation. VM inflight=0 is not resolver completion.
- Existing separate task-mode guests pass on both architectures: RV64 has 65
  main samples, Link-preserved 21 and ioctl-dup-preserved 23; LA64 has 70, 23 and
  24 respectively. Closing/detaching the final owner produces no growth.

Actual nonleader exec evidence:

| Architecture | Requested TID → post-exec TID | Bound task ID | Samples before / after exec |
|---|---|---:|---:|
| RV64 | 59 → 57 | 59 | 35 / 100 |
| LA64 | 74 → 72 | 74 | 32 / 100 |

In both runs source disable starts after the post-exec workload completes, and
the recorded stop reason is target-exit. A living re-bound target is not treated
as an exited numeric TID.

Existing image workload evidence (all-CPU collection also includes other tasks):

| Architecture | CPU records / attributed | Scheduler records / attributed | Fault records / attributed |
|---|---:|---:|---:|
| RV64 | 857 / 60 | 1562 / 36 | 1424 / 649 |
| LA64 | 809 / 54 | 1584 / 37 | 1424 / 793 |

The eight positive runs contain **38 captures and 43,633 records**. Every
capture has been extracted from its archived original serial transfer and
replayed through the final analyzer. The separate legacy FD lifecycle runs and
three rejected transport/cleanup attempts are also retained.

[Evidence bundles and per-file SHA-256](../tests/bpf_record/evidence/195/README.md)
include exact boot kernels, guest executables, scripts, captures, raw logs,
reports and measurement inputs. Initial full-run benchmark data is not used
for qualification; the revised dedicated benchmark runs supply all three
phases' measured resource/loss snapshots.

## Measured three-stage comparison

Each row is one 2.5-second external CPU workload in the same VM. The recorder
window is approximately one second, with exact per-source overlap preserved in
the run JSON. These are whole-workload observations including preparation and
teardown margins, not steady-state overhead or statistically significant gains.
No other QEMU or heavy host build ran during these comparisons.

| Architecture | Stage | Wall ms | Iterations/s | Change from baseline | Recorder FDs / ring bytes | System timer_busy delta |
|---|---|---:|---:|---:|---|---:|
| RV64 | baseline | 2500.048 | 8466.64 | — | no recorder; registry 0 → 0 | 0 |
| RV64 | loaded-detached | 2500.098 | 8589.26 | +1.448% | 35 / 557056 | 22 |
| RV64 | attached | 2500.042 | 8538.66 | +0.851% | 43 / 557056 | 85 |
| LA64 | baseline | 2500.195 | 7647.00 | — | no recorder; registry 0 → 0 | 0 |
| LA64 | loaded-detached | 2500.169 | 7515.09 | −1.725% | 35 / 557056 | 32 |
| LA64 | attached | 2500.033 | 7476.30 | −2.232% | 43 / 557056 | 131 |

Baseline and detached resources/loss are measured from original proc snapshots,
not filled with assumed zeros. Detached snapshots observe 16 registered perf
objects and zero trace subscriptions. Attached captures also retain source,
program, sink and consumer diagnostics. `timer_busy` is a system queue loss
counter, not a per-source sample-loss total; overlapping scopes are not added.
Ring bytes exclude allocator overhead, capture encoding buffers and kernel
objects. There is no RSS or total-memory claim. Retention overflow and genuine
sampling losses stay quantified and partial.

## Review and boundaries

Standards review found a stop-error persistence bug, incomplete mapping safety
invariants, and duplicated context geometry; all were corrected and re-reviewed.
Spec review found nonleader-exec identity handling and missing baseline/detached
measurements; both were corrected and exercised. The new clone/exec fixture's
unsafe boundaries received a separate review without additional findings.

All observed files remain partial. The generic recorder does not yet provide a
typed completeness certificate, matching kernel/image build identities inside
capture, stack contexts, or a temporal mapping journal. Host input manifests
retain actual artifact hashes; they do not backfill unknown capture identities.
Fault major/minor classification and pending resolver ownership remain unknown.
The tool does not claim general Linux/Aya/libbpf or ADR-0005 upstream compatibility.

The initial smoke and installed-workload attempts exposed serial ANSI-prefix and
interleaving problems in the acceptance transport. Those failed logs are kept;
they are not repaired into successful captures or counted as positive evidence.
Source logging remains enabled. Final transfer gates compare exact guest file
bytes, ordered offsets, lengths, CRC and independently parsed source bindings.

See [usage](../docs/bpf-record.md) and [acceptance harness](../tests/bpf_record/README.md).
