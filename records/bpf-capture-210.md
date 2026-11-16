# Unified current BPF capture contract (#210)

2026-11-16. Base: `cd47bf675d93fd41d1dacb91ca06f0da60978812`.
Core implementation: `4fcf8cf0`; source/scope correction: `8768a3a4`;
bounded finalization correction: `b8301df0`. Native archive coverage correction
and the evidence index are included with this record.

## Delivered contract

Only container v6 remains. Required diagnostics and `PBSRC003` source bindings
compose with explicit stack and mapping extensions. Software single-IP v2 and
stack v3 remain distinct native capabilities. Every record has a logical source
ID; stack context kernel event IDs must agree with the selected declaration.
The typed table preserves clock/config, scope/stable task identity, kernel
objects, requested/effective parameters, units/fallback and source windows.

Writer, reader, native RAW importer, generic recorder, analyzer and active
independent evidence readers use this contract. Missing evidence, zero samples,
loss, incomplete unwinds and journal gaps cannot certify complete attribution.
Consumer counts and overlapping producer/program/sink diagnostics stay separate.
Historical archive files were not changed or used as rewritten v6 evidence.

See [the current format and invariants](../docs/bpf-capture.md) and
[recorder usage](../docs/bpf-record.md).

## Validation

| Gate | Result |
| --- | --- |
| Rust: capture, analyzer, recorder, schema and syscall host suites | 480 passed; 3 optional native perf tests separately passed |
| Capture contract and regression tests | 86 passed, including 10 unified-contract tests |
| Native Linux perf consumers | 3 passed (`perf 6.8.12`); full perf-export suite 15 passed |
| Sampling / recorder / smoke Python suites | 106 / 9 / 14 passed |
| RV64 and LA64 capture `no_std + alloc` checks | Passed |
| RV64 and LA64 production recorder builds | Passed |
| Default `make test` | Both architectures passed |
| `make test APP_FEATURES="qemu bpf-trace"` | Both architectures passed |

[Validation logs](issue210-validation.tar.gz) retain the final full suite,
architecture build output, focused red/green checks and mixed guest result.
Existing compiler warnings remain outside this task. An early parallel build
was rejected by the provenance guard because source inputs were changing;
all reported build gates were rerun with frozen production sources.

## Actual guest evidence

| Run | Records | Logical sources | Observed transport/export loss | Outcome |
| --- | ---: | ---: | --- | --- |
| RV task clock + stacks | 2,706 | 1 | 0 / 0 | Lifecycle, ELF stack oracle and independent RAW comparison pass |
| RV CPU clock + stacks + mappings | 3,267 | 16 | 0 / 0 | Six mutation phases and artifact/symbol checks pass |
| LA generic CPU/CPU/task/sched/fault mix | 5,127 | 73 | 4,890 PERF lost / 0 discarded | Stop/no-growth/resource cleanup and independent replay pass |

Every positive capture is v6, every record binding is independently consumed,
and all remain `IncompleteError` with complete attribution disallowed. Missing
kernel provenance in the task run remains explicitly unknown. The combined
run retains its matching provenance and original artifact identities.

- [Native RAW/capture/ELF bundles, member SHA-256 and replay report](../tests/bpf_sampling/evidence/210/README.md).
- [Generic recorder original guest bytes, producer/kernel and replay evidence](../tests/bpf_record/evidence/210/README.md).

The initial 10/20 ms combined stack/mapping run retained 11,915 of 25,599 samples
and counted 13,684 export drops at the existing 8 MiB bound. Its late mapping
oracle correctly failed. The positive combined fixture explicitly requested
50/100 ms; it did not expand the bound or hide loss. Its first host extraction
still expected fixed periods; that checker was corrected to count distinct
explicit source declarations. Revalidation uses the unchanged newly collected
RAW log, retaining the initial failed input/result separately.

The first broad LA lifecycle attempt was interrupted during SIGINT file
transfer after task, dup-close, budget, mixed and frequency-request captures
completed. It is not counted as a passing full lifecycle suite. The focused
mixed rerun passed. No benchmark or quantitative speedup is claimed.

## Review and boundaries

Standards review found one duplicated RAW-envelope decoder; it now uses the
shared parser. Spec review found missing CPU-clock/per-CPU versus
task-clock/task coupling; centralized validation now rejects both malformed
combinations even after a capture's CRC is recomputed. Both findings were
independently rechecked with no remaining findings. New deep diagnostics copies
introduced during migration were removed to preserve bounded guest behavior.

The generic recorder still emits single-IP software contexts and no mapping
journal. This issue makes the format composable; the later generic collection
and exporter-semantic work is not claimed here. Old containers require their
historical consumer baseline and are intentionally rejected by current readers.
