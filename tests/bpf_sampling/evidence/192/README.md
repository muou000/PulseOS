# Issue 192 real stack evidence — 2026-11-15

These bundles contain actual QEMU output, consumed RAW frames, capture v3,
matching kernel **and** guest ELF files, build provenance, and independent
RAW/ELF checks. They contain no synthetic sampling records.

| Run | RAW samples | Exact user A / B chains | Target mmap kernel chains | Source instances | Gate |
|---|---:|---:|---:|---:|---|
| [rv-task](rv-task.tar.gz) | 351 | 30 / 15 | 29 | 1 | PASS |
| [la-task](la-task.tar.gz) | 211 | 28 / 24 | 15 | 1 | PASS |
| [rv-cpu](rv-cpu.tar.gz) | 4151 | 44 / 40 | 29 | 16 | PASS |
| [la-cpu](la-cpu.tar.gz) | 2557 | 28 / 43 | 31 | 16 | PASS |

Each CPU-mode run opens two independent software events on each of eight CPUs.
Source IDs, periods, per-source delivery, VM, sink, consumer and export counts
are reconciled. All four runs have zero transport/export loss, and retain
skipped periods and other independently scoped diagnostics. CPU-mode totals
include foreign tasks; the positive user and mmap checks require the exact
sampler PID **and** TID. Source instances cannot be inferred from CPU alone.

All runs include actual no-FP, unreadable frame, cycle, invalid return address,
misaligned frame and depth-limit probes. For the unreadable frame, mincore is
checked before and after sampling of a readable, lazy anonymous mapping: the
page remains nonresident. Host checks associate the raw termination reason with
each exact probe IP range. `stack-evidence.json` contains positive and negative
counts and real chain examples; `index.json` contains SHA-256 for every bundle
and member, actual measurements and build source identity.

The captures remain `partial` / `IncompleteError`. This preserves incomplete
unwinding and separately scoped loss/unknown diagnostics; gate PASS does not
mean all activations were recovered. The method is bounded FP walking in the
interrupted privilege domain. Kernel examples resolve through the expected
mmap/fault/allocator path and stop explicitly at assembly/trap boundaries.
User examples verify exact middle/outer return labels. Symbol lookup verifies
function membership, not every machine-code call edge; omitted FP, inlining,
tail calls and arbitrary prologue/epilogue windows are not generally recovered.
No cross-privilege frames are synthesized.

Extract a bundle into a scratch directory. From the repository root:

```bash
cargo run -p bpf-analyzer -- /tmp/rv-task/capture.pbcapture --json
cargo run -p bpf-analyzer -- /tmp/rv-task/capture.pbcapture --oncpu /tmp/rv-task.folded
cargo run -p bpf-capture --example runtime_import -- /tmp/rv-task /tmp/reimport.pbcapture
python3 -c 'import sys; from pathlib import Path; sys.path.insert(0, "tests/bpf_sampling"); import stack_evidence; print(stack_evidence.verify(Path("/tmp/rv-task")))'
```

Reimport can change output-path metadata/checksum; record count and contents
must remain identical. Run the importer before the RAW/ELF check to validate the
RAW envelope, checksums and counters. The raw boot image and rootfs copies remain
in the run directories listed by index.json. Kernel ELF and provenance are also
included in every bundle, so function lookup and hash verification do not depend
on those local directories. RV boot bytes can be reconstructed with objcopy;
LA boots the ELF directly. Hashes are evidence identifiers, not signatures.

`validation.tar.gz` preserves both successful dual-architecture build logs and
the final syscall/capture/analyzer host-test logs; its checksum is in index.json.

Live reproduction:

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode task --stacks --archive --timeout 300
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode task --stacks --archive --timeout 300
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu --stacks --archive --timeout 300
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu --stacks --archive --timeout 300
```

An earlier RV task run obtained valid main-session records but failed the
additional FD-lifecycle positive-loop quota because its timed loop also ran all
negative workloads. The timed lifecycle loop now exercises the positive chain
only, with the original thresholds preserved; all negative and kernel workloads
remain in each main measured phase. The failed run is retained locally as
`riscv64-task-20261115-122453-_sbvl15j` and is not counted as passing evidence.
