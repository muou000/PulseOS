# Observation tools: actual guest evidence (2026-11-15)

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

Eight actual RV64/LA64 runs cover task-clock, sched-switch, mixed scheduler and
page-fault completion. Two earlier failing fault workloads are retained: adjacent
anonymous pages were batch-mapped, so they did not produce the required write
fault. These bundles are runtime evidence, not synthetic format fixtures.

| Bundle | Actual records | Result |
|---|---:|---|
| [riscv64-task](riscv64-task.tar.gz) | 64 | PASS |
| [riscv64-trace](riscv64-trace.tar.gz) | 568 | PASS |
| [riscv64-sched](riscv64-sched.tar.gz) | 1436 | PASS |
| [riscv64-fault](riscv64-fault.tar.gz) | 258 | PASS |
| [loongarch64-task](loongarch64-task.tar.gz) | 37 | PASS |
| [loongarch64-trace](loongarch64-trace.tar.gz) | 576 | PASS |
| [loongarch64-sched](loongarch64-sched.tar.gz) | 1678 | PASS |
| [loongarch64-fault](loongarch64-fault.tar.gz) | 258 | PASS |
| [riscv64-fault-initial-failure](riscv64-fault-initial-failure.tar.gz) | no capture | expected FAIL |
| [loongarch64-fault-initial-failure](loongarch64-fault-initial-failure.tar.gz) | no capture | expected FAIL |

The 4,875 RAW samples match normalized records individually. Scheduler reports
contain 266/269 independently checked B/Blocked-switch-out/W/R instances. Both
fault runs have 258 completions, 128 known read targets, 128 known write targets,
and Unknown I/O classification. All captures preserve partial/unknown status;
the gate does not claim complete attribution or parity.

Bundles contain original logs/RAW/capture, deployed payload ELF and source inputs,
source/program/sink snapshots, build manifest and derived reports. Final host
reports were replayed from the unchanged captures after semantic review fixes;
analysis-replay.json pins the analyzer binary and source-file hashes. It records
the then-current workspace commit separately from uncommitted source content.
Kernel ELF and large rootfs images remain in the named local runs; their actual
identities are preserved in inputs/manifests/capture, not guessed from current HEAD.
No unrelated worktree patch is published.

index.json contains bundle/member SHA-256, actual phase measurements and losses.
oracle.json is the independent verifier output. After extracting a bundle in a
scratch directory, run:

```sh
python3 tests/bpf_sampling/verify_observation_evidence.py <extracted-run-directory>
cargo run -p bpf-analyzer -- <capture.pbcapture> --sched-report --json
cargo run -p bpf-analyzer -- <capture.pbcapture> --fault-report --json
cargo run -p bpf-analyzer -- <capture.pbcapture> --phase attached_capture --json
```

The negative bundles deliberately lack a completed capture; inspect their guest
logs and failed result, rather than passing them to the positive oracle. PCP
startup-isolation red/green evidence is separately in [the PCP bundles](../../../pcp_boot/evidence/README.md).
See [the acceptance record](../../../../records/bpf-observation-tools-184-188.md) for scope and limits.
