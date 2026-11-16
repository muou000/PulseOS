# Production recorder destination evidence (#213)

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

2026-11-16. New RV64/LA64 runs, not relabelled #211 evidence.

| Archive | Evidence |
| --- | --- |
| `matrix.tar.gz` | Original 34 boots: 24 production recorder runs and 10 acceptance control/benchmark runs |
| `extension.tar.gz` | Two additional production runs targeting an already-running installed `dd`; original matrix index unchanged |
| `native.tar.gz` | Final 21 positive Queries in both weight units (42 perf.data/SVG outputs), plus the separate LA installed-user strict negative |
| `regressions.tar.gz` | Four fresh scheduler/fault regressions and four expected zero-producer/zero-consumer rejections |
| `counterexamples.tar.gz` | Real function-label before/after regression, missing runtime ELF, unfiltered mapping and exec-churn strict export failures |
| `validation.tar.gz` | Host tests, original/final dual build gates, provenance, hardware/tool identities, commands and final tool-source snapshot |

The 36 guest runs preserve 60 finalized original captures (94,842 records,
all `IncompleteError`) and two actual failed-write prefixes. Originals include
serial file bytes, guest SHA witnesses, control logs, commands, Query results,
matching kernel/recorder/fixture ELF and verified artifacts. `index.json` binds
all six compressed archives and 4,220 members to SHA256/size; identical contents
use archive-internal hardlinks. Boot kernels are retained. Rootfs copies and
the rebuildable host analyzer executable are omitted with explicit hashes and
reasons; hashes identify those bytes but cannot reconstruct the omitted rootfs
or prove that a new guest run used it.

The RV loader supplement adds only a verified host artifact and a new collection
report. The original missing-artifact report, capture, inputs and index remain
unchanged. LA unknown shared-library identities remain unknown: its user Query
is an explicit rejection, never counted as a successful perf/SVG export. The
installed `dd` kernel Queries are positive real task-bound captures on both
architectures. Counterexamples are labelled separately and do not count as
passing production runs; the function-label regression explicitly uses old
#211 bytes to reproduce that host consumer bug.

The initial and final BPF kernel ELF hashes and source-input trees match on
both architectures. Build provenance is in `validation/bpf-*.provenance.json`
and `validation/bpf-final-*.provenance.json`; the summary binds these manifests
to the booted ELF SHA. Build gates ran at `b611b7cb`; the portable verifier's
report-order fix was tested at `d89c79d3`. Subsequent evidence/documentation
commits do not alter the tested code.

## Verify and replay

```sh
cargo build -p bpf-analyzer
python3 tests/bpf_record/evidence.py verify tests/bpf_record/evidence/213 \
  --extract /tmp/213-evidence
python3 tests/bpf_record/qualify.py /tmp/213-evidence/matrix \
  --additional /tmp/213-evidence/extension \
  --analyzer target/debug/bpf-analyzer --perf /usr/local/bin/perf \
  --flamegraph /path/to/pinned/FlameGraph --output /tmp/213-native-replay
```

Both output directories must be new. Perf 6.8.12 and the content-checked
FlameGraph revision `41fee1f99f9276008b7cd112fca19dc3ea84ac32` were used.
No tool is downloaded by the replay. The replay requires every original run,
checks both immutable indexes, and executes the fixed Queries in
[`QUALIFICATION.md`](../../QUALIFICATION.md).

[`archive-verification.json`](archive-verification.json) records extraction and
all member checks. [`portable-replay.json`](portable-replay.json) records the
independent replay: 21 Queries / 42 SVGs, the same per-source counts and periods,
and **42 byte-identical perf.data outputs**. The strict negative is separate.
[`functional-replay.json`](functional-replay.json) records all 36 lifecycle/file
replays with `verify.py` in the disposable extraction after qualification.
That verifier can create derived collection/timeline reports in the extraction;
the archived originals remain unchanged. Extract a new copy before repeating
the immutable-index qualification.

Fresh reproduction, observed counts, actual three-phase throughput/resources,
review fixes and remaining boundaries are in the
[acceptance record](../../../../records/bpf-recorder-e2e-213.md).
The complete packaging command is retained in `validation/package-command.json`.
One benchmark observation per phase is not a statistical overhead conclusion;
source/system/transport/export loss layers remain separate. This gate does not
claim complete dynamic-executable attribution, physical PMU/board coverage or
exact busy/idle utilization.
