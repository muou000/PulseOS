# Fixed #213 consumer Queries

After `acceptance.py` finishes all 36 guest runs, qualify its complete index:

```sh
python3 tests/bpf_record/qualify.py tests/bpf_record/runs/213-fresh \
  --analyzer target/debug/bpf-analyzer --perf /usr/local/bin/perf \
  --flamegraph /path/to/pinned/FlameGraph --output /path/to/new-qualification
```

The gate verifies every indexed original file, result and recorder build identity
before exporting anything. It offers no architecture or suite omission option.
Both `samples` and `period_ns` weights are checked for each supported Query.
When a separately planned extension supplies the two installed-I/O runs, pass
`--additional /path/to/installed-io-matrix`. Each original plan/index must be
complete, and their union must contain all 36 cases exactly once. Both original
indexes retain their bytes and separate SHA identities.

| Original production run / capture | Predeclared Query | Required outcome |
| --- | --- | --- |
| `stacks-cpu/stack-cpu` | `--mode user` | Original ELF leaf/middle/outer functions in one saved chain, native perf and SVG |
| `stacks-cpu/stack-cpu` | `--mode kernel` | Three saved kernel function frames checked against original kernel ELF and native outputs |
| `stacks-task/stack-task` | `--mode user` | Same known user function chain |
| `stacks-mixed/mixed` | `--mode user` | Same known user function chain; repeated logical sources remain distinct |
| `stacks-mixed/mixed` | `--mode kernel` | Same kernel function proof |
| `stacks-existing/existing-shell`, RV64 | `--mode user` | Strict export with matching installed executable/loader artifacts |
| `stacks-existing/existing-shell`, LA64 | `--mode user` | **Strict negative:** `mapped object SHA unavailable`; unchanged original, no successful perf.data or SVG |
| `installed-io/installed-io` | `--mode kernel` | Native kernel export from one already-running installed `dd`; every record must match its stable task source, with actual exec/live/stop witnesses |
| `mapping/mapping-lifecycle` | `--mode user --task ID` | ID is the unique task source's original `bound_task_id`; include every saved sample of that stable task |
| `nonleader-exec/nonleader-exec` | `--mode user` | One stable task with both observed numeric TIDs |
| `nonleader-exec/nonleader-exec` | `--mode user --tid ID`, separately for both original TIDs | Exact pre/post-exec source and record identities |

This is 21 supported native Queries and one separately reported strict-negative
Query across the two architectures. The LA64 installed dynamic executable's
shared-library mappings lack guest-recorded SHA identities. Host files cannot
repair that unknown fact. Its rejection appears in `strict_negatives`, never in
the count of successful native exports. The actual installed program still has
fresh CPU/scheduler/fault capture evidence and a qualified kernel Query; the
independent fixture supplies the positive named user-callchain proof.

The original `existing` suite still runs installed shell/dd/sleep churn for
CPU/scheduler/fault regression. Its whole kernel Query can encounter a real
task mutation interval during exec and must then reject. It is not silently
filtered into a successful export. The separate installed-I/O suite starts one
long-running `dd` before attaching the production task source and stops it only
after recording, so its kernel Query includes every saved target kernel sample.

The mapping Query is specified by the recorder's stable task binding before
analysis. Other contexts observed by its CPU sources remain in the original
capture and diagnostics. Neither this explicit selection nor a successful
symbol lookup promotes partial status or claims complete dynamic executable
symbolization or exact busy/idle attribution.

Every supported Query independently decodes capture v6 bytes, checks guest-file
transfer and SHA witnesses, and compares typed sources, saved stack fields,
mapping journal, artifact identities, table/JSON/folded weights, and native perf
record fields. Own folded output must match the complete multiset of original
task identities, privilege modes, completeness/termination markers, reversed
saved PC chains and per-stack weights; matching only the grand total is
insufficient. A zero-length unavailable chain retains its reason and weight
without adding an IP. Negative cases require the intended semantic error and
ordinary error exit; crashes, unrelated I/O failures and permission diagnostics
cannot count as expected rejection. Known user functions come from the executed fixture's actual
`STT_FUNC` symbols and recorded PC ranges, including raw Rust symbol spelling
when the host perf lacks Rust-v0 demangling. Original ELF/capture files stay
unchanged; declared consumer symbol views retain separate hashes.
