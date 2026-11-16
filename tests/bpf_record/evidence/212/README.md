# Recorder perf exporter replay (#212)

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

2026-11-16: twelve host replays of unchanged #211 captures passed with native
`perf version 6.8.12` and FlameGraph revision
`41fee1f99f9276008b7cd112fca19dc3ea84ac32`. The declared file subset is separately
versioned against Linux v6.12; this does not claim testing with a v6.12 consumer.

| Original #211 capture | User samples | Period sum (ns) | Partial chains |
| --- | ---: | ---: | ---: |
| RISC-V mixed | 21 | 210,000,000 | 15 |
| LoongArch mixed | 49 | 490,000,000 | 24 |
| RISC-V nonleader exec | 138 | 1,380,000,000 | 0 |
| LoongArch nonleader exec | 123 | 1,230,000,000 | 0 |

Each row passes both `samples` and `period_ns` weighting. Four additional
numeric-TID queries split the exec captures: RV TID 60 has 47 samples and TID 57
has 91, all bound to kernel task 60; LA TID 72 has 29 and TID 70 has 94, all
bound to kernel task 72. Both mixed captures contain CPU-clock and task-clock
samples; native FlameGraph output includes both event types exactly once.

`replay.json` records hashes, original record indices, filters, actual field
comparisons, native function rows and incomplete-attribution reasons.
`native-replay.tar.gz` preserves generated perf.data, manifests, native
report/script/buildid-list output, command arguments, folded data and SVGs.
`index.json` hashes the archive and its files. Original captures and matching
ELFs remain in [#211](../211/README.md); they are not duplicated here.
`validation.tar.gz` and `validation.json` retain the host test/build logs and
their hashes: 497 Rust tests, 126 Python tests, default and BPF-enabled RV/LA
build gates passed on code commit `4938fc41`. The rejected first provenance
attempt and failing-before/passing-after regression logs are identified separately.

The oracle is the hash-checked original #211 timeline, including raw
`payload_hex` and transport-order source bindings. `replay.py` decodes those
bytes independently of the current exporter manifest, then compares native
`perf script -D` source, IP, PID/TID, time, CPU, period, mode, context markers
and callchain. It also checks native report row totals, JSON/folded weights,
the `_start` symbol in native output/SVG, and unchanged capture hashes.

All original captures remain `IncompleteError`; symbols and graphs do not
make attribution complete. These are user-mode host replays, not new guest
runs. Some RISC-V addresses resolve to local assembler labels; the archived
native output preserves this limitation rather than renaming those results.

```sh
cargo build -p bpf-analyzer
mkdir -p /tmp/pulse-212-inputs
tar -xzf tests/bpf_record/evidence/211/riscv64.tar.gz -C /tmp/pulse-212-inputs
tar -xzf tests/bpf_record/evidence/211/loongarch64.tar.gz -C /tmp/pulse-212-inputs
python3 tests/bpf_record/evidence/212/replay.py \
  --inputs /tmp/pulse-212-inputs --output /tmp/pulse-212-replay-new \
  --analyzer target/debug/bpf-analyzer --perf /usr/local/bin/perf \
  --flamegraph /path/to/pinned/FlameGraph
```

The output directory must be new. The helper snapshots the analyzer executable
for a consistent run, verifies the installed FlameGraph hashes and never
downloads tools. Failed exports retain their exact rejection in `replay.json`;
none of the twelve recorded queries was rejected.
