# Capture v6 generic recorder evidence (#210)

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

Fresh LoongArch64 QEMU run on 2026-11-16, source baseline `b8301df0`.
The isolated `mixed` suite passed with 73 explicit sources and 5,127 records.
Its 4,890 consumed PERF lost notices remain separate from scoped diagnostics;
status stays `IncompleteError`. Quiescence, no growth and resource cleanup pass.

`loongarch64-mixed.tar.gz` preserves the original guest file, serial log,
producer/fixture executables, exact boot kernel, input hashes, script, original
report/result and independent final replay. `index.json` hashes every member.
Disk images and the rebuildable host analyzer binary are omitted; its original
SHA-256 is in `inputs.json`, and the final consumer SHA is in `final-replay.json`.

Replay after extraction using the current analyzer:

```sh
cargo build -p bpf-analyzer
target/debug/bpf-analyzer /tmp/issue210-la/mixed.pbcapture --json
python3 tests/bpf_record/verify.py /tmp/issue210-la --functional-only
```

The broader first lifecycle attempt was interrupted during the later SIGINT
file transfer after five captures had completed. Its local original run is
`tests/bpf_record/runs/loongarch64-lifecycle-20261116-111524-x9o95zpn`;
it is not counted as a passing full lifecycle suite. The isolated mixed run
above is the positive evidence. No performance speedup claim is made.
