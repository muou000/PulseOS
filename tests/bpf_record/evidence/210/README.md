# Capture v6 generic recorder evidence (#210)

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
