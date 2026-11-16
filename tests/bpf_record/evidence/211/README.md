# Production recorder evidence (#211)

2026-11-16: 14 independently replayed, passing QEMU runs per architecture.
`riscv64.tar.gz` and `loongarch64.tar.gz` contain one directory per suite:
the seven isolated `stacks-*` cases, `mapping`, `recovery`, `negative`,
`lifecycle`, `existing`, `smoke` and `benchmark`.

The archives preserve 52 original finalized partial captures and two actual
1024-byte failed-write prefixes, guest serial logs, original reports, final
replays, guest scripts, deployed recorder/fixture/kernel ELFs, verified
content-addressed artifacts and input identities. Matching duplicate bytes are
stored as archive-internal hardlinks. Disk images and the rebuildable analyzer
executable are omitted; their original hashes are retained. `index.json` hashes
every archived regular file and the archive containers themselves. Extraction
and all member hashes were independently checked before committing.

```sh
cargo build -p bpf-analyzer
mkdir -p /tmp/pulse-211
tar -xzf tests/bpf_record/evidence/211/riscv64.tar.gz -C /tmp/pulse-211
python3 tests/bpf_record/verify.py /tmp/pulse-211/riscv64/stacks-mixed
target/debug/bpf-analyzer /tmp/pulse-211/riscv64/stacks-mixed/mixed.pbcapture --json
```

Use the analogous LoongArch archive and directory for that architecture.
`validation-logs.tar.gz` preserves the default/BPF dual build gates and host
test outputs. `regressions.tar.gz` separately preserves the failed pre-arena
journal-coverage runs; they are not counted among the 28 passing runs.

Normal isolated coverage cases require zero journal loss. The long LA
installed fault workload retains 31,840 journal drops and partial coverage;
bounded-export, stop/journal failure and failed-write cases deliberately retain
their real diagnostics. No capture is upgraded to complete by adding symbols.
See [implementation, review and measurements](../../../../records/bpf-production-capture-211.md)
for the full evidence boundaries and the actual three-stage comparison table.
