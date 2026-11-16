# Production recorder acceptance (#213)

The tested public boundaries are the production guest `bpf-record` command,
its immutable capture file, the host analyzer's Query/export commands, and
unmodified perf plus the pinned FlameGraph scripts. These are the seams
specified by #213. The separate workload fixture never becomes recorder code.

## Required observations

1. Build both production and acceptance binaries, recording their build commands
   and SHA256. Positive CPU/task/mixed, existing-program, mapping and nonleader
   exec cases use production. Failure injection and loaded-detached resource
   measurements explicitly use acceptance. A missing production binary cannot
   fall back to acceptance or a specialized sampler.
2. On each architecture, launch independent frame-pointer workloads before the
   recorder; require a real three-frame user chain and a real kernel chain.
   Repeated CPU sources share CPU and period but retain different logical IDs.
   Exercise installed shell/dd/sleep, real mapping transitions, and task-clock
   binding across nonleader exec. Use the AGENTS.md QEMU command shape.
3. Preserve the guest SHA witness, ordered serial file bytes and host file SHA.
   Decode framing, raw context fields and record-source bindings independently
   of the analyzer's timeline and exporter manifest. Match the selected records
   to table/JSON/folded and native perf fields: logical source, IP, PID/TID,
   monotonic time, CPU, period, context marker and saved callchain order.
4. Run the same explicit Query with samples and period weights. Compare native
   report/script/buildid-list, each source's count, the folded total and SVG
   content. Verify actual captured ELF identities; successful symbolization
   never upgrades capture or stack completeness.
5. Missing/wrong symbols, broken/missing trailer, dropped records, empty producer
   or consumer, incomplete stack, mapping-journal gap and reused numeric
   PID/address identities must retain diagnostics or fail closed. Mutated
   negative files are separate derivatives; original captures remain unchanged.
6. Rerun duration, signal/target exit, dup/close, second load/attach failure,
   observation failure, retained-record overflow and failed-write cleanup.
   Require zero owned resources and no growth after stop where observable.
   Keep real scheduler latency and VirtIO fault-provenance regression runs.
7. Run default and BPF-enabled dual-architecture `make test`, relevant Rust and
   Python suites, and native consumer tests. Freeze source before builds. Run
   baseline/loaded-detached/attached measurements sequentially without concurrent
   builds or QEMU; retain wall time, throughput, resources and separate losses.
   One observation is not a statistical overhead estimate or pass threshold.

## Evidence and failure policy

Every new run has its own inputs, exact commands, original files, matching
kernel/target ELF, tool identities, Query and diagnostics. The index hashes the
archives and their members. Replaying an archive is identified as replay; old
evidence is never relabelled as a new guest run. Missing cases or failed commands
make the aggregate gate fail. A selected supported Query does not erase unknown
facts outside that selection.

Physical PMU/boards, x86/aarch64 guests, unverified fault backends, allocation
tracking and precise busy/idle remain outside this software-sampling gate.
