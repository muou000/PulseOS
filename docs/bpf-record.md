# Guest BPF recorder

`bpf-record` records an existing workload through PulseOS software perf events
and semantic tracepoints. It writes an authoritative BPF capture directly in
the guest. The command does not run a substitute workload or inherit children.
This is the PulseOS fixed-context interface, not a claim of complete Linux,
Aya, libbpf, or ADR-0005 upstream-tool compatibility.

## Build and record

```sh
set -o pipefail
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tools/bpf-record/build.py --arch riscv64
python3 tools/bpf-record/build.py --arch loongarch64
```

Install the matching `tools/bpf-record/build/ARCH/guest/bpf-record` executable
in the guest filesystem. Example guest commands:

```sh
bpf-record --events cpu --cpus all --period-ns 10000000 --duration-ms 1000 --output /tmp/cpu.pbcap
bpf-record --events task --tid 123 --frequency 99 --duration-ms 1000 --output /tmp/task.pbcap
bpf-record --events sched,fault --cpus 0,1 --duration-ms 1000 --output /tmp/events.pbcap
bpf-record --events cpu,cpu,task,sched,fault --tid 123 --duration-ms 1000 --output /tmp/mixed.pbcap
```

For function profiling, deploy the ELF matching the actual boot kernel as
`/boot/kernel.elf` and record its identity with `--kernel-elf /boot/kernel.elf`.
Software sources default to `--callchain fp`; `--callchain none` selects single-IP
records. Current FP limits accept depth 32 and 512 bytes. For example:

```sh
bpf-record --events task --tid 123 --period-ns 10000000 --duration-ms 1000 \
  --callchain fp --kernel-elf /boot/kernel.elf --output /tmp/profile.pbcapture
```

`task` requires an explicit existing TID. A numeric TID is resolved to the
kernel's bound task identity; it does not mean every thread of a process.
The source retains that identity when a nonleader exec changes its numeric
TID, and lifetime checks query that bound task rather than a recycled TID.
`cpu`, `sched`, and `fault` collect on the selected online CPUs. In a mixed
session `--tid` applies only to `task`; it does not filter scheduler subjects
or fault events. A task may migrate, so task sessions require all online CPU
sinks. CPU lists containing duplicates, offline CPUs, or empty entries fail.
The actual online mask comes from a versioned kernel capability snapshot.

The scheduler group expands to event IDs 1–6. Repeating an event creates
independent sources, even with identical CPU and period. `fault` is the returned
resolver event (ID 8). Successful faults are classified from actual target-page
storage reads: verified reads are major, verified resolution without a read is
minor, and unverified backends remain unknown. Error outcomes are counted
separately. See [classification semantics and coverage](research/page-fault-io-classification.md)
for the ext4/Ext4Disk boundary and differences from Linux retry accounting.

`--frequency` and `--period-ns` are exclusive. Frequency converts to the nominal
period with `ceil(1_000_000_000 / Hz)`; this does not promise an achieved rate.
Timer observation granularity, queueing and recorded loss still apply. Pure
tracepoint sessions reject either option. Hardware `cycles` is unavailable;
only `--allow-fallback` explicitly substitutes CPU-clock nanoseconds and saves
the requested mode, actual mode, units and reason.

`--buffer-pages` defaults to 16 and accepts powers of two up to 256 per sink.
`--record-bytes` defaults to 8 MiB and accepts 4 KiB through 64 MiB of normalized
records plus source bindings. A session admits at most 128 sources and 64 MiB
of ring mappings. Kernel objects, allocator overhead and final file encoding
consume additional memory. Capacity exhaustion counts discarded records;
storage does not grow indefinitely to hide loss.

Without `--duration-ms`, recording continues until SIGINT/SIGTERM or task exit.
All stopping paths disable sources, wait for accepted VM work, then drain.
VM completion does not imply all fault resolvers have returned: old entry
generations cannot enter a new activation, and unresolved provenance remains
explicitly unknown. Output errors return failure; an absent or truncated
trailer is not a complete capture.
Control errors go through best-effort disable of every source. Recoverable
errors retain a valid partial capture and return failure. If the final boundary
cannot be established, the recorder detaches links and preserves a nonempty
capture prefix with observed records and unknown stop time, without a trailer;
the analyzer rejects that unfinished file instead of asserting completeness.

## Capture and analysis

Capture v6 is the only current container. It combines mandatory diagnostics and
source declarations with independent stack and temporal mapping extensions.
Every record has one logical source ID; the source table uses revision 3
(`PBSRC003`). Each BPF program emits an envelope containing kind, context length
and logical source ID. The consumer validates schema, scope, period and control
windows against the declaration. It never infers a source from context length,
CPU, period or diagnostic text.

Each declaration retains the timestamp clock, requested and effective event
configuration, period/frequency and buffer sizes, units, fallback reason, stable
task identity, kernel event/program/link identities and individual control
windows. A logical source ID is distinct from the kernel event ID embedded in a
stack context; both must agree through the declaration. The full
[current capture contract](bpf-capture.md) specifies the invariants and bounds.
Preparing multiple sources does not create an atomic shared start time.

```sh
cargo build -p bpf-analyzer
target/debug/bpf-analyzer session.pbcap --json
target/debug/bpf-analyzer session.pbcap --sched-report --json
target/debug/bpf-analyzer session.pbcap --fault-report --json
```

Source, program, sink and consumer counters retain their individual scopes.
They overlap and must not be summed into an invented loss total. A normal
control-flow exit can produce a partial capture; unknown build/mapping facts,
missing counters, zero observations or real loss do not become complete data.
The production recorder captures bounded live FP stacks when enabled and stores
an initial mapping snapshot plus the final temporal mapping journal. It binds
guest-observed artifact identities to that history; missing identities remain
unknown. Software single-IP and stack contexts remain distinct capabilities
within v6; downstream symbolization/export enforces their actual prerequisites.
Containers v1–v5 and source tables `PBSRC001`/`PBSRC002` are rejected. Historical
archives retain their original format and producer/analyzer baseline; do not
rewrite them as evidence for the current format. The standalone demonstrations
and fixed-load regression harness retain their own scope.

## Acceptance

`tests/bpf_record/` drives the actual command and external workloads under the
repository's QEMU command shapes, using copied disk images. Its acceptance
binary enables test-only failure injection; production builds reject those
options. Raw guest capture bytes, logs, command lines and measurements are
retained for independent analysis. Baseline, loaded-detached and attached
measurements describe their actual workload and environment, without invented
performance thresholds or lossless-completeness claims.

```sh
python3 tests/bpf_record/run.py guest --arch riscv64 --suite full --timeout 600
python3 tests/bpf_record/run.py guest --arch loongarch64 --suite full --timeout 600
cargo test -p bpf-record -p bpf-capture -p bpf-analyzer -p pulse_syscalls -p pulse_bpf_schema -- --test-threads=1
python3 -m unittest discover -s tests/bpf_record -p 'test_*.py'
```

The benchmark reports whole-workload throughput, including preparation and
teardown margins, and records the overlap of each source window with that
workload. It is not a steady-state or statistically significant overhead claim.
The deterministic host lifecycle gate also checks an old pending fault after
disable/re-enable; the existing sampling guest's task mode separately verifies
Link ownership and the last duplicated ioctl-attached perf FD closing.
