# Real software sampling regression (#190)

This freestanding RV64/LA64 guest uses raw Linux-shaped syscalls and checks actual
`PERF_SAMPLE_RAW` records produced by a loaded BPF program. It never constructs a
capture file or synthesizes sample/loss counters.

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode task
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode task
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode trace
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode trace
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode block
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode block
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode wake
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode wake
```

Build the appropriate kernels first using the repository's `make rv` / `make la`
(or `make test`) with the required BPF sampling feature enabled. `guest` always
rebuilds its payload, copies the kernel and rootfs, injects only the copied rootfs,
and uses the AGENTS.md QEMU shape (8 GiB, eight CPUs, snapshot disk, UTC RTC).
`--kernel` and `--image` select explicit inputs. Kernel and payload hashes, full
QEMU command, raw output and result JSON are retained under `runs/`.

All modes open eight per-CPU BPF_OUTPUT events (config 10, RAW output). The
default `--mode task` opens one TASK_CLOCK event for the current TID; `--mode cpu`
opens eight per-CPU CPU_CLOCK events and attaches the same program to each.
`--mode trace` opens eight TRACEPOINT events for PulseOS SchedSwitch ID 2,
program type 5, and copies its existing 72-byte version-1 context. The two
small variants `--mode block` and `--mode wake` use the same tracepoint program
and control flow for TaskBlock ID 3 (72 bytes) and TaskWake ID 4 (80 bytes). A PERF_EVENT program copies its full 64-byte
v2 context into one of eight ARRAY scratch values and submits it through helper
25 to the source CPU's output sink. The guest consumes real rings with
Acquire/Release head/tail synchronization and handles wraparound/length bounds.

Two separately labelled assembly busy loops supply exact expected IP ranges.
Both require at least two real user-mode samples attributed to the current
PID/TID in each loop. Every record must contain the correct source CPU/ring,
nonzero task/IP/time, unchanged legacy addr, and context version 2. Task mode
rejects foreign PID/TID; CPU mode counts other tasks separately. Disable/detach
checks use the sum of target and foreign records, so continuing output from any
CPU cannot hide behind the target filter.

Before enabling production, every mode tries two invalid PerfEventArray updates:
a sampling source into slot 0 and CPU 1's BPF_OUTPUT sink into slot 0. Both must
return EINVAL (-22), and MAP_LOOKUP must show slot 0 still holds its original
valid sink. The subsequent live workload must still produce records.

Task mode then runs two independent additional sessions after closing its first
source. In the first, closing the source perf FD while its Link remains open must
retain sampling; detach and Link close must stop it. In the second,
PERF_EVENT_IOC_SET_BPF attaches the program, dup preserves the event across close
of the original FD, and closing the final duplicate must stop production without
an explicit DISABLE. Both sessions require real loop-A IP samples while retained
and zero increment after stop plus bounded in-flight drain. FD_LIFECYCLE markers
contain their actual separate counters; the main OBSERVED/RESULT counters remain
those of the first session, so new sessions do not appear as post-disable growth. After a bounded in-flight drain grace period,
disabling the event and then detaching it must each prevent further records.
The output explicitly says `source=kernel_ring`; old bpf_smoke fixed-record PASS
markers cannot satisfy this gate.

Task mode also reads the actual TASK_CLOCK counter around a 100 ms sleep. It
requires a blocking interval of at least 80 ms and a counter delta no greater
than one fifth of the observed wall interval plus 2 ms of syscall/scheduling
overhead. A wall-clock-based counter fails that check. Input, observed counts,
final counts and lifecycle markers all carry the mode; payload build outputs
are isolated by architecture and mode.

Trace mode uses real yield/nanosleep workloads and separately validates event
ID/version, source CPU/ring, per-CPU monotonic timestamp, distinct nonzero
prev/next task IDs and origin task identity. It reports actual scheduler record
count and distinct observed task subjects (bounded at 64, with an explicit cap
flag), plus `target_contexts` when the producer supplies the guest PID/TID.
Kernel tasks and other processes are allowed; that optional identity count is
not used to pretend every observed switch belongs to the test process. At least
two switches and two subjects are required. Trace mode uses separate
TRACE_OBSERVED/TRACE_RESULT markers and cannot pass using CPU sample markers.
Block mode validates the nonzero blocking task and block sequence, wait reason
and reserved bytes. Wake mode validates a nonzero target and block sequence,
waker identity (which may be zero), wake-source ABI and reserved bytes; it does
not impose switch-specific prev/next constraints. Both variants require at least
two real records and one valid task subject, have their own BLOCK/WAKE markers,
and repeat the same sink rejection, disable and detach checks.

This test proves neither complete callchains nor exhaustive CPU-clock accounting
across all tasks. It does not implement capture/archive semantics (#191). Unsupported
v2 context, zero samples, inconsistent identity, ring loss/corruption, timeout,
or absent disable/detach evidence fail the test. The host validator checks the
emitted counts and lifecycle markers, but their truth depends on this deployed
payload's real ring consumer, not on arbitrary user-supplied text.

Observed red baseline (2026-11-14): both old RV64 and LA64 kernels reject the
v2 context read at offset 48 during BPF_PROG_LOAD with `-13`; the verifier log
reports `22: invalid context access at offset 48 size 8`. This is the expected
pre-implementation failure, not a successful sampling run. Logs are retained in
`runs/riscv64-20261114-221044-iqp4d9j1/` and
`runs/loongarch64-20261114-221044-h6m9cpye/`. A prior RV run stopped in an
unrelated boot PCP self-check before this payload and is not used as red proof.

The separate trace red baseline uses the archived old RV64 kernel from that run.
It successfully loads/attaches the 72-byte tracepoint program, then observes
`sched=0 subjects=0` after actual nanosleep/yield workload and fails instead of
emitting PASS. Log: `runs/riscv64-trace-20261114-222203-zw_rfpkz/`. This demonstrates
that the trace gate detects the absent production queue consumer independently
of the new CPU-sample context ABI.
