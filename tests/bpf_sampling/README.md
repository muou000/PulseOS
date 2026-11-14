# Real software sampling and capture (#190 / #191)

This freestanding RV64/LA64 guest uses raw Linux-shaped syscalls and checks actual
`PERF_SAMPLE_RAW` records produced by a loaded BPF program. It never synthesizes
sample/loss counters. With `--archive`, the host converts its actual RAW frames
through `bpf-capture` and then verifies the standalone file with `bpf-analyzer`.

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
across all tasks. Unsupported
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


## Runtime archive

```bash
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode task --archive
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode trace --archive
# Both architectures, task and trace, with no static-fixture fallback:
python3 tests/bpf_smoke/run.py gate
```

The consumer copies each complete ring frame **before** publishing the Release
store to `data_tail`; `data_head` is loaded with Acquire. Its bounded private
archive is exported after the source is disabled, accepted invocations finish,
and the rings drain. A bounded proc polling loop confirms `inflight=0`
for every disabled source before the final drain; a fixed sleep is not used as
a substitute for that publication boundary. Per-frame sequence, source CPU, CRC32 and length plus a
whole-stream checksum detect damaged/missing/reordered serial output. The
host rejects an empty producer or empty consumer. It uses an explicit context
format: a 64-byte software v2 sample cannot be guessed from length because the
legacy TaskEnqueue trace context is also 64 bytes.

A run directory includes `records.pbraw`, original `stats-before.txt` and
`stats-after.txt`, `archive.json`, `inputs.json`, the saved kernel/ELF/rootfs,
`capture.pbcapture`, and analyzer JSON/table/loss reports. `guest.log` is the raw
QEMU output, not a fabricated normalized-record stream. `result.json` separates
the gate result from the capture's partial status. A valid partial capture can
pass this authenticity gate; it cannot claim complete attribution.

The kernel build produces `<kernel.elf>.provenance.json`; retain this alongside
the ELF. `--kernel-elf` and `--kernel-provenance` select explicit saved inputs.
The harness checks that the boot bytes match the ELF (objcopy for RV raw boots),
then checks the manifest's artifact hashes. Build-time commit, dirty input tree
hash, effective configuration and compiler are saved inside capture diagnostics.
A missing manifest leaves the source commit **unknown**, while a supplied but
mismatching manifest fails. `workspace_commit` records only the harness workspace
and must never substitute for kernel provenance. The injected boot rootfs hash
is recorded separately from its original image hash.

`PBRW0001` has a 64-byte LE header (magic, start/stop, frame count, stream bytes,
IEEE CRC32, export-drop count, 16 reserved zero bytes). Each envelope has
`sequence:u64, cpu:u32, frame_bytes:u32, crc32:u32, reserved:u32` followed by the
unchanged aligned PERF_RECORD. The standalone capture uses format **2**, retains
the normalized schema registry, and stores typed optional diagnostics plus the
full runtime evidence. Format 2 uses IEEE CRC32; format 1 preserves its historical
nonstandard checksum for compatibility. Unknown fields are `null`, not zero.

`/proc/pulse_bpf_stats` is read-only and exposes the calling process's current
PerfEvent FDs and referenced programs. Each open creates a stable, lazily captured
snapshot, permitting fragmented reads; reopening refreshes it. A 64 KiB bound or
unavailable provider fails explicitly. The guest deliberately reads an 8-byte
prefix followed by 97-byte chunks and verifies stable EOF. FD-table entries are
cloned before event locks/callbacks. Source snapshots must show disabled and
inflight=0; event-level counters are read with the control lock held. GLOBAL
counters are system-wide and their snapshot window can include activity outside
the narrower capture interval. This is not a simultaneous whole-system snapshot.

Counter meanings, without double counting:

- source `observed`: source observations examined, not successful samples;
  `delivered`: successful BPF VM executions; `skipped`: periods without a sampled
  PC; `cancelled`: rejected old queued epochs;
- PROGRAM `runs - errors`: successful VM executions, reconciled with source
  delivery; it overlaps that source count;
- output sink `delivered`: samples enqueued; `transport_lost`: rejected samples;
  saved samples + export-dropped samples equal sink delivery;
- source delivery equals sink delivery + sink transport loss for this fixed
  copy-and-output program. Raw LOST records are notifications and can lag the
  authoritative sink counter; neither value is added to the other;
- export drops are samples/notices copied from the ring but omitted from the
  bounded archive. Global queue drops, source skips, VM errors, transport loss
  and export drops remain separately scoped. Consumer corruption/bounds and
  all implemented event/program counters remain visible. The kernel
  `consumer_corrupt/consumer_bounds` counters describe its parser API; the guest
  mmap consumer instead fails explicitly on malformed records. They are not
  presented as the same consumer.

Unsupported verifier/load/attach totals, process RSS, kernel allocation cost and
clock resolution are explicitly unknown. The three phases run the same 128
workload iterations: baseline, loaded-but-detached and attached-with-capture.
Each stores actual monotonic timestamps, wall time, derived iterations/second,
and successfully mapped sampler-owned virtual bytes. These bytes are **not RSS**
or total kernel memory; no unmeasured overhead threshold or parity is asserted.
`capture.pbcapture` is useful independently of `guest.log`; both CPU folded and
off-CPU output remain partial and do not imply available callchains or mappings.

Fault probes use the same program and consumer, with one deliberate fault:

```bash
# Must fail: production disabled, no consumption, or exit before archive END.
python3 tests/bpf_sampling/run.py guest --arch riscv64 --archive --fault zero-producer
python3 tests/bpf_sampling/run.py guest --arch riscv64 --archive --fault zero-consumer
python3 tests/bpf_sampling/run.py guest --arch riscv64 --archive --fault aborted
# Must save nonzero actual records AND nonzero export loss, marked incomplete.
python3 tests/bpf_sampling/run.py guest --arch riscv64 --archive --fault export-overflow
# Fill real Perf Buffers without draining, then preserve their authoritative loss.
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode trace --archive --fault ring-overflow
```

The export overflow probe reduces the private archive to one page. The separate
ring-overflow probe uses one-page Perf Buffers and pauses consumption during the
attached phase. It requires nonzero sink `transport_lost` and incomplete output;
raw LOST notices may still be zero because sources are stopped before space is
freed for a later producer notification. Host tests
also exercise malformed RAW boundaries/checksums/counts, counter inconsistencies,
corrupt/truncated capture trailers and unknown diagnostics. Existing
`pulse_syscalls` tests cover Perf Buffer wraparound, overflow/LOST and ring
corruption, plus Ring Buffer producer publication/ordering. These unit fixtures
are isolated from QEMU's actual-record gate.


Use `--ring-pages 1 --mode trace --archive` for real guest wrap evidence. Each
CPU reports its actual final head/tail and number of frames crossing the ring
end. The host recomputes byte positions and crossing counts from the RAW stream
when no export frames were dropped; it rejects a mismatch. The concurrent host
PerfBuffer regression separately sends 20,000 patterned records through one
page, with head/tail publication as its only per-record synchronization, checking
both header and payload crossings. Neither test replaces the Acquire/Release
contract or proves arbitrary weak-memory executions.
