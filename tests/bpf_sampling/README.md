# Real software sampling and capture (#190 / #191)

This freestanding RV64/LA64 guest uses raw Linux-shaped syscalls and checks actual
`PERF_SAMPLE_RAW` records produced by a loaded BPF program. It never synthesizes
sample/loss counters. With `--archive`, the host converts its actual RAW frames
through `bpf-capture` and then verifies the standalone file with `bpf-analyzer`.

## Target-page fault classification (#196)

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode fault --archive --fault-classes --timeout 240
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode fault --archive --fault-classes --timeout 240
python3 tests/bpf_sampling/fault_class_evidence.py RUN_DIRECTORY
```

The optional classification gate injects a content-checked, non-sparse two-page
file into a copied rootfs. `debugfs bmap` binds each file page to device sectors.
QEMU's `virtio_blk_handle_read` and `virtio_blk_rw_complete` events independently
record storage requests and successful completions. At each guest begin/end
marker the workload blocks on stdin; the host saves the device-trace byte cursor
before acknowledging the boundary. No elapsed-time threshold is an I/O oracle.

| Target operation | Expected classification | Required device evidence |
| --- | --- | --- |
| First anonymous read | Minor | No fixture data read |
| First cold file read | Major | Completed target-page read |
| Cached file read through another mapping | Minor | No target-page read |
| Private file COW write | Minor | No target-page read; other mapping unchanged |
| Cached target with a cold neighbor in its mapping | Minor | No target or neighbor data read |
| Subsequent first touch of that cold neighbor | Major | Completed neighbor-page read |

Each case requires exactly one successful user fault for its precise address,
PID/TID and guest time interval. RAW records must equal normalized capture
records byte for byte. `fault-classification-evidence.json` retains device reads
and classification witnesses; `device-reads.log`, `fault-boundaries.json`,
`fault-file-layout.json` and `fault-file-bmap.txt` make the check replayable.
The gate rejects a fixture read before its cold phase, missing/failed device
completion, Unknown target classification, and misattributed neighbor I/O.
The resident-target path returns a shorter optional batch; the neighbor's read
is independently attributed to the subsequent fault that actually requests it.
The existing 128 isolated anonymous read/write iterations and source shutdown
checks still run. Generic fault captures preserve Unknown for unverified
provenance; that is a current classification, not a historical format fallback.

The runtime red baseline at
`runs/riscv64-fault-20261115-205350-unuhvqom` produced 263 real completed faults
and a valid capture using an archived BPF-enabled kernel, but failed this new
gate because its target classifications were Unknown. Its independent device
trace recorded eight target sectors for the cold phase, eight neighbor sectors
for the mixed batch, and zero fixture sectors for anonymous/hot/COW phases.

## Time-valid mappings and ELF artifacts (#193)

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu --archive --mappings --timeout 300
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu --archive --mappings --timeout 300
target/debug/bpf-analyzer RUN/capture.pbcapture --mapping-report --bundle RUN
```

`--mappings` reads the producer's bounded boot journal before source enable and
after disable/quiescence. Both original proc snapshots have serial byte counts
and CRC32; `mappings.txt` is the exact final stream retained inside capture.
The initial stream must be a prefix of the final stream and its cut must precede
every enable boundary. This is historical evidence, not a terminal `/proc/maps`
snapshot. Stable task IDs, address-space IDs, exec generations, full VMA
revisions, mutation windows, TLB completion tokens and object SHA identities are
checked independently against actual RAW samples. Metadata loss remains partial;
the positive gate requires no metadata loss. Samples inside transitions remain
unknown, including intervals before a pending TLB token completes.

Combined `--stacks --mappings` runs request 50 ms and 100 ms periods for the two
instances on each CPU. This keeps all mutation phases inside the existing 8 MiB
archive budget; the manifest records those actual requested/effective periods.
Other software sampling modes retain their 10 ms base period.

The workload maps the current executable at byte offset 4096, calls a checked
relocation-free loop at its new address, renames the executing file, forks and
calls the inherited mapping, then execs a separately built ELF in the child.
It also changes permissions, moves/expands the parent mapping with `mremap`,
moves just the second page of a separate two-page mapping (retaining its
nonzero file offset), unmaps the ranges and waits for the child to exit. Every workload phase requires actual
user IP samples and content-verified symbol resolution. `mapping-evidence.json`
is the independent RAW/journal oracle; `mapping-report.json` must agree with its
task, generation, mapping, byte offset and `mapped_busy_loop` symbol examples.
The original sample IP is retained when translating via the ELF PT_LOAD table.

`artifacts.json` binds copied kernel, parent and child ELFs to their SHA-256 and
actual GNU build-id notes. No note is recorded as `null`; a truncated SHA is
never substituted. The parent fixture deliberately has no build-id and the
child requests one from the linker. Embedded debug sections are recorded and
bound to the same ELF SHA. External debuglink files, if unavailable, remain
explicitly unavailable. Artifact filenames are content-addressed; paths in the
mapping journal are labels only. The runtime kernel text bounds and `_stext`
reference must match the exact boot ELF after the measured relocation delta.

After each real capture, the host reruns the standalone analyzer with an empty
bundle and with the parent/child bytes swapped under their expected filenames.
Both must retain mapping facts while refusing ELF resolution for all six real
mutation examples. Results are saved in `mapping-negative-report.json`.
The report leaves busy/idle residence unknown: scheduler selection and user
task classification do not supply IRQ/idle accounting. Mutable ordinary mmap
objects without a protected executable identity may have an unknown SHA, and
neither the host nor the analyzer fills this gap from a same-named local file.

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
opens eight per-CPU CPU_CLOCK events. Every source has its own program that
stamps a logical source ID into a 24-byte RAW envelope before the native context.
`--mode trace` opens eight TRACEPOINT events for PulseOS SchedSwitch ID 2,
program type 5, and copies its existing 72-byte version-1 context. The two
small variants `--mode block` and `--mode wake` use the same tracepoint program
and control flow for TaskBlock ID 3 (72 bytes) and TaskWake ID 4 (80 bytes). A PERF_EVENT program copies its full 64-byte
v2 context after the envelope in one of eight ARRAY scratch values and submits it through helper
25 to the source CPU's output sink. The guest consumes real rings with
Acquire/Release head/tail synchronization and handles wraparound/length bounds.

Two separately labelled assembly busy loops supply exact expected IP ranges.
Both require at least two real user-mode samples attributed to the current
PID/TID in each loop. Every record must contain the correct source CPU/ring,
nonzero task/IP/time, zero data address, and context version 2. Task mode
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
# Both architectures, task/trace/sched/fault, with actual RAW capture:
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
TaskEnqueue trace context is also 64 bytes. Raw import requires the declared
context kind; it does not fall back to the removed v1 software layout.

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
unchanged aligned PERF_RECORD. Each sample's RAW payload starts with
`magic:u32=0x31524250, version:u16=1, kind:u16, context_bytes:u32,
logical_source:u32, reserved:u64=0`, then the declared native context. Kinds 1,
2 and 3 mean software single IP, tracepoint and software stack respectively.
The program stamps this logical ID; CPU, period, payload length and diagnostics
never select a source. Stack contexts additionally retain the independent kernel
event ID, which must agree with the explicit source declaration.

The standalone capture uses only format **6** with IEEE CRC32, required
`PBSRC003` typed sources and per-record bindings, required diagnostics, and
explicit stack/mapping extension bits. `ARCHIVE SOURCE` exports numeric source
facts: logical/kernel/program/link identity, context kind/schema, monotonic
clock, requested/effective config, stable task identity or CPU scope, requested
period/frequency and buffer pages, effective parameters, units/fallback and
per-source enable/disable windows. Original proc snapshots independently check
these declarations and retain layered counters. Missing provenance is rejected;
missing measurement evidence stays unknown and partial. Source, stack and
mapping/artifact evidence can coexist in the same session.

Historical capture formats 1–5 and unstamped native RAW samples are rejected by
current importers/readers. Files under `evidence/191` through `evidence/196`
retain their original baseline identity and hashes; use their archived tools to
reproduce historical results. They are not rewritten into format 6 or counted as
new-format runtime evidence. Unknown fields are `null`, not zero.

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


## Scheduler and fault reports (#184 / #185)

```bash
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode sched --archive
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode fault --archive
bpf-analyzer session.pbcapture --sched-report --json --pid 123
bpf-analyzer session.pbcapture --fault-report --json --address-start 0x400000 --address-end 0x800000
```

`sched` loads one explicitly stamped program per source for IDs 1–6: 48 programs
and 48 per-CPU sources sharing eight
output sinks. Each program copies its declared context size; every source's
CPU/event/program binding and every program's execution counters are checked.
It requires real block, wake, switch and enqueue streams. Metadata or exit counts
can legitimately be zero when no task is created/exits during the window.
The independent scheduler report requires an observed Blocked switch-out before
wake and switch-in. Wake-before-switch, missing history, repeated events,
ambiguous timestamp order and unclosed episodes stay explicit. `blocked_wait_ns`
and `wake_to_switch_ns` are separate; neither measures the switch function.

`fault` uses ID 8, an 80-byte completion record. It preserves the entry task,
access, privilege origin, resolver start/result and completion CPU/time. Wall
latency includes descheduling. Successful resolutions use actual target-page
I/O provenance for major/minor classification; unverified provenance stays
Unknown. The dedicated #196 gate above checks the classification against
independent storage-read evidence.
The known workload separates first-read and first-write pages with an inaccessible
middle page, so anonymous batch fault preparation cannot make the second target
resident before its intended access. Each iteration verifies zeros and stored
bytes, removes its mappings and uses the same pacing in all three phases.
The host matches actual RAW records to the reported PID/TID, exact target address
sets and READ/WRITE bits. The fault probe rejects export overflow because it
cannot independently reconstruct the missing target hits.

GLOBAL fault_started/fault_completed/fault_clock_errors are system observations,
not per-FD VM counts. A resolver may outlive stop, so neither started-completed
nor VM inflight=0 is called a global aborted/completed-resolver total. The capture
retains these counters without adding overlapping queue/program/transport losses.

The analyzer's Query intersects phase/time/task/PID/TID/CPU/address filters;
relationships are reconstructed before selection. The same Query applies to
text, JSON and folded outputs. Missing/ambiguous phase boundaries are errors.
CPU folded uses explicit samples or period-ns weights and is empty without CPU
samples. The `--offcpu` output is specifically observed blocked
interval duration-ns, with no fallback to event counts or a fabricated weight 1.
New `scheduler-report.json` / `faults-report.json` are saved by the archive driver;
valid semantic instances must be nonzero for those two modes. This is a fixed
regression workload. The general-purpose recorder is documented in
[`docs/bpf-record.md`](../../docs/bpf-record.md).

## Frozen frame-pointer stack gate (#192)

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode task --stacks --archive --timeout 300
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode task --stacks --archive --timeout 300
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu --stacks --archive --timeout 300
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu --stacks --archive --timeout 300
```

`--stacks` copies the 640-byte `software-stack-v3` context through the real BPF
program and output rings. It requires an archive and matching kernel ELF. The
original 64-byte version-2 prefix remains unchanged. Kernel `bpf-trace` builds
and this guest request compiler frame pointers. Explicit assembly supplies two
three-level user call trees with separately labeled return sites; captured IPs
must equal those labels, not merely fall inside an executable mapping.

The guest also issues populated anonymous mmap/munmap calls. The host checks
actual RAW kernel chains against the exact boot ELF, requires at least three
resolved distinct functions, and requires observed mmap/munmap or prefault
ancestry. It writes `stack-evidence.json` with hashes, representative original
IPs, ELF symbol names, source counts, and termination-reason counts. Unavailable
or partial chains remain recorded and cannot pass as complete unwinds. A kernel
sample never receives an invented user caller, and the guest's synthetic
negative frame records never count as the real positive call-tree evidence.

Negative assembly probes exercise zero FP, a frame whose page is nonresident, a
frame cycle, bad return address, misaligned FP, and a real 41-level recursive
call stack. The unreadable-frame probe points into a readable, lazy anonymous
VMA above the ordinary user stack: its PTE is absent, so the sampler's dedicated
load must fault and return without populating it. `mincore` before and after
requires that page to remain nonresident. Every probe needs an actual timer
sample with the expected reason; a lock-contention `busy` result can be retained
but cannot satisfy that probe. The host independently compares raw records with
the probe PC ranges in the payload ELF.

CPU stack mode opens **two** CPU_CLOCK events on each CPU (10 ms and 20 ms).
The archive checks stable `source_id`, scope, and period against per-event
proc diagnostics, then reconciles the actual record count for each source when
transport/export loss is zero. Task stack mode preserves the task-clock sleep
and FD-lifetime checks. Task/cpu runs without `--stacks` use 64-byte v2 contexts;
unknown required context versions are rejected.
