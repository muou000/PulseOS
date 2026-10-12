# Linux perf_event and tracepoint sampling semantics for PulseOS

Context: Wayfinder issue [#81](https://github.com/muou000/PulseOS/issues/81).

## Primary sources

- Linux perf UAPI: [`include/uapi/linux/perf_event.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/perf_event.h).
- Linux BPF UAPI: [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h).
- Linux tracepoint documentation: [`Documentation/trace/tracepoints.rst`](https://github.com/torvalds/linux/blob/master/Documentation/trace/tracepoints.rst).
- Current first-party libbpf implementation: [`src/libbpf.c`](https://github.com/libbpf/libbpf/blob/master/src/libbpf.c), including tracepoint ID discovery, `perf_event_open`, BPF attach, and perf-buffer setup.
- PulseOS qperf event ABI: [`arceos/modules/axtask/src/qperf_trace.rs`](https://github.com/muou000/PulseOS/blob/main/arceos/modules/axtask/src/qperf_trace.rs).
- PulseOS qperf build path: [`Makefile`](https://github.com/muou000/PulseOS/blob/main/Makefile), target `qperf`.
- Existing PulseOS Linux-compatibility boundary: [`pulse_syscalls/README.md`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/README.md).

## Linux perf event control plane

Linux `perf_event_attr` distinguishes event sources through `type` and `config`:

- `PERF_TYPE_SOFTWARE` (`type = 1`) uses `perf_sw_ids`, including `PERF_COUNT_SW_CPU_CLOCK`, `PERF_COUNT_SW_TASK_CLOCK`, context switches and `PERF_COUNT_SW_BPF_OUTPUT`.
- `PERF_TYPE_TRACEPOINT` (`type = 2`) uses the numeric tracepoint ID in `config`.
- Hardware, raw, cache, breakpoint and architecture-specific sources are separate types and are outside the first portable target.

The attribute carries the event size, `sample_period` or `sample_freq`, `sample_type`, `read_format`, wakeup threshold, and control flags such as `disabled`, `inherit`, `exclude_user`, `exclude_kernel`, `enable_on_exec`, and `task`. PulseOS should accept only fields it implements and reject unsupported combinations rather than ignore them silently.

The perf FD ioctl ABI includes `PERF_EVENT_IOC_ENABLE`, `DISABLE`, `RESET`, `PERIOD`, `SET_OUTPUT`, `SET_BPF`, and query operations. Current libbpf uses `PERF_EVENT_IOC_SET_BPF` as a fallback attach path, enables the event after attaching, disables it before teardown, and closes the FD. A link-based path uses `BPF_LINK_CREATE` with `BPF_PERF_EVENT`, but the perf event itself remains the sampling/attachment target.

A first PulseOS implementation should define an explicit software-event matrix:

| Linux source | First recommendation | Meaning |
|---|---|---|
| `PERF_COUNT_SW_CPU_CLOCK` | Required | A per-CPU monotonic software clock source for periodic sampling. |
| `PERF_COUNT_SW_TASK_CLOCK` | Required if task-scoped sampling is exposed | Monotonic CPU time attributed to a task/thread. |
| `PERF_COUNT_SW_BPF_OUTPUT` | Required for the Perf Buffer path | Output event used to deliver `bpf_perf_event_output` records into per-CPU buffers. |
| context-switch/page-fault/migration software events | Defer or implement only with matching event counters | Useful Linux perf counters, but they need explicit PulseOS accounting semantics and are not necessary if typed tracepoints cover the first analysis. |
| hardware/raw/cache events | Stable `EOPNOTSUPP` initially | PulseOS targets two architectures and cannot assume a common QEMU PMU or identical counters. |

## Tracepoint discovery and attach

The libbpf tracepoint implementation performs this concrete sequence:

1. Resolve `<tracefs>/events/<category>/<name>/id` and parse its integer ID.
2. Fill `perf_event_attr` with `type = PERF_TYPE_TRACEPOINT`, `size`, and `config = id`.
3. Call `perf_event_open(attr, pid = -1, cpu = 0, group_fd = -1, PERF_FLAG_FD_CLOEXEC)` for the CPU/event scope.
4. Attach the loaded BPF program using `BPF_LINK_CREATE`/`BPF_PERF_EVENT` when supported, or `PERF_EVENT_IOC_SET_BPF` as the legacy fallback.
5. Enable the perf event unless delayed enable was requested.
6. Return a link/perf FD whose close or explicit detach removes the attachment and disables the event.

This implies that a Linux-shaped PulseOS tracepoint facility needs:

- a stable category/name registry and numeric ID discovery interface;
- one versioned context layout per tracepoint, not only a raw callback with private Rust arguments;
- a perf event object that can be scoped to a CPU or task and can be polled/controlled;
- attach and teardown semantics visible through real FDs;
- deterministic behavior if a tracepoint is absent or an event is already attached.

Linux's tracepoint documentation describes tracepoints as runtime hooks that call registered probes in the caller's execution context when enabled, with typed prototypes declared by the event. This is a good semantic model for PulseOS, but the context must exclude internal pointers and locks. A BPF program must never be able to retain or dereference a `TaskInner` pointer after the callback.

## Periodic software sampling

A portable first sampler can use software clock events rather than PMU instruction counters. The control semantics should be Linux-shaped:

- A period-based event fires after the configured count/time period; a frequency-based event requests an approximate rate. If PulseOS implements only one, reject the other with `EOPNOTSUPP` and advertise the capability explicitly.
- `pid = -1` with a CPU selects a per-CPU event; a task PID/TID with `cpu = -1` selects task scope. Mixed or unsupported scopes return `EINVAL`/`EOPNOTSUPP` according to the selected contract.
- `disabled` creates the event stopped; `ENABLE`, `DISABLE`, and `RESET` change state without destroying the FD.
- Timestamp, CPU and task identity must use one monotonic time domain and one task identity convention across tracepoints, software samples and capture metadata.
- Sampling in scheduler/IRQ-adjacent paths must not sleep or allocate unbounded memory. A full output buffer must increment a drop counter and continue the guest, not block the sampled task.
- If a sample is generated while another sample or tracepoint is executing on the same CPU, re-entry policy must be explicit: bounded nesting, drop-on-reentry, or a separate per-CPU queue. Silent recursive execution is unsafe.

The first `PERF_EVENT` BPF context should contain portable scalar fields: event ID/version, monotonic timestamp, CPU, PID/TID, and the implemented period/counter values. Do not expose RISC-V or LoongArch register frames until their ABI and unwinding semantics are fixed.

## Sampling records and loss

Perf UAPI defines `PERF_RECORD_SAMPLE` and `PERF_RECORD_LOST`; sample formats can include TID, TIME, CPU, period, ID and raw payload. The UAPI explicitly notes that `PERF_SAMPLE_RAW` contents are not a general stable ABI: their meaning depends on the event and configuration. PulseOS therefore needs a typed BPF event record format inside the selected output map, even if the outer perf ring follows Linux record framing.

Loss is first-class evidence. Userspace must observe and persist:

- per-buffer/per-CPU lost records reported by perf output;
- samples dropped before enqueue because the BPF budget, re-entry policy or event queue was full;
- verifier/helper/output failures that suppress a record;
- total attempted, delivered and lost counts for each event/program and capture window.

A capture with non-zero loss can still be useful, but its analysis must report the loss and cannot claim complete off-CPU attribution. The qperf operating instructions already require checking sample drops, event drops, complete trailer and the same phase window; BPF should carry the same evidence categories in its own capture metadata.

## PulseOS qperf event candidates

The current `qperf_trace` module defines a feature-gated, six-argument marker ABI with these semantic events:

| Existing event | Current payload semantics | BPF tracepoint candidate |
|---|---|---|
| Task metadata | task ID, PID, TID, up to 16 bytes of command name | `task_metadata` event with fixed string/byte-array field and version |
| Scheduler switch | previous task ID, next task ID, previous state | `sched_switch` with CPU, timestamp, prev/next IDs and state |
| Task block | task ID, block sequence, wait reason, resource ID/detail | `task_block` with typed wait reason/resource fields |
| Task wake | task ID, block sequence, waker task ID, wake source/source ID | `task_wake` with typed source fields |
| Task exit | task ID | `task_exit` with exit timestamp and task identity |
| Task enqueue | task ID, enqueue CPU, target CPU, queue depth, enqueue reason | `task_enqueue` with CPU/queue/reason fields |
| Phase marker | begin/end, current task ID, up to 16 bytes phase name | `phase_marker` with versioned phase string and boundary |

These are candidates, not a promise to reuse qperf's ABI. The current qperf marker is a no-op function that a QEMU plugin instruments by reading six argument registers. It has no kernel-side ring buffer, tracepoint ID, BPF context metadata, or explicit loss channel. The BPF event ABI should preserve the semantic fields while adding timestamp/CPU/version and using a stable typed record layout.

The existing events are emitted from the task run queue and syscall marker paths, with `qperf-trace` feature gating. This makes them useful source locations for BPF tracepoints, but the instrumentation must be designed so disabled BPF has minimal overhead and so the callback cannot observe transient internal state without a snapshot.

## Phase windows and qperf comparison

The qperf build is separately feature-gated and creates matching RISC-V64/LoongArch64 artifacts. Its formal BuildStorm timing window starts at the guest `BUILDSTORM_BEGIN` marker; samples before that marker are startup/pre-build evidence only. BPF must adopt an equivalent explicit window marker or a capture-side start/stop protocol. A host analyzer must not compare arbitrary wall-clock ranges between qperf and BPF.

For a valid migration comparison, hold fixed: commit and matching ELF, guest image, QEMU machine/vCPU/memory, workload, CPU/event scope, sample period/frequency, output buffer size, phase marker, and analysis symbol set. BPF instrumentation itself can perturb scheduling, so overhead must be measured with tracing disabled, BPF loaded but detached, and BPF attached with records/loss reported.

## Recommended first event/sampling ABI for #86

1. Define stable tracepoint names and numeric IDs for the existing task metadata, scheduler switch, block, wake, enqueue, exit and phase events.
2. Use one explicit versioned scalar context per event; include event ID, context version, monotonic timestamp, CPU, PID/TID/task ID and event-specific fields.
3. Implement `PERF_TYPE_TRACEPOINT` discovery/attach and Linux-shaped enable/disable/detach first.
4. Implement software `PERF_COUNT_SW_CPU_CLOCK` and `PERF_COUNT_SW_TASK_CLOCK` as portable periodic sources; defer hardware PMU/raw events.
5. Define one initial sampling mode (period or frequency), one time domain, one CPU/task scope matrix, and stable errors for unsupported combinations.
6. Count attempted, delivered, per-CPU lost and runtime-dropped records, and carry these counters into capture metadata.
7. Keep `__pulse_qperf_trace_v1` as a migration baseline only. Do not expose its six-register ABI as the BPF context contract.

This preserves Linux control semantics while giving PulseOS a versioned event model that can be implemented consistently on RISC-V64 and LoongArch64.
