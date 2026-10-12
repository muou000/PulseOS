# Ring Buffer and Perf Buffer compatibility paths

Context: Wayfinder issue [#82](https://github.com/muou000/PulseOS/issues/82).

## Primary sources and repository evidence

- Linux ring buffer design: [`Documentation/bpf/ringbuf.rst`](https://github.com/torvalds/linux/blob/master/Documentation/bpf/ringbuf.rst).
- Linux BPF UAPI map/helper definitions: [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h).
- Linux perf UAPI and record formats: [`include/uapi/linux/perf_event.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/perf_event.h).
- Current first-party libbpf consumer implementation: [`src/libbpf.c`](https://github.com/libbpf/libbpf/blob/master/src/libbpf.c), `perf_buffer__new`, per-CPU buffer setup, record processing, and ring-buffer APIs.
- PulseOS FD/poll primitives: [`pulse_core/src/fd_table/mod.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/fd_table/mod.rs), [`pulse_core/src/fd_table/epoll.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/fd_table/epoll.rs), and [`pulse_syscalls/src/impls/fs/epoll.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/src/impls/fs/epoll.rs).
- PulseOS user-memory mapping and mmap syscall paths: [`pulse_core/src/mm/`](https://github.com/muou000/PulseOS/tree/main/pulse_core/src/mm/) and [`pulse_syscalls/src/impls/mm.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/src/impls/mm.rs).
- PulseOS current qperf output is an external QEMU-plugin marker, not either Linux BPF buffer: [`arceos/modules/axtask/src/qperf_trace.rs`](https://github.com/muou000/PulseOS/blob/main/arceos/modules/axtask/src/qperf_trace.rs).

## Shared requirements

Both Linux output paths provide variable-length records, nonblocking producer behavior when full, a memory-mappable user-space consumer area, event notification through epoll, and an optional busy-poll path. Both therefore need more than a BPF helper:

- a kernel-owned buffer and producer/consumer memory-ordering protocol;
- a map object with a real BPF FD and metadata visible through `BPF_OBJ_GET_INFO_BY_FD`;
- BPF helper validation and runtime failure reporting;
- a user mapping whose lifetime is tied to the map/event object;
- poll/epoll readiness and teardown behavior;
- explicit attempted, delivered and dropped counters for capture correctness.

A full buffer must never block a scheduler, tracepoint or perf-event producer. The helper must return a failure or NULL according to Linux semantics, and the sampler must count that loss.

## `BPF_MAP_TYPE_PERF_EVENT_ARRAY` / Perf Buffer

### Kernel-side model

Linux presents the Perf Buffer path as a `BPF_MAP_TYPE_PERF_EVENT_ARRAY`. The map is an array indexed by CPU; userspace creates one software perf event per selected CPU and stores each perf-event FD into the corresponding map slot. The BPF helper `bpf_perf_event_output(ctx, map, flags, data, size)` requires the map type and a perf event configured with:

- `type = PERF_TYPE_SOFTWARE`;
- `config = PERF_COUNT_SW_BPF_OUTPUT`;
- `sample_type` containing `PERF_SAMPLE_RAW`.

The helper chooses the target CPU through flags (including the current-CPU mask) and copies the bounded raw payload into that CPU's perf ring. The perf UAPI frames delivery as `PERF_RECORD_SAMPLE`; buffer overflow is observable as `PERF_RECORD_LOST` with a lost count.

Before any BPF program can emit, userspace must open/configure the perf event and update the map's CPU slot. This creates an explicit race/error boundary: a program can load successfully but output fails until the map has been populated and the event enabled.

### libbpf consumer behavior

The current libbpf implementation does the following:

1. Calls `BPF_OBJ_GET_INFO_BY_FD` to sanity-check the map type and `max_entries`.
2. Determines the online CPU set, allocates one `perf_cpu_buf` per selected CPU, and creates an epoll FD.
3. Calls `perf_event_open` for each CPU with `PERF_COUNT_SW_BPF_OUTPUT` and `PERF_SAMPLE_RAW`.
4. Maps `page_count * page_size + metadata page` with `mmap(MAP_SHARED)`.
5. Stores each perf-event FD in the BPF map keyed by CPU and enables the event.
6. Uses `epoll_wait` and parses perf records. `PERF_RECORD_SAMPLE` invokes the sample callback; `PERF_RECORD_LOST` invokes the lost callback with the number of records lost.
7. On teardown, deletes the per-CPU map entries, disables events, unmaps, closes perf FDs and closes epoll.

The libbpf path accepts a power-of-two page count and can use a caller-provided CPU list/map-key list. A PulseOS implementation intended to run this workflow must therefore expose compatible perf-event FD mmap/ioctl/poll behavior, not just a read syscall on a private character device.

### Strengths and costs

Strengths:

- This is the established output path for older and widely used libbpf tracing programs.
- Per-CPU buffers isolate producer contention and make CPU attribution direct.
- `PERF_RECORD_LOST` gives a standard loss callback and count.
- Fixed raw payloads map naturally to the first typed PulseOS event record.

Costs:

- It requires `perf_event_open`, `PERF_COUNT_SW_BPF_OUTPUT`, perf FD ioctls, per-CPU map slots, mmap layout, online-CPU discovery, epoll, and perf record parsing.
- Ordering is per CPU rather than a single global event order. Cross-CPU task lifecycle reconstruction needs timestamps and explicit merge rules.
- Buffer sizing and per-CPU allocation can be expensive on many CPUs.
- The output helper copies the record into the perf buffer and can fail when the target CPU buffer is full.

## `BPF_MAP_TYPE_RINGBUF` / Ring Buffer

### Kernel-side model

Linux presents one shared ring buffer as a `BPF_MAP_TYPE_RINGBUF` map. Its key and value sizes are zero, and `max_entries` specifies a power-of-two buffer size. It reuses the BPF map object model and can be combined with map-in-map types, but it does not support ordinary key/value lookup/update/delete operations.

The kernel design is a multi-producer/single-consumer buffer shared across CPUs. It uses producer and consumer logical counters and an 8-byte per-record header with busy/discard state. Reservations are serialized; commits are lockless and records become visible in reservation order after earlier records are committed. This preserves cross-CPU temporal ordering that per-CPU perf buffers do not provide.

The BPF helper APIs are:

- `bpf_ringbuf_output()` copies a bounded record into the ring and resembles `bpf_perf_event_output()`.
- `bpf_ringbuf_reserve()` returns a pointer into ring memory; the program fills it and must call `bpf_ringbuf_submit()` or `bpf_ringbuf_discard()`.
- `bpf_ringbuf_query()` returns advisory snapshots of available data, ring size, and producer/consumer positions.
- Output/submit/discard flags control adaptive, no-wakeup, or forced wakeup behavior.

Reservation failure is nonblocking and returns NULL; output failure returns a negative result. The verifier tracks every reserved record and rejects a program path that exits without submitting or discarding it. The reserved size must be known/verified so the program cannot access outside the record.

### Consumer and notification behavior

The ring buffer exposes a memory-mappable data area and epoll notifications, while also allowing busy polling. Linux's documented design maps the data area twice contiguously so records wrapping the circular boundary appear contiguous to consumers. Notifications are adaptive: a commit wakes the consumer when it has caught up to the committed record; if unread data already exists, an extra wakeup is unnecessary. No-wakeup/force-wakeup flags allow batching but shift correctness responsibility to the BPF program.

This path does not produce `PERF_RECORD_LOST` records automatically. A full reservation/output failure must be counted by a BPF-side map, helper return value, or an explicit kernel-side lost counter that the host capture records. Discarded records are distinct from buffer-full losses and must be represented separately if analysis needs to distinguish them.

### Strengths and costs

Strengths:

- One shared buffer can preserve event order across CPUs, which is valuable for task lifecycle and scheduler analysis.
- No perf-event FD per CPU is required for the output map itself.
- Reserve/commit avoids an extra copy for fixed-size records and can outperform copy-based output.
- The map object integrates with BPF introspection and libbpf rather than inventing a private container API.

Costs:

- Shared producer contention and the reservation protocol need careful atomic ordering and interrupt/preemption rules.
- The verifier must model reserved-record references and require submit/discard on every path.
- The mmap layout, double mapping, record headers and adaptive wakeups are a new implementation surface for PulseOS.
- Zero-copy reserve accepts only verifier-provable record sizes; a variable-size record may need `bpf_ringbuf_output()` and an extra copy.
- A lost-record contract is not supplied by perf's standard `PERF_RECORD_LOST`; PulseOS must design one for capture completeness.

## Comparison for PulseOS

| Dimension | Perf Buffer | Ring Buffer |
|---|---|---|
| Linux object | `BPF_MAP_TYPE_PERF_EVENT_ARRAY` | `BPF_MAP_TYPE_RINGBUF` |
| Producer topology | Per-CPU perf rings | Shared MPSC ring |
| Standard output helper | `bpf_perf_event_output` | `bpf_ringbuf_output` or reserve/submit/discard |
| User mapping | One perf-event mmap per selected CPU | Shared ring mmap, with Linux double-map layout |
| Notification | epoll from perf FDs; wakeup threshold | epoll with adaptive/no/force wakeup |
| Loss signal | `PERF_RECORD_LOST` and count | Helper/reservation failure; explicit lost counter needed |
| Ordering | Per CPU; host merges | Reservation order across CPUs |
| Verifier scope | Pointer/bounds/output size | Plus reservation reference lifetime and fixed-size checks |
| libbpf compatibility | Broad existing compatibility | Supported by modern libbpf but not every old program |
| PulseOS first cost | High, but reuses Linux perf model needed for attach/sampling | High new shared-memory/concurrency surface |

## Recommended delivery order for #87

The compatibility and migration goal argues for a staged implementation:

1. **First compatibility path: Perf Buffer.** Implement `PERF_EVENT_ARRAY`, `bpf_perf_event_output`, software `BPF_COUNT_SW_BPF_OUTPUT`, per-CPU mmap, epoll, enable/disable, and `PERF_RECORD_LOST`. This aligns with the current libbpf core workflow and gives an explicit loss callback for qperf comparison.
2. **Second path: Ring Buffer.** Add `RINGBUF` map creation/info, output helper, mmap/epoll consumer, explicit lost/reservation counters, and only then reserve/submit/discard with verifier reference tracking. Keep the map and record format Linux-shaped so modern libbpf can select it.
3. **Optional same-release target:** if implementation capacity permits, support `bpf_ringbuf_output()` copy mode before zero-copy reserve. It keeps the helper contract close to Perf Buffer and avoids making verifier reference tracking a prerequisite for the first Ring Buffer experiment.

This order does not rule out shipping both in one milestone; it identifies the compatibility-critical path and the additional semantics needed for the second. The final choice belongs to #87 and must include a capability matrix and tests for full-buffer behavior, notification behavior, teardown, and loss accounting.

## Capture facts that must survive either path

Every guest capture should record, at minimum:

- output path and map type;
- buffer size, page count, CPU set and task/event scope;
- program/map/link IDs and ABI/version identifiers;
- monotonic timestamp domain and record schema version;
- attempted, delivered, discarded, helper-failed and buffer-full record counts;
- per-CPU loss counts for Perf Buffer, and producer/reservation loss counters for Ring Buffer;
- enable/disable and phase-window markers;
- architecture, kernel commit/build feature set, matching ELF/image identifiers and host analyzer version.

Without these facts, a non-empty capture cannot distinguish complete data from a silently lossy run or compare Ring Buffer and Perf Buffer results fairly.
