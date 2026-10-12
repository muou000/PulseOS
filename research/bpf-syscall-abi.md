# Linux `bpf()` object model and PulseOS first-version ABI matrix

Context: Wayfinder issue [#79](https://github.com/muou000/PulseOS/issues/79).

## Scope and sources

This note investigates the ABI needed by the first PulseOS BPF performance sampler, not all Linux BPF functionality. The target workload is a libbpf-driven `TRACEPOINT`/`PERF_EVENT` sampler using maps and an event output buffer.

Primary sources:

- Linux UAPI and syscall documentation embedded in [`include/uapi/linux/bpf.h`](https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/linux/bpf.h), especially the `eBPF Syscall Commands` documentation and `enum bpf_cmd`.
- libbpf lifecycle documentation: [BPF App Lifecycle and libbpf APIs](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html).
- PulseOS syscall dispatch: [`pulse_syscalls/src/handler.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/src/handler.rs).
- PulseOS FD object model: [`pulse_core/src/fd_table/mod.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/fd_table/mod.rs), [`pulse_core/src/fd_table/table.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/fd_table/table.rs), and process FD access in [`pulse_core/src/task/process/fd.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/task/process/fd.rs).
- PulseOS capability checks, for example [`pulse_core/src/task/process/mod.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/task/process/mod.rs) and existing checks in [`pulse_syscalls/src/impls/misc/system.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/src/impls/misc/system.rs).

The exact supported libbpf version and ELF/BTF/CO-RE scope remain decisions for issue #83. This note therefore treats libbpf as a consumer of the Linux-shaped kernel object ABI, not as proof that every libbpf API must be implemented.

## Linux object and FD semantics

The Linux UAPI documents the following object operations:

- `BPF_MAP_CREATE` creates a map and returns a close-on-exec FD. Closing the last live reference releases the map unless another FD, pin, or attachment retains it.
- `BPF_PROG_LOAD` verifies and loads a program and returns a close-on-exec FD. Closing the last reference releases it unless another reference remains.
- `BPF_OBJ_PIN` puts a map or program under a pathname on a BPF filesystem and keeps a filesystem reference after the originating FD is closed. `BPF_OBJ_GET` opens another FD for that pinned object. The parent filesystem must be BPF FS.
- `BPF_LINK_CREATE` attaches a program and returns a link FD. `BPF_LINK_UPDATE` changes the program associated with a link; `BPF_LINK_DETACH` forcefully detaches it. Closing the link FD is also part of the normal link lifetime.
- `BPF_OBJ_GET_INFO_BY_FD` returns object-specific information (`bpf_prog_info`, `bpf_map_info`, `bpf_btf_info`, or `bpf_link_info`).
- Linux documents that BPF object FDs can be duplicated, inherited across `fork`, transferred over Unix sockets, or pinned. An object is deallocated only after all FDs and other references (pins/attachments) are gone.

These are observable semantics, not merely implementation details. A PulseOS implementation that returns a new integer without integrating with the process FD table cannot run a normal libbpf lifecycle correctly.

## Command matrix for the performance sampler

The following is the recommended first-version matrix. `Required` means required for the first libbpf performance workflow; `Defer` means it can be absent if the error is stable, documented, and does not make the supported workflow appear to succeed.

| Command | First-version status | Reason and Linux dependency |
|---|---|---|
| `BPF_MAP_CREATE` | Required for supported map types | libbpf load creates maps. Start with `ARRAY`, `HASH`/`PERCPU_HASH` if needed by aggregation, `PERF_EVENT_ARRAY`, and `RINGBUF`. Validate key/value sizes, max entries, flags, and close-on-exec FD behavior. |
| `BPF_MAP_LOOKUP_ELEM` | Required | User-space map inspection and libbpf map operations. Return Linux-shaped `ENOENT`, `EINVAL`, `EFAULT`, `EBADF`/permission errors as applicable. |
| `BPF_MAP_UPDATE_ELEM` | Required | Initial map configuration and user-space aggregation/control. Preserve `BPF_ANY`, `BPF_NOEXIST`, and `BPF_EXIST` semantics for supported maps. |
| `BPF_MAP_DELETE_ELEM` | Required for ordinary maps | Needed by normal map lifecycle and tests. Ringbuf itself does not expose ordinary key/value operations. |
| `BPF_MAP_GET_NEXT_KEY` | Required for ordinary map enumeration | Linux specifies the first-key behavior when the input key is absent and `ENOENT` after the last key. |
| `BPF_PROG_LOAD` | Required | Performs verifier-backed program load and returns a program FD. Must validate program type, instruction memory, license/name/flags as supported, map-FD relocations, helper calls, and context access. |
| `BPF_OBJ_GET_INFO_BY_FD` | Required | libbpf and diagnostics need object metadata; it also makes capability discovery and failure reports inspectable. At minimum support program/map/link info for objects PulseOS creates. |
| `BPF_LINK_CREATE` | Required for the preferred attach lifecycle | Provides a link FD whose close/detach lifecycle is independent from the program FD. Needed for a robust libbpf attach/detach workflow. The exact target representation for tracepoints/perf events is a later semantic decision. |
| `BPF_LINK_UPDATE` | Defer unless the selected libbpf path requires it | Useful for replacing a program without rebuilding an attachment, but not needed to load and collect the first sample. Return `EOPNOTSUPP` until lifecycle semantics are defined. |
| `BPF_LINK_DETACH` | Required if `BPF_LINK_CREATE` is exposed | Explicit Linux-shaped teardown; close must also release the link reference. |
| `BPF_OBJ_PIN` / `BPF_OBJ_GET` | Required for persistent sessions, optional for the first ephemeral sampler | Standard libbpf tooling may pin objects under bpffs. If bpffs is not present, either implement a real BPF filesystem namespace or make pin/get a documented deferred capability; do not accept arbitrary paths as a fake pin. |
| `BPF_PROG_ATTACH` / `BPF_PROG_DETACH` | Defer for tracepoint/perf-event first version | These legacy commands are primarily target-FD/cgroup-style attachment operations. The first performance workflow should use perf event/link semantics rather than pretending a tracepoint is a cgroup target FD. |
| `BPF_RAW_TRACEPOINT_OPEN` | Defer | Raw tracepoint arguments have no ABI guarantee in Linux UAPI and are outside the first stable typed tracepoint context. |
| `BPF_BTF_LOAD` and BTF ID commands | Defer or implement only with a defined BTF plan | BTF is needed for some libbpf/CO-RE workflows, but the first supported workflow can be fixed-layout tracepoint/perf-event programs if issue #83 accepts that boundary. If libbpf requires kernel BTF for the chosen workflow, this moves to Required. |
| `BPF_PROG_GET_NEXT_ID`, `BPF_MAP_GET_NEXT_ID`, FD-by-ID commands | Defer | Useful for global introspection/tools but not required to load one sampler. Stable `EOPNOTSUPP` is preferable to a misleading partial global registry. |
| batch map commands, `BPF_MAP_FREEZE`, `BPF_PROG_TEST_RUN`, iterator/token/stat commands | Defer | Not required by the first tracepoint/perf-event collection loop. Add only when a concrete libbpf version or test requires them. |

The command matrix must be finalized after the libbpf workflow research in issue #78 and the verifier/trace/output decisions. In particular, `BPF_LINK_CREATE` versus a `perf_event_open` FD plus `BPF_PROG_ATTACH` cannot be selected by name alone; the target object and ownership semantics need to match the selected attachment path.

## Map types for the first sampler

Linux UAPI identifies both `BPF_MAP_TYPE_PERF_EVENT_ARRAY` and `BPF_MAP_TYPE_RINGBUF`. Their semantics differ:

- `PERF_EVENT_ARRAY` is a per-CPU event-output path. It normally pairs with `bpf_perf_event_output()` and a userspace perf buffer backed by perf-event FDs/mmap.
- `RINGBUF` is a map object with zero key/value sizes and a power-of-two `max_entries`. Linux's ringbuf documentation describes a shared multi-producer/single-consumer buffer with reserve/commit/discard/output helpers, memory-mappable consumption, epoll notification, and nonblocking reservation failure when full.

Ordinary `LOOKUP/UPDATE/DELETE` should be rejected with the Linux-appropriate invalid-operation behavior for ringbuf rather than silently treating it as an array. The exact ringbuf/perf-buffer split is the subject of issue #82 and the output contract is the subject of issue #87.

## Permissions and error behavior

Linux gates program loading, map creation, attachment, and perf observation through capability and security policy checks. PulseOS already has per-process capability state and checks capability constants in syscall implementations, but `pulse_syscalls/README.md` explicitly lists Linux capabilities, namespaces, kernel configuration, and BPF as unsupported environment areas. There is no current BPF object registry, BPF filesystem, BPF FD object, verifier, or perf-event implementation.

Therefore the first implementation should:

1. Require root or an explicitly defined trusted capability for program load and attachment.
2. Keep permission checks at the syscall/object boundary rather than trusting the user-space sampler.
3. Return `EOPNOTSUPP` for recognized but intentionally deferred commands/types, `EINVAL` for malformed attributes or unsupported combinations, `EBADF` for non-BPF FDs, `EFAULT` for invalid user pointers, and Linux-shaped map lookup/update errors where the operation is implemented.
4. Avoid returning success for a command that creates an object but cannot provide its promised FD or lifetime semantics.
5. Treat verifier rejection as a load failure with a diagnostic log path analogous to Linux's verifier log; do not expose an executable program before verification completes.

Whether to expose `CAP_BPF`/`CAP_PERFMON` names or a simpler root/trusted-process rule is a decision for issue #84. The important ABI constraint is that the rule is deterministic and observable.

## PulseOS gap analysis

Present in the repository:

- Central syscall dispatch and Linux error return conventions in `pulse_syscalls/src/handler.rs`.
- A process FD table with `FdEntry`, shared open-file-description lifetime, duplication, close-range operations, polling hooks, and `Arc<dyn FdObject>` in `pulse_core/src/fd_table/`.
- User-memory access helpers and existing capability state/checks in process and syscall code.
- `linux-raw-sys` as the source of many Linux UAPI structures/constants.
- `epoll`/poll infrastructure that can be reused by a BPF event FD, although no BPF event FD exists yet.

Missing:

- A `bpf` syscall number/dispatcher implementation and a safe decoder for the variable-size `bpf_attr` union.
- BPF-specific FD object types for maps, programs, links, BTF, and event buffers.
- A global/object registry with reference counting that survives FD duplication, pinning, and attachment.
- BPF filesystem/pin namespace or an explicitly supported replacement workflow.
- `perf_event_open`, tracepoint discovery, software event sources, link/attachment registry, and event output mappings.
- Verifier/interpreter/helper implementation and map-FD relocation handling.
- BTF/ELF/CO-RE support to the extent demanded by the selected libbpf workflow.

The existing FD table is a useful integration boundary, but it is not enough by itself: BPF objects have references that outlive an individual process FD and are attached to kernel event sources.

## Consequence for #84

Issue #84 should decide a Linux-shaped minimum rather than promise every UAPI command. The non-negotiable first slice is: BPF FD objects with correct lifetime, `MAP_CREATE` plus core map operations, `PROG_LOAD`, object info, selected attachment/link creation and teardown, explicit privilege checks, and stable errors for deferred commands. Pin/get, BTF, old attach commands, and global ID enumeration should be enabled only when the selected libbpf workflow proves they are necessary.
