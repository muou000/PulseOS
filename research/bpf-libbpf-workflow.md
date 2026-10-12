# Standard libbpf workflow and PulseOS dependencies

Context: Wayfinder issue [#78](https://github.com/muou000/PulseOS/issues/78).

## Primary sources

- Linux kernel documentation: [libbpf overview and BPF app lifecycle](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html).
- Current first-party libbpf implementation: [`src/libbpf.c`](https://github.com/libbpf/libbpf/blob/master/src/libbpf.c), especially `bpf_object__open_file`, `bpf_object__load`, tracepoint attachment, perf-event attachment, and perf-buffer setup.
- Linux BPF UAPI: [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h).
- Linux tracepoint documentation: [`Documentation/trace/tracepoints.rst`](https://github.com/torvalds/linux/blob/master/Documentation/trace/tracepoints.rst).
- Linux ring buffer design: [`Documentation/bpf/ringbuf.rst`](https://github.com/torvalds/linux/blob/master/Documentation/bpf/ringbuf.rst).
- PulseOS syscall boundary: [`pulse_syscalls/src/handler.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/src/handler.rs) and [`pulse_syscalls/README.md`](https://github.com/muou000/PulseOS/blob/main/pulse_syscalls/README.md).
- PulseOS ordinary ELF loader: [`pulse_core/src/mm/loader.rs`](https://github.com/muou000/PulseOS/blob/main/pulse_core/src/mm/loader.rs).
- Existing qperf trace ABI and events: [`modules/axtask/src/qperf_trace.rs`](https://github.com/muou000/PulseOS/blob/main/modules/axtask/src/qperf_trace.rs).

## What “libbpf works” actually means

The official libbpf overview divides a BPF application into four phases:

1. **Open**: parse a BPF object file and discover programs, maps and global variables; userspace may adjust program types and initial global values before kernel objects are created.
2. **Load**: create maps, resolve relocations, verify and load programs. The program is loaded but has not yet executed, so initial map state can be set without racing program execution.
3. **Attachment**: attach loaded programs to hooks such as tracepoints. The program then updates maps or emits records read by userspace.
4. **Tear down**: destroy links/objects and release resources through their normal FD lifetimes.

Therefore “libbpf can run” cannot mean only that PulseOS accepts a `BPF_PROG_LOAD` syscall. At minimum, the selected workflow must exercise real ELF object parsing in userspace, map/program creation and relocation, a Linux-shaped attach path, an event output consumer, and deterministic teardown.

The target for the first compatibility slice should be a fixed, tested libbpf release range and a small set of ordinary C workflows. It should not claim all exported libbpf symbols or all Linux BPF program classes.

## Core tracepoint workflow in current libbpf

The current libbpf source makes the tracepoint path concrete:

1. A program section such as `tracepoint/<category>/<name>` is parsed during object auto-attach.
2. libbpf reads `<tracefs>/events/<category>/<name>/id` to obtain the numeric tracepoint ID.
3. It fills a `perf_event_attr` with `type = PERF_TYPE_TRACEPOINT` and `config = tracepoint_id`, then calls `perf_event_open(attr, pid=-1, cpu=0, group_fd=-1, PERF_FLAG_FD_CLOEXEC)`.
4. It attaches the loaded program to the perf-event FD. On kernels supporting perf links it uses `BPF_LINK_CREATE` with `BPF_PERF_EVENT`; otherwise it falls back to `ioctl(PERF_EVENT_IOC_SET_BPF, prog_fd)` and uses the perf-event FD as the link handle.
5. It enables the event unless the caller requested delayed enable. Detach closes/releases the link and underlying perf-event resources.

This means a PulseOS tracepoint implementation intended for standard libbpf needs, at minimum, a discoverable tracepoint ID interface, `perf_event_open` for tracepoint events, a program attach path (`BPF_LINK_CREATE` or the legacy ioctl fallback), event enable/disable, and FD/poll lifecycle. A private event callback that is not reachable through this path will not satisfy the compatibility goal.

Linux tracepoints are lightweight runtime hooks. The official tracepoint documentation states that an enabled tracepoint calls a registered probe in the caller's execution context, can carry arbitrary typed parameters described by its declaration, and supports registration/unregistration. PulseOS should expose a stable, versioned trace-event context rather than raw internal task pointers. The existing qperf event functions are useful semantic candidates, but their six integer argument layout is not automatically a libbpf tracepoint ABI.

## Perf-event output workflow

The current libbpf perf-buffer implementation demonstrates additional kernel dependencies:

- It creates a `BPF_MAP_TYPE_PERF_EVENT_ARRAY` and uses `BPF_OBJ_GET_INFO_BY_FD` to validate the map type and discover `max_entries`.
- For each selected CPU it calls `perf_event_open` with a software `PERF_COUNT_SW_BPF_OUTPUT` event and `sample_type = PERF_SAMPLE_RAW`.
- It maps the perf event ring with `mmap(MAP_SHARED)`, enables each event using `PERF_EVENT_IOC_ENABLE`, and stores the perf-event FD into the map keyed by CPU.
- It creates an epoll FD, consumes per-CPU buffers, invokes a sample callback for records, and invokes a lost callback when the kernel reports dropped records. Cleanup disables events, removes map entries, unmaps buffers, closes event FDs and closes epoll.

This is a real compatibility surface: a guest with `bpf()` but no `perf_event_open`, `mmap`-able perf buffers, ioctl enable/disable, epoll, or per-CPU enumeration cannot run the ordinary libbpf perf-buffer path.

A ring-buffer workflow has a different shape. Linux presents `BPF_MAP_TYPE_RINGBUF` as a map with zero key/value sizes and power-of-two `max_entries`; BPF programs reserve/commit/discard or copy output records, and userspace consumes a memory-mapped buffer with epoll or busy polling. The kernel design intentionally provides a shared MPSC buffer and cross-CPU ordering, unlike per-CPU perf buffers. Whether PulseOS supports both output paths in the first implementation is left to issue #82, but the compatibility target must name the chosen path rather than saying “event output” generically.

## ELF, BTF and CO-RE boundary

A normal libbpf object workflow requires userspace ELF parsing and section discovery. PulseOS already contains an ELF loader for guest applications, but that loader is not a BPF object parser and does not provide libbpf's BPF section, map relocation, or BTF relocation behavior.

The official libbpf documentation says that CO-RE combines BTF type information, libbpf and compiler-generated relocation information so one BPF executable can run across kernel versions/configurations. Current libbpf also attempts to load running-kernel BTF, commonly from `/sys/kernel/btf/vmlinux`, before resolving CO-RE and other BTF-dependent information.

The compatibility decision should therefore separate three modes:

- **Fixed-layout core mode**: ELF sections and map/program relocations are supported, but tracepoint contexts are fixed and no CO-RE field relocation is promised. This is the smallest path to a controlled sampler.
- **BTF-aware mode**: PulseOS exposes enough BTF metadata and object attributes for libbpf's selected workflow to load BTF-backed programs/maps.
- **CO-RE mode**: PulseOS exposes stable kernel BTF and all required relocation/context semantics. This is the strongest portability mode, not a free consequence of accepting ELF.

The user requirement is to try to make standard libbpf work, so issue #83 must choose a fixed libbpf version and test fixture and then decide which of these modes is in the first compatibility contract. A system that reports success while silently skipping a required relocation is not compatible.

## Dependency inventory

| Dependency | Needed by core libbpf workflow | PulseOS status | Implication |
|---|---:|---|---|
| User-space libbpf + libelf/zlib or equivalent | Yes for ordinary ELF objects | No bundled libbpf/toolchain integration found | Guest rootfs/toolchain must carry the tested libbpf userspace stack, or a host-side loader must be explicitly chosen. |
| `bpf()` syscall and real BPF object FDs | Yes | Missing | Required kernel work; integrate with the existing process FD table and object lifetimes. |
| `BPF_MAP_*`, `BPF_PROG_LOAD`, info and selected link commands | Yes | Missing | Capability matrix is recorded in #79; #84 decides exact first slice. |
| BPF verifier/interpreter/helpers | Yes | Missing | #80/#85 decide the safe instruction/helper subset. |
| ELF BPF section parsing and map/program relocations | Yes | No BPF-specific parser | Must be implemented in libbpf userspace or a compatible loader; ordinary executable ELF loading is not sufficient. |
| BTF and optional CO-RE | Needed by CO-RE/BTF workflows, not every fixed-layout object | Missing | #83 must make this an explicit compatibility tier. |
| `perf_event_open` | Yes for standard tracepoint attach and perf buffers | Missing | Needed with tracepoint discovery and software-event attributes. |
| tracefs/debugfs tracepoint ID files | Yes for libbpf's current auto-attach implementation | No current tracefs/debugfs tree found | Either provide compatible discovery files or add a narrowly scoped libbpf-compatible discovery path. |
| perf-event ioctl and mmap | Yes for legacy perf attach and perf buffers | Missing | Required if `PERF_EVENT_ARRAY` is in the supported path. |
| epoll/poll and CPU enumeration | Yes for normal buffer consumption | Poll/epoll primitives exist, but perf event FDs and `/sys/devices/system/cpu/online` contract are incomplete | Reuse existing wait mechanisms only after BPF event FDs implement the same poll contract. |
| Ring buffer map/helper/consumer | Needed for ring-buffer workflows | Missing | #82 decides first or staged output support. |
| capabilities / privilege checks | Yes for secure load/attach | Some process capability checks exist; BPF-specific policy is missing | #84 must choose root/trusted-process versus named capability semantics. |

## Recommended compatibility contract for #83

Before implementation, define and test one concrete fixture:

- one fixed libbpf release range;
- one Clang-generated ELF object with `tracepoint/<category>/<name>` and `perf_event` sections;
- maps limited to the selected aggregation/output types;
- one attach path and one output path first, with the second path staged if necessary;
- explicit behavior for absent BTF, absent tracefs, unsupported CO-RE relocation, unsupported helper, and unsupported program/map type;
- an end-to-end guest test that opens, loads, attaches, consumes records, observes a loss counter, detaches and closes all FDs.

This contract still aims at standard libbpf, but it prevents “compatibility” from silently expanding to every program type and every libbpf API. Unsupported features must fail during capability probing or load/attach with a stable error, not after producing a misleading partial capture.
