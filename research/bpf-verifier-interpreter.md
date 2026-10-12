# eBPF verifier, interpreter, and helper minimum for PulseOS

Context: Wayfinder issue [#80](https://github.com/muou000/PulseOS/issues/80).

## Primary sources and repository evidence

- Linux verifier design: [`Documentation/bpf/verifier.rst`](https://github.com/torvalds/linux/blob/master/Documentation/bpf/verifier.rst).
- Linux BPF UAPI instruction, register, map, program-type, helper, and ring-buffer definitions: [`include/uapi/linux/bpf.h`](https://github.com/torvalds/linux/blob/master/include/uapi/linux/bpf.h).
- Linux libbpf lifecycle: [libbpf overview](https://docs.kernel.org/bpf/libbpf/libbpf_overview.html).
- PulseOS has no `ebpf`, `verifier`, or BPF interpreter implementation in `modules/`, `pulse_core/`, `pulse_syscalls/`, or `crates/` (excluding the unrelated smoltcp BSD `/dev/bpf` packet-device source).
- PulseOS is `no_std` in kernel paths and already uses `alloc`, `spin`, `hashbrown`, `bitflags`, and related collections. Those are reusable implementation building blocks, not a verifier.

## What cannot be simplified away

Linux's verifier documentation describes safety as two linked steps:

1. A control-flow/DAG pass rejects loops and unreachable instructions in the classic verifier model.
2. A path-sensitive abstract interpreter simulates each instruction and tracks register and stack state along every reachable path, with state pruning for equivalent safe states.

The following invariants are security properties and must remain even in a PulseOS subset:

- The instruction stream is fully bounds-checked before fetch/decode; unknown class, mode, width, opcode, reserved fields, and malformed two-slot `LD_IMM64` encodings are rejected.
- The control-flow graph has valid targets, no fall-through past the program, no unreachable instructions, and no unbounded backward loop. If bounded loops are later accepted, the verifier must prove a finite bound; otherwise reject all loops in the first interpreter.
- At entry, only the context pointer in `R1` and the read-only frame pointer `R10` have defined types. Reading an uninitialized register or an uninitialized stack slot is rejected.
- `R0` must have a valid return value at `EXIT`; caller-saved `R1`-`R5` become unreadable after a helper call, while callee-saved `R6`-`R9` retain tracked state.
- Memory accesses are permitted only through verifier-recognized pointer types and must satisfy size, alignment, and bounds checks. Stack reads require a prior write. A user-provided scalar can never become an arbitrary kernel pointer.
- Context access is program-type-specific. For tracepoint and perf-event programs, the verifier must allow only documented offsets, widths, and read/write directions for the selected context layout. It must not expose raw kernel pointers or internal task structures by accident.
- Map references and map values are typed. A lookup result that may be NULL must be checked before dereference; map FD references in instructions must resolve to a live map of an allowed type; map value access must stay inside the declared value size.
- Helper calls are a whitelist with per-program-type prototypes. The verifier checks argument types and ranges, and the interpreter dispatches only helpers approved for that program type. An unknown helper or a helper allowed for another program type is rejected at load time.
- Any reference-tracked object must be released on every exit path. The first performance subset should avoid helpers that create reference-tracked resources unless the verifier models their release protocol.
- The verifier must account for bounded execution and memory/resource use. A program that is safe at the pointer level but can consume unbounded interpreter time or memory is not safe to attach to scheduler or interrupt-adjacent paths.

These rules are independent of whether execution is interpreted or JIT compiled. JIT is an optimization and can be deferred; verification is the admission boundary.

## eBPF machine subset

The Linux UAPI defines ten 64-bit registers (`R0`-`R10`), 64-bit ALU/JMP operations plus 32-bit forms, load/store classes, conditional/unconditional jumps, helper calls, exit, and two-slot 64-bit immediate loads. A first PulseOS interpreter should decode the standard instruction encoding rather than inventing a private bytecode, but it may reject instructions outside the selected subset during verification.

Recommended first instruction set:

- `LD_IMM64` for constants and pseudo map-FD references used by libbpf relocations.
- Register moves and 32/64-bit add, subtract, multiply, divide/modulo with explicit divide-by-zero behavior, shifts, bitwise operations, negation, endian conversion if the compiler fixture emits it, and signed/unsigned comparisons used by tracing code.
- Immediate and register conditional jumps, unconditional jumps, and `EXIT`.
- `LDX` loads from verifier-approved context, stack, and map-value pointers; `STX`/`ST` stores only to initialized writable stack/map-value/output-record memory as allowed by the helper model.
- `CALL` for the selected helper IDs only.
- Atomic operations only if a concrete aggregation map needs them and the memory-ordering contract is specified; otherwise reject them in the first interpreter instead of implementing a weak approximation.

The interpreter must use wrapping/checked arithmetic exactly as defined by the selected eBPF ISA semantics and must never perform a host pointer dereference based only on an untrusted register value. A small, explicit decoder and typed runtime values are safer than translating instructions directly into native function pointers.

## Context model for the selected program types

A program type determines the initial context and legal context offsets. The first target types are `BPF_PROG_TYPE_TRACEPOINT` and `BPF_PROG_TYPE_PERF_EVENT`.

Recommended initial contract:

- `TRACEPOINT`: expose a stable PulseOS trace-event context containing event ID/version, timestamp, CPU, task/process identifiers, and event-specific scalar fields. The context is read-only to BPF. Do not expose `TaskInner` pointers, Rust trait objects, scheduler locks, or raw kernel addresses.
- `PERF_EVENT`: expose a stable software-sample context containing timestamp, CPU, event ID, task/process identifiers, and the sampling period/counter fields that are actually implemented. Start with scalar reads only; do not expose architecture-specific `pt_regs` or arbitrary register state until both RISC-V64 and LoongArch64 layouts are defined.
- Context offsets and sizes must be versioned and checked by the verifier. A program compiled for one context version must fail clearly when attached to another, rather than reading a coincidentally valid offset.
- Helpers that read kernel/user memory should not be required for the first fixed-layout tracepoint fixture. If later needed for libbpf/CO-RE, they require a separate pointer-safety and BTF decision.

This boundary deliberately favors a stable event ABI over Linux's broad collection of context types. It still uses Linux program types and instruction encoding, so unsupported context fields fail as unsupported semantics rather than silently exposing internal objects.

## Minimum helper allowlist

The Linux UAPI lists a very large helper namespace. The first performance sampler needs only a small, typed subset. Candidate helpers, subject to the output decision in #87, are:

| Helper | First status | Conditions |
|---|---|---|
| `bpf_map_lookup_elem` | Required | Map FD/type and key pointer must be verified; nullable map-value result must be tracked and NULL-checked. |
| `bpf_map_update_elem` | Required if BPF-side aggregation/configuration is in the fixture | Verify map pointer, key/value bounds, flags, and map type; preserve Linux `BPF_ANY`/`NOEXIST`/`EXIST` behavior. |
| `bpf_map_delete_elem` | Optional for first event program | Allow only for map types that support deletion and only with verified key memory. |
| `bpf_get_smp_processor_id` | Required for per-CPU attribution if it is not already in context | Return the current sampler CPU; cannot be spoofed by the BPF program. |
| `bpf_ktime_get_ns` | Required unless timestamp is always supplied in context | Use the same monotonic clock contract as capture metadata. |
| `bpf_perf_event_output` | Required for `PERF_EVENT_ARRAY` output | Verify map type, flags/CPU selection, source pointer and bounded size. Output failure must be observable as a negative return/lost count, not a blocking call. |
| `bpf_ringbuf_output` | Required for ringbuf copy-output mode if #87 selects it | Verify constant/bounded record size and map type; no blocking. |
| `bpf_ringbuf_reserve` / `submit` / `discard` | Defer unless zero-copy ringbuf is in the first fixture | Requires reference tracking so every successful reservation is committed or discarded on every path. |
| `bpf_ringbuf_query` | Defer | Diagnostic/heuristic helper, not needed for a minimal sampler. |
| `bpf_probe_read*` | Defer | Requires a carefully defined safe kernel/user address model; fixed tracepoint contexts avoid it initially. |
| stack-trace, networking, cgroup, task-storage, dynptr and sleepable helpers | Reject initially | Not needed by the selected program types and would expand verifier state/reference/security scope. |

Helper IDs remain Linux IDs, but “recognized” must mean fully implemented and verified for PulseOS. Returning success for a helper that drops records, sleeps, or reads an invalid address would break the security and data-quality contract.

## Resource and execution limits

Linux has evolving implementation limits, and exact values are a later compatibility decision. PulseOS must nevertheless make limits explicit before exposing the syscall:

- maximum instruction count and maximum verifier state/work items;
- maximum stack depth (the standard eBPF stack model is bounded and addressed below `R10`);
- maximum call depth if BPF-to-BPF calls are enabled; otherwise reject subprogram calls initially;
- maximum map key/value/entry sizes and total map memory;
- maximum ring/perf buffer size and per-CPU allocation;
- maximum helper/output record size;
- maximum execution steps per invocation, with a defined drop/error path if exceeded;
- no sleeping, allocation with unbounded latency, lock acquisition that can block, or recursive event re-entry from a tracepoint/perf-event program.

The limits should be enforced at load time where statically knowable and at runtime where dynamic values are involved. A runtime budget is not a replacement for CFG verification; it is a second containment layer for interpreter cost.

## Interpreter design boundary

A portable interpreter is appropriate for both target architectures because eBPF's virtual ISA is independent of the host ISA. The interpreter should:

1. Decode a validated instruction stream into a host-independent representation or execute a carefully checked raw encoding.
2. Keep virtual registers and stack in kernel-owned memory, never aliasing arbitrary user addresses.
3. Represent pointer provenance/types explicitly in verifier state and runtime values.
4. Dispatch helpers through a per-program-type table with checked arguments.
5. Run with preemption/interrupt rules appropriate to the event hook; the event path must not sleep or hold scheduler locks across a helper that can re-enter the scheduler.
6. Produce a verifier log with instruction index, rejected reason, and the relevant register/stack state, similar in purpose to Linux's verifier log.

JIT compilation is out of scope for the first decision. If added later, JIT output must be generated only from the same verified representation, be separately tested on RISC-V64 and LoongArch64, and never widen the accepted program language.

## Reusable PulseOS components and gaps

Reusable foundations:

- `alloc` collections, `spin`/`kspin` synchronization and existing page/heap allocators;
- `hashbrown` or bounded vectors for verifier state caches, with explicit limits;
- existing user-memory validation/copy helpers for syscall attributes;
- existing task/CPU/time APIs as sources for the stable context fields and monotonic timestamp.

Missing components:

- standard eBPF instruction decoder and typed verifier state;
- CFG/DAG analysis and state exploration/pruning;
- map/program FD relocation resolution;
- context access policy per program type;
- helper prototypes and runtime dispatch;
- interpreter and execution budget;
- verifier logs and tests for accepted/rejected programs;
- ring/perf output memory safety and reference tracking.

No existing PulseOS crate should be assumed to provide these invariants merely because it provides an allocator, scheduler, ELF parser, or CPU trap decoder.

## Recommended decision for #85

The first verifier/interpreter contract should accept standard eBPF encoding for a deliberately narrow `TRACEPOINT`/`PERF_EVENT` language, reject all loops and BPF-to-BPF calls initially, use scalar plus context/stack/map-value pointer tracking, support only a small helper allowlist, enforce explicit instruction/stack/state/output limits, and execute only in a portable interpreter. It should reject unsupported program types, helper IDs, context offsets, atomics, raw pointer access, and deferred BTF/CO-RE features with detailed load logs. This preserves the Linux safety model while keeping the first implementation tractable on both architectures.
