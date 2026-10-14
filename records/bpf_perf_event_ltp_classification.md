# BPF Software Perf Event Control & LTP Classification (#97)

## Overview

Issue #97 and Issue #86 define the contract for software performance event control:
- Linux-shaped `perf_event_open` for period-based `PERF_COUNT_SW_CPU_CLOCK` and `PERF_COUNT_SW_TASK_CLOCK`.
- Returning a `PerfEventObject` implementing `FdObject` with thread-safe `read` (64-bit elapsed counter value) and `ioctl` (`ENABLE`, `DISABLE`, `RESET`, `PERIOD`).
- Explicit rejection of frequency mode (`freq == 1`), hardware/raw/cache/breakpoint events, inheritance (`inherit == 1`), cgroups, and namespaces with `EOPNOTSUPP` or `EINVAL`.
- Supported scope matrix:
  - `pid == -1, cpu >= 0`: per-CPU event (requires root or `CAP_SYS_ADMIN`/`CAP_PERFMON`).
  - `pid >= 0, cpu == -1`: selected task event (`pid == 0` resolves to calling process).
  - Other combinations (`pid == -1, cpu == -1`, `pid >= 0, cpu >= 0`, etc.) explicitly rejected.
- Clock and scope coupling:
  - `PERF_COUNT_SW_CPU_CLOCK` requires per-CPU scope.
  - `PERF_COUNT_SW_TASK_CLOCK` requires task scope.

## LTP `perf_event_open` Test Suite Classification

| Test Case | Event Type / Config | PulseOS Status | Classification | Rationale |
|---|---|---|---|---|
| `perf_event_open01` | `PERF_COUNT_HW_INSTRUCTIONS` | Unsupported | `TCONF` | Hardware PMU not exposed in software tier; returns `EOPNOTSUPP` |
| `perf_event_open01` | `PERF_COUNT_HW_CACHE_REFERENCES` | Unsupported | `TCONF` | Hardware PMU not exposed in software tier; returns `EOPNOTSUPP` |
| `perf_event_open01` | `PERF_COUNT_HW_CACHE_MISSES` | Unsupported | `TCONF` | Hardware PMU not exposed in software tier; returns `EOPNOTSUPP` |
| `perf_event_open01` | `PERF_COUNT_HW_BRANCH_INSTRUCTIONS` | Unsupported | `TCONF` | Hardware PMU not exposed in software tier; returns `EOPNOTSUPP` |
| `perf_event_open01` | `PERF_COUNT_HW_BRANCH_MISSES` | Unsupported | `TCONF` | Hardware PMU not exposed in software tier; returns `EOPNOTSUPP` |
| `perf_event_open01` | `PERF_COUNT_SW_CPU_CLOCK` | Supported | `TPASS` / Active | Software counter accumulates CPU time; supports enable/disable/reset/read |
| `perf_event_open01` | `PERF_COUNT_SW_TASK_CLOCK` | Supported | `TPASS` / Active | Software counter accumulates task CPU time; supports enable/disable/reset/read |
| `perf_event_open02` | `group_fd != -1` | Unsupported | `TCONF` / `EINVAL` | Event groups not supported; returns `EINVAL` per spec |
| `perf_event_open03` | Inheritance / cgroups | Unsupported | `TCONF` / `EOPNOTSUPP` | Explicitly rejected with `EOPNOTSUPP` |

### LTP Setup Prerequisites

In Linux userspace, `perf_event_open01` checks `access("/proc/sys/kernel/perf_event_paranoid", F_OK) == 0`. Without this procfs entry, LTP exits early with `TCONF` ("Kernel doesn't have perf_event support").

## Dual-Architecture Verification Evidence

### Host Unit Test Suite
- `cargo test -p pulse_syscalls --lib -- bpf_perf_event`:
  - 12 tests passing covering:
    - `perf_event_attr` size, type, config, flags validation.
    - Scope matrix and root/capability requirements.
    - Clock and scope coupling validation.
    - Counter lifecycle (initial state, enable accumulation, disable pause, reset, read buffer format).
    - IOCTL dispatch and unknown code rejection (`ENOTTY`).

### Guest Smoke Suite
- Executed on both RISC-V 64 (`qemu-system-riscv64`) and LoongArch64 (`qemu-system-loongarch64`):
  - CPU clock counter accumulates > 0 ns during busy loop.
  - Reset via IOCTL resets counter to 0.
  - Task clock counter accumulates task execution time snapshot.
  - Regular file stat mode matches `S_IFREG | 0o600`.
  - Both architectures output `[BPF_GUEST] Perf Event assertions: PASS`.

