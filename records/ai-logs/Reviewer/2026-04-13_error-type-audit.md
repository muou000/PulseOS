# PulseOS 错误类型匹配审计（workspace）

- 日期：2026-04-13
- 范围：`pulse_core`、`pulse_syscalls`、`src`（不含 `arceos/`、`vendor/`）
- 方法：静态扫描 + 重点场景复核（`execve`、`clone/wait4`、`futex`、`mmap/munmap/mprotect`、`openat/statx/utimensat`）

## 1. 错误边界基线

### 1.1 三类返回边界（计数）

- `AxResult` 出现次数：43
- `LinuxResult` 出现次数：45
- `Result<_, isize>` 出现次数：4
- `pub fn sys_* -> isize`（syscall ABI 出口）数量：48

### 1.2 转换点（计数）

- `canonicalize()` 映射：17
- `AxError -> LinuxError`（`into()`）显式点：3
- `map_err(|_| EFAULT)` 风格：2
- `unwrap_or_else(|_| EFAULT)` 风格：3
- syscall 实现中的 `expect(...)`：21

## 2. 错误类型映射矩阵（核心路径）

| 模块/函数 | 输入错误类型 | 输出错误类型 | 转换方式 | 语义判定 |
|---|---|---|---|---|
| `pulse_core::task::Process::read_user_bytes` | 地址范围/页表访问失败 | `AxResult<()>` | `BadAddress` + `AxError::from` | 边界清晰 |
| `pulse_core::task::Process::write_user_bytes` | 地址范围/页表访问失败 | `AxResult<()>` | 同上 | 边界清晰 |
| `pulse_core::task::Process::futex_wait` | `read_user_u32` 失败、超时、值不等 | `AxResult<()>` | `WouldBlock/TimedOut` + 若干 `unwrap_or(...)` | 存在语义吞错风险 |
| `pulse_syscalls::impls::task::ax_error_to_linux_ret` | `AxError` | `isize` | `into()` -> `LinuxError` -> 负 errno | 一致 |
| `pulse_syscalls::impls::task::read_user_bytes` | `AxError` | `Result<(), isize>` | 统一压成 `-EFAULT` | 语义可接受（仅用户内存读） |
| `pulse_syscalls::impls::task::sys_clone` | `AxError`（来自 spawn） | `isize` | 统一 `ax_error_to_linux_ret` | 一致 |
| `pulse_syscalls::impls::task::sys_execve` | `AxError`（`process.exec`） | `isize` | `canonicalize()` 特判 `InvalidExecutable`，其余 `into()` | 一致 |
| `pulse_syscalls::impls::task::sys_wait4` | 用户写回失败 | `isize` | `write_user_i32` -> `-EFAULT` | 一致 |
| `pulse_syscalls::impls::futex::sys_futex` | `AxError`/用户地址错误 | `isize` | `AxError -> LinuxError`；部分 `Err(_) => EFAULT` | 一致性较好，受核心吞错影响 |
| `pulse_syscalls::impls::fs::read_user_bytes` | `AxError` | `Result<(), LinuxError>` | `LinuxError::from(e.canonicalize())` | 一致 |
| `pulse_syscalls::impls::fs::sys_openat` | VFS 错误 | `isize` | `canonicalize()` -> `LinuxError` -> 负 errno | 一致 |
| `pulse_syscalls::impls::fs::sys_fstatat` | 解析/元数据/用户写回失败 | `isize` | 分层透传 errno | 一致 |
| `pulse_syscalls::impls::fs::sys_statx` | 解析/元数据/用户写回失败 | `isize` | 分层透传 errno | 一致 |
| `pulse_syscalls::impls::fs::sys_utimensat` | 解析/timespec/metadata 失败 | `isize` | `canonicalize()` + `LinuxError` | 一致 |
| `pulse_syscalls::impls::mm::sys_mmap` | 参数/fd/映射/文件读失败 | `isize` | 多分支显式 errno | 有一处错误码偏粗 |
| `pulse_syscalls::impls::mm::sys_munmap` | unmap 失败 | `isize` | 统一 `-EINVAL` | 粒度偏粗 |
| `pulse_syscalls::impls::mm::sys_mprotect` | 参数/范围/protect 失败 | `isize` | `EINVAL/ENOMEM` 显式映射 | 一致 |
| `pulse_syscalls::impls::*::sys_*`（多处） | 缺失 current thread/process | panic | `expect(...)` | 与 syscall ABI 目标不一致 |

## 3. 分级问题清单（按严重级别）

## P0（ABI 风险）

1. syscall 路径存在 `expect(...)`，可能 panic 逃逸而非返回 errno。
- 例：`pulse_syscalls/src/impls/task.rs:43`, `:49`, `:328`, `:412`
- 例：`pulse_syscalls/src/impls/mm.rs:42`, `:111`, `:253`, `:310`
- 例：`pulse_syscalls/src/impls/futex.rs:64`
- 例：`pulse_syscalls/src/impls/time.rs:72`, `:119`, `:142`, `:163`
- 例：`pulse_syscalls/src/impls/misc.rs:57`, `:106`, `:113`, `:122`, `:138`, `:171`
- 当前行为：上下文缺失时 panic。
- 期望行为：稳定返回负 errno（通常 `-ESRCH`/`-ENOSYS`），不崩溃。

## P1（语义错误/不准确）

1. `futex_wait` 在轮询分支吞掉用户内存读取错误，可能把 `EFAULT` 变成成功或超时。
- 位置：`pulse_core/src/task/process.rs:699`, `:714-717`
- 当前行为：`read_user_u32(addr).unwrap_or(expected)` 和 `.unwrap_or(true)`。
- 风险：用户地址失效时不返回 `AxError`，`sys_futex` 侧无法映射为 `-EFAULT`。
- 期望行为：地址读取失败应保留错误并返回（最终映射 `-EFAULT`）。

2. `sys_mmap` 对 `aspace.map_alloc` 的失败统一映射 `-ENOMEM`，错误码粒度可能失真。
- 位置：`pulse_syscalls/src/impls/mm.rs:243-246`
- 当前行为：无论底层错误原因，一律 `-ENOMEM`。
- 期望行为：按底层错误类型更细映射（至少区分参数非法与内存不足）。

3. `sys_munmap` 对 `unmap` 失败统一映射 `-EINVAL`，错误语义过粗。
- 位置：`pulse_syscalls/src/impls/mm.rs:277-280`
- 当前行为：所有失败都 `-EINVAL`。
- 期望行为：按底层错误原因映射（参数/地址/状态分开）。

## P2（可维护性问题）

1. 错误转换策略分散：同类路径同时使用 `into()`、`canonicalize()`、手写 `Err(_) => EFAULT`。
- 位置示例：
  - `pulse_syscalls/src/impls/task.rs:53-56`, `:373-398`
  - `pulse_syscalls/src/impls/fs.rs:40-48`, `:395-397`, `:1174-1177`
  - `pulse_syscalls/src/impls/futex.rs:73-78`, `:97`
- 影响：后续统一 errno 语义时成本高、易漏。

2. 存在字面量 errno 返回，不利于一致性维护。
- 位置：`pulse_syscalls/src/impls/fs.rs:1232`（`-25`）
- 建议：统一改为 `-LinuxError::ENOTTY.code() as isize` 风格。

## 4. 重点场景复核结论

- `execve`：总体映射路径清晰，`InvalidExecutable -> shell fallback` 逻辑合理。
- `clone/wait4`：`AxError -> LinuxError` 主路径清晰；`wait4` 对用户写回失败回 `EFAULT` 合理。
- `futex`：syscall 层映射合理，但被 `pulse_core` 中的吞错逻辑破坏（见 P1-1）。
- `mmap/munmap/mprotect`：类型边界一致；`mmap/munmap` 某些失败码粒度过粗（见 P1-2/3）。
- `openat/statx/utimensat`：`canonicalize()` 路径与用户地址错误处理整体一致。

## 5. 修复建议模板（用于后续 patch）

每条问题建议按以下模板落地：

- **Problem**: 当前错误出口与目标语义不一致。
- **Current**: 现有分支/转换代码 + 返回 errno。
- **Expected**: 目标 errno 语义（给出触发条件）。
- **Change**: 最小修改点（函数名 + 行号区间）。
- **Validation**: 至少 1 个正例 + 1 个反例（包含预期 errno）。

## 6. 验收结论

- `规则 A`（核心 `AxResult`、syscall `isize`）: 基本满足。
- `规则 B`（用户地址错误 -> `EFAULT`）: 大体满足，`futex_wait` 存在破口（未满足）。
- `规则 C`（禁止无差别吞错）: 存在有限但关键吞错（未满足）。
- `规则 D`（同语义一致 errno）: 大体满足，`mm` 模块存在粒度偏粗（部分未满足）。

总体结论：**类型边界基本正确，但仍有少量高优先级语义风险（1 个 P0 类簇 + 3 个 P1）需要优先修复**。
