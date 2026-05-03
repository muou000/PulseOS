# [2026-05-02] AI Coder Log: syscall stub 与不完整语义 warn 日志补充

## 1. 任务目标 (Objective)
- 检查 `pulse_syscalls` 中仍处于 stub、兼容占位或语义不完整状态的 syscall。
- 为这些路径补充 `warn!` 日志，使后续运行测试或定位兼容性问题时可以更直观看到哪些 syscall 还不是完整 Linux 语义。
- 尽量保持改动最小，不引入 syscall 行为变更。

## 2. 涉及文件 (Files Modified)
- `pulse_syscalls/src/handler.rs`
- `pulse_syscalls/src/impls/task/schedule.rs`
- `pulse_syscalls/src/impls/misc.rs`
- `pulse_syscalls/src/impls/time.rs`
- `pulse_syscalls/src/impls/mm.rs`
- `pulse_syscalls/src/impls/fs/path.rs`
- `pulse_syscalls/src/impls/fs/meta.rs`

## 3. 详细修改 (Detailed Changes)
- **syscall dispatcher**:
  - 为 `get_mempolicy` 的静默成功 stub 增加 `warn!`，说明当前不具备 NUMA policy 语义。

- **调度相关 syscall**:
  - 为 `sched_getscheduler` 增加 `warn!`，说明当前固定报告 `SCHED_RR`，没有 per-task scheduler state。
  - 为 `sched_setscheduler` 增加 `warn!`，说明传入的 scheduler policy/param 请求目前被忽略。
  - 为 `sched_getparam` 增加 `warn!`，说明当前不报告真实 scheduler 参数。

- **进程组与 syslog**:
  - 将 `setpgid` 原本的 debug stub 日志升级为 `warn!`，说明 process-group state 没有更新。
  - 为 `sys_syslog` 增加一次性 `warn!`，说明当前使用 placeholder，内核日志缓冲区未持久化。

- **时间相关 syscall**:
  - 将 `clock_nanosleep` 的简化 EINTR/rem 语义提示升级为 `warn!`。
  - 将 `clock_getres` 的固定 1ns 分辨率提示升级为 `warn!`。
  - 为 `gettimeofday` 非空 timezone 参数被忽略的情况增加一次性 `warn!`。

- **内存映射相关 syscall**:
  - 为 file-backed `mmap` 增加一次性 `warn!`，说明当前通过复制文件内容填充映射，shared/writeback/lazy mapping 语义不完整。

- **挂载与元数据相关 syscall**:
  - 为 `mount` 忽略 flags/data 的路径增加一次性 `warn!`。
  - 为 `umount2` 忽略 flags 的路径增加一次性 `warn!`。
  - 为 `statx` 增加一次性 `warn!`，说明当前只报告 basic stats，requested mask 和扩展字段语义简化。

- **日志频率控制**:
  - 对可能频繁触发或兼容性探测常见的路径使用 `AtomicBool` 做一次性 warn，避免运行测试时日志被同一类提示刷屏。

## 4. 验证与结果 (Result / Verification)
- 已运行 `cargo fmt`。
- 已运行仓库约定入口 `make test`。
- RISC-V64 与 LoongArch64 release 构建均通过，并完成 rootfs 镜像生成。
- 构建中仅保留已有 dead_code warning：
  - `arceos/modules/axfs/src/highlevel/file.rs` 中 `discard_pages` 未使用。
  - `pulse_syscalls/src/impls/misc.rs` 中 `Sysinfo` 与 `rlimit_for` 未使用。
- 注意：工作区存在非本次任务产生的 `src/testcode_cmd.sh` 改动，本次没有修改该文件。

## 5. 使用模型与Prompt
- **模型**:
  - Codex / GPT-5.5
- **Prompt**:
  - “检查pulse_syscalls中还有哪些syscall是stub或语义不完全的状态，请你为这些情况添加warn日志”
  - “将你的工作内容写入records/ai-logs/Coder下”
