# [2026-06-18] AI Coder Log: 清理过时及不准确的 syscall 警告日志

## 1. 任务目标 (Objective)
- 检查 `pulse_syscalls` 中部分已被实质/完整实现的 syscall，清理过时、误导的 `warn!` 日志或兼容性 placeholder 提示。
- 保证已能正确工作的 syscall 在被调用时不输出无意义的错误/ stub 警告。
- 确保清理后的代码无 `unused_imports` 等编译警告，保持构建的整洁。

## 2. 涉及文件 (Files Modified)
- `pulse_syscalls/src/impls/time.rs`
- `pulse_syscalls/src/impls/task/schedule.rs`
- `pulse_syscalls/src/impls/fs/path.rs`
- `pulse_syscalls/src/impls/task/user.rs`

## 3. 详细修改 (Detailed Changes)

### ① 时间相关 syscall (`time.rs`)
* **`sys_clock_nanosleep`**: 移除“simplified EINTR/rem semantics”的警告日志。因为已实现符合 Linux 标准的绝对与相对睡眠及信号中断（EINTR）后剩余时间计算。
* **`sys_clock_getres`**: 移除“reporting fixed nanosecond timer resolution”的警告日志。返回 1ns 分辨率是 Linux 标准做法。
* **`sys_gettimeofday` / `sys_settimeofday`**: 移除“timezone argument is ignored”的警告日志。时区参数已废弃，避免频繁警告干扰。
* **全局变量与清理**: 删除了在 `time.rs` 中不再使用的 `CLOCK_NANOSLEEP_COMPAT_WARNED`、`CLOCK_GETRES_FIXED_WARNED` 和 `GETTIMEOFDAY_TZ_WARNED` 三个原子 bool 静态变量。同时清理了 `AtomicBool` 和 `Ordering` 的 `unused_imports`。

### ② 调度相关 syscall (`schedule.rs`)
* **`sys_sched_getscheduler`**: 将 reporting `SCHED_RR` 的 stub `warn!` 日志降级为 `debug!` 日志。
* **`sys_sched_setattr`**: 将ATTR请求被接受的 stub `warn!` 日志降级为 `debug!` 日志。
* **`sys_sched_getattr`**: 将获取RT属性的 stub `warn!` 日志降级为 `debug!` 日志。

### ③ 挂载相关 syscall (`path.rs`)
* **`sys_mount`**: 将忽略非空 data 挂载选项的 `warn!` 降级为 `debug!`。
* **`sys_umount2`**: 将忽略未支持的卸载标志的 `warn!` 降级为 `debug!`。

### ④ 进程会话相关 syscall (`user.rs`)
* **`sys_setsid`**: 将 setsid 成功的 `warn!` 降级为 `debug!`。

---

## 4. 验证与结果 (Result / Verification)
- 运行格式化与编译命令：
  ```bash
  make test
  ```
- **构建结果**：RISC-V 64 与 LoongArch64 的内核编译全部成功通过，且控制台输出 **0 warnings**，成功消除了修改导入带来的所有 `unused_imports` 警告。

## 5. 使用模型与Prompt
- **模型**：Gemini 3.5 Flash (Medium)
- **Prompt**：
  1. “对于部分syscalls是否已经不再是stub处理了？”
  1. “帮我清理已经不必要的这种日志”
  2. “帮我将你的清理过程写入ai-logs/coder中”
