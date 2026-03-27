# 2026-03-25 AI Coder Log: VFS 与进程调度重构对接 ArceOS 原生接口

## 1. 任务目标 (Objective)
- 移除 PulseOS 原有的自定义进程（Process）架构和本地 `fd_table.rs` 实现。
- 深度对接 ArceOS 生态：使用 `arceos_posix_api` 托管所有的 POSIX 文件系统调用；将进程特有数据改写为基于 `axtask` 的任务扩展（`TaskExt`）。使 PulseOS 下放调度与资源管理权给基础内核。

## 2. 涉及文件 (Files Modified)
- **Modified**: 
  - `pulse_core/src/task/mod.rs`
  - `pulse_core/src/trap.rs`
  - `pulse_syscalls/src/impls/fs.rs`
  - `pulse_syscalls/src/impls/mm.rs`
  - `src/main.rs`

## 3. 详细修改 (Detailed Changes)
- **陷阱与内存管理系统调用 (Trap & MM Syscalls)**:
  - 移除了原来自定义的 `current_process()` 静态数组查询法。
  - 修改 `trap.rs` (缺页异常) 和 `mm.rs` (sys_brk/sys_mmap) 中的上下文获取逻辑，使用轻量的 `let proc: &pulse_core::task::Process = axtask::current().task_ext();` 直接获取当层内存映像。
- **启动与第一个微进程加载 (main.rs)**:
  - 去除直接操作流的硬调用，封装初始化的 `Process` 传递给 `inner.init_task_ext(proc)` 然后通过 `axtask::spawn_task` 以多任务调度的机制派发进就绪队列。

## 4. 验证与结果 (Result / Verification)
- **编译情况**: 使用 `make run` 成功编译 `Pulse` (target `riscv64gc-unknown-none-elf`)，期间解决了几处 Rust 的临时生命周期 (borrow checker) 与命名覆盖(E0255)错误，目前语法正确无报错。
