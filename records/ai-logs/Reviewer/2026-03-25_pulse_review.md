---
date: "2026-03-25"
topic: "PulseOS Code Review"
decision: "REQUEST_CHANGES"
critical_count: 3
major_count: 0
minor_count: 0
---

# Reviewer Log: PulseOS Rewrite Review

## 发现 (Findings)

### [Critical] 重新实现系统调用分发机制
**位置**: `pulse_syscalls/src/handler.rs`
**ArceOS 对应位置**: `arceos_posix_api/syscalls.rs` 或者 `axns/syscall_dispatcher.rs`
**原因**: PulseOS自定义了 `syscall_dispatcher`，但这部分功能可以通过复用现有的 `arceos_posix_api` 来支持POSIX兼容和系统调用解析。如果需要扩展特定的Sysno，应该组合/继承现有API，而不是重复发明调度逻辑。
**建议修改**: 移除自定义系统调用调度表，调用 `arceos_posix_api` 的 `syscall_handler` 或集成对应模块。

### [Critical] 重新实现文件描述符表 (FdTable)
**位置**: `pulse_core/src/fs/fd_table.rs`
**ArceOS 对应位置**: `arceos/api/arceos_posix_api/src/fs/`
**原因**: ArceOS已经通过 `arceos_posix_api` 和底层虚拟文件系统或网络堆栈内置了文件描述符(FD)的分配与查询管理。再次在内核上层重新实现 `FdTable`，会导致冗余甚至是权限上下文不一致的问题。
**建议修改**: 移除 `pulse_core::fs::fd_table.rs`，并使用ArceOS内建的POSIX兼容FD管理。

### [Critical] 重复的任务/进程状态管理
**位置**: `pulse_core/src/task/mod.rs`
**ArceOS 对应位置**: `arceos/modules/axtask/`
**原因**: ArceOS 的 `axtask` 已经具备了完善的任务上下文(Task context)、ID分配、运行状态管理和调度器实现。自定义 `Process` 如果是为了扩展行为，建议使用 `axtask::TaskExt` 或者对 `axtask` 进行薄封装。全量重复维护任务信息结构体存在与底层调度脱节的安全风险。
**建议修改**: 审查并重构 `Process`，使其复用 `axtask` 作为基础支撑。

## 结论 (Decision)
**REQUEST_CHANGES**

## 悬而未决的问题 (Open Questions)
- ArceOS 默认配置能否完全满足当前基于进程用户空间切换 (`USER_SPACE_BASE`, page fault等)的需要，还是存在某些特性必须要绕开库功能？因为 PulseOS 添加了自己的 `handle_page_fault`。

## 建议变更列表 (Recommended Changes)
1. 移除 `pulse_core/fs/fd_table.rs` 并对接到 `arceos_posix_api`。
2. 删除 `pulse_syscalls` 内自行调度的冗长 `Sysno` match 逻辑。
3. 调整 `pulse_core/task` 使得与 `axtask` 兼容和组合。
