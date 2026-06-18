# [2026-06-18] AI Coder Log: 实现 sched_setattr 和 sched_getattr 系统调用

## 1. 任务目标 (Objective)
- 将原本属于静态 Stub 占位的 `sched_setattr` 与 `sched_getattr` 系统调用进行真实化实现。
- 将调度相关的系统调用（`getscheduler`、`setscheduler`、`setattr`、`getattr`）通过进程中的线程（`Thread`）实例实现统一的调度参数管理，并与底层的 `axtask` 优先级调度器完全对接。

## 2. 涉及文件 (Files Modified)
- `pulse_core/src/task/thread.rs`
- `pulse_syscalls/src/impls/task/schedule.rs`

## 3. 详细修改 (Detailed Changes)

### ① 线程结构体扩展 (`thread.rs`)
* 为 `Thread` 结构体增加了以下原子调度状态字段，以支持线程级的调度属性存储：
  * `sched_policy` (默认为 `SCHED_RR`)
  * `sched_flags` (默认为 `0`)
  * `sched_nice` (默认为 `0`)
  * `sched_runtime` (默认为 `0`)
  * `sched_deadline` (默认为 `0`)
  * `sched_period` (默认为 `0`)

### ② 调度属性设置与获取 (`schedule.rs`)
* **`sys_sched_setattr`**：
  * 从用户态结构体读取并校验 `SchedAttr` 的数据。
  * 根据调度策略进行规则校验（如 `SCHED_DEADLINE` 时 `runtime <= deadline <= period` 且 `priority == 0`，`FIFO`/`RR` 时 `priority` 范围限制等）。
  * 将配置的应用到当前线程（调用 `axtask::set_priority`），同时将对应的调度参数更新保存至 `current_thread()` 的字段中。
* **`sys_sched_getattr`**：
  * 获取当前线程实际对应的 `axtask` 调度器优先级。
  * 读取当前线程结构体里保存的 `sched_policy`、`sched_flags`、`sched_nice` 等调度元数据，并打包回填至用户态的 `SchedAttr` 结构体。
* **`sys_sched_setscheduler` 与 `sys_sched_getscheduler`**：
  * 对接修改，在调用时将 `policy` 写入或读取自 `Thread` 的 `sched_policy` 字段，使传统的策略设置与全新的属性设置接口保持状态的一致与同步。

---

## 4. 验证与结果 (Result / Verification)
- 运行编译命令：
  ```bash
  make test
  ```
- **构建结果**：编译及链接完全成功，且控制台输出 **0 warnings**，清除了所有死代码和无用常量警告。

## 5. 使用模型与Prompt
- **模型**：Gemini 3.5 Flash (Medium)
- **Prompt**：
  1. “sched_get/setattr是否被实际实现？”
  2. “帮我在Thread中添加相应字段，修改这两个syscall，同时注意set/getscheduler syscalls，使其发挥真实功能”
