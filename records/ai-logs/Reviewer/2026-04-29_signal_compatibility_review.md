# Linux 信号系统兼容性评估报告

## 1. 总体结论

PulseOS 目前已经具备“最小可用”的信号骨架：`kill/tkill/tgkill`、`rt_sigaction`、`rt_sigprocmask`、`rt_sigreturn`、`rt_sigsuspend`、`rt_sigtimedwait` 这些入口都接上了，内核侧也已经有 per-thread pending、per-process pending、blocked mask、默认动作判定、handler 跳转和 `sigreturn` 恢复的基本实现。

但是，这套实现还停留在“单条 handler 链路可跑”的阶段，离 Linux 兼容还有明显距离。最关键的短板不是 syscall 名字，而是整条链路缺失：没有真正的 signal frame / ucontext，没有 `sigaltstack`，没有 `SA_SIGINFO` 参数传递，没有异常到 signal 的映射，没有 timer / `SIGALRM` 生成，没有 `SIGCHLD` 生成，没有真正的 signal wakeup，也没有 `SA_RESTART` / `restart_syscall` 语义。

对于单线程、只依赖 `kill` + 简单 handler + `sigreturn` 的程序，这个内核大概率可以跑通最基本场景。对 musl/glibc、libc-test、LTP 的 signal 相关测试来说，当前状态仍然偏低，尤其是多线程、阻塞 syscall 中断、实时信号、`sigaltstack`、job control、默认 core/stop 语义这些部分，缺口比较大。

如果目标是 Linux 应用兼容，当前最现实的判断是：**信号子系统处于“基础骨架可见，但语义不完整”的早期阶段**。它比“只有 kill/exit”强不少，但还不足以支撑 libc-test 的 signal 全量项，更难支撑 LTP 的信号和线程同步测试。

## 2. 完整链路评估

当前链路大致是：

`signal_generate()`  
→ 仅设置 `thread_pending` 或 `process_pending` 位图  
→ 不会主动 wake 目标任务  
→ 在 syscall 返回路径里调用 `check_signals_and_deliver()`  
→ 按 `blocked mask` 过滤  
→ 从 `thread_pending` / `process_pending` 里取最低位信号  
→ 如果是 handler，直接改写 trapframe 的 `PC/RA/a0`  
→ 用户态跳到 handler  
→ handler return 后跳到 vDSO `rt_sigreturn` stub  
→ `rt_sigreturn` 直接恢复保存的 trapframe  

这条链路里，以下环节是完整或接近完整的：

- pending 位图：有
- blocked mask：有
- 基本 handler 跳转：有
- `rt_sigreturn` 恢复 trapframe：有

以下环节明显不完整：

- signal 产生后唤醒阻塞任务：没有
- 线程目标选择：有 helper，但没有真正接入
- 用户 signal frame / `ucontext_t`：没有
- `SA_SIGINFO` 三参数 handler：没有
- `sigaltstack` / `SA_ONSTACK`: 没有
- 异常、定时器、`SIGPIPE`、`SIGCHLD` 等生成链：大多没有
- syscall 中断 / `SA_RESTART`：没有

## 3. syscall 兼容性表

| syscall | 状态 | Linux 兼容程度 | 主要问题 | 证据位置 | 建议测试 |
|---|---|---|---|---|---|
| `kill` | 已实现但偏简化 | 部分实现 | 只做权限判断 + 位图置位，不 wake 目标任务，不填 `siginfo_t` | `pulse_syscalls/src/impls/task/process.rs:72-133`，`pulse_core/src/task/signal.rs:125-131` | `kill(getpid(), SIGUSR1)`，阻塞线程是否被唤醒 |
| `tkill` | 已实现但偏简化 | 部分实现 | 仅按 tid 置位，不验证线程组语义，不 wake | `pulse_syscalls/src/impls/task/process.rs:137-166` | `pthread_kill` / `tkill` 线程定向投递 |
| `tgkill` | 已实现但偏简化 | 部分实现 | 只验证 tgid/tid 存在性，不做 Linux 线程组优先级/唤醒逻辑 | `pulse_syscalls/src/impls/task/process.rs:169-192` | `tgkill(tgid, tid, sig)` 与 `pthread_kill` 对照 |
| `rt_sigaction` | 已实现但偏简化 | 部分实现 | 仅存 handler/flags/mask，忽略 `sa_restorer`、`SA_SIGINFO`、`SA_ONSTACK`、`SA_NOCLDWAIT` 等语义 | `pulse_syscalls/src/impls/misc.rs:246-300`，`pulse_core/src/task/signal.rs:479-505` | `sigaction(SIGUSR1, SA_SIGINFO)`，旧 action 回读 |
| `rt_sigprocmask` | 已实现但偏简化 | 部分实现 | 只读写单个 `u64` mask，未做完整 `sigset_t` 语义，也不影响阻塞中的 syscall | `pulse_syscalls/src/impls/misc.rs:212-243` | `pthread_sigmask` / `sigprocmask` / blocked signal 测试 |
| `rt_sigpending` | 未发现实现，实际 ENOSYS | 低 | 有内部 pending 位图，但没有 syscall 暴露 | `pulse_syscalls/src/handler.rs:238-241`，`pulse_core/src/task/signal.rs:528-535` | `sigpending()` |
| `rt_sigsuspend` | 已实现但偏简化 | 部分实现 | 通过 `yield_now` 忙等；没有被 signal enqueue 主动唤醒 | `pulse_syscalls/src/impls/misc.rs:314-333`，`pulse_core/src/task/signal.rs:450-455` | `sigsuspend` + 另一个线程发送信号 |
| `rt_sigtimedwait` | 已实现但偏简化 | 部分实现 | 只支持位图等待，不支持实时信号队列/顺序，`siginfo_t` 只填最小字段 | `pulse_syscalls/src/impls/misc.rs:336-391` | `sigwaitinfo/sigtimedwait` |
| `rt_sigqueueinfo` | 未发现实现，实际 ENOSYS | 低 | 没有 queued siginfo 路径 | `pulse_syscalls/src/handler.rs:238-241` | `sigqueue()` |
| `rt_tgsigqueueinfo` | 未发现实现，实际 ENOSYS | 低 | 无线程定向 siginfo 发送 | 同上 | `pthread_sigqueue` / 线程组实时信号 |
| `rt_sigreturn` | 已实现但偏简化 | 部分实现 | 只恢复 trapframe，不从 user signal frame 读回，不支持 nested frame / ucontext | `pulse_syscalls/src/impls/misc.rs:303-311`，`pulse_core/src/task/signal.rs:311-319` | handler 中 `raise()` / nested signal / `longjmp` |
| `sigaltstack` | 未发现实现，实际 ENOSYS | 低 | `altstack` 只存在内核状态字段，没有 syscall | `pulse_core/src/task/signal.rs:185-210,248-254`，`pulse_syscalls/src/handler.rs:238-241` | `sigaltstack()` + `SA_ONSTACK` |
| `wait4` | 已实现但语义部分 | 部分实现 | 当前已用安全写回，避免旧的 page fault panic；但只编码“正常退出”状态，无法表达 signal death/core | `pulse_syscalls/src/impls/task/wait.rs:6-63`，`records/ai-logs/Debugger/2026-04-03-riscv64-wait4-panic.md` | `wait4` + 子进程被信号杀死 |
| `waitid` | 未发现实现，实际 ENOSYS | 低 | 没有 `waitid` 分支 | `pulse_syscalls/src/handler.rs:238-241` | `waitid(P_ALL, ...)` |
| `exit` | 已实现 | 较完整 | 线程退出正常，但不是信号默认动作链的一部分 | `pulse_syscalls/src/impls/task/exit.rs:3-11` | `_exit()` |
| `exit_group` | 已实现 | 较完整 | 能设置 group exit 并退出当前线程 | `pulse_syscalls/src/impls/task/exit.rs:13-22`，`pulse_core/src/task/process.rs:1113-1117` | 多线程退出 |
| `clone` | 已实现但语义部分 | 部分实现 | 线程组、`CLONE_SIGHAND`、`CLONE_SETTLS`、`CLONE_THREAD` 只做到基础层，信号共享/唤醒不完整 | `pulse_syscalls/src/impls/task/clone.rs:52-203` | `pthread_create` / `clone(CLONE_THREAD)` |
| `fork` | 通过 `clone`/fork 路径支持 | 部分实现 | handler/mask 部分继承，pending 不继承，但 `sigaltstack` 不继承/不禁用语义不对 | `pulse_core/src/task/process.rs:1383-1505` | `fork` 后检查 handler/mask/pending/altstack |
| `vfork` | 通过 `clone`/fork 路径支持 | 部分实现 | 主要是 vfork 等待，和信号语义无关 | `pulse_syscalls/src/impls/task/clone.rs:199-203`，`pulse_core/src/task/process.rs:1258-1274` | `vfork` + 信号 |
| `execve` | 已实现但信号语义部分 | 部分实现 | 重置 caught handlers，但 `altstack` 没有禁用；多线程 exec 直接拒绝 | `pulse_core/src/task/exec.rs:124-170`，`pulse_syscalls/src/impls/task/exec.rs:20-74` | `execve` 前后 handler/mask/altstack |
| `nanosleep` | 已实现但不符合 Linux 信号中断 | 部分实现/疑似不兼容 | 不会被 signal 打断，不返回剩余时间，固定睡满 | `pulse_syscalls/src/impls/time.rs:110-135`；上层也写明 `TODO should be woken by signals` | `kill` 打断 `nanosleep` |
| `clock_nanosleep` | 已实现但不符合 Linux 信号中断 | 部分实现/疑似不兼容 | 仅支持 `CLOCK_MONOTONIC/REALTIME`，不返回正确剩余时间，不支持 EINTR 重启语义 | `pulse_syscalls/src/impls/time.rs:138-175` | `clock_nanosleep(TIMER_ABSTIME)` + signal |
| `pause` | 未发现实现，实际 ENOSYS | 低 | 没有 syscall 分支 | `pulse_syscalls/src/handler.rs:238-241` | `pause()` |
| `pselect6` | 未发现实现，实际 ENOSYS | 低 | 无 syscall；且现有 `select`/`ppoll` 不实现信号遮罩 | `pulse_syscalls/src/handler.rs:238-241` | `pselect()` |
| `ppoll` | 已实现但不兼容 | 部分实现/疑似不兼容 | `_sigmask` / `_sigsetsize` 完全未用，阻塞中不会被 signal 打断 | `pulse_syscalls/src/impls/fs/io.rs:273-323` | `ppoll(..., sigmask)` + 信号打断 |
| `epoll_pwait` | 未发现实现，实际 ENOSYS | 低 | 只有普通 `epoll_wait`，没有 `pwait` 版 | `pulse_syscalls/src/handler.rs:238-241`，`arceos/api/arceos_posix_api/src/imp/io_mpx/epoll.rs:170-205` | `epoll_pwait()` |
| `futex` | 已实现但信号语义部分 | 部分实现 | `FUTEX_WAIT` 不会被 signal 唤醒，只有 group exit/timeout/值变化 | `pulse_syscalls/src/impls/futex.rs:30-95`，`pulse_core/src/task/process.rs:1277-1315` | `futex_wait` + `kill/tgkill` |
| `setitimer` | 未发现实现，实际 ENOSYS | 低 | libc 层也还是 `unimplemented()` | `pulse_syscalls/src/handler.rs:238-241`，`arceos/ulib/axlibc/c/time.c:177-182` | `alarm()/setitimer()` |
| `getitimer` | 未发现实现，实际 ENOSYS | 低 | 仅头文件声明 | `arceos/ulib/axlibc/include/sys/time.h:37-38` | `getitimer()` |
| `timer_create` / `timer_settime` / `timer_delete` | 未发现实现，实际 ENOSYS | 低 | 没有 timer signal 生成链 | `pulse_syscalls/src/handler.rs:238-241` | POSIX timer / `SIGALRM` |
| `signalfd` / `signalfd4` | 未发现实现，实际 ENOSYS | 低 | Linux 扩展不支持 | `pulse_syscalls/src/handler.rs:238-241` | `signalfd4()` |

## 4. ABI 和数据结构问题

### 4.1 `sigset_t` / `kernel_sigset_t`

- 内核实现按 64 个信号处理：`NSIG = 64`，pending / blocked 都是 `u64` 位图。
- `rt_sigaction` / `rt_sigprocmask` / `rt_sigsuspend` / `rt_sigtimedwait` 只接受 `sigsetsize == 8`，这符合 Linux 64-bit 的常见 rt ABI，但本质上只覆盖前 64 个信号位。
- `sigaddset()` / `sigemptyset()` 在 in-tree libc 里围绕 `_NSIG = 65` 做了最小处理，但 libc 的 `sigset_t` 仍是 128 字节，和内核内部只读写 1 个 `u64` 是两层不同 ABI，需要用户态 wrapper 配合。

### 4.2 `struct sigaction` / `k_sigaction`

- 内核保存的是 `handler + flags + mask`，见 `pulse_core/src/task/signal.rs:26-31`。
- `sys_rt_sigaction()` 读取/写回的是 `linux_raw_sys::general::sigaction`，没有显式处理 `sa_restorer`，也没有根据 `SA_SIGINFO` 切换 handler 调用约定。
- `SA_NODEFER` 和 `SA_RESETHAND` 有部分支持；`SA_RESTART`、`SA_ONSTACK`、`SA_NOCLDSTOP`、`SA_NOCLDWAIT` 没有行为实现。

### 4.3 `siginfo_t`

- `rt_sigtimedwait()` 只填了 `si_signo/si_errno/si_code`，其余字段保持 0。
- 没有 `rt_sigqueueinfo` / `rt_tgsigqueueinfo`，所以 `siginfo_t` 的大部分 Linux 语义还没有入口。

### 4.4 `ucontext_t` / `mcontext_t`

- 当前没有真正的用户态 signal frame，也没有把 `ucontext_t` 写到用户栈。
- `rt_sigreturn` 只是把内核保存的 `TrapFrame` 直接恢复回去，等于把 signal context 隐藏在内核单槽里，而不是 Linux 的用户栈 frame。

### 4.5 `sigaltstack`

- `ThreadSignal` 里有 `altstack` 字段，但没有 `sigaltstack` syscall，也没有 `SA_ONSTACK` 分支。
- `exec` 没有把 altstack 按 Linux 语义禁用，`fork` 也没有继承/复制出可验证的 altstack 状态。

### 4.6 用户/内核拷贝边界

- 这部分比旧版好一些：`wait4` 已经用 `write_user_i32()`，不会再像 2026-04-03 那次日志那样因为直接写用户指针而 page fault panic。
- 但 signal frame 相关的用户栈写回仍然完全没有，所以真正的 `copy_to_user` 风险只是没进入这条路径，不代表语义已经完整。

### 4.7 32/64 位 ABI

- 当前仓库目标是 `riscv64` / `loongarch64`，没有看到 compat 32-bit ABI 的完整支持。
- 所有信号相关状态都按 64-bit `usize/u64` 编写，没有 compat 层转换逻辑。

## 5. 默认动作与特殊语义

- `SIGKILL`：不可屏蔽，`sanitize_mask()` 已经强制去掉，`rt_sigaction` 也拒绝对它设 handler。
- `SIGSTOP`：同上，不能屏蔽/捕获，但真正的 stop/continue 状态转换没有实现。
- `SIGCONT`：默认动作被识别为 `Continue`，但 `syscall_handler` 对它不做实际状态变化。
- `SIGCHLD`：默认动作被标成 `Ignore`，但子进程退出并不会真的走 signal 生成链，只是 `wait4` 依赖 `child_exit_event`。
- `SIGSEGV` / `SIGILL` / `SIGFPE` / `SIGTRAP` / `SIGBUS` / `SIGABRT`：默认动作全都被粗略当成 `Terminate`，没有 core/stop/kill 细分，也没有异常到 signal 的入口。
- `SIGPIPE`：管道写端在无读者时返回 `EPIPE`，没有转换成 `SIGPIPE`。
- `SIGALRM` / `SIGVTALRM` / `SIGPROF`：计时器 syscall 缺失，所以没有信号生成。
- `SIGTSTP` / `SIGTTIN` / `SIGTTOU`：按 Linux 应该是 stop，但这里会落入 `Terminate`。

结论：项目目前主要处理了常见的 `Terminate`，对 `Stop/Continue/job control` 只是保留了枚举，没有把状态机做完整。

## 6. 多线程与线程组问题

线程组模型已经有雏形：

- `clone(CLONE_THREAD)` 会复用同一个 `Process`
- `getpid()` 返回进程 pid，`gettid()` 返回当前 task id
- 每个线程有独立 blocked mask 和 thread pending
- `process_pending` 是共享的 process-directed pending

但和 Linux 仍有明显差距：

- `process-directed signal` 没有真正的目标线程选择和唤醒
- `pick_thread_for_process_signal()` 存在但没有接入主流程
- `pthread_kill` / `pthread_sigmask` 在 in-tree libc 里还是 `unimplemented()`
- `CLONE_SIGHAND` 只是共享 action 容器，缺少 Linux `sighand_struct/signal_struct` 那种更完整模型
- `SIGKILL` / fatal signal 只能把 `group_exiting` 置位，线程退出仍依赖后续 trap/syscall 边界
- `execve` 直接禁止多线程进程执行，说明线程组状态切换还没达到 Linux 级别

## 7. syscall 中断与 SA_RESTART

这一块是当前最明显的 Linux 语义缺口之一。

- `sys_rt_sigsuspend()` 会在看到 pending 信号后返回 `-EINTR`，但它是忙等 `yield_now()`，并且不会因为 signal enqueue 自动唤醒。
- `sys_rt_sigtimedwait()` 会返回 `sig` 或 `-EINTR/-EAGAIN`，这部分最接近 Linux。
- `sys_nanosleep()` / `sys_clock_nanosleep()` 完全不支持被 signal 中断，源码里还明确写了“`simplified EINTR/rem semantics`”。
- `sys_futex(FUTEX_WAIT)` 不看信号，也不会在 signal 到来时返回 `-EINTR`。
- `ppoll()` / `select()` / `epoll_wait()` 实现里都是轮询 + `yield_now()`，没有信号 mask 切换，也没有 `EINTR` 路径。
- `SA_RESTART` 没有被内核解释，`restart_syscall` 也没有看到实现。

结论：**阻塞 syscall 的信号可中断语义基本不成立**。这会直接影响 musl/glibc、pthread cancellation、shell、很多 LTP 信号项。

## 8. fork/exec/wait 相关问题

### fork / clone

- handler / action：会继承或拷贝，见 `new_child_process()`
- blocked mask：会从父线程复制到子线程
- pending：不会继承，符合 Linux 方向
- altstack：没有明确继承逻辑，当前更像缺失

### execve

- caught handler：会被重置为默认
- 被忽略信号：保留忽略，这点符合 Linux
- signal mask：保留
- pending：`reset_on_exec()` 里清掉了
- altstack：没有按 Linux 语义禁用，这是一个缺口

### wait / exit

- `wait4()` 现在已经避免了“直接写用户指针导致 page fault panic”这类错误，属于修复过的状态
- 但 `wait4()` 只写 `(exit_code & 0xff) << 8`，只能表达“正常退出”
- 被信号杀死的子进程没有 Linux 式 `WIFSIGNALED/WTERMSIG/WCOREDUMP`
- `waitid()` 未实现
- `SIGCHLD` 不是从 exit 链路真实生成出来的，只是 `wait4` 依赖 child zombie 状态

## 9. 测试覆盖与缺口

### 当前能看到的证据

- 2026-04-03 的调试日志确认过 `wait4` 曾经因为直接写用户指针导致 supervisor page fault panic；当前代码已经改成安全写回。
- 记录里有 `clone` / `wait4` / `execve` / `fs` 相关改动说明，但没有看到明确的 signal 专项测试日志。
- 我没有在仓库记录里找到 `libc-test signal`、`LTP signal`、`sigaltstack`、`sigwaitinfo`、`pthread_kill` 等专项结果。

### 当前缺口

- 基础功能：`signal/sigaction/raise/kill/sigprocmask/sigpending/sigsuspend/sigaltstack/sigqueue/sigwaitinfo/sigtimedwait`
- 默认动作：`SIGSEGV/SIGILL/SIGFPE/SIGABRT/SIGPIPE/SIGCHLD`
- syscall interrupt：`pause/nanosleep/poll/select/futex`
- 多线程：`pthread_kill/pthread_sigmask/sigwait/tgkill`
- 继承：`fork/exec/waitpid`
- stress：高频 signal、nested handler、实时信号排队、handler 中 syscall/longjmp

### 推荐测试集

- `libc-test` signal 相关测试
- LTP `signal`, `sigaltstack`, `sigtimedwait`, `pthread_kill`, `futex`, `nanosleep` 相关 case
- 自写最小复现：
  - `kill(getpid(), SIGUSR1)` + blocked syscall
  - `sigaction(SA_SIGINFO)` + `sigqueue()`
  - `sigaltstack()` + `SA_ONSTACK`
  - `pthread_kill()` + `sigwait()`
  - `nanosleep()` / `ppoll()` / `futex()` 被信号打断
- 用 `strace` 对比 Linux 返回值和 errno
- musl / glibc 同一套程序对照运行

## 10. 优先级修复建议

### P0

- 修复 signal 进入用户态的完整链路
  - 问题：没有真正的用户 signal frame / `ucontext_t`，`SA_SIGINFO`、`SA_ONSTACK` 都无法正确工作
  - 影响：libc-test、glibc/musl handler 相关程序、nested signal、`sigreturn`
  - 位置：`pulse_core/src/task/signal.rs:458-505`
  - 方向：在用户栈上构造 Linux 风格 signal frame，保存 `ucontext`/`siginfo`
  - 测试：`sigaction(SA_SIGINFO)`、`sigaltstack`、nested signal

- 修复异常到 signal 的映射
  - 问题：`SIGSEGV/SIGILL/SIGFPE/SIGTRAP` 不走 signal
  - 影响：几乎所有 Linux 应用的错误处理、断点、非法指令场景
  - 位置：`pulse_core/src/trap.rs:10-51`
  - 方向：page fault / illegal instruction / divide by zero / breakpoint 进入 signal 生成链
  - 测试：最小 fault 程序

- 修复阻塞 syscall 的中断语义
  - 问题：`nanosleep/futex/ppoll/select/epoll_wait` 不会因 signal 退出
  - 影响：shell、pthread、LTP、glibc/musl
  - 位置：`pulse_syscalls/src/impls/time.rs:110-175`，`pulse_syscalls/src/impls/futex.rs:30-95`，`pulse_syscalls/src/impls/fs/io.rs:273-323`
  - 方向：统一 wait primitive 支持 signal wake + EINTR/restart
  - 测试：阻塞后发信号

### P1

- 补 `sigaltstack` / `SA_ONSTACK`
  - 影响：真实 signal handler、栈保护
  - 位置：`pulse_core/src/task/signal.rs:185-210,248-254`

- 补 `SA_SIGINFO` / `siginfo_t` / `rt_sigqueueinfo`
  - 影响：实时信号、定时器、异步 IO
  - 位置：`pulse_syscalls/src/impls/misc.rs:336-391`

- 补 `waitid` 和 signaled wait status
  - 影响：`WIFSIGNALED/WTERMSIG/WCOREDUMP`
  - 位置：`pulse_syscalls/src/impls/task/wait.rs:6-63`

- 补 `SIGCHLD` / `SIGPIPE` / timer 生成链
  - 影响：shell、pipe、timeout、进程回收

### P2

- 补实时信号队列和顺序投递
  - 影响：`sigqueue/sigtimedwait/sigwaitinfo`

- 补 `pthread_sigmask/pthread_kill/sigwait`
  - 影响：多线程库兼容
  - 位置：`arceos/ulib/axlibc/c/signal.c:73-86`

- 补 `setitimer/getitimer/timer_*`
  - 影响：`alarm()`、`SIGALRM`、POSIX timer

### P3

- `signalfd` / `epoll_pwait` / `pselect6` / job control / ptrace / seccomp 等扩展

## 11. 最终评分

| 维度 | 分数 | 扣分原因 |
|---|---:|---|
| syscall 接口完整度 | 2 / 5 | 基础 `rt_sig*` 和 `kill` 有了，但大量接口仍 ENOSYS |
| ABI / 结构体兼容 | 1 / 5 | 没有 signal frame / ucontext / altstack，`SA_SIGINFO` 不完整 |
| 信号产生链路 | 1 / 5 | 只有手动 `kill/tkill/tgkill`，异常/pipe/timer/child exit 没打通 |
| 信号投递链路 | 2 / 5 | 有 pending/mask/handler，但不 wake 目标任务，也缺少线程选择 |
| handler / sigreturn | 1 / 5 | 能跳 handler，但没有 Linux 风格 frame，nested signal 风险大 |
| 多线程语义 | 1 / 5 | 线程组模型初具雏形，但 pthread / target selection / wake 不完整 |
| syscall 中断 / 重启 | 1 / 5 | `EINTR` 只在少数路径出现，`SA_RESTART` / restart_syscall 缺失 |
| fork / exec / wait | 2 / 5 | handler/mask 部分继承正常，但 altstack、signaled wait status、waitid 缺失 |
| 测试覆盖 | 1 / 5 | 未找到 signal 专项测试证据，只有 clone/wait4 相关日志 |
| 总体 | 2 / 5 | 有基础骨架，但离 Linux / libc-test / LTP 还差一整段语义链 |

### 扣分最核心的原因

1. 没有真正的 signal frame / `ucontext`
2. 没有异常、timer、SIGPIPE、SIGCHLD 的完整生成链
3. 阻塞 syscall 不会被 signal 正确打断
4. 多线程投递和 target 选择没有 Linux 级别行为
5. `sigaltstack`、`SA_SIGINFO`、`SA_RESTART`、实时信号队列都还没到位

### 最推荐的推进路线

1. 先把“用户态 handler + sigreturn”做成 Linux 风格的真正 frame
2. 再把异常、`SIGPIPE`、`SIGCHLD`、timer 信号接到统一生成链
3. 然后修阻塞 syscall 的 `EINTR/SA_RESTART` 和 wakeup
4. 最后补 `sigaltstack`、实时信号、`pthread_*`、`signalfd`、`pselect6/epoll_pwait`

