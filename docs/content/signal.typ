#import "../components/prelude.typ": *

= 信号系统

== 信号队列及相关结构

PulseOS 的信号子系统对接了标准 POSIX 信号的核心机制。为了在多线程环境下实现高效、合规的信号路由与过滤，我们将信号状态划分为进程共享与线程局部两级，并使用多级原子挂起位图进行管理。

=== 核心数据结构

1. `SignalShared`：管理进程内所有线程共享的信号处理程序、进程级未决信号以及相应的信号附加信息。其定义如下：

#figure(
  ```rust
  // pulse_core/src/task/signal.rs
  pub struct SignalShared {
      handlers: Arc<SignalHandlers>,
      process_pending: AtomicU64,
      pub pending_siginfo: Mutex<BTreeMap<usize, [u8; 128]>>,
  }
  ```,
  caption: [SignalShared 进程共享信号状态结构定义],
) <SignalShared-struct>

2. `ThreadSignal`：每个线程独占的信号状态，包括线程私有的未决信号、信号屏蔽字、是否处于 Handler 执行中的状态标志、嵌套恢复上下文以及替代信号栈（`altstack` 目前只实现了接口与注册，并没有实现真正的替换逻辑）。其定义如下：

#figure(
  ```rust
  // pulse_core/src/task/signal.rs
  pub struct ThreadSignal {
      shared: Arc<SignalShared>,
      thread_pending: AtomicU64,
      blocked: AtomicU64,
      in_handler: AtomicBool,
      skip_once: AtomicBool,
      signal_wait: WaitQueue,
      saved_ctx: Mutex<Option<SavedSignalContext>>,
      altstack: Mutex<SignalAltStack>,
      sigsuspend_restore: Mutex<Option<u64>>,
      pub pending_siginfo: Mutex<BTreeMap<usize, [u8; 128]>>,
  }
  ```,
  caption: [ThreadSignal 线程局部信号状态结构定义],
) <ThreadSignal-struct>

== 信号处理

=== 信号排队与状态合并

当用户执行 `kill`、`tkill` 或 `tgkill` 发送信号时，内核会计算出目标线程，并更新相应的 `pending` 位图，随后唤醒其所在的阻塞队列。

在每次线程即将从内核态返回用户态前，内核会将线程局部的 `thread_pending` 与进程级的 `process_pending` 进行按位或运算，并过滤掉被屏蔽的信号，从而合并计算出当前真正可递送的信号集合。

=== 信号分发

对于上述可递送集合中自定义了处理程序的信号，内核将在返回用户态前，通过以下步骤注入信号入口并启动处理流程：

- 栈帧开辟：
  内核在当前用户栈上，向下开辟 `frame_size = 1152` 字节空间并按 16 字节对齐，将当前 `TrapFrame` 的通用寄存器和信号屏蔽字打包写入用户栈的 `ucontext_t` 与 `siginfo_t` 结构中。
- 修改上下文：
  - 将 PC `sepc`（RISC-V 64）或 `era`（LoongArch 64）重定向为用户注册的函数指针 `act.handler`。
  - 将通用寄存器 `a0` 设为信号编号 `sig`，`a1` 设为 `siginfo_t` 用户栈地址，`a2` 设为 `ucontext_t` 用户栈地址。
  - 将栈指针 `sp` 设为刚刚开辟的用户栈帧基址。
  - 蹦床注入：将返回地址 `ra` 改写为进程注册的 `signal_trampoline` 地址，即 vDSO 中的 `__vdso_rt_sigreturn` 的地址。
- 信号处理开始：退出内核进入用户态，CPU 会直接跳转到信号处理函数处执行。

信号处理的整体生命周期时序与控制路径如下时序图所示：

#align(center)[
  #image("../img/13.png", width: 105%)
]

=== 用户栈帧恢复

当用户信号处理程序执行完毕时，通过 `ra` 跳转进入 vDSO 的 `__vdso_rt_sigreturn` 系统调用重新陷入内核。内核在系统调用处理函数中恢复通用寄存器和执行状态的流程如下：

- 上下文恢复流程：
  1. 内核首先从内核安全存储区 `saved_ctx` 中取出被信号打断时的原始寄存器状态，并完全写回当前的 `TrapFrame`。
  2. 随后，内核尝试从用户栈上的 `ucontext_t` 结构中读取用户可能修改的通用寄存器，并安全地覆盖更新至 `TrapFrame` 中。

- PC 校验与防御：
  在将用户态修改的指令指针应用回 `TrapFrame` 前，内核强制执行 PC 地址的边界防御校验：

  - 读回的 PC 必须指向用户地址空间。若检测到读回的 PC 指向内核地址空间，内核将拦截该跳转，并安全回退至 `saved_ctx` 中原本保存的被打断指令地址继续执行。这作为纵深防御的一部分，确保了即使用户态的 `ucontext_t` 被恶意篡改，控制流也无法被劫持到内核地址空间，保障了内核的安全边界。
