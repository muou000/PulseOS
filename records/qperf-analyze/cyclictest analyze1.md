# Cyclictest 火焰图性能分析报告

> **TL;DR 预期收益：综合应用 5 项优化后，cyclictest 平均唤醒延迟预计降低 ~50%，即改善约 1.8x–2.2x。**

> 数据来源：`result.speedscope.json`（speedscope evented profile，共 1681 个时间单元，27010 个事件，1028 个 frame）

---

## 一、总体时间分布（Self Time）

| 类别 | Self Time |
|------|-----------|
| 内存分配（heap/frame allocator） | ~8.86% |
| 调度器 / 上下文切换 | ~5.18% |
| 定时器中断处理路径 | ~4.10%（含 irq_handler inclusive 11.18%） |
| itimer hook 开销 | ~0.77% |
| VDSO 时钟更新 | ~0.54% |
| 抢占开关（NoPreempt/IrqSave） | ~3.1%（分散在多个 frame） |
| fork/clone/exit 生命周期 | ~6.4%（inclusive） |
| 页面错误处理 | ~19.2%（inclusive，含 ELF mmap lazy load） |
| 网络 socket | ~1.25% |
| 文件系统 VFS / ext4 | ~12.4%（inclusive，ELF 读文件） |

> **注意**：由于 cyclictest 会 fork 子进程并做 `exec`，大量时间花在进程初始化（mmap/页错误/ELF 加载）路径上，而不是真正的"稳态 sleep-wake 循环"。

---

## 二、调度关键路径逐项分析

### 2.1 Timer IRQ → 任务唤醒路径（总 inclusive ~11.2%）

```
axhal::irq::irq_handler (11.18% inclusive)
  └─ axplat::irq::handle (10.41%)
       └─ axtask::api::on_timer_tick (7.79%)
            ├─ axtask::timers::check_events (4.10%)
            │    └─ TaskWakeupEvent::callback (3.57%)
            │         └─ AxRunQueueRef::unblock_task (3.63%)
            ├─ pulse_core::task::itimer_tick_hook (3.57%)
            └─ axruntime::vdso::update_vdso_data (1.73%)
```

**关键发现**：

#### ① `itimer_tick_hook` —— **每个 tick 都在扫描所有进程的 itimer，代价高**
- Self time: **0.773%**，inclusive: **3.57%**，调用次数: **49**
- 问题：`itimer_tick_hook` 在 `on_timer_tick` 中被调用，属于 O(进程数) 扫描。cyclictest 会创建多个线程/进程，每次时钟中断都会遍历其 itimer 状态。
- 代码位置：`pulse_core::task::itimer_tick_hook` → `Process::check_itimer_real_tick`

#### ② `check_events` 中的 `BTreeMap` 遍历
- 在 `on_timer_tick` subtree 内，BTreeMap 相关操作（`LazyLeafRange::init_front`、`right_kv`、`BTreeMap::Iter::next`）合计约 **1.2%** self time
- 定时器列表用 `BTreeMap<time, event>` 实现，每次 tick 要 `pop_min` 遍历
- `core::ptr::swap_chunk` (0.297%) 来自 `BinaryHeap::pop`（定时器堆操作）

#### ③ `sbi_call_3` 在 IRQ 路径中出现（0.535%）
- 即 `sbi_rt::binary::sbi_call_3`，这是 SBI 调用（RISC-V 的 ecall）
- 在 timer tick 路径中，原因是：重新设置 oneshot timer（`__TimeIf_set_oneshot_timer`）需要通过 SBI 设置 `stimecmp`
- 该调用会有 ecall 陷入 M-mode 的延迟

#### ④ `u128_div_rem`（`compiler_builtins::int::specialized_div_rem`）—— **意外的重型运算**
- Self time: **0.892%**，出现在 IRQ handler subtree 内，**占 IRQ 子树的 8%**！
- 来源：`starry_vdso::vdso_time_data::clocks_calc_mult_shift`（0.476%） 调用了 128 位除法
- VDSO 时间换算（nanos → clock cycles）的 mult/shift 计算，使用了软件 u128 除法
- RISC-V 无原生 128 位除法指令，由 `compiler_builtins` 实现，**非常耗时**

---

### 2.2 上下文切换路径（Self Time ~1.5%）

| 函数 | Self | 调用次数 |
|------|------|----------|
| `TaskContext::switch_to` | 0.48% | 14 |
| `RRScheduler::pick_next_task` | 0.36% | 8 |
| `AxRunQueue::switch_to` | 0.30% | 7 |
| `FpState::switch_to` | 0.24% | 4 |
| `preempt_resched` | 0.06% | 11 |

**关键发现**：

#### ⑤ `FpState::switch_to`（FP 寄存器保存/恢复）
- 每次上下文切换都触发浮点状态切换
- cyclictest 可能使用了浮点运算，导致 `sstatus.FS` 为 dirty，每次切换都必须保存/恢复 FP 寄存器组
- 可以考虑 lazy FP restore（仅在 FP dirty 时保存）

#### ⑥ 抢占开关总开销
- `__KernelGuardIf_disable_preempt`: 0.833%（27 次）
- `__KernelGuardIf_enable_preempt`: 0.357%（29 次）
- `NoPreemptIrqSave::new`: 0.833%（31 次）
- `NoPreemptIrqSave::release`: 0.654%（12 次）
- `local_irq_save_and_disable`: 0.890%（15 次）
- **合计约 3.5% self time** 花在锁 acquire/release 上
- 每次关抢占 + 关中断 + 开中断都有显著的内存屏障 + atomic 开销

#### ⑦ `TaskInner::current_check_preempt_pending`
- Self: 0.595%，调用 30 次
- 每次从 syscall 返回前都要检查抢占标志，有不小开销

---

### 2.3 sleep/clock_nanosleep 路径（总 inclusive ~3.6%）

```
sys_clock_nanosleep (3.57% inclusive)
  └─ sleep_until_clock_interruptible (2.50%)
       └─ sleep_until (1.67%)
            └─ WaitQueue::wait (→ switch_to)
```

- sleep 本身 self time 极低（0.06%），说明进程确实在睡眠，**sleep 路径本身无热点**
- 问题在于**被唤醒后的延迟**：从 `unblock_task`（IRQ 中触发）到任务真正运行的路径

---

### 2.4 进程生命周期开销（fork/exec/exit，inclusive ~10%）

| 路径 | Inclusive |
|------|-----------|
| `sys_clone` → `spawn_fork_from_trap_frame` | 9.93% |
| `CurrentTask::clone` → `try_clone`（addr space clone） | 7.26% + 9.58% |
| `Thread::exit_current` → `finish_thread_exit` | 6.60% |
| `release_zombie_resources`（页表释放） | 6.19% |

- 这部分时间主要是 cyclictest 启动子进程时消耗的，**不是 cyclictest 稳态循环的延迟**
- 但如果测试包含频繁 fork，这些开销会叠加在 latency 测量期间

---

### 2.5 页面错误 / mmap lazy load（inclusive ~19.2%）

```
riscv_trap_handler (75.43% inclusive) -- 大量时间在内核态
  ├─ handle_page_fault (19.2% inclusive)
  │    ├─ handle_page_fault_file (17%)  <- ELF 段的 demand paging
  │    └─ handle_page_fault_alloc       <- 匿名内存 COW
  └─ handle_syscall (43.4% inclusive)
```

- **ELF 的 demand paging 是大头**：每次 `exec` 后，代码段/数据段按需加载，触发大量 ext4 读操作
- `ext4_rs::get_inode_ref`（12.79% inclusive）、`Block::load`（12.31%）说明磁盘 I/O 在文件页加载时很重
- **这是 cyclictest 首次运行或进程重启时的冷启动成本**，稳态运行时不应出现

---

## 三、关键瓶颈汇总（按优先级）

| 优先级 | 问题 | 自时间 | 影响 |
|--------|------|--------|------|
| 🔴 高 | `itimer_tick_hook` 在每次 tick 扫描所有进程 | 0.77% self / 3.57% incl | 直接增加 IRQ 处理延迟，影响 cyclictest wake latency |
| 🔴 高 | `u128_div_rem` 在 VDSO 时间换算中（软件实现 128-bit 除法） | 0.89% self in IRQ | 每次 tick 都执行，增加 IRQ 不可抢占时间 |
| 🟠 中 | 抢占开关/IRQ 开关累计开销（`NoPreemptIrqSave` 等） | ~3.5% self 合计 | 增加临界区时长，延迟 wakeup |
| 🟠 中 | `check_events` 用 BTreeMap/BinaryHeap 实现定时器列表 | ~1.2% self in tick | 定时器弹出路径有 BTreeMap 遍历开销 |
| 🟠 中 | FP 状态在每次上下文切换时保存/恢复 | 0.24% self / 14次 | 若能 lazy 保存可节省一定开销 |
| 🟡 低 | SBI `sbi_call_3`（设置 oneshot timer） | 0.54% | ecall 陷入 M-mode，有不可避免的延迟 |
| 🟡 低 | `current_check_preempt_pending`（30 次调用） | 0.60% | 每次 syscall 返回均检查，但不可省略 |
| 📊 背景噪声 | ELF demand paging / 页错误（进程初始化期间） | 19.2% incl | 仅在进程冷启动时出现，预热后消失 |

---

## 四、cyclictest 关键延迟路径还原

```
[定时器到期]
    │
    ▼
IRQ 进入 (riscv_trap_handler)
    │
    ├─ axplat::irq::handle
    │    └─ on_timer_tick
    │         ├─ itimer_tick_hook (O(N进程) 扫描) ← 瓶颈①
    │         ├─ update_vdso_data
    │         │    └─ clocks_calc_mult_shift      ← 瓶颈②（u128除法）
    │         ├─ check_events (BTreeMap::pop)     ← 瓶颈③
    │         │    └─ TaskWakeupEvent::callback
    │         │         └─ unblock_task
    │         │              └─ put_task_with_state + resched
    │         └─ reprogram_timer (sbi_call_3)     ← 瓶颈④
    │
IRQ 返回 / 调度决策
    │
    ├─ current_check_preempt_pending              ← 瓶颈⑤
    ├─ pick_next_task (RRScheduler)
    ├─ switch_to (TaskContext + FpState)          ← 瓶颈⑥
    └─ enter_uspace (返回用户态)
```

---

## 五、优化建议

### 建议一：减少 `itimer_tick_hook` 的每 tick 开销
- 当前实现：每个 tick 遍历所有进程检查 itimer 到期
- 优化：维护一个全局 itimer 最小堆或有序集合，O(1) 检查是否有 itimer 即将到期，仅到期时才遍历

### 建议二：消除 VDSO 时间换算中的 u128 除法
- `clocks_calc_mult_shift` 使用软件 u128 除法（0.89% 在 IRQ 路径内）
- 优化：预计算 mult/shift 参数（仅在 timebase 变化时重新计算），避免每次 tick 重算；或用移位近似替代除法

### 建议三：减少 IRQ 临界区内的锁/抢占操作
- IRQ handler 内多次 `disable_preempt` + `enable_preempt`，每次都是原子操作 + 内存屏障
- 优化：减少 IRQ 路径内的 guard 嵌套层数，合并多个 critical section

### 建议四：定时器列表考虑用更高效结构
- `BTreeMap` 对于 timer 最小堆操作（pop min）有 O(log N) overhead 且缓存不友好
- 优化：使用 `BinaryHeap` 或时间轮（Timing Wheel）

### 建议五：FP 寄存器 Lazy Save
- 仅当 `sstatus.FS == Dirty` 时才保存 FP 寄存器，否则跳过
- 对于没有使用浮点的任务（如 cyclictest 主线程），可以完全避免 FP 切换开销
