# 调用栈捕获设计草案（#182）

状态：**Draft，尚未获得设计确认，不构成已实现能力或 issue resolution。**

日期：2026-11-14。PulseOS 代码基线：`758fa083dde3d9c7a36e2f9f5b9c8266439cb889`。调查范围为 RV64/LA64 软件周期采样、现有 BPF interpreter/verifier 与采样调用栈；不改生产代码。关联 [#182](https://github.com/muou000/PulseOS/issues/182)、[#190](https://github.com/muou000/PulseOS/issues/190) 及 [perf.data 研究](perf-data-minimal-subset.md)。

## 建议结论与需要确认的范围

建议首版采用**有界 FP 展开 + 显式不完整状态**：从被采样的 trap 现场开始，将内核/用户地址链冻结为不可变的采样快照；后续 BPF helper 仅复制该快照，主机负责符号化和 `PERF_SAMPLE_CALLCHAIN` 导出。默认每域 32 个 IP，硬上限每域 64 个 IP，深度和字节预算均计入会话配置。DWARF 原始栈转储、任意省略 FP 的用户二进制、任意手写汇编的完整恢复属于后续模式。[S1][S2][S3][S4]

这是一项有明确损失边界的采集功能，不应称作无条件“完整调用栈”。在具有已验证 frame record 的代码中，可以得到受深度限制的链；在缺 FP、优化/汇编边界、内存读取失败或异步 prologue/epilogue 窗口中保留可靠 PC 和已确认的前缀，附带失败原因。单 IP 不得伪装为已经完成 full-stack 验收。

需要维护者确认的主要产品选择是：**首阶段接受上述 FP 能力范围和明确 partial/unavailable 行为，将通用用户 DWARF 延后，是否符合本 map 的“完整 CPU 热点分析”目标。** 其余默认深度、结构体细节、测试布局均可以在该范围内据测量调整；不必让用户选择可由实现和 ABI 查证的事实。

## 1. 已查证的实现入口与缺口

| 位置 | 已有事实 | 对实现的含义 |
| --- | --- | --- |
| RV64 `TrapFrame` | `sepc`、`regs.sp`、`regs.s0`、`regs.ra` 分别持有 PC/SP/FP/RA；trap assembly 保存原 SP | 应在 `riscv_trap_handler(tf, from_user)` 的 IRQ 分支捕获，而非在稍后的 timer hook 读取采样器自身寄存器。[P1] |
| LA64 `TrapFrame` | `era`、`regs.sp`、`regs.fp`、`regs.ra`；assembly 使用 PRMD 判断来源模式并保存原 SP | 在 `loongarch64_trap_handler` 对应 IRQ 分支捕获。[P2] |
| generic IRQ | `IRQ: [fn(usize) -> bool]`，两架构只向其传中断号，未传 tf | 现有 `axtask::on_timer_tick` 得不到被中断现场。#190 需要带现场的 observer 或受控 per-CPU 快照交接；不能在 hook 中用当前 RA 替代采样 PC。[P3] |
| 内核栈 | `TaskStack` 有 start/size，但私有；公开接口只有 `kernel_stack_top()`，内部取 `SpinNoIrq` 锁 | 需要明确活跃栈的有效区间与生命周期接口，避免从“top 减默认大小”猜测所有任务/boot/idle 栈。不能在 IRQ 中盲目重新取得可能已持有的锁。[P4] |
| 用户访问 | `Process::read_user_bytes_partial` 当前进程用 `user_copy`；跨进程路径取地址空间锁并可能主动 fault-in | 不是现成的 IRQ no-fault reader。[P5] |
| page-fault fixup | 内核访问用户地址产生 fault 时，当前 trap 路径先尝试 `proc.handle_page_fault`，失败后才走 exception-table fixup | 仅见到 `user_copy` 和 exception table 并不能证明“不会缺页/阻塞”。应增加受限 no-fault 机制，或以等价且经审计的方案避免慢路。[P6] |
| BPF context | `PerfEventContext` 为 48 bytes，含 period/addr/time/CPU/PID/TID/task；没有寄存器、调用链、mode 或 stack status | 保留已有字段含义。不能把 Linux `addr` 数据地址不加版本地改成 `ip`，也不能向用户暴露 Rust trap-frame 指针。[P7] |
| interpreter/verifier | VM 栈 512 bytes；context 上限 80 bytes（PerfEvent 使用自身 size）；只有 map/time/CPU/output 等 helper，无 get_stack | 双域 64-frame 链共 1024 bytes，不能硬塞进 BPF 栈或现有 context。需独立快照存储及 helper 输入/输出证明。[P8] |
| 用户现场保留 | `Thread` 未发现一个覆盖 syscall/fault/IRQ 嵌套生命周期的、供采样使用的 outer-user-register snapshot | 内核态采样不能从“当前内核 tf”推导用户 FP；需要为当前内核激活建立明确的用户来源快照，或报告 unavailable。[P9] |
| 构建 | `scripts/make/cargo.mk` 目前未设置 `-C force-frame-pointers=yes` | 现有内核 ELF 不能仅凭架构支持就被假定具有 FP 链。[P10] |

当前 #190 只需可靠单 PC 和来源模式即可先建立真实采样门禁；完整链应在本设计确认后单独实现。不得为了让 #190 通过而伪造调用链或读取 worker 后来的栈。

## 2. 两种架构的 frame record 事实

RISC-V psABI 明确 FP 可选；有 FP 时使用 x8/s0。RV64 常规 frame record 是两个 64-bit 值，`previous_fp` 位于 `fp-16`，`return_address` 位于 `fp-8`，FP 在 prologue 结束后指向 CFA。ABI 允许平台不维护链、个别函数不建链或 leaf 不建链，因此这些地址规则不保证任意异步时刻都有当前函数的完整记录。[S1]

LoongArch psABI 将 r22 记作 fp/s9，并规定栈向下增长、过程入口 SP 16-byte 对齐，但其一般调用约定不是“所有函数都有同一 FP 链”的保证。Linux v6.12 用户栈遍历使用 `struct stack_frame { fp, ra }`，从 `fp - sizeof(frame)` 读取，检查 16-byte FP 对齐和向上进展；Linux 内核路径另有 prologue unwinder。PulseOS 若选择统一的 FP walker，必须用受支持 Rust/Clang 产物验证其 frame-record 布局，而不能把 Linux 的 prologue 恢复能力算作已经具备。[S2][S3]

共同 walker 至少应检查：

1. 目标架构模式与地址宽度；PC、SP、FP 不来自 consumer。
2. 所有地址加减及 `fp-16` 用 checked arithmetic；读 16 bytes 前验证整个范围。
3. 内核读取仅落在该采样时有效且仍存活的栈范围；用户读取只在合法用户地址范围。
4. FP 对齐、下一 FP 严格向高地址进展、跨度/字节预算、深度上限。循环或倒退即停止，不能靠“最终也许会碰到零”终止。
5. 返回地址只作为待解析代码地址；不通过把栈中任意“看起来像 text”的整数扫描出来补链。
6. sampled PC 与返回地址的语义不同，不可统一减固定指令长度；RISC-V 压缩指令、tail call、leaf 和异步窗口需要专门测试。

这些是建议的输入防御规则，**不构成 unsafe Rust 的完整证明**。地址落在栈区间并不自动证明 frame record 已初始化、Rust 引用合法或内存不会变化；unsafe 实现还需按本仓库审查流程写出适用的架构/编译器/生命周期前提。禁止为任意栈范围直接构造 `&[u64]` 并以 bounds check 当作安全证明。

## 3. 建议的采样快照与接口

建议由一个栈捕获 Module 集中管理“现场读取、展开、状态、预算”，给调用方提供小 Interface：输入为已验证的采样现场和有界 reader，输出为固定容量地址链及状态。架构 Adapter 只负责寄存器选择和受支持 frame 规则；user/kernel reader 分别实现各自内存访问约束。host 测试通过同一 walker Interface 传入确定的 frame bytes，不测试内部循环形状。

建议内部数据（不是公开 ABI 的最终布局）：

```text
SampleOrigin {
  observed_pc, observed_sp, observed_fp, observed_ra,
  cpu, pid, tid, task_id, timestamp_ns, mode,
  address_space_generation, attachment_generation
}
FrozenCallchain {
  kernel_ips[64], kernel_len, kernel_status,
  user_ips[64], user_len, user_status,
  captured_depth_limit, capture_flags
}
```

`FrozenCallchain` 属于采样事件，不属于“此刻 CPU 上某个全局最近栈”；用不可变所有权或严格的槽位租约绑定事件身份。排队/延后 BPF 时必须一起保存，不能只保存寄存器后让任务继续跑，再由 worker 用过期 FP 读变化后的栈。队列满、代际不符和失效地址空间都应丢弃/标记，不补造旧样本。

用户态被中断时，只要求用户链；采样 IRQ 处理函数自身不是工作负载的内核调用链。内核态被中断时，先记录内核链；若要拼接用户调用来源，需有该线程当前内核激活的 outer-user snapshot，其建立/恢复/退出和 nested trap 生命周期明确。这里的用户现场表示当前 syscall/fault 的用户调用来源，不能拿其他时刻保存的“最近 user PC”拼接。没有来源时 kernel-only，并标 user unavailable。

不建议首版把架构寄存器全量放进稳定 BPF context。context 可通过一个明确的新版本/层级提供 IP、mode、stack status；快照本体由执行环境持有，不给 BPF 任意内核指针。版本选择还需与 #186 的 Linux BPF 兼容边界一起确认。

## 4. 用户栈读取：必须补齐 no-fault 语义

推荐采用专用、当前进程限定的 non-sleepable no-fault reader，且在 capture 生命周期内完成：

- 先验证用户范围、读长度上限与 CPU/task/地址空间身份。
- no-fault guard 激活期间，来自指定 user-copy 指令范围的内核 fault **直接** exception-table fixup，不进入 `resolve_page_fault`、分配器或等待路径；guard 作用范围必须小，不能掩盖普通内核 fault。
- RV64 SUM 按已有 UserAccessGuard 的作用域原则恢复；不得影响被中断的既有 user-copy 状态。LA64 非对齐读采用经过审计的字节/对齐访问，不依赖 LS2K1000 的 UAL。
- 当前CPU不可迁移、guard不能跨线程移动；嵌套和早退都恢复状态。另一个线程并发改写用户栈时可以得到 partial 链，但必须保证不会无限循环、越界或崩溃。
- 不持全局 BPF registry、地址空间写锁或调度队列锁遍历用户栈；锁竞争即明确 unavailable/try-lock failed，不能在 IRQ 等待自己。

替代方案是只复制一段有界原始栈快照再在可睡眠上下文展开；但仍需在采样点使用 no-fault 复制并保存正确寄存器，且 FP 链可能跳出拷贝窗口。其额外内存与截断行为应独立量化，不把“延后处理”当作解决访问安全和时间一致性的手段。

Linux v6.12 的非 sleepable `bpf_get_stack` 使用 `may_fault=false`，LoongArch user walker 明确调用 `pagefault_disable()` 与 inatomic copy；它们支持上述需求方向，但不能直接作为 PulseOS 代码安全性的证明。[S3][S4]

## 5. 在 BPF 程序中访问采样调用栈

推荐优先实现 Linux helper ID **67，`bpf_get_stack(ctx, buf, size, flags)`** 的受限明确子集，而不是再定义一个返回裸内核指针的私有 helper。用户传 `BPF_F_USER_STACK` 选择用户域，否则内核域；skip 使用低 8 bits。`BPF_F_USER_BUILD_ID`、未支持程序类型、跨任务读取与未知 flags 明确失败。符号/build-id 解析仍在 host。[S4][S5]

本建议不等于宣称完整 helper 兼容。必须在加载期 verifier 与运行期同时实现：

| 条件 | 要求 |
| --- | --- |
| ctx | 来自此 program 类型的合法 context，不能靠任意 scalar 冒充 |
| buf | 可写 VM stack 或经过 null check 的可写 map value；验证 offset 与整段 size，不接受 readonly/context 地址 |
| size | 有可证明的常量/上界，8-byte 倍数，受 domain cap 与目标剩余空间限制；现 verifier 仅有泛化 `Scalar`，需补值/范围证明或更窄固定大小约束 |
| 输出初始化 | Linux helper 成功返回复制字节数并清零未使用尾部，错误也清零请求 buffer；与 verifier 的“已初始化字节”状态一致，不能将未写尾部标成 initialized。[S4] |
| 私有快照 | helper 只能复制此事件已经冻结的地址链，不发起任意内存读取，不跑新的栈遍历 |
| license/层级 | v6.12 helper proto 标 `gpl_only`；现 `bpf_prog_load` 只是读取 license 并未保留该属性。若承诺 Linux helper 兼容，必须实现对应加载元数据/门禁；#186 不能忽略这一差异。[S4][P8] |
| 指针生存期 | 不向用户返回可解引用内核地址；地址链中的代码地址是 opaque scalar，verifier 不得把它重新解释成 VM 指针 |

每域 64 个 IP 已等于整个 512-byte BPF 栈；还要存 metadata/另一域时，应使用明确的 map scratch/output 方式或分块协议，不能扩大 VM 栈后无测量地把成本推入中断栈。`get_stackid`/STACK_TRACE map 可以后续加入；首版地址链避免引入哈希碰撞、ID 复用及字典丢失生命周期。

## 6. 状态、深度与性能预算

建议为两域各自保存以下互斥终止状态，并另记 capture 级错误：`complete_at_terminator`、`depth_limit`、`invalid_frame`、`read_fault`、`unavailable`、`unsupported_abi`。在不能识别合法终止边界时，用 partial 状态而不是 complete。FP 优化造成的缺帧不总能被运行时检测，因此会话也必须声明 `unwind_method=fp` 和已验证编译/ABI范围；不能只靠一个 complete bit承诺没有丢失内联或tail-call frame。

默认32/hard64每域是建议起点：最多128个IP、最多128次16-byte frame读取；hard cap 以总字节与最大访问次数共同约束。实际顶层 sampled PC 是否占一个名额、skip前后的深度口径要固定且测试。BPF 指令预算不覆盖 native helper 内部循环，因此必须给 stack capture 自己的预算。

队列容量按“每事件>1KiB”的最坏快照大小计算，各CPU固定容量在会话enable前预分配；不沿用现有80B tracepoint槽位后悄悄截断。记录 capture耗时、有效帧数、各状态和队列满次数。FP缺失或读失败仍可保留有效IP样本；不能把“栈失败”与“整条样本丢失”重复计数。overhead门槛须由真实负载测量再定，不先许诺任意百分比。

## 7. 测试先行与实施顺序

| 阶段 / 对外可观察行为 | 最低测试 | 不足以证明的事情 |
| --- | --- | --- |
| 1. 来源现场（#190） | RV/LA guest两个不同忙循环；实际timer触发；PC落入各自函数范围，mode/CPU/TID正确；disabled无新样本 | 不证明栈展开 |
| 2. walker Interface | 受控三层frame chain、0/最大深度、循环、倒退、地址溢出、读边界、未对齐、reader失败；固定字节fixture给出独立预期链 | 不证明真实编译器frame布局或内存安全 |
| 3. no-fault reader | resident、unmapped、guard-page、跨页、PROT_NONE、并发munmap；fault-in/分配计数不增加，不杀进程；guard早退/嵌套恢复 | host模拟不替代架构exception-table验证 |
| 4. helper/verifier | 拒绝伪ctx、只读/越界目标、未证明size、未知flags；成功返回长度、尾部清零、错误全清零、后续读初始化；支持与不支持的license/类型 | 只通过VM运行不代表真实采样 |
| 5. 编译产物 | 内核profiling配置启用force-FP，RV/LA真实ELF反汇编检查leaf/nonleaf/tailcall/assembly入口；用户测试程序保FP；明确其依赖库范围 | compiler flag不保证所有汇编/第三方库有完整链 |
| 6. 真实栈门禁 | user-only、kernel-only、当前syscall来源混合链；scheduler migration、signal stack、prologue/epilogue压力；错误时状态明确 | 合成地址链不得当真实FP证据 |
| 7. 消费互操作 | 用#181固定Linux perf和匹配ELF显示预期多层函数；截断/未知符号可见，权重保持；#191 capture计数真实 | perf文件能parse不证明捕获正确 |

实现应按以上依赖推进，`make test` 与 AGENTS.md 的双架构QEMU为内核改动门禁。建议先完成独立walker及no-fault reader，再把冻结快照接入#190的有界事件路径；最后实现helper/capture版本与host导出。缺少任一真实用户/内核链门禁时，#182仍只可关闭“设计确认”部分，map不能宣布该功能交付完成。

## 一手依据

- [S1] [RISC-V psABI，固定 revision df36d98e](https://github.com/riscv-non-isa/riscv-elf-psabi-doc/blob/df36d98e187bc6ae4978fbb22a2105d24e7cd32b/riscv-cc.adoc#L41-L75)：FP可选、frame record及平台选择；[Linux v6.12 RISC-V stacktrace](https://github.com/torvalds/linux/blob/v6.12/arch/riscv/kernel/stacktrace.c) 展示异步/leaf等架构处理复杂度。
- [S2] [LoongArch psABI，固定 revision 44ef5f63](https://github.com/loongson/la-abi-specs/blob/44ef5f63e1755e1a165915ea3b2d98d35f68eed0/lapcs.adoc)：r22/fp与栈对齐、保存寄存器规则。
- [S3] [Linux v6.12 LoongArch stacktrace.c](https://github.com/torvalds/linux/blob/v6.12/arch/loongarch/kernel/stacktrace.c)、[stack_frame](https://github.com/torvalds/linux/blob/v6.12/arch/loongarch/include/asm/stacktrace.h)、[prologue unwinder](https://github.com/torvalds/linux/blob/v6.12/arch/loongarch/kernel/unwind_prologue.c)：用户FP链读取与内核展开是分别实现的能力。
- [S4] [Linux v6.12 stackmap.c](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/stackmap.c#L405-L510) 与 [perf-event helper proto](https://github.com/torvalds/linux/blob/v6.12/kernel/bpf/stackmap.c#L579-L640)：非sleepable获取、skip/flags、byte count、清零和verifier参数。
- [S5] [Linux v6.12 bpf.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/bpf.h#L3303-L3344)：`bpf_get_stack` 参数和返回语义；helper ID见同文件mapper。
- [P1] [RV trap](../../modules/cpu/src/riscv/trap.rs)、[context](../../modules/cpu/src/riscv/context.rs)、[assembly](../../modules/cpu/src/riscv/trap.S)。
- [P2] [LA trap](../../modules/cpu/src/loongarch64/trap.rs)、[context](../../modules/cpu/src/loongarch64/context.rs)、[assembly](../../modules/cpu/src/loongarch64/trap.S)。
- [P3] [generic IRQ](../../modules/cpu/src/trap.rs)、[timer hook](../../modules/task/src/api.rs)。
- [P4] [TaskStack与公开top接口](../../modules/task/src/task.rs)。
- [P5] [Process memory读取](../../modules/process/src/lifecycle/memory.rs)、[uaccess](../../modules/process/src/uaccess/mod.rs)。
- [P6] [page fault处理](../../modules/process/src/trap.rs)、[exception table](../../modules/cpu/src/exception_table.rs)。
- [P7] [固定context与队列容量](../../crates/pulse_bpf_schema/src/lib.rs)。
- [P8] [interpreter](../../modules/bpf/src/interpreter.rs)、[verifier](../../modules/bpf/src/verifier.rs)、[program load license处理](../../pulse_syscalls/src/impls/bpf/prog.rs)。
- [P9] [Thread](../../modules/process/src/thread.rs)。
- [P10] [kernel构建flags](../../scripts/make/cargo.mk)。
