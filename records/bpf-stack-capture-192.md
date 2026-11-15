# 真实有界 FP 采样调用栈（#192）

日期：2026-11-15。此实现承接 #182 的受限 FP/no-fault 方案与 #190/#191 的真实采集闭环。默认记录采样 PC 加已确认的 FP record 返回地址，默认深度 32、硬上限 64；运行配置固定读取预算 512 字节。所有地址链在 timer IRQ 中冻结，worker 只处理自有整数快照。它不恢复 DWARF、内联、tail-call 或任意省略 FP 的程序；`complete_at_terminator` 只表示遇到合法的零 previous-FP，不代表所有函数激活均可恢复。

## 格式和生产路径

- RV64 使用 trap 保存的 PC/SP/s0/RA；LA64 使用 PC/SP/fp/RA。FP frame 为 `[previous_fp, return_address]`，位于 `fp-16`。当前 privilege domain 以外的链不可用；内核样本不拼接“最近用户栈”，用户样本不附加采样器自身内核栈。
- 固定 FIFO 保存完整 `FrozenStack`，含寄存器、成功读取字节数、捕获耗时、深度、终止原因和最多 64 个地址；任何借用、指针、地址空间对象均不进入队列。worker 根据已有 activation generation/period 规则处理每个 event，为输出绑定稳定 `PerfEvent.id`。
- 老 64 字节 PerfSampleContext v2 前缀保持不变。新只读 scalar extension 总长 640 字节，BPF 程序直接复制到已验证的 map scratch，避免超过 512 字节 VM 栈；本次没有宣称实现 Linux `bpf_get_stack` helper。
- capture v3 的 native `0x1002/schema3` 保存该扩展。容器 required-extension mask 明确为 1；未知版本/位、长度、状态、保留位、尾部、source/period/CPU/task 归属错误均拒绝。v1/v2 fixture 与旧真实档案继续可读。v3 不能被降级装入 v1/v2 容器。
- analyzer 的 JSON/table/folded 保留真实链、source ID、寄存器、预算和终止原因；folded 按根到叶排列。展开失败只影响链的可用性，不重复算作整条样本损失。period、跳过周期、源/VM/sink/export 各层计数沿用 #191 分别核对。

## 新 unsafe 范围与审查前提

范围限于 `axcpu::sampling` 的两条原生加载、`stack_capture::freeze`、受控用户访问和它们的 IRQ 接线。此记录不是对全内核、全部 Rust 编译器或第三方依赖的通用 soundness 认证。适用平台为本仓库 RV64/LA64，包括其现有异常入口、页表/调度和内存分配契约；实际工具链与源码树哈希记录在每个构建 provenance。

1. **现场和执行身份**：`freeze` 是 unsafe 内部入口，要求 live trap frame、正确来源模式和当前 task；唯一调用点从 IRQ_OBSERVER 和 `current_may_uninit` 得到它们。IRQ 入口已关闭中断，捕获不启 IRQ、不调度、不取得有可能等待的锁，也不运行 NoPreempt 析构；因此任务不能迁移或恢复。当前任务不被两 CPU 同时运行是现有 scheduler TCB。
2. **内核栈生命周期**：构造任务时从实际 TaskStack 分配得到不可变 `[start,end)`，没有默认大小推断；借用 task 期间该分配存在。只读 interrupted SP 以上且位于分配内的对齐 16 字节 record，观察者的活动帧在其下方。boot/init 无 owned stack 返回 unavailable。内核栈机器字读取使用专用汇编，不构造指向中断局部变量的 Rust 引用或切片。
3. **用户地址空间**：同时 try-read Process 的地址空间 slot 和 AddressSpaceLock 的 VMA 锁，前者阻止 exec 替换、后者阻止 unmap/mprotect；竞争返回 busy。检查整个 frame 属于 READ|USER mapping，排除 Linear/MMIO 后端，COW 解包最多 16 层。PC/RA 必须符合架构对齐并属于 EXECUTE mapping。后端的 owned RAM 合同是现有 axmm TCB。
4. **并发 PTE/COW**：VMA 读锁本身不阻止其他 CPU 的 COW PTE 替换。安全额外依赖现有 DeferredReclaims/TlbShootdown 合同：旧物理页在本 CPU 完成失效确认前不回收，IRQ 关闭期间不能伪造确认；本 CPU 的一次同步捕获不会等待该确认。两次加载可观察并发用户写入或 COW 的混合值，作为不可信整数重新验证，不宣称原子栈快照。
5. **no-fault**：新的两条加载指令有精确符号地址；只有 supervisor READ fault 且 PC 匹配时，trap 在日志、进程获取、开 IRQ、resolver 之前把 PC 改到失败返回。普通 user_copy 不受影响。汇编先完成两次读取才写入 Rust 提供的已初始化 `[u64;2]`；失败不写目标。RV SUM guard 恢复进入时的状态；嵌套 fault 通过 trap 保存/恢复其状态。代码不做分配、fault-in、重试或 PTE 锁等待。
6. **原生汇编 TCB**：目标 ABI 的 C 调用约定、trap 保存/恢复通用寄存器、对齐普通 RAM 机器字读取（含用户并发写入）及 fault continuation 是明确的平台前提。该前提不由 Rust 的 typed-pointer 规则推导，也不把机器上可读的任意栈区域声称为合法 Rust `&[u64]`。固定汇编只用 caller-saved 寄存器，写入传入独占目标的 16 字节，恢复调用者控制流。语言/工具链语义依据为 Rust Reference 的 inline/global assembly 与外部 C ABI；跨版本语义不由此记录作无条件保证。
7. **纯算法**：所有加减受检查；FP 对齐、FP>=SP+16、后继严格增加；有效返回地址才加入前缀；最多 63 次 16 字节读取，depth/bytes 均在读前检查，第一次失败即停。环、回退、地址错误和未知状态不会继续解引用。decoder 独立检查这些 wire 不变量。

## 验收办法

- Host：纯 walker 的三层链、0/最大深度、字节预算、环/回退/越界、无 FP、reader 失败、坏返回地址；v1/v2/v3 往返及未知必需扩展；同 CPU 两源 ID/period/逐源计数；frozen context 经真实 verifier/interpreter/map 传递。
- Guest：两组独立、固定 frame 的三层汇编调用，核对 leaf IP 与 middle/outer 精确返回标号；反复 MAP_POPULATE/munmap 的真实内核调用，使用匹配 ELF 符号核对采样链及 mmap 祖先。内核链允许在 trap/汇编边界 partial，不补造用户帧。
- Guest 负例：零 FP、不可读/未 resident 页、环、坏 RA、未对齐 FP、41 层链触发 depth_limit。lazy anonymous 页在读栈前后用 mincore 验证未 resident，证明采样没有 fault-in；负例 IP 与 RAW 中的具体状态独立核对。
- 同 CPU 多实例：CPU mode 每 CPU 两个不同 period 的 event，RAW 的稳定 source ID 对应同次诊断，逐源对账；不是按 CPU 猜实例。
- 使用仓库指定的 8 CPU/8 GiB/snapshot QEMU 形态，保存 RAW、capture、用户/内核 ELF、构建 provenance、原始日志、前后 counters 和 analyzer 输出。capture 的 partial 状态与本功能验收 PASS 分开。

## 最终验证结果

四组实际 QEMU 均通过，原始可重放证据、完整匹配 ELF 与逐文件 SHA-256 见 [evidence/192](../tests/bpf_sampling/evidence/192/README.md)。

| 平台/范围 | 实际 RAW samples | 目标 user A/B 链 | 目标 mmap 内核链 | 独立 source |
|---|---:|---:|---:|---:|
| RV64 task | 351 | 30 / 15 | 29 | 1 |
| LA64 task | 211 | 28 / 24 | 15 | 1 |
| RV64 CPU | 4151 | 44 / 40 | 29 | 16 |
| LA64 CPU | 2557 | 28 / 43 | 31 | 16 |

所有六种负例在每组中均取得实际准确状态；两个 task 会话通过 disable/detach、Link 保留源 FD、dup/最终 close 生命周期验证。CPU 总数含 foreign tasks，但正向 user/mmap 证据均限定目标 PID/TID。四组 transport/export loss 都为 0；source skipped periods、queue/cancellation 和未知诊断另行保存，未将它们重复求和。三阶段实际时间/吞吐和映射字节保存于 index；没有基于一次 QEMU 数据设定未验证的开销阈值。

捕获文件仍为 partial / IncompleteError，保留展开终止原因和其他 unknown/分层损失。真实链例子包括 RV64 的 alloc_page_batch → AnonPageLoad::prepare → resolve_page_fault → try_fault_in_user_range → prefault_user_range → sys_mmap，以及 LA64 的 memset → resolve_page_fault → try_fault_in_user_range → prefault_user_range → sys_mmap。此处箭头表示采集前缀的叶到根函数归属，不是每条机器调用指令的证明。

验证命令：

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
make test 2>&1 | tail -30
cargo test -p pulse_bpf_schema -p bpf-capture -p bpf-analyzer
cargo test -p pulse_syscalls -- --test-threads=1
cargo check -p bpf-capture --no-default-features --features alloc
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
```

Host 结果：schema 34 项、capture/analyzer 137 项、syscalls 230 项与 sampling clock 2 项、Python 61 项通过；新增 schema/walker 先观察到缺少实现的 red，再通过实现转 green。BPF-enabled 与默认双架构构建门禁均通过，原始日志保存在 evidence/192/validation.tar.gz。`git diff --check` 通过。

初轮 RV 主会话取得 371 条有效记录，但额外 FD 生命周期负载被六类负例稀释，正向 loop A 不足两次采样而失败；修复测试负载后最终 RV 生命周期通过，未放宽阈值。该失败未用作成功证据。初轮并行修改时构建来源校验也拒绝了变化中的源码；最终两架构的 provenance 来自固定源码构建。

#192 的真实调用链、失败诊断、稳定实例、版本兼容与运行验收由以上交付覆盖；本地实现没有关闭 #180，也不宣称 PMU、通用 DWARF 或 perf.data 导出已完成。

交付重放复核：四包共 84 个成员的 SHA-256 全部匹配。独立解压 RV task 后 importer 重建 351 条记录，normalized record 字节与原 capture 完全一致；analyzer 状态/诊断/栈字段一致，folded 总权重 351，RAW/ELF 正负链计数一致。报告保存于 evidence/192/replay-report.json。
