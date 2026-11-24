# 缺页 resolver 完成事件契约（#185）

#196 的后续实现与当前分类语义见 [target-page I/O 分类契约](page-fault-io-classification.md)。
本文的全部 Unknown 描述保留为 #185 历史基线，不再描述支持 I/O provenance 的新 producer。

状态：依据继续推进 #180 的授权选定的实现契约。2026-11-15，调查基线 `96a73a176df502f38d652912cb6a3cc04a44c23c`。此文明确 #185 的六个决定；schema、生产钩子和 host dispatch 回归随实现交付，真实 RV64/LA64 workload/capture 已集成验证：两架构各258条完成记录、已登记目标READ/WRITE各128。完整范围与失败反例见[本轮验收](../../records/bpf-observation-tools-184-188.md)；major/minor 的真实I/O分类仍由 #196 实施，不能用构造事件测试代替。

## 决定

| 问题 | 选定契约 |
|---|---|
| Tracepoint 或 kprobe | 追加 PulseOS 固定布局语义事件 `mm:page_fault`，ID 8、version 1；不依赖 Linux `do_page_fault` 符号或尚未实现的 kprobe。 |
| 捕获内容 | fault VA、访问 READ/WRITE/EXECUTE 位、origin privilege、进入 resolver 的 task/PID/TID、resolver 返回结果、开始/完成时间与墙钟耗时。 |
| 用户态与内核态 | `origin` 来自架构 trap 传入的 `is_user`，不能由 fault 地址推断。kernel 访问用户映射导致的 resolver 调用可被记录。 |
| 聚合 | 首版保留原始完成事件，由 host 按稳定 task ID/进程、地址范围、access、origin、outcome 聚合 count 和墙钟分布；过滤不改变原始记录。 |
| 热路径开销 | 无订阅时只走订阅检查，不读取观察时钟、不分配、不入队。有订阅时保存标量，resolver 返回后向既有有界队列复制 80 字节；worker 执行 BPF。实际开销仍须 baseline/loaded-detached/attached 实测。 |
| kmalloc/vmalloc | 不在此事件/第一阶段范围内。缺页 resolver 墙钟不是分配器延迟，不为统一工具而混用指标。 |

现有 trap 有真实 `is_user`、VA 和 access flags；`Process::handle_page_fault` 委托 `AddressSpaceLock::resolve_page_fault`，最终只返回 `AxResult<bool>`。driver 可经历 file/anon/COW 准备、completion 等待、重新提交与 TLB completion；这些来源没有通过最终 bool 返回为 Linux major/minor 分类。[trap](../../modules/process/src/trap.rs)、[process resolver](../../modules/process/src/lifecycle/runtime.rs)、[address-space coordinator](../../modules/process/src/aspace_lock.rs)、[fault driver](../../modules/mm/src/aspace.rs)。

Linux v6.12 的 `VM_FAULT_MAJOR` 指示存储读取，fault accounting 接收 resolver 返回码并对 retry/error 作专门处理。PulseOS 的 `FileMappingSource::get_shared_page_paddrs` 返回 page batch，没有相应的 I/O provenance。因此本版**全部 classification=Unknown**；不能根据地址是否 file-backed、延迟长短、事前缓存检查或“匿名页大概是 minor”来填分类。若后续添加精确分类，必须沿实际填页/等待路径传播事实并另测并发共享读取。[Linux mm_types.h](https://github.com/torvalds/linux/blob/v6.12/include/linux/mm_types.h#L1241)、[Linux fault accounting](https://github.com/torvalds/linux/blob/v6.12/mm/memory.c#L5912)、[PulseOS FileMappingSource](../../modules/mm/src/backend/file.rs)。

## 时间与结果

`start_ns` 在调用 `proc.handle_page_fault` 紧前取得；completion timestamp 在该调用返回后、信号和 fixup 后处理前取得。`elapsed_ns = completion_ns - start_ns` 包含等待、I/O、被调度出去的时间与观察点之间的小量仪器化开销，单位为 guest monotonic nanoseconds，不是 CPU time，也不是整个 trap 到 user-return 的时长。completion CPU 是返回时 CPU；origin task/PID/TID 在进入时冻结，因此跨 CPU 恢复不会被 worker 身份替代。[实现观察点](../../modules/process/src/trap.rs)、[有界发布器](../../modules/task/src/bpf_trace.rs)。

结果只描述 resolver 返回值：`Resolved=1` 对应 `Ok(true)`，`NotHandled=2` 对应 `Ok(false)`，`NoMemory=3` 对应 `Err(AxError::NoMemory)`，其余错误为 `ResolverError=4`。观察路径不改变这个原始结果；既有信号、内核 fixup、进程终止和返回分支继续消费它。完成事件不能表示“进程已成功恢复用户态”。先于 resolver 的 kernel fixup、没有 Thread 的 fault、提前进程退出或未返回的 panic 不产生虚假的 completion。[trap 分支](../../modules/process/src/trap.rs)。

时钟回退以 checked subtraction 检出；增加 `clock_errors`，不输出一个伪造的零时长。相同 clock tick 的起止可合法得到零。`started`、`completed` 是系统范围的、曾在订阅存在时进入观察的 resolver 数；即使订阅停止，已开始 token 返回时仍增加 completed。它们不是每 source/event 的 VM 次数，不能与 source `delivered` 硬相等；观察区间之间可能有在途 resolver，差值也不能直接命名为 aborted。捕获层继续报告缺失、unknown 和 partial。[计数与 token 生命周期](../../modules/task/src/bpf_trace.rs)。

## 固定 wire schema

所有整数显式小端，新增 `PageFaultContext::to_bytes()` 不读取 Rust struct padding。ID 1–7、已有 context 和保留的 100–105 均不重定义；新 context 仍在 80-byte queue/verifier 上限内。[schema/registry](../../crates/pulse_bpf_schema/src/lib.rs)。

| Offset | 字段 | 大小/含义 |
|---:|---|---|
| 0 | ContextCommon | 40：event=8/version=1；completion timestamp/CPU；origin PID/TID/task ID；reserved=0 |
| 40 | fault_address | u64，原始 fault VA |
| 48 | start_ns | u64，resolver 进入观察时间 |
| 56 | elapsed_ns | u64，完整 resolver 墙钟 |
| 64 | access | u32，Unknown=0；READ=1、WRITE=2、EXECUTE=4 的独立位集；不是直接暴露 MappingFlags |
| 68 | origin | u32，Kernel=1、User=2 |
| 72 | outcome | u32，Resolved=1、NotHandled=2、NoMemory=3、ResolverError=4 |
| 76 | classification | u32，Unknown=0；Minor=1/Major=2 预留，当前 producer 不产生它们 |

observer 在 entry 保留 observation generation。resolver 可能睡眠；不能在 completion 重新取新 generation，把旧 fault 送入随后开启的新采集。完成时只复制标量进 queue，队列满/递归的既有 trace counters 继续负责，source dispatch 再按 activation epoch 判断。`fault_started`、`fault_completed`、`fault_clock_errors` 作为系统 scoped diagnostics 向 capture 传播，不与 trace queue drops 或各 FD 计数求和。[queue/generation](../../modules/task/src/bpf_trace.rs)、[activation dispatch](../../modules/bpf/src/perf_event.rs)。

地址空间、Page Cache 和 TLB completion 的处理仍在原 coordinator 中；发布发生在 resolver 返回以后。不会为观察更改映射 ownership、重试、锁顺序或文件系统依赖方向，继续遵守 [ADR-0001](../adr/0001-mapped-page-lifecycle-protocol.md) 和 [ADR-0004](../adr/0004-axmm-file-mapping-source-boundary.md)。ADR-0004 的历史 qperf 描述不表示本事件恢复 qperf 依赖。

## 验证与后续运行门禁

已建立的公开接口测试：

- registry 发现 ID/name/version/size/逐字段 offset；旧 ID 与 deferred ID 语义保持；实际编码的字节值与固定预期核对。
- measured duration 的 100→350 得 250，origin/kernel 与地址不混淆，completion CPU 与 origin identity 分开；100→99 不伪造零。
- 实际 verifier 接受 tracepoint 程序读取全部 80 字节，通过公开 PerfEvent dispatch 运行解释器并输出实际 Perf Buffer record；79 字节截断拒绝；resolver entry 的旧 generation 在 disable/enable 后被取消，不能进入新 activation。该 host 测试构造 context，只证明规范化之前的 dispatch/transport，不冒充真实 fault 生产。

```bash
cargo test -p pulse_bpf_schema -p pulse_syscalls -- --test-threads=1
```

真实门禁应由 fault workload 验证：新匿名页首次访问、重复 resident 访问、写保护/COW 或不可访问地址的原有结果、kernel-origin user-copy fault，以及模式启用/禁用；同时按地址范围和 origin task 核对实际 buffer/capture 记录。OOM/fixup 若没有可控、安全的运行负载，只能保留独立结果映射测试和明确的覆盖缺口，不能把未执行场景标通过。完整 host/capture 集成应拒绝不一致的 completion/start/elapsed、未知必需版本和损坏记录，并记录实测开销及分层损失。

## 已接入的分析与 probe 证据协议

`FaultReport` 按稳定 task 身份（含观察时 PID/TID）、4-KiB 地址 reporting bin、access、origin、resolver outcome 和 classification 分组。这些 bin 不宣称是实际 PTE 页大小。每组保留 record count、未被 query 截断的 duration count/min/max/sum/mean 与以 2 的幂为包含式上界的纳秒 histogram；sum 使用 u128，避免多个长时长把 u64 总和回绕。未知 classification 有独立真实计数和 `unknown` 标签；未知 PID/TID 输出 null，零条测量的 min/max/mean 也为 null。capture partial 不会被局部筛选升级成完整。输入为 Query 已按 completion 选择的事件，start 早于窗口或 completion 达到右界的记录仍计数，但其完整 duration 不混入窗口内延迟分布，也不会裁剪成较短样本。[实现](../../crates/bpf-analyzer/src/fault.rs)、[公开测试](../../crates/bpf-analyzer/tests/fault_report_tests.rs)。

native fault probe 的同一 workload 每阶段执行 128 次：新建私有匿名两页，一页先读验证零填充再写；另一页先写、随后验证其它字节仍为零和写入读回，最后 munmap。若两页都先读，后续对 RW 映射的写可能不再触发 fault，因此明确区分两种首次访问。每次返回的地址只是已解除映射的数字证据，不能再次解引用。[workload](../../tests/bpf_sampling/fault_workload.rs)。

guest 归档 128 个真实 target 对及 PID/TID/read_hits/write_hits；Python log parser 与 Rust importer 分别核对 RAW 记录中 user-origin、相同 PID/TID、准确地址集合和 access 位对应的实际 hits，并要求读/写均有正例。相同 VA 在不同 iteration 被复用允许，漏项/重复 index/不一致 hit 或缺任一 fault GLOBAL counter 均拒绝。当前 probe 在 export buffer 丢记录时明确拒绝 hit 完整性验证；不会猜测丢弃记录对应哪种访问。Perf Buffer 的 transport loss 仍独立持久化并产生 partial。该协议已通过合成输入和实际 importer/analyzer 二进制测试；它们不是实际 guest fault 证据。[archive parser](../../tests/bpf_sampling/archive.py)、[Rust importer](../../crates/bpf-capture/examples/runtime_import.rs)、[协议测试](../../tests/bpf_sampling/test_fault_archive.py)。


## 真实负载的批量映射边界

首轮双架构运行保留在 `records/bpf185-rv-fault.log` / `bpf185-la-fault.log`。
原两相邻匿名页负载读命中为128/62、写命中为0；这是负载假设失败，不能算写缺页验证。
`Alloc::page_fault_alloc_request` 可在同一 VMA 内批量准备最多四页，因此第一处读缺页
已使下一页驻留。修正负载使用三页 mapping，中间页 mprotect(PROT_NONE) 分隔读写目标，
分别首先读第一页、首先写第三页。解除整块映射后每轮休眠1ms，为异步worker提供机会；
baseline/loaded-detached/attached三阶段使用完全相同的128轮paced负载。
实际RAW仍须逐条匹配目标地址/身份/访问位，不能从控制操作成功推导发生了fault。
内核原有批量映射行为没有因测试而取消；guest与host协议经修正后由真实QEMU补证，两架构READ/WRITE均各128，原失败日志保留。


架构没有提供访问方向时保留 access=Unknown(0)，例如 LoongArch PagePrivilegeIllegal
只给出 USER 属性。不能猜成 READ/WRITE，也不能因此丢掉合法 completion 或判整条 ring
损坏；报告单独计 unknown_access。未知位（7以外）仍拒绝。公开writer与实际Rust importer
回归覆盖这一路径，包括保留 NotHandled 结果且不增加已知读/写目标命中数。
