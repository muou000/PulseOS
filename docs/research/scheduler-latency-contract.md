# 调度唤醒延迟契约（#184）

日期：2026-11-15。调查基线 `96a73a176df502f38d652912cb6a3cc04a44c23c`。
这是 #180 当前实施采用的契约及主机分析实现，不表示维护者另行批准了一个新 ADR，
也不以设计完成替代双架构混合事件运行验收。

## 六项决策

| #184 问题 | 当前选择 | 为什么 |
|---|---|---|
| 事件选择 | 保持 PulseOS TaskBlock / TaskWake / SchedSwitch，联合 TaskMetadata / TaskExit / TaskEnqueue；不增加 Linux 同名假 ABI | 这些事件已包含稳定 task identity、block sequence、状态与入队原因；事件名称相似不表示 Linux context 相同 [P1][L1] |
| 配对状态 | host 按 `(task_id, block_sequence)` 保留 episode，任务进度另按 task_id 跟踪 | wake CPU、运行 CPU 可以不同，PID/TID 可以重用；per-CPU 或 PID-only 表不足以配对 [P1][P2] |
| 延迟计算 | kernel 只发布真实语义标量，host 在完整原始流上关联 | 保留丢失、重复、迁移和不确定顺序的证据；无需在热路径维护跨 CPU 配对 Map |
| 输出 | 先保存事件流和 #191 分层诊断，再提供实例、按 task 聚合及固定分箱 | 内核 histogram 不足以追溯 wake-before-switch；可选低开销 histogram 留待有界淘汰与跨 CPU 语义单独验证 |
| 边界 | 重复保留最早记录，前史不足/未闭合/同时间戳/退出/序号冲突显式报告 | 不用 `saturating_sub`、未来无关 switch 或 stop 时间填补“零/完整延迟” |
| 与 sched_trace 的关系 | 扩展 PulseOS 既有 `bpf-analyzer` 和统一采集模式；保留外部例子，未承诺直接兼容 | 固定 tgoskits 例子只读取三个 u64 的 raw-switch 参数并输出 switch 信息；它不提供本契约的 block/wake 前史 [T1] |

这里的 Module 是 scheduler reconstruction；其 Interface 是
`CaptureAnalyzer::scheduler_report()`、`SchedulerReport::compute(events, capture_incomplete)`
及 report 的 text/JSON 输出。调用者不需要维护 wake 表、running 表或重做跨 CPU 配对。
Query 的 Seam 位于重建之后：先保留所有前史形成实例，再按目标任务、CPU、时间范围选择
展示实例。`rebuild_summaries()` 仅重算筛选后数值，不能擦掉 capture 级诊断或提升完整性。

## 代码实际表达的时间边界

`blocked_resched` / `sleep_until` 在任务仍占用当前 CPU 时改变其状态并发布 TaskBlock。
随后另一个 CPU 可通过 Blocked→Ready 转换发布 TaskWake，而原 CPU 尚未保存完现场；
远端入队可能被推迟到旧现场保存完成后的 DeferredWake。因而 block、wake、enqueue、
真正切出和再次选中是不同边界。[P2][P3]

SchedSwitch 在底层 `switch_to` 之前发布，`prev == next` 路径不发事件。
所以末端是“调度器选中目标作为 next”的观察点，并非目标执行第一条指令的精确时刻；
该指标也不是 switch_to 函数耗时。[P2]

当前分析只将以下有序证据纳入 wake latency：

```text
TaskBlock(task, sequence) @ B
SchedSwitch(prev=task, prev_state=Blocked, CPU=block_cpu) @ O
TaskWake(target=task, same sequence) @ W
SchedSwitch(next=task) @ R

B < O < W < R
blocked_wait_ns = W - B
wake_to_switch_ns = R - W
```

`TaskState::Blocked` 的 PulseOS 值为 3，不是 Linux `prev_state` 的位掩码。[P4][L1]
例如 block@10、Blocked switch-out@20、wake@30、switch-in@50 产生两个独立的 20ns
区间。仅有 block@10、wake@30、switch-in@50 三条记录不能证明任务曾在 wake 前离开
CPU；当前契约把它记为 `unproven_blocked_switch_out`，不能凭三条记录虚构有效等待。
这是根据实际产生点作出的保守推断，不是声称所有被排除 episode 都没有调度延迟。

`blocked_wait_ns` 只代表 block 语义点到 wake 语义点，可能含实际 switch-out 前的时间，
不应命名为所有 off-CPU 时间。入队时间不替换 wake 起点；DeferredWake 延迟包含在
wake_to_switch 中。常规 Preempt/Yield 不含成功 TaskWake，不进入该直方图。

## 身份、顺序和未完成状态

- task identity 与阻塞序号为关联键；PID/TID/comm 为展示标签。TaskWake 的 common
  identity 属于 waker，不是 target。目标标签来自此前 TaskMetadata 或目标自己的
  TaskBlock common identity，绝不从未来改名回填。[P1][P3]
  target metadata 与 wake 同戳但来自不同 CPU 时，只保留所有可能顺序中一致的 PID/TID/comm
  字段，其余为 unknown；同 CPU 的已证明 sequence 先后仍选择对应旧/新身份。跨 CPU
  同戳的多条 metadata 若冲突，其 unknown 延续到后续观察，不能任选消费顺序的最后一条。
- 全流按时间关联，保留原始 sequence_index 以检查每 CPU 已观察 scheduler 语义记录的时间倒退；软件采样/其它 observer 的独立来源队列不充当此时序依据。
  同一任务的不同因果角色若具有相同 timestamp，记 ambiguous；消费序号只保证
  确定性展示，不用它为零时间差建立因果证明。
- 重复同 key block/wake 不改变最早端点，不重复产生 latency；新 generation 的 wake
  即使缺 block，也会使旧 pending generation 失效。零序号、回退序号、退出后同 task
  identity 再出现都明确诊断，不能继承旧 PID 的状态。
- wake 前缺实际 Blocked switch-out：保留可观察 block→wake，但不将之后无关 switch-in
  作为有效等待。当前 v1 缺少更精确的 wake-on-CPU 标记，因此不报告确定的
  `wake_without_switch=0ns`；这类边界是 ambiguous。
- 缺 block 前史是 left-censored；源停止时仍等待 wake/run 是 right-censored；有实际
  switch-in 却缺 wake 则是 missing-wake。退出、被更新序号替代、时钟问题分别保留原因。
  不把 capture stop 时间当作真实 wake 或 run。
- loss/unknown 不删除已观察的可配对实例，但不能提升为完整归因。当前 report 明确
  `scope=observed_intervals`、`coverage=unknown`、`complete_attribution=false`。
  诊断类别可能重叠，不得加总为“总丢失次数”。

## 输出和统计

`wake_latencies` 保存 task/sequence、wake 时身份、三个端点、两个区间、wake/run CPU、
waker/source、观察到的 enqueue/migration 次数。`blocked_waits` 保持独立，并带顺序
歧义标记；`unfinished` 使用可空端点和明确 reason，不补零。

总体和每 task 的统计包括 count、min/max、sum/mean、精确 nearest-rank p50/p95/p99，
以及 inclusive 上界为 1μs、10μs、100μs、1ms、10ms、100ms、1s、overflow 的固定分箱。
JSON 单位均为 ns；u128 `sum_ns` 编码为十进制字符串，避免宿主 JSON double 截断。
没有实例时 min/max/mean/percentile 为 null。分位数来自保留的实际实例，不是将 histogram
分位数伪称精确值，也不代表丢失区间中的总体分布。

接口没有导出任意 perf.data，也没有宣称 Aya/raw tracepoint 的外部工具已兼容。
ADR-0005 的 libbpf-bootstrap profile 具名兼容目标仍是另一个范围；本实现不悄然改写它。

## 验证与运行门禁

已落盘 `crates/bpf-analyzer/tests/scheduler_latency_tests.rs`，通过公开 capture writer /
reader / analyzer 运行 21 项语义回归；测试输入明确是合成语义 oracle，不是 guest 性能数据。
首先观察不存在公开入口的 RED；随后还用真实失败测试暴露零序号误分类、新 generation
未能废弃旧 wake、已经 resumed 的缺 wake 被误称未结束睡眠，并修复为 GREEN。

```bash
cargo test -p bpf-analyzer --test scheduler_latency_tests -- --test-threads=1
```

回归覆盖独立 20ns/20ns 预期、跨 CPU 与 DeferredWake、不重置端点、重复、抢占/yield、
退出与 PID 重用、双边 censored、同戳两种消费顺序、时钟倒退、时序 comm、精确分位数、
JSON 转义/null、过滤后 summary 重建、capture partial 传播，以及独立软件采样队列的交错不误判 scheduler 时钟；另有三项同戳身份回归验证跨 CPU unknown、同 CPU sequence 及冲突对后续 wake 的影响。

主 agent 已完成两次真实 mixed scheduler 采集，同时订阅 ID 1–6，6 个程序/48 个
source 共享 8 个输出 sink；已保存 #191 的 source/PROGRAM/sink/consumer 对账。此处
使用公开 CLI 读取其实际 capture，得到：

| 架构 / run | 原始记录 | 有效 wake interval | p50 / p99（ns） | left / right censored |
|---|---:|---:|---:|---:|
| RV64 `riscv64-sched-20261115-011920-0zu9792k` | 1367 | 258 | 58,500 / 515,300 | 10 / 9 |
| LA64 `loongarch64-sched-20261115-011920-odkpeu46` | 1668 | 268 | 24,280 / 169,410 | 10 / 9 |

命令为 `cargo run -p bpf-analyzer -- <run>/capture.pbcapture --sched-report --json`。
完整输出保存于 `records/bpf184-rv-scheduler.json` 和 `records/bpf184-la-scheduler.json`。
另从 capture 字节独立解码 normalized records，对全部 258/268 个实例逐一确认实际
TaskBlock、同 CPU 的 Blocked switch-out、同 sequence 的 TaskWake 和对应 run CPU
的 SchedSwitch 四个端点；没有用报告的统计数字替代原始数据存在性证明。

两份 capture SHA-256 分别为：

- RV64 `36131aeaa19fed08085c1085b0a716bd0929456a2f5e3ac7c391992b5a8494f4`。
- LA64 `1def58cdc5f6b1b8045bf742cb1481c709fb0953a8eae1c2647f8a122faaed0d`。

例如 LA 的 task52 / sequence262 实际从 wake CPU6 到 run CPU1，保留 enqueue=2、
migration=1，wake latency 为 80,520ns。两份流均无观察到的重复、时间倒退或同戳歧义；
但 source 的边界及 capture unknown/loss 仍保留为 partial，`complete_attribution=false`。
这些运行基于已归档的 #191 enabled 内核，证明混合调度输入与主机配对，不证明新缺页
schema 的内核构建或完整 CPU callchain。单独采 switch 或 wake 的旧运行不能代替它。
低开销、实时或全任务完整覆盖承诺需要另行证据。

## 一手依据

- [P1] [PulseOS schema 和 identity/sequence 字段](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/pulse_bpf_schema/src/lib.rs)。
- [P2] [实际 block/wake/switch/deferred-wake 产生位置](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/modules/axtask/src/run_queue.rs)。
- [P3] [context 现场身份、时钟及队列发布](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/modules/axtask/src/bpf_trace.rs)。
- [P4] [TaskState / TaskId / block_sequence](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/modules/axtask/src/task.rs)。
- [L1] [Linux v6.12 sched tracepoint 定义](https://github.com/torvalds/linux/blob/v6.12/include/trace/events/sched.h)（2026-11-15 查阅）；仅用于比较 wake/switch 状态和布局，未当作 PulseOS ABI。
- [T1] [固定 tgoskits sched_trace eBPF 源码](https://github.com/rcore-os/tgoskits/blob/3686ff71f00072fdf13edc3785c06a790899d47b/apps/starry/ebpf/sched_trace/sched_trace-ebpf/src/main.rs)（2026-11-15 查阅）。


最终与本轮fault/PCP隔离一起运行的完整八组门禁全部通过；新RV/LA mixed capture分别1436/1678条，
有效wake latency为266/269。独立oracle逐条核对原始数据，见[最终验收](../../records/bpf-observation-tools-184-188.md)
及 `records/bpf184-188-final-runs.json`。早先258/268的记录保持为原型证据，不用新数字改写旧文件。
