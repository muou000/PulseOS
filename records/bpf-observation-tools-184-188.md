# 调度、缺页与分析工具验收（#184/#185/#187/#188）

日期：2026-11-15。实现基于 `96a73a17`，延续 #190/#191 的真实生产、消费、诊断与构建来源链。
本轮交付调度延迟分析、缺页完成事件及报告、统一查询/时间线，以及解除实际运行门禁阻碍的
PCP 自检隔离修正。#187 的通用 recorder、真实栈/映射/标准文件导出和精确缺页分类仍由
#192–#196 承接，不能据本轮设计票或 partial capture 宣称 #180 全部完成。

契约分别见 [调度](../docs/research/scheduler-latency-contract.md)、
[缺页](../docs/research/page-fault-observation-contract.md)、
[控制](../docs/research/sampling-control-contract.md)、
[分析](../docs/research/capture-analysis-contract.md)。既有
`sampling-tools-design.md` 仍是历史草案，不被当作人工批准记录。

## 调度观测与真实配对

`sched` 模式加载六个 tracepoint 程序、48 个 per-CPU source 和八个共享 output sink。
每个 source 的 CPU/event/program 绑定与每个 program 的 `runs-errors` 分别核对，不能
交换两个程序的计数后凭总量相同通过。原始记录保留实际发布顺序和时间，不造 metadata/exit。

分析器以稳定 task ID 和 block sequence 跟踪 episode。有效唤醒延迟需要实际观察到
Block → Blocked switch-out → Wake → switch-in；分别报告 blocked wait 与 wake-to-switch。
跨 CPU/deferred enqueue/migration 不重置 wake 起点；重复、退出、缺前史、未闭合、时钟
倒退和不能证明顺序的同戳都保留诊断，不借将来的 switch 或会话结束时间补造延迟。
名称/身份按实际时间与同 CPU sequence 解析；跨 CPU 同戳冲突保留 unknown。

最终 RV64/LA64 的有效实例为 266/269。独立标准库脚本直接解码捕获字节，逐一核对真实
B/Blocked-switch-out/W/R、CPU、waker/source、sequence 与差值，以及 summary、每任务统计、
分位数和 histogram。先前原型的 258/268 实例同样经过核对，原路径与结果保留在调度契约中。

## 缺页完成事件与负载

追加 ID8、version1、80 字节 `mm:page_fault`，旧 IDs/布局不改。钩子紧贴原 resolver
调用，保存 entry 的身份/generation、fault VA、access/origin、resolver 结果和完成 CPU/time。
`elapsed_ns` 是含等待/抢占的 resolver 墙钟，不是 CPU 时间或整个异常到 user-return 的耗时。
源代码不改变原来的返回、signal/fixup 分支；无订阅不读取观察时钟，发布用既有有界队列。
`fault_started/completed/clock_errors` 是系统范围，不与 source/VM/sink 计数硬相等或相加。

访问方向无法由架构给出时是 Unknown(0)，例如 LoongArch PagePrivilegeIllegal 只有 USER
属性；capture、importer、guest consumer 与报告一致保留它。未知位仍拒绝，不能猜 READ/WRITE，
也不把这类合法 completion 当作损坏的 ring。major/minor 全部仍 Unknown，真实 I/O 分类是 #196。

实际负载先读一个匿名页、先写另一个页，验证零填充和写入后释放映射。最初的相邻两页
假设被双架构负例否决：read hits=128/62、write hits=0，因为匿名 fault 会批量准备邻页。
修正为三页 mapping，中间页 PROT_NONE 分隔；每轮结束休眠1ms，三阶段执行相同128轮。
host 按真实 RAW 中的 PID/TID、精确地址集合、origin 与访问位核对 target hits。

最终两架构均得到 258 条完成记录，其中登记的目标地址各有 128 次 READ 与 128 次 WRITE；
另外两条是同一采集进程、不在已登记 workload 目标集合的真实访问。所有记录逐条核对
`end-start==elapsed`，统计 count/min/max/sum/分组与 unknown；这些计数不是固定写入的 fixture。
异常 outcome、COW/冷热文件与 kernel-origin 的全面运行覆盖不由这组匿名页负载代替。
未返回的 resolver 或早期 fixup 不伪造完成事件。

## 查询、输出与格式约束

公开 Query 与 CLI 共用先关联后筛选的路径，支持 phase、半开时间窗、task/PID/TID、CPU、
故障地址范围和 user/kernel 模式。CPU 权限模式与 fault origin 是明确事实；没有模式的 legacy
记录不猜成 kernel。typed runtime phase 与旧 marker 要唯一闭合；两种表示同时存在时须一致。
实际 #191 capture 的 `attached_capture` 可被查询，baseline 没有采样则输出零记录。

JSON/table/folded/timeline 使用同一 Query。timeline 保留实际事件、schema/载荷、上下文与原端点，
另列显示裁剪范围；未闭合 end 保持 null，不产生假事件。CPU folded 只用真实 v2 IP，权重显式为
samples 或 period-ns；legacy v1 的 addr 保留为数据地址，IP/mode unavailable，不用它造帧。
空数据不写假权重1；兼容 `--offcpu` 只输出 observed blocked duration-ns，不转成次数。

`scheduled_time_ns` 只统计真实闭合 switch 区间。busy/idle 是 unknown/null，不能由 task_id==0、
名字或 PID0 推断，也不能把包含 IRQ 的任务驻留时间说成硬件利用率。同 CPU 已确认的时间
倒退不会排序成有效 on-CPU 区间；其他 CPU 与独立 software/fault 来源不会被误伤。
文件内自述 schema 不能改写已知 native event 的版本或 payload shape，未来版本明确拒绝。

三种文件输出先打开但不 truncate，使用实际 input/output 句柄的 dev/inode 检查 input alias
和多个 output 冲突，通过后才在同一句柄写入。实际 hardlink 负例验证输入 bytes 不变；不同的
既有报告仍可覆盖。Unix 文件身份不可用时文件输出明确拒绝，stdout 可用。

## 运行与门禁

原入口 `python3 tests/bpf_smoke/run.py gate` 已扩大为四模式×两架构，八组均通过。
实际命令按 AGENTS.md 的 8 GiB、8 CPU、snapshot disk、UTC RTC 运行，并保留匹配内核 ELF/
启动镜像的 provenance。原始路径见 `records/bpf184-188-final-runs.json`；[发布的运行包与逐文件SHA-256](../tests/bpf_sampling/evidence/184-188/README.md)包含最终报告与失败负载。

| 架构 | task 样本 | trace 记录 | mixed sched 记录 / 有效延迟 | fault 记录 / 目标读 / 目标写 |
|---|---:|---:|---:|---:|
| RV64 | 64 | 568 | 1436 / 266 | 258 / 128 / 128 |
| LA64 | 37 | 576 | 1678 / 269 | 258 / 128 / 128 |

八组共 4,875 条 RAW sample 与 normalized record 逐条同序匹配。采集保持真实 loss/unknown，
不因门禁 PASS 就宣称完整归因或 parity。采集内核仍来自已匹配的 enabled 构建，默认构建
不是采样支持的替代证据。baseline/loaded-detached/attached 的实际测量继续保存；1ms pacing
是负载的一部分，不用这些单次 QEMU 数据推导统计性性能阈值。

独立 oracle：[verify_observation_evidence.py](../tests/bpf_sampling/verify_observation_evidence.py)。
它仅用标准库 struct/zlib 解码，两套采集/分析库都不被用作断言依据；七项内存突变负例
包括坏 CRC、缺 trailer、重算 CRC 后把 IP 换成 addr、取消 Blocked switch-out、错 elapsed、
假 target hit、漏报 unknown access，全部被拒绝。它验证已报告实例的证据，不声称证明所有
可能 episode 都已经报告，也不替代实际 guest 或 build provenance。

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
make test 2>&1 | tail -30
cargo test -p bpf-capture -p bpf-analyzer -p pulse_bpf_schema -p pulse_syscalls -- --test-threads=1
cargo check -p bpf-capture --no-default-features
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
python3 tests/bpf_smoke/test_runner.py
python3 tests/bpf_sampling/verify_observation_evidence.py records/bpf184-188-final-runs.json
```

最终主机结果为 analyzer 84、capture 47、schema 23、syscall/runtime 229、clock 2；
Python sampling 48、兼容入口15，以及 no_std check 均通过。最后审查新增两个真实负例并修复：合法 access=0 被误拒绝，以及同 CPU 原序20→10被排序成
10ns有效区间。保留原始记录、unknown/clock诊断，未用饱和减法或默认零使其看起来成功。

## PCP 自检隔离与运行证据边界

整组门禁曾在 userspace 前因原 PCP 全局占用断言失败。完整诊断与原失败日志见
[pcp-boot-diagnosis.md](pcp-boot-diagnosis.md)及 [PCP证据包](../tests/pcp_boot/evidence/README.md)。
可抢占窗口、guard-only、main-first 逐变量验证；main-first 被 LA64 的 13/20 失败否决。
最终只让 Pulse opt-in 在 runtime 初始化屏障内检查，secondary 初始化后 IRQ-off 等待，primary
持 guard 完整检查后才发布 INITED。constructors 原 IRQ 环境保留，所有原 assert 未变。
真正隔离版 RV/LA 各20/20及原八组 BPF 门禁通过；没有改 allocator 生产算法或重试求绿。
这不声称多个全局快照成为原子事务，也不证明任意并发 allocator 工作负载无缺陷。

两份早期 paced fault 运行在 host 写报告时遇到变量覆盖 TypeError。修复后保留原始 guest log
并重放，同一 normalized capture SHA-256 完全一致；最终上表八组通过原 driver，不依赖该恢复。

## 仍需实现的地图目标

- #192：真实有界调用栈与诊断终止状态。
- #193：时间有效的映射、地址空间/任务身份、实际符号 artifact。
- #194：从真实 capture 导出 perf.data、函数热点/调用树/火焰图。
- #195：通用 guest bpf-record 的可指定目标、参数、时长和多模式生命周期；固定回归工具不冒充它。
- #196：从实际 I/O provenance 传播 major/minor，不能把 Unknown 当完成类型分析。

这些均已建立 #180 原生 sub-issue 和依赖。设计研究的 resolution 与运行功能交付分别记录，
#180 在这些目的地验收完成前保持开放。
