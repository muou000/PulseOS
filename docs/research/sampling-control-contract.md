# 统一采集控制契约（#187）

日期：2026-11-15。状态：根据继续推进 #180 的授权选定的实现契约；不把设计视为通用 recorder 已交付。基线 `96a73a176df502f38d652912cb6a3cc04a44c23c` 已有可信的单模式真实采集回归，本轮混合 scheduler 原型进一步验证多程序/多 CPU 输出对账。通用命令、任意目标/时长及多模式协调仍须单独实现和通过下述门禁。

## 六项决策

| #187 问题 | 选定契约 |
|---|---|
| 命令行 | guest `bpf-record` 是生产采集入口；host 部署/回归命令调用它。事件、CPU/TID、duration、period/frequency、buffer 大小、输出路径均显式；无效组合在启用前失败。 |
| 统一模式 | CPU-clock、单线程 task-clock、调度完整事件组、fault completion 是事件计划。所有组复用一个会话生命周期和输出；CPU 与 task-clock 的同类型并发源必须有不可混淆的实例绑定。 |
| 多程序 | 先准备所有 sinks/maps，再 load 和 attach 全部程序且保持 disabled；全部就绪才 enable。任何准备失败逆序释放，不能把部分事件计划标成功。 |
| 原始格式 | BPF capture 为默认且权威原始产物，保存全部 schema/config/identity/loss。perf.data 由 host 从该产物派生，不在 guest 热路径二次符号化或写一个缺关键事实的标准文件。 |
| 实时模式 | 第一阶段离线 finalized/partial 文件；运行中可输出显式 provisional 状态。实时 top/GUI 后置，不让未终结窗口冒充 finalized 会话。 |
| 既有工具 | 现有 syscall histogram/sched_trace 示例保留其原指标和兼容范围；回归 harness 不冒充通用命令。旧固定 capture/伪 parity 已被 #191 移出真实运行入口。 |

既有材料：[capture/真实回归](../../records/bpf-runtime-capture-191.md)、[#184 调度契约](scheduler-latency-contract.md)、[#185 fault 契约](page-fault-observation-contract.md)、[#188 分析契约](capture-analysis-contract.md)、[能力与移植边界](sampling-capabilities-design.md)。ADR-0005 要求未修改的具名上游 C profile，与本地图当前自有 fixed-context 入口并非同一个交付；本工具不声称满足该历史兼容承诺。

## 命令与参数语义

候选命令形状：

```text
bpf-record --events cpu --cpus all --period-ns 10000000 --duration-ms 1000 --output session.pbcap
bpf-record --events task --tid 123 --frequency 99 --duration-ms 1000 --output session.pbcap
bpf-record --events sched,fault --cpus 0,1 --duration-ms 1000 --output session.pbcap
```

这里 `--tid` 是当前实现所绑定的稳定线程对象的可发现数字 TID，不把 kernel `PerfEventScope::Task { pid }` 的字段名误解成整个进程树。PID/TID 重用、exec 或目标退出必须保留绑定身份和结果。第一阶段不默认 fork inheritance；未支持的 process-wide/children 选择在准备阶段拒绝，不能静默退成一个线程。主机过滤属于 Query，不改变记录中原来的采集范围。

软件时钟原生参数为非零 period ns。若提供 frequency 语法，由 planner 用向上取整的 `1_000_000_000 / Hz` 转换，保存 requested Hz、effective nominal period 和转换方式；实际可达到的频率仍受 IRQ 观察粒度、worker 与 skipped/loss 限制。过高频率不能无声钳位后宣称达到请求值。硬件 PMU 或 exclude 选项不可用时明确报错；只有显式 `--allow-fallback` 才能改用已探测到的能力，并保存 requested/effective/reason。

CPU 列表必须根据真实在线 CPU/能力查询展开，不能从“测试虚拟机常用八核”推导生产环境在线集合。为空、重复、离线、超界、无能力查询结果均有明确错误。一次 scope=all 的声明必须包含实际展开结果。buffer pages 使用 transport 的合法值并设置会话总资源上限；溢出保留真实 loss，不无限增长掩盖背压。

有限 duration 与显式 stop/SIGINT 都走相同 stopping 协议；write/stop 错误输出 partial 状态。第一阶段不默认把“采集一个既有目标”变为启动子命令、追踪全部后代的另一语义。是否添加 launch 模式须配套初始 exec/映射身份门禁。

## 一个会话的公开 Interface

对调用方暴露 `SessionPlan -> prepare -> start -> stop -> CaptureResult`；参数检查、资源回滚、程序/源绑定、drain 与计数核对收在同一模块。CLI 不分别手工管理数十个 FD，也不复制一套 writer/transport 解析器。测试通过这条 Interface 或实际 CLI 注入无效配置、控制 stop 和读取结果。

状态为 `prepared -> attached_disabled -> running -> stopping -> finalized | partial | failed`。

1. 探测并冻结能力、目标 identity、计划与资源预算；建立实际 build/artifact 身份和 session ID。required capability/identity 缺失时明确 unknown 或拒绝相应声明。
2. 建立每 CPU BPF_OUTPUT sink 与共享 output Map，验证类型和 CPU 槽位；#190 的 source-as-sink/错误 CPU 绑定拒绝继续适用。
3. load/attach 各程序，记录每个源的 type/config、program/map/link/perf object ID、scope、period 和 schema。失败回滚已取得资源，保留实际失败阶段，不能生成“全计划完整”的 trailer。
4. 收集初始目标/映射/符号身份快照与其有效边界，再顺序 enable；记录每个源的 enable-before/after，不能假装 N 个控制操作原子开始。
5. 按公开 transport 内存序消费，把完整 RAW 记录复制后再释放 tail。记录源类型与实例须显式绑定，禁止按 payload 长度或数值猜格式。
6. stop 时 disable 所有源并记录各窗口，等待每个源已接受 VM invocation 的 inflight=0，再最终 drain。fault resolver 还可能在 stop 后返回旧 entry epoch，不能把 VM inflight=0 当作全系统 resolver 已返回。旧 epoch 不进入新 activation；相关 counters 记录其系统/事件作用域。
7. 对 source、program、sink、consumer 的各层事实分别核对，写最终完整性 trailer。先释放 link/source，再释放程序/Map/sink；dup 与用户提前关闭保持真实所有权，错误路径不能泄漏或留下继续生产的 subscription。

`CaptureResult` 区分控制流程成功、产物存在、observed data quality 和完整归因能力。一个含真实 loss/unknown 的 partial 文件可以是成功结束的采集结果，不会自动取得“完整 off-CPU/调用链/符号”资格。

## 记录类型和源实例

BPF_OUTPUT 的 RAW payload 是程序选择的输出，不是一个天然带所有源配置的 perf.data SAMPLE。软件 v2 的 64 字节 context 与 TaskEnqueue 的 64 字节 context 可碰撞；仅靠长度不能判别。当前单模式回归通过显式 mode 选择格式；本轮 sched 组可以根据同一 tracepoint context 中的 ID/version 与已验证的配置组判别。

通用多模式会话应使用明确版本/长度/record-kind/logical-source 的输出 envelope，或内核提供等价的源实例绑定；reader 只接受已声明的绑定。不能把 mode-specific 测试中的推断直接泛化成任意混合流。CPU_CLOCK 与 TASK_CLOCK、不同 period 的相同软件 record 类型也需要独立实例；不按 CPU 或 period 猜 `PERF_SAMPLE_IDENTIFIER`。具体 wire 扩展与 #182 callchain / #188 exporter 的数据演进一起审查，旧 capture 保持可读。

完整计划是版本化列表，而非一个“代表全部”的 program_id。capture v2 的 typed diagnostics/evidence 可承载当前显式 source 列表；legacy SessionConfig 的单值只作为兼容投影，不作为多程序选择真相。每个源的 enabled 窗口、schema、程序实例、CPU/稳定 task 绑定必须可逐项核对。

## 多程序原型证据与测试门禁

`tests/bpf_sampling/run.py --mode sched --archive` 的原型配置六个 tracepoint 程序（IDs 1–6）、48 个 per-CPU 源和八个共享 sinks，统一 stop/drain。48 个源逐项绑定对应 program，48 个 CPU/event 槽位必须完整；每个 program 的 runs-errors 单独与其 source delivered 对账，程序间交换计数不能靠总量相同过关。

该原型已在 #191 已归档的 enabled kernels 上取得实际 mixed capture：RV64 1,367 条、LA64 1,668 条。没有产生 metadata/exit 的已存在任务负载保留实际零，不伪造生命周期。真实控制/消费行为证明一个可行实现方向；它仍使用固定回归负载/时长，不能写成通用 guest recorder 已交付。

后续通用命令的独立验收：

- 真实 CLI 无参数/错误 CPU/非法 frequency/period/未支持的 scope 在 enable 前失败；请求/有效计划可读，不能悄悄更改类型。
- 第二程序 load/attach 失败时释放首个程序及已准备资源；FD/订阅/buffer 数回到可查证的原状态，且无继续生产。
- 同 CPU 两个软件实例、多种 schema 的混合输出保持可追溯实例；未知 envelope、错长度、损坏、零消费者与缺 trailer 失败。
- duration、显式 stop、dup/close、目标退出和在途 fault 分别验证；来源不明确或会话缺记录保持 partial。
- RV64/LA64 实际 guest 对既有 CPU/sched/fault 目标采集，产物被现有 analyzer 和后续 perf exporter 消费；不依赖固定五记录或 hard-coded hash。
- baseline、loaded-detached、attached 的实测 wall/throughput/资源与分层 loss 保留，不能用“能生成文件”代替功能与开销证据。

通用控制器实施由 [#195](https://github.com/muou000/PulseOS/issues/195) 承接；#187 的设计部分与本轮多程序原型有独立证据，#180 在通用控制器运行验收之前继续开放。
