# BPF capture 分析与标准工具互操作契约（#188）

日期：2026-11-15。状态：**选定的实现契约**，用于落实 #188 的六项决策与后续验收；不是“所有分析功能已实现”的声明。审计基线为 `96a73a176df502f38d652912cb6a3cc04a44c23c`。本文按用户继续 #180 全地图的授权确定实现方向，不把较早草案中的待选方案当成人工批准记录。保留 [#181 的格式研究](perf-data-minimal-subset.md)、[#182 的栈捕获设计](stack-capture-design.md) 和 [#183/#186 的能力边界](sampling-capabilities-design.md) 作为相互约束的依据。

## 1. 六项决策

| #188 的问题 | 选定契约 | 验收边界 |
| --- | --- | --- |
| 输入格式 | `bpf-analyzer` 直接读取版本化 BPF capture；外来 perf.data 交给 Linux perf。CPU perf.data 是从 capture 派生的互操作产物。 | 不新增一个只读少数字段却宣称通用兼容的 perf.data reader；原 capture 始终是记录、配置和诊断来源。 |
| 分析模式 | 自有分析器提供事件表、原始 IP 热点、调度/缺页语义统计和 timeline JSON；具备真实链与符号身份后提供函数热点、调用树和 CPU 火焰图。 | 原始 IP、已确认栈前缀、完整受支持 ABI 链是不同能力；单 IP 不能补成完整栈。 |
| 符号解析 | 使用实际 ELF/debug artifact 与采样时生效的内核/用户映射和生命周期。先由 exporter 校验 artifact 身份，再交给固定版本 perf 进行符号/调用树展示。 | 不能使用主机同名文件、采集结束时的一份 maps 或仅有 build-id 的字符串冒充实际符号内容。 |
| 过滤与聚合 | 所有输出共用一个 Query 和同一个已关联的 AnalysisResult；先解析历史身份/映射/事件关系，再筛选展示和聚合。 | `--phase`、`--tid`、CPU 与时间过滤必须实际作用于 CLI table、JSON、folded 和 export，不能只实现一个未接入 CLI 的内部过滤器。 |
| 输出格式 | 第一阶段为终端文本、JSON、明确单位的 folded；SVG 通过固定版本 FlameGraph 渲染，调用树由 perf report 提供。HTML 交互界面后置。 | 不在运行时下载工具；产物记录 query、单位、版本、原 capture hash、未知与丢失状态。HTML 后置不削减地图要求的 CPU 火焰图交付。 |
| Linux perf 兼容 | 采用 #181 的小端、可 seek、未压缩 PERFILE2 子集；用未修改的 perf report/script 验收。 | 语法可读、函数符号正确、真实调用链正确分别验收。自有调度/缺页事件首版留在 capture/JSON，不伪装成 CPU SAMPLE。 |

Linux v6.12 的 perf 文档提供 `--vmlinux`、`--symfs`、call graph、period 列以及 script 字段选择；这些是外部消费者接口，不证明 PulseOS 已提供对应输入。本文沿用固定 v6.12 格式基线，并单独记录实际执行的 perf 版本。[L1][L2][L3]

## 2. 当前已实现与实际缺口

以下描述固定审计基线，不把正在开发的工作树改动算成已有交付：

| 基线能力 | 已有证据 | 尚不能推出 |
| --- | --- | --- |
| 真实 CPU/task-clock 与调度事件采集 | #190/#191 的双架构原始 ring 数据、capture、诊断与故障证据 | 完整调用栈、函数符号、完整 off-CPU 归因或 perf.data 已交付 |
| 软件 v2 记录 | normalized event `0x1001` 的 period、独立 addr/IP、mode，及 common 时间/CPU/PID/TID/task ID | 返回地址链、展开终止原因、映射或地址空间代际 |
| capture 格式 2 | typed optional diagnostics、匹配构建/artifact 身份、分层计数和实际测量 | diagnostics 中有 ELF hash 就能确定任意时刻用户 IP 所属的 ELF/映射 |
| 分析器输出 | table、JSON、现有统计与 folded；runtime v2 不允许完整归因声明 | 所有 renderer 已使用一致 Query，或 folded 已是函数调用栈 |
| #181 fixture | 三架构合成文件通过固定 perf reader、符号和 FlameGraph 实验 | fixture 中的预展开地址链来自 PulseOS 实际栈捕获 |

上述事实可直接对照 [record/schema](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-capture/src/record.rs)、[runtime diagnostics](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-capture/src/diagnostics.rs)、[analyzer](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-analyzer/src/analyzer.rs) 与 [#191 验收记录](../../records/bpf-runtime-capture-191.md)。

基线存在三处必须修复的可观察问题：

1. [`main.rs`](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-analyzer/src/main.rs) 的 `--phase` 仅用于 table；JSON 和两个 folded 路径仍分析整个会话。
2. [`event.rs`](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-analyzer/src/event.rs) 先遍历全部 TaskMetadata 建最终 comm 表，再回填历史事件，因此后来的名称可以错误地出现在早期样本上。
3. [`emission.rs`](https://github.com/muou000/PulseOS/blob/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-analyzer/src/emission.rs) 的 on-CPU folded 在有样本时累加次数，无样本时改用调度区间纳秒；off-CPU 还可退回 block 次数。空输出又生成权重 1 的占位行。这些行为会混淆数据单位和没有证据的情况。

## 3. Query 与关联语义

分析 Module 的公开 Interface 是 `capture + Query -> AnalysisResult`。CLI 只解析 Query 和选择 renderer；renderer 不重新从原 capture 计算另一套全量统计。保留原有快捷选项可以减少迁移成本，但同一次调用请求多种输出时必须共享同一个结果。

Query 至少包含：事件/指标类型、稳定 task ID、PID/TID、CPU、时间范围、phase、kernel/user mode、缺页地址范围，以及所请求的权重。组合条件取交集。`--from-ns`/`--to-ns` 使用 capture 声明的时钟与纳秒值，时间窗口为半开区间 `[from,to)`；非法范围、不可解析数值、未知 phase 或无法唯一配对的同名 phase 明确报错，不静默忽略过滤。legacy `--phase` 行为变更需在 CLI 文档和回归中显式说明。

Phase 解析同时支持 `RuntimeDiagnostics.phases` 的 typed measurement 窗口与旧 `PhaseMarker` 事件。只存在一个来源时，必须是该来源唯一合法的闭合定义；两者均有同名定义时，必须各自唯一闭合且 start/stop 完全一致，否则报错，不随机优先使用一方。存在但不完整的 marker 也不会被 typed metadata 悄悄覆盖。Query JSON 的 `phase_source` 标明 `runtime_diagnostics`、`stream_markers` 或 `both`。#191 的 baseline/loaded-detached 窗口可能位于实际 records 采集之前；合法窗口无记录应返回 empty，而非 missing phase。

处理顺序固定为：

1. 校验 capture 完整性、schema 和诊断；未知不是零。
2. 保留源事件顺序，按时钟重建必要前史：TaskMetadata/exec/映射、每 CPU running 状态、pending block/wake、退出/身份代际。
3. 形成带主体、单位、因果依据与质量状态的样本/区间；跨 CPU 同 timestamp 的消费顺序不作为已证明的因果顺序。
4. 在关联结果上应用 Query，形成 selected 数据及必要 context 引用；计算统计，再由所有 renderer 展示。

过滤对象必须按事件含义确定。wake 的主体是 target task，不能用 common 中的 waker PID/TID筛掉它；switch 同时涉及 prev/next；wake latency 的运行 CPU 取 switch-in CPU，而不是唤醒源 CPU。跨 CPU 前史即使不在展示 CPU 中也参与配对。若 table 为解释关联而展示范围外前史，必须标为 context，不计入 selected records 或样本数。

任务名和 PID/TID 映射按事件发生时解析；后来的 rename 不回写旧样本。身份缺失保持 unknown，不能从另一 task 的最新元数据借用。匹配用稳定 task identity，PID/TID 只是附带的显示/过滤信息；exec 或 PID 重用不能继承旧地址空间的映射历史。

身份查询使用实际产生关联端点的事件 CPU 和 publication sequence：on-CPU 起点取真实 switch-in，unfinished wake 取真实首次 wake，无 wake 时才取 block。不能用 `usize::MAX` 或借用 block CPU 推定 wake 时刻的身份。同 timestamp 跨 CPU 冲突字段在后续时间仍保持 unknown，直到新的有序事实恢复它；消费顺序不建立“最后一次 metadata”的事实。

原始样本按自身 timestamp 选择。延迟直方图和分位数默认只纳入两端都在 Query 窗口内、已闭合且因果有效的完整实例。重建得到但跨越查询边界的区间可用于 timeline 裁剪，保留原始端点并标 `query_clipped`；缺观测端点另标 left/right-censored。不能把裁剪后的时长作为原始延迟样本，也不能用会话 stop 虚构一次 switch-in。

即使窗口内没有新原始事件，也可能存在从此前延续的 observed pending episode。RightCensored 实例按其当前阶段起点（已有 wake 时为 wake，否则为 block）至 capture stop 的观测范围与窗口相交来保留；窗口切断这段观测时进入 query clipped/censored 计数。capture stop 只限制可陈述的观测范围，不是伪造的 switch-in，不生成完成延迟；查询在 capture stop 之后不能无限延长 pending 事实。

capture 质量与 Query 覆盖度分别报告。无法定位影响范围的会话损失不会因选了一个小窗口而消失；过滤掉 loss 行不等于得到无损会话。JSON 至少保存规范化 Query、selected/context 数、指标单位、有效/未配对/歧义/截断计数、原 capture 状态与 Query 限制。

## 4. 指标、单位与输出

| 报告/产物 | 权重与单位 | 明确禁止 |
| --- | --- | --- |
| CPU IP/函数热点 | 显式 `samples`（次数）或实际样本 `period`；软件 clock 的 period 单位为 ns | 把频率 Hz 当每样本 period；把请求期望次数当实际样本；把不同事件单位混加 |
| CPU 调用树/火焰图 | 与所选 CPU 热点一致，根到叶折叠；保留 kernel/user 分域和 unwind 状态 | 缺链时复制 IP 构造多层栈；把未解析地址当作已知函数 |
| 调度运行区间 | `duration_ns`，来自可验证的 switch 区间 | 没有 CPU 样本时在相同 CPU-sample 输出名下自动切换成纳秒区间 |
| blocked/wake-to-switch | 分别统计各自的墙钟 ns，采用 #184 的主体与边界契约 | 将 block→wake、wake→switch、switch 函数耗时统称为同一个延迟 |
| fault completion | count 与 resolver wall-ns 分开；major/minor unknown 保持独立类别 | 从耗时推断 major/minor；把 fault duration 当 allocator latency |

CPU 的 `scheduled_time_ns` 仅累加实际匹配 switch-in/switch-out 的已闭合观察区间；最后一个非 switch 事件或会话 stop 不能替代 switch-out。公共 `CpuStatistics.busy_time_ns` / `idle_time_ns` 为 `Option`，当前始终 None，JSON 为 null 并说明 unsupported。不能用 task ID 是否为零、PID 0 或名称（包括普通任务也可叫 idle）猜运行类别。旧 task 级 `on_cpu_time_ns` 保留兼容字段名，含义同样只是观察到的 closed scheduled intervals。

在按 timestamp 排序前，按原 publication sequence 检查每 CPU 的 scheduler semantic queue（metadata/block/wake/switch/exit/enqueue）。该队列一旦出现时钟倒退，当前保守地排除该 CPU 的全部 on-CPU 区间和相应时长，仍保留原始事件与 capture 级 scheduler clock 诊断；不能把逆序端点排序成有效区间或 timeline 的 `observed_closed`。其他 CPU 的有效区间不受影响；独立 software/perf、fault 或 phase 来源的合并顺序不用于判定 scheduler 时钟倒退。Query/CLI 与旧公共 statistics 接口遵守同一规则。

后续 [#193](https://github.com/muou000/PulseOS/issues/193) 将从 producer 记录实际任务类别/身份事实。即使知道 `Task.is_idle`，也只知道 idle 任务被选中，期间仍可能执行 IRQ；这不证明硬件 idle residency，不能自动把该区间换算成精确 busy/idle 利用率。sample 的 user/kernel privilege 与任务类别也不是同一事实。

旧软件样本 `0x1000` / schema v1 的第二个 u64 保持 `addr` 数据地址语义，**没有 IP 或 mode**。分析器继续读取并计数这些观察，table/timeline 保留 addr，IP/mode 明示 unavailable/null；它们不进入 IP 热点或 CPU folded。只有 v2 的独立 `ip` 才用于该输出。JSON 分别报告 `software_samples_with_ip` / `software_samples_without_ip`，避免将无 IP 的记录丢弃或冒充 profile frames；v1 字节与格式不改变。

同一图只能有一个权重定义；名称、JSON metadata、folded/图标题与 FlameGraph countname 必须一致。空查询返回零条真实数据与明确的 no-data 状态，folded 文件可以为空；不得写一个 weight=1 的假样本使绘图成功。partial 数据可以输出并保留原因，不能由成功写文件推导完整性。当前 v2 的保守归因禁令只有在独立的语义覆盖证明及测试落地后才可细化。[P1][L1][L2]

终端文本和 JSON 是自有稳定接口。timeline JSON 记录原始时间、CPU、task、关联键、已知端点和质量状态；不为动态图假造中间事件。HTML 界面不是当前第一阶段必需项。SVG 的生成需要调用显式配置的工具路径并记录版本；缺外部工具时说明哪一层未完成，不把 folded 文件改名为 SVG。

## 5. 符号化与 CPU exporter 的最小数据契约

下面列出实现所需的语义字段，不在本文擅自分配新的 wire ID 或偏移。扩展须走版本化 schema，旧 capture 仍可读取，未知必需记录不能静默丢弃。

| 必需事实 | capture 必须保存什么 | 当前 v2 的缺口 |
| --- | --- | --- |
| 事件实例归属 | logical source/instance ID，实例的 event type、clock、scope、effective period/单位与有效窗口 | `event_id=0x1001` 只是记录类型；同 CPU 上多个 CPU/task-clock 实例不能仅按 CPU 或 period 猜归属 |
| 采样现场与链 | 可靠 sampled IP/mode、每域有序 IP 前缀、终止状态、深度/字节预算、unwind 方法及受支持 ABI | 只有单 IP/mode；没有 callchain 或 unwind 失败状态 |
| 地址空间身份 | 与 task/PID/TID 关联的 address-space identity 和 exec generation | 稳定 task ID 不等于完整地址空间生命周期 |
| 映射历史 | 生效/失效时刻或明确 epoch、start/len、文件字节 pgoff、权限、对象身份；初始快照与动态变更的排序/覆盖证明 | 没有足够的 typed MMAP/exec/unmap/fork 历史；终态 maps 不能补回过去 |
| 内核符号定位 | 实际 kernel ELF/debug hash、可用时的真实 build-id、运行时 text 范围/重定位及参考符号事实 | ELF hash 已有，但不自动描述 runtime kernel mapping/relocation |
| 用户 artifact | 对象在目标机的标识、实际 ELF/debug SHA-256、可用时的真实 build-id、target arch，与映射对象的绑定 | workload ELF 的已知 hash 不代表系统中所有用户映射都已匹配 |
| 任务生命周期 | 发生时的 fork/exec/exit/rename，及初始存在任务的快照范围 | TaskMetadata/TaskExit 不足以替代全部地址空间/继承事件 |

如果一个受限单事件会话能根据经过验证的配置唯一确定实例，可以先生成实例绑定；多实例无法区分时必须拒绝导出该样本或保留明确 unresolved，不能猜测。由另一个工具取得的映射或身份事实只有在时钟、有效窗口和 artifact 校验通过后才能导入，并应嵌入 capture，使分析结果无需暗中依赖一份可变外部状态。

符号匹配以实际文件内容和记录的对象身份为依据。路径是名称，不是身份证明；同名不同 hash 的 ELF 必须拒绝。若 ELF 有 build-id，导出该真实值；没有时标明 absent，不能把任意截取的 SHA-256 当成 ELF 本来的 GNU build-id。严格符号交付模式需有可验证的 artifact bundle；缺少所需身份时，原始 IP 查看可用，但不得通过完整函数/调用链门禁。[P2][L3]

用户运行时地址需要按生效映射的 `addr/len/pgoff` 与对应 ELF PT_LOAD 关系解释，不能统一用 IP 减文件起始地址。内核采用 #181 已验证的参考符号/重定位约定，不能把内核 ELF 路径随意写成普通模块 MMAP。exec、fork、映射覆盖、PID 重用的测试必须独立存在；无法证明动态覆盖的旧 capture 不应追溯升级为可信符号化数据。[P2]

## 6. perf.data 与原 capture 的关系

选用 #181 的 PERFILE2 子集：显式小端、已定义的 attr/instance IDs、SAMPLE 的真实 IP/TID/TIME/CPU/PERIOD，以及已捕获时才出现的 CALLCHAIN；所需 COMM/MMAP/FORK/EXIT、ARCH 和实际 build-id 等 metadata 同步输出。非 SAMPLE 的 sample_id_all 布局按固定 Linux reader 契约编码，不把 Perf Buffer RAW 直接改文件头当作 perf.data。[P2][L3]

提供两种明确能力：

- `ip-only` 互操作可保留可靠 IP，缺链应标 unavailable；它不满足地图中的调用树/调用栈火焰图交付。
- `callchain` 互操作要求实际捕获的地址链、kernel/user context markers、匹配 artifact 与时序映射。前缀截断必须保留原因，不能把 nr 的合法性当作完整链证明。

导出后的 perf.data 无法完整表示所有 PulseOS diagnostics。伴随 export manifest 必须包含原 capture SHA-256、规范化 Query、source/导出样本数量与权重、unknown/stack 状态、保留或拒绝的数据范围、损失口径、artifact manifest hash、exporter 与 perf/FlameGraph 版本。原 capture 不被替换或删除。

只有能确证的导出样本损失才映射为相应标准 LOST；source skipped、栈截断、system queue 计数和 transport loss 不能相加成一个虚构的 sample lost。`perf report` 页头也不能代替原始 LOST 和 capture 诊断核对；#181 已记录 LOST 与 LOST_SAMPLES 展示口径不同的实验。[P2]

## 7. 测试先行与独立 oracle

测试进入公开库 Interface、实际 CLI 与外部消费者；不以未接入的 helper 测试代替用户行为。

| Seam / 场景 | 独立预期 | 不能只用什么作为成功依据 |
| --- | --- | --- |
| 实际 CLI 组合 `--phase --tid --from-ns --to-ns` | 用窗口外、另一 TID 和边界时刻的记录构造可手算样本；table、JSON、folded 的选中数与权重一致；全会话诊断仍保留 | 只测试 Query 内部 predicate，或仅看 table |
| Metadata 时序 | rename 前后样本分别使用当时名称；新 task 重用 PID 不继承旧状态 | 最终名称快照回填 |
| 跨 CPU 前史 | wake 在 CPU0、switch-in 在 CPU1，筛 CPU1 仍保留关联；窗口裁剪不改变原始延迟 | 先按 CPU/PID 删原事件后计算 |
| 权重 | 两条 period=10/30 的样本：samples=2，period=40；普通调度区间不改变这两个数字 | 单一固定 period fixture 无法暴露混单位 |
| 空/部分/损坏输入 | 空查询无假权重；丢失/unknown 保持 partial；损坏/truncated trailer 拒绝 | 图可渲染或 parser exit=0 |
| 符号身份 | 两个同名 ELF、缺 ELF、错误 build-id/hash、非零 pgoff、PIE/exec/PID 重用均有独立负例 | 使用主机上碰巧同名的二进制 |
| CPU exporter 格式 | #181 fixture 的字段/计数/period/COMM/MMAP/FORK/EXIT/LOST 由未改的 perf script/report/buildid-list 核对 | 自己的 writer 和 reader 相互认同 |
| 真实调用链 | RV64/LA64 已知多层 user/kernel 与混合链；read-fault/depth-limit/缺 FP 可见；函数和总权重符合实际 workload | 合成链或只含 sampled PC 的文件 |
| FlameGraph | 固定版本 perf script → stackcollapse → SVG；解析 SVG，核对折叠栈、总权重和单位 | 仅生成一个非空 XML 文件 |
| 真实端到端 | #191 的实际消费计数继续与导出记录/权重核对；两架构按 AGENTS.md QEMU 门禁 | 静态 fixture 替代真实事件生产 |

#181 的脚本 [`fixtures/perf_data_minimal.py`](fixtures/perf_data_minimal.py) 已包含明确标记的合成 oracle：三条样本、总 period=30,000,000、用户/内核函数名、非零 pgoff、FORK 继承、LOST=2 和缺用户 ELF 的负例。既有记录的实际 reader 为 perf 6.8.12，格式依据为 Linux v6.12；本次文档没有重新运行该实验，因此不声称新增了 exporter 或真实栈证据。[P2]

## 本轮已落地的查询与输出 slice

新增 `CaptureAnalyzer::query(&Query)` 与 `query::AnalysisResult`，实际 CLI 的 table、JSON、folded、`--sched-report`、`--fault-report` 共用该入口。已经支持 phase、半开时间窗口、task/PID/TID/CPU、fault address、显式 user/kernel mode 过滤，以及 CPU folded 的 samples/period 权重；无效或歧义 phase 在 CLI 返回错误。旧 `events_in_phase` / `aggregate_statistics_in_phase` 已标 deprecated 并转发相同的 Query，兼容 Vec/statistics 返回类型仍以空结果表示错误，新调用方必须使用 fallible Interface。

```text
bpf-analyzer session.pbcapture --phase workload --tid 123 --from-ns 100 --to-ns 500 --json --oncpu cpu.folded --weight period
bpf-analyzer session.pbcapture --mode user --timeline user-timeline.json --json
bpf-analyzer session.pbcapture --sched-report --cpu 1 --tid 123 --json
bpf-analyzer session.pbcapture --fault-report --address-start 0x400000 --address-end 0x500000 --json
```

Query 先在全记录上关联，再选择完整区间；JSON 分别保存 selected/capture/context 数量与窗口裁剪计数。scheduler diagnostics 仍声明为 capture scope，不能因筛选变成无损；fault completion 的起点跨窗口时保留事件数，但 duration 计入 censored 而不进入完整延迟分布。`--offcpu` 为兼容选项名，其输出现在只含已配对的 blocked-wait 纳秒，不代表全部实际未运行时间。

历史名称按时间解析，同 timestamp 的跨 CPU 冲突保持 unknown；TaskExit 清理名称。CPU folded 不再退回调度纳秒，未配对 block 不再变成 count 权重，空数据不再生成假 weight=1；任务名中的 folded 分隔符/控制字符被转义，不能注入额外堆栈或权重。

新增 `query_cli_tests.rs` 的实际 binary 与公开 helper 回归覆盖这些行为，并以已发布 #191 capture（成员 SHA 核对、无 marker 7）验证 typed `attached_capture` 选出真实 82 条记录、baseline 为空，另调整原先依赖无样本 fallback 的旧 fixture 断言。该实现与默认 legacy `aggregate_statistics` 的历史兼容输出有明确区分，新语义报告使用 Query；真实映射/符号/callchain、perf.data exporter 和 SVG 联动仍属于下面的后续工作。本 slice 不把 §2 固定基线之后的改动追溯成旧基线已有能力。

### 显式 privilege 与 timeline v1

`--mode user|kernel` 只使用软件 v2 的 `mode` 和 fault completion 的 `origin`。旧软件样本及调度事件没有相应字段，选择 privilege 时不纳入；旧软件样本还因缺少 IP 而不进入未过滤的 CPU folded；未知 CLI mode 值报错。`--sched-report` 与 `--mode` 的组合明确拒绝。folded 的 `[user]`、`[kernel]` 是 v2 IP 样本的分组标签，用于区分同一个数值 IP 的不同上下文；它们不是新捕获的函数栈帧，不能提升调用栈能力声明。

`--timeline <json-file>` 生成版本 1 JSON，与其它 renderer 使用相同 Query。它将三类事实分开：

- `events` 是实际选中的 normalized records，保留 capture sequence、时间/CPU/原始 PID/TID/task、语义主体、payload hex 和 typed semantic 字段。`schemas` 保存这些 payload 的原 schema 描述，offset 相对 normalized payload；显示名称不代替原始字节。
- `context_events` 仅保留已关联区间/unfinished 所用的原始端点、blocked switch-out、相关身份前史与 phase 边界，显式与 selected 记录分开。它不是额外采样，不能加入 selected 计数或权重。
- `intervals` 保留已观察的原始 start/end、CPU、证据 record 序号和质量，同时提供 visible 范围及 `query_clipped`。超出查询边界的条目只用于显示，不进入完整延迟统计。fault 的 start CPU 未被记录，保持 null，不能从 completion CPU 倒推。

`unfinished` 的 `end_ns` 和 `visible_end_ns` 始终为 null；RightCensored 可另给 `observation_limit_ns`（查询边界与 capture stop 的较小者），并明确它不是 endpoint。不会为了画出横线而补发 raw wake/switch/fault 事件。空的 phase/time 交集标记 `empty_window`，不生成倒置区间。

Timeline 的 source 部分保留 capture format/arch/window/count 和已验证 trailer checksum；CRC 不是 SHA-256 或签名，文件的强身份仍由原 capture 及外层 artifact manifest 的 SHA-256 绑定。timeline、oncpu、offcpu 文件输出共用打开句柄的保护：保持实际读取的 input 句柄，打开各 output 时不截断，使用 Unix `dev+ino` 核对 input/output 与各 output 之间的同文件或硬链接冲突；全部通过后才在同一句柄上 truncate/write，不按路径重新打开。不同的既有普通 report 文件仍可覆盖，冲突时不改动已有文件内容。无法提供该文件身份的 host 平台明确拒绝文件输出，stdout 报告仍可用。JSON 序列化以仓库已经要求的 Python 标准 JSON reader 作独立测试 oracle，没有添加 Cargo 依赖；其整数读者应保留 u64 精度。

## 8. 后续实现切分与历史 ADR

建议在设计票的 resolution 中链接后续实施票，再关闭设计部分；没有实施与运行证据时 #180 继续开放。可审查的纵向切分为：

1. **Query、时序身份与单位**：修复基线三项可观察问题，以实际 CLI 多 renderer 测试验收；随后接入 #184/#185 的语义报告。
2. **符号身份与映射/lifecycle 采集**：生成可验证的初始/动态 metadata、address-space generation 与 artifact bundle，建立错误 ELF/exec/PID 重用负例。
3. **真实栈快照与 capture 演进**：依 #182 完成受限 no-fault 读取、每域链/状态/预算、source instance 绑定与真实 RV/LA 多层链门禁。
4. **CPU perf.data exporter 与图形产物**：先通过独立文件 oracle，再消费上述真实 capture；实现函数热点、调用树和明确单位的火焰图。schema 正确、符号正确、真实采样正确分开给证据。

这四项是实施建议，不是本研究已创建或完成的 GitHub 票据。

**与 ADR-0005 的冲突必须保留可见。** [ADR-0005](../adr/0005-profile-specific-linux-bpf-compatibility-tier.md) 要求具名、固定版本、未修改的 libbpf-bootstrap C `profile` 兼容层；#180/#186 当前路线采用 PulseOS 自有 fixed-context 采样与标准文件消费者。这不是同一个验收目标。完成本契约不能写成“已满足 ADR-0005”，也不能因提供 perf.data 就宣称任意 Linux BPF/Aya/libbpf 程序兼容。该历史 ADR 的替代或状态调整应单独、显式记录，本文不暗改原文。[P2][P3]

## 依据

- [P1] 当前 [analyzer 源码](https://github.com/muou000/PulseOS/tree/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-analyzer/src)、[capture 源码](https://github.com/muou000/PulseOS/tree/96a73a176df502f38d652912cb6a3cc04a44c23c/crates/bpf-capture/src)、[#191 原始证据](https://github.com/muou000/PulseOS/tree/96a73a176df502f38d652912cb6a3cc04a44c23c/tests/bpf_sampling/evidence/191)：本次读取并核对的固定实现基线。
- [P2] [perf.data 最小兼容子集研究](perf-data-minimal-subset.md)及其[可执行 fixture](fixtures/perf_data_minimal.py)：既有 #181 研究与独立消费者实验；其静态/真实证据边界保持不变。
- [P3] [栈捕获设计](stack-capture-design.md)、[采样能力与兼容层设计](sampling-capabilities-design.md)、[ADR-0005](../adr/0005-profile-specific-linux-bpf-compatibility-tier.md)：受限 FP/no-fault/partial 契约及历史路线冲突。
- [L1] [Linux v6.12 perf-report 文档](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf-report.txt)：本次经 GitHub contents API 读取，blob `7c66d81ab978c84bf46244d9e4fccea28d2162db`，核对 call graph、vmlinux/symfs、CPU 选择与 total-period 接口。
- [L2] [Linux v6.12 perf-script 文档](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf-script.txt)：本次读取 blob `b72866ef270b906812dc90d768bba088d797e873`，核对输出字段、period、vmlinux/symfs 和纳秒展示。
- [L3] [Linux v6.12 perf.data 格式说明](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf.data-file-format.txt)：本次读取 blob `010a4edcd3849257e989edd8d7681a22f661a0ec`，核对 BUILD_ID/ARCH 特性；具体 wire 布局沿用 #181 对同 tag UAPI 和 reader/writer 的逐字段核验。


后续实施已建立原生地图子票：[#192 真实栈](https://github.com/muou000/PulseOS/issues/192)、
[#193 映射与身份](https://github.com/muou000/PulseOS/issues/193)、
[#194 perf.data/函数图](https://github.com/muou000/PulseOS/issues/194)。本轮实现与原始运行门禁
见[验收记录](../../records/bpf-observation-tools-184-188.md)；不是把这些未完工作当成设计票的已实现功能。
