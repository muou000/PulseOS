---
name: bpf-sampling
description: 使用 PulseOS BPF 工具采集或分析 CPU 热点、调用栈、调度延迟和缺页，导出 perf/火焰图，并整理采样报告与精简提交。适用于新采样、已有 capture 分析和性能证据验收。
---

# BPF 采样分析

在 PulseOS 仓库根目录工作。目标是回答具体性能问题，并留下可审查的结果、
复现方法和证据边界。报告原始观测与推断的区别。

## 1. 先定义问题和验证方式

先读根 [AGENTS.md](../../../AGENTS.md)、[GLOSSARY.md](../../../GLOSSARY.md)
的 Performance observation，以及[当前 recorder 契约](../../../docs/bpf-record.md)。
明确架构、实际工作负载/线程、观测时间窗、指标和通过/失败信号，再选择采样入口。
已有 capture 足够回答问题时直接分析；缺少关键信息时再安排新采样。

| 问题 | 选择与关键约束 |
| --- | --- |
| CPU 热点/调用栈 | `cpu` 或绑定既有线程的 `task`；需要函数链时启用 FP 并保存匹配 ELF 身份 |
| 阻塞/唤醒延迟 | `sched` 完整事件组；有效区间必须能配对，保留歧义、缺端点与 censored |
| 缺页及处理延迟 | `fault`；major/minor 依据实际目标页 I/O provenance，未验证 backend 保持 unknown |
| 开销/回归对比 | 同一负载、参数和迭代定义；比较 baseline、loaded-detached、attached，记录重复次数和干扰 |
| 整体生产流程验收 | 阅读[固定门禁](../../../tests/bpf_record/QUALIFICATION.md)，执行完整 guest 矩阵及独立消费者校验 |

普通性能分析按问题限定范围；宣称双架构完整验收时才要求完整矩阵。
PulseOS 自有采样是当前范围，ADR-0005 的历史上游 profile 兼容目标不构成现成能力。

## 2. 获取可信输入

新采样时按[操作步骤](references/workflow.md#新采样)构建和运行。固定源码后构建，
记录实际启动 kernel/image、recorder、analyzer、ELF 与工具身份；不要边改源码边生成
构建 provenance。运行沿用 AGENTS.md 的 QEMU 参数，使用独立镜像副本。

业务负载必须实际被采集。固定 runner 的 fixture 可验证采样工具，不能冒充业务负载。
`task --tid` 绑定一个既有线程；混合会话的 TID 不会过滤 CPU/sched/fault 来源。
模式或调用栈降级须有用户明确允许，并记录 requested/effective/unit/reason。

结束后核对退出码、guest 保存 SHA 与 host 原文件、trailer 和记录数。
QEMU `snapshot=on` 的输出不会写回底层镜像，退出 guest 前完成文件传输。
失败可以留下有效 partial 或不可解析前缀；零记录、超时、缺 trailer 不能当成功采样。

## 3. 分析并核对

按[分析步骤](references/workflow.md#分析已有-capture)先检查 capture 全局诊断，
再声明 Query；table/JSON/folded/perf 使用同一组身份、时间窗、模式和权重。
`--task` 是稳定 kernel task ID，`--tid` 是 numeric TID；从 capture 取值。
单独说明事后筛选理由及被排除范围，不据此改变会话完整性。

需要函数图时按[符号与导出步骤](references/workflow.md#函数热点与火焰图)收集实际
匹配 ELF，运行原生 perf/固定 FlameGraph。缺 guest 身份、时序映射或匹配 ELF 时
报告严格拒绝；仅有同名 host 文件不能补造身份。

检查实际样本数、逐源权重、保存的链与终止原因，而不只看是否生成图：

- `samples` 是条数，软件 clock 的 `period` 权重是 `period_ns`，不是实际 wall time。
- source/system/VM/sink/export/consumer/journal loss 保留各自作用域，不相加成伪总数。
- partial/unknown/unavailable、缺失计数保持原义；解析或符号化成功不使 capture 完整。
- wake-to-switch 到 scheduler selection；fault 延迟不能用来猜 major/minor；没有
  IRQ/idle 驻留事实时，不从采样比例推导精确 CPU busy/idle。

## 4. 写报告并按授权交付

读[报告与提交规则](references/reporting.md)，使用[报告模板](assets/report-template.md)
生成 `records/` 下的精简报告，按问题删掉不适用栏目。新 guest、历史回放和合成
fixture 分别标明；同时报告改善、退化和未验证范围，单次观察不宣称统计显著性。

[保留策略](../../../docs/sampling-evidence-retention.md)是数据提交的唯一规则来源：
Git 保留结论、关键统计/身份/哈希、复现代码和必要小 fixture；完整采样产物留在
ignored runs 或外部存储。摘要及哈希不能代替已移除原包的完整回放。

提交前检查已暂存文件及其实际 blob 大小。commit、push、issue 更新按当前会话授权
执行，已有授权直接继续；本 skill 本身不授予发布、删除用户运行数据或重写历史的权限。

完成时交付结论、报告路径、实际验证、数据保留/回放条件和提交状态。
