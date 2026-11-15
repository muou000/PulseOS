# #180 验收复核与当前标准清理

复核日期：2026-11-15。实现基线：`aadc7001`；对照 #180 记录的
`5195b84f`，重点审查 #192–#196 的已合并实现。工作区改动另列于下文。

## Spec

**结论：#180 尚未达到完整交付标准。** #192–#196 均已关闭并合并，
主票仍列为未完成的清单及 #209 待合并说明已经过时。但专项入口的运行验收
不能替代通用入口到分析结果的完整流程。

### P1：通用 recorder 尚未接通调用栈、映射与 perf 导出

[`sampling-control-contract.md`](../docs/research/sampling-control-contract.md)
要求 enable 前保存目标、映射和符号身份，且通用命令产物可供后续 perf exporter
消费。当前实现存在三处尚未接通的接口：

- `tools/bpf-record/src/runtime.rs` 的软件事件程序只输出 `SoftwareV2` 单 IP，
  没有采集 stack context、时序 mapping journal 和匹配构建身份。
- `CaptureWriter::set_mappings` / `configure_recorder` 不允许 recorder 与
  mapping 元数据共存。
- `bpf-analyzer::perf::sources` 从 diagnostics 身份项读取 source，尚未使用
  recorder 的逐记录 source binding；非空 CPU 导出随后还需要 mapping 元数据。

实际复现：将 `tests/bpf_record/evidence/195/riscv64-recovery.tar.gz` 中的
`task.pbcapture` 原样提取到临时目录，运行
`bpf-analyzer CAPTURE --bundle DIR --perf-data DIR/perf.data`，退出码为 1：

```text
Error: sample 0 has missing or ambiguous source instance
```

错误发生在 ELF 查找之前，不由临时目录缺少 ELF 引起。此问题在本轮兼容清理
之前已存在。完成 #180 仍需接通真实 source、stack、mapping 和 artifact
生命周期，并对通用命令输出执行 RV/LA 的 perf report/script 与火焰图验收。
本轮完成检查和兼容清理，未把这项缺失功能标记为已实现。

### P3：进度与使用文档过时

已修正 `docs/bpf-record.md` 中“major/minor 全部 unknown”的当前使用说明：
#196 已提供验证过的 Ext4Disk/VirtIO 路径分类，其他未经验证的 backend 仍为
Unknown。GitHub 主票未在本轮改写或关闭。

物理 PMU、未经验证的文件系统 backend、精确 CPU busy/idle 仍是明确记录的
能力边界；不把它们额外提升为软件采样基线的阻塞要求。

## Standards

本轮用户要求只保留当前标准，覆盖历史票据及 ADR-0005 中要求维护旧接口的
兼容承诺。旧设计与运行证据作为历史记录保留，当前实现删除以下兼容行为：

- capture v1 读写及其非 IEEE CRC；所有支持的 capture 均要求 diagnostics。
  缺失运行证据时写入明确 unknown 的 diagnostics，状态保持 partial。
- 软件样本 v1（ID `0x1000`）注册、解码与展示；即使文件自行声明该 schema，
  也不能重新启用。保留 current v2 的 data address 与 IP 不混用检查。
- `PBSRC001` source 表和 numeric-TID 回退；只接受 `PBSRC002`，task source
  必须绑定稳定 kernel task identity。
- 按 payload 长度猜格式的输入 API、`SampleFormat` 别名、弃用的 phase API、
  同步 probe 空实现及 smoke 历史命令别名。
- 无 diagnostics 的旧完整归因绕过。消费者实际观测的 loss/discard/corruption
  仍单独展示，不恢复没有测量依据的 producer 零值，不累加重叠 loss scope。

v2（诊断）、v3（栈）、v4（映射）、v5（source-bound recorder）仍由当前生产
入口使用，是并行能力格式；v5 不是 v4 的超集。保留这些格式是维护现有能力，
不代表继续支持已退役的 v1 或 `PBSRC001`。

独立复审发现的消费者计数展示回归已修复，并加入文本/JSON 回归检查。

## 验证及证据边界

- #192–#196：24 个归档及 710 个索引成员的 SHA-256 全部匹配。
- 清理后原样重放 14 份 RV/LA capture，共 14,727 条记录，覆盖活跃 v2/v3/v4/v5；
  全部保持原 partial 状态。旧 `PBSRC001` 输入被明确拒绝。
- capture Rust 测试 76 项、analyzer 普通测试 118 项及原生 perf 消费者测试
  3 项通过；原生 consumer 是 `perf 6.8.12`。
- 最终合跑 `pulse_bpf_schema`、`bpf-capture`、`bpf-analyzer`、`bpf-record`：
  234 项普通 Rust 测试通过（另有上述 3 项原生 perf 测试）。
- Python：sampling 101 项、recorder 8 项、smoke 14 项通过。
- 默认及 `APP_FEATURES="qemu bpf-trace"` 两组 `make test` 均通过 RV64/LA64
  构建门禁；两架构生产版 `bpf-record` 可执行文件构建通过，包含 no_std capture。
- 本轮新运行两架构 recorder smoke，CPU / 调度 / 缺页共 6 份 capture、
  16,537 条实际记录，均通过当前 analyzer，状态全部保持 `IncompleteError`。
  quiesce、停止后无增长、资源回收及原始镜像未改变检查均通过。

| 架构 | CPU 记录 | 调度记录 | 缺页记录 | 本轮结果 |
|---|---:|---:|---:|---|
| RV64 | 868 | 4,261 | 2,359 | [result.json](../tests/bpf_record/runs/riscv64-smoke-20261115-212941-cq7q1p2x/result.json) |
| LA64 | 784 | 5,288 | 2,977 | [result.json](../tests/bpf_record/runs/loongarch64-smoke-20261115-213103-dw_5p1ja/result.json) |

这些 `runs/` 目录是本地验证产物，保存匹配的 kernel、recorder、analyzer、
输入 SHA、原始串口记录及 capture。RV 使用 acceptance 构建的普通 smoke 路径，
LA 使用生产构建。运行遵循 AGENTS.md 的 QEMU 配置；这不是开销基准测试。

归档哈希验证、当前 analyzer 重放和新 guest 运行是不同证据。原归档未改写，
新 writer 的默认 registry 已移除旧 schema，不要求历史 capture 经重新导入
后逐字节相同。历史部分数据不因格式清理而变成完整采样。

Standards 剩余 0 项；Spec 剩余 1 项功能缺口（P1）和 1 项主票状态更新（P3）。
