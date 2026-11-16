# 通用 recorder 的 perf 消费契约（#212）

日期：2026-11-16。实现基线 `66192275e4cd6c428cf671db37dd6a89b6b10f3c`。

#210/#211 已将 exporter 的来源查找迁到 capture v6 typed sources 与
`record_sources[sequence_index]`。本票按当前代码补齐行为和验收；不恢复 #195
历史容器可读性，不把历史 capture 改写成新采集证据。

## 可观察行为

- perf attr 写入有效软件 clock/config、period/frequency 和 monotonic clockid；
  原始 `PERF_SAMPLE_PERIOD` 不随展示单位改变。逻辑 source ID 与 kernel event ID
  分开保存，manifest 明示 perf identifier 的 ID 域。
- table/JSON 展示原记录索引、逻辑 source 和 CPU 权重；排序/筛选保留绑定。
  混合 sched/fault 记录没有 CPU 权重。空选择保持零条、零权重。
- 合法 unavailable 空链保留真实 IP、period、终止原因，CALLCHAIN 长度为零；
  folded 保留原因和权重，不制造栈地址。原生 perf 的空链记录须与 manifest
  中的真实零长度链逐条相符，流水线才为它保留 unknown 标记及权重。
- 同一 Query 包含 cpu-clock/task-clock 时，固定 FlameGraph collapser 按事件分别
  处理并核对权重，SVG 以事件名分组。GNU build-id 缺失保持缺失；原生 perf
  可以省略缺 note 的 DSO，但不能遗漏实际 ID 或添加伪造 ID。
- 缺/错 ELF、mapping gap、PID/地址重用、混合域栈等仍严格验证；成功 manifest
  明示 partial/unknown 原因，拒绝导出返回具体错误而不写成功 manifest。
  原 capture、已验证 ELF 和输出间的同 inode 保护保持；普通报告仍按既有契约
  在全部校验通过后允许重写。

## 红绿验证

公开测试边界为 issue 指定的 exporter、Query 和 CLI。

| 失败回归 | 修改前 | 修改后 |
|---|---|---|
| perf attr 时钟/有效频率 | file attr 80 bytes，无 clockid | attr 96 / file attr 112，monotonic 和有效模式保留 |
| JSON/table Query 权重 | 缺少选定权重汇总 | 同一 Query 的样本/period 汇总一致 |
| unavailable 空链 | folded 丢失权重，perf 拒绝导出 | 保留零长度链、原因和权重 |
| 多软件 clock 火焰图 | `select one CPU event kind before combining FlameGraph weights` | 各事件及全图权重分别核对 |
| 混合有/无 GNU note ELF | `native perf buildid-list differs from actual bundled GNU notes` | 允许省略缺 note 的 DSO，仍严格核对真实 ID |

多源 CLI fixture 的 transport 顺序为 `[300, 200, 200, 120, ...]`，选定结果
原记录序号 `[1,2,0]`、逻辑 source `[7,9,11]`、kernel event ID
`[9007,9009,9011]`；包含同 CPU/同 period 的两个实例及跨 CPU、numeric TID
改变后的稳定 task source。输出为 **3 samples / 50 ns**。原生 perf 独立核对
IP、PID/TID、time、CPU、period、identifier、context marker、函数及权重；
固定 FlameGraph 分别生成 samples/period_ns SVG。

缺失/重复/未知来源、记录数量错配、kernel ID 错配、控制窗口和 task identity
重用由当前 capture 的 `unified_contract_tests`、`recorder_v5_tests` 继续拒绝。
exporter 测试保留 ELF、PIE/非零 pgoff、fork/exec、PID/地址重用、loss、截断栈
及 mapping gap 负例。没有性能优化声明，因此不以采集吞吐量对比作为本票证据。

## 验证命令

```sh
cargo check -p bpf-capture -p bpf-analyzer
cargo test -p pulse_bpf_schema -p bpf-capture -p bpf-analyzer -p pulse_syscalls -- --test-threads=1
PULSE_PERF=/usr/local/bin/perf \
FLAMEGRAPH_DIR=/tmp/pulse-perf-research-181/flamegraph \
cargo test -p bpf-analyzer --test perf_export_tests --test perf_cli_tests -- --ignored
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
python3 -m unittest discover -s tests/bpf_record -p 'test_*.py'
set -o pipefail
make test 2>&1 | tail -30
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
```

Linux v6.12 是格式子集基线，实际 consumer 为 perf 6.8.12；FlameGraph 固定
`41fee1f99f9276008b7cd112fca19dc3ea84ac32` 并校验内容 SHA。不在运行时下载工具。

## 真实 capture 重放与审查

[#212 重放证据](../tests/bpf_record/evidence/212/README.md) 包含十二组 Query，输入为
#211 未修改的双架构 capture/ELF。独立 oracle 从原归档 timeline 的 payload bytes
和 transport source bindings 解码期望值，与 native perf 全字段逐条比较。

| 原 #211 capture（user Query） | samples | period_ns | partial chains |
|---|---:|---:|---:|
| RV mixed | 21 | 210,000,000 | 15 |
| LA mixed | 49 | 490,000,000 | 24 |
| RV nonleader exec | 138 | 1,380,000,000 | 0 |
| LA nonleader exec | 123 | 1,230,000,000 | 0 |

四组各验证两种单位；另外四组按 exec 前后 numeric TID 分别筛选。全部保留
`IncompleteError`，无完整归因声明。部分 RV 地址被 perf 显示为本地汇编标签，
真实输出原样保留；函数核对包括 `_start`，不宣称所有地址都已恢复函数名。
本票执行 host replay，新的 guest 端到端流程仍由后续票验收。

双轴审查发现同一项 P2：固定 collapser 将 TID 0 显示为 `?/0`，空链标记未匹配
它的标签规则。修复后，Python 回归、原固定 Perl 的独立重放、kernel/idle 空链
的原生 perf → SVG 两种单位均通过。Standards 没有规范违反或需要处理的代码异味。
两轴复查均无剩余发现。主机验证共 **497 项 Rust 测试**（490 常规 + 7 原生 perf）
及 **126 项 Python 测试**（109 sampling + 17 recorder）通过；`cargo check` 通过。

一次初始默认构建在编译期间提交证据，改变了 provenance 中的 Git identity，
因此被 `source inputs changed during build` 门禁拒绝；不计为通过。
最终门禁在源文件和提交固定后重新运行。
