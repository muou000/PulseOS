# 真实消费到独立 capture 的验收（#191）

日期：2026-11-15。#190 的真实软件采样与调度事件经过 mmap ring 消费、RAW 校验、显式格式规范化、capture writer、独立 host analyzer，已形成可复查闭环。旧 smoke 的固定五条记录、假 hash、默认补零和伪 parity 路径已退出真实运行入口。

可下载的原始证据与逐文件 SHA-256：[`tests/bpf_sampling/evidence/191/`](../tests/bpf_sampling/evidence/191/README.md)。包含实际 QEMU 输出、实际 guest ELF、RAW 数据、完整 capture、输入与构建来源、before/after 原始诊断和分析器输出；故障探针保留失败原因。完整启动内核与磁盘副本保留在每次本地 `tests/bpf_sampling/runs/<run>/` 中，未将大镜像重复提交。

## 行为与可信边界

- 软件 context v2 的独立 IP/mode 被保留为 normalized event `0x1001`、schema version 2；原 `addr` 不改成 PC。旧 TaskEnqueue 也长 64 字节，因此输入格式必须由附着程序明确指定，不能按长度猜测。
- 消费器 Acquire 读取 head，校验完整 record 后复制原始帧，再 Release 更新 tail。FRAME 序号、CPU、长度和 IEEE CRC32 都校验；不允许零生产或零消费通过。关闭所有源后有界等待各自 inflight=0，再最终 drain 和读取 after 快照。固定等待不是完成证明。
- `/proc/pulse_bpf_stats` 对每次 open 保存稳定快照，允许跨页分片读取；新 open 刷新。guest 使用 8 字节前缀加 97 字节分片，并验证 EOF。输出超过 64 KiB、provider 不可用或并发换程序导致 PROGRAM 身份不一致时明确失败。FD-table 锁外访问 event；程序按 ID 去重。
- accepted invocation 在控制锁内计入 inflight，退出时 Release，诊断在同锁下 Acquire 读取；disabled + inflight=0 才是会话调用完成边界。GLOBAL 是系统范围计数，before/after 区间可能比采集窗口宽，不能冒充只属于该进程的损失，也不保证全系统同时快照。
- source `delivered` 是成功 VM 执行数，PROGRAM `runs-errors` 与之核对。sink `delivered` 是入队样本，`transport_lost` 是被拒绝样本；本固定 copy/output 程序满足 source delivery = sink delivery + sink loss。saved samples + export-dropped samples = sink delivery。RAW LOST 是可能滞后的通知，不能与 sink loss 相加。consumer、源、VM、交接队列各层分别保存；cancelled/invalid 等不是关闭后永不变化的全系统最终总量。
- 内核 consumer corruption/bounds 计数属于其 parser API；guest mmap parser 的损坏记录会直接使运行失败，二者不冒充同一计数器。未实现的 verifier/load/attach 总量、RSS/内核分配成本、时钟分辨率明确 unknown。
- capture 格式 2 包含 typed diagnostics、三阶段测量及完整原始 JSON 证据，并用标准 IEEE CRC32。格式 1 保留历史 checksum（测试向量 `123456789` 为 `c6dd3518`，非标准 IEEE 的 `cbf43926`），兼容旧文件。缺 trailer、损坏、错误长度/offset、未知诊断和零记录均不能报告完整。
- 构建在 Cargo 前后记录并核对实际源树/有效配置，完成后绑定 ELF 与裸镜像 SHA-256。运行核对实际启动字节和 ELF，再核对 manifest；保存的是构建时 commit + dirty source-tree hash，不用运行时 HEAD 冒充内核来源。来源细节见 [构建来源协议](../docs/kernel-build-provenance.md)。本次内核在 `dd67ee7b` 基础上的 dirty 工作树构建，准确 tree hash 在各 artifact 中，不声称仅该 commit 就包含本实现。
- 实际采集的 source 选择、period、program/map/link/event ID、CPU/task 身份、时间窗口、原始 rootfs hash 和注入 payload 后的 boot image hash 全部保存。后续运行还会保留编译输入副本和 payload-build.json，源文件在编译/归档期间变化会拒绝。

## 真实运行与故障证据

四组正常运行由旧 `bpf_smoke` 兼容入口及新的 `bpf_sampling` 入口完成，RV64/LA64 × task-clock/sched_switch；trace 使用一页 ring。每组实际 records、wrap 次数、capture hash 和 run 路径以 evidence/index.json 为准。trace 的 RAW 流重算得 RV64 10 次、LA64 8 次实际跨环尾记录，与 guest head/tail/wraps 完全一致。

五种故障各有独立实际运行：

| 故障 | 实际结果 | 门禁含义 |
|---|---|---|
| 关闭生产 | samples=0，guest exit=1，无 capture | 旧固定五条不能替代实际生产 |
| 停止消费 | 源已运行但实际消费为零，guest exit=1，无 capture | 不能只看生产或控制面成功 |
| archive END 前异常退出 | exit=1，缺 END，无 capture | 缺失结束记录不被补成完整文件 |
| 私有导出缓冲区一页 | 实际消费 77 条，保存 39 条，export drop=38 | 允许保存 partial，禁止完整归因 |
| Perf Buffer 一页且暂停 drain | 保存 235 条，sink transport loss=317，RAW LOST=0 | 无 LOST 通知不等于无实际丢失 |

所有有效 capture 的分析器状态均为 `IncompleteError`，完整归因标记均为 false：存在 unknown 字段，部分运行另有 system timer busy、skipped 或 cancelled。这里 PASS 表示真实性、核对关系和预期故障处理通过，**不表示零损失、完整 off-CPU 归因、调用栈、符号解析或跨架构 parity 已完成**。

三阶段运行同样的 128 次 workload。墙钟来自实际 monotonic 起止，吞吐为 iterations / elapsed；额外映射字节来自成功创建的 sampler mappings。未把该数值冒充 RSS 或内核总开销，也未设置缺少测量依据的开销阈值。逐阶段实测数据在 index.json 和独立 capture 内；一次 QEMU 测量不用于统计性性能结论。

## 验证

```bash
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
make test 2>&1 | tail -30
cargo test -p bpf-capture -p bpf-analyzer -p pulse_syscalls -- --test-threads=1
cargo check -p bpf-capture --no-default-features
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
python3 tests/bpf_smoke/test_runner.py
python3 -m unittest discover -s scripts -p test_build_provenance.py
```

上述均通过：capture/analyzer 65 项、syscall/runtime 228 项、clock 2 项；sampling Python 31 项（含实际调用 Rust importer/analyzer 的 11 项）、兼容入口 15 项、provenance 5 项。新增 PerfBuffer 并发测试实际发送 20,000 条带序号/反码的记录，head/tail 是唯一逐条发布同步，重复复制校验，覆盖至少 300 次记录回绕和 30 次头部回绕；不把宿主测试当成所有弱内存执行的形式证明。

正确性回归包括：PROGRAM runs 被改为零仍有样本时拒绝；consumer/program 错误必须 partial；计数回退或加法溢出必须友好失败；CPU/context/version/record-size 不一致拒绝；重算 checksum 后伪造 Complete 仍被诊断证据否决；未知统计不补零；截断每个 trailer 字节均拒绝。

采样 worker 早于启动自检运行时，曾观察 PCP 全局页数断言失败。现在 worker 在启动自检完成后、加载用户程序前启动；未删除或放宽断言。最终两架构真实运行通过；这不声称解决所有已有 PCP 波动。一次 host 预启动失败是权限扫描将 git diff 中的测试字符串当作诊断；改为直接归档 diff 文件再计算 hash，没有真实文件权限错误或绕过权限。

补充验证：在保留 payload ELF、编译输入副本和 source-change 检查后，再以匹配的已归档内核运行 RV task，真实保存 65 条样本并通过分析器；本地记录 `tests/bpf_sampling/runs/riscv64-task-20261115-005246-isl4wic3/`。主要九组证据中的实际 payload 则从各自保存的注入 rootfs 只读恢复，并与当次 SHA-256 核对。

## 验收映射与剩余 map

#191 的七项验收分别由实际零生产/消费负例、源/VM/sink/consumer 对账、损坏/截断与回绕/并发测试、构建绑定和 typed unknown、两种溢出/异常退出、三阶段实测、双架构构建与独立分析器证据满足。

#191 仅交付可信 capture 基线。#180 保持开放：#184/#185/#187/#188 的设计与后续工具、调用栈/映射/符号、perf.data exporter 及物理 PMU 能力仍需后续实现和验收，不能从本 capture 的 partial 数据推断已经完成。
