# #180 软件采样基线验收

2026-11-16 复核结论：达到当前验收标准，
[#180](https://github.com/muou000/PulseOS/issues/180) 已以 `completed` 关闭，
不需要补建阻塞票。关闭时间为上海时间 15:51:41。
GitHub 的 19 个原生子票全部关闭；PR #222 于上海时间 15:08:33 合并，
main 合并提交为 `a1a7e016bf135127172d564add38bdad51ff48f9`，
其 head 为本地复核基线 `9169652f2c2f9118301832161c581d9d22f26906`。
主票中“#213 / PR 待合并”的状态已经过时。

## 逐项结论

| 目的地 | 验收依据 |
| --- | --- |
| CPU 热点、真实调用栈与火焰图 | 生产 CLI 的 CPU/task/mixed、独立目标、既有程序、nonleader exec；21 个正向 Query、42 份原生 perf/SVG，逐记录与真实调用链核对 |
| 调度性能 | 新 RV/LA 回归分别逐字段核对 1,386/1,675 条 RAW，259/267 个有效 blocked/wake 实例；时间终点是 scheduler selection |
| 缺页及延迟 | 两架构各 265 条回归；冷目标/邻页各 8 个实际读取扇区，匿名/热页/COW/缓存命中无对应数据页读取 |
| Linux 工具互操作 | 实际 perf 6.8.12 report/script/buildid-list、固定 FlameGraph；原记录绑定保持 source、period、task identity 和调用链 |
| 通用采集与平台分级 | RV64/LA64 生产 bpf-record、生命周期、负例、映射及构建身份已接通；硬件能力缺失仅在显式允许时降级 |

完整 guest 验收和性能边界见 [#213 记录](bpf-recorder-e2e-213.md)。
保存的默认/BPF-enabled 双架构构建均通过，历史主机测试为 522 Rust、148 Python。
原始 finalized capture 共 60 份、94,842 条记录，均为 `IncompleteError`；
两份实际写失败前缀各 1,024 bytes，不能算成功 capture。

## 本轮实际复验

- 清理前重新校验 #213 六个归档和 4,220 个成员的 SHA-256、大小并解包。
- 从原字节独立解码全部 60 份 capture，核对记录数和 partial；两份写失败前缀
  按 trailer/boundary 错误拒绝。
- 在新解包目录执行 `qualify.py`：36 个原 guest 结果的身份和索引通过，
  21 个正向 Query 和 1 个 LA 用户态严格拒绝通过；重新生成 42 份 SVG，
  42 份 perf.data 与历史产物逐字节相同。
- 清理后 recorder 38 项 Python、sampling 110 项 Python（其中 1 个原生工具
  测试在普通运行中跳过）通过；另单独启用真实 perf/FlameGraph 执行该组 10 项
  测试，全部通过。Rust 历史 capture 格式拒绝回归通过。
- 本轮没有重跑 QEMU 或内核构建；没有修改生产功能代码。

本轮机器可读结果见
[`acceptance-review.json`](../tests/bpf_record/evidence/213/acceptance-review.json)。
重放使用 `tests/bpf_record/evidence.py verify ... --extract DIR`，随后
`tests/bpf_record/qualify.py DIR/matrix --additional DIR/extension`
配合当前 analyzer、`/usr/local/bin/perf` 和固定 FlameGraph
`41fee1f99f9276008b7cd112fca19dc3ea84ac32`。

## 保留边界及数据清理

LA 动态库缺 guest SHA、mapping mutation interval 仍严格拒绝归因；
partial/unavailable 栈和分层 loss 不因输出火焰图而升级为完整。
物理 PMU/板卡、x86/aarch64 guest、未经验证的 fault backend、分配追踪、
精确 busy/idle 和旧 ADR-0005 的上游 profile 兼容不属于本次软件基线关闭门禁。

历史单次 attached 吞吐相对 baseline：RV -2.222%、LA -5.561%；
loaded-detached：RV -0.093%、LA +5.372%。这些是 QEMU 八 CPU / 8 GiB、
串行单次观测，不是统计开销结论；环境、资源和分层 loss 保留在关键结果中。

按维护者要求，移除 63 个完整历史归档（208.86 MiB），保留原始索引、
验收/回放摘要、#213 关键结果和约 361 KiB 的必要回归 fixture。
三个依赖归档的自动测试已迁移且未削弱断言。
见[保留策略](../docs/sampling-evidence-retention.md)和
[删除清单及原 SHA](sampling-evidence-retention.json)。
原包已退出当前树，摘要不具备完整回放能力。初次清理未重写历史；维护者随后
明确授权，现已完成[历史重写及远端同步](sampling-history-rewrite.json)。
原构建身份仍按当时 SHA 记录，另有[旧新提交映射](sampling-history-commit-map.json)。
