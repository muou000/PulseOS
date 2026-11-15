# CPU perf.data 与函数火焰图（#194）

日期：2026-11-15。实现基线 `82b9417b8479447ef9c2e2f8376bc660d146dfbb`。
本次实现主机侧 exporter 与显式外部工具流水线，消费 #192/#193 已实现的
真实 stack-v3、时序映射和 ELF bundle；不修改内核采样生产路径。

## 验收先行

- 以公开 capture → exporter 和 CLI 为测试边界。首先记录旧 CLI 不识别
  `--perf-data`、未生成空选择产物的失败；外部工具流水线亦先验证未实现接口的失败。
- Linux v6.12 是 wire 格式基线；原样 `perf report` / `script` / `buildid-list`
  是独立消费者。实际执行版本与可执行文件 SHA 分别保存在流水线结果中。
- 核对原始 IP、PID/TID、时间、CPU、period、source instance 和捕获链。每条
  用户 frame 必须通过当时映射与 PT_LOAD 核对；内核 frame 核对运行范围及参考符号。
- 负例包括缺失/错误 ELF、PIE 与非零 pgoff 错配、PID 重用、混合域链和 loss。
  空数据的条数与权重均为零；partial 链和缺失诊断保持可见。
- 图形流水线使用固定 FlameGraph
  `41fee1f99f9276008b7cd112fca19dc3ea84ac32` 的原始脚本，核对内容 SHA，
  不运行时下载。SVG 需通过 XML、总权重、单位和已知函数名检查。

## 运行方法

命令入口和边界见 [使用说明](../docs/perf-export.md)。真实 guest 采用仓库约定的
8 GiB / 8 CPU / snapshot disk / UTC RTC QEMU 参数，由现有 runner 保存完整 argv。
本次 combined 负载同时执行两组汇编调用树、负面栈探针，以及六阶段映射变更：

```bash
python3 tests/bpf_sampling/run.py guest --arch riscv64 --mode cpu \
  --archive --stacks --mappings --timeout 300 \
  --kernel SAVED_RV/kernel --kernel-elf SAVED_RV/kernel.elf \
  --kernel-provenance SAVED_RV/kernel.provenance.json
python3 tests/bpf_sampling/run.py guest --arch loongarch64 --mode cpu \
  --archive --stacks --mappings --timeout 300 \
  --kernel SAVED_LA/kernel --kernel-elf SAVED_LA/kernel.elf \
  --kernel-provenance SAVED_LA/kernel.provenance.json
```

`SAVED_RV` / `SAVED_LA` 分别为 #193 最终运行目录中的 BPF-enabled 内核。
这保留实际 kernel SHA、build provenance 与当前 analyzer 改动之间的区别，
不把旧生产者伪称为当前提交编译出的内核。

## 中间失败与边界

首次 combined guest 在两个架构都产生了真实样本并通过 guest 检查，但 #193 的
主机映射 oracle 使用 timestamp/task/IP/CPU 键，无法区分同一次 IRQ 内两个不同
source 实例。原始数据与失败结果保留；映射报告和 oracle 增加 source_id 后重放。

开发期间的一次 `make test` 在 provenance 阶段拒绝记录，因为编译期间源码仍在
修改。该失败没有被当作构建成功；最终门禁在源码停止修改后重新执行。

第二轮 RV64 的组合负载触及 4 MiB 私有档案上限，导致末尾映射阶段缺样；原始
export loss 和失败结果保留。组合模式改为 8 MiB 后重跑，其他模式仍为 4 MiB。
各次真实采集的内存配置记录在原 archive/source 中，不作性能前后比较。

真实内核验收还发现，重复发布同一 kernel MMAP 会使 perf 后续样本失去符号；
修正为按捕获的发布时刻输出一次，逐帧身份校验仍保留。实际 Rust ELF 的本地
`.L` 调试标签又遮挡函数名；增加显式、可验证的符号视图，保持所有加载字节和
函数表事实，隐藏本地非函数标签。验收因此要求已知内核函数，而非仅检查地址一致。

采样器的全部 source skipped、unknown、transport loss、栈终止原因继续由原
capture 解释。选定函数与权重可验证，不表示整个 capture 具备完整 CPU 归因，
也不表示 scheduler/fault 记录已经成为 Linux perf tracepoint。

## 自动化验证

```bash
cargo check -p bpf-analyzer -p bpf-capture
cargo test -p pulse_bpf_schema -p bpf-capture -p bpf-analyzer -p pulse_syscalls -- --test-threads=1
cargo test -p bpf-analyzer --test perf_export_tests -- --ignored
python3 -m unittest discover -s tests/bpf_sampling -p 'test_*.py'
make test 2>&1 | tail -30
make test APP_FEATURES="qemu bpf-trace" 2>&1 | tail -30
```

原生 perf 集成测试独立执行，因此默认 host 测试中的三项 ignored 并非未验收。
它们核对 PIE/非零 pgoff、函数链、两个不同 period、同一 PID/TID/地址退出后
换用不同 ELF，以及多个连续内核样本的实际 reader 行为。普通 host 测试还覆盖单 IP source 唯一性、
混合 user/kernel 链拒绝、mapping loss、transport loss 保留及输出文件别名保护。

## 最终真实采集

最终 RV64 原始档案为 4,717 条，LA64 为 4,233 条；两者 guest gate 均通过，
transport loss 与 export drop 均为零，capture 仍保留 unknown/error 的 partial 状态。
两种架构均启用 16 个 CPU-clock 实例（每 CPU 的 10 ms 与 20 ms），同时捕获
原始调用栈和映射生命周期。软件时钟权重来自真实 period，不代表精确 CPU busy 时间。

| 架构 | 用户函数样本 | 用户 period_ns | 内核函数样本 | 内核 period_ns |
|---|---:|---:|---:|---:|
| RV64 | 481 | 6,470,000,000 | 65 | 810,000,000 |
| LA64 | 432 | 5,760,000,000 | 68 | 960,000,000 |

用户 Query 选择实际 target PID/TID 的 user 样本；内核 Query 再限制到 RAW 独立
观察到的 mmap/munmap 负载时间范围。每个查询核对 table/JSON/folded/perf 中
相同的条数和权重。用户 period 与 samples 两次展示使用完全相同的原始样本；
内核样本单独核对，不能将二者当作一段互斥 CPU 时间相加。

至少三层 `sample_chain_a → sample_middle_a → sample_loop_a` 用户函数以及
来自真实 mmap/munmap 的至少三个内核函数，在原样 perf script/report/calltree
和固定 FlameGraph SVG 中核对。RAW → native perf 独立 oracle 同时比较 source ID、
IP、PID/TID、时间、CPU、period、mode、context marker 和完整保存的链前缀。

证据入口与完整 Query 见 [evidence/194](../tests/bpf_sampling/evidence/194/README.md)。
每个包保存原始 RAW、capture、串口日志、journal、实际 ELF/source/provenance、
perf.data、manifest、未修改的 consumer 输出、符号视图和 SVG，逐成员 SHA 可重放。
实际 consumer 为 `perf 6.8.12`，FlameGraph 为前述固定提交。原始 ELF 缺 GNU build-id
时，buildid-list 的缺失也作为事实验证。
