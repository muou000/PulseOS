# #194：真实 CPU capture → perf → 函数火焰图

> **Retention update — 2026-11-16:** The raw `.tar.gz` bundles described below
> have been removed from the current tree. Retained indexes, hashes, counts and
> replay reports record historical verification; they do not provide a complete
> replay from this checkout. Bundle names and links below are historical references.
> The old replay commands require complete bundles held separately; metadata
> cannot reconstruct their bytes. For new evidence, follow the
> [fresh-run instructions](../../README.md) and keep raw output out of Git.
> See the [sampling evidence retention policy](../../../../docs/sampling-evidence-retention.md).

日期：2026-11-15。`index.json` 保存两个原始采集包及每个成员的 SHA-256。
`replay-report.json` 是新临时目录中重新导入、运行实际 perf/FlameGraph 的验证结果。
原 capture 状态保持 partial；这些结果证明已记录样本的函数与权重，不代表完整 CPU 归因。

| 架构 | 原始 RAW | 用户 samples | 用户 period_ns | 内核 samples | 内核 period_ns |
|---|---:|---:|---:|---:|---:|
| RV64 | 4,717 | 481 | 6,470,000,000 | 65 | 810,000,000 |
| LA64 | 4,233 | 432 | 5,760,000,000 | 68 | 960,000,000 |

每包 117 个普通文件，包含原串口/RAW/capture、映射日志、实际 ELF、build provenance、
负载源码、独立 stack/mapping 报告，以及 `perf/` 下三组 data/manifest/未修改 consumer
输出/folded/SVG。RV64 用户 `sample_loop_a` 为 24 samples / 320,000,000 ns；
LA64 为 40 / 510,000,000 ns。用户与内核分别验证至少三个来自实际 ELF 的有序函数。

- `perf/user-period/flamegraph.svg`：用户 period_ns 图。
- `perf/user-samples/flamegraph.svg`：同一组用户样本的 samples 图。
- `perf/kernel-period/flamegraph.svg`：真实 mmap/munmap 范围内的内核 period_ns 图。
- `acceptance-report.json`：精确 Query、函数范围和逐函数权重。
- `perf/*/commands.json`：实际调用参数；各 `.stdout/.stderr` 保留原样输出。
- `perf/kernel-period/kernel-symbols.elf`：显式派生符号视图；源/派生 SHA、隐藏标签数及
  变换版本在对应 `result.json`，原 kernel ELF 保持不变。

实际消费者为 perf 6.8.12；FlameGraph 固定提交
`41fee1f99f9276008b7cd112fca19dc3ea84ac32`，按两份脚本 SHA 校验，运行时不下载。
数据格式依据 Linux v6.12 子集，consumer 版本单独记录。复现使用明确安装的工具：

```bash
python3 tests/bpf_sampling/verify_perf_evidence.py tests/bpf_sampling/evidence/194 \
  --perf /usr/local/bin/perf --flamegraph /path/to/pinned/FlameGraph
# 不重新执行外部工具时，仍校验索引、RAW/capture/reimport、ELF、保存的原生输出和 SVG：
python3 tests/bpf_sampling/verify_perf_evidence.py tests/bpf_sampling/evidence/194
```

重放不需要原始运行目录或磁盘镜像：从 ELF 重建启动字节、检查 provenance，并重新
导入 RAW，再用当前 exporter 逐字节复现六组 perf.data 与 manifest。执行外部工具的路径和临时目录可能不同，核对采样事实及结果而非文本路径。

最终实际 producer 采用 #193 已记录 BPF-enabled 内核，保留原 build commit 与 dirty
输入树身份。LA64 的采集使用 4 MiB 私有 archive；RV64 最终运行使用组合测试的
8 MiB archive。两者 transport loss/export drop 为零；不是性能前后对照实验。
中间失败、边界和测试结果见 [验收记录](../../../../records/bpf-perf-export-194.md)。
