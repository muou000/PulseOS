# CPU capture 的 perf.data 与火焰图

`bpf-analyzer` 从原始 BPF capture 派生 CPU perf.data。原 capture 保留配置、
映射历史、原始采样和分层诊断；perf.data 与 SVG 是可重新生成的分析产物。
调度和缺页事件继续使用各自的报告接口，不会转换为 CPU 样本。

## 显式导出与工具流水线

```bash
cargo build -p bpf-analyzer
target/debug/bpf-analyzer session.pbcapture \
  --bundle /path/to/capture-bundle \
  --pid 123 --mode user --from-ns 1000000 --to-ns 2000000 \
  --weight period --perf-data /path/to/output/perf.data

python3 scripts/perf_pipeline.py /path/to/output/perf.data \
  --manifest /path/to/output/perf.data.json \
  --bundle /path/to/capture-bundle \
  --perf /usr/local/bin/perf \
  --flamegraph /path/to/FlameGraph \
  --output /path/to/new-report-directory
```

示例 PID 和时间窗需替换为实际 capture 中的值。导出与 table、JSON、folded
共用 Query，先关联全部历史再筛选；窗口之外的映射前史仍可用于解释窗口内的样本。
不传筛选参数即选择全部记录。`--bundle` 必须显式指定，它包含采集时保存的
`artifacts/<sha256>.elf`，不能用主机上同名 ELF 替代。
table 的 RECORD/SOURCE 列和 JSON 的 `cpu_samples` 保留原记录序号及逻辑 source；
`sample_weight` 只汇总 CPU 样本，混合会话中的 sched/fault 仍保留各自事件语义。

导出同时写 `FILE` 和 `FILE.json`。校验失败时不覆盖现有报告；capture 或已验证 ELF
与任一输出、多个输出之间的同文件及硬链接冲突均拒绝。I/O 中断可能留下不完整的文件对，
流水线必须核对 manifest 中的 perf.data SHA-256 才能消费。

外部工具路径由调用者提供，运行时不下载。FlameGraph 固定为
[`41fee1f99f9276008b7cd112fca19dc3ea84ac32`](https://github.com/brendangregg/FlameGraph/tree/41fee1f99f9276008b7cd112fca19dc3ea84ac32)，
按脚本内容哈希验证，不能只修改版本标签。流水线保留未修改的 `perf report`、
`perf script`、`perf buildid-list` 输出和实际工具版本，并核对 folded 总权重与 SVG 单位。
一个 Query 含多个软件时钟时，逐事件调用固定 collapser、核对各自权重，再在图中
以事件名分组；不会只保留 collapser 默认选择的第一个事件。

## 单位与完整性

`--weight samples` 表示样本条数，`--weight period` 表示 `period_ns`。
perf.data 中的 `PERF_SAMPLE_PERIOD` 始终保留真实软件时钟增量，不能为了按样本计数
而把 period 改成 1。两种图表必须分别核对条数和 period 总和；空选择保持零权重。
perf attr 按 typed source 写入有效 cpu-clock/task-clock 配置、实际 period/frequency
模式及 `use_clockid`/`CLOCK_MONOTONIC`。请求参数和降级事实仍在 manifest 中单独保留。

导出不补造调用者。仅有 IP 的样本只能表示 IP；已捕获的栈前缀保留原始地址顺序和
终止状态，partial/unavailable 不变为完整调用链。混合 user/kernel 链必须有可信的
上下文分界，不能按地址大小猜测所属模式。当前单域 stack-v3 不包含这种分界。

只接受当前 capture v6 的显式来源契约。v2 单 IP 和 v3 栈样本均通过原记录的
`sequence_index` 查找 `record_sources`，排序、筛选不会改变绑定。同 CPU、同 period
的不同实例分别保留；不读取 diagnostics 字符串猜测来源。perf 的 identifier 使用
逻辑 source ID，v3 context 的 kernel source ID 只与声明的 `kernel_event_id` 核对，
两者不混用。task source 按稳定 kernel task identity 和启停窗口验证；nonleader exec
改变 numeric TID 后仍属于原 source，重用相同 PID/TID 的新 task 不继承绑定。
合法的 unavailable 空链保留真实 IP 和 period，perf 的 CALLCHAIN 长度为零；
folded 保留原因标记及权重。两者都不会补造调用者，manifest 保留栈终止原因和
`attribution_incomplete_reasons`。

缺失、内容不匹配的 ELF，以及不能证明采样时映射归属的样本，严格导出失败；可以
使用明确的 Query 选择已有证据的范围，但不能把被排除范围的未知或丢失改写为零。
原 capture 和 manifest 保留 capture 级诊断及所选范围，函数图不代表完整 CPU 利用率。
source skipped、栈截断、全局队列损失和输出 transport loss 有不同口径，不相加为
一个 CPU 样本丢失数。
拒绝导出时错误说明具体缺失证据，不写成功 manifest；成功 manifest 中的 partial/unknown
原因不因符号解析成功而消失。

当前支持 ELF 内嵌调试信息；独立 debug ELF 在缺少显式 consumer staging 时拒绝。
内核任务若只有共享的 PID/TID 0/0，名称保持 unknown，原始 stable task identity
保存在 manifest，不把它猜作某个 idle 任务。
真实 GNU build-id 缺失保持 absent，不截取 SHA 伪装 build-id。Linux v6.12 导出子集
支持最长 20 字节的实际 GNU build-id，超出时明确报错。
原生 `buildid-list` 可以省略没有 GNU note 的 ELF；所有实际 build-id 仍必须逐一匹配，
也不允许缺 note 的 ELF 获得伪造 ID。

## 消费端 ELF 符号视图

实际 kernel 和用户 ELF 都可能包含本地 `STT_NOTYPE` 的 `.L` 调试标签及 RV64 ISA
映射标记；perf 6.8.12 会优先把它们展示为函数名。流水线从已经通过 capture SHA
校验的原 ELF 生成单独的符号视图，只把这些已识别的本地非函数标签的 visibility
改为 hidden。所有 PT_LOAD 文件字节、真正函数的地址/大小/名称保持一致；原始
ELF 不修改。kernel 视图作为 `--vmlinux`，用户视图位于新报告目录的 `symfs/`
并作为 `--symfs`；不得借助 artifact 路径逃出该目录。输出记录原始与派生 ELF
SHA、修改数、转换规则和视图工具 SHA，用户条目还记录原 artifact 路径与派生路径。
这是一项已声明的 consumer 适配，不把派生文件的 SHA 当作采集时身份。

当前安装的 perf 6.8.12 对这批 Rust v0 符号保留原始修饰名，例如已保存的
`sample_leaf` 函数在报告中带有 `_RNv…` 前缀。流水线保留原样 perf 输出和真实
`STT_FUNC` 名称，验收从匹配 ELF 的函数符号确定期望链，再核对 script、calltree
和 SVG；不会重命名函数或把汇编标签猜作函数。

## 兼容边界与验收

写入格式采用 Linux v6.12 的小端、可 seek、未压缩 PERFILE2 子集；实际 consumer
版本独立记录，格式基线不等于 consumer 版本。参考
[Linux v6.12 UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/perf_event.h)、
[文件格式](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf.data-file-format.txt)
及仓库的[逐字段研究](research/perf-data-minimal-subset.md)。

验收分别检查文件解析、真实 ELF 函数归属、真实多层调用链及图表权重。合成 fixture
负责确定的负例和 wire 格式；RV64/LA64 的原始 RAW、capture 和匹配 ELF 负责真实采样
链路。命令和结果见 [#194 验收记录](../records/bpf-perf-export-194.md)。
当前通用 recorder 的回归与原 capture 重放见 [#212 验收记录](../records/bpf-recorder-perf-212.md)。
生产构建的双架构完整流程见 [#213 验收记录](../records/bpf-recorder-e2e-213.md)。
