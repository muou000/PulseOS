# PulseOS perf.data 最小兼容子集研究

- 对应地图：[#180 完善 eBPF 性能采样功能](https://github.com/muou000/PulseOS/issues/180)。
- 对应 research：[#181 调研 perf.data 格式的最小兼容子集](https://github.com/muou000/PulseOS/issues/181)。
- 研究日期：2026-11-14。
- 格式及实现依据：**Linux v6.12 固定 tag** 的 UAPI、perf writer、reader 和命令文档。v6.12 是本研究的兼容基线，不表示最新 Linux 版本。源码中的 `perf.data-file-format.txt` 自称主体更新至 v4.7，涉及歧义时以同 tag 的 UAPI 和实际 reader/writer 为准。[S1][S2][S3]
- 状态：研究结论与实现建议；不表示 PulseOS 已实现 CPU 调用栈采样或 perf.data 导出。

## 结论与范围

建议第一阶段由用户态/主机转换器生成 **可 seek 的、未压缩的 PERFILE2 文件**，先支持一个软件 CPU-clock 事件及其多个 CPU 实例，输出已展开的 `PERF_SAMPLE_CALLCHAIN`。配套 `COMM`、可执行映射、进程生命周期和丢样记录，携带目标架构和实际 ELF build-id；使用匹配内核 ELF 与用户 ELF 在 Linux 主机上运行 `perf report` / `perf script`。不要求 PulseOS 内核运行 Linux perf，不要求把 BPF Perf Buffer 的 mmap 内容原样保存为 perf.data。[S1][S2][S3][S4]

这是本研究的**推荐导出契约**，需要后续实现票采纳；它不是 Linux 对所有合法 perf.data 的最小强制集合。以下分清三个层次：

| 层次 | 可验证结果 | 本阶段要求 |
| --- | --- | --- |
| 文件解析 | header、attr、ID、record 边界合法，工具能读完 | 必须，但单独通过不代表热点有效 |
| 符号化热点 | sample IP 与 pid/tid 对应正确映射，解析到匹配 ELF 的函数 | 必须，内核和用户态分别验证 |
| 调用链分析 | 栈帧顺序、内核/用户上下文、权重正确，能展示调用树并导出折叠栈 | CPU profiling 的交付门禁；栈截断和失败必须显式记录 |

数据分析仍保留 PulseOS capture 的构建身份、schema、分层 loss/error 和完整性事实。perf.data 是 Linux 分析工具的互操作产物；标准 `LOST` 无法完整表示 PulseOS 所有失败原因，不应以成功导出文件代替 capture 完整性判断。此处建议不裁定 #187/#188 的统一工具入口或默认文件格式。[P1][S2]

## 1. 当前仓库事实与本研究解决的缺口

当前 `tgoskits/apps/starry/ebpf/profile` 是 `raw_syscalls:sys_enter` 的 syscall 次数直方图：BPF 程序按 syscall number 更新 Hash Map，loader 打印计数。它没有 CPU 采样 IP、调用栈、映射历史或 perf.data writer，不能把现有直方图还原成真实 CPU 样本。[P2]

`pulse_core/src/bpf/perf_event.rs` 已定义 CPU/task clock、BPF output、SAMPLE/LOST 和软件 tick 模型，但本次地图代码审计还发现真实 timer/tracepoint 分发未接通、guest smoke 固定构造输出的缺口，分别记录为 #190/#191。因此现有模型/格式 smoke 不证明真实采样已经可用。`pulse_bpf_schema` 的现有事件记录是有界 tracepoint context；不能仅改文件头就声称成为完整 CPU profile。[P3][P4][P7]

ADR-0005 记录了旧 #77 路线图的 fixed-layout BPF v1 与具名上游工具兼容层级，且把硬件 PMU 排除于当时目标之外。维护者已在 #130 的关闭评论中明确转向“完善 PulseOS 自有采样能力”，上游 profile 移植不再是新目标。因此本研究不把旧具名工具层级作为 #180 的交付前提；#186 应协调历史 ADR 与当前 Linux 移植边界。#182 决定栈捕获，#183 决定 PMU 边界，#187/#188 决定工具与 capture 集成；本研究不默默改写旧 ABI。[P1][P5][P6]

## 2. 文件容器：PERFILE2、section 与 attribute

### 2.1 固定 header

Linux 的格式采用采集端字节序，magic 可用于识别字节序；本阶段支持的 RV64/LA64 产物统一显式写小端整数，不把主机语言结构体、padding 或本机指针直接转储到文件。64 位标准 file header 为 104 bytes；各 section 均是文件起点相对的 `u64 offset, u64 size`。[S1][S3]

| 字段（文件偏移） | 编码 | 必需性与推荐值 |
| --- | --- | --- |
| `magic` (0) | 8 bytes | 必须，字节串 `PERFILE2` |
| `size` (8) | `u64` | 必须，104 |
| `attr_size` (16) | `u64` | 必须，**每个 perf_file_attr 的总大小**；推荐 80，不是 64 |
| `attrs` (24) | `offset, size` | 必须，指向 attribute entries；size 是 entry count × 80 |
| `data` (40) | `offset, size` | 必须，指向完整 event stream；结束后回填真实长度 |
| `event_types` (56) | `offset, size` | 废弃/忽略，写 0、0；不能拿它代替 attrs |
| `adds_features` (72) | 256-bit bitmap，32 bytes | 必须存在；仅为确实写出的 feature 设置 bit；bit 0 保留为 0 |

推荐布局如下。ID 数组可以在 attrs 之前；读者依据 offset，不应假定它们紧接某个固定区域。feature descriptor table 的位置则固定为 `data.offset + data.size`，按已设置 feature bit 的升序写 `{offset,size}`，每项 16 bytes；它指向后面的 feature payload。[S1][S3]

```text
104-byte header
u64 event-instance IDs[]
perf_file_attr entries[]
data: COMM / MMAP / FORK / SAMPLE / LOST / EXIT ...
feature section descriptors[]  ← 必须紧接 data
feature payloads[]
```

推荐转换器先完成数据与元数据校验，再原子替换最终输出文件。中断文件保留为临时产物并报告 incomplete；`data.size=0` 不是“流直到 EOF”的常规完成标志，perf reader 会对此警告。pipe-mode、目录格式、压缩、AUX 和 `FINISHED_ROUND` 不属于首版 writer；离线转换可将完整事件按时间及因果顺序排序。[S1][S3]

### 2.2 `perf_file_attr` 与 event ID

`perf_file_attr = perf_event_attr + perf_file_section ids`。首版字段都位于 `PERF_ATTR_SIZE_VER0=64`，因此推荐 `perf_event_attr.size=64`、header `attr_size=64+16=80`；本次 fixture 实测采用此布局。若后续需要 `clockid`、register/stack 等扩展，必须提升 attr.size 到覆盖相应字段的合法版本；采用 v6.12 完整 `PERF_ATTR_SIZE_VER8=136` 时 header.attr_size 必须为 152，并把未使用扩展清零。reader 先按 **attr 自身的 size** 消费字节，再读取 ids section；两种 size 不一致会导致 ID/下一 entry 错位。不要把“parser 接受旧版本”理解为任意截断皆可。[S2][S3]

| attr 字段 | 推荐值/语义 | 必需性 |
| --- | --- | --- |
| `type: u32` | `PERF_TYPE_SOFTWARE=1` | 必须，首版描述真实软件事件 |
| `size: u32` | 64 | 必须，与序列化长度匹配 |
| `config: u64` | `PERF_COUNT_SW_CPU_CLOCK=0`；task-clock 应独立建 attr | 必须，不能把 timer 样本标成硬件 cycles |
| `sample_period/sample_freq: u64` | 实际配置；由 `freq` bit 决定解释 | 必须，不与每条样本的实际 `period` 混淆 |
| `sample_type: u64` | `IDENTIFIER \| IP \| TID \| TIME \| CPU \| PERIOD \| CALLCHAIN` = `0x101a7` | 本导出契约必须 |
| `read_format: u64` | 首版 0 | 必须存在；不启用未序列化的 READ payload |
| flags `sample_id_all` | 1 | 本导出契约必须，保证非 SAMPLE 事件有时间/身份 |
| flags `freq`、`exclude_*` | 反映实际采样配置 | 必须真实；没有精确 IP 保证就不设 `precise_ip`/EXACT_IP |
| flags `mmap`、`comm`、`task`、`comm_exec` | 对应本次采集/合成的元数据能力 | 按实际设置；不能代替真的写出记录 |
| flags `mmap2`、`build_id` | 仅采用相应 MMAP2 采集语义时设置 | 可选，首版 MMAP 路径为 0 |
| `use_clockid`、`clockid` | 最小 attr 不启用；需要时提升 attr.size 并确认与 Linux clock ID 语义一致 | 条件；不得把任意 cycle counter 冒充 monotonic ns |
| `wakeup_events/watermark`、`bp_type`、`config1` | 首版不用，写 0 | 位于最小 64-byte attr 内 |
| `config2/3`、`branch_sample_type` | 首版不序列化；完整 attr 模式写 0 | 扩展字段，不能越过 attr.size 写入 |
| `sample_regs_user/intr`、`sample_stack_user`、AUX、`sig_data`、扩展保留字段 | 首版不序列化；完整 attr 模式写 0 | 不启用 DWARF/register/AUX payload |
| `sample_max_stack` | 最小 attr 不序列化；扩展模式与实现限制一致或写 0 | 可选；文件中的实际 `nr` 仍须检查 |
| entry 尾部 `ids.offset/size` | 指向该 attr 的 `u64 IDs[]`，size 为 8 的倍数 | 本导出契约必须 |

Event ID 标识本次采集的事件实例，不是 PID、tracepoint ID、Map ID 或数组下标。一个 attr 可关联多个 per-CPU 实例 ID；所有 SAMPLE 的 IDENTIFIER 与非 SAMPLE trailer 的 IDENTIFIER 都必须能查回正确 attr。首版即保留 IDENTIFIER，避免以后多事件合并遇到不同 sample layout 的识别歧义；所有 attr 的 `sample_id_all` 保持一致。[S1][S3][S4]

## 3. 通用 record header 与 `sample_id_all`

所有 data records 以 8-byte `perf_event_header` 开始：`type:u32, misc:u16, size:u16`；size 包含 header、payload、字符串 padding 和 trailer。推荐所有记录按 8 bytes 对齐、保留字节清零、字符串 NUL 结束；必须在写入前检查 `size <= 65535`、长度运算溢出和 section 越界。`misc & PERF_RECORD_MISC_CPUMODE_MASK` 对 sample/映射区分 `KERNEL=1`、`USER=2`；“QEMU 内的 PulseOS”本身不等于 perf 的 host/guest 合并记录，不应因此改用 GUEST marker。[S2][S4][S5]

当 `sample_id_all=1` 时，支持的非 SAMPLE 内核记录在原 payload 后按下列**固定顺序**追加 sample_id。只追加 `sample_type` 选中的项，不能照 SAMPLE 全部字段复制；尤其不追加 IP、PERIOD 或 CALLCHAIN。feature payload、file attr 和 perf 自己的用户类型记录没有因此自动获得这种 trailer。[S2][S4]

| 顺序 | 条件 | 字段 | 首版 |
| --- | --- | --- | --- |
| 1 | `PERF_SAMPLE_TID` | `pid:u32, tid:u32` | 8 bytes |
| 2 | `PERF_SAMPLE_TIME` | `time:u64` | 8 bytes |
| 3 | `PERF_SAMPLE_ID` | `id:u64` | 不启用 |
| 4 | `PERF_SAMPLE_STREAM_ID` | `stream_id:u64` | 不启用 |
| 5 | `PERF_SAMPLE_CPU` | `cpu:u32, reserved:u32=0` | 8 bytes |
| 6 | `PERF_SAMPLE_IDENTIFIER` | `id:u64` | 8 bytes |

因此首版 trailer 长度为 **32 bytes**。IDENTIFIER 在 SAMPLE 中是 header 后第一个字段，在非 SAMPLE trailer 中却是最后一个字段。`COMM`/`MMAP` 的字符串必须先补齐，再放 trailer；FORK/EXIT 的原生 `time` 仍须保留，不能被 trailer 时间替代。[S2][S4]

对合成的初始任务/映射快照，转换器应记录快照时间并确保它先于对应样本；动态记录保留实际时间，不能全部归零。多 CPU 数据要按时间排序，并在相同时间保持原 CPU 顺序及 `FORK → COMM/MMAP → SAMPLE → EXIT` 的已知因果约束；未知先后不可凭排序伪造。`sample_id_all=0` 的文件可被解析，但 perf 会在有序消费路径降级，因此不是本契约的推荐模式。[S1][S6]

## 4. 各记录的字段和必需性

“必须”指本推荐的 CPU profile 导出；“条件必须”指相应事实发生/该范围开启时必须提供；“可选”不是让 writer 省略已经启用的 record 内字段。

### 4.1 `PERF_RECORD_SAMPLE=9`

只序列化 sample_type 选择的字段，必须遵循 UAPI 的排列顺序，**不是按 bit 数值升序**。首版结构如下。[S2][S4]

| 顺序 | 字段 | 大小 | 必需性与含义 |
| --- | --- | --- | --- |
| 0 | header | 8 | 必须；misc 描述采样 IP 的 privilege mode |
| 1 | `identifier` | 8 | 必须；事件实例 ID |
| 2 | `ip` | 8 | 必须；采样时被中断代码的 PC，不是 BPF helper 的 PC |
| 3 | `pid, tid` | 4 + 4 | 必须；进程与线程不能交换，映射按所属进程关联 |
| 4 | `time` | 8 | 必须；统一的纳秒采样时钟 |
| 5 | `cpu, reserved` | 4 + 4 | 必须；CPU 是采样时 CPU，reserved=0 |
| 6 | `period` | 8 | 必须；本样本代表的实际事件增量，不能填写频率 Hz |
| 7 | `nr` | 8 | 必须；紧随其后的 64-bit callchain entries 数量，包含 context markers |
| 8 | `ips[nr]` | 8 × nr | 成功捕获时必须；从叶到根，保留上下文分界 |

总大小为 `64 + 8*nr`。如果未得到调用链，仍可输出可靠的 IP 样本，但必须在 capture/伴随元数据中累计 stack unavailable/truncated 原因，不得构造假的完整栈。若不承诺调用链的独立 IP-only 模式选择移除 CALLCHAIN bit，则必须同时移除 nr/ips，成为另一个明确的样本配置。[S2][S4]

period 是 perf 的事件权重；频率调节场景下各样本 period 可以不同。热点统计与折叠栈必须明确采用样本次数还是 period 加权；生成火焰图时不得默认把每条不等权样本视作等量 CPU 时间。首版建议固定 period，保留实际 period，以使这一验证简单且可扩展。[S2][S4][S7]

### 4.2 `PERF_RECORD_MMAP=1` 与 `PERF_RECORD_MMAP2=10`

MMAP 将采样虚拟地址关联到 ELF 文件。对每个参与符号化的用户可执行映射、内核 text 映射，以及采样期间新发生的 exec/mmap，**映射元数据条件必须**；只有原始数值 IP 的文件不满足函数级热点交付。[S2][S5][S8]

| MMAP 字段 | 大小 | 必需性与语义 |
| --- | --- | --- |
| header | 8 | 必须，用户映射 USER；主内核映射 KERNEL |
| `pid, tid` | 4 + 4 | 必须；用户地址空间的 PID 与对应 TID；内核合成记录按 perf machine 约定 |
| `addr` | 8 | 必须；运行时映射起始虚拟地址 |
| `len` | 8 | 必须；该映射的字节长度，不是结束地址 |
| `pgoff` | 8 | 必须；用户映射为**文件字节偏移**，不是页号；内核特殊格式见 §5 |
| `filename[]` | NUL 字符串 + padding | 必须；目标机的稳定路径/映射名，不是主机偶然的临时文件名 |
| `sample_id` | 32 | 本契约必须；映射生效时间及来源实例 |

MMAP2 在 `pgoff` 后、filename 前增加以下字段，其余同 MMAP；`filename` 前固定部分总计 72 bytes（含 header）。首版 **MMAP + HEADER_BUILD_ID** 已足以建立所需映射和构建身份，因此 MMAP2 可以分阶段加入，不应为了伪造 Linux inode 信息而阻塞导出。[S2][S5]

| MMAP2 扩展 | 大小 | 必需性与条件 |
| --- | --- | --- |
| union 的 inode 形式：`maj:u32,min:u32,ino:u64,ino_generation:u64` | 24 | 未设置 misc `MMAP_BUILD_ID` 时使用；内容反映真实文件身份 |
| union 的 build-id 形式：`build_id_size:u8,res1:u8,res2:u16,build_id[20]` | 24 | 设置 misc `PERF_RECORD_MISC_MMAP_BUILD_ID` (bit 14) 时使用；保留字段 0；不能与 inode 形式叠加 |
| `prot:u32, flags:u32` | 8 | 采用 MMAP2 时必须，描述真实映射属性 |

ASLR、PIE、共享库和非零 pgoff 都要求正确的 `addr/len/pgoff` 与 ELF PT_LOAD 关系；不能只做“IP 减 ELF 文件起始地址”。相同 PID 的 exec、新映射覆盖旧映射、fork 继承和 PID 重用必须由有序 metadata 描述。Linux 没有一个通用 `PERF_RECORD_MUNMAP` 记录可随意新增；首版限制/测试范围应写明，不能给自定义类型套一个 Linux 编号。[S2][S5][S8]

### 4.3 `PERF_RECORD_COMM=3`

| 字段 | 大小 | 必需性与语义 |
| --- | --- | --- |
| header | 8 | 必须；exec 导致的 COMM 设置 misc `COMM_EXEC` (bit 13) |
| `pid, tid` | 4 + 4 | 必须；每个被采样线程的身份 |
| `comm[]` | NUL 字符串 + padding | 必须；任务名，不等同完整命令行或 ELF 路径 |
| `sample_id` | 32 | 本契约必须 |

初始线程快照及后续改名/exec 必须进入采集；仅凭 sample 的 PID 会造成 `[unknown]` 或误归属。exec 标记有地址空间/任务状态含义，不能把所有 COMM 都标成 exec。[S2][S5]

### 4.4 `PERF_RECORD_FORK=7` / `PERF_RECORD_EXIT=4`

两者 payload 相同；对采样窗口内发生的相关创建/退出**条件必须**，静态单进程 fixture 可以没有。FORK 表示子线程/进程与父线程/进程关系，使 perf 可以继承映射与 comm；退出和 PID 重用是时间线正确性的验收项。[S2][S5][S9]

| 字段 | 大小 | 必需性与语义 |
| --- | --- | --- |
| header | 8 | 必须；type 区分 FORK/EXIT |
| `pid, ppid` | 4 + 4 | 必须；事件线程所属进程 ID、其父进程 ID |
| `tid, ptid` | 4 + 4 | 必须；事件线程 ID、父线程 ID |
| `time` | 8 | 必须；事件发生时间，不省略 |
| `sample_id` | 32 | 本契约必须；与本体时间同一时基 |

总大小 64 bytes。不能把 Linux PID/TID 填入内核内部 task pointer；如果 PulseOS 内部 ID 范围/身份与 Linux u32 不一致，采集端必须明确映射并保持窗口内稳定，而不是截断碰撞。

### 4.5 丢样与暂不支持的类型

`PERF_RECORD_LOST=2` 结构为 header、`id:u64`、`lost:u64`、sample_id（本契约共 56 bytes）。发生可归属的丢失时条件必须；id 指向受影响事件实例，lost 是该事件输出路径丢失的记录/事件数，不能填丢失 bytes；传输层可能丢失 SAMPLE 以外的记录，不能无条件把它解释为 CPU 样本数。`PERF_RECORD_LOST_SAMPLES=13` 只有 lost 加 trailer，是另一种语义/布局；首版统一选 LOST，避免重复记账。[S2][S4]

对 BPF re-entry、helper failure、预算超限、transport full、用户消费失败、栈截断等不同事实，保留 capture 原因计数；导出 CPU 样本丢失时，只有能证明“恰好未产生多少条 CPU 样本”的事实才合成相应 LOST；原始 transport LOST 应保留其丢记录口径，不能与丢 metadata、栈失败等计数混算。栈截断但 IP 样本仍在，不等于整个 sample 丢失。转换器不能吞掉未知损失或把未知数写成 0。首版不写 READ、BRANCH_STACK、REGS、STACK_USER、AUX、BPF_PROG_INFO、BTF、私有 RAW 事件；新增调度/缺页 tracepoint perf.data 需要另行处理 event format metadata 与 `HEADER_TRACING_DATA`，不能把它们冒充 CPU-clock sample。[P1][S1][S2]

## 5. 符号、build-id 与元数据 features

### 5.1 文件需要的 features

features 并非解析样本的全部硬前提，但下表区分本项目需要可靠互操作时的要求。[S1][S3]

| Feature | bit | 推荐要求 | payload / 用途 |
| --- | --- | --- | --- |
| `HEADER_BUILD_ID` | 2 | 本阶段符号化交付必须；没有真实 build-id 时先明确降级/补构建支持 | 每个相关 DSO/内核的 build-id 记录列表 |
| `HEADER_OSRELEASE` | 4 | 建议 | 字符串，记录 PulseOS 构建版本而非导出主机 Linux 版本 |
| `HEADER_VERSION` | 5 | 建议 | 字符串，标明 writer 版本；不能冒充由 perf v6.12 采集 |
| `HEADER_ARCH` | 6 | **跨架构必须** | 字符串 `riscv64` 或 `loongarch64`，是采集目标架构 |
| `HEADER_NRCPUS` | 7 | 建议 | `u32 available,u32 online` |
| `HEADER_CMDLINE` | 11 | 建议 | `u32 nr` + 字符串列表，保存真实采样命令 |
| `HEADER_EVENT_DESC` | 12 | 建议，尤其多事件时 | nr/attr_size、各 attr、nr_ids、名称、IDs；此处 attr_size 是 **64**，不是 file attr 的 80；若升级为完整 attr 则分别为 136/152 |
| `HEADER_SAMPLE_TIME` | 21 | 建议 | `u64 first_sample,u64 last_sample` |
| `HEADER_CLOCK_DATA` | 29 | 条件 | 有可靠时钟对应关系才写 `u32 version=1,u32 clockid,u64 wall_clock_ns,u64 clockid_time_ns` |

feature string 为 `u32 len` 加包含终止 NUL 与 padding 的字节串；len 必须覆盖实际写入长度，建议遵循 perf writer 的字符串 padding。metadata 中不得把 host uname 当成 target architecture：缺 ARCH 时 perf 会假定本地主机架构，这在 x86 主机分析 RV/LA 时会隐藏错误。[S1][S3][S10]

### 5.2 build-id 不是符号表

推荐构建产物使用真实的 **20-byte GNU ELF build-id**，保存内核和所有被映射用户 ELF/共享库，检查 `.note.gnu.build-id` 后写文件。不把 git SHA、任意文件 hash 或文件名当成 ELF build-id；超出本契约支持长度的 ID 必须明确拒绝/改构建配置，不能静默截断为另外一个身份。build-id 用于选择和核对 ELF；它不携带 `.symtab`、DWARF 或源文件。[S11][S12]

`HEADER_BUILD_ID` payload 是变长 build-id entries。v6.12 `perf_record_header_build_id` 的固定前缀为 36 bytes：header (8)、`pid:s32` (4)、24-byte union；现代形式为 `data[20],size:u8,res1:u8,res2:u16`，随后 filename。设置 misc `PERF_RECORD_MISC_BUILD_ID_SIZE` (bit 15) 表示 size 有效；没有这个 bit 的历史形式默认 20-byte ID。**这与 MMAP2 的 size 在 ID 之前的 union 不同**，不可复用同一序列化结构。[S3][S11]

| build-id entry 字段 | 本阶段约定 |
| --- | --- |
| `header.type` | 可采用 `PERF_RECORD_HEADER_BUILD_ID=67`；feature reader 按 entry size 消费，不能把 feature 当 data 中 SAMPLE 来解析 |
| `header.misc` | USER 或 KERNEL，再加 BUILD_ID_SIZE；不是 MMAP_BUILD_ID |
| `header.size` | 包含 fixed prefix、NUL 文件名及对齐 padding |
| `pid` | 普通单机器文件使用 perf host machine ID **-1**；这里不是被采样进程 PID |
| `data[20],size,reserved` | 真实 build-id，推荐 size=20，保留字段 0 |
| `filename` | 用户 DSO 与 MMAP 路径匹配；内核使用与 perf 主内核 DSO 对应的名字 |

采用显式 artifact bundle：`perf.data`、对应的完整内核 ELF、按目标绝对路径组织的用户 ELF 根目录、构建清单和 capture 完整性信息。运行时为 perf 指定 `--vmlinux <matching-kernel-elf>` 与 `--symfs <target-root>`；build-id cache 可以作为便利手段，但不依赖主机刚好存在同名二进制。`kernel-rv/kernel-la` 是否是含符号 ELF 必须用文件类型/ELF notes 检查，不能仅靠文件名判断。[S7][S12][S13]

### 5.3 内核与用户地址的特别处理

用户映射用目标运行时地址与文件字节偏移，perf 再结合 ELF 的 segment/符号表完成地址转换；PIE、共享库和非零 pgoff 要单独验证。推荐保留未剥离 ELF 或匹配的独立调试文件，函数名通常依赖符号表，源码行/内联函数需要额外调试信息；Rust demangling 是工具展示能力，不能作为二进制布局正确性的替代证据。[S8][S12][S13]

主内核映射应沿用 perf 的合成格式：misc=KERNEL，filename 为 `[kernel.kallsyms]` 加真实的参考符号名（例如 `_text`），addr/len 覆盖实际 text，`pgoff` 填该参考符号的**运行时地址**。这不是用户 mmap 的文件 offset 语义。perf reader 根据参考符号与匹配 ELF 处理重定位；直接把 `/tmp/kernel.elf` 写成内核 mmap filename 可能进入 module 分支，而不是主内核映射。[S5][S14]

PulseOS 应选择自身 ELF 确实存在的 text 参考符号，并测试有/无重定位两种情况，不假设 Linux `_stext` 在 PulseOS 存在。`--kallsyms` 可作为另一个受控符号输入，但绝不读取分析主机的 `/proc/kallsyms` 来解释 PulseOS 地址。[S5][S13][S14]

## 6. 调用链：首版已展开 CALLCHAIN，DWARF 后续独立验收

### 6.1 文件中的 CALLCHAIN

`PERF_SAMPLE_CALLCHAIN` 是地址序列而非帧指针链，也不是 DWARF 栈字节。叶到根序列通过 `PERF_CONTEXT_KERNEL=(u64)-128`、`PERF_CONTEXT_USER=(u64)-512` 切换后续地址的 privilege mode；marker 计入 nr，不是可符号化的 PC。示例为：kernel marker、采样 kernel PC、kernel callers、user marker、被中断 user PC、user callers。只捕获一个域时只输出该域，不能为凑“完整栈”复制另一个时刻的用户栈。[S2][S5]

一个 SAMPLE 的 `misc` 只能描述初始 CPU mode，不能替代混合 callchain 的 context markers。不能颠倒为 root-first 后仍宣称 Linux 原始 callchain；perf 的 caller/callee 选项是在展示阶段决定。标准 callchain 本身没有本项目所需的详细截断原因字段，因此深度限制、读用户内存失败、不可展开帧等事实保留在 capture/manifest。[S2][S5][S7]

### 6.2 FP 与 DWARF 比较

| 路径 | 采集端必须保存 | perf.data 字段 | 前提/限制 | 建议 |
| --- | --- | --- | --- | --- |
| 内核/用户 FP 栈展开 | 采样时正确 PC/SP/FP 与有界、安全的栈读取；展开后的地址 | CALLCHAIN | 需要实际保留 frame pointer；优化、尾调用、leaf/异步 trap 边界可能丢帧 | 首版优先；#182 决定 ABI、安全边界、深度和失败状态 |
| 用户 DWARF 离线展开 | 用户寄存器快照、用户栈字节、架构、匹配 ELF/CFI | REGS_USER + STACK_USER，必要时并存内核 CALLCHAIN | 需要匹配寄存器枚举、CFI、目标架构 unwind backend；截断 stack dump 不能恢复未采集字节 | 后续独立模式，不阻塞首版 |
| 内核 DWARF/其他展开器 | 对应内核展开器和元数据 | 通常导出已展开内核 CALLCHAIN | Linux perf 的 user `--call-graph dwarf` 不意味着能从任意内核栈离线展开 | 不作为 perf.data 首版要求 |

Linux `perf record --call-graph fp/dwarf` 文档明确区分用户展开方式与内核配置；FP 遇到省略帧指针的代码可得到错误链，DWARF 用户方式记录 stack dump 并依赖 libunwind/libdw。由此不能在 #181 仅凭文件格式承诺所有用户程序都能获得完整调用栈。[S15]

若后续启用 DWARF，必须按 UAPI 顺序新增：`REGS_USER={abi:u64, regs[popcount(sample_regs_user)]}`，`abi=NONE` 时没有寄存器数组；`STACK_USER={size:u64,data[size],dyn_size:u64}`，但 **size=0 时不写 dyn_size**，dyn_size 是实际有效字节数。寄存器按目标架构 mask 的 bit 顺序，不能把 Rust trap frame 整体转储；IP/SP 等必须在 mask 和实际数组中一致。设置 sample_regs_user/sample_stack_user 并提供匹配 debug/CFI 只是必要条件，仍需验证目标 backend。[S2][S4][S16]

### 6.3 RV64/LA64 在 x86 Linux 主机上的边界

PERFILE2 的字段编码与已展开 CALLCHAIN 不要求主机执行目标 ISA；因此“x86 perf + 真实 RV/LA ELF + 正确映射 + 已展开地址链”是合理的首版验证目标，但必须实测目标 ELF 的函数名/栈顺序，不能只改 HEADER_ARCH 字符串就声称跨架构通过。[S3][S5][S8]

相反，v6.12 的 libdw 初始寄存器设置由 `arch/riscv/util/unwind-libdw.c`、`arch/loongarch/util/unwind-libdw.c` 等架构文件提供并按构建选项编入；libunwind 的远程 backend 选择也不是“所有目标架构自动支持”。**x86 主机能读 RV/LA 符号，不等于它能离线展开 RV/LA 的用户 DWARF 栈**。后续必须锁定 perf 构建、libdw/libunwind 版本与 backend，分别测试；不支持时要求目标架构 perf 或显式支持该目标的分析器，不能静默退成看似完整的栈。[S16][S17][S18]

## 7. `perf report`、`perf script` 和火焰图的最小依赖

纯软件 SAMPLE + 已展开 CALLCHAIN 的离线分析不需要采集主机的 PMU 或打开 live perf event；需要的是可执行的 perf reader、有效 attr/ID、记录、映射和匹配符号产物。build-id cache、TUI、Python scripting、tracepoint decoding、DWARF unwind 是分别可选/条件依赖；若选择 raw tracepoint 或 DWARF，其相应库和元数据就进入门禁。先使用 `--stdio`/普通 `perf script` 验证，避免把终端 UI 缺失误认为文件格式失败。[S3][S4][S7][S13][S15]

建议验收命令（参数路径由 artifact bundle 提供；以下不是已完成的 PulseOS 运行记录）：

```bash
perf version --build-options
perf report --header-only -i perf.data
perf report --stdio --no-children -i perf.data \
  --vmlinux artifacts/kernel.elf --symfs artifacts/rootfs
perf script -i perf.data \
  --vmlinux artifacts/kernel.elf --symfs artifacts/rootfs
perf buildid-list -i perf.data
```

`perf report` 给热点/调用树，`perf script` 给按样本排列、可包含调用链的文本；SVG/HTML 火焰图还需要折叠/渲染步骤，不能把“perf 能 parse”直接写成“已生成正确火焰图”。#188 应锁定 fold/render 工具版本、caller/callee 方向、Rust demangling、线程/CPU 过滤、period 或次数权重，并验证折叠权重之和与原始样本一致。[S7][S13]

不要求原生 Linux `perf record` 在 PulseOS 运行，也不需要先实现 BTF/CO-RE、bpffs 或硬件 PMU 才能写此离线格式。格式转换本身不证明所声明采样事实真实：采样 IP 必须来自执行上下文，内核/用户地址与身份必须来自同一次采样，metadata 必须覆盖该采样窗口。

## 8. 测试优先的后续验收矩阵

实现票先提交/确定可复现 fixture 与预期输出，再接入真实采集端。把 writer round-trip 只当辅助证据，核心检查使用未修改的 Linux perf，防止自写 reader/writer 共享同一错误。

| 门禁 | 输入 | 必须断言 |
| --- | --- | --- |
| 容器基础 | 固定已知 attr/ID、少量 SAMPLE、无 feature/完整 feature 两份 fixture | header/attr size、section bounds、事件数正确；工具退出成功且没有 malformed record |
| trailer 与排序 | COMM、MMAP、FORK、SAMPLE、EXIT、多 CPU 乱序输入 | 输出保留时间/CPU/身份，metadata 生效顺序正确；不是只查命令退出码 |
| 用户符号 | 有符号 ELF、非零 pgoff、PIE/ASLR、共享库 | 精确匹配预期函数与 DSO，不能只接受 `[unknown]` |
| 内核符号 | 带真实 build-id/参考符号的内核 ELF，KERNEL mapping 与 sample | 主内核函数正确；重定位前后结果一致；不引用 host kallsyms |
| 调用链 | 至少三层已知调用链、kernel/user marker、两种 period | 栈方向、上下文、聚合计数/权重与预期一致 |
| 生命周期 | fork/thread、exec 替换映射、退出后 PID 重用 | 新旧地址空间不混淆，子任务正确继承，旧符号不会泄漏到新进程 |
| 丢样与不完整 | 已知 LOST、栈截断、helper 错误、截断 capture | 各项计数可追溯；未知/不完整不会被宣称为完整成功 |
| 负面格式 | 错 attr_size、坏 ID、错误 trailer、nr 越界、截断 record | 转换器拒绝并说明原因；不写看似有效最终文件 |
| 错符号 | 同路径但 build-id 不匹配的 ELF | 明确失败/未知符号，不接受错误命名函数作为成功 |
| 跨架构 | **真实 RV64/LA64 ELF** 和地址链，在固定 x86 Linux perf 上分析 | 架构记录正确，预期符号/调用链均通过；DWARF 不混入这一结果 |
| 真实采集 | RV/LA QEMU 固定 CPU workload、内核/用户独立链、loss 压力 | 捕获真实热点、实际周期与计数；与静态 fixture 分开报告 |

涉及内核实现后遵循仓库 `make test 2>&1 | tail -30` 双架构构建门禁，QEMU 使用根 `AGENTS.md` 指定命令；本研究文档与 host 格式 fixture 不以编译整个内核作为必要验证。x86_64/aarch64 与物理平台的扩大验收留给地图单独确定，不把存在示例配置等同于现行仓库门禁。

## 9. 对地图与后续 tickets 的建议

- #181 可以按“已完成固定基线的格式研究、字段表、符号决策建议和可执行验收设计”关闭；这不关闭实现缺口。
- #182 先确定采样上下文、FP 规则、用户栈安全读取、最大深度与失败状态；交付已展开 callchain 是本研究的优先建议，完整用户 DWARF 保持后续独立门禁。
- #183 明确真实 CPU-clock / PMU 事件及 period 单位，能力降级必须进入配置与 capture，不能用软件样本伪装 cycles。
- #187/#188 明确谁收集映射/生命周期/build-id、谁写文件、artifact bundle、缺失信息的拒绝策略、火焰图权重与分析入口。旧 syscall histogram 的 profile 名称不应被误认为 CPU profiling 已完成。
- 创建独立实现票时至少拆分：①采样事实/生命周期元数据；②perf.data writer 与静态互操作 fixture；③profile 工具接线与双架构真实采样验收。②不依赖硬件 PMU；③依赖①、②及 #182 的结果。
- 不将自定义调度/缺页事件直接塞进 CPU profile 最小子集。#184/#185 可复用文件基础设施，但若承诺 Linux perf tracepoint 解码，应另行定义 event format、时序、字段和 `HEADER_TRACING_DATA`。

## 10. 本次验证记录

本次新增 [host fixture 脚本](fixtures/perf_data_minimal.py)。源码/格式基线仍为 Linux v6.12，**实际 reader 是 x86_64 Linux 上的 perf 6.8.12**（可执行文件路径位于 linux-tools-6.8.0-149）；二者分开记录，不能称为已测试 v6.12 reader。

脚本用 clang 18.1.3、LLD 23.1.1（rust-lld）和 GNU readelf 2.42 为 x86_64、riscv64、loongarch64 分别生成含 20-byte build-id 的真实用户/内核 ELF，但不执行这些 ELF；从实际 ELF section/program header/符号读取地址与偏移，再生成预展开样本。为每种目标单独写 ARCH，并使用隔离 build-id cache、显式 symfs/vmlinux、空 DEBUGINFOD_URLS，避免偶然借用主机符号。

复现命令（需要 Python 3、支持对应 target 的 clang、readelf、LLD 和 Linux perf；工具路径可由参数覆盖）：

```bash
python3 docs/research/fixtures/perf_data_minimal.py \
  --perf /usr/lib/linux-tools-6.8.0-149/perf
```

默认输出到新的临时目录；需要固定位置时使用脚本的 `--output-dir`。结果写入 `results.json`，各架构保存 `perf.data`、ELF、命令输出和错误输出。本次证据目录为 `/tmp/pulse-perf-research-181/`，目录是可重建的临时实验产物，不作为仓库中的不可变发布文件。

| 目标 ELF / HEADER_ARCH | 样本数 | period 合计 | 用户 text pgoff（bytes） | 结果 |
| --- | --- | --- | --- | --- |
| x86_64 | 3 | 30,000,000 | 4,096 | PASS |
| riscv64 | 3 | 30,000,000 | 4,096 | PASS |
| loongarch64 | 3 | 30,000,000 | 65,536 | PASS |

每份文件使用 header=104、attr=64、file attr=80、sample_type=0x101a7、sample_id_all trailer=32、BUILD_ID+ARCH features。包含 2 条 user 样本和 1 条 kernel→user 混合调用链，覆盖非零 user pgoff、COMM、FORK 映射继承、EXIT 与 `LOST.lost=2`（合成丢记录数）。`perf script` 成功解析预期用户/内核函数和任务名，正例没有 `[unknown]`；`perf report` 断言 3 个样本及总 period；`perf buildid-list` 与实际 ELF ID 匹配。将 symfs 换成空目录的负例中，用户地址保持 `[unknown]`，显式 vmlinux 的内核仍能解析，证明 build-id 本身不携带符号。

**丢样展示细节：**本实验 `perf report` 页头显示 `Total Lost Samples: 0`，但 stderr 报告丢失 1 个 chunk，`perf script -D` 正确解码 `PERF_RECORD_LOST lost:2`。v6.12 源码也将 LOST 计入 `total_lost`，将 LOST_SAMPLES 计入 `total_lost_samples`，而 report 页头打印后者；它们不是同一统计口径。验收必须核对原始 LOST/capture 计数，不能只检查页头，也不能为让页头好看而把 transport loss 改写为 LOST_SAMPLES。[S19]

火焰图另用上游 `brendangregg/FlameGraph` 固定提交 `41fee1f99f9276008b7cd112fca19dc3ea84ac32` 的 `stackcollapse-perf.pl` 和 `flamegraph.pl` 实测。三架构均从 `perf script` 输出得到以下折叠栈，并成功生成 XML 可解析的 SVG：

```text
child;user_parent;kernel_parent;kernel_leaf 10000000
child;user_parent;user_leaf 10000000
parent;user_parent;user_leaf 10000000
```

该版本 collapse 脚本读取 perf 文本中的 period，故合计权重为 **30,000,000 ns，而非 3 个 sample**；渲染使用 `--countname nanoseconds`。它验证了调用链跨 kernel/user 边界后的 root-first 折叠与权重保持。示例复现步骤如下，`FlameGraph/` 需检出上述固定提交；其余两架构替换路径即可。[S20]

```bash
perl FlameGraph/stackcollapse-perf.pl \
  /tmp/pulse-perf-research-181/riscv64/script.stdout \
  > /tmp/pulse-perf-research-181/riscv64/flamegraph.folded
perl FlameGraph/flamegraph.pl --countname nanoseconds \
  --title 'PulseOS perf.data synthetic fixture (riscv64)' \
  /tmp/pulse-perf-research-181/riscv64/flamegraph.folded \
  > /tmp/pulse-perf-research-181/riscv64/flamegraph.svg
```

本次 SVG 大小分别为 14,942 / 14,943 / 14,947 bytes（x86_64 / RV64 / LA64），折叠与渲染 stderr 均为空；逐架构计数、SVG SHA-256 和解析结果保存在 `/tmp/pulse-perf-research-181/flamegraph/results.json`。

此实验只证明**预展开合成样本的文件互操作、跨架构 ELF 符号化与静态 SVG 火焰图消费链**，不证明 PulseOS guest 的真实计时采样、FP walker、用户栈读取、DWARF 展开、PMU、完整 PIE/exec/PID 重用或所有负面格式测试通过。真实生产接线由 #190、真实 capture 消费由 #191 跟踪，完整调用栈仍依赖 #182；§8 中其余门禁保留给实现阶段。

## Primary sources

下列 Linux 源码全部固定到 v6.12；FlameGraph 使用单独列出的固定提交。表格中的字段事实来自 UAPI 与对应 reader/writer；本项目推荐约束已在正文中明确标为建议或导出契约。

- [S1] [Linux perf.data 格式说明](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf.data-file-format.txt)：容器、features、ID、排序及 pipe-mode。
- [S2] [Linux perf_event UAPI](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/perf_event.h)：attr/sample bits、record payload、sample_id_all、CALLCHAIN context。
- [S3] [perf header.h](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/header.h#L59-L87) 和 [header.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/header.c#L3680-L3795)：file header/attribute writer；[read_attr](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/header.c#L4148-L4191) 与 [read_header](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/header.c#L4240-L4340)。
- [S4] [perf evsel.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/evsel.c#L2485-L2550)：trailer reader；[sample parser](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/evsel.c#L2650-L3000)：字段顺序、长度、DWARF 可变字段。
- [S5] [perf machine.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/machine.c#L1595-L1800)：映射处理；[callchain context](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/machine.c#L2054-L2135)：context marker 解释。
- [S6] [perf session.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/session.c#L198-L220)：没有 sample_id_all 时有序事件处理降级。
- [S7] [perf-report 文档](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf-report.txt)：stdio、call graph、symbol/DSO、vmlinux/symfs 与展示模式。
- [S8] [perf map.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/map.c) 和 [symbol-elf.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/symbol-elf.c)：映射地址与 ELF 符号装载。
- [S9] [perf thread.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/thread.c) 和 [machine.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/machine.c)：任务创建、继承与生命周期处理。
- [S10] [perf env.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/env.c#L457-L469)：未提供目标 ARCH 时回退本机 uname。
- [S11] [perf build-id record 定义](https://github.com/torvalds/linux/blob/v6.12/tools/lib/perf/include/perf/event.h#L296-L310)、[build-id writer](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/build-id.c#L272-L335)、[build-id reader](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/header.c#L2269-L2330)。
- [S12] [perf symbol.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/symbol.c)、[symbol-elf.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/symbol-elf.c)、[build-id.c](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/build-id.c)：ELF build-id、符号与 cache。
- [S13] [perf-script 文档](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf-script.txt)：字段、符号输入、call graph、header 等输出。
- [S14] [perf 合成 kernel MMAP](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/synthetic-events.c#L1114-L1182)：参考符号、内核 pgoff 与命名规则。
- [S15] [perf-record call-graph 文档](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Documentation/perf-record.txt#L282-L318)：FP/DWARF 与内核/用户展开方式的区别。
- [S16] [目标寄存器选择](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/perf_regs.c)、[RISC-V libdw callback](https://github.com/torvalds/linux/blob/v6.12/tools/perf/arch/riscv/util/unwind-libdw.c)、[LoongArch libdw callback](https://github.com/torvalds/linux/blob/v6.12/tools/perf/arch/loongarch/util/unwind-libdw.c)。
- [S17] [RISC-V util Build](https://github.com/torvalds/linux/blob/v6.12/tools/perf/arch/riscv/util/Build)、[LoongArch util Build](https://github.com/torvalds/linux/blob/v6.12/tools/perf/arch/loongarch/util/Build)、[perf Makefile.config](https://github.com/torvalds/linux/blob/v6.12/tools/perf/Makefile.config)：backend 编译条件与依赖。
- [S18] [libunwind backend 选择](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/unwind-libunwind.c#L11-L55)：不能仅凭 header 架构假定存在任意跨架构展开能力。
- [S19] [perf report 丢样页头](https://github.com/torvalds/linux/blob/v6.12/tools/perf/builtin-report.c#L558-L561) 与 [session 丢样计数](https://github.com/torvalds/linux/blob/v6.12/tools/perf/util/session.c#L1290-L1299)，以及 [通用 ring buffer 输出失败计数](https://github.com/torvalds/linux/blob/v6.12/kernel/events/ring_buffer.c#L247-L264)：LOST 与 LOST_SAMPLES 的统计区别。

- [S20] [FlameGraph stackcollapse-perf.pl](https://github.com/brendangregg/FlameGraph/blob/41fee1f99f9276008b7cd112fca19dc3ea84ac32/stackcollapse-perf.pl#L230-L285)、[flamegraph.pl](https://github.com/brendangregg/FlameGraph/blob/41fee1f99f9276008b7cd112fca19dc3ea84ac32/flamegraph.pl)：上游 perf 文本折叠、period 权重与 SVG countname 标签。

## 仓库依据

PulseOS 已提交代码基线为 `758fa083dde3d9c7a36e2f9f5b9c8266439cb889`。术语表参考当前工作树（含任务开始前已有的未提交补充，本次未改动）；`tgoskits` 是独立 checkout，以下链接固定其实际 revision。这些是现状证据，不是以后实现不可改变的 ABI。

- [P1] [术语表](../../GLOSSARY.md)：Linux BPF 兼容层级、采样调用栈、perf.data 兼容记录、BPF capture 与 BPF 采样丢失。
- [P2] [profile BPF 程序](https://github.com/rcore-os/tgoskits/blob/3686ff71f00072fdf13edc3785c06a790899d47b/apps/starry/ebpf/profile/profile-ebpf/src/main.rs) 与 [loader](https://github.com/rcore-os/tgoskits/blob/3686ff71f00072fdf13edc3785c06a790899d47b/apps/starry/ebpf/profile/profile/src/main.rs)：现有 syscall-frequency 直方图。
- [P3] [perf-event core](../../pulse_core/src/bpf/perf_event.rs)：现有事件定义与 tick 路径。
- [P4] [pulse_bpf_schema](../../crates/pulse_bpf_schema/src/lib.rs)：现有 context、tracepoint 元数据与有界记录。
- [P5] [ADR-0005](../adr/0005-profile-specific-linux-bpf-compatibility-tier.md)：既有 fixed-layout BPF v1 与具名工具兼容边界。
- [P6] [#130 维护者的目标转向说明](https://github.com/muou000/PulseOS/issues/130#issuecomment-6542849311)：上游工具移植不是新地图目标。
- [P7] [#190 真实采样/tracepoint 接线](https://github.com/muou000/PulseOS/issues/190)、[#191 真实 capture 消费](https://github.com/muou000/PulseOS/issues/191)：本次代码审计发现的实现前置缺口。
