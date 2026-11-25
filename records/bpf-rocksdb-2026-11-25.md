# PulseOS 上的 RocksDB 9.11.2 性能基线

2026-11-25，在 PulseOS `be649c89f7b7d29f447ea772e8c1d8f0d8171ff9` 的 RISC-V 64 和 LoongArch64 QEMU 来宾中重新运行预装的 `db_bench`。数据库放在 ext4 根盘，每轮读写均为单前台工作线程，16 字节键、256 字节值、无压缩。基准同时启用 RocksDB 的直方图、统计和文件操作计数。

## 工作负载与热点

1. **逐条持久写。** 两种架构每轮各写 1,000 条。开启逐条 WAL 同步后，RV64 吞吐从 2,856 降至 321 ops/s，LA64 从 4,911 降至 187 ops/s。三轮中 RocksDB 的 WAL 同步累计时间分别占单线程基准 elapsed 的 76–77% 和 84–87%。RV64 函数栈把工作线程定位到 fdatasync、页缓存同步和 ext4 按 inode 写回。优化须在同步开启、持久性相同的条件下验证。[#283](https://github.com/muou000/PulseOS/issues/283)
2. **块缓存未命中后的 SST 随机读取。** 对总计 20,000 个键的已刷盘数据库，将 RocksDB 块缓存从 1 MiB 增至 16 MiB，两个架构的文件层读取由每轮约 41,200 次降到 1,440 次。吞吐分别达到原来的 4.84 倍（RV64）和 7.11 倍（LA64）。这是参数对照。待优化的内核场景是在相同 1 MiB 预算下服务小块随机读。[#284](https://github.com/muou000/PulseOS/issues/284)
3. **VirtIO 完成复查定时器。** 在 RV64 小缓存随机读工作线程的 172 个内核样本中，29 个叶样本位于 `set_generic_timer`，调用者都是 `VirtIoBlockFuture::poll`。可按每次设备 I/O 分开衡量定时器登记成本，并验证丢中断时的兜底行为。[#285](https://github.com/muou000/PulseOS/issues/285)

### 吞吐和延迟

每个格子的三个吞吐值按该配置实际运行次序排列。P50、P99 为三轮各自 `db_bench` 操作延迟分位数的中位数。写入每轮新建数据库。每个读进程重新打开同一个 SST，RocksDB 块缓存重新建立，来宾文件缓存和虚拟设备缓存沿用。两种缓存设置每架构各执行 150,000 次随机读，全部找到键。两架构的准备阶段均完成 `fillseq,flush`，`sst_dump --command=verify` 均通过。

| 架构 | 负载 | 三轮 ops/s | 中位 ops/s | P50（µs） | P99（µs） |
|---|---|---|---:|---:|---:|
| RV64 | 写，sync=0 | 3657, 2806, 2856 | 2,856 | 185.52 | 870.00 |
| RV64 | 写，sync=1 | 335, 321, 272 | 321 | 2,789.68 | 6,515.38 |
| RV64 | 读，1 MiB | 1556, 1573, 1462 | 1,556 | 368.96 | 2,811.19 |
| RV64 | 读，16 MiB | 7653, 6602, 7538 | 7,538 | 81.55 | 1,667.52 |
| LA64 | 写，sync=0 | 4911, 5206, 4005 | 4,911 | 107.46 | 773.33 |
| LA64 | 写，sync=1 | 272, 174, 187 | 187 | 3,725.00 | 20,833.33 |
| LA64 | 读，1 MiB | 1102, 1286, 1496 | 1,286 | 255.91 | 8,845.36 |
| LA64 | 读，16 MiB | 9146, 9352, 8972 | 9,146 | 46.68 | 1,300.00 |

小缓存每轮 50,000 次读，RV64 的 data block hit/miss 均为 8,769/41,231，LA64 均为 8,774/41,226。大缓存两架构均为 48,571/1,429。小缓存下 `rocksdb.read.block.get.micros` 的 SUM 占读阶段 elapsed 的 69–70%（RV64）和 81–82%（LA64），它记录 block get 的耗时。读写直方图、PerfContext 和设备计时的范围不同，有嵌套的时间不作加总。

## 方法与复现

常规内核从干净的 HEAD 串行 `make rv`、`make la`，默认 release、info 日志。校验实际启动文件与各自 provenance 的 SHA。QEMU 11.1.50（v11.1.0-2112-g2a0ac9c8ac），virt、8 vCPU、8 GiB、`snapshot=on`，RV64 使用 virtio-mmio，LA64 使用 virtio-pci。测试镜像预装固定版本的 RocksDB 9.11.2 Debian 包，db_bench 通过各架构的动态加载器运行。宿主为 AMD Ryzen 7 8845H、WSL2 Linux 6.6.87.2，提供 12 个逻辑 CPU。三轮基线的两个来宾串行，绑定宿主 CPU 0–7。详细指标和 BPF 采样使用 8–11，宿主另有 QEMU 活动，RV64 最早的运行与构建有重叠。结果用于同架构同参数对照，不能外推到物理盘、生产并发或另一架构的相对速度。

在仓库规定的 QEMU 参数下，从镜像副本启动来宾。在来宾内执行以下命令。写和读的三轮对照顺序均为 AB、BA、AB。基线未附加 BPF。QMP 和 BPF 各在单独启动的诊断来宾执行。

```sh
opts='--threads=1 --key_size=16 --value_size=256 --compression_type=none --seed=42 --histogram=1 --statistics=1 --report_file_operations=1'
for sync in 0 1 1 0 0 1; do
    db=$(mktemp -d /root/wal.XXXXXX)
    db_bench $opts --db="$db" --benchmarks=fillseq --num=1000 --batch_size=1 --disable_wal=0 --sync="$sync"
done
db=$(mktemp -d /root/read.XXXXXX)
db_bench $opts --db="$db" --benchmarks=fillseq,flush --num=20000
sst_dump --file="$db" --command=verify
for cache in 1048576 16777216 16777216 1048576 1048576 16777216; do
    db_bench $opts --db="$db" --benchmarks=readrandom --use_existing_db=1 --num=20000 --reads=50000 --cache_size="$cache"
done
```

## QEMU 设备与 RocksDB 函数计时

独立诊断各运行一次，加入 `--stats_level=4 --perf_level=4`。在 guest 每个 db_bench 进程启动前和退出后通过串口握手，做两次 `query-blockstats`，只取设备 `x0` 顶层计数差值。计数包含进程启动、建库或打开数据库、关闭和同期后台 I/O。RocksDB FS Read 包含在该次报告中累计的文件操作，PerfContext 来自工作线程。设备、文件和数据块的计数分别给出。QEMU 字节统计度量虚拟设备接口，实际宿主盘写入量未知。

| 架构 | 缓存 | RocksDB FS Read | 线程 block_read_time | x0 读请求 | x0 读字节 |
|---|---:|---:|---:|---:|---:|
| RV64 | 1 MiB | 41,232 | 28.025 s | 13,554 | 55,754,752 |
| RV64 | 16 MiB | 1,440 | 1.301 s | 608 | 2,519,040 |
| LA64 | 1 MiB | 41,233 | 78.337 s | 13,691 | 56,602,624 |
| LA64 | 16 MiB | 1,440 | 1.905 s | 610 | 2,592,768 |

| 架构 | 写入模式 | WAL 同步累计 | x0 写请求 | x0 写字节 | x0 flush 次数 |
|---|---|---:|---:|---:|---:|
| RV64 | sync=0 | 0.000 s | 125 | 696,320 | 33 |
| RV64 | sync=1 | 8.388 s | 2,344 | 10,334,208 | 1,057 |
| LA64 | sync=0 | 0.000 s | 134 | 995,328 | 33 |
| LA64 | sync=1 | 11.769 s | 2,346 | 10,346,496 | 1,056 |

十个进程（每架构五个，含准备）都正常退出，每个 QMP 窗口均有成对的 before/after。设备报告的失败和无效读、写、flush 增量均为 0。同步写两组的 WAL 均为 288,000 B。虚拟设备的 flush 用时覆盖后端服务的一部分，无法据此直接换算 guest 的 CPU 或阻塞时间。

### 固定应用缓存后改变 SST 大小

RV64 另启来宾，块缓存固定 1 MiB，先准备单个 5,597,747 B SST（20,000 键）再准备单个 2,799,156 B SST（10,000 键）。各自 flush 后由新进程以 seed=42 读 50,000 次，全部找到键。每组一次，宿主 CPU 0–7。

| 单 SST 大小 | 数据块 miss | RocksDB FS Read | x0 读请求 | x0 读字节 | ops/s |
|---:|---:|---:|---:|---:|---:|
| 5,597,747 B | 41,200 | 41,211 | 11,832 | 48,852,992 | 2,502 |
| 2,799,156 B | 32,210 | 32,221 | 0 | 0 | 5,545 |

小库的文件读取在窗口内全部由来宾侧满足。两个 SST 的大小分别在每文件 1,024 个 4 KiB 缓存页的软上限两侧，这给出了可验证的线索。该组固定运行顺序，VFS 页缓存、ext4 块缓存及各自驱逐策略的贡献仍待分解。首次驱动误认串口半行，已隔离。表中使用重跑的 8 个完整 QMP 边界。

## RV64 CPU 函数采样

使用相同源码、单独构建的 frame-pointer 内核（`make rv APP_FEATURES="qemu bpf-trace"`）和生产 `bpf-record`。每个负载各用独立来宾。先启动 db_bench，确认业务读写已经有进度，再采 4 s。默认缓存读使用 10,000 键并持续随机读。小缓存采用 20,000 键、seed=42，`fillseq,flush,readrandom` 同一进程，readrandom 受 30 s 时长约束，实际 20,999/20,999 找到键。同步写另用 12,000 次 WAL 单条写。这些诊断窗口与上表固定次数基线分开计量。

```sh
bpf-record --events cpu --cpus all --period-ns 10000000 --duration-ms 4000 \
    --callchain fp --kernel-elf /boot/kernel.elf --output /tmp/work.pbcap
```

实际配置为 8 个 CPU-clock 来源、每 sink 16 页、8 MiB record buffer、最多 32 帧/512 B、无 fallback。通过串口回收 guest 原文件，核对 `RECORD SAVED` 的 SHA 和 host SHA、trailer、记录数。分析先检查整个 capture 的 `--loss`，再按实际 DB PID 事后筛选，分别用 `--mode kernel` 与 `--mode user`，均保留整个记录窗口、所有 CPU，`--weight period`。这样排除了 recorder、shell 和同机其他进程，入选样本都来自表中工作线程。每个 source 的每条权重同为 10,000,000 period_ns。

| 负载 | 全局条数 | DB PID / 工作 TID | DB 样本（内核 / 用户） | DB 各 CPU 来源样本 0–7 | 映射日志 dropped |
|---|---:|---|---:|---|---:|
| 默认缓存随机读 | 3,175 | 246 / 346 | 0 / 398 | 27, 92, 69, 64, 0, 1, 74, 71 | 706 |
| 同步写 | 3,015 | 53 / 139 | 237 / 54 | 180, 10, 10, 26, 21, 11, 15, 18 | 0 |
| 1 MiB 随机读 | 2,735 | 53 / 157 | 172 / 94 | 188, 0, 10, 9, 18, 10, 18, 13 | 0 |

- **同步写。** 237 个内核栈中，223 个经过 `sys_fdatasync`、168 个经过 `CachedFileShared::sync_dirty_range_with_backend`、132 个经过 `Ext4Disk::flush_owner`、68 个经过 `flush_batches`。后续可分段计量选择脏页/块、写回提交与设备完成。各函数数值为 inclusive，会重叠。
- **小缓存随机读。** 172 个内核栈中，166 个经过 `sys_pread64`、140 个经过 `ensure_pages_loaded_async`、91 个经过 `read_blocks_from_disk_async`、50 个经过 `VirtIoBlockFuture::poll`。29 个叶样本是从此 poll 登记 `set_generic_timer`。检查代码可区分设备级 1 ms 的完成复查回调与 ext4 的外层读超时。定时器的占比只以这 172 条内核样本为分母。
- **证据质量。** 三个 capture 的全局状态均为 `IncompleteError`。读默认/写/读小缓存的系统 timer_busy 分别为 107/173/132，逐来源 skipped 分别为 [1,0,4,2,1,5,2,2]、[42,19,16,13,13,19,21,33]、[78,58,35,41,82,33,67,71]。默认读 source 8 有 1 次 invalid。写 source 1/5 的 cancelled 为 1/2，小缓存读 source 3 的 cancelled 为 1。三个 consumer 的 ringbuf_lost、discarded、corrupt 和 bounds 均为 0。各层口径有重叠。
- 两个有内核样本的 Query 均通过匹配 ELF、原生 perf 6.8.12 与固定版本 FlameGraph 核验，其内核栈全在 `nonmonotonic_frame` 截断，保留已观察前缀。默认读的用户态因映射日志丢失被严格导出拒绝，其余两组用户态被拒因 mapped object SHA unavailable。用户态函数占比、物理 CPU 周期及等待时间未获归因。小缓存读第一次试跑未触发采集，已修正阶段检测后重跑，仅计入有 capture 的那次。

## tmpfs 对照发现的数据丢失

性能基线使用 ext4。RV64 另在全新 tmpfs 目录分别运行 sync=0/1 各两次，四次均在 open 时报 `Corruption: CURRENT file does not end with newline`，CURRENT 为 0 B，而 MANIFEST-000001 为 52 B。ext4 四次均成功。在两个架构的独立快照里进一步缩小到无 RocksDB 的最小复现。写入并关闭 16 B 文件再同目录 mv，inode 号保持、长度变 0。对照中打开旧 fd 跨越 mv 并在关闭前重新读新路径，16 B 内容可保留。此项未进入吞吐或延迟统计。[#282](https://github.com/muou000/PulseOS/issues/282)

## 输入身份与本地回放

常规与 BPF 内核的源码输入树 SHA-256 均为 `4d8a24a24d206065dae3afb9e6bec77760f2153b2760db4ae64f97eeed0c3022`。下列为实际文件的 SHA-256。BPF 负载脚本和匹配 ELF 随其独立镜像部署。

| 输入/产物 | SHA-256 |
|---|---|
| RV64 常规启动内核 | `d77a343a4b1d5f2f72e6826ac17e67076e448e58e3150278fcc1aa190b879360` |
| RV64 基础 rootfs | `c3c65c539d355b7f5d759af5bc6a939c8e5ab09c3985596b99ddda8536160917` |
| RV64 基线启动时的镜像副本 | `7a3bdc76e62217826aba42f02eb6f224d9ac7894c03930a4cf3e0db60067bb24` |
| LA64 常规启动内核 | `073efb9f377053024f581713c1ea3fbe0092452481b21fc5d9f04f669c84cc3f` |
| LA64 基础 rootfs | `4295a4d166cf2d904d2b67710789a80d54a4facacafb164a4ec761e89875030c` |
| LA64 基线启动时的镜像副本 | `e9726a8ea43240f05340462678c7e693257b281987e9bf7d1c62f4b7d6056438` |
| RV64 BPF 启动内核 | `0164bce76f5ec60a1e5fbe791b6387ad18286aa02eb2ba03faa18b35274fa8d3` |
| RV64 BPF 配套 ELF | `ec0dccd6e14a3bcc21938c6e875350766752f7366af7dd1e41dd15d7eccb7a04` |
| RV64 生产 recorder | `056834ae23e66c9488d5f0c657086889e4d20280c76da6b06705e8163cbe0a71` |
| 宿主 analyzer | `027ffe799b545ea0ac1eb4397a782400a97e657c06e44370dd4772fd55f24fa7` |
| 默认缓存读 capture | `e710695d4a8e89df0b6a0a413bed8667308422c51a7527811272ea53335a2b93` |
| 同步写 capture | `44d0f253885c33b1fdda3a6325445443cc5dae1418508c84602eef2a70a4e70b` |
| 小缓存读 capture | `3efdef00fc7a418bf67c7c6d50ca7a0a45a9535a57a15d7f8999029d192ac311` |

完整日志、输入、命令、原始 capture、perf.data、符号包和 SVG 留在本机 Git 忽略的 `tests/bpf_record/runs/` 下，无外部归档或约定留存期。仅有本报告时可以复做实验。逐条回放需要对应的原文件。各目录入口如下。

| 证据 | 目录内入口 |
|---|---|
| 基线与逐轮指标 | [RV64 串口](../tests/bpf_record/runs/rocksdb-20261125/riscv64-ext4.log) · [LA64 串口](../tests/bpf_record/runs/rocksdb-20261125/loongarch64-ext4.log) · [复现脚本](../tests/bpf_record/runs/rocksdb-20261125/ext4.sh) |
| QMP 与 PerfContext | [RV64](../tests/bpf_record/runs/rocksdb-20261125-qmp/riscv64-summary.json) · [LA64](../tests/bpf_record/runs/rocksdb-20261125-qmp/loongarch64-summary.json) · [SST 大小对照](../tests/bpf_record/runs/rocksdb-20261125-size/riscv64-summary.json) |
| BPF 全局诊断与 Query | [三次采样身份、逐源计数和哈希](../tests/bpf_record/runs/rocksdb-20261125-rv64/results-short.json) · [同步写火焰图](../tests/bpf_record/runs/rocksdb-20261125-rv64/sample-write/kernel-native/flamegraph.svg) · [小缓存读火焰图](../tests/bpf_record/runs/rocksdb-20261125-rv64/sample-cold2/kernel-native/flamegraph.svg) |
| tmpfs 正确性 | [DB 矩阵](../tests/bpf_record/runs/rocksdb-20261125-tmpfs/guest.log) · [最小复现](../tests/bpf_record/runs/rocksdb-20261125-tmpfs/rename.sh) |
