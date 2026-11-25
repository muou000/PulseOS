# PulseOS 内存管理应用与匿名页基线（2026-11-25）

SQLite 3.54.1 的内存数据库在 RV64 与 LA64 上均完成建表、插入、索引、查询、更新和完整性检查。默认内核各运行三次，结果流长度和指纹全部与原生 x86_64 Linux 一致。两端 SQLite 分配器峰值均为 3,499,128 字节，关闭后分配数为零。访存探针同时发现了稀疏匿名页的分配代价和两处应用可见的内存记账缺口。[发布的测试盘与校验和](https://github.com/muou000/PulseOS/releases/tag/rootfs-mm-tests-20261125)

## 默认内核

| 测量 | RV64 QEMU virt | LA64 QEMU virt |
| --- | ---: | ---: |
| SQLite `--size 5` 的 TOTAL，三次，秒 | 6.690 / 7.019 / 6.776 | 2.298 / 1.889 / 1.973 |
| LTP `brk01 / mincore03 / mmap01 / mremap01` 通过断言数 | 2 / 2 / 1 / 1 | 2 / 2 / 1 / 1 |
| lmbench `bw_mem -P 1 -N 5 8M frd`，MB/s | 1599.04 | 1352.10 |

LTP 在 tmpfs 工作目录验证了 libc 和裸调用的堆伸缩、未触及及锁页的驻留、文件末页和文件映射扩展。两架构均无失败、跳过或损坏。lmbench 为镜像预装的上游程序，源码标识为 `$Id$`，仓库子模块修订为 `27b43aeec9dc0bb45f420388c78e42dde4c23bf0`。带宽列是单个程序调用的输出。QEMU TCG、宿主调度及架构工具链都会影响时间。应在相同架构及环境比较后续改动。[lmbench 源码](https://github.com/intel/lmbench/blob/27b43aeec9dc0bb45f420388c78e42dde4c23bf0/src/bw_mem.c)

## 匿名页首次访问

以 `39e61bab5903b773666d54123b51f66aa2ab8101` 的普通内核为基线。在独立实验工作树中，只将 `modules/mm/src/backend/alloc.rs` 的 `MAX_FAULT_BATCH_PAGES` 由 4 改为 1，重新执行 `make test`。两个内核版本使用同一原盘的只读快照启动。默认和单页配置各架构均完成 5 次探针及 3 次 SQLite，对照配置的 SQLite 摘要也与宿主一致。

| 阶段（16 MiB 区间，4096 页） | 四页批量下的驻留页 | 单页对照下的驻留页 |
| --- | ---: | ---: |
| 仅预留 | 0 | 0 |
| 每隔 64 KiB 写一页，实际触及 256 页 | 1024 | 256 |
| 写过全部页 | 4096 | 4096 |
| MADV_DONTNEED 后、读回前 | 0 | 0 |
| 每页读回此前写入的位置并验证零 | 4096 | 4096 |

默认内核在该稀疏访问中多驻留 768 页，即 3 MiB。源代码在缺页位置探测连续空页，分配、清零并安装至多四页。单页对照把这一成本与实际写入量对齐，同时增加密集访问的缺页处理工作。[匿名缺页实现](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/mm/src/backend/alloc.rs#L388)

另用交替启动顺序复测计时。每种架构与策略各启动两次，每次先预热一轮，再记录三轮。以下为六轮中位数，计时只包围访问循环。

| 架构与批量 | 稀疏首次写，ms | 稀疏写之后的全页写，ms | 丢弃后全页首次读，ms |
| --- | ---: | ---: | ---: |
| RV64 四页 | 28.64 | 87.04 | 143.16 |
| RV64 单页 | 17.95 | 216.71 | 229.79 |
| LA64 四页 | 8.27 | 53.06 | 64.78 |
| LA64 单页 | 3.60 | 97.18 | 85.71 |

两架构的方向一致。共享宿主上同期有其他 QEMU 作业，逐次波动较大。应用层收益需在受控宿主分别复测。驻留结果在两个架构可重复。全部原始纳秒样本、命令、宿主负载、镜像与内核散列见随附数据。[逐轮记录](results.json)

考虑到并行工作发现的 vDSO 时钟读数偏差，我们在镜像副本中将探针的读时改为直接调用 `SYS_clock_gettime`，其余源码和内核相同。每种配置预热一次，再测三轮。四页改为单页后，稀疏写耗时中位数分别为 RV64 12.02 → 6.55 ms、LA64 4.39 → 1.64 ms。随后的全页写分别为 38.50 → 102.69 ms 和 18.66 → 40.11 ms。两种计时方式得到一致方向。两轮宿主负载不同，绝对耗时应在各自轮次内比较。[直接系统调用复测](syscall-clock.json) · [时钟问题 #299](https://github.com/muou000/PulseOS/issues/299)

## 应用可见的记账

- 在预留 16 MiB 时，两架构的 `mincore` 都报告区域内零页驻留，`/proc/self/status` 的 VmRSS 已增加 16384 KiB，且与 VmSize 相等。密集写入与丢弃阶段的 RSS 都维持高位，解除映射时才下降。源码直接将 VMA 长度赋给进程和线程的 RSS 字段。[procfs 实现](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/process/src/procfs.rs#L150)
- 在同一实验中，`getrusage(RUSAGE_SELF)` 的峰值 RSS 与 minor faults 各阶段都为零。现有入口初始化结构后只填 CPU 时间。原生 Linux 参考运行从基线到密集写的 minor faults 为 85 → 4181，密集写后峰值为 17152 KiB，丢弃后保留。单个区间的 mincore 与整个进程的 RSS 范围不同。[getrusage 实现](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/pulse_syscalls/src/impls/misc/system.rs#L365)

## 复测

检出发布标签，执行 `make test`，下载测试盘并校验 SHA256，然后按 README 启动普通 QEMU 内核。实验使用 QEMU 11.1.50（v11.1.0-2112-g2a0ac9c8ac）、8 vCPU、8 GiB RAM、VirtIO 块设备和 snapshot 模式。两种架构启动日志均显示 8 个 CPU 启动。[构建与来宾命令](../../README.md#在来宾里测试内存管理)

```sh
/opt/mmbench/bin/speedtest1 --memdb --testset main --size 5 --verify --stats
/opt/mmbench/bin/anon_residency
/opt/lmbench/bin/bw_mem -P 1 -N 5 8M frd
```

此组测试在 QEMU virt 上运行。文件支持的映射和私有匿名内存有各自的用例。结果未覆盖持续内存压力、交换、长时间并发回收或物理板的性能。

后续工作分别跟踪进程与线程的 RSS、getrusage 峰值与缺页数，以及稀疏和顺序访问的批量分配策略。[RSS #312](https://github.com/muou000/PulseOS/issues/312) · [getrusage #313](https://github.com/muou000/PulseOS/issues/313) · [匿名页批量策略 #314](https://github.com/muou000/PulseOS/issues/314)

## 公开制品复验

从 GitHub Release 分别重新下载并校验压缩盘、工具包与解压后的原盘，使用同一组默认内核再次启动两架构。SQLite 的 `--size 5` 和 `--size 20` 在两端都与各自的原生 Linux 结果指纹一致。较大工作负载的参考值为 `3807866 2738af78e6eaae28c03f3766bc00b9defffe6fac85355c4d`，两端 SQLite 的峰值分配均为 13,961,576 字节。两端探针再次观测到 256 页稀疏写带来 1024 页驻留，且丢弃后成功读零。将 `TMPDIR` 设为 `/root` 后，两端的 `mmap01`、`mremap01` 又各通过一次。临时目录日志均为根盘上的 `/root/LTP_*`，LTP 报告 ext2/ext3/ext4 文件系统族，发布盘由 `mkfs.ext4` 建立。[公开盘复验数据](published-replay.json)

双架构工具包在独立输出目录从固定源码重建，与发布包逐字节一致。Release 的 `validation.tar.xz` 包含串口原始日志、命令、构建来源、文件系统校验和单页对照内核的补丁，SHA256 为 `9c8b820dd4e99cf755ce95bc0d75db182a8c1ccdcbadc05de243fe5f8b96a35f`。[原始验证证据](https://github.com/muou000/PulseOS/releases/download/rootfs-mm-tests-20261125/validation.tar.xz)
