# PulseOS 进程调度测试 · 2026-11-25

RISC-V 64 和 LoongArch64 两份 QEMU 测试盘都能运行 rt-tests 2.11 的进程／线程消息传递和 CPU 0 上的周期唤醒测量。每架构运行 36 个 LTP 程序，其中各有 15 个触发失败断言。优先处理跨线程调度接口和 RV64 时钟读数差异。前者影响已有应用接口，后者会让极少数周期延迟读数失真。[发布盘、SHA256SUMS 与原始证据](https://github.com/muou000/PulseOS/releases/tag/rootfs-sched-tests-20261125)

## 运行环境与复现

- QEMU 11.1.50（v11.1.0-2112-g2a0ac9c8ac），TCG virt、8 vCPU、8 GiB、ext4 snapshot。宿主为 AMD Ryzen 7 8845H、WSL2，12 个逻辑 CPU；同期还有独立 QEMU、构建与压缩任务。所有表格按架构分别统计。本次未比较内核改动前后，未测板卡的实时性。
- 两个常规内核均为干净提交 `3f8b3396d8167156011409f6c950ee0ff8956955`，时钟 tick 配置 100 Hz。制盘脚本基于网络盘标签 `rootfs-tests-20261125`（`39e61bab`），制盘改动提交为 `fdd25b33`。使用 `ROOTFS_VARIANT=tests ./scripts/build_img.sh all`。两份 ext4 通过只读 `e2fsck -fn`，压缩包通过 `zstd -t`，解压字节的标识见下表。
- LTP 20260930、sysbench 1.1.0-3ceba0b、lmbench 与 rt-tests 2.11 随盘提供。标准用例使用发布盘；策略及两种时钟诊断小程序另装在私有副本中。源码、实际命令、程序退出码和串口输出随 Release 的 `scheduler-evidence.tar.xz` 发布。QEMU 和来宾命令见[运行说明](../README.md#在来宾里测试进程调度)。

| 架构 | 实际启动内核 SHA-256 | 发布盘解压 SHA-256 |
| --- | --- | --- |
| RV64（bin） | `58a3a18d2af7b25c7f77068dddd351b07ebafa4bedd83c996e5ce51cb73151ef` | `820acb3775cadc934f26d09aa4227bdb344f1f746eef76080369d59acaa56aba` |
| LA64（ELF） | `845eb9a9198d3fb77ad5d48d072351f878d8b7aeb19f8ccc46ee558509d79465` | `794dce7dd7ad468e9f2187b992993153267706caf9f7a5d1817a4806d6a3b0c7` |

## 调度功能

每行第一组数按可执行程序的退出码计数，第二组按程序内部断言计数。两个架构的 `sched_yield01` 均输出一条旧格式 TPASS，已计入。完整的 36 项清单可用于逐项重跑。[逐程序计数](scheduler-20261125-ltp.tsv)

| 架构 | 程序通过 / 失败 / 前置阻塞 | 断言通过 / 失败 / BROK |
| --- | --- | --- |
| RV64 | 13 / 15 / 8 | 60 / 46 / 8 |
| LA64 | 12 / 15 / 9 | 57 / 46 / 9 |

- 两架构的 `getcpu01/02`、`sched_yield01`、`sched_getattr01`、`sched_setattr01` 和本线程的多项优先级用例通过。DEADLINE 属性读回只验证元数据，内核源码说明该类目前仍走普通 EEVDF。
- `sched_getparam01` 读取子进程失败；不存在的 TID 在亲和性和多项调度接口得到 EPERM。普通策略接收非零静态优先级、部分无效参数 errno、资源限制和权限规则也未通过 LTP。nice 越界未饱和。[目标 TID #292](https://github.com/muou000/PulseOS/issues/292) · [策略与 ABI #293](https://github.com/muou000/PulseOS/issues/293) · [nice 边界 #296](https://github.com/muou000/PulseOS/issues/296)
- `sched_setscheduler04` 每架构各 8 个失败断言。补充探针核对所有返回值，并让子进程自查。无标志的 FIFO/RR 优先级 10 均设置和继承成功；带 RESET_ON_FORK 时，两架构在设置阶段就返回 EINVAL，因而带标志的实际继承行为尚未测到。[策略继承 #294](https://github.com/muou000/PulseOS/issues/294)
- 六个程序在 `/proc/self/mounts` 返回 ENOENT 时中止；`sched_setscheduler03` 在 RLIMIT_NICE 得到 EINVAL，`nice05` 因对指定线程 CPU clock 的读取返回 EINVAL 而中止。LA64 的 `setpriority01` 还遇到 useradd 的 NSS/systemd 断言退出。[procfs 前置条件 #295](https://github.com/muou000/PulseOS/issues/295) · [指定线程 CPU 计时 #301](https://github.com/muou000/PulseOS/issues/301)

## 性能基线

以下为三次独立调用的中位数；sysbench 的 P95 一栏取三次各自 P95 的中位数。sysbench 每个事件使用单个 mutex、每次持锁 yield 后解锁，重复 100 次。所有工具输出均通过串口回收，单位取自对应工具。

| 负载与指标 | RV64 | LA64 |
| --- | ---: | ---: |
| hackbench 管道，进程，完成时间 | 84 ms | 29 ms |
| hackbench 管道，线程，完成时间 | 72 ms | 45 ms |
| lmbench lat_ctx，2 / 8 进程，每跳 | 308.28 / 461.88 µs | 474.10 / 669.70 µs |
| sysbench 单锁，1 / 8 线程，事件/s | 1305.65 / 390.23 | 2132.69 / 561.85 |
| 同上，单次事件 P95，1 / 8 线程 | 1.44 / 84.47 ms | 1.16 / 66.84 ms |
| cyclictest CPU 0，OTHER / FIFO 10，每轮 Avg 的中位数 | 1047 / 1014 µs | 2042 / 1665 µs |

hackbench 的参数为 `-g 1 -f 4 -l 100 -s 100`。管道选择 `-p`，工作任务选择 `-P` 或 `-T`，耗时包含 IPC、唤醒和回收。AF_UNIX socketpair 各作一次对照，RV64 进程 / 线程为 121 / 101 ms，LA64 为 61 / 27 ms。lmbench 命令为 `ENOUGH=10000 /opt/lmbench/bin/lat_ctx -P 1 -W 0 -N 3 -s 0 2 8`，包含管道接力的影响。sysbench 使用 `--threads=N --time=2 --events=0 threads --thread-locks=1 --thread-yields=100 run`，令 N 为 1 或 8。[sysbench 事件实现](https://github.com/akopytov/sysbench/blob/3ceba0b/src/tests/threads/sb_threads.c)

### 周期唤醒与读时正确性

每轮 CPU 0、一个线程、1 ms 周期、200 个样本，OTHER 和 FIFO 10 各跑三轮。RV64 的六轮最大值在 4,022–13,584 µs 之间，LA64 在 13,905–30,313 µs 之间。实际观测包含定时器、派发、返回用户态和宿主调度，不据此承诺实时上界。两架构默认使用 libnuma 的路径各三次在产生样本前失败，已验证的命令使用 `taskset -c 0` 与上游 `-S`。[上游工具和测量口径](https://wiki.linuxfoundation.org/realtime/documentation/howto/tools/cyclictest/start) · [单节点拓扑 #297](https://github.com/muou000/PulseOS/issues/297)

RV64 另一次全核 FIFO 运行中，一条输出 Max=-79 µs 且 Avg 超出合理范围，已从计时表剔除。独立探针让 8 个线程各做 500 次绝对睡眠，返回后依次执行系统调用、libc、系统调用读取同一单调时钟。RV64 的 4,000 次中，第一次直接读取早于目标为 0，libc 早于目标为 8，落在前后直接读取区间之外为 11。libc 最早比目标小 5.438 ms。LA64 的同一轮各计数均为 0。数据指向时间读取路径，尚不足以认定定时器提前唤醒或指定 VVAR 更新处为根因。[单调时钟 #299](https://github.com/muou000/PulseOS/issues/299)

第二轮从 AT_SYSINFO_EHDR 解析并直接调用 vDSO，在每架构 12,000 个样本中，RV64 有 24 次、LA64 有 2 次落在直接系统调用的夹取区间外，最坏分别比前一次直接读取小 139.00 / 21.06 µs。此轮两架构均未读到早于目标的值。

### 单锁与多锁对照

8 线程、每轮 2 秒，三组按 ABC、BCA、CAB 轮换。在 A/B 中每个事件都持锁 yield 100 次，连续的事件轮转选择一把锁，B 将事件分散到 8 把锁。C 将每事件工作量改为 1 次 yield。各轮启动时宿主另有三个 QEMU。表中每格为事件/s 中位数及每轮事件 P95 的中位数（ms）。

| 8 线程 sysbench | RV64 事件/s / P95 ms | LA64 事件/s / P95 ms |
| --- | ---: | ---: |
| A · 1 锁，100 次 yield | 425.83 / 81.48 | 610.78 / 59.99 |
| B · 8 锁，100 次 yield | 1912.10 / 19.65 | 2993.05 / 15.00 |
| C · 1 锁，1 次 yield | 27549.16 / 0.36 | 35635.25 / 0.16 |

B 相对 A 的吞吐分别为 4.49 倍和 4.90 倍，说明应用锁争用形态对本负载影响很大。要评估可优化的内核成本，还需在主机其它 QEMU 停止时对照 futex 阻塞／唤醒、队列等待、迁核、实际派发和宿主占用。C 的每事件工作量不同，不能换算成同量工作下的内核加速比。[锁争用调查 #300](https://github.com/muou000/PulseOS/issues/300)

## RV64 调度轨迹

单独使用干净 `39e61bab` 的 BPF 内核及生产 recorder，基于此前网络测试盘的私有副本。目标为 CPU 1 上 `taskset 2 /usr/bin/sysbench --threads=4 --time=30 --events=0 threads --thread-yields=100 --thread-locks=1 run`。待 4 个工作线程出现后运行 `bpf-record --events sched --cpus 1 --duration-ms 200 --buffer-pages 256 --kernel-elf /sched-kernel.elf --output /tmp/sysbench.pbcapture`，确认录制结束时应用仍存活。初次短负载在录制前退出，已排除。

使用 analyzer 的 `--loss` 和 `--sched-report --json` 读取整场会话，再以 mapping journal、应用 TID 和事件序列绑定 PID 58 的 4 个稳定 task 69/70/71/73。426 条记录包括 switch 169、block 56、wake 56、enqueue 145。4 个工作线程被选中 45/38/43/42 次。逐条核对的 10 个 futex 唤醒到被调度器选中区间中，中位数 76.7 µs，最大 1085.0 µs；11 个阻塞到唤醒区间中位数 941.0 µs。

会话状态为 `IncompleteError`。系统 trace_full=4120、timer_busy=9，源 2/3/4/6 的 cancelled 为 87/30/28/90；消费者丢弃及损坏为 0，mapping journal dropped=0。会话的左／右截断为 45/3，superseded 为 43。不同层次计数不可相加，完整配对的十条只描述此子集。原始 capture 的来宾与主机 SHA-256 一致，为 `e7c2b20de80b13864263f9b4bb031aa3c7955c480d5a806c636a74d4f7e96edd`；Release 证据包保留原文件、诊断、命令与构建身份，可独立回放。[跟踪事件丢失 #298](https://github.com/muou000/PulseOS/issues/298)
