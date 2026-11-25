# QEMU 网络应用与性能审计 · 2026-11-25

`rootfs-tests-20261125` 为 RISC-V 64 和 LoongArch64 的 QEMU 测试盘提供了 iperf3 3.22.1、darkhttpd 1.17 和 weighttp 0.5-pulse1。两端都能运行 IPv4 TCP、UDP 和并发 HTTP 测试。发布镜像上的首要正确性问题是 **宿主下载 64 KiB 文件时，服务端已记录 200，客户端仍可能提前遇到 EOF**。另外，两种架构的 TCP 新连接都丢失了监听端的 `TCP_NODELAY` 设置。下文给出可以复核这些行为的命令，以及为后续内核改动留存的性能基线。[测试工具发布](https://github.com/muou000/PulseOS/releases/tag/rootfs-tests-20261125) · [网络审计总票 #289](https://github.com/muou000/PulseOS/issues/289)

## 环境与测量口径

- 两种来宾均使用 QEMU 11.1.50（`v11.1.0-2112-g2a0ac9c8ac`）、`virt`、8 vCPU、8 GiB、TCG、磁盘快照和 QEMU user 网络。RV64 使用 `-cpu max` 与 VirtIO MMIO，LA64 使用 VirtIO PCI。宿主为 x86-64 WSL2 Linux 6.6.87.2。来宾回环、来宾访问 `10.0.2.2` 的宿主服务、宿主通过 `hostfwd` 访问来宾服务，是三条分别测量的路径。
- HTTP、传输和 socket 测试使用干净的常规内核 `3f8b3396` 和发布版本 `39e61bab` 制作的测试盘。两次提交之间为 rootfs、脚本和文档变更。CPU 采样使用单独构建的 RV64 BPF 内核和采样盘，源码为 `39e61bab`。环境清单记录各内核、ELF、原盘、recorder、analyzer 和宿主 iperf3 的 SHA256。[环境与产物身份](environment.json)
- 这些数据用于同架构、同路径、同参数的改动前后复测。本次没有运行网络内核优化后的对照版本。宿主上观察到其他 QEMU 或编译任务，短时吞吐、延迟与跨架构差值均受调度影响。结果限于上述 QEMU 用户态网络和来宾回环。

## HTTP 正文、短连接与连接复用

每架构 48 轮，分别对回环与 hostfwd、61 B 原装页面与 64 KiB 全零文件、并发 1 与 8、逐请求建连与 keep-alive 各测三遍。每轮使用一个客户端线程，发出 48 个请求。计入吞吐的轮次须满足 48 次成功、48 个 2xx、零失败与错误、正文字节总数正确且连接复用数符合预期。RV64 的 48 轮均合格，且逐请求标记与服务端日志相符。LA64 有 41 轮合格，主测试服务端日志下载也提前结束，LA64 主矩阵按客户端统计。完整表保留每个单元的成功轮数及其中位数，各轮结果另列 p95、RPS 和字节数。[HTTP 逐场景结果](evidence/http.md) · [逐轮数据及独立客户端收到的字节分布](evidence/http-details.json)

- **回环小页面。** 并发 1 时，短连接 / keep-alive 的中位吞吐为 RV64 136 / 64 req/s、LA64 96 / 54 req/s。并发 8 时分别为 129 / 156 和 126 / 140 req/s。这组数据说明连接复用效果随并发和负载而变。
- **大正文正常关闭。** LA64 hostfwd、64 KiB、并发 1 的三轮都有 48 个 2xx，但完整响应仅 43、27、30 个。并发 8 的三轮均触发 20 秒 watchdog。独立测试改用宿主 Python 客户端逐次核对完整正文，服务端使用发布的 darkhttpd。两架构都能复现，其中 RV64 主性能矩阵曾全部通过。[HTTP 完整性问题 #290](https://github.com/muou000/PulseOS/issues/290)

| 架构 | 并发 | 完整且字节相同 / 请求总数 | 正文提前 EOF | 连接异常 | 服务端记录 200 |
|---|---:|---:|---:|---:|---:|
| RV64 | 1 | 25 / 32 | 7 | 0 | 32 |
| RV64 | 8 | 25 / 32 | 7 | 0 | 32 |
| LA64 | 1 | 25 / 32 | 7 | 0 | 32 |
| LA64 | 8 | 18 / 32 | 13 | 1 | 32 |

**TCP_NODELAY。** darkhttpd 对监听 fd 设置 `TCP_NODELAY=1`。在两个来宾上，`accept()` 返回的 fd 都读出 0，Linux 宿主对照读出 1。用同一份诊断版 darkhttpd 交替开启、关闭“在子 fd 上重新设置选项”，在回环、61 B、并发 1、keep-alive、每轮 48 次的条件下，RV64 两对 p50 从 27.59、24.20 ms 降至 13.61、16.34 ms，LA64 从 24.09、25.53 ms 降至 15.02、9.04 ms。该应用诊断单独保留，发布版 darkhttpd 仍使用上游源码。[继承语义问题 #291](https://github.com/muou000/PulseOS/issues/291) · [诊断补丁](darkhttpd-nodelay.patch)

## TCP 与 UDP 传输

76 次 iperf3 运行中，74 次完成传输，两个架构各有一次显式设置 128 KiB 窗口时报错。表中单位均为接收端 Mbit/s。TCP 的 P1、P4 指 1、4 条数据流。每轮 2 秒，除 UDP 1M 和窗口选项诊断各一次外，每个场景三轮取中位数。回环正向由来宾客户端发送，反向由同一来宾内的服务端发送。网卡反向通过 `-R` 让宿主 Linux 服务端发送。RV64 六个回环样本的初始驱动误将服务端后台进程的等待状态判为失败，随后取回原轮次双方 JSON，核对端点和收发字节后计入。完整范围、收发端口径、UDP 丢包和抖动见附件。[传输结果](evidence/transport.json)

| 负载 | RV64 | LA64 |
|---|---:|---:|
| TCP 回环 P1 正向 / 反向 | 146.6 / 150.3 | 108.6 / 118.4 |
| TCP 来宾 → 宿主 P1 / P4 | 56.6 / 62.1 | 41.6 / 65.7 |
| TCP 宿主 → 来宾 P1 / P4 | 114.8 / 121.4 | 74.7 / 117.6 |
| UDP 来宾 → 宿主，512 B，目标 1M / 10M / 40M | 0.992 / 5.108 / 4.704 | 0.968 / 8.929 / 8.875 |
| UDP 来宾 → 宿主，1200 B，目标 40M | 12.520 | 20.485 |

两架构的 512 B UDP 都未达到 40 Mbit/s 发送目标。补测在两种架构分别重新启动，保持报文大小和路径，交错使用默认 pacing、10 ms pacing 和不限速。发送端中位速率为 RV64 1,239 / 1,174 / 1,324 包/秒、LA64 1,961 / 1,851 / 1,850 包/秒。接收端对应 5.055 / 4.783 / 5.393 和 7.957 / 7.538 / 7.531 Mbit/s。18 次补测的接收端序号丢包计数均为 0。其中 11 次收发包数相等，另 7 次接收比发送少 1 包，尾包是否落在计数窗口之外仍待核对。发送端自身未达到目标。调整 pacing 定时器并未持续提高包率。精确归因仍需逐段计数。[UDP pacing 对照与宿主负载范围](evidence/udp-pacing.json) · [小包发送研究 #311](https://github.com/muou000/PulseOS/issues/311)

## Socket ABI、分配与就绪等待

同一 C 探针在 Linux 宿主和两种来宾上使用标准 socket API。两个来宾得到相同的选项结果。以下差距影响应用行为，也影响 iperf3 输出的解释。[探针源码与构建命令](socket_probe.c) · [RV64 探针结果](evidence/socket-rv.json) · [LA64 探针结果](evidence/socket-la.json)

| 应用动作 | 两种 PulseOS 来宾 | Linux 宿主对照 |
|---|---|---|
| TCP/UDP 分别为收发缓冲请求 16、128 KiB | 设置均返回成功，读回始终为 65,536 B。两架构 iperf3 的 `-w 128K` 均退出 1，报 `socket buffer size not set correctly` | 读回 32、256 KiB |
| TCP 已建立连接并传输 2,048 B 后读取 `TCP_INFO` | 成功返回 104 B，状态、MSS、cwnd、RTT、重传均为 0。`TCP_CONGESTION` 报告 cubic | 返回 248 B，已建立、MSS 1,448 B、cwnd 10 段、RTT 非零 |
| 设定 100 ms 的 `SO_RCVTIMEO` 后读回 | 设置与读取均成功，读回 0 | 读回 100 ms |
| 设置并读取 `SO_LINGER={1,0}`，复制 fd 后关闭 | 设置与读取均为 `ENOPROTOOPT`。复制的 fd 可继续收发，最后关闭后对端读到 EOF | 选项往返成功，最后关闭后对端读到 `ECONNRESET` |

因此来宾发送端的 RTT、cwnd、重传数和拥塞控制名称不能作为该次 TCP 传输的实测遥测。反向网卡场景的发送端在 Linux，附件标明了各项来源。weighttp 0.5-pulse1 对 `SO_LINGER` 返回 `ENOPROTOOPT` 作兼容处理，继续按系统默认方式关闭。[缓冲区 #305](https://github.com/muou000/PulseOS/issues/305) · [SO_LINGER #307](https://github.com/muou000/PulseOS/issues/307) · [TCP_INFO #308](https://github.com/muou000/PulseOS/issues/308) · [超时读回 #309](https://github.com/muou000/PulseOS/issues/309)

**空闲 socket 的内存占用。** 单次在无业务数据的条件下创建 16 个 TCP socket，两个来宾的 `MemFree` 均下降 8,208 KiB，折合 513 KiB/个。创建 4 个 UDP socket 时均下降 34,304 KiB，折合 8,576 KiB/个。关闭后 TCP 与初始值相差 16 KiB，UDP 回到初始读数。这是来宾全局内存差，包含缓冲、元数据与分配器效应。[空闲 socket 内存 #306](https://github.com/muou000/PulseOS/issues/306)

**一个连接可读时的等待成本。** 最后一个 TCP 连接保留一个未读取字节，其余 1、16 或 64 个连接空闲。仅订阅读事件，timeout 为零，每次测 64 个系统调用，取三轮单次平均耗时的中位数。两种架构所有窗口均只报告预期 fd。下表单位为微秒，每格依次为三种空闲 fd 数量。pipe 对照使用相同事件和迭代次数。

| 等待方式 | RV64（1 / 16 / 64） | LA64（1 / 16 / 64） |
|---|---:|---:|
| TCP epoll_wait | 278 / 8,533 / 100,454 | 70 / 1,683 / 23,397 |
| TCP poll | 203 / 6,960 / 100,743 | 52 / 1,884 / 23,397 |
| pipe epoll_wait | 47 / 81 / 373 | 21 / 27 / 68 |
| pipe poll | 38 / 107 / 640 | 10 / 27 / 72 |

TCP 查询就绪时会进入 `poll_interfaces`，后者遍历 socket 集合并处理唤醒。测量表明相同可读数下增加空闲 TCP 连接会大幅增加等待成本。各次扫描、锁持有和有效唤醒的开销尚无独立计数。[就绪检查 #304](https://github.com/muou000/PulseOS/issues/304) · [网络栈扫描路径](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/net/src/smoltcp_impl/mod.rs#L306)

## RV64 内核 CPU 采样

分别在空闲监听、TCP 回环、TCP VirtIO 出站和回环短连接 HTTP 上，用生产 recorder 对全部 8 个 CPU 做 3 秒采样。周期为 10 ms，使用 FP 调用栈和 64 页缓冲。各窗口只采一次。三个有负载的客户端都在采样前启动并持续到窗口结束，最终退出码均为 0。[详细采样分析](evidence/bpf.md) · [身份、逐源丢样、栈状态与叶地址](evidence/profile.json)

| 场景 | 保留内核样本 | 链完整 / 部分 / 不可用 | 链含 poll_interfaces | 软件校验和叶样本 |
|---|---:|---:|---:|---:|
| 空闲 | 2,132 | 229 / 6 / 1,897 | 0 | 0 |
| TCP 回环 | 2,013 | 264 / 183 / 1,566 | 154 | 33 |
| TCP VirtIO 出站 | 2,125 | 367 / 130 / 1,628 | 217 | 8 |
| 短连接 HTTP | 1,922 | 272 / 251 / 1,399 | 145 | 1 |

回环 33 个校验和叶样本中，发送调用链 21 个，接收调用链 12 个。HTTP 的 16 个 `memset` 叶样本中，14 个可追溯到创建 TCP socket 或收到 SYN。VirtIO wrapper 的 139 个叶样本中有 135 个位于重新使能 IRQ 的指令之后。定时 IRQ 的观察位置受关中断区间影响，需要额外计数才能量出区间内部的实际开销。[回环校验和研究 #310](https://github.com/muou000/PulseOS/issues/310)

四个采样会话均为 **IncompleteError**，有 timer busy、skipped、cancelled 和未知映射身份。各源记录的 transport_lost、export_discarded、emission_gap 均为零。内核符号已与 ELF 和运行时地址核对，分析器的整会话 `attribution_claim_allowed` 为 false。以上数量只描述保存下来的内核样本，不可换算成 CPU 利用率或锁等待时间。LA64 没有对应采样。仓库保留聚合值、身份与代表性调用链；完整二进制 capture 和逐请求临时日志没有长期保留保证。

## 复现

1. 可直接从 Release 下载并校验对应的测试盘。需要自行制盘时，在发布标签的仓库根目录使用 `./scripts/fetch-rootfs.sh --tests`，然后分别执行 `make img ARCH=riscv64`、`make img ARCH=loongarch64`。按仓库说明启动对应常规内核和快照盘。测宿主 HTTP 时，在现有 `-netdev user,id=…` 末尾添加 `,hostfwd=tcp:127.0.0.1:18080-:8080`。[QEMU 启动命令](../../README.md#运行测试-qemu)
2. 在来宾启动以下服务。对于其他矩阵单元，更换文件名和 `-c 1/8`，保留或去掉 `-k`。hostfwd 客户端在宿主运行同版本 weighttp，将 URL 改为 `http://127.0.0.1:18080/large.bin`。正文校验器在宿主运行，返回非零表示至少一个请求不完整。独立核对时为每轮保留服务端日志和客户端结果。[宿主正文校验器](http_close.py)

   ```sh
   dd if=/dev/zero of=/opt/netbench/www/large.bin bs=65536 count=1
   darkhttpd /opt/netbench/www --addr 0.0.0.0 --port 8080 --no-listing \
       --log /tmp/http-access.log >/tmp/darkhttpd.out 2>&1 &
   weighttp -q -t 1 -n 48 -c 1 -k -a 12 -s 5 http://127.0.0.1:8080/index.html
   ```

   ```sh
   python3 records/qemu-network-20261125/http_close.py --port 18080 -c 1
   python3 records/qemu-network-20261125/http_close.py --port 18080 -c 8
   ```

3. TCP、UDP 回环在来宾启动 `iperf3 -4 -s -B 127.0.0.1` 并在来宾连接 `127.0.0.1`。测网卡时改在宿主监听 `127.0.0.1`，来宾运行以下示例，双方分别保存 JSON。TCP 调整 `-P 1/4` 和 `-R`，UDP 调整 `-b` 和 `-l`。单独的 pacing 对照分别使用 `-b 40M`、`-b 40M --pacing-timer 10000` 及 `-b 0`。

   ```sh
   iperf3 -4 -c 10.0.2.2 -t 2 -i 1 -J --connect-timeout 3000 -P 4 -R
   iperf3 -4 -c 10.0.2.2 -t 2 -i 1 -J --connect-timeout 3000 -u -b 40M -l 512
   iperf3 -4 -c 10.0.2.2 -t 2 -i 1 -J --connect-timeout 3000 -w 128K
   ```

4. 按源码开头的静态编译命令为各架构构建探针，将对应二进制置于测试盘快照，在来宾分别执行 `./probe`、`./probe footprint`、`./probe ready`。复核 NODELAY 对应用的影响时，在上游 darkhttpd 1.17 源码目录用 `patch -p1` 应用本记录的补丁。以同一诊断二进制交替运行两遍环境变量未设置、两遍设置 `PULSE_DIAG_REAPPLY=1` 的服务，保持日志和客户端参数一致。每次用 `weighttp -q -t 1 -n 48 -c 1 -k -a 12` 访问同一回环 URL。[ABI 探针](socket_probe.c) · [NODELAY 诊断补丁](darkhttpd-nodelay.patch)
5. CPU 采样需使用 BPF 内核、与其匹配的 `/boot/kernel.elf` 及生产 recorder。每个负载开始后采集，再运行宿主 analyzer 的 `--loss`、`--artifact-manifest`、`--weight period --json` 和 `--mode kernel --weight period --json` 检查身份、损失和样本分布。完整命令与采样参数见记录。[采样复现命令](evidence/bpf.md)
