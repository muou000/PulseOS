# io_uring SQPOLL 双架构验收（#247）

2026-11-23，QEMU 11.1.50（2a0ac9c8ac），virt，8 vCPU，8 GiB。两种架构均使用带测试套件的 ext4 镜像副本和 QEMU snapshot。RV64 使用 `-cpu max -bios default`，块设备经 virtio-mmio 连接；LA64 使用 virtio-pci。

## 活跃区间

同一用户态探针每批发布 4 个读请求，连续 8 批。每项使用唯一的 `user_data`，交替使用普通 fd 和固定文件，核对长度和全部字节。普通 ring 每批调用一次 enter。SQPOLL 在计量前唤醒，计量区间通过共享 CQ 接收全部结果。计数覆盖探针内该 ring 的所有 enter 入口。每侧只有一次短程计时，耗时包括用户态发布和收割。宿主还在执行其他验收任务，这组数据用于核对系统调用数，耗时会受 QEMU 调度影响。

| 架构 | 普通 ring 的 enter 次数 | SQPOLL 的 enter 次数 | 普通 ring 耗时 | SQPOLL 耗时 | 耗时变化 |
| --- | ---: | ---: | ---: | ---: | ---: |
| RV64 | 8 | 0 | 2619 μs | 3728 μs | +42.3% |
| LA64 | 8 | 0 | 2415 μs | 2744 μs | +13.6% |

基线启动产物的内核输入摘要为 `7ab7bc54863aec6b2a6ccd9457275f956a1d3410cbc288769b28a77a942dea49`，与 `bed3dc3a` 的内核输入一致。基线普通 ring 在 RV64 的特性探测中缺少 `SQPOLL_NONFIXED`。下列运行使用提交 `8ff29701` 对应的内核输入，摘要为 `6a6dbac6cad5317a4e69b58bd26e0fcd407033ccfee6be87f06aa0028351597f`。

## Guest 串口摘录

### RV64

启动文件 SHA-256 为 `d7fb54a4a94e6d31e8ff9e879f1f45aae5a6e5357cc718f7a49a5901c9c2efca`。

```text
SQPOLL ordinary flags, feature and affinity errors PASS
[  1.657990 1:53 pulse_core::io_uring::sqpoll:98] SQPOLL affinity requested=1 running=1
SQPOLL active batches=8 unique=32 ordinary_reads=16 fixed_reads=16 enters=0 elapsed_us=3728
SQPOLL foreign fd table, address space and wakeup PASS
SQPOLL regression ordinary ring unshare and close released writer PASS
SQPOLL unshare lookup, FILES_UPDATE, socket install and old table release PASS
SQPOLL full SQ_WAIT, sleep boundary and CQ overflow coexistence PASS
SQPOLL active/asleep/inflight close and exit reclaimed fixed writers PASS
SQPOLL_RESULT PASS
SQPOLL liburing-2.9 sqpoll-sleep.t PASS
BPF_HOST_EXIT riscv64 0
```

### LA64

启动文件 SHA-256 为 `805aebc31640f4634f81150d398a7039b2a4d50922582944888dd915f81a603b`。

```text
SQPOLL ordinary flags, feature and affinity errors PASS
[  1.135562 1:62 pulse_core::io_uring::sqpoll:98] SQPOLL affinity requested=1 running=1
SQPOLL active batches=8 unique=32 ordinary_reads=16 fixed_reads=16 enters=0 elapsed_us=2744
SQPOLL foreign fd table, address space and wakeup PASS
SQPOLL regression ordinary ring unshare and close released writer PASS
SQPOLL unshare lookup, FILES_UPDATE, socket install and old table release PASS
SQPOLL full SQ_WAIT, sleep boundary and CQ overflow coexistence PASS
SQPOLL active/asleep/inflight close and exit reclaimed fixed writers PASS
SQPOLL_RESULT PASS
SQPOLL liburing-2.9 sqpoll-sleep.t PASS
BPF_HOST_EXIT loongarch64 0
```

## 既有用例与回归

两端的 liburing-2.9 原兼容集均为 53 项通过、1 项跳过、0 项失败。跳过的是依赖 `IORING_REGISTER_FILES2` 的 `ooo-file-unreg.t`。两端 LTP `io_uring01` 至 `io_uring03` 通过，`io_uring04` 因 `AF_RDS` 返回 TCONF（32）。两端 `smp_stress` 通过。

- 上游 `connect-rep.t` 在第一轮 SQPOLL 运行中报出 `submit=2`。轮询线程现在复制 SQE 后即发布 SQ head，下一次提交可以在读到上一个 CQE 后立即复用槽位。
- 上游 `io-cancel.t` 在关闭 SQPOLL ring 时等待未就绪的管道。阻塞的 worker 现在同时订阅流就绪和取消通知；关闭 ring 后释放写端，管道读取返回 EOF。
- 对照提交 `7f13d552` 在普通 ring 的 `unshare(CLONE_FILES)` 用例中读到 `EAGAIN`。提交 `8ff29701` 将 fd 表保活限定在 SQPOLL 线程，双架构均在关闭 ring 后读到 EOF。

`make test` 以及双架构 `guest-checks` 的页帧、固定资源与拆除检查通过。宿主 `pulse_io_uring_core` 38 项、`pulse_syscalls` 235 项、`pulse_user_abi` 36 项和 `axtask` 14 项通过。

使用既有 `fio` 模式核对普通 ring 的直接 I/O 和缓存读。相对同步缓存读，LA64 QD32 的吞吐提升 31.57%。RV64 并行验收时仅提升 13.72%，未达到 20% 门槛；保持同一内核和镜像，单独运行 RV64 guest 后提升 34.17%，通过原门槛。

## BPF 导出回归

在相同的内核源上启用 `qemu bpf-trace`，使用既有 `--mode bpf` 验收器，以 100 Hz 采集 CPU 和调度事件。每个工况按验收器原有规则选取非空闲 CPU 样本最多的 PID/TID，导出内核模式的 period、samples 两种权重并完成 native perf 和 FlameGraph 核对。下表列出选中样本数和该 capture 中的非空闲样本总数。

| 架构 | 工况 | PID/TID | 选中／非空闲 | capture SHA-256 前缀 |
| --- | --- | --- | ---: | --- |
| RV64 | `cached_psync` | 66/95 | 466/793 | `3dfde56aa0963d3b` |
| RV64 | `cached_uring_qd32` | 122/144 | 445/622 | `6f832cb735767242` |
| RV64 | `direct_psync` | 171/194 | 368/476 | `9cf290a25d47cb05` |
| RV64 | `direct_uring_qd16` | 221/244 | 438/565 | `250793b5408c09ef` |
| LA64 | `cached_psync` | 97/106 | 514/678 | `f2abaf8fd1e2fb93` |
| LA64 | `cached_uring_qd32` | 148/157 | 483/621 | `b71614f3d24add21` |
| LA64 | `direct_psync` | 195/202 | 243/410 | `1a19f91471709e5b` |
| LA64 | `direct_uring_qd16` | 239/248 | 373/547 | `c5357cc60b71036f` |

首轮 RV64 `cached_psync` 中，样本 43679 缺少任务身份，严格导出失败。该工况使用 `--cases cached_psync --buffer-pages 128` 单独重采后通过。其余三个 RV64 工况从同一轮串口记录校验 SHA 并回放。各 capture 的会话级完整性为 `IncompleteError`，导出只验证所选线程的查询，不支持全系统热点归因。完整 capture 和导出保存在本地验收运行目录。

## 复现

构建工具会把固定版本的 liburing 和探针放入 `target/iouring-tests`。验收器每次从测试镜像复制出单独的运行盘，串口日志保存在其输出的运行目录中。

```bash
make test
./scripts/build_iouring_tests.sh --arch all
for arch in riscv64 loongarch64; do
    python3 tests/io_uring/run_acceptance.py --arch "$arch" --mode sqpoll
    python3 tests/io_uring/run_acceptance.py --arch "$arch" --mode functional
done
```

对照组在基线 guest 中运行同一可执行文件 `/opt/io_uring/sqpoll --ordinary-baseline`。
