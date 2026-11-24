# io_uring 专核通信双架构验收（#252）

RV64 与 LA64 均使用 QEMU 11.1.50（`v11.1.0-2112-g2a0ac9c8ac`），`virt`、8 个在线 vCPU、8 GiB 内存。内核与 guest 探针取自 `a8e058af`。每个 guest 中 CPU 0–6 允许运行用户任务，CPU 7 是唯一的内核保留核及 SQPOLL 服务核。每次运行从建环到关闭一直使用同一个 ring。完整 QEMU 参数、内核启动文件的 SHA-256、请求标识和原始计数见 [RV64](riscv64.json) 和 [LA64](loongarch64.json)。

| 观测项 | RV64 | LA64 |
| --- | ---: | ---: |
| ring ID | 3 | 3 |
| 提交至收割区间（guest 单调时钟，ns） | 3245719900–3340954300 | 2656550830–2715834280 |
| 活跃 SQ 消费（CPU 7 / 其他核） | 3 / 0 | 3 / 0 |
| 缓存读内联完成（CPU 7 / 其他核） | 1 / 0 | 1 / 0 |
| Future 首次 poll（CPU 7 / 其他核） | 1 / 0 | 1 / 0 |
| Future 恢复 poll（CPU 7 / 其他核） | 1 / 0 | 1 / 0 |
| Path 3 开始（CPU 7 / 其他核） | 1 / 0 | 1 / 0 |
| Path 3 完成（CPU 7 / 其他核） | 1 / 0 | 1 / 0 |
| 活跃期唯一 CQE / enter | 3 / 0 | 3 / 0 |
| 预热 / 空闲唤醒 / 4001 的 enter | 1 / 1 / 0 | 1 / 1 / 0 |
| CPU 0–7 用户任务调入增量 | 32, 2, 3, 0, 0, 0, 0, 0 | 34, 2, 2, 0, 0, 0, 0, 0 |

CPU 0 与 CPU 1 通过 release/acquire 交接共享 SQ 的发布权和 CQ 的收割权。CPU 1 提交两个读并分别核对返回的两个字节。请求 2001 命中内联缓存读，2002 带 `IOSQE_ASYNC` 进入工作池。CPU 0 随后提交 1001 并收割其 `POLLIN`。CPU 2 在主机从串口读到目标 ring 的首次 Pending 后写管道。内核记录每个 Future 的连续 poll 序号，runner 将其请求 ID 与用户发布的 `user_data` 配对。串口记录直接来自对应执行点，检查器要求预期的 SQ 消费、内联结果、连续 poll 直到 Ready、同一 worker 的开始与结束记录全部到齐。

`submit_to_reap_ns` 是用户态开始发布这组请求到收割最后一个 CQE 的单调时钟区间。`active_request_placement` 按请求身份统计执行点。调度器在每个用户线程实际调入时累计计数，建环和关闭时逐核读取，JSON 保留前值、后值和差值。内核对整个 ring 的所有线程累计 `io_uring_enter`，guest 另行分阶段计数。预热一次，空闲阶段在发布和屏障后观察到 `NEED_WAKEUP` 并显式唤醒。随后再发布 4001，核对同一 ring 上的 CQE。关闭后读取只剩注册文件表持有写端的管道，取得 EOF。

## 对照和回归

以基线 `9cb50387` 的 RV64 内核运行同一份 guest，主机在确认 Pending 后延迟 3 秒才通知写端。guest 完成了读取、异核唤醒、空闲恢复和关闭。验收器因缺少内核的 ring 计数而拒绝这份日志。

普通和 `guest-checks` 两种配置均通过 `make test`。普通配置在两个架构上的启动掩码都是 `reserved=0x0 user=0xff sqpoll=0x0`。两端的 LTP `io_uring01..03`、`smp_stress`、SQPOLL 回归和上游 `sqpoll-sleep.t` 均通过。观测内核另通过 `future-cpu` 与 `guest-checks` 回归。将每份专核日志中的 CPU、poll 序号、系统调用计数或后续请求 ID 改错时，验收器拒绝了每架构 10 个负对照。

**套件跳过项。** liburing-2.9 每架构 53 个程序通过、1 个跳过、0 个失败。依赖 `IORING_REGISTER_FILES2` 的 `ooo-file-unreg.t` 返回 77。通过的程序内部也报告了可选子用例跳过，包括 `connect` 的 flags 0x3000、`read-write` 的 buffer select、`send_recv` 的可选 recv，以及 `timeout` 的 exec-target。LTP `io_uring04` 需要 `AF_RDS`，返回 TCONF（32）。上表的三条专核路径均由独立的目标请求完整验证。

**RV64 普通回归的间歇性停顿。** 三次运行在 `accept-test.t` 启动后停住，两次等待超过 3 分钟，第三次在独立复跑成功后终止。保留同一份已安装的镜像，在基线和本分支各启动新 QEMU 快照，直接运行原来的 `sh /opt/io_uring/guest_job.sh`。两次完整套件均以 0 退出，结果如上。再只运行原始 `accept-test.t`，设置 50 秒宿主超时，基线 `9cb50387` 在三次冷启动中超时一次，本分支在三次中超时两次。具体原因和发生率尚未确定。

**宿主测试。** 340 项测试通过。默认并行运行时，三个 BPF 测试共用模拟 CPU 13，出现重入计数冲突与超时。同样三项失败在基线上复现。改用 `cargo test -p pulse_syscalls --lib -- --test-threads=1` 后，235 项 syscall 测试全部通过。

## 复跑

在仓库根目录执行。准备 RV64 的 `disk.img` 和 LA64 的 `disk-la.img` 测试镜像，确认 `kernel-rv` 和 `kernel-la` 分别指向本次构建的 RV64 BIN 和 LA64 ELF。本次使用已暂存的 liburing-2.9 套件，并运行 `--component tests` 重新交叉编译 guest 探针。以下命令从头生成测试二进制，再分别运行两种配置。

```sh
set -e
scripts/build_iouring_tests.sh --arch all --component all
make test APP_FEATURES="qemu guest-checks"
for arch in riscv64 loongarch64; do
    python3 tests/io_uring/run_acceptance.py --arch "$arch" --mode dedicated-ring
done
make test
for arch in riscv64 loongarch64; do
    for mode in functional sqpoll; do
        python3 tests/io_uring/run_acceptance.py --arch "$arch" --mode "$mode"
    done
done
```

Runner 为每次启动复制对应架构的镜像，并在 QEMU 的快照模式下运行。专核用例将副本的 `/etc/pulse-kernel-cpus` 和 `/etc/pulse-sqpoll-cpus` 都设为 `7`。普通回归从原始测试镜像另取副本。每次运行保留 `guest.log`，输出复跑目录和 QEMU 命令。
