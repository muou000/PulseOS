# #271 内核模块迁移整体验收

基线是 `4f9af137`，移除门面的代码提交是 `c4b20a56`。QEMU virt 使用 8 vCPU、8 GiB、快照磁盘和用户网络，RV64 用 `-cpu max`、VirtIO MMIO 和 `disk.img`，LA64 用 VirtIO PCI 和 `disk-la.img`。默认内核为 release、SMP、info。每次来宾对照都使用相同架构的同一测试镜像。

| 默认启动文件 | 基线 SHA-256 | 迁移后 SHA-256 |
| --- | --- | --- |
| RV64 .bin | `a10b1f62ab420c13e37222fdd5cd358644f6dc1f2221bfbbf6ec4e27a719c193` | `d77a343a4b1d5f2f72e6826ac17e67076e448e58e3150278fcc1aa190b879360` |
| LA64 .elf | `e08ae0981fb52335cc7daf571debea23daeba00d55e159180626604e2f3087ea` | `073efb9f377053024f581713c1ea3fbe0092452481b21fc5d9f04f669c84cc3f` |

默认基线内核来自 `403a5648`，其 Git 树与 `4f9af137` 相同。已按各自构建清单验证启动文件与符号 ELF。工具链是 rustc 1.101.0-nightly（`c1070d693`）、QEMU 11.1.50（`2a0ac9c8ac`）。迁移后的内核清单记录 1,002 个本地输入文件，源码 SHA-256 为 `4d8a24a24d206065dae3afb9e6bec77760f2153b2760db4ae64f97eeed0c3022`。

## 模块与依赖

逐项核对 ADR-0009 的旧名和目标名。下表中每个目标都恰有一个本地 Cargo package ID，根工作区成员、目录、库目标及依赖导入名一致。[旧名到目标名清单](../docs/adr/0009-module-names-and-ownership.md)

| 批次 | 已核对的 `modules/` 包 |
| --- | --- |
| #268 基础模块 | `kernel_alloc`、`config`、`cpu`、`hal`、`ipi`、`kernel_log`、`runtime`、`sched`、`sync`、`task` |
| #269 内存与 I/O | `mm`、`fs`、`vfs`、`io`、`poll`、`net`、`io_uring_core` |
| #270 驱动与显示 | `driver`、`driver_base`、`driver_block`、`driver_display`、`driver_net`、`driver_pci`、`driver_virtio`、`display` |
| #264–267 从旧门面迁出 | `ipc`、`bpf`、`elf_loader`、`process` |

锁定 metadata 有 44 个工作区成员，默认解析 282 个包，全特性解析 323 个。RV64 与 LA64 默认目标树均选中 27 个模块，启用显示后选中全部 29 个。`Pulse` 和内核目标的 `pulse_syscalls` 都直接依赖 `process`。后者直接使用 `ipc`、`bpf`。三个外部 Arm/x86 平台仍通过 `crates/compat/axcpu` 使用同一个本地 `cpu` 实现。

比较两种 QEMU 目标各六组 Cargo 图（默认、BPF、guest checks、二者同时启用、mapping/file 检查、显示）以及两个板级目标。逐包核对名称、版本、来源及选中的 feature，去除旧门面后与基线一致。三个独立主机 workspace 均通过锁定解析及各自的运行入口。现行补丁 `tests/kernel_cpus/switch-counts.patch`、`tests/io_uring/worker-scheduler.patch`、`tests/sysv_ipc/shmdt-reservation.patch` 均通过 `git apply --check`。#136 的补丁按归档提交回放。

## 双架构来宾行为

| 默认内核检查 | RV64 和 LA64 的实测结果（每架构） |
| --- | --- |
| SysV IPC 生命周期 | 基线与迁移后均通过 5 项。最后一个 `shmdt`、进程退出、失败的 fork、共享地址空间的 vfork 和 `SEM_UNDO` 的释放符合探针预期。 |
| LTP SysV IPC | 两版各架构相同。`shmat01` 失败 4 项，`shmdt01` 失败 1 项，`semget01` 通过 1 项、失败 2 项，`semop01` 通过 4 项。已有失败涉及 `IPC_STAT` 返回的段大小、挂接数、信号量数量及创建者字段。 |
| exec | 两版均通过 LTP `execve01` 至 `execve06` 共 170 条断言。缺失 ELF 解释器时返回 `ENOENT`，原调用线程与同组线程能再次会合。 |
| 文件映射 | 两版各通过 3 项，覆盖重叠读顺序、写入端 COW 隔离和同文件跨窗口追加。两侧复用相同探针 ELF，runner 核对源镜像摘要和正常关机。 |
| PID 1 与退出 | 两版的身份、fork、信号递送、子进程回收和写回关机均通过。每次 QEMU 正常退出。 |
| FD 与 io_uring | 两版均通过 LTP `io_uring01–03`。`io_uring04` 因 AF_RDS 返回 TCONF。liburing 每次 53 项通过，`ooo-file-unreg.t` 返回 77 跳过。SMP 压力通过，含 16 轮有在途固定缓冲区读、poll 和 timeout 的异常退出。 |
| SQPOLL | 两版的外部提交者、共享与已分离的 FD 表、固定文件更新及最后关闭均通过。上游 `sqpoll-sleep.t` 的 90–110 ms 窗口在基线首次启动测得 RV64 65 ms、LA64 85 ms，两者原配置重试均通过。迁移后两者首次均通过。 |

在镜像内执行 `/opt/ltp/testcases/bin/{shmat01,shmdt01,semget01,semop01}` 及 `execve01` 至 `execve06`。exec 设置 `LTPROOT=/opt/ltp`，将 `$LTPROOT/testcases/bin` 加入 PATH 并进入该目录。`execve05` 采用 `-i 5 -n 32`。[IPC 探针](../tests/sysv_ipc/README.md) · [失败 exec 探针](../tests/exec/README.md)

按架构取对应镜像，默认内核用以下入口复现。io_uring 的产物由 `scripts/build_iouring_tests.sh` 构建。

```sh
make test
for arch in riscv64 loongarch64; do
    python3 tests/init_shutdown/run.py --arch "$arch" --action identity
    python3 tests/file_sg_io/run.py --arch "$arch" --suite mappings
    python3 tests/io_uring/run_acceptance.py --arch "$arch" --mode functional
    python3 tests/io_uring/run_acceptance.py --arch "$arch" --mode sqpoll
done
```

## 构建与主机门禁

- `make test` 构建两个默认内核。`python3 tests/guest_checks/build.py` 对两种架构各检查默认、仅 BPF、仅 guest checks、BPF 与 guest checks 同时启用这四种链接结果。
- `make vf2` 在 SMP=4 下生成 U-Boot 镜像。头部和载荷 CRC 通过，载荷逐字节匹配 .bin，加载和入口地址均为 `0x40200000`。`make ls2k1000` 在 SMP=2 下生成 ELF，SHA-256 前缀为 `e9f5be2ccde7`。两块实体板均只进行构建与产物验证。
- 三个独立工作区均通过锁定 Cargo 解析。`tests/axfs_io_host` 通过 10 项文件位置及 2 项 FAT 测试，`tests/axfs_mount_host` 通过 16 项，`tests/axsync_host` 的 4 组运行检查通过。
- 根工作区串行运行 BPF、io_uring 状态机、系统调用、线程采样时钟和 VFS 共 299 项。另有 7 项 ELF 装载与 36 项用户 ABI 测试通过。构建脚本 10 项、映射 runner 5 项、BPF recorder 38 项、采样工具 110 项 Python 测试通过。采样工具测试使用本机 perf 及仓库测试使用的 FlameGraph。
- 两种内核目标均通过 `cargo check --locked`，合并启用 `qemu,smp,bpf-trace,guest-checks,mapping-lifecycle-test,file-io-test` 及架构对应的总线配置。

```sh
cargo metadata --locked --format-version 1
cargo metadata --locked --all-features --format-version 1
cargo test --locked -p pulse_syscalls -p bpf -p io_uring_core -p vfs -- --test-threads=1
cargo test --locked -p elf_loader -p axfeat -p pulse_user_abi --lib \
    --features axfeat/multitask,axfeat/irq,axfeat/fs,task/test -- --test-threads=1
python3 tests/guest_checks/build.py
make vf2
make ls2k1000
```

## 额外的映射与文件 I/O 启动组合

两版另行构建了 `make test APP_FEATURES="qemu mapping-lifecycle-test file-io-test"`，并对两个架构各运行同一条 `tests/file_sg_io/run.py --suite mappings` 命令。四次均打印 20 个相同的 `MLC_KERNEL PASS`，包括 9 个进程地址空间用例、9 个 FS 页缓存用例、ext4 相邻块缓存检查和写回失败阻止关机检查。

四次都在随后运行的写回缓冲池自检处停止。`drop(data1)` 后，全局池长度为 2，自检要求为 1。这组内核未到达 shell，用户态映射探针执行了 0 条断言。上表的 3 项用户态映射断言来自正常启动的默认内核。[触发断言的启动自检](../modules/fs/src/highlevel/file/cache.rs)

本次验证了三份插桩补丁对最终源码的适用性。SHM 解绑失败注入、完整 LTP 套件、实体板启动和性能对比均未运行。

## BPF 与启动检查

干净基线 `4f9af137` 与实现提交 `c4b20a56` 均以 `qemu bpf-trace guest-checks` 启动，使用 QEMU 11.1.50 virt、8 vCPU、8 GiB 和对应架构的快照磁盘。每次运行均在启动串口日志中逐条核对 13 个 BPF/管道断言和 6 个 io_uring 固定资源及并发 worker 断言。

`tests/bpf_sampling` 的专项 guest 在自己的 TID 创建一个软件 task-clock 事件，周期 10 ms，全部 8 个 CPU 各有 16 页输出环。探针执行固定热点 A/B、检查睡眠期间的 task clock，以及 link 持有目标、ioctl 附着后 dup 至最终 FD 关闭的采样寿命。下表按记录条数统计整个采样窗。

| 内核 | TID / 稳定 task ID | 样本（热点 A / B） | RAW 质量 / capture 状态 | 采集窗口诊断增量 |
| --- | --- | --- | --- | --- |
| 基线 RV64 | 50 / 50 | 375（191 / 182） | `partial` / `IncompleteError` | global timer_busy 121，event skipped 7 |
| 基线 LA64 | 54 / 54 | 45（25 / 20） | `partial` / `IncompleteError` | global timer_busy 26，event skipped 5 |
| 候选 RV64 | 50 / 50 | 371（182 / 187） | `partial` / `IncompleteError` | global timer_busy 97，event skipped 1，event cancelled 1 |
| 候选 LA64 | 54 / 54 | 50（28 / 22） | `partial` / `IncompleteError` | global timer_busy 21 |

四次探针均通过，外来任务样本、环传输丢失和 RAW 导出丢弃均为 0。主机验证 RAW 后生成 capture v6，解码条数与 RAW 逐次相符。全局和事件级诊断作用域重叠，分析器对四份 capture 均报告 `attribution_claim_allowed=false`。样本数用于验证采样注册、身份和递送。本轮未测符号调用栈、生产 recorder 全矩阵或性能变化。

| 内核 | 启动文件 / 匹配 ELF SHA-256 前缀 | capture SHA-256 | 本地运行目录（`tests/bpf_sampling/runs/`） |
| --- | --- | --- | --- |
| 基线 RV64 | `0e15c55c90412166` / `740dd67c7effd492` | `eb0f63d56ab1006aeed07e06d8ecd8052fecdff5febcf93a08a7b5da40a666ee` | `riscv64-task-20261124-211215-zglom55c` |
| 基线 LA64 | `0269f31e57065bb3` / `0269f31e57065bb3` | `e34364c9c27b625a83c4c3363cffbe140404c29e101335e671332297e2b0f2f3` | `loongarch64-task-20261124-211215-dtt1hnj0` |
| 候选 RV64 | `aaac435af3d1454b` / `6369e63cc15b527c` | `2aff8b4af3ed046de8de240f4d1f65c9510bfe5227216d303f529fc9b7f14cf4` | `riscv64-task-20261124-211544-am3pepuv` |
| 候选 LA64 | `10faca2b09bf711c` / `10faca2b09bf711c` | `6db38e3ef680c8788d93a67872f1231a018e5e1b6e86514ab5d8dc01f358043d` | `loongarch64-task-20261124-211807-39bhd6uv` |

源镜像 RV64 / LA64 SHA-256 前缀为 `efc83112f60d929c` / `ef9a74f8c7fdde1e`。专项 guest ELF 分别为 `00773fe6521543a7` / `308abcf8a0c20ae9`，主机 analyzer 为 `027ffe799b545ea0`。每份运行目录含 `inputs.json`、`kernel.provenance.json`、`guest.log`、`records.pbraw`、`capture.pbcapture` 和分析结果，核对了实际启动文件、匹配 ELF 与构建时提交。原包留在本地忽略目录，仅凭哈希无法回放。

复现时 `$boot`、`$elf` 指向同一干净提交的组合 feature 构建产物，`$image` 使用对应架构原始镜像。

```sh
python3 tests/bpf_sampling/run.py guest --arch "$arch" --mode task --archive \
  --kernel "$boot" --kernel-elf "$elf" --kernel-provenance "$elf.provenance.json" --image "$image"
```
