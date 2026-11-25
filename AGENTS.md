# AGENTS.md

本仓库的协作约定如下。

## 项目上下文

- 这是一个基于 ArceOS 组件化内核构建的 PulseOS 仓库，目标是同时支持 RISC-V 64 和 LoongArch64。
- 仓库的主要结构如下：
  - `modules/`：内核核心模块（从原 ArceOS 及核心 crates 摊平迁入，包括内存、文件系统、调度、驱动等）。
  - `api/`：统一功能特性与接口层（`api/axfeat`）。
  - `configs/`：内核及平台构建配置文件（如 `defconfig.toml`）。
  - `platforms/`：平台适配实现与 `axplat` 统一抽象层（RISC-V virt, VisionFive 2, LoongArch virt, LS2K1000）。
  - `modules/process/`：用户进程与线程生命周期、用户内存访问、FD、socket、io_uring 执行和 trap。
  - `pulse_syscalls/`：Linux 兼容系统调用实现与分发。
  - `crates/`：独立的外部支持库或待解耦 crates（如 `eevdf-scheduler`, `ext4plus`, `smoltcp`, `virtio-drivers` 等）。
  - `scripts/`：根 Makefile 构建支撑（`scripts/make/`）与镜像辅助脚本。
  - `src/`：内核启动与主入口。
  - `records/`：日志、记录和过程性产物，通常不参与正式构建。
  - `sdcard-rv.img` 和 `sdcard-la.img` 分别是 riscv64 和 loongarch64 架构下的测例镜像。

## 编译方式

- 统一编译入口（除非必要不要关闭日志）：
  - RISC-V 64：`make rv 2>&1 | tail -30`
  - LoongArch64：`make la 2>&1 | tail -30`
  - VisionFive 2：`make vf2 2>&1 | tail -30`
  - LS2K1000：`make ls2k1000 2>&1 | tail -30`
  - 双架构构建门禁：`make test 2>&1 | tail -30`
- 若需要清理构建产物，统一使用 `make clean`。

## 运行测试方式

- **测试镜像**：优先使用包含预装测试套件的测试 rootfs 镜像（通过 `./scripts/fetch-rootfs.sh` 与 `./scripts/build_img.sh all`，或 `make img ARCH=riscv64` / `make img ARCH=loongarch64` 生成 `disk.img` / `disk-la.img`）。镜像内已包含 `lmbench`（`/opt/lmbench/bin` 及 `/bin/{bw_pipe,lat_pipe,lat_syscall}`）、`LTP`（`/opt/ltp`）、`sysbench`（`/usr/bin/sysbench`）、`UnixBench`（`/opt/unixbench`）、`fio`（`/usr/bin/fio`）、`liburing` 核心测试子集（`/opt/io_uring/liburing-tests`）和 RocksDB（[来宾基准命令](README.md#在来宾里测试-rocksdb)）。
- **测试选型**：验证功能与性能指标时，优先选用上述预装的第三方标准测试套件（`UnixBench`、`lmbench`、`LTP`、`sysbench`、`fio`、`liburing`、RocksDB）；仅当第三方套件中没有能够针对性展示当前优化点或功能行为的用例时，才编写自定义测试。
- **网络测试**：TCP/UDP 吞吐与丢包使用 iperf3，并发 HTTP 使用 darkhttpd 和 weighttp。回环与 VirtIO 两种路径的命令和成功判据见[来宾网络测试](README.md#在来宾里测试网络)。

新工作树先按 [README 的 QEMU 运行步骤](README.md#运行测试-qemu) 建立 `kernel-rv` 和 `kernel-la` 链接。使用以下命令启动来宾。

### RISC-V 64

```bash
qemu-system-riscv64 -machine virt -cpu max -kernel kernel-rv -m 8G -nographic -smp 8 -bios default -drive file=disk.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net -rtc base=utc
```

### LoongArch64

```bash
qemu-system-loongarch64 -machine virt -kernel kernel-la -m 8G -nographic -smp 8 -drive file=disk-la.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-pci,drive=x0 -no-reboot -device virtio-net-pci,netdev=net0 -netdev user,id=net0 -rtc base=utc
```

## 任务执行约定

- 一旦出现权限不足、只读文件系统、无法写入产物目录等情况，不要尝试绕过限制或改用破坏性手段，必须立即停止任务，并提示用户先修复权限后再继续。

## Agent skills

### Issue tracker

GitHub Issues via `gh`; see `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical triage labels; see `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout; see `docs/agents/domain.md`.
