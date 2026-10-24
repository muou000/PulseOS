# AGENTS.md

本仓库的协作约定如下。

## 项目上下文

- 这是一个基于 ArceOS 组件化内核构建的 PulseOS 仓库，目标是同时支持 RISC-V 64 和 LoongArch64。
- 仓库的主要结构如下：
  - `modules/`：内核核心模块（从原 ArceOS 及核心 crates 摊平迁入，包括内存、文件系统、调度、驱动等）。
  - `api/`：统一功能特性与接口层（`api/axfeat`）。
  - `configs/`：内核及平台构建配置文件（如 `defconfig.toml`）。
  - `platforms/`：平台适配实现与 `axplat` 统一抽象层（RISC-V virt, VisionFive 2, LoongArch virt, LS2K1000）。
  - `pulse_core/`：PulseOS 核心实现（进程/线程管理、内存映射、陷阱与上下文支持）。
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

统一使用以下命令进行qemu测试，而不是`make run`或`make la`:

### RISC-V 64

```bash
qemu-system-riscv64 -machine virt -kernel kernel-rv -m 8G -nographic -smp 8 -bios default -drive file=disk.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net -rtc base=utc
```

### LoongArch64

```bash
qemu-system-loongarch64 -machine virt -kernel kernel-la -m 8G -nographic -smp 8 -drive file=disk.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-pci,drive=x0 -no-reboot -device virtio-net-pci,netdev=net0 -netdev user,id=net0 -rtc base=utc
```

## 任务执行约定

- 尽量只修改与当前任务直接相关的文件。
- 保持改动最小且可审查，不要顺手做无关重构。
- 如果遇到权限问题，必须立即停止任务，并提示用户先修复权限后再继续。
- 一旦出现权限不足、只读文件系统、无法写入产物目录等情况，不要尝试绕过限制或改用破坏性手段。
- 制订计划时必须先考虑制订功能的测试

## Agent skills

### Issue tracker

GitHub Issues via `gh`; see `docs/agents/issue-tracker.md`.

### Triage labels

Default canonical triage labels; see `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout; see `docs/agents/domain.md`.
