# AGENTS.md

本仓库的协作约定如下。

## 项目上下文

- 这是一个基于 ArceOS 组件化内核构建的 PulseOS 仓库，目标是同时支持 RISC-V 64 和 LoongArch64。
- 仓库的主要结构如下：
  - `arceos/`：ArceOS 内核主体、模块、示例、脚本和平台配置。
  - `plat/`：本仓库补充的平台实现，目前主要是 `axplat-loongarch64-qemu-virt`。
  - `pulse_core/`：PulseOS 的核心库或基础封装代码。
  - `pulse_syscalls/`：系统调用相关实现与对外接口。
  - `rootfs/`：根文件系统内容与覆盖层，参与磁盘镜像生成。
  - `vendor/`：第三方依赖和 vendored 代码，通常不要随意改动。
  - `bin/`：本仓库使用的本地工具链或辅助程序。
  - `cargo/` 和 `.cargo/`：Cargo 配置与构建辅助配置。
  - `records/`：日志、记录和过程性产物，通常不参与正式构建。
  - `src/`：仓库根层代码入口。
  - `sdcard-rv.img`和`sdcard-la.img`分别是riscv64和loongarch64架构下的测例镜像。

## 编译方式

- 统一使用 `make test` 作为编译入口,除非必要情况下，不要关闭日志。
- 不要自行替换成其他构建命令，除非任务明确要求。
- 若需要清理构建产物，优先使用 `make clean`。
- 可以使用 `cargo check` 快速进行语法和借用检查（需在根目录下执行并指定目标架构和平台 Feature）：
  - **RISC-V 64**: `cargo check --target riscv64gc-unknown-none-elf --features axfeat/defplat`
  - **LoongArch64**: `cargo check --target loongarch64-unknown-none-softfloat --features axfeat/defplat`

## 运行测试方式

统一使用以下命令进行镜像构建，而不是`make run`或`make la`

### RISC-V 64

```bash
timeout 360 qemu-system-riscv64 -machine virt -kernel kernel-rv -m 1G -nographic -smp 1 -bios default -drive file=sdcard-rv.img,if=none,format=raw,id=x0 -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net -rtc base=utc -drive file=disk.img,if=none,format=raw,id=x1 -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
```

### LoongArch64

```bash
timeout 360 qemu-system-loongarch64 -machine virt -kernel kernel-la -m 1G -nographic -smp 1 -drive file=sdcard-la.img,if=none,format=raw,id=x0 -device virtio-blk-pci,drive=x0 -no-reboot -device virtio-net-pci,netdev=net0 -netdev user,id=net0 -rtc base=utc -drive file=disk-la.img,if=none,format=raw,id=x1 -device virtio-blk-pci,drive=x1
```

## 任务执行约定

- 尽量只修改与当前任务直接相关的文件。
- 保持改动最小且可审查，不要顺手做无关重构。
- 如果遇到权限问题，必须立即停止任务，并提示用户先修复权限后再继续。
- 一旦出现权限不足、只读文件系统、无法写入产物目录等情况，不要尝试绕过限制或改用破坏性手段。
