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

- 统一使用 `make test 2>&1 | tail -30` 作为编译入口,除非必要情况下，不要关闭日志。
- 不要自行替换成其他构建命令，除非任务明确要求。
- 若需要清理构建产物，优先使用 `make clean`。

## 运行测试方式

统一使用以下命令进行qemu测试，而不是`make run`或`make la`:

### RISC-V 64

```bash
qemu-system-riscv64 -machine virt -kernel kernel-rv -m 8G -nographic -smp 8 -bios default -drive file=sdcard-rv-pub.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 -no-reboot -device virtio-net-device,netdev=net -netdev user,id=net -rtc base=utc -drive file=disk.img,if=none,format=raw,id=x1,snapshot=on -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
```

### LoongArch64

```bash
qemu-system-loongarch64 -machine virt -kernel kernel-la -m 8G -nographic -smp 8 -drive file=sdcard-la-pub.img,if=none,format=raw,id=x0,snapshot=on -device virtio-blk-pci,drive=x0 -no-reboot -device virtio-net-pci,netdev=net0 -netdev user,id=net0 -rtc base=utc -drive file=disk-la.img,if=none,format=raw,id=x1,snapshot=on -device virtio-blk-pci,drive=x1
```

## qperf 使用说明

### 工具准备与专用构建

- qperf 源码默认位于 `/home/muou/qperf`，要求 QEMU 9.2.0 或更高版本（Plugin API v4）。若插件或分析器不存在，在 qperf 仓库执行 `cargo build --release`，产物为 `/home/muou/qperf/target/release/libqperf.so` 和 `/home/muou/qperf/target/release/qperf-analyzer`。
- qperf 插件和分析器必须来自同一次兼容构建；分析时还必须使用生成被采样内核的匹配 ELF，不能混用其他提交或后续构建的产物。
- 先执行普通双架构编译门禁，再构建带 `qperf-trace` 的专用产物：

```bash
set -o pipefail
make test 2>&1 | tail -30
make qperf-test 2>&1 | tail -30
```

- `make qperf-test` 生成以下独立产物，不覆盖普通的 `kernel-rv` 和 `kernel-la`：
  - RISC-V64：`kernel-rv-qperf` 与 `PulseOS_riscv64-qemu-virt-qperf.elf`。
  - LoongArch64：`kernel-la-qperf` 与 `PulseOS_loongarch64-qemu-virt-qperf.elf`。
- 普通 `make test` 产物不启用 `qperf-trace`，不能提供任务、调度、阻塞和唤醒事件。

### 采样方式

- 采样仍使用上一节规定的 QEMU 命令，不使用 `make run` 或 `make la`。把 `-kernel` 参数替换为对应的 qperf 专用内核，并追加 `-plugin` 参数。
- trace 地址必须每次从本轮匹配 ELF 动态解析，禁止复用旧地址。采样输出应放入带时间戳的独立目录，避免覆盖历史证据。
- 以下是 120 秒 RISC-V64 示例；`mode=icount,period=100000` 表示按每个 vCPU 的 guest 内核指令数采样，不等同于 QEMU 的 `-icount` 参数：

```bash
QPERF_ELF=PulseOS_riscv64-qemu-virt-qperf.elf
QPERF_KERNEL=kernel-rv-qperf
QPERF_RUN_DIR="records/qperf-riscv64-$(date +%Y%m%d-%H%M%S)"
QPERF_CAPTURE="$QPERF_RUN_DIR/capture.bin"
QPERF_LOG="$QPERF_RUN_DIR/guest.log"
QPERF_TRACE_ADDR="0x$(nm -n "$QPERF_ELF" | awk '$3 == "__pulse_qperf_trace_v1" { print $1; exit }')"
mkdir -p "$QPERF_RUN_DIR"
test "$QPERF_TRACE_ADDR" != "0x"

set -o pipefail
timeout --signal=INT --kill-after=20s 120s \
  qemu-system-riscv64 \
  -machine virt \
  -kernel "$QPERF_KERNEL" \
  -m 8G \
  -nographic \
  -smp 8 \
  -bios default \
  -drive file=sdcard-rv-pub.img,if=none,format=raw,id=x0,snapshot=on \
  -device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
  -no-reboot \
  -device virtio-net-device,netdev=net \
  -netdev user,id=net \
  -rtc base=utc \
  -drive file=disk.img,if=none,format=raw,id=x1,snapshot=on \
  -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1 \
  -plugin "/home/muou/qperf/target/release/libqperf.so,mode=icount,period=100000,trace=$QPERF_TRACE_ADDR,out=$QPERF_CAPTURE" \
  2>&1 | tee "$QPERF_LOG"
```

- LoongArch64 采样使用上一节的 LoongArch64 QEMU 参数，并作以下替换：
  - `QPERF_ELF=PulseOS_loongarch64-qemu-virt-qperf.elf`。
  - `QPERF_KERNEL=kernel-la-qperf`，即把 `-kernel kernel-la` 改为 `-kernel "$QPERF_KERNEL"`。
  - 输出目录使用 `records/qperf-loongarch64-<时间戳>`，并追加与示例相同的 `-plugin` 参数。
- 达到限时边界时 `timeout` 返回 `124` 属于预期现象，但必须确认日志包含 `QPerf capture complete`，且 capture 具有完整 trailer；其他退出状态、panic 或日志提前停止必须单独报告。

### 分析与结果判读

- 使用匹配的 qperf ELF 解析 on-CPU、按 CPU/任务分组以及 off-CPU 数据：

```bash
/home/muou/qperf/target/release/qperf-analyzer \
  --elf "$QPERF_ELF" \
  --group-by-cpu \
  --group-by-task \
  --split-by-cpu \
  --off-cpu-output "$QPERF_RUN_DIR/offcpu.folded" \
  "$QPERF_CAPTURE" \
  "$QPERF_RUN_DIR/oncpu.folded"
```

- 不要把 `kernel-rv` 或 `kernel-rv-qperf` 这类 flat binary 传给分析器；必须使用匹配的 `PulseOS_*-qperf.elf`。
- 记录分析器输出的选中样本数、sample drops、trace event 数和 event drops，并检查各 vCPU 的 folded 文件非空。sample drops 非零会削弱 on-CPU 结论，event drops 非零表示 off-CPU/调度归因不完整。
- 阶段归因必须让 on-CPU samples 和 trace events 使用同一个由 guest 标记界定的时间窗口；如果工具无法对事件应用同一窗口，就不能作该阶段的 off-CPU 结论。
- folded 栈是内核 on-CPU 的 inclusive 证据，各调用链占比不能相加为墙钟时间，也不能单独证明用户态编译器耗时或设备等待耗时。off-CPU 累计时长按任务/vCPU 聚合后可能超过墙钟时间。
- qperf trace 会扰动调度与阻塞路径。性能对比必须保持提交、内核与 ELF、插件与分析器、镜像、QEMU 参数、CPU/内存、采样模式与 period、trace 开关及工作负载阶段一致，并保留 `.bin`、guest `.log`、`.folded` 和输入哈希。
- 分析 BuildStorm 时必须以 guest 日志中的 `BUILDSTORM_BEGIN` 为正式计时阶段边界。未出现该标记的样本只能表述为启动或 pre-build 阶段证据，不能称为最终 BuildStorm 成绩或端到端性能提升。

## 任务执行约定

- 尽量只修改与当前任务直接相关的文件。
- 保持改动最小且可审查，不要顺手做无关重构。
- 如果遇到权限问题，必须立即停止任务，并提示用户先修复权限后再继续。
- 一旦出现权限不足、只读文件系统、无法写入产物目录等情况，不要尝试绕过限制或改用破坏性手段。
- 制订计划时必须先考虑制订功能的测试
