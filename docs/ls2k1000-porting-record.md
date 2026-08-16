# PulseOS 龙芯 2K1000 从零适配全过程记录

本文记录 PulseOS 从没有 2K1000 平台入口，到能够在物理板上完成串口启动、
解析 U-Boot 传入的 FDT、识别双核和内存、初始化中断与时钟、发现 SATA
硬盘、挂载 ext4 根文件系统并进入 BusyBox 用户态的全过程。本文也记录每个
阶段实际遇到的故障、排查标记、根因、修复方法和当前仍未闭环的项目。

本文不是“已经完全支持 2K1000”的声明。尤其需要注意：最后加入的软件非对齐
访问补偿，以及本轮针对 GCC/`cc1` 页权限异常加入的 TLB refill 补偿，都已经通过
源码检查和构建门禁，但清理诊断代码后生成的对应正式镜像尚未取得新一轮物理板
串口闭环证据。

## 1. 记录基线与证据边界

### 1.1 代码基线

| 项目 | 本文核对值 | 说明 |
| --- | --- | --- |
| PulseOS 适配前基线 HEAD | `91197ed839331540300cc17831c920c3c887d156` | 本次 2K1000 提交以此为父提交；单独检出该基线不能复现实现 |
| tgoskits 初始参考提交 | `bee2d2f15dc3f3d75f42454d6b4507ee8cec136c` | `feat(loongarch64): add LS2K1000 physical board support (#1368)` |
| tgoskits 当前核对提交 | `343d47f4e5c1ba2e1a3df2e5799c518740cc4649` | 用于复核后续 LIOINTC 和非对齐补偿实现 |
| 上一轮清理探针镜像 SHA-256 | `7b496ed51e9e3604bc7624854bb5c05af69ee26dd5197f08d5ee0846c0120ec6` | 历史 `kernel-ls2k1000`，不包含本轮 TLB refill 无效项补偿 |
| 开发工作区 TLB/PPI 补偿镜像 SHA-256 | `9ed86f15f1bb0ad8ad7a35478d66ea89869f65edbbc7217e0612a7a1c17052a3` | 暂存隔离前的历史构建，包含 LS2K1000 专用无效页表项处理 |
| 隔离提交候选镜像 SHA-256 | `e365dd66eaffb3e40a1b4ab9fcdfdc6c46a5ad369d7d76fa00bb0519e2d8cdf9` | 从精确暂存树的临时 worktree 构建，未混入工作区其他改动 |

### 1.2 证据分级

本文使用四类证据，不能相互替代：

| 证据 | 能证明什么 | 不能证明什么 |
| --- | --- | --- |
| tgoskits 源码审计 | 参考平台的地址、FDT、LIOINTC、AHCI、GMAC、RTC和非对齐处理方式 | PulseOS 已经正确实现或已能上板 |
| PulseOS 源码与 ELF 审计 | 代码路径、链接地址、入口和构建特性符合设计 | 真实 2K1000 的 MMU、IRQ、SATA 一定可用 |
| `make test`、`make ls2k1000`、QEMU 回归 | 双架构没有明显编译回归，通用 LoongArch 路径能够运行 | QEMU `virt` 不模拟 2K1000 的 LIOINTC、AHCI、GMAC 接线 |
| 物理板串口日志 | 某个具体镜像确实运行到了日志对应阶段 | 未出现在该日志中的后续功能已经通过 |

开发中采用逐层验收，不把“能编译”直接写成“完成适配”：

1. 构建并检查镜像入口、物理装载地址和诊断字符串。
2. U-Boot 能跳入第一条指令，串口能输出早期字符。
3. 建立高半地址、软件 TLB refill 和异常入口。
4. 正确解析 U-Boot 参数、FDT、CPU、RAM 和保留区。
5. 初始化 UART、时钟、IPI、LIOINTC 和第二个 CPU。
6. 发现 AHCI 硬盘、挂载 ext4 根文件系统。
7. 加载 `/bin/busybox` 并进入用户态。
8. 处理真实 CPU 暴露的非对齐访问，重新取得 shell 和长期运行证据。

目前物理板证据完成到第 7 步，并在第 8 步的原始故障点停住；第 8 步的软件
修复已实现但尚待正式镜像复测。

## 2. 从参考实现提取平台契约

### 2.1 为什么参考 tgoskits，但不直接复制

tgoskits 的 2K1000 支持是动态平台体系的一部分，启动、设备探测和 StarryOS
用户态组织方式与 PulseOS 不同。PulseOS 已经有 VisionFive2 的独立平台 crate
组织形式，因此本次选择“复用硬件契约，重做 PulseOS 边界”：

- 从 tgoskits 获取 2K1000 的启动地址、设备地址和固件/FDT 约定；
- 对照其 LoongArch 启动、LIOINTC、AHCI、GMAC、RTC 和非对齐访问实现；
- 在 PulseOS 内新建独立 `axplat-loongarch64-ls2k1000` crate；
- 通过根 Cargo feature、驱动 feature 和顶层 Make 目标接入；
- 不把 tgoskits 的动态平台框架或 StarryOS 进程模型整体搬入 PulseOS。

### 2.2 硬件和固件契约

| 项目 | 2K1000 契约 |
| --- | --- |
| CPU | `cpu@0`、`cpu@1`，最多使用 2 核 |
| 原始低端 RAM | `[0x0000_0000, 0x1000_0000)`，PulseOS 从 `0x0020_0000` 开始发布为可用内存 |
| 高端 RAM | `[0x9000_0000, 0xc000_0000)` |
| UART | NS16550A，物理地址 `0x1fe2_0000` |
| LIOINTC | 控制寄存器 `0x1fe0_1400`，ISR `0x1fe0_1040` |
| LIOINTC 级联 | CPU 原始 IRQ 3，即 HWI1 |
| AHCI | `0x400e_0000` |
| 内核物理装载地址 | `0x9800_0000` |
| U-Boot cached DMW 地址 | `0x9000_0000_9800_0000` |
| FDT 暂存地址 | 本次使用 `0x9000_0000_0a00_0000` |

### 2.3 与 tgoskits 的功能差异

| 功能 | tgoskits 参考 | PulseOS 当前状态 |
| --- | --- | --- |
| 串口 | 支持 | 已实现并有上板输出 |
| FDT/内存拓扑 | 支持 | 已实现并有上板证据 |
| 本地定时器、IOCSR IPI、SMP | 支持 | 已实现，CPU1 已上板启动 |
| LIOINTC | 完整域和路由 | 已实现本板需要的 32 输入、HWI1 级联和 IRQ 安全状态发布 |
| AHCI | 更完整的控制器路径 | 当前为互斥串行化的轮询块设备，已挂载真实 ext4 根盘 |
| GMAC | 支持 | 未实现 |
| RTC | 支持 | 未实现，日志时间从 1970 年开始 |
| LoongArch 非对齐补偿 | 支持 | 已移植并加强用户地址空间校验，尚待 2K1000 复测 |
| TLB refill 无效中间项补偿 | 支持 | 仅 `ls2k1000` feature 启用，已构建，尚待该镜像实板复测 |

因此当前实现不是 tgoskits 的功能等价移植，不能把 tgoskits 的网络、RTC 或
AHCI 性能结论套用到 PulseOS。

## 3. PulseOS 中的最终组织形式

### 3.1 构建入口

顶层 `make ls2k1000` 使用以下独立配置：

```text
ARCH=loongarch64
MYPLAT=axplat-loongarch64-ls2k1000
SMP=2
APP_FEATURES=ls2k1000
BUS=mmio
PLAT_CONFIG=crates/axplat-loongarch64-ls2k1000/axconfig.toml
```

输出为：

| 产物 | 用途 |
| --- | --- |
| `kernel-ls2k1000` | U-Boot `go` 使用的 flat binary |
| `kernel-ls2k1000.elf` | 与镜像匹配的符号和段信息 |
| `PulseOS_loongarch64-ls2k1000.elf` | 构建系统原始 ELF 产物 |

### 3.2 平台模块

| 文件 | 职责 |
| --- | --- |
| `crates/axplat-loongarch64-ls2k1000/axconfig.toml` | 40 位高半地址、物理装载地址、MMIO、UART、CPU 数等常量 |
| `src/boot.rs` | DMW、启动页表、MMU、主核/从核入口和高半跳转 |
| `src/topology.rs` | U-Boot/UHI 参数、FDT、CPU 和 LIOINTC 拓扑 |
| `src/mem.rs` | RAM、FDT 保留区、memreserve、`/reserved-memory` 和内核段发布 |
| `src/console.rs` | 保留 U-Boot 已配置的 NS16550 状态并提供控制台 |
| `src/time.rs` | 稳定计数器和本地定时器 |
| `src/mp.rs` | IOCSR mailbox/IPI 启动 CPU1 |
| `src/irq.rs` | LoongArch 本地 IRQ 与 LIOINTC 级联分发 |
| `crates/axdriver_block/src/ls2k1000_ahci.rs` | 固定 MMIO 的串行轮询 AHCI 块设备适配器 |
| `crates/axcpu/src/loongarch64/unaligned.rs` | ALE 指令解码、寄存器读写和提交语义 |
| `crates/axcpu/src/loongarch64/unaligned.S` | 带 exception table 的逐字节读写 |
| `pulse_core/src/trap.rs` | 用户地址范围预缺页、权限检查、地址空间稳定和 SIGBUS 回退 |

## 4. 镜像格式与 U-Boot 上板方法

### 4.1 为什么没有先打包为 uImage

`uImage` 是 U-Boot legacy image 容器，主要增加架构、类型、装载地址、入口、
长度和校验头。它不会自动解决 2K1000 的 40 位规范地址、启动页表、TLB refill
或 FDT ABI 问题。

本次参考链路明确使用 flat binary 加 `go <entry> <fdt>`。这样 U-Boot 不解释
内核格式，PulseOS 可以精确控制入口寄存器和 FDT 参数。若简单把当前 binary
套一层 uImage 后改用 `bootm`，U-Boot 可能按 Linux 内核协议重排参数，而当前
入口实现接收的是 U-Boot `go` 的 `argc/argv` 或 UHI sentinel ABI，两者不能在
没有适配层时混用。

因此当前选择 raw image 是启动 ABI 的设计选择，不是 U-Boot 不支持封装。将来
若要提供 uImage，应同时增加并验证 `bootm` 入口协议、load/entry 字段和 FDT
传参，再把它作为第二种正式产物，不能只运行 `mkimage` 就宣称完成。

### 4.2 推荐上板命令

```console
setenv loadaddr 0x9000000098000000
setenv fdt_addr 0x900000000a000000

fdt addr ${fdtcontroladdr}
fdt header get fdt_size totalsize
fdt move ${fdtcontroladdr} ${fdt_addr} ${fdt_size}
fdt addr ${fdt_addr}

tftpboot ${loadaddr} kernel-ls2k1000
go ${loadaddr} ${fdt_addr}
```

上板前应校验 TFTP 目录中的镜像与本地正式镜像 SHA-256 一致；否则串口结果不
能反证当前源码。

### 4.3 FDT 四条命令的作用及是否需要重复

```console
fdt addr ${fdtcontroladdr}
fdt header get fdt_size totalsize
fdt move ${fdtcontroladdr} ${fdt_addr} ${fdt_size}
fdt addr ${fdt_addr}
```

其含义依次是：

1. 选择 U-Boot 自己正在使用的 control FDT。
2. 从 FDT 头读取精确 `totalsize`。
3. 把 control FDT 复制到约定的独立地址，避免 U-Boot 后续使用或重定位造成冲突。
4. 把复制后的 FDT 设为 U-Boot 当前工作 FDT。

在同一次上电、内存未被覆盖、地址未变化时，不必在每次 `go` 前重复复制。
本次内核装载区 `0x9800_0000` 与 FDT 物理地址 `0x0a00_0000` 不重叠。但出现
复位、重新初始化 DRAM、修改 control FDT、改变地址，或读到全 `0xff` 的 FDT
头后，应重新执行整段命令。仅设置 `fdt addr` 不会把数据复制回来。

### 4.4 `go` 后异常为什么没有回到 `=>`

`go` 是无返回控制转移。PulseOS 接管 CPU、异常入口、MMU 和中断后，U-Boot
不再是调用栈上的可靠返回者。早期异常可能落入固件异常打印或 PulseOS 的停机
循环，但不能假定 `Ctrl-C` 能恢复 U-Boot。开发阶段若串口停住，应使用板上复位、
看门狗或断电重启，然后重新确认 FDT 是否仍有效。

## 5. 从零适配的完整问题演进

### 5.1 阶段 0：只有通用 LoongArch QEMU 平台，没有 2K1000 目标

**问题。** PulseOS 原先的 LoongArch 支持面向 QEMU `virt`，其内存布局、虚拟
地址宽度、设备模型和中断控制器都不能直接用于 2K1000。项目也没有独立的
2K1000 Cargo feature、平台 crate、驱动 feature 或 Make 目标。

**思路。** 先审计 VisionFive2 的独立平台组织，再审计 tgoskits 的 2K1000
支持，不在通用 QEMU 平台里堆板级条件分支。

**实现。** 新建 `axplat-loongarch64-ls2k1000`，接入 workspace、根 feature、
`axfeat/driver-ls2k1000-ahci` 和 `make ls2k1000`。初始范围只覆盖启动所需的串口、
FDT、内存、时钟、IPI、LIOINTC 和 SATA 根盘，明确暂不实现 GMAC、RTC。

**结果。** 首先取得交叉编译成功，但此时只属于构建证据，尚不能称为上板成功。

### 5.2 阶段 1：raw image、入口地址和 uImage 认知

**问题。** 开发初期容易把“没有 uImage 头”误判为无法由 U-Boot 启动，或者
按 tgoskits 私有镜像头计算入口。

**定位。** ELF 检查显示入口为 `0x98000000`，第一个 `PT_LOAD` 物理地址也是
`0x98000000`；U-Boot 可以把 binary 装到其 cached DMW 别名
`0x9000000098000000` 后直接执行。

**修复。** 固化 raw image 合同：构建输出 `kernel-ls2k1000`，使用 `tftpboot`
和 `go`，不解析不存在的私有头，也不未经 ABI 适配改用 `bootm`。

**结果。** U-Boot 能显示：

```text
## Starting application at 0x9000000098000000 ...
```

随后出现的 CPU 异常证明已经进入镜像，而不是 TFTP 或容器格式失败。

### 5.3 阶段 2：沿用 QEMU 的 48 位高半地址，第一跳立即地址异常

**现象。** 最初反复得到：

```text
csr 0x00000005 -> 0x0000000000030000
csr 0x00000006 -> 0xffffffff9800008c
```

更早的构建还出现过 `0xffff80009800008c`。串口没有 PulseOS 正常日志。

**诊断。** 加入最小的单字符和 CSR 标记，确认入口已执行，但在切换高半地址
附近失败。CPUCFG 探针报告 `VABITS=0x28`，即 40 位虚拟地址；QEMU 平台使用
的 `0xffff8000_...` 属于 48 位布局，在该处理器上不是合法规范地址。

**根因。** 真实 2K1000 与 QEMU `virt` 的虚拟地址宽度不同。页表内容尚未真正
参与翻译，CPU 已先因非规范地址拒绝访问。

**修复。** 平台改用符号扩展的 40 位高半窗口：

```text
KERNEL_BASE_VADDR = 0xffffffff98000000
PHYS_VIRT_OFFSET  = 0xffffffff00000000
```

**结果。** 异常地址从错误的 `ffff8000...` 布局收敛到
`ffffffff9800...`，启动继续进入页表阶段。

### 5.4 阶段 3：错误地把高虚拟地址按 DMW 掩码转物理地址

**现象。** 探针曾打印：

```text
high-target=ffffffff98000104 phys=0fffffff98000104
```

这个所谓物理地址明显超出 2K1000 的 40 位物理范围。

**根因。** `0xffff_ffff_9800_0104` 是链接后的高半地址，不是 DMW 地址。只清除
最高 nibble 会得到 `0x0fff_ffff_9800_0104`，并不会得到真正物理地址
`0x9800_0104`。

**修复。** 对链接高半符号使用 `vaddr - PHYS_VIRT_OFFSET`；只有已经处于 DMW
形式的指针才应用 DMW 物理掩码。启动页表、异常入口和跳转目标统一使用这套
转换。

**结果。** 探针变为：

```text
high-target=ffffffff9800012c phys=000000009800012c
```

消除了错误页表根和错误跳转物理地址。

### 5.5 阶段 4：QEMU 可用的 1 GiB 巨页在 2K1000 上不能完成启动

**现象。** 入口能打印早期字符，但建立分页后在高半跳转处出现指令页无效，
典型 `ESTAT` 为 `0x70000`，ERA 位于 `0xffffffff98000094` 附近。

**定位。** 逐级打印 root、目录项和 leaf，确认表地址可读，随后手工预填一对
4 KiB TLB 项。预填后出现 `JH`：`J` 表示执行高跳，`H` 表示已经在高地址运行。
这证明高地址本身正确，失败点在页表粒度/refill，而不是链接器。

**根因。** 通用 LoongArch QEMU 平台使用的 Dir2 级 1 GiB leaf 在这块 2K1000
上没有得到相同结果；本板可工作的启动映射是 Dir1 级 2 MiB leaf。

**修复。** 启动页表调整为：

```text
Dir3 root -> Dir2 table -> Dir1 2 MiB leaf
```

分别建立低端 0–1 GiB、设备 1–2 GiB 和内核物理 2–3 GiB 的表，同时建立
相应的 40 位高半镜像。

**结果。** 高半入口稳定执行，后续故障转移到真正的 TLB refill 和数据访问。

### 5.6 阶段 5：硬件没有可依赖的页表遍历器，TLB miss 后停住

**现象。** 日志推进到：

```text
[ls2k early] lookup begin
[ls2k early] lookup asid=00000000000a0000 tlbidx=ffffffff8c000000
```

早期构建没有 `lookup done`；加标记后能通过 `tlbsrch`、`ibar`、`dbar`，但在
访问下一个未预填高地址时只打印 `M` 后停住。

**诊断。** CPU 探针给出：

```text
cfg1=0000000003e2727e pabits=28 vabits=28
cfg2=000000000470c047
ptw-cap=0 ptw-en=0
```

预填当前高半页后可以执行 `JH`，而访问下一个页再次 miss，说明不能期待硬件
自动从 PGD 填充 TLB。

**根因。** 该处理器启动环境没有可用的硬件 page-table walker。PulseOS 原先
的异常入口和页表根设置不足以处理真实板上的特殊 TLB refill 异常。

**修复。** 对照 tgoskits/LoongArch 参考实现，在 `axcpu` 安装物理
`TLBRENTRY`，使用 `LDDIR`/`LDPTE` 软件遍历并执行 `tlbfill`。同时：

- 把同一有效启动根安装到 `PGDH` 和 `PGDL`；
- 把未使用目录项指向内核镜像内的自引用无效表；
- 不允许 `LDDIR` 因空目录项继续访问 PA 0，因为 PA 0 不属于可用 RAM；
- 在改变页表和 CRMD 后执行 `ibar 0`、`dbar 0`；
- 保持 early exception entry 可通过 DMW 物理地址到达。

**中间弯路。** 曾分别尝试把 `TLBRENTRY` 指到 `0x98001000` 的 trampoline、
`0x98000000` 的 dispatch 和内核尾部的 production handler。`JH` 只能证明一页
预填可用，不能证明生产 refill 已正确。通过打印 miss 目标、TLBLO0/1、TLBEHI、
TLBIDX 和 `TLBRERA`，才把问题收敛到 production handler 的页表遍历。

**结果。** 日志最终出现：

```text
[ls2k probe] data-miss target=ffffffff982eae80
Mm value=000000001a000f84
JH[ls2k early] D high crmd=00000000000000b0
```

其中 `Mm` 表示 miss 已由软件 refill 返回并成功读取值，高半 Rust 入口开始运行。

### 5.7 阶段 6：PTE 通过 cached/uncached 两个别名读写导致状态不一致

**现象。** 同样的镜像重试时，TLB 查询位置和结果不稳定；表内看似已经写入，
refill 仍可能读到旧值。

**根因。** 启动代码曾通过一个缓存域写页表、通过另一个 DMW 缓存属性读取，
真实硬件上可能留下互相覆盖的 D-cache 行。QEMU 不容易暴露该问题。

**修复。** DMW0 作为 uncached，DMW1 作为 coherent cached；启动页表初始化和
软件 refill 统一从 cached DMW 域访问，并在启用分页前完成屏障。CRMD 的分页
和 DATM 状态一次性切换，避免中间窗口。

**结果。** 页表根和 leaf 输出不再随重试漂移，软件 refill 可重复到达高半。

### 5.8 阶段 7：错误理解 U-Boot `go` 的寄存器参数

**现象。** 高半已经工作，但内核把 `a1` 当 FDT 指针时解析失败。

**诊断。** 探针打印：

```text
handoff-args v0=0000000000000002 v1=900000000cbf5eb0
uboot-argv-item v0=0000000000000001 v1=900000000cbf6fc6
uboot-fdt-arg v0=900000000cbf6fc6 v1=900000000a000000
handoff-fdt v0=000000000a000000
```

这说明 `a0=2` 是 `argc`，`a1` 指向 `argv`；第二个字符串才是 FDT 地址。它
不是 RISC-V 风格的 `a1=dtb` 直接传参。

**修复。** `boot_fdt_paddr` 同时支持：

- U-Boot `go <entry> <fdt>` 的 `argc/argv`，限制参数数量和字符串长度并解析
  十六进制地址；
- 固件直接传入 UHI FDT sentinel 的 ABI。

无法取得有效 FDT 时立即停止，而不是回退到 QEMU 的伪造内存图。

**结果。** FDT 物理地址稳定解析为 `0x0a000000`。

### 5.9 阶段 8：FDT 缓存别名、失效数据和映射范围问题

这一阶段出现了三个不同问题，不能混为“FDT 解析器坏了”。

**问题 A：缓存视图。** U-Boot 留下的 FDT 可能在 cached DMW 或 uncached DMW
视图中可见。实现先验证 cached 头，失败后再验证 uncached 头，并限制最大 DTB
为 16 MiB。

**问题 B：FDT 内存本身无效。** 一次日志中 cached/uncached 原始值均为全
`0xffffffffffffffff`：

```text
fdt-raw-c v0=ffffffffffffffff v1=ffffffffffffffff
fdt-raw-u v0=ffffffffffffffff v1=ffffffffffffffff
fdt-cached-invalid ...
fdt-uncached-invalid ...
```

这不是字节序或 parser 问题，而是目标地址没有有效 FDT。重新从
`${fdtcontroladdr}` 复制后，原始头恢复为 `d00dfeed` 对应字节，`totalsize`
为 `0x3d37`。

**问题 C：内核增长后越过早期映射窗口。** 曾在 FDT 解析期间出现
`badv=ffffffff983fe6dc`。代码增长使 FDT 解析路径落在原先没有覆盖的高半页。
修复不是修改 FDT，而是把启动内核区域扩展为整个对应 1 GiB 物理窗口的
2 MiB leaf 映射。

**结果。** 日志依次通过 `fdt-header`、`topology-fdt-ok`、`topology-done` 和
`platform-fdt-ready`。

### 5.10 阶段 9：高半内核无法访问 UART/LIOINTC/AHCI MMIO

**现象。** 进入 `init-early` 后发生地址异常：

```text
estat=0000000000020000
badv=ffffffff1fe20003
```

该地址对应 UART `0x1fe20000` 的高半线性别名。

**根因。** 启动页表只映射了低地址和内核代码，没有映射
`phys_to_virt(0x1fe20000)` 所使用的高半 MMIO 窗口。

**修复。** 增加 low/device 两张 2 MiB leaf 表，把前 2 GiB 物理空间同时映射
到 `PHYS_VIRT_OFFSET` 对应的高半线性区。UART、LIOINTC 和 AHCI 在 runtime
页表接管前都能使用统一的 `phys_to_virt`。

**结果。** `init-early`、console 和平台初始化继续执行。

### 5.11 阶段 10：重新初始化 UART 后出现乱码

**现象。** 内核横幅之后日志字符交错或成为乱码，早期单字符输出却正常。

**根因。** 通用 NS16550 初始化路径使用的输入时钟/分频假设不适合当前板级
固件配置。U-Boot 已经把串口设置为可用波特率，内核再次写 divisor 反而破坏
了配置。

**修复。** 早期控制台读取并保留 U-Boot 的 UART 配置，不在尚未解析出可靠
clock contract 时盲目重编程 divisor；日志中的 `uart-preserve v0=3` 也确认了
8N1 线路控制状态。

**结果。** 正常 PulseOS 横幅和运行日志可以持续输出。长期方案仍应从 FDT/时钟
驱动取得 UART 输入频率后再决定是否完全接管。

### 5.12 阶段 11：把 DMW 虚拟别名误发布为物理内存

**现象。** 早期内存日志曾把 `0x9000...` 开头的 cached DMW 地址作为
`PhysAddr` 发布，导致 allocator 看到不真实的物理区间。

**根因。** FDT、固件参数和 DMW 指针在进入内存管理前没有统一规范化；相同
物理地址可能以原始物理、cached DMW、uncached DMW 或高半线性地址出现。

**修复。** 增加统一的 `firmware_to_phys`/canonicalization，再做范围裁剪、排序
和相减。内存初始化同时保留：

- live DTB 自身范围；
- FDT memory reservation block；
- `/reserved-memory` 节点；
- UART/LIOINTC 和 AHCI MMIO；
- 内核 `.text`、`.rodata`、`.data`、boot stack 和 `.bss`。

**结果。** 物理板最终发布的关键区间为：

```text
[0x00200000, 0x0a000000) free
[0x0a000000, 0x0a004000) DTB reserved
[0x0a004000, 0x0f000000) free
[0x0f000000, 0x10000000) reserved
[0x1fe00000, 0x1ff00000) MMIO
[0x40000000, 0x40100000) MMIO
[0x90000000, 0xc0000000) high RAM,扣除内核段
```

### 5.13 阶段 12：诊断异常入口把正常硬中断当成致命异常

**现象。** 完成文件系统和 CPU1 初始化附近出现：

```text
E estat=0000000000001000 era=ffffffff98326d18 ...
```

探针随后打印 TLB 状态并停机。

**诊断。** `ESTAT.ECODE=0`，置位的是 `IS` 中断位。这不是新的地址异常，而是
定时器或外设中断进入了开发期通用异常打印器。

**根因。** 为抓早期 MMU 故障临时安装的诊断 handler 截获了正常中断，没有
转发到生产 IRQ 路径。

**修复。** 调试阶段先让 `ECODE=0` 的事件进入原中断分发；生产版本恢复标准
trap entry，删除通用打印后自旋的 probe 逻辑。

**结果。** 定时器、IRQ 初始化和后续用户态启动继续推进。这也说明诊断代码
不能长期留在正式异常路径中，否则会制造“修复后仍崩溃”的假象。

### 5.14 阶段 13：LIOINTC 的寄存器语义和硬中断并发

**问题。** LIOINTC 有 32 个输入、4 个父路由，enable/disable 寄存器为写一
命令。若硬中断路径与任务上下文共用普通控制器锁，可能死锁；若用读改写处理
write-one 寄存器，会错误改变其他 IRQ。

**修复。** 从 FDT 解析 `loongson,2k1000-icu`、控制区、ISR 和级联 IRQ 3；
输入按 active-high level 配置。任务上下文负责写 enable/disable 命令，硬中断
路径只读取 ISR 和原子发布的 enabled mask，不获取任务上下文控制器锁。

**结果。** 平台日志取得 LIOINTC 地址和级联 IRQ，CPU1 可启动，观测启动阶段
没有立即发生中断风暴。由于 AHCI 当前使用轮询，尚没有设备 IRQ 吞吐和压力证据。

### 5.15 阶段 14：SMP 启动需要硬件 CPU ID 与逻辑 CPU ID 分离

**问题。** 不能假定 FDT 中 CPU 节点顺序、硬件 ID 和 PulseOS 逻辑 ID 永远
相同，也不能在从核启动前临时读取会被覆盖的 FDT 指针。

**修复。** 启动主核时先从 `/cpus` 建立最多两项的静态拓扑，把 boot CPU 放在
逻辑 0，发布硬件 ID 到逻辑 ID 映射。通过 IOCSR mailbox 写入从核栈和入口，
从核读取硬件 ID 后再转换为逻辑 ID，并安装相同 MMU 根。

**结果。** 物理板日志出现：

```text
CPU number: max = 2, platform = 2, use = 2
smp = 2
Secondary CPU 1 started.
Secondary CPU 1 init OK.
```

这证明双核启动链路成立，但还不等同于长时间 SMP/IRQ/IO 压力稳定性。

### 5.16 阶段 15：AHCI 与“是不是 rootfs 没装载”的排除

**问题。** 用户态不能继续时，一度怀疑根文件系统没有正常装载。

**证据。** 物理板串口已经给出完整反证：

```text
AHCI device: Kingchuxing 32GB
LS2K1000 AHCI ready: 62533296 blocks, 512 bytes/block
filesystem on device 0: ext4 (size=31266648 KiB)
select block device 0 (ls2k1000-ahci, 31266648 KiB) as root filesystem
mounted proc at /proc
mounted devtmpfs at /dev
Preparing to load shell: path=/bin/busybox, args=["sh"]
User process loaded successfully, activating address space...
```

**结论。** SATA、分区/块设备、ext4 和 `/bin/busybox` 读取均已成功；后续异常
不是 rootfs 没装载。

**当前实现。** `ls2k1000_ahci.rs` 在 `0x400e0000` 初始化 `simple-ahci`，使用
全局互斥把读写串行化并轮询完成，向现有 axdriver/axfs 注册块设备。这个路径
优先保证启动正确性，尚未实现 IRQ completion、并发队列、超时恢复和性能调优。

### 5.17 阶段 16：进入用户态后的指令页故障是诊断路径的中间态

**现象。** 一个 probe 构建在进入用户态后出现：

```text
estat=0000000000030000
era=0000000000313800
badv=0000000000313800
```

**分析。** 这是用户指令页相关异常。当时 probe 异常入口仍优先打印并停住，
因此该日志不能直接证明 ELF loader 或 rootfs 损坏。恢复生产 refill/异常分发并
保持用户页表根一致后，下一版越过该地址，运行到 BusyBox 内更晚的 ALE。

**经验。** 早期 bring-up 中每次“看到新异常”都要先确认它是否被临时 probe
截获；异常类别、特权级和实际生产 handler 是否执行，比异常地址本身更重要。

### 5.18 阶段 17：BusyBox 触发 AddressNotAligned

**最终板上现象。** 去掉大部分 probe 后，系统已经挂载根盘并进入 BusyBox，
随后打印：

```text
Address error! pid=7 exe=Some("/bin/busybox")
ip=0x254c60 vaddr=0x2f0b8d kind=Misaligned
```

**为什么不是 PulseOS 文件系统问题。** ELF 已经加载、地址空间已经激活，异常
发生在 BusyBox 用户指令的内存访问上。`vaddr=...8d` 也直接表明访问未按 2/4/8
字节自然对齐。

**硬件与参考实现核对。** tgoskits 没有假定所有 LoongArch CPU 都透明支持
非对齐宽访存，而是在 `axcpu` 中提供 ALE 软件模拟，并在 StarryOS 用户 trap
路径中调用。由此确认：真实 2K1000 暴露了需要软件兼容的架构行为，PulseOS
原先只发送 `SIGBUS/BUS_ADRALN` 的处理不够；不能把责任归给 rootfs。

**第一层修复：约束内核生成代码。** 仅在 `ls2k1000` feature 构建中增加：

```text
-C target-feature=-ual
```

并通过 `-Z build-std=core,alloc` 让约束覆盖内核、`core` 和 `alloc`。这避免 LLVM
在内核中基于 `ual` 假设生成宽非对齐访问，但不会改变已经编译好的 BusyBox，
所以还必须实现用户态补偿。

**第二层修复：移植并加强软件补偿。** 当前实现：

- 解码整数 load/store、pointer form、indexed form 和浮点 load/store；
- 用逐字节汇编重建 2/4/8 字节值，访问点进入 exception table；
- 只有全部读取成功后才写目标寄存器，只有全部操作成功后才把 `ERA += 4`；
- 用户访问先校验完整地址范围，按读/写权限预触发缺页；
- 在实际字节访问期间持有地址空间读锁，防止并发 `munmap` 改变映射；
- 不支持的指令、无效范围或无法解决的 page fault 仍走原有 SIGBUS 路径；
- 内核来源 ALE 也尝试相同模拟，失败才 panic。

解码器、内核态入口和用户态入口都由 `ls2k1000` feature 控制；普通 LoongArch
QEMU 构建不启用 `-ual`、`build-std` 或该模拟器，保持原有异常语义。

**当前证据边界。** 源码审计、双架构构建和通用 LoongArch 回归已经通过；
但尚未用清理诊断代码后的正式镜像在 2K1000 上证明 BusyBox 已越过
`ip=0x254c60`。这项必须作为下一轮物理验收的第一判据。

### 5.19 阶段 18：清理诊断代码并恢复生产镜像

bring-up 期间使用过以下临时手段：

- `tlb-refill-probe` 构建 feature 和专用 probe 镜像；
- `[ls2k early]`、`[ls2k probe]` 阶段标记；
- 单字符 `J/H/M/E` 定位高跳、refill 和异常；
- FDT 原始字、页表层级、TLB 项、CSR、UART 和内存区间打印；
- 覆盖生产异常入口的停机式诊断 handler。

这些代码帮助把问题从“启动无输出”逐步缩小到一条指令，但会改变时序、镜像
大小、异常分发和串口行为，因此在功能路径确定后全部移除。保留的是生产所需的
40 位地址、2 MiB 启动页表、软件 TLB refill、FDT、LIOINTC、AHCI 和非对齐
补偿，不保留 probe feature 和探针输出。

清理后的 `kernel-ls2k1000` 中已检查不到 `[ls2k probe]`、`[ls2k early]` 或
`tlb-refill-probe` 字符串。

### 5.20 阶段 19：GCC/cc1 的 `BADV=0` 页权限异常

**现象。** 在已经能够进入 BusyBox 的镜像中执行 `gcc hello.c`，`gcc` 本身和
其子程序 `cc1` 都能被 `execve`，但 `cc1` 初始化语法树时崩溃：

```text
sys_execve: path="/usr/bin/gcc"
sys_execve: path="/usr/libexec/gcc/loongarch64-alpine-linux-musl/14.2.0/cc1"
handle_page_fault: reject=out_of_range vaddr=VA:0x0
aspace_range=VA:0x1000..VA:0x4000000000
era=0x120befae0, badi=0x00000000
```

随后内核把异常转成 `SIGSEGV`，GCC 报告内部编译器错误。第二次异常的 `ERA`
变为 `0x1213269f0`，但 `BADV` 和 `BADI` 仍为零。

**第一轮判断：排除 rootfs，但继续审计 ELF 映射细节。** 日志已经证明
`/usr/bin/gcc`、`cc1` 被成功打开并开始执行，因此失败不是块设备、ext4 或
rootfs 挂载问题。对照 tgoskits 后还发现一项独立的兼容差异：其 StarryOS ELF
loader 会把最后一个 `PT_LOAD` 的文件后端延伸到 `PT_TLS` 初始化镜像末尾；
PulseOS 原先只映射 `PT_LOAD.p_filesz`。本次同步实现了该规则，并校验
`p_filesz <= p_memsz`、偏移溢出和最终范围不越过 `PT_LOAD.p_memsz`。这是通用
ELF 文件布局修复，不是 2K1000 硬件补偿，因此对所有架构生效。

加入该修复后的复测仍得到相同的 `BADV=0/BADI=0`，说明它补齐了 loader 与
tgoskits 的已知差异，但不足以解释本次 GCC 崩溃。`aspace_range` 进一步表明
内核收到的是虚拟地址零，而不是 `cc1` 实际指令地址；直接把零交给 VM 必然得到
`out_of_range`，排查重点因此转向 2K1000 的 PPI/TLB refill 路径。

**第二轮判断：确认是 LS2K1000 的 PPI 信息不完整。** LoongArch 规范将页面权限
非法、`BADV`、`ERA` 和 `BADI` 分别用于描述权限异常、故障地址、异常指令地址
和指令编码；但 LS2K1000 对本次用户取指权限异常同时返回 `BADV=0、BADI=0`，
只留下有效的 `ERA`。因此之前仅在能从 `BADI` 识别 `addi.w/addi.d` 时才使用
`ERA` 的保守回退无法触发。规范参考：[LoongArch Volume 1](https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html)。

**第三轮判断：对照 tgoskits 的 refill 路径。** PulseOS 原来的生产 refill
入口是无条件执行：

```text
LDDIR level 3 -> LDDIR level 2 -> LDDIR level 1 -> LDPTE -> TLBFILL
```

如果某一级中间页表尚未建立，继续 `LDDIR` 会让硬件沿空指针继续走；在 2K1000
上，这可能不是一个干净的普通 page fault，而是先填入权限不正确的 TLB 项，
再以 `PagePrivilegeIllegal` 进入 Rust 异常路径。tgoskits 的对应实现会在每个
`LDDIR` 后检查零值；遇到无效中间表时，构造 `NR|NX` 的无效项后再 `TLBFILL`，
让下一次访问回到正常 VM 缺页路径。参考提交：[tgoskits LS2K1000 支持](https://github.com/rcore-os/tgoskits/commit/bee2d2f15dc3f3d75f42454d6b4507ee8cec136c)。

**修复。** 在 `crates/axcpu/src/loongarch64/trap.S` 增加编译期参数
`ls2k1000`，仅在 `ls2k1000` feature 下：

1. 检查三级 `LDDIR` 的返回指针，任一级为空就跳到无效项路径；
2. 用 `TLBREHI` 设置 4 KiB 页大小；
3. 设置 `TLBRELO0/1` 的 `NR|NX`，禁止空页被当作可读、可执行页；
4. 继续执行 `TLBFILL`，由后续普通 page fault 交给 PulseOS 的文件页/匿名页
   后端处理。

同时在 `trap.rs` 中把该常量传入 `global_asm!`，保留 LS2K1000 专用的 PPI 入口
和 `ERA/BADI` 诊断；未启用 `ls2k1000` 的 LoongArch 构建仍使用原有 refill
序列。这样软件补偿不会改变 QEMU 或其他 LoongArch 平台的异常语义。

**静态验证。** 从精确暂存树创建的隔离 worktree 已经通过：

```text
make test
make ls2k1000
git diff --cached --check
```

生成的 `kernel-ls2k1000` 为：

```text
SHA-256: e365dd66eaffb3e40a1b4ab9fcdfdc6c46a5ad369d7d76fa00bb0519e2d8cdf9
```

反汇编确认该镜像的 `handle_tlb_refill` 包含三级 `beqz` 和无效
`TLBRELO` 路径；普通 `PulseOS_loongarch64-qemu-virt.elf` 仍只有原有的
`LDDIR/LDPTE/TLBFILL` 序列。

**当前边界。** 用户提供的 `gcc` 崩溃日志对应的是加入 `ERA/BADI` 诊断、但尚未
包含本轮 TLB refill 无效项补偿的镜像。本轮新镜像已经完成构建，但尚未取得实板
复测日志，因此目前只能说“补偿已实现并通过静态/构建验证”，不能说 GCC 已经在
2K1000 上编译成功。下一轮复测的首个判据是：不再出现 `PagePrivilegeIllegal`
导致的 `vaddr=0`；若仍异常，应记录新的 `estat/ERA/BADV/BADI` 第一条输出，
继续区分无效中间页表、有效页表权限错误和真正的空指针访问。

## 6. 问题总表

| 编号 | 现象 | 根因 | 解决办法 | 当前状态 |
| --- | --- | --- | --- | --- |
| P01 | 没有 2K1000 构建目标 | 仅有 QEMU LoongArch 平台 | 独立 axplat、feature、Make 目标 | 已完成 |
| P02 | 误以为必须 uImage | 混淆容器和启动 ABI | raw binary + `go`，bootm 留待独立适配 | 已明确 |
| P03 | `go` 后立即 `0x30000` | 使用 48 位 `ffff8000...` 地址 | 改为 40 位 `ffffffff...` 高半 | 已完成 |
| P04 | 高地址转出的“物理地址”超范围 | 对链接地址错误套 DMW mask | 减 `PHYS_VIRT_OFFSET` | 已完成 |
| P05 | 分页后 `0x70000` | 1 GiB Dir2 leaf 不适用本板 | 改用 2 MiB Dir1 leaf | 已完成 |
| P06 | TLB miss 后停住 | 无可用硬件 PTW | `LDDIR/LDPTE/tlbfill` 软件 refill | 已完成 |
| P07 | refill 访问 PA 0 | 空目录项仍被 LDDIR 追踪 | 自引用无效表，PGDH/PGDL 都使用有效根 | 已完成 |
| P08 | 相同镜像 TLB 结果漂移 | 页表 cached/uncached 别名不一致 | 统一 coherent cached DMW 与屏障 | 已完成 |
| P09 | a1 不是 FDT | `go` 传 `argc/argv` | 解析第二个 argv，并兼容 UHI | 已完成 |
| P10 | FDT 头全 `ff` | FDT 未搬运或内存已失效 | 重新执行 `fdt move`，双别名校验 | 已完成流程 |
| P11 | FDT 解析路径越界 | 内核增长超过早期高半窗口 | 扩大 2 MiB leaf 启动映射 | 已完成 |
| P12 | UART 高半地址异常 | 缺少高半 MMIO 映射 | 映射前 2 GiB 线性 MMIO 窗口 | 已完成 |
| P13 | 串口乱码 | 错误重编程 UART divisor | 保留 U-Boot 串口配置 | 已完成启动路径 |
| P14 | 物理内存出现 `0x9000...` | DMW 别名未规范化 | 固件地址统一转物理地址 | 已完成 |
| P15 | 正常中断被打印后停机 | probe handler 截获 ECODE=0 | 转发 IRQ，最终删除 probe handler | 已完成 |
| P16 | LIOINTC 可能锁死/误写 | write-one 寄存器和硬 IRQ 并发 | 原子 enabled mask，硬 IRQ 无任务锁 | 已完成基础路径 |
| P17 | 怀疑 rootfs 未加载 | 用户态随后异常造成误判 | 用 AHCI/ext4/BusyBox 日志分层排除 | 已排除 |
| P18 | 用户入口一次 `0x30000` | probe 截获用户页异常/生产分发未恢复 | 恢复生产 refill 和 trap 分发 | 后续已越过 |
| P19 | BusyBox `Misaligned` | 2K1000 不透明执行该非对齐宽访存 | `-ual` + tgoskits 风格软件模拟 | 代码完成，待上板 |
| P20 | 调试镜像行为与正式镜像不同 | 探针改变入口、时序和大小 | 删除 probe feature/输出，固定正式哈希 | 已清理，待正式板测 |
| P21 | `cc1` 初始化期崩溃，怀疑 TLS 文件镜像缺页 | PulseOS 未覆盖 tgoskits 的 `PT_TLS` 尾部文件映射规则 | 最后一个 `PT_LOAD` 的文件后端按 `PT_TLS` 文件末尾扩展并做边界校验 | 已实现；单独不能解决 `BADV=0` |
| P22 | `gcc`/`cc1` 报 `SIGSEGV`，`BADV=0` | LS2K1000 的 PPI 未提供有效故障地址，空中间页表还可能生成错误 TLB 项 | LS2K1000 专用 `LDDIR` 空指针检查和 `NR|NX` 无效 refill 项 | 已构建，待该镜像实板复测 |
| P23 | 基于 `BADI` 的取指回退不触发 | LS2K1000 同时返回 `BADI=0` | 保留诊断并优先修复 refill 入口，暂不把所有 `BADV=0` 强行当取指 | 已收敛，待复测结果 |

## 7. 已取得的物理板里程碑

最新的有效物理板日志（加入软件非对齐补偿之前）证明了以下链路：

1. U-Boot 从 cached DMW 地址进入 PulseOS。
2. 40 位高半地址、启动页表和生产软件 TLB refill 能工作。
3. 正确解析 U-Boot `argc/argv` 和位于物理 `0x0a000000` 的 live FDT。
4. 正确发布两段 RAM、DTB 保留区、`/reserved-memory` 和 MMIO。
5. 识别 2 个 CPU，CPU1 启动并完成初始化。
6. UART、计时器、IPI 和启动阶段中断分发可工作。
7. AHCI 识别 `Kingchuxing 32GB`，容量 `62533296 * 512` 字节。
8. ext4 根文件系统大小 `31266648 KiB`，`/proc`、`/dev`、`/dev/shm`、`/tmp`
   均挂载。
9. `/bin/busybox sh` 成功读取、创建进程并激活用户地址空间。
10. 用户态在 `ip=0x254c60` 暴露真实 ALE，而不是 rootfs 失败。

这些证据没有证明：最终清理镜像能越过 ALE、网络可用、RTC 正确、AHCI 中断
和错误恢复可用、长期 SMP 稳定或性能达到 tgoskits 水平。

## 8. 构建与静态验收

仓库规定的基础门禁为：

```bash
set -o pipefail
make test 2>&1 | tail -30
make ls2k1000 2>&1 | tail -30
git diff --check
```

正式产物还应检查：

```bash
sha256sum kernel-ls2k1000
readelf -h kernel-ls2k1000.elf | rg 'Entry point'
readelf -lW kernel-ls2k1000.elf
strings kernel-ls2k1000 | rg '\[ls2k (probe|early)\]|tlb-refill-probe'
```

上一轮清理后的历史镜像结果为：

- `make test` 通过；
- `make ls2k1000` 通过；
- `git diff --check` 通过；
- ELF entry 为 `0x98000000`；
- 第一个 `PT_LOAD` 的物理地址为 `0x98000000`；
- 历史镜像 SHA-256 为
  `7b496ed51e9e3604bc7624854bb5c05af69ee26dd5197f08d5ee0846c0120ec6`；
- 正式镜像不存在 probe/early 诊断字符串。

本轮加入 LS2K1000 PPI/TLB refill 补偿后的构建结果为：

- `make test` 通过；
- `make ls2k1000` 通过；
- `git diff --cached --check` 通过；
- `kernel-ls2k1000` SHA-256 为
  `e365dd66eaffb3e40a1b4ab9fcdfdc6c46a5ad369d7d76fa00bb0519e2d8cdf9`；
- LS2K1000 ELF 的 `handle_tlb_refill` 含三级空指针检查和无效 TLB 项路径；
- 尚无使用该哈希镜像在 2K1000 物理板上运行 `gcc hello.c` 的新串口证据。

通用 LoongArch QEMU 回归只能检查共享 `axcpu`、trap 和 PulseOS 用户态没有明显
回归。QEMU `virt` 不具备 2K1000 的设备模型，不能直接运行
`kernel-ls2k1000` 来代替物理板验收。

## 9. 下一轮物理板验收清单

下一轮应只使用哈希一致的正式镜像，并保存完整串口日志：

1. 在开发机和 TFTP 服务目录分别计算 SHA-256，确认都是本轮镜像的
   `e365dd66eaffb3e40a1b4ab9fcdfdc6c46a5ad369d7d76fa00bb0519e2d8cdf9`。
2. 复位后重新复制 FDT，确认 `fdt_size` 合理且 `fdt_addr` 不与镜像重叠。
3. 执行 `tftpboot` 和 `go`，确认正式日志中没有任何 `[ls2k probe]` 标记。
4. 确认内存区间、CPU 数、CPU1、AHCI 型号、ext4 根盘与先前证据一致。
5. 重点确认 BusyBox 越过 `ip=0x254c60`，不再打印 `kind=Misaligned`。
6. 在 shell 中执行 `gcc hello.c`，确认不再出现 `PagePrivilegeIllegal`、
   `BADV=0` 和 `handle_page_fault: reject=out_of_range vaddr=VA:0x0`。
7. 若 GCC 仍失败，保存第一条 `estat/ERA/BADV/BADI` 和对应 `vaddr`，不要只
   保存 GCC 的二次 ICE 文本。
8. 执行基本文件读写、`mount`、`cat /proc/cpuinfo` 和多次进程创建。
9. 增加跨页非对齐 load/store 定向测试，验证缺页、只读页、无效页和 SIGBUS 回退。
10. 进行 SMP + SATA 并发压力，观察中断风暴、死锁、数据错误和超时。
11. GMAC、RTC、AHCI IRQ completion 分别立项，不能混入“基础启动已完成”的结论。

## 10. 当前结论

这次适配已经把 PulseOS 从“只有 LoongArch QEMU 平台”推进到“真实 2K1000 可
启动、可识别双核和内存、可访问 SATA、可挂载 ext4、可加载 BusyBox 用户态”。
过程中真正决定成败的不是某一个设备驱动，而是以下跨层合同同时成立：

- 40 位规范虚拟地址和物理/DMW/高半地址转换；
- 2 MiB 启动页表和没有硬件 PTW 时的软件 TLB refill；
- U-Boot `go` 的 `argc/argv` ABI 与 live FDT 生命周期；
- early map、runtime map、MMIO 和缓存属性一致；
- FDT 派生的 RAM、保留区、CPU 和 LIOINTC 拓扑；
- PulseOS 块设备/文件系统路径与真实 AHCI 根盘；
- 真实 2K1000 对非对齐访问的 ALE 行为与用户态软件兼容。

当前最关键的未完成项是使用本轮哈希一致的正式镜像在物理板上同时验证软件
非对齐补偿和 GCC/`cc1` 的 TLB/PPI 补偿，并取得 shell 持续运行证据。在这项
完成前，准确表述应是“2K1000 基础启动、SMP、SATA/ext4 和用户程序装载已取得
板上证据；非对齐补偿和 GCC 页权限补偿已实现但待本轮镜像板测”，而不是
“2K1000 已完整适配”。
