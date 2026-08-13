# PulseOS VisionFive 2 适配全过程记录

本文记录 PulseOS 初步支持 StarFive VisionFive 2（JH7110）的完整工程过程，
包括参考实现选择、平台抽象落地、U-Boot/TFTP 启动、早期启动定位、动态 DTB、
PLIC、SD/MMC、功能裁剪以及 `SMP=4` 问题的分析与修复。

记录日期为 2026-08-07，2026-08-09 追加 NIC 实现记录。本文描述的是一次 bring-up，
而不是已经完成全部板级驱动、稳定性和性能验收的产品级支持。

NIC 的专题实现、失败因果链和逐项验收方法另见
[VisionFive 2 NIC 实现与问题排查记录](visionfive2-nic-implementation.md)。

## 1. 当前结论与证据边界

为了避免把推测写成结果，本文使用以下标记：

- **已上板确认**：由 VisionFive 2 串口日志直接证明。
- **源码事实**：由当前 PulseOS、TGOSKits、Linux、U-Boot 或 OpenSBI 源码证明。
- **因果推断**：由日志、寄存器和代码路径共同推导，但没有做完严格的单变量实验。
- **待上板确认**：代码已经修改、编译和部署，但尚未收到修改后的板端日志。

截至本文写作时，状态如下：

| 能力 | 状态 | 证据 |
| --- | --- | --- |
| U-Boot `bootm` 进入 PulseOS | 已上板确认 | 出现 `BPMTK`、PulseOS Logo 和运行时日志 |
| UART0 早期输出 | 已上板确认 | MMU 前后诊断字符和完整日志均可见 |
| 动态 RAM 与保留区解析 | 已上板确认 | 识别出实际 RAM、DTB 保留区并完成内存初始化 |
| PLIC 拓扑初始化 | 已上板确认到初始化阶段 | `pqrstwuxvL` 完整通过，运行时进入中断初始化 |
| SD 卡识别 | 已上板确认 | 识别为 SDXC，容量 121466880 个 512 字节块 |
| ext4 根文件系统读取与挂载 | 已上板确认 | 成功选择块设备并挂载 `/proc`、`/dev`、`/tmp` 等 |
| VisionFive 2 网络 | 已完成实板基本验收 | GMAC0/IRQ 7/MAC/PHY、物理 ARP/单播 ICMP、数值 TCP、本地 HTTP/HTTPS Git 均通过；用户已确认板端 GitHub clone 成功 |
| `SMP=4` U74 hart 过滤修复 | 已上板确认 | 已排除 S7 hart 0，logical CPU 1/2/3 分别启动 U74 hart 2/3/4 |
| 四核进入用户态 | 已上板确认 | 四个 CPU 均完成 init，系统继续进入 BusyBox shell |

四核启动已由 2026-08-09 的新串口日志闭合，但这不等于 timer/IPI/PLIC 长稳和性能验证。
网络也必须区分“驱动注册成功”和“数据面收发成功”：后续追加的实板 ARP、单播 ICMP、
数值 TCP、本地 Git 和 GitHub clone 已闭合基本数据面及应用路径；这仍不等于长稳或性能验收。

## 2. 任务目标、环境与非目标

### 2.1 目标

本轮目标是让现有 PulseOS 在 VisionFive 2 上完成初步启动，优先打通以下链路：

1. 通过 U-Boot 和 TFTP 加载内核。
2. 保留 RISC-V 固件交接的 hart ID 和 DTB 地址。
3. 建立适用于 JH7110 的早期页表、串口、时钟、PLIC 和 SBI 服务。
4. 识别 VisionFive 2 的四个 U74 应用 hart。
5. 驱动板载 microSD，对接 PulseOS 现有块设备与 ext4 根文件系统。
6. 不影响现有 RISC-V QEMU 和 LoongArch64 构建路径。

### 2.2 实际调试环境

- PulseOS 工作区：`/home/muou/PulseOS`
- 本地 TGOSKits：`/home/muou/PulseOS/tgoskits`
- 串口设备：`/dev/ttyUSB0`
- 主机 TFTP 地址：`169.254.141.27`
- Windows TFTP 根目录：`D:\Tftpd64`
- WSL 对应目录：`/mnt/d/Tftpd64`
- 板端固件：开发板已有 U-Boot 和 OpenSBI
- 内核加载与入口地址：`0x40200000`

### 2.3 本轮明确不做的内容

- 不替换开发板已有 OpenSBI/U-Boot 固件。
- 2026-08-07 第一阶段不实现以太网、PCIe、USB 和 RTC；2026-08-09 另行追加 GMAC0 NIC。
- 不在第一阶段引入 SD/MMC IDMAC、DMA 和中断驱动的多队列设计。
- 不把仅能识别设备或挂载一次文件系统描述为完整的可靠性、写入一致性或性能验证。
- 不为了 VisionFive 2 重构 PulseOS 的现有 QEMU/LoongArch64 平台边界。

### 2.4 环境准备阶段遇到的问题

串口已经枚举为 `/dev/ttyUSB0`，但最初从非完整交互终端启动 `minicom` 时，终端类型和
界面初始化不兼容。处理方式是在真实 PTY 中设置可用的 `TERM`，并按 115200 8N1、关闭
软硬件流控连接：

```bash
TERM=xterm minicom -D /dev/ttyUSB0 -b 115200
```

`minicom` 在本轮只负责操作 U-Boot 和收集串口日志；大约 3 MiB 的内核并不是通过串口
逐字节烧录，而是由 U-Boot 通过 TFTP 下载到 RAM，再一次性 `bootm`。

主机最初也没有 `mkimage`，因此即使 flat binary 已经编译成功，也无法生成 U-Boot legacy
header。用户安装 `mkimage` 后，`make visionfive2` 才能完成 uImage 阶段。构建目标保留了
显式工具检查，缺少工具时立即报错，而不是留下一个名称像 uImage、实际却是 raw binary
的文件。

初次在 WSL 内检查 UDP/69 时没有看到本地监听者，后来确认 TFTP 服务实际运行在 Windows
侧的 Tftpd64，根目录是 `D:\Tftpd64`，对应 WSL 路径 `/mnt/d/Tftpd64`。板端随后确认能够
下载该目录中的文件，因此不再把“WSL 内没有 UDP/69 socket”误判为板端网络故障。

## 3. 参考来源与复用边界

### 3.1 PulseOS 的 QEMU RISC-V 平台

`crates/axplat-riscv64-qemu-virt` 是最接近当前 PulseOS `axplat 0.3` 接口的实现，
因此它是平台 crate 的直接骨架来源。可以复用的是：

- `axplat` 的 console、memory、time、IRQ、power 接口组织方式；
- Sv39 临时页表和高半区直接映射的构造方式；
- SBI timer、IPI、HSM 和 system reset 的调用方式；
- 逻辑 CPU ID 与物理 hart ID 分离的设计；
- PLIC claim/complete 和中断源路由框架。

不能原样复用的是 QEMU 的物理地址、Goldfish RTC、VirtIO 设备、PCI 范围、hart 编号
假设以及 QEMU 生成的 DTB 结构。

### 3.2 TGOSKits 的 VisionFive 2 历史实现

TGOSKits 历史提交 `c4efd6871` 提供了有价值的 JH7110 板级常量：

- DRAM 从 `0x40000000` 开始；
- 内核从 `0x40200000` 运行；
- UART0 位于 `0x10000000`；
- PLIC 位于 `0x0c000000`，`riscv,ndev = 136`；
- SDIO1 位于 `0x16020000`；
- timer frequency 为 4 MHz。

但该历史实现的 `max-cpu-num = 1`，内存仍有“以后解析 DTB”的 TODO，CPU 映射直接用
`hart_id - 1`，因此它只能证明单核 bring-up 的设计意图，不能证明四核 SMP 已经可用。

TGOSKits 后续曾加入 VisionFive 2 快速启动说明，但在 2026-07-30 的块设备运行时重构
提交 `689462214` 中又撤下了该章节。保留下来的平台和驱动代码不能单独证明当前版本已经
完成可重复的 rootfs、写入、fsync、校验和关机验证。本适配因此沿用“初步支持”的措辞，
并把每项板测证据单独列出。

### 3.3 StarryOS、Linux、U-Boot 与 OpenSBI

- [StarryOS](https://github.com/Starry-OS/StarryOS) 用于理解 ArceOS 上层系统的整体组织，
  但 PulseOS 当前接口和 feature 结构不同，不能直接搬运整个板级目录。
- [StarFive VisionFive 2 数据手册](https://doc-en.rvspace.org/VisionFive2/Datasheet/VisionFive_2/hardware.html)
  用于核对 JH7110 四个应用核加一个 monitor core、2/4/8 GiB 内存型号和板载 TF 卡能力。
- [StarFive JH7110 文档中心](https://doc-en.rvspace.org/JH7110/Datasheet/Doc_Center/all_pdf_docs.html)
  是 SoC 级数据手册、启动和外设资料的官方入口。
- [Linux JH7110 DTS](https://github.com/torvalds/linux/blob/master/arch/riscv/boot/dts/starfive/jh7110.dtsi)
  用于核对 S7 hart 0、U74 hart 1 至 4、PLIC 地址、上下文顺序和中断源数量。
- [Linux JH7110 common DTS](https://github.com/torvalds/linux/blob/master/arch/riscv/boot/dts/starfive/jh7110-common.dtsi)
  用于核对 4 MHz timebase、4 bit SDIO1、50 MHz assigned clock 和 pinctrl/供电依赖。
- [Linux StarFive DW MMC 驱动](https://github.com/torvalds/linux/blob/master/drivers/mmc/host/dw_mmc-starfive.c)
  用于确认该控制器是 StarFive 扩展的 DesignWare MMC，而不是 BCM2835 SDHCI。
- [U-Boot `bootm` 文档](https://docs.u-boot.org/en/latest/usage/cmd/bootm.html)
  用于确认 legacy image 的 kernel、ramdisk 和 FDT 参数位置。
- [OpenSBI HSM 实现](https://github.com/riscv-software-src/opensbi/blob/master/lib/sbi/sbi_hsm.c)
  用于把 `sbi_trap_error` 的地址还原到 secondary hart 启动状态迁移。

复用原则不是“看到相似代码就复制”，而是先确定硬件合同，再复用与该合同无关的抽象层。

### 3.4 JH7100 资料为什么只能作为旁证

检索过程中也考虑了 JH7100/VisionFive 1 的资料，但 VisionFive 2 使用的是 JH7110。两代
SoC 有家族关系，不代表 CPU topology、clock/reset、PLIC context、SDIO 地址或 syscon 位域
相同。最终代码中的硬件值没有仅凭 JH7100 文档落地，而是要求至少由 JH7110 DTS、驱动、
官方文档或当前板端寄存器日志之一确认。

这个边界直接影响两个设计决定：一是 SD host 必须匹配 JH7110 的 DW MMC 扩展；二是
CPU topology 必须认识 JH7110 的 S7 hart 0 和 U74 hart 1 至 4，不能套用其他 StarFive
SoC 的连续应用核假设。

## 4. 最终采用的板级合同

| 项目 | 当前值或来源 | 处理方式 |
| --- | --- | --- |
| DRAM 基址 | `0x40000000` | 配置给出下界，实际范围从 live DTB 读取 |
| DRAM 配置上界 | 8 GiB | 只用于早期可达窗口；分配器使用 DTB 的实际范围 |
| 本板实测 RAM 末端 | `0x140000000` | 来自板端内存区域日志 |
| 内核 load/entry | `0x40200000` | `mkimage -a` 与 `-e` 均使用该值 |
| 高半区直接映射偏移 | `0xffffffc000000000` | 与当前 PulseOS RISC-V 地址空间一致 |
| UART0 | `0x10000000` | 直接 MMIO，沿用 U-Boot 已配置的波特率和 pinmux |
| timebase | 4 MHz | 读取 `time` CSR，使用 SBI 设置 timer |
| PLIC | `0x0c000000`，64 MiB | 优先从 DTB 解析，并校验所有访问是否落在 MMIO 范围内 |
| PLIC sources | 136 | 来自 `riscv,ndev`；也是受限 fallback 的板型指纹之一 |
| microSD | SDIO1 `0x16020000` | JH7110 DW MMC，轮询 PIO |
| 管理核 | S7 hart 0 | 明确排除，不交给 PulseOS 调度 |
| 应用核 | U74 hart 1 至 4 | 映射为逻辑 CPU 0 至 3，启动核始终放在逻辑 CPU 0 |
| DTB | U-Boot `fdtcontroladdr` | 通过 `a1` 传入，内核启动期间必须保持驻留 |

本板日志中的 DTB 地址为 `0xf76df9b0`。这个地址是一次启动的运行时值，不能硬编码。

## 5. 整体启动链路

```text
SPI/OpenSBI
    |
    v
U-Boot: TFTP 下载 legacy uImage 到 ${loadaddr}
    |
    v
bootm ${loadaddr} - ${fdtcontroladdr}
    |             |  |
    |             |  +-- 第三个参数：FDT
    |             +----- 第二个参数 `-`：无 initrd
    v
PulseOS _start(a0 = boot hart, a1 = DTB physical address)
    |
    +-- UART0 早期输出
    +-- 建立 identity + direct-map 临时 Sv39 页表
    +-- 从 DTB 建立 U74 逻辑拓扑
    +-- 进入 axruntime 并再次发布运行时拓扑
    +-- 从 DTB 发布 RAM、reserved-memory、PLIC contexts
    +-- 初始化 allocator / scheduler / IRQ / drivers
    +-- JH7110 SDIO1 -> PulseOS block API -> ext4 rootfs
    +-- SBI HSM 启动其余 U74 harts
```

这里的 `Image Type: RISC-V Linux Kernel Image` 是 U-Boot legacy image 的类型标签，
不表示 payload 变成了 Linux。payload 仍然是 PulseOS 的 flat binary。

## 6. 第一阶段：建立可独立选择的平台 crate

### 6.1 为什么不继续把 VisionFive 2 塞进 QEMU 平台

最早的尝试是在构建配置中复用 QEMU RISC-V 平台，以最快速度得到一个可链接的镜像。
这很快暴露出两个问题：

1. QEMU 平台的设备和 feature 会通过依赖解析进入 VisionFive 2 构建；
2. 即使 Rust 代码可以通过编译，平台名、MMIO、DTB 和设备探测仍然是错误的。

因此按照后续要求，新建了：

```text
crates/axplat-riscv64-visionfive2/
```

该 crate 基于当前 `axplat-riscv64-qemu-virt` 的接口形状修改，同时只吸收 TGOSKits 中
已经由硬件资料印证的 JH7110 常量。根包通过 `MYPLAT=axplat-riscv64-visionfive2` 选择它。

### 6.2 构建配置遇到的第一个问题

VisionFive 2 没有 QEMU VirtIO MMIO 范围，也没有本轮要启用的 PCI ranges，因此配置中
需要空数组。`axconfig-gen` 不能只从 `[]` 推断元素类型，最初生成配置时失败。

解决方法是在 `axconfig.toml` 中显式标记类型：

```toml
virtio-mmio-ranges = [] # [(uint, uint)]
pci-ranges = [] # [(uint, uint)]
```

这是配置生成器的类型信息需求，不是硬件需要一个“假设备范围”。

### 6.3 旧生成配置污染平台选择

构建系统可能复用之前生成的 QEMU axconfig；同时根 Cargo feature 如果无条件依赖 QEMU
平台，也会让两个平台 crate 同时参与 feature 解析。表现为明明传入 VisionFive 2，生成
产物仍带有 QEMU package 或设备特征。

修复分两部分：

- `axplat-riscv64-qemu-virt` 改为根包 `qemu` feature 下的可选依赖；
- 每次 `make visionfive2` 前删除专用输出目录里的旧 axconfig，再用板级配置重新生成。

这保证“选择哪个平台”是构建输入，而不是由上一次构建残留决定。

## 7. 第二阶段：生成 U-Boot 真正能启动的镜像

### 7.1 raw binary、`go`、`booti` 和 `bootm` 的区别

PulseOS/QEMU 原路径通常直接把 flat binary 传给 QEMU 的 `-kernel`。U-Boot 下存在几种
不同入口：

- `go <addr>`：把内存地址当作 standalone 程序入口，不提供标准内核镜像检查；
- `booti`：期望符合 Linux RISC-V Image header 的镜像；
- `bootm`：可以解析 U-Boot legacy image 或 FIT，并按镜像头加载 payload。

本轮选择 `bootm`，因此需要 `mkimage` 把 flat binary 包装成 legacy uImage。

### 7.2 为什么必须设置 entry address

构建脚本最初只设置 load address。U-Boot 会分别使用镜像头中的 load 和 entry 字段，
所以两者都必须与链接入口一致。`arceos/scripts/make/build.mk` 最终同时传入：

```text
-a 0x40200000
-e 0x40200000
```

板端 `iminfo` 随后确认：

```text
Image Type:   RISC-V Linux Kernel Image (uncompressed)
Load Address: 40200000
Entry Point:  40200000
Verifying Checksum ... OK
```

### 7.3 构建和部署命令

```bash
set -o pipefail
make visionfive2 2>&1 | tee /tmp/pulseos-vf2-build.log
cp kernel-vf2.uimg /mnt/d/Tftpd64/kernel-vf2.uimg
```

`make visionfive2` 默认 `VF2_SMP=4`，输出：

- `kernel-vf2`：flat binary；
- `kernel-vf2.uimg`：供 U-Boot `bootm` 使用；
- `PulseOS_riscv64-visionfive2.elf`：符号、反汇编和地址定位使用的匹配 ELF。

写本文时最后一次本机构建快照为：

```text
raw kernel SHA-256: b1203452ebcf4a39e6fdde82a57017fe68c521f56375e2b59df32ab9dd25471c
uImage SHA-256:     07eab6dad3a993be97070b6bb8517d8b4e6b4d95bacfa4dbe1a9d50a7d429ea2
payload size:       3171328 bytes
load/entry:         0x40200000 / 0x40200000
```

TFTP 目录中的文件与仓库根目录的 uImage 逐字节一致。需要注意 legacy uImage 头包含创建
时间，因此同一 raw kernel 在不同时间重新运行 `mkimage` 后，uImage 哈希也可能变化。

## 8. 第三阶段：从“Starting kernel”后无日志定位到平台初始化

### 8.1 最初现象

第一轮板端能够完成 TFTP、`iminfo` 和 `bootm`，但只看到：

```text
Starting kernel ...
clk u0_mipitx_dphy_clk_txesc already disabled
pmic_ops: cannot read pmic power register
```

这不能直接证明“内核完全没有执行”。最后两行可能来自固件/U-Boot 的设备清理或复位路径。
在标准日志系统、异常向量和内存管理都没有初始化时，最有效的办法是加入最小、不可分配、
不依赖锁的 UART 单字符检查点。

### 8.2 早期 UART 为什么直接访问 MMIO

JH7110 UART0 是 DW APB UART，地址 `0x10000000`，寄存器宽度和步长均为 32 bit/4 byte。
U-Boot 已经设置波特率、时钟和 pinmux，因此内核早期阶段不重置 UART，只轮询 LSR 并写
THR。MMU 前使用物理地址，MMU 后使用 direct-map 虚拟地址。

这样做比早期依赖 SBI console 更适合本次定位：即使 OpenSBI 的 console 扩展差异或内存
缓冲区转换出错，仍能看到最前面的字符。

### 8.3 第一组标记的含义

```text
B  已进入 0x40200000 的 `_start`
P  临时页表已经填充
M  已启用 Sv39，identity mapping 仍存在
T  已从 DTB 建立启动 hart 的逻辑映射
K  即将跳入高半区 `axplat::call_main`
```

板端依次返回：

```text
BPMTK
```

这一步排除了以下方向：镜像入口错误、`bootm` 没有跳转、UART 完全不可用、最初页表建立
即失败、高半区跳转前崩溃。调试范围被收窄到运行时早期平台初始化。

### 8.4 第二组标记与 live DTB

继续加入：

```text
I  进入平台 init_early
F  DTB header 和 totalsize 校验通过
Y  在运行时阶段重新解析并发布 CPU topology
M  开始内存布局解析
a..h  RAM、memreserve、reserved-memory、对齐/交集和发布阶段
N  内存布局完成
p..v  PLIC 节点、reg/ndev、phandle、contexts、边界校验和发布
L  PLIC topology 完成
D/R/E  安装 trap、初始化 time 并离开 init_early
```

每个字符都放在可能失败操作的前后，因此“最后一个字符”就是最小故障区间。它们是
bring-up 诊断接口，不是正常用户日志协议。

## 9. DTB 与内存解析问题

### 9.1 把 `memory-controller@...` 错当作 RAM

早期内存扫描如果只按节点名包含或前缀 `memory` 判断，会把 JH7110 的
`memory-controller@15700000` 一类设备节点误认为系统内存。后果不是简单“多一行日志”，
而是分配器可能把 MMIO 当作可分配页，随后出现不可预测访问异常。

修复方法是只接受：

```text
device_type = "memory"
```

然后读取该节点的所有 `reg`，与配置的物理上界相交，并将起点截到 kernel load address
之后。这样配置文件只提供早期可达上界，真正交给分配器的 RAM 由固件 DTB 决定。

### 9.2 不能忽略 DTB 和 reserved-memory

U-Boot 把 live DTB 放在 RAM 高地址。如果直接把整段 RAM 交给 allocator，DTB 可能在平台
解析尚未结束时被分配覆盖。当前实现按以下顺序处理保留区：

1. 先加入 live DTB 自身范围，确保固定容量不足时也不会漏掉它；
2. 读取 FDT header 的 memreserve 表；
3. 读取 `/reserved-memory` 子节点；
4. 向 4 KiB 页边界扩展；
5. 与实际 RAM 相交、排序、合并后一次性发布。

板端最终显示 DTB 所在的 `0xf76df000..0xf76eb000` 被标为 reserved，证明这条链路已生效。

### 9.3 为什么 CPU topology 要解析两次

第一次解析发生在 `_start` 的极早期，用于把 U-Boot 传入的物理 hart ID 转换为 PulseOS
逻辑 CPU 0。随后 axruntime 会完成自己的 BSS/运行时初始化，早期写入的全局拓扑状态在
先前版本中不能保证继续有效。

板端曾出现：早期 `T` 已通过，但运行时 PLIC 查不到完整 CPU 映射。解决方法不是继续给
空状态加 fallback，而是在 `init_early` 中从同一个 live DTB 再解析一次，并用 release/acquire
顺序重新发布。这就是日志中的 `Y`。

## 10. PLIC topology 问题

### 10.1 `pqrst!` 表示什么

某轮日志为：

```text
IFMabcdefghNpqrst!
```

这说明：

- PLIC compatible、`reg` 和 `riscv,ndev` 已找到；
- CPU interrupt-controller phandle 和 `interrupts-extended` 已开始解析；
- 但至少一个逻辑 CPU 没有得到 S-mode external interrupt context。

JH7110 PLIC 的典型上下文排列为：hart 0 只有管理侧 context，U74 hart 1 至 4 分别拥有
M-mode/S-mode context。对 PulseOS 有用的 S-mode context 是 2、4、6、8。

### 10.2 为什么不能无条件写死 2、4、6、8

首选方案始终是按 DTB 的 `interrupts-extended` 和 CPU intc phandle 建立映射，因为 context
顺序属于固件描述的一部分。实际板上的 U-Boot control DTB 与 Linux OS DTB 的 phandle
组织并不完全相同，导致按标准链接解析时有缺口。

最终加入了一个严格受限的 JH7110 fallback，只有同时满足以下条件才启用：

- PLIC base 为 `0x0c000000`；
- `riscv,ndev` 为 136；
- 某些 U74 S-mode context 仍缺失。

fallback 根据物理 hart ID 计算 `hart_id * 2`，得到 2、4、6、8。随后仍会计算 priority、
enable 和 context register 的最大末端，确认全部访问落在 DTB 给出的 PLIC MMIO size 内。
这避免把一个“为当前板救急的映射”扩散成所有 RISC-V PLIC 的默认假设。

### 10.3 `pqrstw!` 之后仍失败的原因

加入 fallback 后日志变为：

```text
IFMabcdefghNpqrstw!
```

`w` 证明 fallback 已执行，但仍缺 context。结合前面“早期 T 通过、运行时映射为空”的现象，
最终确认问题在拓扑发布时机，而不在 PLIC 算法本身。运行时重新解析并发布 topology 后，
完整标记成为：

```text
IFYMabcdefghNpqrstwuxvLDRE
```

随后出现 PulseOS Logo、内存、调度器、中断和驱动初始化日志。这是平台基本启动链路的
第一个完整板端里程碑。

## 11. 从“无可用文件系统”到 JH7110 SD/MMC

完整进入运行时后的第一个 panic 是：

```text
No usable filesystem found!
```

这不是 ext4 实现本身的第一嫌疑，因为日志中还没有任何块设备注册。下一步应先让 SDIO1
成为 PulseOS 的 `BlockDriverOps` 设备，再讨论分区或文件系统。

### 11.1 为什么不能直接复用 `bcm2835-sdhci`

两者都能连接 SD 卡，但“卡协议相同”不等于“主控制器寄存器相同”。

| 项目 | BCM2835 SDHCI 路径 | VisionFive 2 SDIO1 |
| --- | --- | --- |
| SoC | Broadcom/Raspberry Pi | StarFive JH7110 |
| 控制器模型 | BCM SDHCI/eMMC | Synopsys DesignWare Mobile Storage Host |
| 本地驱动创建方式 | `EmmcCtl::new()`，内部固定地址 | 由平台配置传入映射后的 MMIO base |
| 驱动中的固定地址 | `0xFE340000` | 实际为 `0x16020000` |
| clock/reset/FIFO/timing | BCM 专用流程 | JH7110 clock/reset/syscon 和 DW MMC 寄存器 |
| 中断/状态位 | SDHCI 语义 | DW MMC `RINTSTS/STATUS/FIFOTH` 语义 |

若只把 BCM 驱动基址改成 `0x16020000`，它会把一套控制器的寄存器偏移和值写到另一套
控制器上。这不是“不够优雅”，而是硬件语义错误，可能直接破坏控制器状态。

真正可复用的是上层 `BlockDriverOps`、512 字节块语义、错误映射和文件系统接入模式；
寄存器级 host controller 必须使用 JH7110/DW MMC 实现。因此新增了
`starfive-jh7110-sdmmc`，而不是复制一个改名后的 BCM 驱动。

### 11.2 第一版 `simple-sdmmc` 尝试和 CMD8 失败

第一版适配已经能读出控制器 ID：

```text
VERID=0x5342290a
HCON=0x00c43cc1
```

这证明 `0x16020000` 的 direct map 和基本 MMIO 访问正确。但初始化停在：

```text
command 8 failed
```

CMD8 属于卡识别早期命令。审计该实现后发现，它对 JH7110 的 controller takeover 不完整，
并使用固定分频。以板上的 50 MHz CIU reference 计算，识别阶段实际时钟约为 6.25 MHz，
而 SD identification 通常应在约 400 kHz 工作。

这轮修改同时替换了 host driver 和初始化流程，因此严格说不能把 CMD8 失败只归因于一个
分频数；可以确认的是，通用简化实现没有满足这块 JH7110 板的完整初始化合同。

### 11.3 为什么没有直接使用 TGOSKits 最新 IDMAC 版本

调研时 TGOSKits 最新 DW MMC 路径已经转为 IRQ + IDMAC，要求驱动获得一致的 DMA buffer、
物理地址、缓存维护和中断完成事件。直接把它塞入当前 PulseOS 会产生两个问题：

1. `axdriver` 到 `axdma/axmm/axfs` 的现有依赖方向可能形成循环；
2. 在没有完成 cache coherency 和 DMA ownership 合同前，能编译也不代表数据可靠。

bring-up 阶段因此选用最后一组仍支持 polling/FIFO 的匹配版本，并精确锁定：

```text
starfive-jh7110-dwmmc = 0.1.3
dwmmc-host             = 0.3.3
sdio-host2             = 0.1.4
sdmmc-protocol         = 0.4.2
```

这是有意的阶段性取舍：先建立可解释的 PIO 基线，再单独设计 DMA/IRQ，不把两类风险混在
一次调试中。

### 11.4 当前块设备适配器做了什么

`crates/axdriver_block/src/starfive_jh7110.rs` 负责：

- 接收 `axconfig::devices::SDMMC_PADDR` 的 direct-map 地址；
- 重置并初始化 JH7110 DW MMC；
- 以 50 MHz reference 生成约 400 kHz 的 identification clock；
- 将上游默认的 256-word FIFO 配置修正为 JH7110 的 32-word、32-bit FIFO；
- 设置 `FIFOTH = 0x200f0010`；
- 使用 SD-only 初始化、3.3 V、1 bit 识别后切换 4 bit；
- 用 `Mutex` 串行化控制器和卡状态；
- 按 512 字节单块执行 CMD17/CMD24；
- 对初始化和 I/O 使用有界超时；
- 映射到 PulseOS 同步块设备接口；
- async trait 当前只是立即完成的兼容包装，不代表异步硬件执行。

`flush()` 当前返回成功，但控制器路径没有实现可证明的持久化屏障。因此不能据此宣称
写入、fsync 或突然掉电一致性已经完成验证。

### 11.5 CMD17 CRC 错误与 6.25 MHz 保守时钟

换用 JH7110 host 后，卡初始化成功：

```text
kind=Sd, high_capacity=true, rca=0x1
capacity_blocks=121466880
```

但文件系统读取块 0 的 CMD17 出现 CRC mismatch。寄存器日志显示 RXDR、data CRC 状态和
FIFO occupancy，说明问题已经从“卡未识别”推进到“数据阶段不稳定”。初始化后的默认
SD 时钟是 25 MHz；当前实现是 CPU 轮询 FIFO，没有 DMA/IRQ 给出的服务余量。

本轮只改变传输时钟，将其从 25 MHz 限制到 6.25 MHz，同时保留 4 bit 和 3.3 V。新日志：

```text
DIV=0x00000004 ENA=0x00000001
CTYPE=0x00000001
FIFOTH=0x200f0010
JH7110 SD/MMC card ready
```

随后 block 0 读取、ext4 打开和挂载成功。这一前后对比支持“25 MHz 下当前 PIO 路径的
时序或 FIFO 服务余量不足”这一判断。它不表示硬件只能运行在 6.25 MHz；等 DMA、IRQ、
pinctrl、clock 和 regulator 都由 PulseOS 接管后，应重新逐档测试频率。

### 11.6 U-Boot 的三条 MMC 命令分别做什么

```console
mmc list
mmc dev 1
mmc rescan
```

- `mmc list`：列出 U-Boot 已注册的 MMC/eMMC/SD 控制器及编号，不写卡。
- `mmc dev 1`：把后续 U-Boot MMC 操作的当前设备切换到编号 1；本板日志中它对应可拆卸
  microSD/SDIO1，但编号应以 `mmc list` 的实际输出为准。
- `mmc rescan`：重新初始化当前控制器并枚举卡，刷新容量和卡状态；它不会格式化或写入
  文件系统。

当前 PulseOS 驱动会重置 DW MMC，但仍依赖 U-Boot 已准备好的 clock tree、pinmux 和
regulator，因此在 bring-up 合同中保留 `mmc dev 1` 和 `mmc rescan`。

## 12. ext4 成功后为什么又出现 `No NIC device found`

SD 时钟修复后，板端首次出现：

```text
filesystem on device 0: ext4
select block device 0 ... as root filesystem
mounted proc at /proc
mounted devtmpfs at /dev
mounted tmpfs at /tmp
No NIC device found!
```

这证明存储和 ext4 已经通过，新的 panic 来自 feature 组合。根包原先把 `net` 作为所有
RISC-V 构建的共同能力，VisionFive 2 因此进入 `axnet::init_network`，但驱动列表中没有
JH7110 DWMAC NIC。

修复方式是按平台声明真实能力：

```toml
net = ["axfeat/net"]
qemu = ["dep:axplat-riscv64-qemu-virt", "net"]
visionfive2 = [
    "dep:axplat-riscv64-visionfive2",
    "axfeat/driver-starfive-jh7110-sdmmc",
]
```

QEMU 仍启用 VirtIO 网络，VisionFive 2 在没有 NIC 驱动前不编译网络运行时。这比注册一个
假网卡或捕获 panic 更符合 feature 表达硬件能力的含义。

后续板端日志确认 ext4 挂载仍成功，且 `No NIC device found` 已消失。

## 13. `SMP=4` 的 OpenSBI hart 0 异常

### 13.1 现象

网络 panic 消失后，系统在挂载临时文件系统之后出现：

```text
sbi_trap_error: hart0: trap handler failed (error -2)
sbi_trap_error: hart0: mcause=0x5
sbi_trap_error: hart0: mtval=0x4003d068
sbi_trap_error: hart0: mepc=0x40004f9e
sbi_trap_error: hart0: ra=0x4000a810
sbi_trap_error: hart0: tp=0x4003d000
```

`mcause=5` 是 load access fault。所有 `0x4000....` 地址都位于开发板 OpenSBI firmware
区域，而 PulseOS 从 `0x40200000` 开始，因此不能只在 PulseOS ELF 中查 `mepc`。

### 13.2 为什么首先怀疑 SBI HSM

异常发生在根文件系统挂载之后。此时 axruntime 即将启动 secondary CPUs，而
`PowerIf::cpu_boot` 正是通过 `sbi_rt::hart_start` 调用 OpenSBI HSM。

从板上 TFTP 目录的匹配 firmware FIT 提取 OpenSBI payload，并按 `0x40000000` 反汇编后：

```text
0x40004f9e: lr.d.aq a0,(a5)
```

调用点 `0x4000a810` 落在 `sbi_hsm_hart_start_finish` 一带，即 secondary hart 将状态从
START_PENDING 迁移到 STARTED 的路径。这与 `hart0` 报错和 HSM 调用时机一致。

### 13.3 根因不是“OpenSBI 不支持四核”，而是 CPU topology 选错了核

Linux DTS 中：

- hart 0 是 SiFive S7 管理核；
- hart 1、2、3、4 才是带 Sv39/F/D 扩展的 U74 应用核；
- Linux OS DTS 通常将 hart 0 标为 `disabled`。

但开发板当前 U-Boot **control DTB** 将 `cpu@0` 标为可用。旧解析器只检查
`status = "okay"` 并限制最多四项，没有检查 CPU 类型或允许的 hart 范围。

假设 U-Boot 从 hart 1 启动，旧算法的实际结果是：

```text
先强制加入 boot hart 1       -> [1]
遍历时加入 status=okay 的 0   -> [1, 0]
hart 1 重复，跳过             -> [1, 0]
加入 hart 2                   -> [1, 0, 2]
加入 hart 3，达到容量 4       -> [1, 0, 2, 3]
hart 4 被容量上限挤掉
```

因此逻辑 CPU 1 被错误映射到物理 hart 0。axruntime 启动第一个 secondary CPU 时，实际执行
的是：

```text
sbi_hart_start(0, _start_secondary, stack)
```

这直接解释了 OpenSBI 为什么报告 `hart0`，也解释了为什么 `max-cpu-num = 4` 没有保护
系统：容量限制只能保证“最多四个”，不能保证“四个都是 U74”。

### 13.4 修复方法

当前 topology parser 增加 JH7110 应用核约束：

```text
VF2_FIRST_U74_HART_ID = 1
VF2_LAST_U74_HART_ID  = 4
```

只有同时满足以下条件的节点才进入 PulseOS CPU topology：

1. 节点是可用 CPU；
2. 能从 `reg` 取得 hart ID；
3. hart ID 位于 `1..=4`。

启动 hart 仍先放入逻辑 CPU 0，其余 U74 按 DTB 顺序去重加入，预期结果为：

```text
logical CPU 0 -> hart 1  (boot hart)
logical CPU 1 -> hart 2
logical CPU 2 -> hart 3
logical CPU 3 -> hart 4
```

同时新增回归测试，明确拒绝 hart 0 和 hart 5，并保留 U74 到 PLIC S-mode context
2、4、6、8 的映射测试。

`PowerIf::cpu_boot` 在调用 SBI 前新增诊断日志。修复后的板端应看到类似：

```text
Starting logical CPU 1 on JH7110 hart 2: entry=..., stack=...
Starting logical CPU 2 on JH7110 hart 3: entry=..., stack=...
Starting logical CPU 3 on JH7110 hart 4: entry=..., stack=...
```

不应再出现任何 `hart_start(0)` 或 `sbi_trap_error: hart0`。

### 13.5 为什么没有用 `VF2_SMP=1` 掩盖问题

`make visionfive2 VF2_SMP=1` 对定位很有价值，可以区分“基本板级启动”与“secondary hart
启动”问题。但用户目标明确要求修复 `SMP=4`，所以单核只能作为诊断开关，不能作为最终
解决方案。默认值保持为 4，并让根包的 `smp` feature 通过可选依赖传播到 VF2 平台 crate。

## 14. 完整问题演进表

| 阶段 | 板端或构建现象 | 定位结论 | 处理 |
| --- | --- | --- | --- |
| 配置生成 | 空 ranges 无法推断类型 | axconfig 类型缺失 | 给空数组加 `[(uint, uint)]` 注释 |
| 平台选择 | VF2 构建混入 QEMU 平台 | feature 与旧生成配置污染 | 平台依赖可选化，每次重建专用 axconfig |
| 镜像生成 | raw binary 不适合 `bootm` | 缺 U-Boot legacy header | 增加 `mkimage` 和 load/entry |
| 最早上板 | `Starting kernel` 后无 PulseOS 日志 | 故障范围未知 | 增加 MMU 前 UART 单字符检查点 |
| 早期启动 | `BPMTK` | 已到 `call_main` | 继续在 `init_early` 内分段 |
| 平台初始化 | 停在 `I` 或内存阶段 | live DTB/内存扫描问题 | 校验 DTB，只认 `device_type=memory` |
| PLIC | `pqrst!` | S-mode contexts 不完整 | 解析 phandle，增加受限 JH7110 fallback |
| PLIC | `pqrstw!` 仍失败 | 早期 topology 状态未可靠保留 | 运行时再次解析并发布，出现 `Y` |
| 运行时 | Logo 后 `No usable filesystem` | 没有块设备 | 接入 JH7110 SDIO1 |
| SD 第一版 | controller ID 可读，CMD8 失败 | 简化 host 初始化/识别时钟不契合 | 换用匹配的 JH7110 polling/FIFO 驱动栈 |
| SD 第二版 | 卡识别成功，CMD17 data CRC | 25 MHz PIO 数据阶段余量不足 | 单变量降到 6.25 MHz，保留 4 bit/3.3 V |
| 文件系统 | ext4 挂载后无 NIC panic | VF2 错启用 QEMU 网络 feature | 分离 `qemu/net` 与 `visionfive2/sdmmc` |
| SMP | OpenSBI `hart0` load access fault | control DTB 把 S7 0 纳入四核拓扑 | 只接受 U74 hart 1 至 4 |
| SMP 修复后 | 新镜像已构建并放入 TFTP | 本地门禁通过 | 等待最后一轮板端串口确认 |

## 15. 代码落点

### 15.1 平台层

`crates/axplat-riscv64-visionfive2/`：

- `axconfig.toml`：板级地址、四核上限、8 GiB 早期 RAM 上界、4 MHz timer、SDIO1。
- `boot.rs`：临时 Sv39 页表、主核/从核入口、早期 trap 和诊断字符。
- `console.rs`：JH7110 UART0 直接 MMIO，复用 U-Boot 初始化状态。
- `topology.rs`：live DTB、U74 topology、PLIC topology 和受限 fallback。
- `cpu_topology.rs`：逻辑 CPU 与物理 hart 的小型定长映射及单元测试。
- `mem.rs`：RAM、DTB memreserve 和 `/reserved-memory` 的解析/发布。
- `plic.rs`：动态 context 的 enable、threshold、claim、complete 和路由。
- `irq.rs`：timer、IPI、external IRQ 分派和 SBI IPI。
- `time.rs`：4 MHz monotonic time、SBI one-shot timer 和 JH7110 RTC wall clock。
- `power.rs`：SBI HSM secondary boot、错误映射和 system reset。

### 15.2 驱动与 feature 层

- `crates/axdriver_block/src/starfive_jh7110.rs`：JH7110 SD/MMC block adapter。
- `crates/axdriver_block/Cargo.toml`：锁定 polling/FIFO 兼容依赖版本。
- `arceos/modules/axdriver/`：注册 probe、build cfg 和 driver macro。
- `arceos/api/axfeat/Cargo.toml`：暴露 `driver-starfive-jh7110-sdmmc`。
- 根 `Cargo.toml`：拆分 `qemu`、`net`、`visionfive2` 和 `smp` feature。

### 15.3 构建与使用入口

- 根 `Makefile`：`visionfive2`、`visionfive2-elf`、`VF2_SMP` 和专用输出目录。
- `arceos/scripts/make/build.mk`：uImage architecture、load 和 entry。
- `docs/visionfive2.md`：日常构建、TFTP 和启动命令的简版说明。
- 本文：设计、排错和证据的完整记录。

## 16. 本地验证方法与结果

### 16.1 VisionFive 2 专用构建

```bash
make visionfive2
```

结果：通过，生成 flat binary、legacy uImage 和匹配 ELF。`mkimage -l` 确认架构、payload、
load address 和 entry address 正确。

### 16.2 PulseOS 原有双架构门禁

按照仓库约定执行：

```bash
set -o pipefail
make test 2>&1 | tail -30
```

结果：在最后一轮实现修改后通过。该结果只证明现有 RISC-V QEMU 和 LoongArch64 构建没有
被本轮 feature/平台修改破坏，不等于 VisionFive 2 硬件运行验证。

### 16.3 静态差异检查

```bash
git diff --check
```

结果：通过。2026-08-07 的原始裁剪确认 VF2 当时不包含 `axnet` 初始化路径，QEMU 构建
仍保留网络 feature；2026-08-09 的 NIC 增量重新启用 VF2 `axnet`，并以独立 DWMAC driver
feature 保持 QEMU 的 VirtIO 网络路径不变。

### 16.4 已完成的板端验证

板端已经依次证明：

1. legacy image 校验通过并跳入 `0x40200000`；
2. MMU 前后 UART 可用；
3. live DTB、RAM、reserved ranges 和 PLIC topology 初始化完成；
4. 运行时识别 `platform = riscv64-visionfive2` 和 `smp = 4`；
5. JH7110 SD/MMC 识别 59.3 GiB SDXC；
6. 6.25 MHz、4 bit PIO 下可以读取块 0；
7. ext4 根文件系统打开并挂载；
8. 在 2026-08-07 尚未实现 NIC 时，不会再错误进入 `axnet` panic。
9. logical CPU 1、2、3 分别在 U74 hart 2、3、4 完成初始化，四核继续进入 shell；
10. DWMAC 增量识别 GMAC0 `0x16030000`、IRQ 7 和 EEPROM MAC，并由 `axnet` 选择为 `eth0`。

### 16.5 尚未完成的板端验证

仍需要确认：

1. 四核下 timer/IPI/PLIC 没有新的长稳异常；
2. 系统完成目标测例，而不只是进入 shell；
3. 进行足够时长和次数的 SD 读取稳定性测试；
4. 在专用可破坏介质上验证写入、flush/fsync、校验和和重启后数据一致性；
5. 在 VisionFive 2 上复验 `ping -c 3 127.0.0.1` 与本机 TCP server/client；同一内核的
   RISC-V QEMU BusyBox ICMP/TCP loopback 已通过；
6. 当前最新候选读到有效 DMA descriptor writeback，并完成主机到
   `169.254.141.28` 的 ARP/ICMP。

## 17. 当前上板命令

先在 U-Boot 确认控制器编号：

```console
mmc list
mmc dev 1
mmc rescan
```

然后进行一次性 TFTP 启动，不执行 `saveenv`：

```console
setenv serverip 169.254.141.27
setenv ipaddr <开发板同网段地址>
ping ${serverip}
tftpboot ${loadaddr} kernel-vf2.uimg
iminfo ${loadaddr}
bootm ${loadaddr} - ${fdtcontroladdr}
```

如果 `${loadaddr}` 不是可用下载地址，可显式使用已验证的临时下载地址，但不要让下载区
覆盖 kernel 目标地址或 DTB。当前镜像头会由 `bootm` 把 payload 加载到 `0x40200000`。

## 18. 后续日志的判读顺序

下一轮 `SMP=4` 板测建议按以下顺序判读，避免看到后期错误后重新怀疑已证实的前期链路：

1. `iminfo` 的 CRC、load、entry 是否正确；
2. 是否出现 `BPMTK`；
3. 是否出现完整 `IFYMabcdefghNpqrstwuxvLDRE`；
4. 是否识别四个 CPU 和 JH7110 block device；
5. 是否成功打开并选择 ext4 root；
6. `Starting logical CPU ...` 是否严格映射到 hart 2、3、4；
7. 是否还有 `hart0`、HSM、IPI、timer 或 PLIC 异常；
8. 是否进入 shell/测例并能持续运行。

如果在前四步之前失败，应优先检查镜像、DTB、页表和固件交接；如果只在第六步失败，才应
集中检查 HSM、secondary entry、stack 和 per-CPU 初始化。这种分层能避免每轮都从零猜测。

## 19. 当前局限与下一步设计

### 19.1 SD/MMC

当前是串行 polling PIO，6.25 MHz 是稳定 bring-up 参数，不是性能目标。后续要升级到
IDMAC/IRQ，必须先定义：

- DMA buffer 的分配和物理地址合同；
- cache clean/invalidate 规则；
- descriptor ownership 与 completion 顺序；
- IRQ 注册、屏蔽、丢失唤醒和超时恢复；
- 与 `axdriver`、`axdma`、`axmm`、`axfs` 的无环依赖边界；
- 多块请求、flush 和错误恢复语义。

当前 PulseOS 文件系统探测还直接从整个块设备的 block 0 查找 ext 文件系统，没有在这条
板级路径中实现 MBR/GPT 分区选择。因此已确认的启动介质是将 PulseOS rootfs 镜像直接写
入专用 microSD 的布局；一张带 Debian/U-Boot 分区表的卡即使能被控制器识别，也不保证
会被选为 PulseOS root。写 raw image 会覆盖原分区表，必须使用可破坏的专用卡并保留
SPI firmware 或其他恢复手段。

### 19.2 固件依赖

UART、SDIO clock tree、pinmux 和 regulator 仍部分依赖 U-Boot 的准备状态。这意味着当前
镜像是“在既有板载固件之后启动”，不是“从复位状态独立初始化所有 SoC 外设”。

### 19.3 FDT

当前使用 `fdtcontroladdr` 的 U-Boot control DTB。它与 Linux OS DTB 的 `status` 和 phandle
可能不同，S7 hart 0 问题已经证明不能把某一种 DTB 的假设推广到另一种。后续应考虑：

- 优先加载一份专用、版本受控的 OS DTB；或
- 继续使用 control DTB，但为所有关键节点做 compatible、资源和拓扑的组合校验。

### 19.4 未支持设备

- RTC：从 live FDT 解析 JH7110 RTC 并读取稳定 date/time 快照；该 SoC RTC 不跨整板掉电
  持久，值无效或早于镜像时以构建时间作为 wall-clock 下界。
- Ethernet：GMAC0 的物理 ARP 和普通单播 ICMP 已在 `c28c25d0...` 候选上闭合；硬件以
  `PR` 接收，smoltcp 执行目的 MAC 过滤。当前仍依赖 U-Boot 准备 RGMII clock/pinmux。
- PCIe/USB：未探测、未初始化。
- 板级电源关闭：`system_reset` 后出现的 PMIC 提示属于固件/板级关机路径，尚未单独适配。

## 20. 本次适配得到的工程经验

1. **先确定硬件控制器，再决定复用层级。** SD 卡协议可以复用，BCM SDHCI 寄存器驱动
   不能用于 JH7110 DW MMC。
2. **编译通过只证明接口闭合。** 真正的板级问题依次出现在入口、DTB、PLIC、SD 时钟、
   feature 组合和 HSM topology，均无法由一次 Cargo build 发现。
3. **早期单字符标记非常有效，但要有阶段语义。** `BPMTK` 和
   `IFYMabcdefghNpqrstwuxvLDRE` 把无日志死机转成了可定位状态机。
4. **live DTB 是输入，不是绝对真理。** 必须同时检查 compatible、`device_type`、地址范围
   和 SoC 固定事实；`status=okay` 不能把管理核自动变成应用核。
5. **受限 fallback 优于全局硬编码。** PLIC context fallback 只有在 JH7110 base 和 ndev
   同时匹配时生效，并继续做 MMIO 边界验证。
6. **SMP 必须区分 logical CPU ID 和 physical hart ID。** `max-cpu-num=4` 是容量，不是
   拓扑；每次 HSM/IPI/PLIC 操作都应使用同一份显式映射。
7. **每次只推进一个故障边界。** CMD17 CRC 阶段只降低传输时钟，使“卡识别”和“数据读取”
   的因果关系可解释；网络 panic 则通过 feature 边界修复，而不是混入 SD 驱动。
8. **历史代码只能作为线索。** TGOSKits 的单核平台和后来撤下的文档说明，存在代码不等于
   当前硬件支持声明；必须保留对应版本、构建和板端证据。

## 21. 最终状态说明

本轮适配已经把 PulseOS 从“U-Boot 显示 Starting kernel 后没有内核证据”推进到：

```text
U-Boot/TFTP/bootm
  -> PulseOS early boot
  -> live DTB RAM/PLIC/U74 topology
  -> allocator/scheduler/IRQ
  -> JH7110 SDXC
  -> ext4 root mount
  -> 排除未实现网络
  -> 定位并修复错误启动 S7 hart 0 的 SMP topology
```

默认 `SMP=4` 已在板上确认 logical CPU 1、2、3 分别启动 U74 hart 2、3、4，并继续进入
shell。NIC 增量的最终数据面验收仍单独保留，不用四核启动证据替代网络收发证据。

## 22. 2026-08-09：JH7110 GMAC0 NIC 增量

本次增量把网络 feature 从“平台是否有网络”拆为通用 `net` 运行时和具体设备驱动：QEMU
显式选择 VirtIO net，VisionFive 2 显式选择 `starfive-jh7110-dwmac`。这样 VF2 只有在真实
GMAC 驱动注册后才进入 `axnet::init_network`，也不会改变现有 QEMU 设备选择。

实现范围如下：

1. 从 live FDT 识别 GMAC0 `0x16030000`、macirq、MAC 地址和 PHY phandle；兼容 mainline
   `starfive,jh7110-dwmac` 与旧 vendor U-Boot `starfive,jh7110-eqos-5.20`。
2. 实现 DWMAC 5.20 基本 MAC、MTL、DMA、40-bit descriptor、Clause 22 MDIO 和 YT8531
   link status 编程；按 JH7110 DT 使用 fixed burst、PBL=16、禁用 PBLx8。
3. 把 PLIC IRQ 接到 `axpoll::PollSet`，由 RI/TI 完成状态转换 RX/TX ownership；注册 handler
   之前保持设备中断关闭，避免初始化窗口丢失完成事件。
4. DMA 页来自全局页分配器，并通过 JH7110 CCACHE `flush64` 做显式缓存维护。由于当前平台
   没有独立 clean/invalidate 原语且 RISC-V 页表未提供真实 uncached 映射，RX/TX 环各有
   4 项，但任一时刻只向 DMA 暴露 1 项，避免同一缓存行出现并发 ownership。
5. PHY 探测优先复用固件 MDIO CR，再扫描标准 CSR clock selector 并尝试校验 YT8531 PHY
   ID；读不到 ID 时保留固件 CR 和已协商链路，不把诊断失败升级为 NIC 注册失败。MTL RX/TX
   queue size 按 JH7110 的 2 KiB FIFO 编程，避免依赖复位默认值。
6. 正常路径仍由 PLIC RI/TI 唤醒；DWMAC 额外请求 10 ms 有界轮询，并直接复核当前 RX 和
   上一项 TX descriptor 的 OWN 位。这样首次中断未路由或丢失时，ARP 收包和 TX completion
   不会永久停在网络线程的无限等待中；其他 NIC 默认不请求该轮询周期。
7. 从 live FDT 的 `snps,axi-config` phandle 读取 WR/RD outstanding limit、BLEN 和 LPI；
   当前板型得到 WR=15、RD=15、BLEN=`0xf0`。同时遵循
   `snps,force_thresh_dma_mode`，把 RX/TX MTL 从 store-forward 改为 Linux 同样采用的
   64-byte threshold。这补上了此前 DMA system-bus 寄存器只写 fixed-burst/EAME 的缺口。
8. 对照 Linux `dwmac-starfive.c`，从 `starfive,syscon` 的 phandle、offset、shift 和
   `phy-mode` 重新写入 SoC PHY interface select。当前板型目标寄存器是
   `0x1701000c[20:18]`，RGMII 编码为 1；AON syscon 同时加入板级 MMIO 映射。该步骤不再
   假设 U-Boot 留下的接口模式必然正确，并记录写入前后的寄存器值。
9. StarFive Linux glue 还无条件设置 `dma_cfg->dche = true`，随后 DWMAC4/5 DMA init 在
   soft reset 后写 `DMA_MODE.DCHE`（bit 19）。PulseOS 之前没有恢复该位；当前初始化已补齐，
   并由模拟 MMIO 单元测试同时验证 DCHE 与 AXI system-bus 值。

本轮静态和构建证据为：驱动库 13 项单元测试通过，其中两项模拟无 IRQ 的 RX/TX DMA OWN
回写；`make visionfive2` 成功生成 3.08 MiB
legacy uImage，load/entry 均为 `0x40200000`；仓库约定的 `make test` 双架构门禁通过；镜像
中确认嵌入 `169.254.141.28/24`、gateway `169.254.141.27` 和 DWMAC 设备名。一次 40 秒
RISC-V QEMU 有界回归仍注册 `virtio-net`、初始化 `10.0.2.15/24`，并到达
`BUILDSTORM_MINIBUILD ok`；限时退出只证明这段 QEMU 启动路径，不是 VF2 板端网络证据。

板测先后完成两版镜像：均由 U-Boot GMAC0 成功 TFTP，PulseOS 串口均识别
`GMAC0 at 0x16030000, IRQ 7`、EEPROM MAC `6c:cf:39:00:7b:9c`，`axnet` 选择
`starfive-jh7110-dwmac` 并配置 `169.254.141.28/24`，四个 U74 也均进入 shell。但两版主机
ping 都是 100% 丢包；第二版额外记录到 PHY status `0x0000`。这证明控制面接入，不证明
RX/TX 数据面可用。

基于该失败证据，修正版增加 MDIO CR/PHY ID 探测、4 项单在途 DMA ring、正确的 5.20
NIS/AIS 位和 2 KiB MTL FIFO 配置。第一次把 PHY ID 当作硬门槛的镜像上板后返回
`JH7110 DWMAC: initialization failed: Io`，随后 `axnet` 因无 NIC panic；这证明严格门槛不适合
当前固件依赖的 bring-up 合同。最终源码改为探测失败时保留固件 CR 并继续注册。

上一版镜像以独立文件名 `kernel-vf2-nic-final-20260809.uimg` 同步到 TFTP 根目录，SHA-256 为
`95d1f77ffecb97865aa7d61ad6d50b3ab38c2c9fae9fb6258285d7c066697b09`。严格版 panic 后走
PMIC 关机，串口不再响应，因此回退版仍需重新上电后复验：

```console
setenv serverip 169.254.141.27
setenv ipaddr 169.254.141.28
tftpboot ${loadaddr} kernel-vf2-nic-final-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

串口必须出现 GMAC/axnet 日志；PHY ID/status 若仍不可读，应出现明确的 firmware-CR fallback
警告，而不是拒绝注册。本版还会记录初始化 DMA/当前 RX/TX descriptor 状态，以及首次完成
中断或首次异常中断的原始 DMA/MAC 状态，用于区分报文未进 MAC、DMA 未回写和 PLIC 未唤醒。
最后由主机执行一次 ping，才构成本次基本收发能力的板级证据。
单在途 descriptor 设计只用于先闭合缓存一致性与功能链路，不能据此声称网络吞吐性能达标。

补齐 AXI/threshold 配置后的镜像为
`kernel-vf2-nic-axi-20260809.uimg`，仓库与 TFTP 根目录副本的 SHA-256 均为
`d1faccae339ccacc75b7aa6b47fe9f80a8f45ee979ba41939efbc7f7fe537956`。下一轮板测必须显式
加载该文件，不能用旧 `final` 文件名替代：

```console
tftpboot ${loadaddr} kernel-vf2-nic-axi-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

在该版上执行 `ping -c 3 127.0.0.1` 得到
`can't create raw socket: Protocol not supported`。源码核对确认 smoltcp 已编译
`socket-raw/socket-icmp`，但 PulseOS `sys_socket` 对 AF_INET/AF_INET6 `SOCK_RAW` 直接返回
`EPROTONOSUPPORT`；因此该输出只定位出 Linux socket ABI 缺口，不能证明 loopback 失败。
QEMU 日志中本机 `127.0.0.1:8080` 已处理多次 HTTP TCP 请求，证明同一 PulseOS 软件栈的
TCP loopback 路径可工作；VisionFive 2 板端仍要用 `busybox httpd` 与 `curl` 做同类双端复验。

继续核对 Linux StarFive glue 后生成的最新版为
`kernel-vf2-nic-syscon-20260809.uimg`，仓库与 TFTP 副本 SHA-256 均为
`58683f17c046f48423fc7ba0e9714a9f1945e11090aee728c1dc35a2902fb96b`，load/entry 仍为
`0x40200000`。本轮 `make visionfive2`、仓库规定的 `make test` 和 `git diff --check` 通过。
独立 host `axdriver` 单测在依赖解析阶段被仓库缺失的
`crates/axdriver_display/Cargo.toml` 阻断，未进入本次测试代码；不能把该项写成通过。

补齐 DCHE 后的最终候选镜像为 `kernel-vf2-nic-dche-20260809.uimg`，仓库与 TFTP 副本
SHA-256 均为
`75721a0125d02ea6b2b4c74feac7cc041bc39a52b1197421e6e4878cc5cafc75`。驱动库 14 项测试、
`make visionfive2`、双架构 `make test` 和 `git diff --check` 通过；后续板测应以该文件为准。

随后对照 Linux DWMAC4/5 地址寄存器写法，发现主 MAC 地址槽 0 的 high register 除地址高
16 位外还必须设置 `AE`（bit 31）。旧实现只写地址字节，可能导致目的地址为本机 MAC 的
单播帧被过滤；当前实现同时设置 slot 0 `AE` 和 packet filter 的 perfect-filter 选择。新增
模拟 MMIO 测试覆盖这两个寄存器后，驱动库共 15 项测试全部通过。

软件回环已用交互式 RISC-V QEMU 实测，而不是继续使用不受支持的 raw ICMP：guest 内启动
`busybox httpd` 监听 `127.0.0.1:18080`，`curl` 收到 `HTTP/1.1 200 OK`、完整读取
`/etc/os-release`，并返回 `CURL_RC=0`。该结果闭合了 bind/listen/accept、TCP 收发和
loopback 路由，但不包含 VirtIO 或 DWMAC 物理设备的数据收发，不能替代板端验收。

包含 DCHE 和主 MAC perfect-filter 修复的最新候选为
`kernel-vf2-nic-rxfilter-20260809.uimg`，TFTP 副本与构建产物 SHA-256 均为
`02ed01bc5c9b24ebb3fb434169e13b65c975149e6b3c45ca8f6c7c204223b5a8`。本轮
`make visionfive2`、仓库规定的双架构 `make test`、交互式 `make debug` 和
`git diff --check` 均通过；此前的 `final`、`axi`、`syscon`、`dche` 候选均由该文件取代。
下一次物理板复验必须显式加载：

```console
tftpboot ${loadaddr} kernel-vf2-nic-rxfilter-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

继续审计 descriptor ring 后确认 tail pointer 使用“可用区间的排他末端”；当前单在途 RX
从 descriptor 0、tail=descriptor 1 开始，每次补下一项并把 tail 再推进一项，与 Linux
`dirty_rx`/tail 更新合同一致，未发现 off-by-one。当前 DT 还包含
`starfive,tx-use-rgmii-clk`；Linux StarFive glue 在该属性存在时同样不动态设置 TX clock
rate，因此没有额外引入不符合该板型的时钟切换。

为缩短下一轮板测诊断，驱动现在记录 DMA mode/system-bus、TX/RX channel control、current
descriptor、排他 tail、MAC config/filter/address-high 和 MTL queue mode。包装层另各记录一次
“首个 RX frame 已交给 smoltcp”和“首个 TX frame 已交给 DMA”。主机发 ARP 后：没有首 RX
表示问题仍在 MAC/PHY/DMA；有首 RX 而无首 TX 表示协议栈未产生回应；两者都有但主机收不到
则集中检查 TX DMA/RGMII。

同时移除了用户态网络查询中的 QEMU 常量。Netlink 与传统 `SIOCGIF*` 现在读取当前 `axnet`
接口的 IP、prefix、broadcast 和 MAC。交互式 RISC-V QEMU 中
`busybox ifconfig eth0` 仍报告预期的 `10.0.2.15`、`255.255.255.0` 和
`52:54:00:12:34:56`；VF2 应对应报告 `169.254.141.28/24` 与 EEPROM MAC。当前镜像没有
iproute2，板测不要把 `ip: not found` 误判为网络驱动故障。

包含上述诊断和动态接口查询的最新候选为
`kernel-vf2-nic-diagnostics-20260809.uimg`，TFTP 副本与构建产物 SHA-256 均为
`75a1fe836b968a47313eae270ba4d938bc24a78a147749c4ce02b4158c4b60b1`。驱动库 15 项测试、
`make visionfive2`、仓库规定的双架构 `make test`、交互式 `make debug` 和
`git diff --check` 通过；该文件取代 `kernel-vf2-nic-rxfilter-20260809.uimg`：

```console
tftpboot ${loadaddr} kernel-vf2-nic-diagnostics-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

继续补齐无 PLIC 唤醒场景后，10 ms 回退路径除了检查 descriptor OWN 位，还会读取并 W1C
清除 DMA channel status、同步 completion 状态并唤醒 poll set。首次 completion/abnormal 日志
明确标记来源为 `initial`、`IRQ` 或 `poll`，因此实机上可以直接判断 DMA 已完成但 PLIC 未送达，
而不是只看到 ARP 超时。

当时的 RISC-V rootfs 经 `debugfs` 只读检查确认没有 `/etc/resolv.conf`，但
`/etc/nsswitch.conf` 包含 `hosts: files dns`。因此此前 `git clone` 的
`Could not resolve host: github.com` 首先是 DNS 配置缺失证据，不能作为 GMAC 收发失败证据；
板端数据面仍应先用数值地址 TCP 测试。2026-08-11 已在公共 rootfs overlay 中加入
`1.1.1.1` 和 `8.8.8.8` 回退；旧 SD 卡内容不会随 TFTP 内核更新，仍需单独更新。

包含轮询 DMA status 诊断的最新候选为
`kernel-vf2-nic-pollstatus-20260809.uimg`，TFTP 副本与构建产物 SHA-256 均为
`010cf05c22c7a1d11dc909c78368b373e219436290ba052824de27c33bfeb700`，load/entry 均为
`0x40200000`，data size 为 3,236,864 bytes。隔离驱动库 15 项单元测试、
`make visionfive2`、仓库规定的双架构 `make test` 和 `git diff --check` 通过；Cargo 自动追加
的 doctest 另因仓库已有 `doc_auto_cfg` 在当前 nightly 被删除而失败，`--lib` 单元测试门禁不受
影响。该文件取代 diagnostics 候选：

```console
tftpboot ${loadaddr} kernel-vf2-nic-pollstatus-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

随后针对“U-Boot TFTP 正常、PulseOS 接管后失败”继续检查链路重配。Linux Motorcomm 主线驱动
对 YT8531 specific status `0x11` 的定义为：bit 10 link、bit 11 speed/duplex resolved、
bit 13 duplex、bits 15:14 speed。PulseOS 原实现只有 link 与 resolved 同时置位才改 MAC；因此
此前看到的 `0x0000` 会保留默认千兆/全双工，并不会误降为 10M/半双工。该假设被源码否定。

为覆盖延迟自协商和后续网线/速率变化，板级包装层现在最多每秒读取一次 PHY status。只有
link up、resolved 且速度为 10/100/1000 Mbps 时才更新 MAC speed/duplex；超时、link down、
unresolved 或非法 speed code 均保留最后一次有效模式。日志仅在 raw status 变化时输出。

模拟 DMA 测试也从 OWN 位检查扩展到完整数据搬运：RX 测试写入 64-byte payload 并验证上层
NetBuf 内容、下一 descriptor、索引与排他 tail；TX 测试验证 NetBuf payload 被复制到 DMA
buffer，descriptor 长度/OWN、索引与 tail 均正确。加上 PHY 10/100/1000M 映射测试后，隔离
驱动库共 18 项单元测试通过。

包含周期链路刷新和上述诊断的最新候选为
`kernel-vf2-nic-linkpoll-20260809.uimg`，TFTP 副本与构建产物 SHA-256 均为
`142a34267c15995d5bf291ed0beab1fd4215c9c483120a0be7d7377388515ddf`，load/entry 均为
`0x40200000`，data size 为 3,236,864 bytes。`make visionfive2`、仓库规定的双架构
`make test` 与 `git diff --check` 通过。该文件取代 pollstatus 候选：

```console
tftpboot ${loadaddr} kernel-vf2-nic-linkpoll-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

用户实际执行 `ping -c 3 127.0.0.1` 暴露了 syscall 层的 raw socket 缺口。当前实现只开放
IPv4 `AF_INET/SOCK_RAW/IPPROTO_ICMP`，按 Echo 报文 identifier 延迟绑定 smoltcp ICMP socket，
并接入现有的阻塞等待、超时和 poll 唤醒。smoltcp 接收接口只返回 ICMP payload，因此 syscall
返回前补出 Linux BusyBox 所期望的 20-byte IPv4 header；其他 raw 协议及 IPv6 raw ICMP 仍明确
返回不支持。

交互式 RISC-V QEMU 使用 shell-only debug 内核和 `make debug` 生成的 rootfs，保持规定的
8-vCPU VirtIO NIC/块设备拓扑。guest 中实际执行：

```console
/ # ping -c 3 127.0.0.1
PING 127.0.0.1 (127.0.0.1): 56 data bytes
64 bytes from 127.0.0.1: seq=0 ttl=64 time=7.608 ms
64 bytes from 127.0.0.1: seq=1 ttl=64 time=6.438 ms
64 bytes from 127.0.0.1: seq=2 ttl=64 time=1.117 ms

--- 127.0.0.1 ping statistics ---
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 1.117/5.054/7.608 ms
```

该结果闭合 raw socket 创建、ICMP 发送、smoltcp loopback 应答、阻塞唤醒与 Linux 风格接收头，
不经过 VirtIO 或 DWMAC，不能替代 VisionFive 2 物理收发证据。独立 `cargo test -p axnet --lib`
仍在解析阶段被仓库缺失的 `crates/axdriver_display/Cargo.toml` 阻断，未执行新增的纯 header
测试；双架构 `make test`、`make debug`、`make visionfive2`、运行时 ping 与
`git diff --check` 均通过。

包含周期 PHY 刷新、DMA 诊断和 IPv4 ICMP loopback 支持的最新候选为
`kernel-vf2-nic-icmp-20260809.uimg`，TFTP 副本与构建产物 SHA-256 均为
`d913ae1dfcfdda7b3e43ecfb54d12a846bdd36a8445875fc4084f41680389d2c`，load/entry 均为
`0x40200000`，data size 为 3,261,440 bytes。该文件取代 linkpoll 候选：

```console
tftpboot ${loadaddr} kernel-vf2-nic-icmp-20260809.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

## AON CRG takeover after U-Boot TFTP

U-Boot's StarFive DWMAC stop path disables MAC operation and asserts the
GMAC0 AON AXI/AHB resets after a successful TFTP transfer. PulseOS previously
performed only the DWMAC internal soft reset, so a physical boot could reach
the driver with the GMAC still held in SoC reset. The driver now validates the
live `starfive,jh7110-aoncrg` node at `0x17000000`, enables AON clock gates 2
and 3, clears reset bits 0 and 1, and polls the AON reset-status register before
touching the MAC. The VisionFive2 MMIO map includes the complete AON CRG
window; QEMU paths do not contain this node and therefore do not write these
registers.

The shell-only QEMU regression remained green after this change:

```console
/ # ping -c 3 127.0.0.1
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 1.079/5.666/10.580 ms
```

`make test` (both architectures), `make visionfive2`, `rustfmt`, and
`git diff --check` passed. The frozen U-Boot image is
`/mnt/d/Tftpd64/kernel-vf2-nic-reset-20260809.uimg`, SHA-256
`eb2425a3449ccc45d4ac14823e9bcc83ff6aee6f551a6a9ce1b5cd7ec9724dbe`, with
load/entry `0x40200000` and data size `3261440` bytes. Do not treat the QEMU
loopback result as physical NIC RX/TX evidence; after booting this image, the
next board test must capture GMAC diagnostics and a host-side ARP/ICMP or
numeric-address TCP exchange.

为补足仓库 workspace 缺失 `crates/axdriver_display/Cargo.toml` 导致的直接
`cargo test -p axnet --lib` 阻断，本轮将当前 `crates/axdriver_net` 和
`crates/axdriver_base` 复制到临时隔离工作区，仅使用相同源码和
`starfive-jh7110-dwmac` feature 运行单元测试。descriptor、AXI、MAC filter、PHY、
轮询、RX payload 和 TX payload 共 18 项测试全部通过；该测试没有改动仓库工作树。

## 2026-08-10：补齐 ARP 广播的 RX queue 路由

板端 `ping -c 3 127.0.0.1` 已完成 3 发 3 收，说明 raw ICMP 和软件回环路径正常；主机
随后从 `eth1` 向 `169.254.141.28` 发送 5 次探测仍全部超时，邻居项保持 `INCOMPLETE`。
该组合证据把问题继续限定在 DWMAC 物理数据面，而不是 ICMP syscall。

对照 U-Boot EQoS 和 Linux DWMAC4 core 后发现，已有代码只设置了
`GMAC_RXQ_CTRL0.RXQ0EN`，没有设置 `GMAC_RXQ_CTRL1.MCBCQEN`。ARP request 是广播帧；
因此当前修复把 multicast/broadcast queue 明确选择为 queue 0 并使能，同时将 RXQ1
寄存器加入启动诊断。更新后的隔离 DWMAC 单元测试 18/18 通过，仓库规定的双架构
`make test`、`make visionfive2`、`rustfmt --check` 和 `git diff --check` 均通过。

新候选为 `/mnt/d/Tftpd64/kernel-vf2-nic-mcbcq-20260810.uimg`，构建产物与 TFTP 副本的
SHA-256 均为 `c217e6326cebf2497bc634f9da0ba73623dd447e336facbfa0cd5993d9c184a3`；
data size 为 3,261,440 bytes，load/entry 均为 `0x40200000`。该修复仍需实板 ARP、ICMP
和数值地址 TCP 复验，不能仅凭构建通过判定物理 NIC 已完成。

## 2026-08-11：单播过滤、RTC、DNS 与 Git 分层验收

MCBCQEN 后，板端广播 ARP、TX completion 和主机邻居学习均成立，但 DWMAC packet filter
为 `0x400` 时，目的地址为 EEPROM MAC `6c:cf:39:00:7b:9c` 的普通单播仍不进入 RX。
曾尝试把主 MAC 寄存器改为 Linux/U-Boot 一致的 high-word-first 顺序；实板仍 3 发 0 收，
因此该顺序修正应保留，但不是单播故障的充分根因。前文把 slot 0 `AE` 描述为最终修复的
判断也被这轮物理 A/B 否定。

U-Boot EQoS core 在启动时设置 `MAC_PACKET_FILTER.PR`。PulseOS 采用相同板级策略，保持
底层驱动的精确过滤能力，但 VisionFive 2 wrapper 启用硬件全目的地址接收。smoltcp 在
ARP/IP 前丢弃目的 MAC 既非本机、广播或组播的帧，因此软件层继续提供目的地址隔离。
当前 filter 为 `0x481`。

候选 `/mnt/d/Tftpd64/kernel-vf2.uimg` 的 SHA-256 为
`c28c25d0f7270c1aae7112608ecd7eb185351e04f455fcf6b9ad2a9b72e76698`。同一镜像启动后，
WSL 与 Windows 分别对 `192.168.137.2` 完成 3 发 3 收，邻居项为上述 EEPROM MAC 且状态
`REACHABLE`。这闭合了主机到板端的普通 ARP、单播 RX、ICMP 处理和回复 TX。板端随后
从 `192.168.137.1:18080` 取得 `VF2_HOST_TCP_OK`，用 HTTP clone 本地 bare repository，
`git fsck --full` 完成且 README 内容匹配。公网 HTTPS Git 仍需单独记录，不能由本地 Git
代替。

同时参考 tgoskits 的 JH7110 RTC 和 rootfs resolver 处理，平台从 live FDT 解析 RTC MMIO，
兼容 `starfive,jh7110-rtc` 与旧 `starfive,rtc_hms`，用稳定 date/time/date 快照计算 wall-clock
offset；解码与时间选择测试 4/4 通过。公共 rootfs overlay 新增 `1.1.1.1`、`8.8.8.8`，隔离构建的
ext4 镜像可由 `debugfs` 读回。TFTP 只更新内核，不会修改已写入 SD 的空
`/etc/resolv.conf`，所以旧卡仍须单独更新，且 Windows ICS/NAT 仍是公网返回路径的主机侧
前提。

该版首次上板后 `date` 仍为 1970，证明“存在解码实现”不能替代实板时间证据。tgoskits 的
偏移和位域与本实现相同；进一步查阅 StarFive 勘误确认 JH7110 RTC 不在独立常供电域，整板
掉电后不能持久。现在平台保留并报告 RTC base、原始 time/date 和稳定性；RTC 无效或早于
本轮镜像时，使用 `VF2_BUILD_EPOCH` 建立启动墙钟下界。该下界解决 1970/2001 导致的 TLS
证书“尚未生效”，但精确时间仍应在联网后由 `clock_settime` 或 NTP 校准。

公网 Git 的另一条失败链与 RTC 无关。`git-remote-https` 发出 SYN 后报告
`getsockname() failed with errno 107`；此时 smoltcp 已分配本地端点并处于
`STATE_CONNECTING`，PulseOS 的 `local_addr` 状态白名单却漏掉该状态。修复将
`CONNECTING` 纳入查询范围并增加状态回归测试。新候选
`adfbb12caea964f25f5b30344b8d43b1a456be1be9264aaef740b2745c7f255d` 已通过实板复验：
`date` 为 2026-08-11，`nslookup github.com` 成功，本地主机 HTTPS Git `ls-remote` 返回
预期 HEAD/master 且退出码为 0，随后用户确认板端 GitHub clone 成功。最终公网运行没有保留
主机侧连接跟踪，因此该结果关闭应用层验收，但不区分直连 NAT 与 CONNECT 代理。

公网测试期间出现过 `first/probe TX stalled` 诊断；源码复核发现其时间戳来自最早提交，
而 ownership 检查可能已经指向后续 descriptor。最早提交已回收后，后续 slot 短暂繁忙会
造成假阳性。诊断逻辑现把“首次提交已经回收”作为终止状态，并增加回归测试；该日志不是
实际 Git 传输失败的根因。

主机侧捕获的 ruleset 还显示第三个独立问题：`FORWARD policy drop` 下的 ACCEPT 和
POSTROUTING MASQUERADE 都只匹配旧地址 `169.254.141.28`，当前板端地址
`192.168.137.2` 不匹配。到 `192.168.137.1` 的本地 HTTP/Git 不进入 FORWARD，因此其成功
不能证明公网 NAT；公网复验前必须同步主机规则中的板端地址。
