# VisionFive 2 NIC 实现与问题排查记录

本文整理 PulseOS 在 StarFive VisionFive 2 v1.3B（JH7110）上实现 GMAC0
网络设备支持的过程。重点不是只列最终代码，而是保留每个问题的现象、错误假设、
根因、修复和验证边界，便于后续继续完成物理收发验收。

本文只讨论 NIC。完整的平台、SMP、SD/MMC 和根文件系统移植过程见
[VisionFive 2 完整移植记录](visionfive2-porting-record.md)。日常构建和启动命令见
[VisionFive 2 Bring-Up](visionfive2.md)。

## 1. 目标与完成标准

目标是在 PulseOS 中把 VisionFive 2 的板载 GMAC0 注册为 `eth0`，并完成基本的
Ethernet、ARP、IPv4、ICMP 和 TCP 收发。

NIC 支持不能只用“驱动探测成功”或“`127.0.0.1` 能 ping”作为完成证据。完整验收需要：

1. `make test` 的 RISC-V64 和 LoongArch64 构建门禁通过；
2. `make visionfive2` 生成可由 U-Boot `bootm` 加载的 uImage；
3. 板端从 live FDT 识别 GMAC0、MAC 地址、PHY 和 PLIC IRQ；
4. DWMAC RX/TX descriptor 模拟测试通过；
5. 板端 `ping -c 3 127.0.0.1` 通过，证明软件回环路径可用；
6. 主机能够解析板端 ARP，并能与 `169.254.141.28` 双向传输数据；
7. 至少完成一次数值地址 TCP 请求，排除 DNS 对测试结论的干扰。

截至 2026-08-11，构建、隔离驱动测试、板端 loopback、物理 ARP、普通单播 ICMP、
数值地址 TCP、本地 HTTP/HTTPS Git 和公网 GitHub clone 均已闭合。`c28c25d0...` 候选由
WSL 和 Windows 分别完成 3 发 3 收；`adfbb12c...` 候选进一步闭合了可信启动时间、DNS、
非阻塞 `getsockname` 和 HTTPS Git。

## 2. 硬件与启动合同

当前实现只支持 GMAC0，关键资源来自 U-Boot 传入的 live FDT：

| 资源 | 当前板级值 | 用途 |
| --- | --- | --- |
| GMAC0 MMIO | `0x16030000`, size `0x10000` | DWMAC 5.20 MAC/MTL/DMA 寄存器 |
| macirq | PLIC source 7 | RX/TX DMA completion |
| AON CRG | `0x17000000`, size `0x10000` | GMAC0 AHB/AXI 时钟门和复位 |
| AON syscon | `0x17010000`, offset `0x0c` | RGMII/RMII interface select |
| PHY | FDT `phy-handle` 指向的 Clause 22 PHY | 当前板为 Motorcomm YT8531 |
| 主机地址 | `169.254.141.27` | 直连测试端 |
| 板端地址 | `169.254.141.28` | PulseOS 静态 IPv4 地址 |

构建和运行链路如下：

```text
make visionfive2
  -> MYPLAT=axplat-riscv64-visionfive2
  -> driver-starfive-jh7110-dwmac
  -> axdriver board wrapper
  -> axdriver_net DWMAC core
  -> axnet/smoltcp
  -> PulseOS socket syscall ABI
```

U-Boot 负责加载 legacy uImage，并把 boot hart ID 和 FDT 地址分别放在 `a0`、`a1`。
PulseOS 不使用静态复制的 DTB，因为 MAC 地址、PHY phandle、PLIC context 和可用 hart
信息都需要从本次固件传入的数据中获得。

## 3. 代码分层

### 3.1 构建与 feature

- 根 `Cargo.toml` 的 `visionfive2` feature 选择板级平台、DWMAC、SD/MMC、网络栈和 SMP。
- `Makefile` 的 `visionfive2` 目标使用独立的 `target/visionfive2` 输出目录，并生成
  `kernel-vf2.uimg`、`kernel-vf2` 和匹配 ELF。
- `arceos/modules/axdriver` 把 `starfive-jh7110-dwmac` 加入动态设备模型。

### 3.2 平台层

`crates/axplat-riscv64-visionfive2` 提供：

- live FDT 解析和动态 RAM/reserved-memory 范围；
- U74 hart 与 PLIC supervisor context 映射；
- GMAC0、AON CRG、AON syscon 的设备 MMIO 窗口；
- PLIC claim/complete 和设备 IRQ 注册；
- JH7110 CCACHE `flush64` DMA cache maintenance。

DMA cache maintenance 是实板必须项。QEMU VirtIO 路径不能覆盖 U74 非一致缓存问题，
因此“QEMU 网络正常”不能证明 DWMAC descriptor 在板上可见。

### 3.3 板级 DWMAC 包装层

`arceos/modules/axdriver/src/starfive_jh7110.rs` 负责：

- 从 live FDT 定位 GMAC0、macirq、MAC、PHY 和 `snps,axi-config`；
- 重新使能 AON AHB/AXI clock gate，并释放 GMAC0 AXI/AHB reset；
- 按 `starfive,syscon` 和 `phy-mode` 写 interface-select；
- 提供连续 DMA 页分配、物理地址转换和 cache flush；
- 注册 PLIC handler，并把 completion 唤醒接到 `axpoll`；
- 每 10 ms 有界轮询 descriptor ownership，覆盖第一次中断丢失；
- 每秒刷新一次 PHY link/speed/duplex；
- 输出首个 RX、首个 TX、首个 completion 和首个 abnormal status 诊断。

### 3.4 DWMAC 核心

`crates/axdriver_net/src/starfive_jh7110/` 实现：

- DWMAC 5.20 MAC、MTL 和 DMA channel 0；
- 一条 RX queue 和一条 TX queue；
- 40-bit DMA base/buffer address；
- 4-entry descriptor ring，但每条 ring 同时只向 DMA 暴露一个 descriptor；
- Clause 22 MDIO 和 YT8531 PHY status；
- primary MAC programming with hardware `PR` receive and smoltcp destination filtering；
- `snps,axi-config`、fixed burst、no-PBL-x8 和 threshold DMA mode；
- DWMAC soft reset 后恢复 JH7110 所需的 descriptor cache enable（DCHE）。

每次只给 DMA 一个 descriptor 是正确性策略。JH7110 当前只提供组合式
clean/invalidate 操作，而 4 个 16-byte descriptor 共享一条 64-byte cache line；若多个
descriptor 同时归 DMA 所有，CPU flush 其中一个时可能把同一 cache line 中的旧 OWN 状态
写回并覆盖 DMA 更新。

### 3.5 网络栈与 syscall

`axnet` 使用现有 smoltcp Ethernet interface。为支持 BusyBox `ping`，实现了 IPv4
`AF_INET/SOCK_RAW/IPPROTO_ICMP` 子集：

- 只接受 ICMP Echo request/reply；
- 按 Echo identifier 延迟绑定 smoltcp ICMP socket；
- 接入阻塞等待、超时、poll 和信号中断；
- 接收时补出 Linux raw IPv4 socket 预期的 20-byte IPv4 header。

其他 raw IP 协议及 IPv6 raw ICMP 仍返回不支持。这是有意限定的兼容范围，不等同于完整
Linux raw socket 实现。

## 4. 问题与解决过程

### 4.1 ext4 成功后出现 `No NIC device found`

现象：

```text
No NIC device found!
```

根因：最初 VisionFive 2 feature 为了先完成 SD/MMC，保留了 `net` 上层功能，但没有注册
任何 VF2 网络设备。`axnet` 启动时设备列表为空。

解决：新增 `starfive-jh7110-dwmac` feature，把 GMAC probe 接入 `axdriver` 动态设备列表，
并只在 VisionFive 2 feature 中启用，不影响 QEMU VirtIO NIC。

验证：板端日志识别 `GMAC0 at 0x16030000, IRQ 7`，并由 `axnet` 选择为 `eth0`。
这只证明控制面接入，不证明帧已经收发。

### 4.2 驱动探测成功，但主机 ping 仍 100% 丢包

现象：GMAC、MAC 地址和 `eth0` 均出现，主机仍不能解析 ARP。

ARP 位于 ICMP 和 DNS 之前；只要邻居表保持 `INCOMPLETE`，首先应检查物理 RX、MAC
filter、DMA descriptor 和 PHY/MAC interface，而不是修改 DNS。

解决方法是增加分层诊断：

- 记录 DMA mode、system-bus、channel control、current descriptor 和 tail；
- 记录 MAC config、filter、address slot 和 MTL queue mode；
- 记录第一帧进入 smoltcp、第一帧提交 DMA、第一次 completion 和异常状态；
- 在 IRQ 之外每 10 ms 检查 descriptor OWN。

| 日志 | 结论 |
| --- | --- |
| 没有 first RX | 问题在 PHY、MAC ingress、filter、DMA 或 cache |
| 有 first RX，没有 first TX | 帧已进协议栈，但没有产生响应 |
| RX/TX 都有，主机仍收不到 | 检查 TX completion、RGMII 和 host link |
| 出现 abnormal/FBE/RBU | 检查 DMA 地址、ownership、tail 和 cache |

### 4.3 PHY ID 作为硬门槛导致网络设备消失

现象：一版实现要求必须读到 YT8531 ID，否则 DWMAC 初始化返回 `Io`，随后 `axnet` 因没有
NIC 设备而失败。

根因：固件留下的 MDIO CSR clock selector 不一定能在 PulseOS 接管后的第一个读取窗口内
工作。PHY ID 不可读并不等于 MAC/DMA 不能启动。

解决：先读取固件留下的 MDIO CR，再扫描标准 CSR clock selector；无法确认 ID 时保留
警告而不让设备探测硬失败；周期读取 PHY status，延迟自协商完成后再更新 MAC。

### 4.4 DWMAC soft reset 清除了 StarFive descriptor cache 配置

现象：固件设置看似正确，但 DWMAC soft reset 后 DMA 仍不工作。

根因：StarFive 主线 glue 强制设置 `dma_cfg->dche = true`。soft reset 会清除
`DMA_MODE.DCHE`，不能依赖 U-Boot 留值。

解决：在 soft reset 完成后重新设置 DCHE，再配置 system-bus 和 descriptor base。

### 4.5 精确地址过滤仍丢弃普通单播

现象：广播 ARP 可进入 RX，板端 TX 也能使主机邻居项变为 `REACHABLE`，但 packet filter
为 `0x400` 时，主机发往 EEPROM MAC 的普通单播没有进入板端 RX。交换主 MAC high/low
寄存器写入顺序后实板结果不变，因此不能把寄存器顺序称为该故障的根因。

解决：保留 Linux/U-Boot 一致的 high-word-first 地址写入，但按 VisionFive 2 U-Boot EQoS
驱动启用 `PR`。当前寄存器值为 `0x481`；smoltcp 在 ARP/IP 处理前检查目的 MAC，丢弃既非
本机、广播或组播的帧，所以目的地址过滤从不可靠的硬件 perfect filter 下移到软件层。

### 4.6 PLIC completion 可能缺失

现象：descriptor 可能已由 DMA 回写，但没有观察到第一个 PLIC completion，网络 poller
随后睡眠。

解决：保留 PLIC 正常路径，同时请求 10 ms fallback polling，直接读取当前 RX 和上一 TX
descriptor 的 OWN 位。该方案适合 bring-up，但不是最终高性能设计。

### 4.7 PHY status `0x0000` 被误解为 10 Mbps

错误假设：速度位为零，所以应立即把 MAC 改为 10 Mbps 半双工。

源码核对：YT8531 status 还包含 link 和 speed-resolved 位。`0x0000` 表示链路未建立或状态
未解析，不能当作有效的 10 Mbps 协商结果。

解决：只有 link、resolved 同时置位且 speed code 有效时才更新 MAC；其他状态保留上一次
有效设置。

### 4.8 `ping 127.0.0.1` 报 raw socket 不支持

现象：

```text
PING 127.0.0.1 (127.0.0.1): 56 data bytes
ping: can't create raw socket: Protocol not supported
```

根因：smoltcp 已编译 ICMP socket，但 PulseOS `sys_socket` 对 `AF_INET/SOCK_RAW` 直接返回
`EPROTONOSUPPORT`。这是 Linux socket ABI 缺口，不是 DWMAC 失败。

解决：实现前述 IPv4 ICMP raw socket 子集，并补齐 BusyBox 期待的 IPv4 receive header。

QEMU 复验：

```text
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 1.148/5.054/8.513 ms
```

2026-08-09 的 VisionFive 2 板端复验：

```text
3 packets transmitted, 3 packets received, 0% packet loss
round-trip min/avg/max = 0.150/4.333/12.663 ms
```

两项都走软件 loopback，不经过 VirtIO 或 DWMAC，不能作为物理 NIC 证据。

### 4.9 `git clone` 报 `Could not resolve host`

根因边界：旧 rootfs 没有 `/etc/resolv.conf`，BusyBox 因而把查询发往 `127.0.0.1`。域名
解析失败首先证明 DNS 配置缺失，不能直接证明 GMAC 不收发。公共 rootfs overlay 现已加入
`1.1.1.1` 和 `8.8.8.8`；已写入 SD 卡的旧镜像仍需更新该文件。

正确顺序是先验证 ARP，再验证数值 IPv4 TCP，最后根据实际拓扑配置 resolver。DNS 成功后
才使用 `git clone` 作为更高层工作负载。

### 4.9.1 HTTPS Git 报 `getsockname() failed with errno 107`

实板已经发出到 GitHub 地址的 TCP SYN，但 Git/cURL 随即以 `ENOTCONN` 退出。源码链显示，
非阻塞 `connect` 已由 smoltcp 选择本地 IP 和临时端口，并把 PulseOS socket 置为
`CONNECTING`；`TcpSocket::local_addr` 却只允许 `CLOSED`、`CONNECTED` 和 `LISTENING`，遗漏
了此时合法的 `CONNECTING`。修复后 `getsockname` 可以在握手中返回已分配的本地端点，
不会在 TLS 之前提前终止。

这只修复 socket ABI。是否收到 SYN-ACK 仍取决于主机转发/NAT；证书验证还依赖可信墙钟，
两者都必须分开验收。

修复候选在板端访问主机临时 HTTPS Git 服务时，`ls-remote` 返回预期 HEAD 和
`refs/heads/master`，退出码为 0；随后用户确认同一板上可以完成 GitHub clone。因此
`ENOTCONN` 修复后的 Git/TLS 路径已经闭合。最终公网测试没有保留主机侧连接跟踪，不能据此
进一步断言它使用了直连 NAT 还是 CONNECT 代理。

### 4.9.2 JH7110 RTC 与 HTTPS 时间

tgoskits 的 JH7110 RTC 偏移和位域与 PulseOS 当前实现一致。实板仍从 1970 启动的原因不是
解码差异，而是 RTC 寄存器无效或停留在默认时间。StarFive 勘误明确指出该 RTC 不在独立
常供电域，不能跨整板掉电持久计时。PulseOS 现在记录原始 time/date；RTC 无效或早于当前
镜像时，以 `VF2_BUILD_EPOCH` 为启动墙钟下界，之后仍允许 `clock_settime`/NTP 校准。

该候选实板启动后，`date` 从此前的 1970 修正为 `Tue Aug 11 12:57:15 UTC 2026`，随后
`nslookup github.com` 成功。该结果证明 TLS 所需的时间和 resolver 前置条件已经补齐；它不把
构建时间下界描述成持久 RTC 或精确网络授时。

### 4.9.3 首帧 TX stall 诊断假阳性

首次/探测 TX 的时间戳属于最早提交的 descriptor，但后续诊断读取的是当前 descriptor。
最早提交已经回收后，后续流量短暂占用当前 slot，旧逻辑仍可能按最早时间戳输出
`first/probe TX stalled`。这不是对应首帧仍由 DMA 持有的证据，也不能解释成功的本地 HTTPS
传输。诊断状态现记录“已经回收”；一旦首次提交完成，后续流量不再把它重新分类为 stall，
并有回归测试覆盖该状态转换。

### 4.10 U-Boot TFTP 成功，PulseOS 接管后 GMAC 仍被 SoC reset

现象：U-Boot 能通过 GMAC0 下载内核，但 `bootm` 后 PulseOS 没有物理帧。

根因：U-Boot `eqos_stop()` 在 TFTP 完成后关闭 MAC/DMA，并调用 StarFive reset hook
assert GMAC0 AXI/AHB reset。PulseOS 原实现只执行 DWMAC 内部 soft reset，没有先释放
AON CRG 的 SoC reset。

解决：验证 live FDT 中的 AON CRG，重新使能 AHB/AXI gate，清除 reset bits 0、1，并轮询
reset-status 后再访问 DWMAC；同时记录 reset 前后状态。

源码核对还否定了一个错误假设：YT8531 使用的 U-Boot `genphy_shutdown()` 是空操作，
`eth_halt()` 没有把 PHY 写入 BMCR power-down，因此不应加入没有证据的 PHY power-cycle。

### 4.11 最新失败：ARP 广播没有进入 RX queue 0

2026-08-10，板端 loopback 通过后，主机测试：

```text
5 packets transmitted, 0 received, 100% packet loss
169.254.141.28 ... INCOMPLETE
```

主机接口为 `LOWER_UP` 且已发出邻居探测，但没有收到 ARP response。

对照 U-Boot 和 Linux 初始化发现，PulseOS 已设置 `GMAC_RXQ_CTRL0.RXQ0EN`，却遗漏
`GMAC_RXQ_CTRL1.MCBCQEN`。U-Boot 会显式打开 multicast/broadcast queue routing；ARP
request 是广播帧，因此该遗漏与“没有 first RX、ARP 一直 INCOMPLETE”直接相关。

当前修复：

- 新增 `GMAC_RXQ_CTRL1` 和 MC/BC queue 位定义；
- 清空 MC/BC queue selection，选择 queue 0 并设置 `MCBCQEN`；
- 把 RXQ1 加入启动诊断；
- 扩展 MAC 配置单元测试。

状态边界：该修复已通过隔离单元测试、双架构构建和 VisionFive 2 专用构建，但尚未完成
实板复验，不能写成已经解决物理 ARP。

## 5. 测试设计与已有结果

### 5.1 隔离驱动测试

根 workspace 缺少 `crates/axdriver_display/Cargo.toml`，直接执行 `cargo test -p axnet
--lib` 会在解析依赖阶段失败。为避免修改无关 workspace，把当前 `axdriver_net` 和
`axdriver_base` 复制到临时目录并声明独立 workspace：

```bash
cargo test --manifest-path axdriver_net/Cargo.toml \
  --features starfive-jh7110-dwmac --lib
```

当前源码的 descriptor、AXI、MAC filter/MCBC queue routing、PHY、polling、诊断寄存器、
RX payload 和 TX payload 共 22 项测试通过，0 项失败；RTC 解码和启动时间选择另有 4 项
纯逻辑测试通过。

### 5.2 构建门禁

```bash
set -o pipefail
make test 2>&1 | tail -30
make visionfive2 2>&1 | tail -30
git diff --check
```

2026-08-10，最新 MCBCQEN 增量已通过双架构 `make test`、`make visionfive2`、
`rustfmt --check` 和 `git diff --check`。

2026-08-11，包含 DNS、RTC/build-time 下界、`getsockname` 和 TX stall 诊断修正的当前源码
再次通过同一双架构 `make test`、`make visionfive2`、目标 Rust 文件 `rustfmt --check` 和
`git diff --check`。

### 5.3 证据边界

软件回环只验证：

```text
BusyBox ping -> raw ICMP syscall -> smoltcp -> loopback route -> recv wakeup
```

物理验收必须覆盖：

```text
host eth1 -> cable/PHY -> GMAC filter/RX queue -> RX DMA/cache
  -> smoltcp ARP/IPv4 -> TX DMA/cache -> GMAC/PHY -> host eth1
```

## 6. 当前上板验收

已完成物理 ARP、ICMP、数值 TCP 和本地 Git 验收的基线为：

```text
SHA-256 c28c25d0f7270c1aae7112608ecd7eb185351e04f455fcf6b9ad2a9b72e76698
data size 3269632 bytes, load/entry 0x40200000
```

完成最终网络验收的 TFTP 候选为：

```text
/mnt/d/Tftpd64/kernel-vf2.uimg
SHA-256 adfbb12caea964f25f5b30344b8d43b1a456be1be9264aaef740b2745c7f255d
data size 3269632 bytes, load/entry 0x40200000
```

TX stall 诊断修正后的仓库根目录构建产物 SHA-256 为
`1f77b58722873c2de72d362db258fb360994411fc861a30a682a103162474270`。该产物通过专用构建，
但未复制到 TFTP 目录、也未重新上板；实板功能结论仍对应上面的 `adfbb12c...`，后续不能把
两个哈希写成同一轮物理证据。

U-Boot：

```console
tftpboot ${loadaddr} kernel-vf2.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

板端：

```console
ping -c 3 192.168.137.1
busybox ifconfig eth0
git clone http://192.168.137.1:18080/repo-483e7b80.git /tmp/vf2-clone
git -c http.sslVerify=false ls-remote \
  https://192.168.137.1:18443/repo-483e7b80.git
git clone https://github.com/muou000/test /tmp/vf2-github
```

主机：

```bash
ping -I eth1 -c 3 -W 1 192.168.137.2
ip -s neigh show dev eth1
```

验收时保存 uImage SHA-256、GMAC/AON/PHY/DMA 启动日志、`ifconfig eth0`、first RX/TX、
completion/abnormal，以及主机 ARP/ICMP/TCP 输出。

物理 ARP/ICMP、数值 TCP、本地 HTTP/HTTPS Git 均已通过；用户随后确认板端 GitHub clone
成功。后续回归应继续按数值 TCP、DNS、Windows ICS/NAT、HTTPS 时间和 Git 分层，不再回退
为“DWMAC 完全不收包”的结论。

较早采集的 WSL ruleset 只允许旧板端地址 `169.254.141.28`，而当前镜像使用
`192.168.137.2`；`FORWARD` 默认策略为 drop。公网测试前必须让 ACCEPT/MASQUERADE 规则
与当前板端地址一致。本地 `192.168.137.1:18080` 成功不会经过转发链，不能替代该检查。
最终 GitHub clone 已由用户确认，但没有保留该次主机侧连接跟踪，因此这里只关闭应用层验收，
不把最终路径进一步归因为直连 NAT 或 CONNECT 代理。

## 7. 参考源码

- [Linux JH7110 device tree](https://github.com/torvalds/linux/blob/master/arch/riscv/boot/dts/starfive/jh7110.dtsi)
- [Linux StarFive DWMAC glue](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac-starfive.c)
- [Linux DWMAC4 DMA](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_dma.c)
- [Linux DWMAC4 core](https://github.com/torvalds/linux/blob/master/drivers/net/ethernet/stmicro/stmmac/dwmac4_core.c)
- [Linux Motorcomm PHY](https://github.com/torvalds/linux/blob/master/drivers/net/phy/motorcomm.c)
- [U-Boot StarFive EQoS glue](https://github.com/u-boot/u-boot/blob/master/drivers/net/dwc_eth_qos_starfive.c)
- [U-Boot EQoS core](https://github.com/u-boot/u-boot/blob/master/drivers/net/dwc_eth_qos.c)
- [U-Boot JH7110 reset controller](https://github.com/u-boot/u-boot/blob/master/drivers/reset/reset-jh7110.c)
- [StarFive JH7110 errata](https://doc-en.rvspace.org/JH7110/PDF/JH7110_Errata.pdf)

## 8. 当前结论

PulseOS 已具备 VisionFive 2 GMAC0 的平台注册、DWMAC 5.20 基础驱动、DMA cache
maintenance、PLIC/poll completion、PHY 状态跟踪、MCBCQ 路由和软件目的 MAC 过滤。
`c28c25d0...` 候选的物理 ARP、普通单播 ICMP、板端数值 TCP、本地 Git clone、object fsck
和工作树读取已通过。DNS overlay、RTC/build-time 下界和 `CONNECTING` 状态的
`getsockname` 已实现；`adfbb12c...` 候选进一步通过实板时间、DNS、本地 HTTPS Git，且用户
已确认 GitHub clone 成功。由此本轮“板端无法 git clone”的功能问题已经闭合；主机最终采用
直连 NAT 还是 CONNECT 代理未由留存日志区分，不能把这个未归因的拓扑细节重新归因给已经
闭合的 DWMAC、socket ABI 或 TLS 路径。
