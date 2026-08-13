# PulseOS VisionFive 2 新机器复现配置报告

本文说明如何在一台全新开发机上复现 PulseOS 的 VisionFive 2（JH7110）启动、
物理网络和 GitHub clone。目标不是只让内核完成编译，而是按可定位的顺序闭合：

```text
源码快照 -> 工具链 -> ext4 根文件系统 -> TFTP/串口 -> ARP/数值 TCP
         -> DNS/时间 -> 本地 HTTP/HTTPS Git -> GitHub clone
```

本文记录的实板验收日期为 2026-08-11。完整驱动因果链见
[VisionFive 2 NIC 实现记录](visionfive2-nic-implementation.md)，平台启动合同见
[VisionFive 2 Bring-Up](visionfive2.md)。

## 1. 复现结论和证据边界

### 1.1 已验收配置

| 项目 | 已验收值 |
| --- | --- |
| 开发板 | VisionFive 2 v1.3B，JH7110 |
| 固件 | 板上已有 OpenSBI/U-Boot，内核由 TFTP 一次性加载 |
| 主机系统 | Ubuntu 24.04.4 LTS，实测环境为 WSL2；原生 Linux 更容易复现路由 |
| Rust | `rustc 1.99.0-nightly (9f36de775 2026-07-19)` |
| Cargo | `cargo 1.99.0-nightly (3efb1f477 2026-07-17)` |
| U-Boot tools | `mkimage 2025.10` |
| 主机板端接口 | `192.168.137.1/24` |
| PulseOS 地址 | `192.168.137.2/24` |
| PulseOS 网关 | `192.168.137.1` |
| 板端 MAC | `6c:cf:39:00:7b:9c`，实际值仍应以 EEPROM/FDT 日志为准 |
| uImage load/entry | `0x40200000` / `0x40200000` |
| 已验收 uImage SHA-256 | `adfbb12caea964f25f5b30344b8d43b1a456be1be9264aaef740b2745c7f255d` |
| uImage 总大小 | 3,269,696 bytes，payload 3,269,632 bytes |
| 主机基础 rootfs SHA-256 | `d74e436522f5946ca17280a7a25f17dbb6604b71fe675bb8a021ce8e849b334c` |
| 根文件系统大小 | 15,032,385,536 bytes，未分区的 ext4 文件系统 |

已验收 uImage 的构建时间下界为 Unix epoch `1786453035`，即
`2026-08-11 12:57:15 UTC`。当前源码在修正 TX stall 诊断后还构建过
`1f77b587...` 镜像，但该镜像没有再次上板；不能把它与
`adfbb12c...` 的实板证据合并。

最后一次 GitHub clone 已由用户在实板确认，但没有保留对应主机连接跟踪。因此它证明
PulseOS 的应用层 Git 路径可用，不足以单独区分当时走的是主机直连 NAT 还是显式 CONNECT
代理。本文同时给出这两种可复现配置。

rootfs 哈希只标识写卡前的主机基础镜像。板端修改 `/etc/resolv.conf`、Git worktree 或任何
文件后，microSD 全盘哈希都会变化，不能再要求它等于上述输入哈希。

### 1.2 四级验收

| 级别 | 完成标准 | 不能替代它的证据 |
| --- | --- | --- |
| L1 构建 | `make test` 与 `make visionfive2` 通过 | QEMU 启动 |
| L2 板级启动 | 串口进入 shell，SD/ext4 挂载成功 | uImage 生成成功 |
| L3 物理网络 | 普通 ARP、单播和数值地址 TCP 成功 | `127.0.0.1`、强制广播或 TFTP |
| L4 GitHub | DNS、时间、CA、HTTPS 和 Git clone 全部成功 | 本地 HTTP Git |

## 2. 第 0 步：先发布可克隆的源码快照

这是当前最重要的复现前提。撰写本文时，仓库基线 HEAD 为
`0821bb12f5d1012398a66aed254e601a8ea6699b`，但 VisionFive 2 平台、DWMAC 和相关
修复仍位于脏工作区，其中多个关键目录尚未被 Git 跟踪。只在新机器 clone 当前远端 HEAD
不会得到已验收实现。

在旧机器上应先完成一次人工审查并把本轮 VF2 代码形成 commit/tag。不要直接执行
`git add -A`，因为当前工作区还有与 VF2 无关的改动。至少确认以下类别已经进入目标快照：

- 根 `Cargo.toml`、`Cargo.lock`、`Makefile` 和 VisionFive 2 feature；
- `crates/axplat-riscv64-visionfive2/`；
- `crates/axdriver_net/src/starfive_jh7110/`；
- `arceos/modules/axdriver/src/starfive_jh7110.rs` 及驱动注册；
- `axnet`/`smoltcp` 的物理接口、ICMP、过滤和 `getsockname` 修复；
- `rootfs/overlay/common/etc/resolv.conf`；
- 本文及其他 `docs/visionfive2*.md`。

旧机器发布前记录：

```bash
git rev-parse HEAD
git status --short
git diff --check
sha256sum Cargo.lock
```

新机器必须检出发布后的 commit 或 tag，而不是上面的脏工作区基线：

```bash
git clone https://github.com/muou000/PulseOS
cd PulseOS
git switch --detach <VF2_COMMIT_OR_TAG>
git status --short
git rev-parse HEAD
```

`git status --short` 应为空。不要复制旧机器的 `.git/config`，也不要把含访问令牌的 remote
URL 写入报告、日志或源码压缩包；新机器只配置无凭据仓库 URL，并通过 credential helper
提供认证。

## 3. 硬件和布线

准备以下硬件：

- VisionFive 2 v1.3B；
- 一张专用于 PulseOS 根文件系统的 microSD 卡；
- 3.3 V TTL 串口转接器；
- 一条连接开发机专用以太网口和开发板 GMAC0 的网线；
- 已能进入 U-Boot 的 SPI/OpenSBI/U-Boot 固件。

串口只连接 `GND`、交叉的 `TX/RX`，不要连接转接器的 5 V 引脚。Linux 下优先使用稳定路径：

```bash
ls -l /dev/serial/by-id/
picocom -b 115200 --flow n /dev/serial/by-id/<SERIAL_ADAPTER>
```

也可以使用：

```bash
TERM=xterm minicom -D /dev/ttyUSB0 -b 115200
```

若串口设备属于 `dialout` 组，应把当前用户加入该组并重新登录。串口能打开只证明主机设备
可用，必须实际看到 U-Boot 输出才能证明 TX/RX/GND 接线正确。

## 4. 开发机软件环境

以下以 Ubuntu 24.04 为例：

```bash
sudo apt update
sudo apt install -y \
  build-essential git curl ca-certificates make pkg-config \
  u-boot-tools e2fsprogs xz-utils zstd perl \
  tftpd-hpa picocom minicom \
  iproute2 iptables nftables ethtool \
  iputils-ping iputils-arping tcpdump \
  openssl python3
```

仓库当前没有 `rust-toolchain.toml`，因此新机器必须显式固定工具链：

```bash
rustup toolchain install nightly-2026-07-19 --profile minimal
rustup component add --toolchain nightly-2026-07-19 \
  rust-src llvm-tools-preview rustfmt
rustup target add --toolchain nightly-2026-07-19 \
  riscv64gc-unknown-none-elf \
  loongarch64-unknown-none-softfloat
rustup override set nightly-2026-07-19

rustc -Vv
cargo -V
mkimage -V
```

`llvm-tools-preview` 是必须项，仓库的 `bin/rust-objcopy` 和 `bin/rust-objdump` 会从当前
Rust sysroot 查找这些工具。预期至少看到：

```text
rustc 1.99.0-nightly (9f36de775 2026-07-19)
cargo 1.99.0-nightly (3efb1f477 2026-07-17)
```

## 5. 根文件系统

### 5.1 GitHub 验收推荐输入

GitHub clone 复现应使用已包含 Git、HTTPS remote helper 和 CA bundle 的
`sdcard-rv-pub.img`。该 14 GiB 镜像被 `*.img` 规则忽略，不在 Git 仓库中，必须作为独立
构建产物传到新机器，并先核对：

```bash
sha256sum sdcard-rv-pub.img
stat -c '%n %s bytes' sdcard-rv-pub.img
file sdcard-rv-pub.img
debugfs -R 'stat /usr/bin/git' sdcard-rv-pub.img
debugfs -R 'stat /etc/ssl/certs/ca-certificates.crt' sdcard-rv-pub.img
debugfs -R 'cat /etc/resolv.conf' sdcard-rv-pub.img
```

已验收主机副本的 `/etc/resolv.conf` 仍为 QEMU 的 `nameserver 10.0.2.3`。它不适用于
VisionFive 2 直连网络，因此写卡后必须在板端替换为：

```text
nameserver 1.1.1.1
nameserver 8.8.8.8
```

### 5.2 写入 microSD

> 警告：以下操作会覆盖整张目标盘的分区表和数据。必须用 `lsblk` 逐项核对容量、型号、
> 传输总线和挂载点；绝不能把系统盘、仓库目录或不确定的设备作为目标。

先只读确认设备：

```bash
lsblk -o NAME,SIZE,MODEL,SERIAL,TRAN,MOUNTPOINTS
```

手工卸载该卡上由 `lsblk` 列出的所有分区。确认目标后，把
`<CONFIRMED_MICROSD_DEVICE>` 替换成整盘设备，例如经人工确认的 `/dev/sdb`：

```bash
sudo dd if=sdcard-rv-pub.img \
  of=<CONFIRMED_MICROSD_DEVICE> \
  bs=4M iflag=fullblock status=progress conv=fsync
sync
```

Windows/WSL 环境更适合在 Windows 中使用 Rufus、balenaEtcher 或同类 raw image 工具写卡。
不要把 ext4 镜像写到某个分区；PulseOS 当前从整盘 block 0 识别 ext4。

### 5.3 仓库脚本生成的最小镜像

以下命令已经在当前源码验证，生成的 ext4 包含 `1.1.1.1` 和 `8.8.8.8`：

```bash
OUTPUT_DIR=target/vf2-rootfs IMG_SIZE=128M ./build_img.sh riscv64
debugfs -R 'cat /etc/resolv.conf' \
  target/vf2-rootfs/rootfs-riscv64.img
```

但当前 `rootfs/base`、`overlay` 和 `extras` 组合生成的最小镜像没有 `/usr/bin/git`。
它适合验证 SD/ext4 启动，不足以完成 GitHub clone。除非已经把 Git、remote-https、其动态库
依赖和 CA bundle 纳入 rootfs 输入，否则不要用它替代 `sdcard-rv-pub.img` 的 Git 验收。

## 6. 构建内核

先执行仓库规定的双架构门禁：

```bash
set -o pipefail
make test 2>&1 | tail -30
```

再构建与本文网络拓扑匹配的 VisionFive 2 内核：

```bash
SOURCE_DATE_EPOCH=1786453035 \
make visionfive2 \
  VF2_IP=192.168.137.2 \
  VF2_GW=192.168.137.1 \
  VF2_SMP=4 \
  VF2_BUILD_EPOCH=1786453035
```

`VF2_BUILD_EPOCH` 是 JH7110 RTC 无效时的墙钟下界，不能代替 NTP 精确授时。
`SOURCE_DATE_EPOCH` 固定 uImage header 时间；即使如此，源码快照、Rust、Cargo、依赖、
构建路径或工具版本不同仍可能改变二进制，因此不要只追求历史哈希。

检查产物：

```bash
mkimage -l kernel-vf2.uimg
sha256sum \
  kernel-vf2.uimg \
  kernel-vf2 \
  PulseOS_riscv64-visionfive2.elf
```

预期 `mkimage -l` 显示：

```text
Image Type:   RISC-V Linux Kernel Image (uncompressed)
Load Address: 40200000
Entry Point:  40200000
```

构建生成：

- `kernel-vf2.uimg`：供 U-Boot `bootm`；
- `kernel-vf2`：flat binary；
- `PulseOS_riscv64-visionfive2.elf`：与本轮内核匹配的调试 ELF。

## 7. 配置 TFTP

### 7.1 Linux

确认 `/etc/default/tftpd-hpa` 使用独立目录，例如：

```text
TFTP_USERNAME="tftp"
TFTP_DIRECTORY="/srv/tftp"
TFTP_ADDRESS="0.0.0.0:69"
TFTP_OPTIONS="--secure"
```

部署并启动：

```bash
sudo install -d -m 0755 /srv/tftp
sudo install -m 0644 kernel-vf2.uimg /srv/tftp/kernel-vf2.uimg
sudo systemctl restart tftpd-hpa
sudo systemctl status --no-pager tftpd-hpa
sudo ss -lunp | grep ':69'
sha256sum kernel-vf2.uimg /srv/tftp/kernel-vf2.uimg
```

若主机防火墙默认拒绝入站，应只在连接开发板的接口上允许 TFTP。TFTP 首包使用 UDP 69，
后续数据端口由服务端分配，因此应使用带连接跟踪的 TFTP 防火墙规则或按 `tftpd-hpa` 的固定
端口配置放行，而不是只凭“UDP 69 已监听”判定传输一定可用。

### 7.2 Windows/WSL

已验收环境使用 Windows Tftpd64，TFTP root 为 `D:\Tftpd64`，WSL 对应
`/mnt/d/Tftpd64`。Tftpd64 中必须：

1. 选择地址为 `192.168.137.1` 的板端网卡；
2. 把 Current Directory 指向真正包含 `kernel-vf2.uimg` 的目录；
3. 在 Windows Defender Firewall 中允许 Tftpd64 的专用网络入站；
4. 比较 WSL 构建产物与 Windows TFTP 副本 SHA-256。

不要因为 WSL 内没有 UDP 69 listener 就判断 Tftpd64 未启动；它是 Windows 进程，应在
Windows 侧检查。

## 8. 配置主机直连网络和 NAT

### 8.1 原生 Linux 推荐配置

先识别接口，不要沿用旧机器的 `eth0`/`eth1` 名称：

```bash
ip -br link
ip -br addr
ip route show
```

以下示例要求用户明确填写：

```bash
VF2_IF=<DEDICATED_BOARD_ETHERNET_INTERFACE>
UPLINK_IF=<INTERNET_UPLINK_INTERFACE>
VF2_HOST_IP=192.168.137.1
VF2_BOARD_IP=192.168.137.2
```

确认 `192.168.137.0/24` 不与 VPN、公司网络或 Docker 网络冲突，然后配置：

```bash
sudo ip link set dev "$VF2_IF" up
sudo ip addr replace "$VF2_HOST_IP/24" dev "$VF2_IF"
sudo sysctl -w net.ipv4.ip_forward=1

ip -br addr show dev "$VF2_IF"
ip route get 1.1.1.1
```

当前 Ubuntu 使用 `iptables-nft` 时，应继续使用 `iptables` 命令管理对应规则，不要同时手工
修改它标记为 managed 的 nft table。以下规则严格限制到板端接口和 `192.168.137.2/32`：

```bash
sudo iptables -C INPUT \
  -i "$VF2_IF" -s "$VF2_BOARD_IP/32" -j ACCEPT 2>/dev/null ||
sudo iptables -I INPUT 1 \
  -i "$VF2_IF" -s "$VF2_BOARD_IP/32" -j ACCEPT

sudo iptables -C FORWARD \
  -i "$VF2_IF" -o "$UPLINK_IF" -s "$VF2_BOARD_IP/32" \
  -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
sudo iptables -I FORWARD 1 \
  -i "$VF2_IF" -o "$UPLINK_IF" -s "$VF2_BOARD_IP/32" \
  -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT

sudo iptables -C FORWARD \
  -i "$UPLINK_IF" -o "$VF2_IF" -d "$VF2_BOARD_IP/32" \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null ||
sudo iptables -I FORWARD 1 \
  -i "$UPLINK_IF" -o "$VF2_IF" -d "$VF2_BOARD_IP/32" \
  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

sudo iptables -t nat -C POSTROUTING \
  -s "$VF2_BOARD_IP/32" -o "$UPLINK_IF" -j MASQUERADE 2>/dev/null ||
sudo iptables -t nat -I POSTROUTING 1 \
  -s "$VF2_BOARD_IP/32" -o "$UPLINK_IF" -j MASQUERADE
```

核对规则实际匹配当前地址，而不是旧的 `169.254.141.28`：

```bash
sudo iptables -S INPUT
sudo iptables -S FORWARD
sudo iptables -t nat -S POSTROUTING
sudo nft list ruleset
```

这些命令默认是临时配置，重启后是否保留取决于发行版的 firewall manager。先完成本轮验收，
再使用 NetworkManager、systemd-networkd 和发行版支持的持久化机制保存；不要在不知道现有
firewalld/ufw/Docker 规则所有权时直接覆盖完整 ruleset。

### 8.2 Windows ICS/WSL

Windows 上可把有公网连接的 Wi-Fi/以太网适配器通过“Internet Connection Sharing”共享给
连接 VisionFive 2 的专用网口。ICS 通常把共享网口设置为 `192.168.137.1/24`，与本文内核
参数一致。完成后在 PowerShell 检查：

```powershell
Get-NetAdapter
Get-NetIPAddress -AddressFamily IPv4
Get-NetConnectionProfile
```

如果 WSL `ip -br addr` 能看到拥有 `192.168.137.1/24` 的板端接口，才在 WSL 中把它作为
`VF2_IF`。若该物理口只由 Windows 管理，则 TFTP、防火墙、ICS 和抓包都应在 Windows 侧
完成，不能用 WSL 内另一张同名接口替代。

ICS、WSL mirrored networking、Docker 和代理软件都可能重建规则。每次
`wsl --shutdown`、Windows 重启或切换网络后，都要重新检查地址、forward policy 和 NAT
计数器。

### 8.3 Mihomo/Clash fake-IP

如果板端执行 `nslookup github.com` 得到 `198.18.0.0/15` 地址，它不是 GitHub 的固定公网
地址，而是代理软件的 fake-IP。此时有三种选择：

1. 让 Mihomo TUN 正确接管并转发来自板端 `192.168.137.2` 的流量；
2. 在代理配置中让 GitHub/DNS 对板端返回真实地址；
3. 使用显式 HTTP CONNECT 代理。

不要把一次查询得到的 GitHub IP 固定写入 `/etc/hosts`。GitHub 地址会变化，并且该做法
绕过不了 TLS SNI、代理和返回路由问题。

显式代理可使用主机上的 tinyproxy。其关键配置应限制监听和来源：

```bash
sudo apt install -y tinyproxy
```

```text
Listen 192.168.137.1
Port 8888
Allow 192.168.137.2
ConnectPort 443
```

重启并确认只在板端地址监听：

```bash
sudo systemctl restart tinyproxy
sudo systemctl status --no-pager tinyproxy
ss -ltn | grep '192.168.137.1:8888'
```

板端只对本次 Git 使用代理：

```console
git -c http.proxy=http://192.168.137.1:8888 \
  clone https://github.com/muou000/test /tmp/vf2-github
```

不要为本地 `192.168.137.1` HTTP/HTTPS 分层测试设置该代理，也不要为了临时诊断永久关闭
TLS 验证。

## 9. U-Boot 启动

在串口 U-Boot 中执行一次性命令，不要在 bring-up 阶段 `saveenv`：

```console
setenv serverip 192.168.137.1
setenv ipaddr 192.168.137.2
printenv serverip ipaddr loadaddr fdtcontroladdr
ping $serverip

mmc dev 1
mmc rescan
tftpboot ${loadaddr} kernel-vf2.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

`mmc dev 1`/`mmc rescan` 是当前固件交接合同的一部分：PulseOS 会重置 SDIO1/DW MMC，
但仍复用 U-Boot 准备的 clock tree、pinmux 和 regulator。`bootm` 负责把 boot hart ID 和
`fdtcontroladdr` 按 RISC-V 固件 ABI 传给内核；不要改用 `go`，`booti` 也不适用于当前
legacy uImage。

TFTP 只替换内核，不会更新 microSD 上的 `/etc/resolv.conf`、Git、CA 或其他用户态文件。

## 10. 板端首次配置

进入 PulseOS shell 后先检查文件系统、接口和时间：

```console
mount
df -h /
busybox ifconfig eth0
date
cat /etc/resolv.conf
git --version
git --exec-path
test -x "$(git --exec-path)/git-remote-https"
```

若使用已验收的 `sdcard-rv-pub.img`，更新 resolver：

```console
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
sync
cat /etc/resolv.conf
```

预期 `eth0` 为 `192.168.137.2/24`，网关日志指向 `192.168.137.1`。`date` 不应停留在
1970；JH7110 RTC 掉电后不持久，PulseOS 会用构建 epoch 作为下界。

## 11. 分层网络验收

以下主机命令可能运行在不同终端。每个新终端都应重新明确设置 `VF2_IF`、
`VF2_HOST_IP` 和 `VF2_BOARD_IP`，不要依赖另一个 shell 中未导出的变量。

### 11.1 ARP 和普通单播

主机终端 1：

```bash
sudo tcpdump -U -ni "$VF2_IF" -e -vv \
  'arp or host 192.168.137.2'
```

主机终端 2：

```bash
ping -I "$VF2_IF" -c 3 -W 1 192.168.137.2
ip neigh show dev "$VF2_IF" 192.168.137.2
```

成功标准是普通 ARP 解析到板端 EEPROM MAC，并收到普通单播回复。强制广播、`127.0.0.1`
或仅看到“first TX submitted”都不能替代这一步。完成后用 Ctrl-C 停止 `tcpdump`，再检查
pcap；捕获进程未关闭时的 0-byte 文件不能作为无流量证据。

### 11.2 数值地址 TCP

主机：

```bash
VF2_HTTP_ROOT=$(mktemp -d /tmp/vf2-http-XXXXXX)
printf 'VF2_HOST_TCP_OK\n' > "$VF2_HTTP_ROOT/index.html"
python3 -m http.server 18080 \
  --bind 192.168.137.1 \
  --directory "$VF2_HTTP_ROOT"
```

板端：

```console
busybox timeout 10 wget -qO- http://192.168.137.1:18080/
```

预期输出 `VF2_HOST_TCP_OK`。如果这一步失败，先排查 ARP、主机 INPUT firewall、DWMAC
RX/TX 和 TCP，不要继续到 DNS 或 GitHub。完成后用 Ctrl-C 停止这个临时 HTTP server，
避免与下一节的 18080 端口冲突。

### 11.3 本地 HTTP Git

主机另开终端，准备一个 dumb HTTP bare repository：

```bash
VF2_GIT_WORK=$(mktemp -d /tmp/vf2-git-work-XXXXXX)
mkdir -p /tmp/vf2-http
git -C "$VF2_GIT_WORK" init
git -C "$VF2_GIT_WORK" config user.name vf2-repro
git -C "$VF2_GIT_WORK" config user.email vf2-repro@example.invalid
printf 'VF2_HOST_TCP_OK\n' > "$VF2_GIT_WORK/README"
git -C "$VF2_GIT_WORK" add README
git -C "$VF2_GIT_WORK" commit -m init
git clone --bare "$VF2_GIT_WORK" /tmp/vf2-http/repo-vf2.git
git --git-dir=/tmp/vf2-http/repo-vf2.git update-server-info
python3 -m http.server 18080 \
  --bind 192.168.137.1 \
  --directory /tmp/vf2-http
```

板端：

```console
busybox timeout 30 git clone \
  http://192.168.137.1:18080/repo-vf2.git /tmp/repo-vf2
git -C /tmp/repo-vf2 fsck --full
cat /tmp/repo-vf2/README
```

该步骤闭合物理 NIC、TCP、进程执行和 Git object/worktree，但不证明 DNS、TLS 或公网 NAT。

### 11.4 本地 HTTPS Git

保留上一节的 `/tmp/vf2-http/repo-vf2.git`，另开主机终端生成只用于本地诊断的临时证书：

```bash
VF2_TLS_DIR=$(mktemp -d /tmp/vf2-tls-XXXXXX)
export VF2_TLS_DIR

openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
  -keyout "$VF2_TLS_DIR/key.pem" \
  -out "$VF2_TLS_DIR/cert.pem" \
  -subj '/CN=192.168.137.1' \
  -addext 'subjectAltName=IP:192.168.137.1'

python3 - <<'PY'
import http.server
import os
import ssl

server = http.server.ThreadingHTTPServer(
    ("192.168.137.1", 18443),
    lambda *args, **kwargs: http.server.SimpleHTTPRequestHandler(
        *args, directory="/tmp/vf2-http", **kwargs
    ),
)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(
    os.path.join(os.environ["VF2_TLS_DIR"], "cert.pem"),
    os.path.join(os.environ["VF2_TLS_DIR"], "key.pem"),
)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
PY
```

板端：

```console
busybox timeout 30 git -c http.sslVerify=false ls-remote \
  https://192.168.137.1:18443/repo-vf2.git
```

预期返回 HEAD 和分支 ref，退出码为 0。这里只因为证书是本轮临时自签名证书才关闭验证；
该选项绝不能带到 GitHub。此步骤成功可单独证明 Git remote-https、TLS 和物理 TCP 路径，
不依赖公网 DNS、NAT 或代理。测试结束后用 Ctrl-C 停止 HTTPS server。

### 11.5 DNS 和墙钟

板端：

```console
date
nslookup github.com
getent hosts github.com
```

判读：

- `connection timed out; no servers could be reached`：先检查 resolver 和 UDP/53 NAT；
- 目标为 `127.0.0.1`：旧 rootfs 的 resolver 配置仍未修正；
- 返回 `198.18.x.x`：进入前述 Mihomo fake-IP 分支；
- 时间为 1970：重新检查 `VF2_BUILD_EPOCH`，不要关闭公网 TLS 验证绕过它。

### 11.6 GitHub

先做低开销的 HTTPS/Git 握手：

```console
busybox timeout 30 git ls-remote \
  https://github.com/muou000/test
```

再执行完整 clone：

```console
busybox timeout 120 git clone \
  https://github.com/muou000/test /tmp/vf2-github
git -C /tmp/vf2-github fsck --full
```

公网 GitHub 不应使用 `http.sslVerify=false`。如果直连 NAT 在当前网络被代理策略阻断，可按
8.3 节使用一次性 `http.proxy` 重试，并在证据记录中明确注明路径。

## 12. 故障定位表

| 现象 | 优先检查 | 不能直接下的结论 |
| --- | --- | --- |
| U-Boot TFTP 超时 | serverip/ipaddr、实际 TFTP root、防火墙、所选网卡 | PulseOS DWMAC 故障 |
| PulseOS 找不到根文件系统 | 是否写整盘、SDIO1、ext4 block 0、`mmc rescan` | 网络故障 |
| 主机邻居为 `INCOMPLETE` | 普通 ARP、MCBCQ、RX filter、PHY、部署镜像哈希 | DNS/Git 故障 |
| 板端 ping 主机失败但 wget 成功 | 主机 ICMP INPUT policy | TCP 或 NIC 必然失败 |
| `Could not resolve host` | `/etc/resolv.conf`、UDP/53、fake-IP | DWMAC 完全不收发 |
| `getsockname() errno 107` | 是否仍在运行遗漏 `CONNECTING` 修复的旧内核 | GitHub 服务异常 |
| TLS 证书尚未生效 | `date`、RTC/build epoch | CA bundle 一定损坏 |
| TLS issuer/CA 错误 | CA bundle、证书链、代理 TLS interception | 系统时间一定错误 |
| `Broken pipe` 只出现在公网 | NAT、FORWARD、代理/TUN、返回路由、pcap | 1514-byte DWMAC TX 一定卡死 |
| `first/probe TX stalled` 但传输成功 | 是否含诊断假阳性修正、descriptor 已回收状态 | 首帧确实永久 DMA-owned |

## 13. 证据保存

每次复现创建独立目录，至少保存源码、工具、内核、根文件系统和主机网络身份：

```bash
VF2_RUN_DIR="records/vf2-repro-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$VF2_RUN_DIR"

git rev-parse HEAD > "$VF2_RUN_DIR/commit.txt"
git status --short > "$VF2_RUN_DIR/worktree.status"
rustc -Vv > "$VF2_RUN_DIR/rustc.txt"
cargo -V > "$VF2_RUN_DIR/cargo.txt"
mkimage -V > "$VF2_RUN_DIR/mkimage.txt" 2>&1
ip -br addr > "$VF2_RUN_DIR/host-addresses.txt"
ip route show > "$VF2_RUN_DIR/host-routes.txt"
sha256sum kernel-vf2.uimg sdcard-rv-pub.img \
  > "$VF2_RUN_DIR/inputs.sha256"
```

主机抓包应使用本轮实际 `VF2_IF`：

```bash
sudo tcpdump -U -ni "$VF2_IF" -w "$VF2_RUN_DIR/board.pcap" \
  'arp or host 192.168.137.2'
```

复现结束前用 Ctrl-C 正常关闭抓包，再保存 `iptables -S`、`iptables -t nat -S` 或对应
Windows ICS/Firewall 配置、完整串口日志，以及板端 `date`、`ifconfig`、`nslookup`、
`git ls-remote`、`git clone` 和 `git fsck` 输出。日志中不得包含访问令牌、私钥或带凭据 URL。

## 14. 最终通过条件

只有同时满足以下条件，才可以写成“新机器复现成功”：

1. 使用已发布且工作区干净的 VF2 commit/tag；
2. `make test` 和带本轮 IP/GW 的 `make visionfive2` 通过；
3. TFTP 副本与构建产物哈希一致，串口日志确认启动的确切镜像；
4. microSD 上是 block 0 可识别的 ext4，并包含 Git、HTTPS helper、CA 和正确 resolver；
5. 普通 ARP、普通单播和数值 TCP 通过；
6. 板端时间可信，DNS 结果的直连/fake-IP 语义已确认；
7. GitHub clone 完成且 `git fsck --full` 通过；
8. 保存了足以区分直连 NAT、Windows ICS 或显式代理的主机侧配置和日志。

若只完成前五项，应报告为“物理 NIC 与本地 Git 通过，公网 Git 待主机拓扑验收”，而不是把
主机代理、DNS 或 NAT 问题重新归因给 JH7110 DWMAC。
