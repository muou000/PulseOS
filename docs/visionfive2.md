# VisionFive 2 Bring-Up

PulseOS has an initial StarFive VisionFive 2 (JH7110) path for booting a
U-Boot image over TFTP. It uses the dedicated
`axplat-riscv64-visionfive2` crate, derived from PulseOS's FDT-driven RISC-V
SBI/PLIC implementation. The U-Boot-provided FDT supplies the actual RAM
layout, PLIC contexts, and four usable U74 harts.

The complete Chinese engineering record, including failed attempts, serial
checkpoints, SD/MMC diagnosis, and the SMP hart-0 root cause, is available in
[visionfive2-porting-record.md](visionfive2-porting-record.md).
The NIC-specific implementation, failure analysis, fixes, and acceptance
boundaries are collected in
[visionfive2-nic-implementation.md](visionfive2-nic-implementation.md).
For a clean-machine setup covering the source snapshot, root filesystem,
TFTP, serial console, host NAT, DNS, and GitHub acceptance, see
[visionfive2-reproduction-guide.md](visionfive2-reproduction-guide.md).

## Build

Install `mkimage` from the host `u-boot-tools` package, then run:

```bash
make visionfive2
```

The board build defaults to `169.254.141.28/24` with gateway
`169.254.141.27`. Both values can be overridden without affecting the QEMU
configuration:

```bash
make visionfive2 VF2_IP=192.168.1.50 VF2_GW=192.168.1.1
```

The target defaults to all four U74 application harts. A different CPU count
can be selected for diagnosis:

```bash
make visionfive2 VF2_SMP=1
```

The JH7110 also contains an S7 management hart at hardware hart ID 0. U-Boot's
control DTB may mark it as available, so the platform parser explicitly limits
the PulseOS CPU topology to U74 hart IDs 1 through 4. Treating `status =
"okay"` as sufficient would make the first secondary startup incorrectly call
SBI HSM `hart_start(0)`.

The command produces:

- `kernel-vf2.uimg`: a U-Boot legacy kernel image.
- `kernel-vf2`: the raw binary for inspection.
- `PulseOS_riscv64-visionfive2.elf`: the matching debug ELF.

The U-Boot image has both load and entry addresses set to `0x40200000`.
The crate's `axconfig.toml` is the board configuration source; the build
selects it through `MYPLAT=axplat-riscv64-visionfive2` and applies the selected
`VF2_SMP` CPU-count override to the generated configuration.

## One-Shot U-Boot Boot

Use the board's existing U-Boot and OpenSBI firmware. Do not persist these
commands with `saveenv` during bring-up:

```console
setenv serverip 169.254.141.27
setenv ipaddr 169.254.141.28
mmc dev 1
mmc rescan
tftpboot ${loadaddr} kernel-vf2.uimg
bootm ${loadaddr} - ${fdtcontroladdr}
```

`bootm` preserves the RISC-V firmware handoff: `a0` carries the boot hart ID
and `a1` carries the board FDT. The FDT must be resident in RAM while PulseOS
starts.

`mmc dev 1` selects the removable microSD slot (`SDIO1` at `0x16020000`). The
initial PulseOS driver takes over and resets the DW MMC controller itself, but
still reuses the clock-tree, pinmux, and regulator state prepared by U-Boot, so
the rescan is part of the current boot contract.

## Root Filesystem

The JH7110 SD/MMC adapter exposes the microSD card through PulseOS's existing
block-device API. It currently uses serialized, polling PIO transfers; the
async API is a compatibility wrapper and is not yet interrupt driven.

The adapter uses the last polling-capable tgoskits driver generation
(`starfive-jh7110-dwmmc 0.1.3`, `dwmmc-host 0.3.3`, and
`sdmmc-protocol 0.4.2`). It resets the controller, derives the 400 kHz
identification divider from the JH7110 50 MHz CIU reference clock, and programs
the board's 32-word, 32-bit FIFO threshold. After card initialization, the
polling PIO path currently caps the 4-bit transfer clock at 6.25 MHz. This is a
conservative bring-up setting that provides more signal and FIFO-service margin
than the 25 MHz SD default clock. Later tgoskits releases are IDMAC-only and
require a full DMA and interrupt-runtime integration.

PulseOS currently probes an ext filesystem at block zero and does not select a
partition from an MBR or GPT. For a full boot, write a PulseOS root filesystem
image such as `sdcard-rv-pub.img` directly to a dedicated microSD card. A
partitioned Debian or U-Boot card can prove card detection, but its filesystem
will not be selected as the PulseOS root. Writing a raw image destroys the
existing partition table, so keep the board firmware in SPI flash or use a
separate card.

## Ethernet

The VisionFive 2 feature set registers GMAC0 (`0x16030000`, PLIC source 7) as
a DWMAC 5.20 network device and enables the normal PulseOS `axnet` runtime.
Probe data comes from the live FDT, including the MAC address and PHY phandle.
Both the mainline `starfive,jh7110-dwmac` compatible and the older vendor
U-Boot `starfive,jh7110-eqos-5.20` compatible are accepted.

The live FDT also supplies the referenced `snps,axi-config`. The driver applies
the advertised AXI read/write outstanding limits, supported burst lengths,
low-power-idle setting, and `snps,force_thresh_dma_mode`. On the current
VisionFive 2 DTB this selects WR/RD limit 15, burst lengths 32 through 256,
and a 64-byte RX/TX MTL threshold instead of store-and-forward mode.
The StarFive glue configuration is also reapplied from `starfive,syscon` and
`phy-mode`; for GMAC0 RGMII this programs the AON syscon interface-select field
instead of relying on the value left by U-Boot.

The initial driver supports one RX queue, one TX queue, up to 40-bit DMA
addresses, Clause 22 MDIO, the board's YT8531 PHY status, and PLIC-driven
completion wakeups. It probes the MDIO clock selector against the PHY ID and
falls back to the firmware selector when the firmware-prepared PHY is not
readable. Following the StarFive Linux glue contract, it enables DWMAC5's
different-descriptor-cache mode again after the MAC DMA soft reset. The
primary MAC address is written high-word first, matching Linux and U-Boot.
Exact-address filtering nevertheless dropped ordinary unicast on the tested
board. The VisionFive 2 wrapper therefore follows U-Boot's EQoS setup and
enables hardware promiscuous receive; smoltcp rejects foreign destination MAC
addresses before ARP or IP processing. The network poller also
samples and acknowledges the DMA channel status and checks RX/TX descriptor
ownership every 10 ms. A missing first PLIC wakeup therefore cannot leave a
completed descriptor unobserved indefinitely, and the first completion log
identifies whether it was observed through the IRQ or polling path. The current
JH7110 cache API exposes only a combined clean/invalidate operation. Each ring
contains four descriptors, but
software exposes only one descriptor to DMA at a time. This avoids concurrent
CPU/DMA ownership within a 64-byte cache line. It is intended for basic
connectivity, not throughput.

The YT8531 status is refreshed at most once per second while the network poller
is active. A link-up status whose speed and duplex have resolved updates the MAC
for 10, 100, or 1000 Mbps operation. A timed-out, link-down, or unresolved read
preserves the last valid MAC mode rather than interpreting zero as 10 Mbps.
Only status changes are logged, so delayed auto-negotiation and later cable or
speed changes remain visible without flooding the console.

PulseOS now supports the IPv4 `SOCK_RAW/IPPROTO_ICMP` subset needed by BusyBox
Echo ping. A shell-only RISC-V QEMU run completed `ping -c 3 127.0.0.1` with
three replies and zero packet loss. The raw receive path includes the IPv4
header expected by Linux applications; other raw protocols and IPv6 raw ICMP
remain unsupported. A local TCP server/client remains a useful second loopback
check:

```console
busybox httpd -p 127.0.0.1:18080 -h /
curl -v --max-time 5 http://127.0.0.1:18080/etc/os-release
killall httpd
```

The ICMP and TCP results above are software loopback evidence only. The TCP
test returned `HTTP/1.1 200 OK`, read `/etc/os-release` completely, and exited
with curl status 0. Physical VisionFive 2 RX/TX acceptance is recorded below
from separate host-to-board ARP, ICMP, and numeric-address TCP tests.

Interface-query responses are derived from the live `axnet` interface rather
than QEMU constants. `RTM_GETLINK`, `RTM_GETADDR`, `SIOCGIFCONF`,
`SIOCGIFHWADDR`, `SIOCGIFADDR`, `SIOCGIFNETMASK`, and `SIOCGIFBRDADDR` therefore
report the VisionFive 2 address and EEPROM MAC. The current root filesystem
does not contain iproute2; use `busybox ifconfig eth0` on the board.

Older RISC-V root filesystem images have no `/etc/resolv.conf`, although their
host lookup policy includes DNS. The common rootfs overlay now installs
`1.1.1.1` and `8.8.8.8` as fallback resolvers; an existing SD card must be
updated or rebuilt to receive that file. Consequently, `git clone` reporting
`Could not resolve host` on an older card does not diagnose the NIC. First
validate the data path with numeric addresses. For example, start
`busybox httpd -p 169.254.141.28:18080 -h /` on the board and request
`http://169.254.141.28:18080/etc/os-release` from the directly connected host.
Configure a resolver only after the host route/NAT or DNS-forwarder address is
known to be reachable from the board.

JH7110's integrated RTC is not in a separately powered always-on domain, so it
cannot be treated as a persistent clock across board power loss. PulseOS reads
and reports the raw RTC time/date registers, but rejects an invalid or stale
value. In that case the VisionFive 2 build timestamp seeds the wall clock as a
lower bound; `VF2_BUILD_EPOCH=<unix-seconds>` can make that value explicit for
reproducible images. This prevents a fresh image from starting at 1970 or the
RTC's 2001 default, while normal `clock_settime` or NTP can still install a more
accurate time after networking is available.

HTTPS clients use nonblocking TCP. Once `connect` has selected a local endpoint
and entered `CONNECTING`, POSIX `getsockname` must expose that address even
before the SYN handshake completes. PulseOS now includes `CONNECTING` in the
valid local-address states; the former `ENOTCONN` result caused Git/cURL to
abort before TLS and was independent of DWMAC packet transfer.

The bring-up image logs the initialized DMA mode/system-bus/channel controls,
current and tail descriptor pointers, MAC filter/address registers, and MTL
queue modes. It also emits one message for the first RX frame delivered to
smoltcp and one for the first TX frame submitted to DMA. Completion and abnormal
DMA status are captured from both PLIC and fallback-poll paths. These markers
separate no-MAC-ingress, descriptor/IRQ, protocol-stack, and transmit-side
failures.

The Ethernet probe now takes ownership of the GMAC0 AON resources declared by
the live DTB. It re-enables the AHB/AXI gates and deasserts the AON CRG reset
bits that U-Boot's `eth_halt()` can leave asserted after a successful TFTP
load, then applies the RGMII/RMII syscon selection again. The remaining PHY
clock-parent setup and pinmux are still firmware-prepared board state.

The first physically validated baseline image has SHA-256
`c28c25d0f7270c1aae7112608ecd7eb185351e04f455fcf6b9ad2a9b72e76698`.
With that image, both WSL and Windows received three of three ICMP replies from
`192.168.137.2`, and the host neighbor entry resolved to the EEPROM MAC
`6c:cf:39:00:7b:9c`. This is physical ARP and unicast RX/TX evidence for the
software-filtering candidate. The board then fetched
`http://192.168.137.1:18080/`, cloned the served repository, completed
`git fsck --full`, and read the expected worktree file.

The accepted TFTP candidate is `/mnt/d/Tftpd64/kernel-vf2.uimg`, SHA-256
`adfbb12caea964f25f5b30344b8d43b1a456be1be9264aaef740b2745c7f255d`.
It adds the `getsockname` fix and the RTC/build-time lower bound. On the board,
`date` reported 2026-08-11 rather than 1970, `nslookup github.com` succeeded,
and HTTPS Git against the host's temporary server returned the expected HEAD
and `refs/heads/master`. The user then confirmed a complete GitHub clone on the
same board. No host-side connection trace was retained for that final public
run, so this establishes application-level acceptance without distinguishing
direct host NAT from CONNECT proxying.

## Scope

This initial port covers serial/FDT/SBI/PLIC/SMP, the removable JH7110 SD/MMC
slot, JH7110 RTC sampling, and basic GMAC0 Ethernet. The SoC RTC is not a
persistent clock across power loss. PCIe and USB are not yet supported. Both
SD/MMC and Ethernet depend on firmware-prepared board state, and their current
PIO/single-outstanding-descriptor paths are bring-up implementations rather than final
performance designs.
