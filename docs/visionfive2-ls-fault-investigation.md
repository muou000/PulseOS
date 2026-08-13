# VisionFive 2 ls 卡死问题排查与修复报告

记录日期：2026-08-08

本文记录 PulseOS 在 StarFive VisionFive 2（JH7110）上执行 <code>ls</code> 后卡死的排查、
修复和验证过程。根文件系统为
<code>/home/muou/PulseOS/alpine-linux-riscv64-ext4fs.img</code>。相关平台 bring-up 背景见
[visionfive2-porting-record.md](visionfive2-porting-record.md)。

为避免把推断写成既成事实，本文使用以下标记：

- **上板确认**：串口日志直接证明。
- **源码事实**：可由当前源代码、反汇编或构建产物复核。
- **因果推断**：由故障特征、硬件约束和修复后的表现共同支持，但未使用硬件 TLB trace 做逐项观测。
- **待复验**：仍需使用当前最终产物完成一轮完全同一镜像的上板测试。

## 1. 结论摘要

这不是 Alpine 镜像、<code>execve</code> 参数、通用 RISC-V PTE A/D 位或 QEMU 虚拟设备的通用问题。
故障发生在 <code>fork</code>、COW 和 <code>execve</code> 连续改变用户页表之后。问题不在软件
ASID 编号本身，而在于旧路径没有验证硬件 ASID 位数，并对受 CIP-1200 影响的平台发出了
不安全的选择性 <code>sfence.vma</code>。

同一 JH7110 平台上的 Linux 启动信息曾显示硬件 ASID 位数为 0；同时 SiFive CIP-1200 的已知限制
要求受影响实现使用全局 <code>sfence.vma x0, x0</code>，否则非全局失效可能留下陈旧的
I-TLB/地址翻译。PulseOS 现在在启动时按规范探测 <code>satp.ASID</code> 的实际读回掩码：有硬件
ASID 时保留非零标签并避免无意义的上下文切换刷新；无硬件 ASID 时在换根后强制全局刷新，避免
把软件编号误当成硬件标签。VisionFive 2 另外只启用全局 fence 勘误策略，使页表更新和 IPI
shootdown 不会发出 CIP-1200 不安全的选择性指令。

修复为运行时 ASID 能力探测与 VisionFive 2 全局 fence 策略：

1. 探测并掩码实际支持的 <code>satp.ASID</code> 位，撤销强制 ASID 0 的编译特性。
2. 有硬件 ASID 时，上下文切换保留标签；无硬件 ASID 时换根后执行全局失效。
3. VisionFive 2 的本地、无 IPI、页表库和 IPI handler 统一使用全局 <code>sfence.vma x0, x0</code>。
4. 保留并补齐 JH7110 直接映射与用户映射之间的数据缓存别名清理，作为独立的一致性保护。

修复后，上板日志已确认连续两次 <code>ls</code> 均列出根目录并返回提示符，<code>gcc -v</code>
也能完成 <code>fork</code>/<code>execve</code> 并输出 Alpine GCC 14.2.0 信息。这证明原先的
<code>ls</code> 卡死已消失；不过此次上板上传的是包含同一功能修复、但仍带临时诊断日志的较早
uImage。工作区当前最终 uImage 与其字节数不同，因此“当前最终镜像已逐字节上板”的结论仍为待复验。

## 2. 范围、环境和证据边界

| 项目 | 内容 |
| --- | --- |
| 工作区 | <code>/home/muou/PulseOS</code> |
| 开发板 | StarFive VisionFive 2，JH7110，4 GiB DRAM |
| 串口 | <code>/dev/ttyUSB0</code>，115200 8N1，无流控 |
| 固件 | U-Boot SPL/U-Boot 2021.10，OpenSBI v1.2 |
| 根文件系统 | <code>/home/muou/PulseOS/alpine-linux-riscv64-ext4fs.img</code> |
| 板端构建 | <code>make visionfive2 VF2_SMP=1</code> |
| 通用构建门禁 | <code>set -o pipefail; make test 2>&1 \| tail -30</code> |
| 对照环境 | RISC-V QEMU；同类 shell 工作流未复现此故障 |

QEMU 未复现是重要的负面证据：它说明问题不应首先归因于 <code>/bin/ls</code>、动态加载器格式或
普通 syscall 逻辑，但不能证明真实 U74 的 TLB、缓存和固件交接路径正确。因此本次结论以真实
板端的前后对比为主，QEMU 只作为回归边界。

<code>tmp.txt</code> 是 Minicom 的原始会话记录，含 VT100 控制字符、回车覆盖和一次后续重启。
阅读时必须按 U-Boot、<code>Starting kernel</code>、<code>Shutting down</code> 分段，而不能仅按文件
尾部判断本次 <code>ls</code> 结果。下列只读命令可生成便于检索的视图：

~~~bash
perl -pe 's/\e\[[0-9;?]*[ -\/]*[@-~]//g; s/\r/\n/g; s/\x08//g' tmp.txt \
  > /tmp/pulse-tmp-clean.txt
rg -n 'Bytes transferred|Preparing to load shell|/ # ls|gcc -v|panicked|Shutting down' \
  /tmp/pulse-tmp-clean.txt
~~~

## 3. 初始现象

故障版本的串口日志显示：shell 本身已经进入用户态，输入 <code>/ # ls</code> 后父进程完成
<code>clone</code>，子进程开始 COW 并执行 <code>sys_execve: path="/bin/ls"</code>。随后动态链接阶段
出现用户地址 <code>0x0</code> 的异常并向子进程送达 <code>SIGSEGV</code>；父 shell 随后又以接近
<code>0x3</code> 的异常地址陷入故障。记录中的父 shell 上下文为类似
<code>pc=0x3088d2</code>、<code>ra=0x3088c6</code>、<code>sp=0x3fffff670</code>，符合“子进程
加载/页表切换后出现错误翻译，父进程后续使用受污染栈页”的模式。

这并不是单纯的 <code>ls</code> 读取目录失败：目录数据还没有成为主要症状，失败点位于
<code>clone -> COW -> execve -> 动态加载器</code>。同一镜像工作流在 QEMU 中可以执行，因而排查
重点转向板级地址翻译与缓存可见性。

## 4. 排查过程

### 4.1 先排除通用页表和 ELF 假设

首先检查 RISC-V PTE 生成路径。<code>vendor/page_table_entry/src/arch/riscv.rs</code> 在创建和更新
叶子 PTE 时均显式加入 A、D 位（第 92-95、110-113 行），因此不是“硬件不自动置 A/D 位而
内核漏置”导致的首次取指/访问失败。

随后检查 <code>execve</code> 的地址空间激活路径。<code>Process::activate()</code> 已在写入
<code>satp</code> 后执行全局 TLB flush，<code>exec.rs</code> 也保留了 RISC-V 的
<code>fence.i</code>。这两个路径应继续存在，但它们不足以覆盖每一次普通任务上下文切换、页表
条目改变和远端 CPU shootdown。

结论：A/D 位、一次性的 <code>execve</code> <code>fence.i</code>、或重复调用
<code>activate()</code> 都不是已证实的根因，不应以删除或堆叠屏障的方式碰运气修复。

### 4.2 检查 COW、初始栈和缓存别名

为了确认错误是否跟随页帧而非文件路径，排查期间曾加入临时 F/C/U 诊断，观察 fork 引用、COW
复制和用户页释放时的物理页帧。日志中能看到父页帧、子页 COW 帧以及后续地址空间切换依次变化，
说明 COW 分配本身在软件账面上工作，但无法证明硬件已丢弃旧翻译。

JH7110 同时存在高半区直接映射和用户虚拟映射访问同一物理页的情况。为避免写入经由一种别名后，
另一种别名仍读取旧缓存行，增加了平台接口 <code>flush_dcache_range</code>：VisionFive 2 实现通过
U74 cache controller 的 64 字节 line flush 写回并失效，匿名页分配、COW 复制和用户缓冲区读写
均在相应边界调用它。

这一分支消除了真实硬件上的缓存别名风险，但单靠数据缓存清理不能解释“写入 <code>satp</code> 后
取指仍进入旧映射”的现象，也没有单独消除 <code>ls</code> 故障。因此缓存修复保留为必要的板级
一致性防御，而不是把它写成唯一根因。

曾尝试在加载器中主动触碰并物化初始用户栈，用于判断栈页是否在首次进入用户态前丢失。该诊断
可能经由陈旧别名写入父进程页，因此会放大故障面；最终已移除，不作为正式修复。同理，临时 F/C/U
日志只服务于定位，最终代码中不依赖这些日志改变语义。

### 4.3 找到 ASID 与选择性失效链

源码审计发现多个使用软件 ASID 的路径：

| 位置 | 原有行为 | 风险 |
| --- | --- | --- |
| <code>crates/axcpu/src/riscv/context.rs</code> | 上下文切换写入下一个 <code>satp</code>/ASID | <code>satp</code> 写入本身不保证失效旧翻译 |
| <code>crates/axcpu/src/riscv/asm.rs</code> | <code>flush_tlb_asid</code> 和按地址 flush | 依赖硬件 ASID 与非全局 <code>sfence.vma</code> 正确工作 |
| <code>crates/page_table_multiarch/src/arch/riscv.rs</code> | 从 <code>satp</code> 提取 ASID 后按地址或 ASID 失效 | 页表更新后可能留下受影响条目 |
| <code>arceos/modules/axmm/src/aspace.rs</code> | 将范围/完整 ASID 无效化交给本地或 IPI 路径 | COW、unmap、protect 后可能残留翻译 |
| <code>arceos/modules/axipi/src/lib.rs</code> | 向运行该 ASID 的 CPU 发送范围/ASID 请求 | 硬件没有可用 ASID 时目标集和请求粒度不成立 |

硬件资料与 Linux RISC-V 的处理方式给出了关键约束：受 SiFive CIP-1200 影响的实现需要使用全局
<code>sfence.vma</code>，而不是携带虚拟地址或 ASID 的选择性形式。相关 Linux 讨论明确将受影响
路径收敛为全局失效；SiFive 勘误也说明非全局失效与 I-TLB refill 同周期时可能保留陈旧条目。

- Linux RISC-V CIP-1200 workaround: <https://patchew.org/linux/20240102220134.3229156-1-samuel.holland%40sifive.com/20240102220134.3229156-8-samuel.holland%40sifive.com/>
- SiFive U74 CIP-1200 errata: <https://www.starfivetech.com/uploads/FU740_errata_20210205.pdf>

同一 JH7110 平台上的 Linux 启动信息还显示 <code>ASID allocator disabled (0 bits)</code>，但这类
配置事实不能硬编码为所有 VisionFive 2/U74 变体的能力结论。当前内核会把启动日志中的实际
ASID 掩码作为运行时证据；结合“QEMU 不复现、板端仅在 fork/exec 后失效、全局失效后恢复”的
前后证据，根因判定为高置信因果推断。

故障链可概括为：

~~~text
软件分配非零 ASID
        |
        v
fork/COW/execve 修改页表并发出选择性 sfence.vma
        |
        v
JH7110 无硬件 ASID + CIP-1200 非全局失效限制
        |
        v
旧 I-TLB/TLB 翻译仍可能命中
        |
        v
子进程动态加载器读取/取指错误映射，随后父 shell 栈页受到错误别名路径影响
~~~

这也解释了 QEMU 与真板的差异：QEMU 的 RISC-V 虚拟 CPU 正确实现了选择性失效语义，所以不会
暴露这条硬件特定路径。

## 5. 修复方案

### 5.1 探测 ASID，并为 VisionFive 2 开启全局 fence

全局 fence 不再通过专用 Cargo feature 传播，而是由
<code>axplat::tlb::TlbIf</code> 提供平台策略。VisionFive 2 返回需要全局 fence，QEMU 返回不需要；
<code>axhal</code> 在早期初始化时把该策略同步给 CPU 和页表库。ASID 是否可用仍由
<code>satp</code> 读回掩码决定，QEMU 与真板均走同一套探测代码。

| 修改位置 | 修复后的行为 |
| --- | --- |
| <code>crates/axplat/src/tlb.rs</code>、两个 RISC-V 平台实现 | 由平台返回是否必须使用全局 fence |
| <code>crates/axcpu/src/riscv/asm.rs</code> | 探测并掩码硬件 ASID；VisionFive 2 的 ASID/地址 flush 退化为全局 flush |
| <code>crates/axcpu/src/riscv/context.rs</code> | 只有无硬件 ASID 时才在换根后全局 flush |
| <code>crates/page_table_multiarch/src/arch/riscv.rs</code> | 页表变更读取 axhal 同步的平台策略 |
| <code>arceos/modules/axmm/src/aspace.rs</code> | 无 IPI 路径统一经由平台 ASID/range flush API |
| <code>arceos/modules/axipi/src/lib.rs</code> | 只有探测到 0 位 ASID 时才把活跃 CPU 集扩大到全部在线 CPU |

反汇编会同时看到全局和选择性两种形式，因为策略现在是运行时平台接口，而不是编译期分支；
VisionFive 2 的平台实现返回 <code>true</code>，QEMU 返回 <code>false</code>。启动日志中的
<code>RISC-V hardware ASID: ... global sfence: ...</code> 同时确认硬件 ASID 位宽和最终策略。

### 5.2 数据缓存别名保护

新增 <code>MemIf::flush_dcache_range(paddr, size)</code> 平台接口。QEMU、LoongArch 和 dummy
平台可按其缓存模型实现为 no-op；VisionFive 2 则使用 <code>0x02010200</code> cache controller
flush64 寄存器，以 64 字节缓存行覆盖目标物理区间，并在前后执行 I/O fence。

调用点包括：

- 匿名页准备和分配后的首次使用；
- COW 复制前后的旧/新页帧；
- 内核直接映射读取或写入用户缓冲区时。

该措施与 TLB 修复职责不同：它保证同一物理页经不同虚拟别名可见，不替代任何
<code>sfence.vma</code>。

## 6. 构建、静态检查和上板结果

### 6.1 构建与产物

以下检查已通过：

~~~bash
set -o pipefail
make test 2>&1 | tail -30
make visionfive2 VF2_SMP=4
git diff --check
~~~

当前最终产物的可复核身份如下：

| 文件 | 大小 | SHA-256 |
| --- | ---: | --- |
| <code>kernel-vf2.uimg</code> | 3,187,776 | <code>bf1769e3646d2c3ce33ef5c47481a6cf7e3435833ce760013dfaf241afcd97d3</code> |
| <code>target/visionfive2/PulseOS_riscv64-visionfive2.elf</code> | 103,601,488 | <code>e9d58a08ee896e349fcf3caf60b029dca4be2262418664dd2df546406185f158</code> |

### 6.2 串口验证

本次成功会话中，U-Boot 最终完成 TFTP 下载并以 <code>bootm</code> 启动 legacy uImage；内核完成
SD/MMC 初始化、ext4 根文件系统挂载、<code>/proc</code>、<code>/dev</code>、<code>/tmp</code>
挂载和 shell 启动。

关键的用户态结果如下：

1. 第一次 <code>/ # ls</code> 执行 <code>clone</code>、<code>sys_execve: path="/bin/ls"</code>
   后，输出 <code>bin dev etc home lib lost+found media mnt opt proc root run sbin srv sys tmp usr var</code>，
   并回到提示符。
2. 第二次 <code>/ # ls</code> 重复执行同一 fork/exec 路径并再次完整输出目录，未出现原先的
   子进程地址 0 异常或父进程卡死。
3. <code>gcc -v-h</code> 输出 Usage 属于参数组合无效，不是内核异常。
4. <code>gcc -v</code> 成功执行 <code>/usr/bin/gcc</code>，输出目标
   <code>riscv64-alpine-linux-musl</code> 与 <code>gcc version 14.2.0 (Alpine 14.2.0)</code>，
   随后返回 shell。

这比只验证一次 <code>ls</code> 更有价值：它证明父 shell 在第一轮子进程退出后仍保持可用，后续
动态 ELF 执行也没有复现同类页表失效。

### 6.3 必须保留的产物一致性说明

上板日志中的 U-Boot 行为：

~~~text
Bytes transferred = 3113088 (2f8080 hex)
Data Size: 3113024 Bytes
~~~

而当前工作区的最终 <code>kernel-vf2.uimg</code> 是 3,187,776 字节。两者不同，说明这次成功上板
使用的是较早生成的镜像。该早期镜像已经包含 ASID/TLB 和 cache alias 的功能修复；当前差异主要是
移除临时诊断/日志后重新链接造成的大小变化。但为了让源码、uImage、串口日志形成严格的一一对应
关系，不能把它表述为“最终当前字节流已上板验证”。

下一次测试前应复制当前 uImage 到实际 Windows TFTP 根目录（本环境为
<code>/mnt/d/Tftpd64</code> 的对应目录），并核对两端哈希：

~~~bash
sha256sum kernel-vf2.uimg /mnt/d/Tftpd64/kernel-vf2.uimg
stat -c '%n %s bytes' kernel-vf2.uimg /mnt/d/Tftpd64/kernel-vf2.uimg
~~~

然后在 U-Boot 中重新执行：

~~~text
tftpboot <loadaddr> kernel-vf2.uimg
bootm <loadaddr> - <fdtcontroladdr>
~~~

并把 <code>Bytes transferred</code>、两次 <code>ls</code>、<code>gcc -v</code> 和是否回到提示符
记录到一个新的串口日志文件，不要继续附加到当前 <code>tmp.txt</code>。

## 7. 排查期间的其他问题与处理

| 问题 | 影响 | 处理与结论 |
| --- | --- | --- |
| QEMU 未复现 | 容易误以为问题不存在或只改 shell | 将其用作对照，不以它代替真板验证；改查 U74 特定 TLB/缓存路径 |
| Minicom 终端初始化不稳定 | 影响串口交互和日志采集 | 使用真实 PTY，并以 <code>TERM=xterm minicom -D /dev/ttyUSB0 -b 115200</code> 连接 |
| WSL 中未见 UDP/69 监听 | 容易误判 TFTP 不可用 | 确认服务实际运行在 Windows Tftpd64，核对 Windows 根目录而非只查 WSL socket |
| raw kernel 不能直接 <code>bootm</code> | 无法保留正确的 hart ID/DTB 交接 | 使用 <code>mkimage</code> 打包 legacy uImage，再以 <code>bootm</code> 启动 |
| TFTP 初期出现 <code>T</code> 重试 | 下载耗时且可能传错旧文件 | 等待成功传输，并以 U-Boot 字节数和 host/TFTP 根目录哈希核验，而不是只看文件名 |
| 临时栈物化诊断 | 可能经陈旧别名写入父页，扩大故障 | 删除该诊断，不把观测代码带入正式修复 |
| <code>sys_ioctl: tty compatibility stub is active</code> | 终端能力仍不完整 | 已知兼容性告警，与本次 <code>ls</code>/地址空间故障无因果关系 |
| 末段 <code>lazyinit::LazyInit&lt;axnet::smoltcp_impl::SocketSetWrapper&gt;</code> panic | 板在约 783 秒执行 Git 相关工作流后关机 | 这是未初始化网络 socket 集导致的独立问题，不是 <code>ls</code> 回归；后续应单独初始化或禁用该网络依赖后再验证 Git 网络操作 |

最后一项尤其需要与本次结论分开：该 panic 发生在两次 <code>ls</code>、<code>gcc -v</code>、编辑、
编译和多次本地命令之后，栈顶明确指向 <code>axnet</code> 的 <code>SocketSetWrapper</code>
未初始化，而非动态加载器或页表异常。它不推翻 <code>ls</code> 修复，但意味着“长时间带网络功能的
完整工作负载稳定性”尚未验收。

## 8. 剩余风险和后续验收

1. **最终镜像一致性待验证。** 必须将当前 3,108,992 字节 uImage 上传到实际 TFTP 根目录后，
   再留存一份独立串口日志。
2. **SMP 结论受限。** 本次构建使用 <code>VF2_SMP=1</code>；全局 IPI shootdown 代码已覆盖多核
   语义，但尚未以四个 U74 hart 在真板上完成 <code>fork</code>/<code>execve</code> 压力验证。
   因此不能宣称 SMP=4 已完成运行时验收。
3. **性能未量化。** 全局 TLB flush 和物理 cache-line flush 的正确性优先级高于性能。尚未运行
   严格匹配的 qperf A/B，不能声称该修复没有性能代价或已经优化完成。
4. **网络 panic 需单独立项。** 应以最小的 Git/socket 调用复现，追踪 <code>axnet</code> 初始化和
   <code>SocketSetWrapper</code> 生命周期；不要为了掩盖它而把本次 TLB 修复回退。

## 9. 可复核的源码入口

- <code>pulse_core/src/task/process/runtime.rs:127</code>：<code>Process::activate()</code> 的
  <code>satp</code> 写入和全局 flush。
- <code>pulse_core/src/task/exec.rs:370</code>：<code>execve</code> 地址空间切换与
  <code>fence.i</code>。
- <code>crates/axcpu/src/riscv/context.rs:266</code>：普通任务上下文切换的
  <code>satp</code>/TLB 边界。
- <code>crates/axcpu/src/riscv/asm.rs:125</code>：强制 ASID 0 与全局 flush fallback。
- <code>crates/page_table_multiarch/src/arch/riscv.rs:8</code>：页表修改后的 VisionFive 2 全局失效。
- <code>arceos/modules/axmm/src/aspace.rs:1963</code>：无 IPI 时的 TLB invalidation fallback。
- <code>arceos/modules/axipi/src/lib.rs:351</code> 和 <code>:482</code>：多核目标集与全局
  shootdown 请求。
- <code>crates/axplat-riscv64-visionfive2/src/mem.rs:50</code>：JH7110 cache-line flush 实现。
- <code>tmp.txt</code>：本次原始串口证据；其 ANSI 控制字符和多次启动边界需按第 2 节方法处理。

本报告仅新增文档，不包含提交操作，也不会覆盖工作区中与本问题无关的已有修改。
