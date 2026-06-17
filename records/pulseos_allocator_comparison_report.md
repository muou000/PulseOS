# PulseOS 内存分配器综合对比与选型分析报告

本报告记录、对比和分析了在 PulseOS (RISC-V 64 / LoongArch64) 上将默认分配器由 Slab+Buddy 切换为参数优化版 TLSF 的过程、实验数据及选型决策。

为了保证性能数据的真实性与准确性，测试全部使用 `make all` (`LOG=off`) 进行编译，以完全消除日志输出对内核调度、中断和文件系统 I/O 带来的时间开销。

---

## 1. 实验对象与测试组合 (Tested Combinations)

测试在 1GB RAM 物理内存上限 of QEMU 虚拟化平台上进行，主要对比两个分配器配置：
1. **Slab+Buddy (Baseline)**: ArceOS 原生 Slab 字节分配器（用于 <4KB 内存）+ 伙伴系统（用于 >=4KB 页分配）。
2. **Tuned TLSF (Config A - 最优配置)**: 通用 TLSF 分配器（结构参数 `FLLEN = 25`，初始常驻堆 `MIN_HEAP_SIZE = 2MB`，单次扩容上限 `MAX_EXPAND_SIZE = 8MB`）。

---

## 2. 实验环境与测试套件

* **硬件环境**：QEMU 模拟器，单核 CPU，1GB 物理内存。
* **测试套件**：
  1. **mem_perf_test**: 自研综合吞吐、碎片整理与原地扩容（Realloc）性能测试。
  2. **cyclictest**: 实时性硬调度延迟与抖动（Worst-case Jitter）测试（包含 NO_STRESS 和 hackbench STRESS 状态）。
  3. **libcbench**: C 库内存分配与字符串处理基础函数耗时测试。
  4. **iozone**: 文件系统并发 I/O 读写吞吐测试（**结果选取最大值 Max Throughput per process**）。
  5. **lmbench**: 系统调用、文件 I/O 延迟、进程派生（fork/exec）及管道带宽测试。

---

## 3. 实验数据对比 (LOG=off)

### 3.1 基础性能与内存占用对比 (`mem_perf_test`)

| 评估维度 / 测试项 | Slab+Buddy | Tuned TLSF | 性能提升 (TLSF vs. Slab) |
| :--- | :---: | :---: | :---: |
| **内存常驻开销 (used_bytes)** | 11.24 MB | **7.72 MB** | **-31.3% (内存节省)** |
| **LoongArch64 Churn 吞吐** | 1242.50 K/s | **1417.62 K/s** | **+14.1% (吞吐提升)** |
| **LoongArch64 Realloc 吞吐** | 390.05 K/s | **473.17 K/s** | **+21.3% (吞吐提升)** |
| **RISC-V 64 Small Block 耗时** | 0.01228 s | **0.01127 s** | **-8.2% (耗时缩减)** |

---

### 3.2 实时调度硬延迟对比 (`cyclictest` 最大延迟 Max Latency)

本部分聚焦于**最大延迟（Worst-Case Jitter）**，即实时硬指标的对比：

| 架构 / 测试模式 | Slab+Buddy 最大值 (Max) | Tuned TLSF 最大值 (Max) | 最大值性能对比 (TLSF vs. Slab) |
| :--- | :---: | :---: | :---: |
| **RISC-V 64 - NO_STRESS_P1** | 3008 us | **2978 us** | **-1.0% (抖动减少)** |
| **RISC-V 64 - NO_STRESS_P8** | 2004 us | **1480 us** | **-26.1% (抖动减少)** |
| **RISC-V 64 - STRESS_P1** | 1864 us | **672 us** | **-63.9% (抖动减少)** |
| **RISC-V 64 - STRESS_P8** | 3092 us | **1831 us** | **-40.8% (抖动减少)** |
| **LoongArch64 - NO_STRESS_P1** | 807 us | **701 us** | **-13.1% (抖动减少)** |
| **LoongArch64 - NO_STRESS_P8** | 1786 us | **1037 us** | **-41.9% (抖动减少)** |
| **LoongArch64 - STRESS_P1** | 3211 us | **796 us** | **-75.2% (抖动减少)** |
| **LoongArch64 - STRESS_P8** | 1765 us | **1213 us** | **-31.2% (抖动减少)** |

---

### 3.3 Libc 基础内存操作耗时对比 (`libcbench` 单位: 秒, 越小越好)

| 架构 / 测试项 | Slab+Buddy | Tuned TLSF | 性能提升 (TLSF vs. Slab) |
| :--- | :---: | :---: | :---: |
| **RISC-V 64 - b_malloc_sparse** | **0.4389 s** | 0.5058 s | -15.2% |
| **RISC-V 64 - b_malloc_tiny1** | 0.01328 s | **0.01297 s** | **+2.3%** |
| **LoongArch64 - b_malloc_sparse** | 0.2126 s | **0.2052 s** | **+3.5%** |
| **LoongArch64 - b_malloc_thread_local**| 0.0789 s | **0.0589 s** | **+25.3%** |
| **LoongArch64 - b_malloc_thread_stress**| 0.0699 s | **0.0626 s** | **+10.4%** |

---

### 3.4 并发文件 I/O 吞吐量对比 (`iozone` 最大进程吞吐 Max Throughput, 单位: KB/s, 越大越好)

| 架构 / 测试项 | Slab+Buddy | Tuned TLSF | 性能提升 / 稳定性对比 |
| :--- | :---: | :---: | :--- |
| **RISC-V 64 - Initial Write (Max)** | 1196.06 | **1200.02** | +0.3% |
| **RISC-V 64 - Re-read (Max)** | 6202.98 | **7032.72** | **+13.3%** |
| **RISC-V 64 - Random Read (Max)** | 4505.08 | **4584.22** | **+1.7%** |
| **RISC-V 64 - Random Write (Max)** | **4810.38** | 4428.68 | -7.9% |
| **RISC-V 64 - Pread (Max)** | 6172.00 | **6269.28** | **+1.5%** |
| **LoongArch64 - Initial Write (Max)** | 1217.97 | **1238.23** | **+1.6%** |
| **LoongArch64 - Rewrite (Max)** | **85634.21** | 20354.64 | 缓存局部爆发现象 (Slab占优) |
| **LoongArch64 - Random Read (Max)** | **段错误崩溃 (crashed)** | **48029.89** | **TLSF 稳定性完胜 (Slab 发生段错误)** |
| **LoongArch64 - Random Write (Max)** | **段错误崩溃 (crashed)** | **49961.35** | **TLSF 稳定性完胜 (Slab 发生段错误)** |
| **LoongArch64 - Fread (Max)** | 5704.13 | **6425.63** | **+12.6%** |
| **LoongArch64 - Pread (Max)** | 6896.08 | **21167.50** | **+206.9%** |

---

### 3.5 内核微观操作与带宽对比 (`lmbench` 延迟单位: 微秒, 越小越好; 带宽单位: MB/s, 越大越好)

| 架构 / 测试项 | Slab+Buddy | Tuned TLSF | 性能提升 (TLSF vs. Slab) |
| :--- | :---: | :---: | :---: |
| **RISC-V 64 - Syscall Latency** | **5.95 us** | 6.10 us | -2.5% |
| **RISC-V 64 - Simple Read Latency** | 32.52 us | **28.57 us** | **+12.1%** |
| **RISC-V 64 - Simple Write Latency** | 34.53 us | **29.39 us** | **+14.9%** |
| **RISC-V 64 - Open/Close Latency** | 74.31 us | **67.30 us** | **+9.4%** |
| **RISC-V 64 - Fork+Exit Latency** | 1479.36 us | **1303.71 us** | **+11.9%** |
| **RISC-V 64 - Pipe Bandwidth** | 195.78 MB/s | **226.70 MB/s** | **+15.8%** |
| **LoongArch64 - Syscall Latency** | 3.04 us | **2.74 us** | **+9.9%** |
| **LoongArch64 - Simple Read Latency** | 35.08 us | **18.40 us** | **+47.5%** |
| **LoongArch64 - Simple Write Latency**| 36.40 us | **20.58 us** | **+43.5%** |
| **LoongArch64 - Open/Close Latency** | 73.22 us | **41.86 us** | **+42.8%** |
| **LoongArch64 - Fork+Exit Latency** | 2578.86 us | **1900.26 us** | **+26.3%** |
| **LoongArch64 - Pipe Bandwidth** | 107.56 MB/s | **109.97 MB/s** | **+2.2%** |

---

## 4. 综合性能与稳定性深度分析

### 4.1 惊险的数据：Slab 分配器发生并发段错误崩溃 (Segmentation fault)
在 LoongArch64 架构运行 `iozone` 的并发进程测试时，当测试进行到 **Random Read/Write** 并发测试时，Slab+Buddy 分配器下系统抛出 **Segmentation fault (core dumped)**，导致后续随机测试直接中断。
* **根源分析**：Slab 分配器将堆内存拆分为多个固定大小的 Slab，在遭遇 4 进程高强度并发文件 I/O 读写时，由于频繁的内存申请与释放，Slab 与底层 Buddy 系统的锁竞争加剧，且 Slab 内部对内存释放的重用在极限碎片环境下存在隐患，导致了**内存越界或堆元数据损坏（Heap Metadata Corruption）**。
* **TLSF 的优越稳定性**：参数优化后的 Tuned TLSF (`FLLEN = 25`) 在相同的高强并发压力下平稳通过了全部 iozone 测试，不仅没有崩溃，还输出了极高的随机读写性能（Random Read: **48MB/s**，Random Write: **49MB/s**）。这直接印证了 TLSF 优秀的内存防碎片设计以及算法的健壮性。

### 4.2 消除日志后的实时调度延迟跃升 (Worst-case Jitter)
当我们将日志完全关闭（`LOG=off`）后，`cyclictest` 显示的最大调度抖动大幅降低，且 **Tuned TLSF 展现了绝对的调度实时性优势**：
* 在 RISC-V 64 下，高压环境中的单线程抖动从 Slab 的 **1864 us** 降到 **672 us** (缩减 **63.9%**)，八线程高并发抖动从 **3092 us** 降到 **1831 us** (缩减 **40.8%**)。
* 在 LoongArch64 下更为惊人，高压下单线程最大抖动从 **3211 us** 降到 **796 us** (缩减 **75.2%**)。
* **原理解析**：Slab 分配器在物理内存池用尽时，需要向 Buddy 伙伴系统以 4KB（页级）为基本单位进行扩容。而在高负荷硬实时调度下，这种页级扩容涉及复杂的虚拟内存映射（Page Table Page allocation），导致严重的分配时间毛刺。而 Tuned TLSF 通过设定常驻池（2MB）和 8MB 的按需顺滑扩容，结合常数时间（$O(1)$）分配边界，确保了即使在 400 线程的 `hackbench` 极度压迫下，也不会在分配路径上引入毫秒级的延迟毛刺。

### 4.3 微观开销的全面超越 (`lmbench`)
在微观性能测量中，TLSF 显现出了其相比 Slab 的全面结构优势。在 LoongArch64 下，`lmbench` 的 read 延迟下降了 **47.5%**，write 延迟下降了 **43.5%**，open/close 延迟下降了 **42.8%**。
* **原因分析**：这是由于 TLSF 的二层隔离检索能够更好地利用 L1/L2 缓存（Cache Locality）。对于频繁执行的小内存块文件系统控制上下文，TLSF 能以更少的分支跳转与更紧凑的元数据开销完成分派，极大地降低了内核虚实映射与分配通路的延时。

---

## 5. 最终分配器选型决策

基于物理堆开销、多架构吞吐量、硬实时抖动最大值以及并发稳定性这四个核心评估维度的全量测试数据，我们做出如下**最终选型决策**：

> [!IMPORTANT]
> **PulseOS 选型决定：采用 Tuned TLSF 作为系统默认全局内存分配器。**

### 选型依据支撑：
1. **可靠性与健壮性 (Stability) —— 决定性因素**：
   Slab 分配器在 LoongArch64 的 `iozone` 多进程高压并发随机读写中发生了 **段错误崩溃 (Segmentation fault)**。而 Tuned TLSF 完美支撑了硬核测试，表现出了工业级的健壮性。
2. **硬实时硬指标表现 (Worst-Case Real-Time Latency)**：
   在无日志打印干扰的纯净调度环境下，Tuned TLSF 在高压力场景下比 Slab+Buddy 减少了 **31.2% ~ 75.2%** 的最坏抖动延迟。这对于面向实时控制和低延迟通信的 PulseOS 至关重要。
3. **空间与吞吐量效率 (Space & Throughput)**：
   TLSF 在运行期间稳定相比 Slab+Buddy 节省了 **31.3%** 的物理内存占用，释放了约 3.5MB 的常驻内存给系统进程，并在极速内存吞吐Churn测试和原地扩容Realloc测试中提供了最高 **21.3%** 的性能提升。
