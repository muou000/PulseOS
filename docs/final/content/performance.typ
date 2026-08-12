= 性能分析与优化

== 性能瓶颈及分析过程

+ 热点定位： 通过分析qperf采样数据，候选热点指向 file page fault、page-cache 和 copy 路径。
+ 冷 file-backed mmap 缺页：
  - 瓶颈： 顺序首次访问会反复进入单页 file fault 和页缓存装载路径，重复的页查找、
    I/O 准备和发布工作成为首扫开销。
  - 分析： `bw_mmap_rd` 会预热、`lat_mmap` 主要测映射管理、iozone 本轮走
    buffered `read`/`pread`，都不覆盖目标路径；因此构造独立的静态非 PIE 测试，首次
    顺序触碰未访问的 `48 MiB` 文件。
+ 并发 Ext4 持久写：
  - 瓶颈： 多 worker 同时写不同文件时，共享 inode/metadata、目录 registry、block
    cache stripe、dirty owner 和 I/O range lock 产生竞争；`fsync` 与 `close` 又把
    writeback 和元数据提交纳入关键路径。
  - 分析： 用 8 个 worker、8 个文件、`64 KiB` 对齐请求、每 worker `44 MiB`，并以
    `-e` 计入 fsync、`-c` 计入 close；按 `B-C-C-B` 顺序比较 iozone Parent aggregate
    throughput，且将写操作与读操作分开判读。
+ 顺序 mmap 预取与匿名 fault 探针：
  - 瓶颈假设： 预取可能减少 demand fault 等待，但也可能引入无用 I/O、缓存淘汰和
    锁等待；匿名 fault 的重复页表读锁查询则是局部可疑开销。
  - 分析： 对预取使用 marker 界定的完整 BuildStorm A/B；对匿名 fault 先做源码和
    qperf 机制检查。只有完成同一正式阶段的普通内核对照，才纳入端到端效果结论。

== 优化方案

+ 连续 file-backed fault-around： 在确认访问连续且页偏移对齐后，
  将单页 `ensure_page_resident` 扩展为最多四页的批量预取和页缓存扩展；仍沿用
  single-flight、generation 校验、写锁、逐页映射和本地 TLB flush，避免以正确性换取
  速度。
+ Ext4 分片与 range lock： 将 inode state/metadata cache 和目录
  registry 分为 32 个 shard；分散 block-cache stripe 与 dirty owner，并设置 128 个
  I/O range-lock bucket，使不重叠范围的并发写不必争用同一把全局锁。
+ 匿名 fault PTE 查询去重： 在同一页表子树内复用
  `PageTableReadGuard`，最多覆盖连续四页，减少重复查询；分配、PTE 写锁、映射和
  TLB 刷新路径保持不变。该方案目前只有源码支持，尚无匹配的完整 A/B。
+ 顺序 mmap 预取： 采用每文件 single-flight、全局
  两个预取槽位和 try-lock admission，忙时优先 demand fault；设计上限制投机 I/O，
  但必须以完整 BuildStorm 结果决定是否保留为优化。

== 优化前后的效果对比

+ 冷 file-backed mmap 首扫： 基线版本的四次中位数为 `3.526777 s`，候选版本
  为 `1.465404 s`；耗时减少 `58.45%`，速度为 `2.407x`，吞吐由
  `13.610 MiB/s` 提升至 `32.755 MiB/s`。该结果支持四页 fault-around 在目标首扫路径
  有效，但仍是 QEMU/guest 页缓存冷启动，不等于物理盘冷读。
+ Ext4 并发持久写： 分片版本相对未分片基线的 Parent aggregate throughput 变化
  如下：
  - durable initial write：`91,741.29 -> 292,501.34 KiB/s`，`+218.83%`；
  - durable rewrite：`101,993.00 -> 333,791.98 KiB/s`，`+227.27%`；
  - durable pwrite：`99,947.95 -> 351,533.27 KiB/s`，`+251.72%`；
  - mixed initial write：`94,002.81 -> 376,367.91 KiB/s`，`+300.38%`；
  - mixed rewrite：`97,744.82 -> 313,203.82 KiB/s`，`+220.43%`；
  - mixed random write：`69,207.76 -> 157,889.76 KiB/s`，`+128.14%`。
  - 写入结果支持分片和 range lock 针对并发 fsync/close-inclusive 写路径有效；不能
    外推为所有 Ext4 操作或物理盘吞吐全面提升。
+ Ext4 读路径： 读项单独列出，避免把不同 I/O 语义合并为一个总分：
  - durable read：`248,443.80 -> 231,654.52 KiB/s`，`-6.76%`；
  - durable re-read：`248,901.36 -> 251,009.16 KiB/s`，`+0.85%`；
  - durable pread：`244,552.77 -> 247,864.29 KiB/s`，`+1.35%`；
  - mixed reverse read：`138,645.27 -> 140,089.04 KiB/s`，`+1.04%`；
  - mixed stride read：`229,588.76 -> 239,204.14 KiB/s`，`+4.19%`；
  - mixed random read：`137,121.44 -> 141,853.52 KiB/s`，`+3.45%`。
  因此读路径没有出现与写路径同等级的稳定收益。

== SMP 核数对比

在相同普通内核、镜像和 BuildStorm 输入下，仅改变 QEMU 运行期 vCPU 数。正式耗时取
guest `BUILDSTORM_BEGIN` 至 `BUILDSTORM_COMPILE` 的区间，并以单核结果计算加速比与
并行效率：

#align(center)[
#table(
  columns: (1fr, 1.8fr, 1.8fr, 1.8fr),
  align: (right, right, right, right),
  stroke: 0.5pt + rgb("#dddddd"),
  fill: (x, y) => if y == 0 { rgb("#eeeeee") } else { none },
  [vCPU], [正式耗时], [相对单核加速], [并行效率],
  [1], [2883.84 s], [1.000x], [100.0%],
  [2], [1588.21 s], [1.816x], [90.8%],
  [4], [1109.79 s], [2.599x], [65.0%],
  [8], [949.03 s], [3.039x], [38.0%],
)
]

核数从 1 增至 8 时，正式耗时持续下降：2 核、4 核和 8 核相对单核分别缩短
44.9%、61.5% 和 67.1%；即使从 4 核增加到 8 核仍获得 1.169 倍加速。数据表明该
BuildStorm 负载能够利用多个 CPU，PulseOS 的 SMP 并行是有效的；并行效率随核数增加
而下降，则说明收益并非线性扩展，PulseOS仍然存在改进空间。
