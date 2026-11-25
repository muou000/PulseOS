# RV64 网络负载的 CPU-clock 采样，2026-11-25

回环 iperf3 的 2,013 个内核样本中，33 个中断 PC 落在 TCP 软件校验和计算，保存的调用链把其中 21 个定位到发送端、12 个定位到接收端。短连接 HTTP 的 1,922 个内核样本中，16 个 PC 位于 memset，其中 14 个调用链包含 TCP 新建 socket 或处理 SYN。这两条路径适合用同一应用做改动前后测量。四个 capture 的会话状态均为 **IncompleteError**。下面报告收到的样本和可辨认的调用链，CPU 利用率与精确耗时均未知。

## 采样范围

QEMU RISC-V virt，8 vCPU、8 GiB、-cpu max、VirtIO MMIO、user 网络后端。每个场景一个采样窗口。idle 时 darkhttpd 与 iperf3 server 已监听，未发起客户端负载。loop 和 virtio 分别在来宾运行 iperf3 TCP 单流客户端 16 秒，目的地为 127.0.0.1 和 10.0.2.2 上的服务器。全程接收端分别为 80.2、51.8 Mbit/s。HTTP 在来宾回环运行 weighttp，以四个并发连接逐请求重新建连访问 darkhttpd 的 61 字节页面。三项负载均在 recorder 前启动，采样后 kill -0 成功，最终退出码为 0。HTTP 客户端 JSON 可完整独立解析，退休 1,500 个请求、1,500 个 2xx、0 fail、0 errs、91,500 正文字节。该次 HTTP 运行中客户端重定向与服务端日志使用了同一个路径，未把服务端日志作为这一窗口的独立成功计数。采样时宿主另有任务，应用全程数字只标识该工作负载。

生产版 bpf-record 配置如下。四个真实 RV64 capture 均在 recorder 日志中以 duration 停止、返回 0，RECORD SAVED 的字节数与 SHA256 与宿主一致，v6 解析器成功读取 trailer。没有选用 PID、CPU 子集、二次时间窗或用户态符号筛选。

```sh
/root/bpf-record --events cpu --cpus all --callchain fp --period-ns 10000000 \
    --duration-ms 3000 --buffer-pages 64 --kernel-elf /boot/kernel.elf --output CASE.pbcap
bpf-analyzer CASE.pbcap --loss
bpf-analyzer CASE.pbcap --artifact-manifest
bpf-analyzer CASE.pbcap --weight period --json
bpf-analyzer CASE.pbcap --mode kernel --weight period --json
```

各项内核样本占比统一除以该窗口**全部已保留的内核态样本数**。软件时钟实际样本权重均为 10,000,000 ns，故同一窗口的 period 权重占比等于条数占比。8 个 CPU 的权重可以重叠，不能当成整个窗口的实际 wall time。FP 深度上限 32、读栈预算 512 字节，没有 fallback。中断 PC 原值用于叶地址，返回地址减 1 用于定位 caller 的调用点。GNU addr2line 2.42 配合验证过的内核符号表工作；给出的源码行是人工核对的入口。

| 场景 | 全部 / 内核 / 用户样本 | 内核 nominal 权重（秒） | 内核链完整 / 部分 / 不可用 | system timer_busy | 各源 skipped / cancelled |
|---|---:|---:|---:|---:|---:|
| idle | 2142 / 2132 / 10 | 21.32 | 229 / 6 / 1897 | 141 | 260 / 1 |
| loop | 2018 / 2013 / 5 | 20.13 | 264 / 183 / 1566 | 144 | 364 / 9 |
| virtio | 2137 / 2125 / 12 | 21.25 | 367 / 130 / 1628 | 124 | 255 / 4 |
| http | 1954 / 1922 / 32 | 19.22 | 272 / 251 / 1399 | 120 | 436 / 4 |

逐源记录数按 CPU 0 至 7 列出，logical source 1 至 8 与 CPU 顺序一一对应。每个数字乘以 10,000,000 即该源保留的 period_ns。已用每条事件 sequence_index 核对 recorder 的 record_sources 项，与各源声明、CPU、retained_samples、delivered 和 kernel event 身份匹配。小结 JSON 另列每源观测、跳过、取消和权重。

| 场景 | CPU 0–7 保存的样本数 |
|---|---|
| idle | 286, 254, 254, 253, 287, 283, 246, 279 |
| loop | 258, 273, 266, 264, 246, 228, 255, 228 |
| virtio | 264, 276, 280, 276, 260, 256, 284, 241 |
| http | 236, 247, 255, 260, 239, 239, 258, 220 |

四个会话的 source transport_lost、export_discarded、emission_gap 均为 0。8 个 sink 的 transport_lost、consumer_corrupt、consumer_bounds 均为 0，program errors 均为 0。consumer 中 PERF_RECORD_LOST、ringbuf_lost、discarded_records、corrupt、out_of_bounds 也均为 0。system timer_busy 与 source skipped / cancelled 各自保留，统计口径重叠。旧版 loss_counters 字段为 null。四次 mapping journal dropped 均为 0，mapping_artifact_identity_unknown 分别为 13、37、71、104。分析器全会话 attribution_claim_allowed=false；查询内核模式未改变该状态。idle 的内核部分链以 5 个 nonmonotonic_frame 和 1 个 invalid_frame 结束，其余三次内核部分链均为 nonmonotonic_frame。用户栈终止原因、可用的代表性链、受影响区间的身份限制均不改变已保存的叶 IP。该报告没有对用户 PC 分配函数名称。

## 观察到的内核执行路径

| 每条内核样本计一次，同一条可在多列出现 | idle | loop | virtio | http |
|---|---:|---:|---:|---:|
| 叶函数 run_idle | 1830 | 1457 | 1583 | 1308 |
| 链含 SocketSetWrapper::poll_interfaces | 0 | 154 | 217 | 145 |
| 上一行中同时含 WaitQueue notify | 0 | 47 | 23 | 54 |
| poll 样本中同时含 RawMutex | 0 | 15 | 3 | 22 |
| 叶函数 ip::checksum::data | 0 | 33 | 8 | 1 |
| 叶函数 memcpy | 3 | 26 | 5 | 13 |
| 叶函数 memset | 2 | 5 | 0 | 16 |
| 叶 IP 前一条指令为 csrs sstatus,rs | 2087 | 1841 | 2039 | 1722 |

- **回环校验和。** 在 loop 的 33 个 checksum 叶样本（1.64%）中，24 个停在 0xffffffc080572fba，其余 9 个停在 0xffffffc080573000。匹配 ELF 显示它们落在校验循环。采到的发送链经过 dispatch_ip / emit_payload，接收链经过 process_tcp。这与 LoopbackDev::capabilities 使用 DeviceCapabilities 默认 Checksum::Both 一致。可单独评估内部回环不重复计算和验证 TCP checksum 能否改善单流吞吐。真实网卡路径、端到端字节及仍需校验的外部/可注入报文应作为控制条件。没有该改动的性能测量。[回环能力](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/net/src/smoltcp_impl/loopback.rs#L109) · [smoltcp 默认值](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/crates/smoltcp/src/phy/mod.rs#L169)
- **socket 就绪扫描与唤醒。** 保存链中含 poll_interfaces 的比例分别为 0%、7.65%、10.21%、7.54%。HTTP 存有 sys_close → TcpSocket::shutdown → poll_interfaces → WaitQueue::notify_one_with_context，以及经 RawMutex 的等待链。loop 和 virtio 还有 sys_write → TcpSocket::send → poll_interfaces 的链。源代码逐项遍历 socket、查询就绪并收集待唤醒队列，可评估扫描、同一就绪状态下重复通知和调用频率。可用分阶段计数核对每次 poll 的扫描项、实际状态变化、有效唤醒和任务吞吐，保留边沿、阻塞和并发正确性。样本支持定位路径，无法区分每一次通知是否必要、也没有量出锁等待时间。[扫描和通知](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/net/src/smoltcp_impl/mod.rs#L306)
- **短连接建连与清零。** HTTP 的 16 个 memset 叶样本中 14 个保存了 ListenTable::incoming_tcp_packet 或 TcpSocket::new 的调用链。实例为 CPU 6、单调时钟 81,344,080,100 ns、IP 0xffffffc0805a732a、部分链终止于 nonmonotonic_frame。代码为每个 smoltcp TCP socket 初始化各 256 KiB 的 RX、TX 缓冲，实际写入量和分配生命周期值得与短连接创建率一起测量。此处 14/1922 是观测到的链，无法据此估算改变缓冲策略后的收益。[TCP 缓冲分配](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/net/src/smoltcp_impl/mod.rs#L211) · [收到 SYN 的创建入口](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/net/src/smoltcp_impl/listen_table.rs#L175)
- **VirtIO 的中断边界。** virtio 的 139 个 VirtIoNetDevWrapper 叶样本中，135 个位于 csrs sstatus 之后。transmit、recycle_rx_buffer、recycle_tx_buffers 中分别有 66/68、45/47、11/13 个集中在同一类位置。反汇编与 driver wrapper 的锁释放吻合。定时 IRQ 观察被打断的 PC，IRQ 关闭区间可能要到重新使能时才被观察，这些位置无法量化锁里面的硬件 I/O/复制/排队成本。若优化该处，需要独立的临界区、队列或真实发送计数。idle 中 1,829 个样本同样聚集于 run_idle 的 0xffffffc080595fb4，即 csrs sstatus 后的下一条指令。没有 IRQ 驻留与 idle 时间线，无法从这些样本推出精确的 CPU 忙闲、IRQ 占用或锁竞争百分比。[VirtIO wrapper](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/driver/src/virtio.rs#L319) · [IRQ observer](https://github.com/muou000/PulseOS/blob/39e61bab5903b773666d54123b51f66aa2ab8101/modules/process/src/bpf/sampling.rs#L88)

## 身份与复现

源码 commit 39e61bab5903b773666d54123b51f66aa2ab8101，BPF-enabled 内核构建 provenance 记录干净的源输入。QEMU 命令指向的内核 bin 和保留的 kernel.elf 均与构建 provenance 的 SHA256 相符。四个 capture 的 kernel artifact SHA、GNU build-id 和运行时 _stext 与 ELF 匹配。采样镜像身份由本地制盘记录提供；capture 自身的 image_hash 和 pulse_commit 均为 unknown。生产 recorder 与 build.json、四个 capture 内的 artifact 身份相符。执行机本地留存了原始 capture、完整串口日志和匹配 ELF，无公开原始归档或保留期限保证。重放需要取得对应的原始 capture 及 ELF。

[分场景采样证据](profile.json) 含四个 SHA、工具/镜像身份、分层 loss、所有链终止原因、逐源权重、主要叶 PC 和代表性调用链。可按上文的 recorder 和 analyzer 命令复采及核对。火焰图、用户态符号导出、跨架构采样对照和内核改动后的 A/B 均未执行。[环境记录](../environment.json)
