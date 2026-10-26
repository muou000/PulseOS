# PulseOS

PulseOS is a multi-architecture kernel whose domain model spans processes, descriptors, user memory, filesystems, and guest-visible system calls.

## Language

### Descriptor and I/O behavior

**就绪等待**:
等待一组描述符达到请求事件，同时处理通知、信号和 deadline，并返回每个描述符的观察结果。
_Avoid_: readiness polling, generic waiting

**I/O 操作**:
在用户缓冲区、描述符对象和文件位置之间完成一次或多次读写，并定义部分完成、错误和信号结果。对支持多段流式读写的对象，单次 I/O 操作可在一次文件位置与缓存锁周期内消费或填充多个缓冲段。
_Avoid_: read/write helper, transport operation

**钉住用户缓冲段列表**:
将一段或多段用户虚拟内存范围验证并钉住（持有物理页框生命周期引用）后形成的离散物理页段集合（Scatter-Gather 缓冲），在 I/O 期间保证底层页框不被回收，并在析构时批量归还零引用页框。
_Avoid_: contiguous pinned slice, raw user pointer list

**DMA 缓冲分片注册表**:
按虚拟地址空间分片（2 MiB 颗粒度）管理的物理连续 DMA 缓冲区所有权与租约注册表。支持底层块设备驱动以单分片局部锁快速反查与申领（claim），跨分片锁获取严格升序以避免死锁，消除全局自旋锁争用。
_Avoid_: global dma registry, monolithic buffer map

**可复用写回连续页池**:
用于 Page Cache 批量脏页写回的高阶连续物理页缓冲池。写回批次完成后将高阶连续页组归还池中供后续批次直接复用，避免每次写回批次重复向伙伴系统申请和释放高阶连续页。
_Avoid_: static bounce buffer, buddy churn cache

### Memory and process lifecycle

**映射页生命周期**:
文件或匿名页从准备、发布到映射、TLB 完成、脏页发布和退休的全过程。`prepared` 资源尚未发布，只能由其准备对象清理；`published` 映射必须等待 TLB completion 后才能退休。文件 fault 的准备还携带 mapping identity 和权限快照，用于拒绝同一虚拟地址上的陈旧提交。脏页发布只更新 page-cache 状态，storage durability 还需要显式同步。
_Avoid_: page-cache wrapper, mapping helper

**批量物理页框归还**:
将延迟退休、页缓存淘汰与钉住缓冲析构中收集到的多个待释放物理页框（含物理不连续的页段），在释放上层业务锁后，通过单次分配器临界区批量归还给底层页分配器或每 CPU 页缓存池的过程。
_Avoid_: per-page dealloc loop, locked frame free

**每 CPU 物理页框热缓存池 (PCP)**:
每个 CPU 维护的有界本地 Order-0 物理页框缓存池。无约束单页分配与单页释放优先在本地完成以避免全局 Buddy 自旋锁竞争；本地池空时单次持锁批量补水，达到高水位或全局内存紧缺时批量排水归还 Buddy。
_Avoid_: per-cpu buddy, per-thread page cache

**子进程退休**:
终态 child 被 wait 消费后，完成 accounting、task 引用、资源缩减、描述符影响和全局注销的过程。
_Avoid_: child cleanup, process deletion

### IPC

**管道容量**:
同一匿名管道或命名 FIFO 的读写端共同使用的缓冲字节上限；统计普通缓冲与零拷贝页中尚未读取的数据。
_Avoid_: pipe buffer length

**信号量事务**:
对同一 System V 信号量集的一组操作作为一个状态转换：只有全部操作可满足时才提交，否则保持状态并等待、超时或返回错误。
_Avoid_: semaphore batch, semaphore helper

**共享内存附着**:
一个进程将共享内存段映射到自己的地址空间并取得该段的附着 ownership；解除附着同时撤销映射并释放该进程的附着记录。
_Avoid_: shared memory handle, mapping helper

### Performance observation

**BPF 性能采样器**:
PulseOS 中的性能数据记录与分析入口。它通过受控的 BPF 程序观察内核性能事件，生成可供主机侧分析的采样数据，已完全替代旧版 qperf。
_Avoid_: qperf plugin, generic tracing

**qperf 基线（已退役）**:
早期基于 QEMU 插件的指令采样与内核事件记录链路，已完全退役并由 BPF 性能采样体系替代。
_Avoid_: BPF backend, permanent BPF ABI

**Linux BPF 兼容层级**:
PulseOS 对 Linux BPF 用户态接口和语义的明确支持范围。层级内的接口应保持可观察的 Linux 行为；层级外的能力可以暂不实现，但必须以稳定、可诊断的错误拒绝，而不能暗示完整兼容。
_Avoid_: full Linux compatibility, private BPF API

**具名工具兼容层级**:
为固定版本的上游工具建立独立版本化的最小 Linux BPF 能力集，使该工具源码无需 PulseOS 专属修改即可运行；该层级只承诺该工具实际使用的接口，不代表通用 Linux BPF 兼容。
_Avoid_: full Linux compatibility, tool-specific private API

**libbpf 核心工作流**:
固定版本范围内，用户态 libbpf 对 BPF ELF 对象执行 open、load、attach、事件消费和 teardown 的可复现路径；它是兼容验收范围，不等于支持全部 libbpf API。
_Avoid_: full libbpf compatibility, BPF syscall only

**上游采样工具兼容目标**:
在固定上游版本、可复现构建和明确调用参数下运行的具名 Linux 采样程序；通过该目标只证明其约定工作流可执行并产生真实采样，不代表兼容所有 Linux 工具或全部 BPF API。
_Avoid_: full Linux BPF compatibility, generic tool support

**BPF ELF 对象**:
包含 eBPF 程序、Map 定义、section 信息和重定位记录的用户态对象文件，由 libbpf 解析并转换为 Linux BPF 对象模型操作。
_Avoid_: ordinary application ELF, kernel BPF bytecode blob

**BTF 元数据**:
描述 BPF 程序、Map 或内核数据类型及其布局的类型信息，可被 libbpf 用于检查和重定位；它不是 eBPF 指令本身。
_Avoid_: event context, ELF section

**CO-RE 重定位**:
libbpf 根据 BTF 将编译时记录的类型/字段引用调整到目标内核布局的兼容机制。未实现的 CO-RE 能力必须显式失败，不能静默跳过。
_Avoid_: generic relocation, fixed-layout BPF

**BPF 对象 FD**:
指向 BPF Map、Program、Link 或 Perf Event 对象的进程文件描述符；它参与对象引用计数、dup/继承、poll 或 teardown 生命周期，不等同于一个不具备所有权语义的整数句柄。
_Avoid_: BPF handle, object ID

**BPF link**:
将已加载 BPF Program 与 tracepoint 或 Perf Event attach point 绑定的独立生命周期对象。Link FD 的关闭或显式 detach 解除绑定，但只有在没有其他引用时才释放底层对象。
_Avoid_: callback registration, qperf marker

**BPF pin**:
将 BPF 对象的引用持久化到 BPF filesystem 路径，使对象可以在原始 FD 或进程结束后通过 `BPF_OBJ_GET` 重新打开；临时进程内对象不具有 pin 语义。
_Avoid_: ordinary file save, object serialization

**eBPF verifier**:
在 BPF Program 获得执行资格前，对指令控制流、寄存器/栈状态、指针来源、内存边界、Map 引用、Helper 参数和资源上限进行静态安全检查的加载阶段。
_Avoid_: bytecode parser, runtime monitor

**BPF interpreter**:
在内核中执行已通过 verifier 的标准 eBPF 指令的跨架构虚拟机。它是执行引擎，不扩大 verifier 接受的程序语言；JIT 是后续可替换的优化实现。
_Avoid_: user-space emulator, native JIT

**BPF helper**:
按 Program 类型授予 BPF 程序调用的、具有固定 Linux helper ID 和参数原型的内核服务。Helper 只有在参数验证、运行时错误和资源影响都被实现后才算支持。
_Avoid_: arbitrary kernel call, syscall from BPF

**BPF context**:
一次 Tracepoint 或 Perf Event 执行提供给 BPF 程序的、版本化且只读的字段集合。Context 只暴露稳定标量和允许的偏移，不暴露 Rust 内部对象、锁或原始内核地址。
_Avoid_: TaskInner pointer, raw event arguments

**语义 tracepoint**:
位于调度、阻塞、唤醒或任务生命周期等稳定语义边界的可发现事件契约；一个语义 tracepoint 可以由多个内部代码路径汇聚触发，不等同于某个函数地址或 qperf 的寄存器 marker。BPF v1 发布前可以调整事件集合，发布后通过追加 ID 或提升 schema version 演进。
_Avoid_: function probe, qperf marker, raw callback

**BPF 采样会话**:
由采样工具显式开始和结束的一段性能观测范围，携带事件配置、程序/Map 标识、时间基准、工作负载或静态对照证据及丢失计数；它不依赖 BuildStorm 等特定应用阶段。
_Avoid_: BuildStorm window, qperf phase marker

**软件 perf event**:
由内核软件计数器产生的可采样事件，例如每 CPU CPU clock 或线程 task clock；它通过 perf event 控制面产生周期样本，不要求业务代码在每个路径手工插入 BPF 调用。
_Avoid_: semantic tracepoint, hardware PMU event

**Perf Buffer**:
以 `BPF_MAP_TYPE_PERF_EVENT_ARRAY` 和每 CPU perf-event mmap 环传输 BPF 记录的 Linux 兼容输出路径；它提供 `PERF_RECORD_SAMPLE` 与 `PERF_RECORD_LOST` 语义，但不保证跨 CPU 全局顺序。
_Avoid_: generic ring buffer, qperf capture

**Ring Buffer**:
以 `BPF_MAP_TYPE_RINGBUF` 提供共享 MPSC 记录传输的输出路径；它可以保持跨 CPU reservation order，但需要独立的共享内存、通知、丢失计数和 verifier reference tracking 语义。
_Avoid_: Perf Buffer, file-backed queue

**BPF normalized event record**:
独立于 Perf Buffer 或 Ring Buffer 的版本化 BPF 事件记录 schema，包含事件 ID、schema version、时间戳、CPU、任务身份和事件字段；输出路径只负责运输，不改变记录含义。
_Avoid_: PERF_SAMPLE_RAW ABI, qperf marker tuple

**BPF capture**:
由一个 BPF 采样会话生成的独立、版本化记录文件，包含采样配置、匹配构建身份、schema registry、normalized records、分层 loss/error counters 和完整性 trailer，供 host analyzer 消费。
_Avoid_: qperf binary, folded report

**BPF 采样丢失**:
采样会话中由于重入、缓冲区满、Helper 失败、解释器预算、Perf/Ring Buffer 生产失败或用户态消费错误而未形成可分析记录的事实；必须按原因、事件、程序、CPU 和会话持久化。
_Avoid_: aggregate drops, parser warning
