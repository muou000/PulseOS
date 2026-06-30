#import "../components/prelude.typ": *

= 文件系统

== VFS 架构与描述符管理

=== FdTable 与 FdObject

PulseOS 中的虚拟文件系统采用面向对象的接口抽象设计，以支持多种文件类型的多态化处理。所有能够进行 I/O 操作的内核实体，如常规文件、目录、管道、网络套接字与事件描述符，都被统一抽象为描述符对象:

- *`FdObject` Trait*：定义了对描述符的操作接口，包括 `read`、`write`、`ioctl`、`seek`、`poll` 以及可阻塞等待就绪的 `wait_ready`，为内核提供了极佳的解耦能力。`FdObject` 提供了一系列带有默认错误的实现，使得具体的实体对象仅需实现其所支持的操作。
- *`FdTable` 结构*：包含一个存储 `Option<FdEntry>` 的动态向量数组 `entries`，以及一个基于位图的 `open_fds`。它利用位操作进行空闲描述符槽位的高效检索，并在空间不足时进行指数级动态扩容。

#figure(
  ```rust
  pub trait FdObject: Send + Sync {
      /// 用于向下转型为 dyn Any 以便获取具体实现类型
      fn as_any(&self) -> &dyn Any;

      /// 描述符的读取操作，默认返回 EBADF
      fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
          Err(LinuxError::EBADF)
      }

      /// 描述符的写入操作，默认返回 EBADF
      fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
          Err(LinuxError::EBADF)
      }

      /// 设备控制 I/O 操作，默认返回 ENOTTY
      fn ioctl(&self, _cmd: u32, _arg: usize) -> LinuxResult<isize> {
          Err(LinuxError::ENOTTY)
      }

      /// 查询当前描述符的 I/O 事件就绪状态
      fn poll(&self) -> LinuxResult<PollState>;

      /// 移动描述符读写指针，默认返回 ESPIPE
      fn seek(&self, _pos: SeekFrom) -> LinuxResult<u64> {
          Err(LinuxError::ESPIPE)
      }

      /// 可阻塞地等待描述符的指定事件就绪，默认返回 EOPNOTSUPP
      fn wait_ready(&self, _events: i16, _deadline: Option<Duration>) -> LinuxResult<bool> {
          Err(LinuxError::EOPNOTSUPP)
      }

      // ... 包含 stat, set_nonblocking, location 等其他辅助或特定类型的方法
  }
  ```,
  caption: [FdObject 抽象接口定义],
) <FdObject-abstraction>

==== 多态实现

`FdObject` 支撑了 PulseOS 中丰富且多态的内核实体：

#align(center)[
#table(
  columns: (auto, auto, 1fr),
  align: (left, left, left),
  [*实体分类*], [*具体实现结构*], [*说明*],
  [标准 I/O 实体], [StdinObject, StdoutObject], [封装控制台 TTY 读写，内置 STDIN_WAIT_QUEUE 支持异步就绪唤醒。],
  [文件系统实体], [FileObject, DirObject], [封装常规文件与目录的底层 `axfs` 系统调用交互。],
  [进程与控制句柄], [PidfdObject], [进程文件描述符，提供跨进程信号发送与状态监测机制。],
  [低延迟控制], [CpuDmaLatencyObject], [用于电源管理与低延迟 DMA 调优的专用描述符。目前底层驱动并未使用该限制值，其实现主要是为了满足 `cyclictest` 测例的运行要求。],
  [IPC 与网络通信], [PipeObject, Socket, EpollObject], [分别对应管道双端、网络套接字以及事件多路复用轮询实体。],
)
]

==== $O(1)$ 位图分配与指数扩容机制

为了高效管理海量描述符槽位，`FdTable` 采用二级管理机制：
1. *二级位图检索*：`open_fds` 存储为 `Vec<u64>`，每个 bit 对应一个描述符。在分配描述符时，通过对对应 `u64` 字的位操作定位空闲位。这能在单个字范围内实现 $O(1)$ 级时间复杂度检索。
2. *指数动态扩容*：系统初始化时 `entries` 保持较小规模。当申请的描述符超出当前向量容量时，系统将触发以2倍指数级自动对 `entries` 和 `open_fds` 进行扩容，最大扩增至内核硬上限 `FD_LIMIT` ($1048576$)，这既节省了冷启动内存，又保障了大并发场景下的平滑扩容。

=== 共享描述符表并发访问控制

为了在多核多线程环境下保障描述符表的并发安全，PulseOS 采用了精细化的双重锁同步设计：

1. *表元数据同步锁*（`SharedFdTable = Arc<RwLock<FdTable>>`）：
   - 并发读锁：当线程执行常规 I/O 读写时，只需调用 `fd_table().read()` 获取读锁以取得 `Arc<dyn FdObject>`，允许并发操作不同的描述符，从而实现极高的吞吐率。
   - 排他写锁：当创建、复制或关闭描述符时，获取写锁 `write()`，以确保描述符表元数据（如 entries 的扩容、计数及位图）的一致性。
2. *进程级表指针锁*（`Process::fd_table: RwLock<SharedFdTable>`）：
   - 用于同步进程层面的描述符表切换。例如，当线程调用 `sys_unshare(CLONE_FILES)` 解除与父进程的描述符共享时，通过获取该锁的写锁来安全地将进程的 `SharedFdTable` 指针替换为私有拷贝，防止表替换与多线程并发访问发生竞态。

=== exec时的CLOEXEC延迟释放

在执行 `exec` 时，系统会调用 `take_cloexec_on_exec()`，查找所有带有 `CLOEXEC` 标志的描述符项并将其从表中移除。为了缩短写锁的持有时间，PulseOS 在设计上采用了延迟析构策略：

关闭文件描述符或网络套接字等实体可能会伴随着耗时的 I/O 同步、缓冲区刷新或底层设备通信。如果直接在持有一级写锁的临界区内释放这些实体，将造成严重的锁阻塞。因此，我们选择使用`take_cloexec_on_exec`在临界区内将所有带有`CLOEXEC`标志的描述符项提取并打包到一个临时 `Vec<FdEntry>` 向量中并返回。当离开作用域释放写锁后，在临界区外对该向量执行 `drop`，完成底层 `FdObject` 引用计数的归零及物理句柄的真正释放。

这一流程的时序关系如下：

#align(center)[
  #image("../img/9.png", width: 120%)
]

== VFS 挂载树与路径越界解析机制

PulseOS 支持高度灵活的多源文件系统挂载与传播机制,这一部分主要由AI在LTP中fs_bind及相关测例中实现。
- *挂载节点 `Mountpoint`*：代表文件系统的挂载实例。它并没有直接存储目标文件系统引用，而是拥有挂载点的根目录项 `root: DirEntry`（其内部已绑定特定文件系统）。它不直接拥有父挂载点引用，而是通过包装了父挂载点上下文的路径游标 `location: Option<Location>` 间接回溯；同时，它通过子挂载点弱引用集合 `children: Mutex<HashMap<(u64, usize), Weak<Mountpoint>>>` 来建立挂载树树枝，以 `(inode, fs_ptr)` 对作为唯一键。使用 `Weak` 弱引用可避免父子挂载点循环引用导致的内存泄漏。
- *路径游标 `Location`*：包含了当前的节点 `entry: DirEntry` 以及它所属的挂载实例 `mountpoint: Arc<Mountpoint>`。当路径解析跨越挂载边界时，`Location` 会自动切换 `Mountpoint` 上下文。
- *挂载传播*：PulseOS VFS 实现了完整的挂载传播状态机，支持共享挂载（Shared）、从属挂载（Slave）、私有挂载（Private）与不可绑定挂载（Unbindable）等类型，并能在挂载/卸载时在对等组（Peer Group）成员间进行递归传播或联动清理。

=== 双向挂载边界越界解析机制

路径解析在跨越挂载点边界时表现为双向解析：

1. *向下越界（进入挂载点）*：
   当路径解析器尝试访问下一个子目录（如 `mnt_dir`）时，系统会先在当前目录的子项中检索出相应的 `DirEntry`。接着，在当前挂载点的 `children` 映射表中以该 `DirEntry` 的 `entry_key` 即 `(inode, fs_ptr)` 作为键进行查找。如果命中（即该子目录为挂载点），则将 `Location` 切换为子挂载点实例，并将 `entry` 指向子文件系统的根目录。

   时序关系如下所示：

#align(center)[
  #image("../img/10.png", width: 105%)
]

2. *向上越界（回溯至父挂载点）*：
   当在当前挂载点的根目录下解析父目录时，若当前 `Location` 已是当前挂载点的根目录（即 `is_root_of_mount()` 为真），路径解析器将回溯其绑定的挂载位置 `mountpoint.location()`，安全跨越边界返回到父挂载点中挂载该子挂载点的那个父目录的 `Location`，从而实现挂载树的无缝逆向遍历。

=== 挂载传播与联动机制

PulseOS 支持复杂的挂载传播机制，通过一个全局的对等组注册表 `PEER_GROUPS: Mutex<HashMap<u64, Vec<Weak<Mountpoint>>>>` 维护共享组关系：
- *传播类型*：包含 `Private`（无传播）、`Shared`（与对等组成员同步共享）、`Slave`（接收来自 Master 的传播，但不反向传播）、`SharedAndSlave`（混合模式）以及 `Unbindable`（防止无限绑定复制）。
- *挂载子树递归传播*：在对对等组进行挂载时，若目标父挂载点处于共享模式，新挂载会通过 `propagate_new_mount` 生成副本并递归复制挂载子树，传播至组内所有成员。
- *联动卸载*：在执行 `unmount` 时，系统会递归收集并联动卸载所有因挂载传播而在其他对等组成员中自动生成的关联挂载，保证系统状态的一致与清洁。



== ext4驱动替换与文件系统性能优化

=== 替换的背景

为了实现更加健壮和高效的持久化存储支持，我们在开发后期决定将 `ext4_rs` 替换为 `ext4plus`，原因有以下几点：

- `ext4_rs` 驱动在设计上是完全同步的，这导致其极难适应高并发或未来可能引入的异步 `async/await` 磁盘 I/O 运行时。而 `ext4plus` 在库级层面实现了高度的同步/异步编译解耦，能无缝适配异步块层，为 PulseOS 后续向全异步与中断化文件系统的演进奠定了基础。

- `ext4_rs` 默认采用直写机制。我们曾为其引入了缓存层，但暴露出数据不一致以及死锁竞态等安全隐患。此外，它也缺失了许多 ext4 的高级特性；尽管我们实现了动态块大小等特性，但在进一步尝试支持日志机制时遇到了大量问题，这促使我们决定将其彻底替换。

- 在方案的选择上，我们曾尝试过ArceOS默认的 `lwext4_rust` 并进行了性能对比。虽然其读写速度与当时的 `ext4_rs` 基本持平（当时的性能瓶颈实际上主要在 VFS 层），但考虑到其缺乏 `ext4plus` 优秀的异步扩展性，我们最终放弃了该方案。


=== 移植过程中axfs/vfs稳健性改进与优化

在将 `ext4plus` 整合进 PulseOS 虚拟文件系统的过程中，我们对 `axfs` 和 `vfs` 层进行了深度的健壮性改进与性能优化。

在安全方面，我们将磁盘 I/O 锁由自旋锁升级为睡眠锁，允许 I/O 等待时出让 CPU 以防范忙等死锁；同时，引入了 Inode 缓存命中时的父级弱引用更新机制、防重入的全局刷盘任务过滤器 `FLUSHING_TASKS`，以及用于推迟已删除文件物理释放的 `pending_deletions` 延迟回收队列，有效解决了锁重入死锁、内存泄漏和解挂载漏洞。

在性能提升方面，我们设计了 8 槽位最近关闭文件缓存，实现了 4KB 对齐的 DMA 零拷贝直通读写；同时，通过优化 `query_user_page_slice` 大缓冲区边界的一次性验证，以及 Futex 调度锁前的物理页预翻译，大幅消除了 VMA 检索开销，并规避了调度临界区内的缺页死锁风险。

在这一系列改进实施后，我们使用 qperf 对 `iozone` 中的各项测试进行了性能数据采样。`iozone` 测试中 57.22% 的 CPU Ticks 处于空闲等待状态，这主要源于内核主任务在等待 I/O 完成时的阻塞。这表明当前的性能瓶颈已转移到慢速磁盘 I/O 硬件本身导致的任务阻塞上。因此，PulseOS 的下一阶段改进计划将从异步化与中断化着手。

#par(first-line-indent: 0pt)[
从 ext4plus 文件中读取数据块的链路如下：
]

#align(center)[
  #image("../img/11.png", width: 105%)
]

== 文件锁与flock机制

PulseOS 实现了标准的`flock`文件锁语义，用于在多个进程或线程之间同步对同一个文件的访问：
#par(first-line-indent: 0pt)[
锁目标识别 `LockTarget`：支持两种锁定颗粒度：
]

  - `Location`：基于底层文件系统的 `fs_id` 和文件的 `inode` 号进行识别。这是标准的文件锁，所有指向同一物理文件的描述符共享同一个锁状态实例进行争用；但在由 `dup`/`fork` 复制的描述符之间由于共享同一个描述符对象，因而共享该锁的持有权。
  - `FdObject`：基于描述符对象的内存指针地址进行识别。

#h(2em)
锁状态`LockState`包含锁的类型，即 Shared 共享锁或 Exclusive 排他锁，当前持有此锁的所有者列表 `owners`，以及用于阻塞等待的等待队列 `wait_queue`。
全局锁表 `FLOCK_MAP`：所有的文件锁都被汇总存放在一个全局静态的 B 树映射表 `FLOCK_MAP: Lazy<Mutex<BTreeMap<LockTarget, LockState>>>` 中，由一个 `spin::Mutex` 锁进行全局保护。

在阻塞等待锁释放的过程中，`do_flock()` 会在每次被唤醒时通过 `current_has_pending_signal` 检查当前线程是否有挂起的未屏蔽信号。若有，则立即返回 `EINTR` 中断错误，支持标准的 POSIX 信号打断语义。

#par(first-line-indent: 0pt)[
进程 A 申请排他锁被阻塞，等待进程 B 释放锁后被唤醒的流程如下：
]

#align(center)[
  #image("../img/12.png", width: 108%)
]

== 特殊文件系统

PulseOS 在 `axfs/src/fs` 中实现了多种特殊文件系统，用来向用户态提供运行期状态以及虚拟硬件接口：

1. `procfs` 进程文件系统：
   - `/proc/self`：动态指向当前发出请求的进程 PID 目录的符号链接。
   - `/proc/meminfo`：向用户态 `free` 等工具动态回填系统内存总量、空闲量及可用量。
   - `/proc/filesystems` 和 `/proc/cpuinfo`：动态回填当前系统支持的文件系统列表及 CPU 处理器硬件信息。
   - `/proc/sys/kernel/`：提供 `pid_max`、`tainted`、`core_pattern` 等内核配置状态节点。
   - `/proc/[pid]/maps`：通过遍历进程 `MemorySet` 中的各个虚拟区域，动态拼接虚拟地址段、权限、偏移量、设备号、Inode 以及关联文件路径，格式化输出给用户态程序。
   - 进程描述符扩展：在 `/proc/[pid]/` 目录下支持 `fd/`、`ns/`(stub)、`children`以及 `task/`。
2. `devfs` 设备文件系统：
   - 动态提供 `/dev/null`，该节点会丢弃所有写入并在读取时返回 EOF；`/dev/zero`，能无限提供 0x00 字节；`/dev/tty` 与 `/dev/console`，提供控制台字符通道输入输出。
   - 提供 `/dev/random` 与 `/dev/urandom`，通过 PCG 随机数生成算法提供伪随机数流。
   - 设备控制及虚拟硬件：提供 `/dev/cpu_dma_latency` 和 `/dev/loop-control`，并能将系统检测到的磁盘等块设备动态注册为 `/dev/vd*` 块设备节点。
3. `tmpfs` 临时文件系统：
   - 支持高并发的临时文件创建与读写。由于采用全内存读写，且与 VFS 层的页缓存系统深度集成，在检测到 `tmpfs` 时会自动实例化无容量限制的内存页缓存作为介质，保证了编译、解压等测试项的高吞吐性能。
