#import "../components/prelude.typ": *

= 网络模块

PulseOS的网络模块实现大部分工作由AI完成。

== 套接字抽象与多态实现

网络模块在 `pulse_core/src/net/mod.rs` 中被统一抽象并集成至 VFS 多态接口下。其核心的 `Socket` 结构体包含具体的 `SocketInner` 枚举，统一了对不同网络协议类型的控制：

```rust
// pulse_core/src/net/mod.rs

pub struct Socket {
    pub domain: AtomicU32,
    pub inner: SocketInner,
    pub pending_send: Mutex<alloc::vec::Vec<u8>>,
    pub pending_addr: Mutex<Option<core::net::SocketAddr>>,
    pub rx_shutdown: AtomicBool,
    pub tx_shutdown: AtomicBool,
}

pub enum SocketInner {
    Tcp(TcpSocket),
    Udp(UdpSocket),
    Local(LocalSocket),
    Packet(PacketSocket),
    Netlink(NetlinkSocket),
}
```

1. Tcp / Udp 套接字：
   - 封装底层的 `axnet` 驱动，并调用 `smoltcp` 完成 IP、TCP、UDP 协议栈的数据包分发、解析和滑动窗口维护。

2. Packet 原始套接字（Mock 桩实现）：
   - 提供 `AF_PACKET` 类型的原始链路访问抽象，支持相关的套接字配置选项。目前为 Mock 占位实现，写操作会直接丢弃数据包并报告成功，读操作返回 `0`。

3. Netlink 通道（静态 Mock 实现）：
   - 提供了对 `AF_NETLINK` 协议族的支持。目前采用静态响应机制，主要用于解析用户空间的网络配置查询请求，硬编码返回静态的本地环回接口 `lo` 和以太网网卡 `eth0`（IP 默认为 `10.0.2.15`，MAC 默认为 `52:54:00:12:34:56`），以保证用户空间的网络管理与查询工具能顺利读取配置。

== Netlink 接口解析与构建

为了向用户态网络管理程序提供网络状态报告，`NetlinkSocket` 实现了对 `RTM_GETLINK` 和 `RTM_GETADDR` 消息的静态 Mock 支持：
- 当用户态向 Netlink 发送写请求时，内核解析 Netlink 消息头部的前 16 字节，提取消息类型与序列号。
- *静态 Mock 状态生成*：
  - `RTM_GETLINK`：硬编码构建 `ifinfomsg` 结构及嵌套的 RTA 属性，静态返回本地环回接口 `lo` 和以太网网卡 `eth0` 的链路状态。
  - `RTM_GETADDR`：硬编码构建 `ifaddrmsg` 结构，静态返回 `lo` 接口的 `127.0.0.1` 地址和 `eth0` 网卡的 `10.0.2.15` 地址。
- Netlink 结构定义：
  ```rust
  pub struct NetlinkSocket {
      pub rx_data: Mutex<alloc::vec::Vec<u8>>,
      pub read_offset: Mutex<usize>,
      pub nonblocking: AtomicBool,
  }
  ```
- 将组装好的静态 Netlink 消息存入 `rx_data` 缓冲区，供用户态随后通过读系统调用读取，从而使 iproute2 工具链中的基础查询指令能在 PulseOS 上顺利运行并获取模拟配置。

== 套接字控制 Ioctl

在套接字的 `ioctl` 系统调用处理中，PulseOS 提供了对网络测试及工具链关键控制命令的静态 Mock 兼容：
- `FIONREAD`：
  用于读取当前网络套接字接收缓冲区中未读的数据字节数。内核通过调用 `recv_queue()` 得到缓冲长度（如 TCP/UDP 底层队列，或 UNIX 域套接字的环形缓冲区可读大小），并将长度写入用户态指定的参数指针。
- `SIOCGIFCONF`：
  用于检索网络接口的配置列表。为了让 `ifconfig` 等工具能够顺利执行查询，内核实现了该命令的静态响应，向用户态传入的 `ifconf` 结构体中的 `ifreq` 数组格式化回填环回接口 `lo`与以太网网卡 `eth0`的静态配置，满足用户态的网络信息初始化与呈现需求。
- 其它接口控制命令，如 `SIOCGIFFLAGS`、`SIOCGIFHWADDR`、`SIOCGIFMTU`、`SIOCGIFTXQLEN`：
  内核同样提供了静态 Stub 支持，返回硬编码的网卡 Flags、MTU值、MAC地址和发送队列长度，从而实现了对 `ifconfig` 工具完整查询链的静态兼容。

== 本地套接字退化与多态映射机制 AF_UNIX

PulseOS 在处理 UNIX 域套接字 `AF_UNIX` 时采用了极度简化的方案：针对普通命名套接字，退化为回环网络以减少内核协议栈的独立开发开销；针对成对匿名套接字，则使用专用的内存管道缓冲区。

- 普通套接字退化与映射：
  - 套接字映射：在 `sys_socket` 系统调用中，如果请求 `AF_UNIX` 域，则根据类型直接映射为普通的 `TcpSocket`（流式 `SOCK_STREAM`）或 `UdpSocket`（数据报 `SOCK_DGRAM`）。
  - 地址绑定 bind：如果是 pathname 类型的套接字，内核在 VFS 对应的路径下创建一个空文件节点，以便文件系统可见。随后将套接字绑定到本地回环网络 `127.0.0.1:0`，由底层 `smoltcp` 随机分配一个空闲的本地端口。最后，将套接字路径与本地端口的映射关系注册进全局的 `UNIX_REGISTRY` 中。
  - 建立连接 connect：当另一个套接字连接到该 UNIX 路径时，内核查询全局 `UNIX_REGISTRY`，检索对应的本地回环端口号，并在底层网络协议栈上直接发起对 `127.0.0.1:端口` 的 TCP 或 UDP 连接。

客户端连接本地 UNIX 域套接字服务端的过程时序如下：

#align(center)[
  #image("../img/14.png", width: 105%)
]

- 与通过 `sys_socket` 创建的单体套接字不同，通过 `sys_socketpair` 系统调用创建的匿名对套接字，在内核中由 `SocketInner::Local` 分支接管。其底层直接构建了基于 `LocalSocketRingBuffer` 的物理环形缓冲区，读写双方在内存中直接拷贝数据，从而提供无网络栈参与的极速本地进程间通信支持。