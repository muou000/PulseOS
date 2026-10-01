# LTP syscall 宿主测试

在仓库根目录运行：

```bash
cargo test -p pulse_syscalls --lib
cargo test -p pulse_syscalls --lib ltp_
```

第一条执行所有共享校验测试；第二条只执行名称包含 LTP 用例编号的测试。
不需要 QEMU、rootfs 镜像、root 权限或 LTP 的 C 编译环境。

## 实际测试对象

`src/validation/` 保存 PulseOS syscall 的纯参数解析和 ABI 规则。裸机的
`src/impls/` 调用这些函数，宿主 Cargo 测试调用同一份函数。没有调用宿主 Linux
syscall，也没有用成功的 mock 替代 PulseOS 实现。

`Cargo.toml` 将内核运行时依赖限制在 `target_os = "none"`，`src/lib.rs` 同样限制
trap handler 和运行时实现的编译。宿主测试只依赖 `axerrno` 和 `linux-raw-sys`，
避免为了验证参数而链接 CPU 特权指令、页表、驱动和调度器。RISC-V64 与 LoongArch64
的裸机构建仍包含完整 syscall 实现；宿主库不提供 `syscall_handler` 或 `sys_sync`。

测试验证的是解码后的参数和状态转换，不证明 trap ABI、用户内存可访问性或真实
内核资源操作。宿主的 `linux-raw-sys` 绑定也不能证明两种 guest 架构的结构布局。
依赖 `Process`、`Thread`、`SignalShared` 等内核对象的既有 `impls` 测试不在这条宿主
门禁中；原有页对齐 helper 测试已随生产 helper 移入 `validation/mm.rs`。

## 首批 LTP 对照

LTP 源码位于 `../ltp/testcases/kernel/syscalls/`。下表中的“保留断言”均为该 C 用例的
部分语义，不能据此宣称整个 LTP 可执行程序已经通过。无 `ltp_` 前缀的测试是
PulseOS 的额外边界回归，或原有 helper 测试。

| LTP 来源 | Rust 测试模块 | 保留断言 | 仍需要 guest 环境的行为 |
| --- | --- | --- | --- |
| `close_range/close_range01.c` | `validation/fd.rs` | 接受 `UNSHARE`、`CLOEXEC` 及其组合 | 关闭 FD、共享 FD 表分离、clone 继承 |
| `close_range/close_range02.c` | `validation/fd.rs` | 反向范围和未知 flags 返回 `EINVAL`；允许 `UINT_MAX` 下界 | FD 实际关闭与 CLOEXEC 状态 |
| `pipe2/pipe2_01.c` | `validation/fd.rs` | 接受 0、`O_CLOEXEC`、`O_NONBLOCK` | 创建管道、`fcntl` 状态读回；`O_DIRECT` packet mode 尚未实现 |
| `futex/futex_waitv01.c` | `validation/futex.rs` | 空 waiter 数组、非法 clock、0/129 个 futex 返回 `EINVAL` | 单个 waiter 的读取/校验、值不匹配 `EAGAIN`、实际等待和超时 |
| `mmap/mmap06.c` | `validation/mm.rs` | 零长度、缺少 mapping type 返回 `EINVAL` | 文件打开模式产生的 `EACCES` 与真实映射 |
| `mmap/mmap20.c` | `validation/mm.rs` | `MAP_SHARED_VALIDATE` 加 `1 << 10` 返回 `EOPNOTSUPP` | 映射文件 setup 与用户内存访问 |
| `mprotect/mprotect01.c` | `validation/mm.rs` | 地址未按页对齐返回 `EINVAL` | 未映射地址的 `ENOMEM`、文件映射权限的 `EACCES` |
| `nanosleep/nanosleep04.c` | `validation/time.rs` | 原始三组非法 timespec 均返回 `EINVAL` | 用户指针读取和负 errno syscall 返回值 |
| `clock_nanosleep/clock_nanosleep01.c` | `validation/time.rs` | 两组非法 nanoseconds、thread CPU clock 的 `EOPNOTSUPP` | `EINTR`、剩余时间、无效用户指针 |
| `clock_gettime/clock_gettime01.c` | `validation/time.rs` | 用例中的八种 clock id 被识别 | 真实时钟读取、CPU 时间计费、非零/规范 timespec 写回 |
| `clock_getres/clock_getres01.c` | `validation/time.rs` | 非法 clock id 被拒绝 | resolution 写回与 NULL 输出；alarm clocks 尚未支持 |
| `poll/poll01.c` | `validation/io.rs` | 只返回请求的 `POLLIN` / `POLLOUT` readiness | 管道状态、poll 返回数量和等待 |
| `ppoll/ppoll01.c` | `validation/io.rs` | 普通文件 readiness 中只返回 `POLLIN` / `POLLOUT` | `POLLNVAL`、FD/指针校验、超时、信号与临时 mask |
| `rt_sigprocmask/rt_sigprocmask01.c` | `validation/signal.rs` | BLOCK/UNBLOCK 更新规则；额外覆盖 SETMASK | pending signal 与 handler 投递 |
| `rt_sigprocmask/rt_sigprocmask02.c` | `validation/signal.rs` | 错误的 kernel sigset size 返回 `EINVAL` | 无效 old-mask 输出地址的 `EFAULT` |
| `rt_sigaction/rt_sigaction01.c` | `validation/signal.rs` | 支持 RESETHAND、SIGINFO、NODEFER flags | 安装 disposition、handler 执行与 flags 的实际效果 |

额外回归覆盖：32 位 `close_range` 参数截断、`pipe2` NULL 输出与非法 flags 的错误优先级、
futex2 word 对齐/flags/mask/count、绝对 deadline 的过期计算、mmap 文件 offset 对齐与
负 FD 优先级、mprotect 长度溢出、timespec 转换、纳秒饱和、非法 clock/flags、iovec
长度上界、SIGKILL/SIGSTOP mask 清除、signal number 与 kernel sigset size 边界。
这些测试不会把 futex2 的 word 校验误称为 `futex_waitv` 中逐项检查已被覆盖。

## I/O 写入策略

`sys_write`、`sys_writev`、`sys_pwrite64` 和 `sys_pwritev` 共享同一个用户段执行器。
调用者仍负责 syscall 参数与 iovec 解码；执行器统一负责：

- 用户地址加法、总长度和 positional offset 的溢出检查，且总长度必须适合有符号 syscall 返回值；
- direct regular file 的 block 对齐检查，覆盖共享当前位置、显式位置以及每个 iovec 的地址和长度；
- 64 KiB 分块、pin/scratch 用户页策略、短写和已有进度后的错误优先级；
- `FileObject` 的稳定 slice adapter 与 pipe/socket 的 `FdObject` adapter 分发；
- 关闭 pipe 的零进度 `EPIPE` 与 `SIGPIPE` 规则。

文件位置同步仍由 `FileObject`/VFS 持有；`pwrite*` 的显式位置不会改变 shared file offset。
标量对齐的大型 pipe 写入仍保留独立的 zero-copy fast path，因为它直接向 pipe 提交用户页。
这些规则的纯 ABI 边界测试位于 `src/validation/io.rs`；真实 fragmented mapping、跨 64 KiB
chunk、interruption 前后部分进度、direct-I/O 文件以及 ordinary/aligned-large closed-pipe
场景仍必须在 guest/LTP 中验证。

`pipe2` 目前拒绝 `O_DIRECT`，CPU-time clock 的 sleep 支持也有限。对应测试记录当前
PulseOS 支持边界，不将这些兼容差异记为 LTP 通过。

## 未迁移测试的边界

LTP syscall 树包含 1,423 个 C 文件，另有共享 headers、子程序和 Makefiles。此次只移植
上表断言，不是全部 LTP 移植。以下类别需要 PulseOS guest 或另行建立真实内核测试环境：

- 进程与线程：fork/clone/exec/exit/wait、PID/TID、进程组、调度、信号投递和 syscall restart。
- 用户内存与 VM：`EFAULT`、跨页拷贝、mmap 的零填充/COW/共享映射、SIGBUS/SIGSEGV、TLB shootdown。
- FD 与文件系统：真实 read/write/pipe/dup/fcntl、CLOEXEC、临时目录、路径解析、权限、元数据、挂载和写回。
- 网络与异步事件：socket 连接/传输、epoll、设备 ioctl、wait queue、真实 futex 唤醒和竞争条件。
- Linux 专用环境：root/capabilities、namespace、内核配置、proc/sys、NUMA、模块、BPF 等。

例如 `pipe/pipe01.c` 验证管道读写数据一致性，`mmap/mmap01.c` 验证 EOF 后页尾零填充与
写回边界，不能用 flags/页对齐测试替代。上述类别没有注册为 `#[ignore]` 后计入成功，
也没有生成总是通过的占位测试。要扩大宿主范围，应继续从生产路径抽取可独立验证的
逻辑并保留对应 LTP 断言，而不是复制一份实现到测试目录。
