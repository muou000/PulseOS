# Linux `io_uring` 核心 UAPI 契约与 LTP `io_uring01`–`io_uring04` 行为调研（#225）

日期：2026-11-19。所属规划地图：[#224 PulseOS io_uring 架构与兼容规划地图](https://github.com/muou000/PulseOS/issues/224)；调研票：[#225](https://github.com/muou000/PulseOS/issues/225)。

本文基于以下**一手规范与源码**核对并沉淀 PulseOS 真异步 `io_uring` 设计所需的精确 UAPI 契约、内存序协议、错误处理矩阵、LTP 测例行为约束及仓库 Rust 依赖现状：

- **Linux 内核 `v6.12` 一手源码与 UAPI**：
  - [include/uapi/linux/io_uring.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h)
  - [include/uapi/linux/time_types.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/time_types.h)
  - [include/uapi/asm-generic/unistd.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h) 与 [scripts/syscall.tbl](https://github.com/torvalds/linux/blob/v6.12/scripts/syscall.tbl)
  - [include/linux/io_uring_types.h](https://github.com/torvalds/linux/blob/v6.12/include/linux/io_uring_types.h)
  - [io_uring/io_uring.h](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.h)、[io_uring/io_uring.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c)、[io_uring/memmap.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/memmap.c)、[io_uring/register.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/register.c)、[io_uring/rsrc.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/rsrc.c)、[io_uring/opdef.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/opdef.c)、[io_uring/rw.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/rw.c)、[io_uring/eventfd.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/eventfd.c)
- **上游 `liburing`（`liburing-2.8`）手册页与参考实现**：
  - [man/io_uring_setup.2](https://github.com/axboe/liburing/blob/liburing-2.8/man/io_uring_setup.2)、[man/io_uring_enter.2](https://github.com/axboe/liburing/blob/liburing-2.8/man/io_uring_enter.2)、[man/io_uring_register.2](https://github.com/axboe/liburing/blob/liburing-2.8/man/io_uring_register.2)
  - [src/include/liburing/barrier.h](https://github.com/axboe/liburing/blob/liburing-2.8/src/include/liburing/barrier.h)、[src/include/liburing.h](https://github.com/axboe/liburing/blob/liburing-2.8/src/include/liburing.h)、[src/setup.c](https://github.com/axboe/liburing/blob/liburing-2.8/src/setup.c)、[src/queue.c](https://github.com/axboe/liburing/blob/liburing-2.8/src/queue.c)
- **上游 LTP（commit `686a331b6` / `20260930`，与仓库预打包测试 rootfs 完全一致）**：
  - `testcases/kernel/syscalls/io_uring/io_uring0{1..4}.c`、`io_uring_common.h`、`include/lapi/io_uring.h`、`include/tst_safe_io_uring.h`、`lib/tst_safe_io_uring.c`、`lib/tst_kconfig.c`、`lib/tst_capability.c`、`lib/tst_sys_conf.c`、`lib/tst_taint.c`

---

## 1. 系统调用与基础 ABI 契约（RISC-V 64 与 LoongArch64）

### 1.1 系统调用号与寄存器签名

RISC-V 64（`arch/riscv/include/uapi/asm/unistd.h` 引入 `<asm/unistd_64.h>`）与 LoongArch64（`arch/loongarch/include/uapi/asm/unistd.h` 引入 `<asm/unistd_64.h>`）均采用 Linux `<uapi/asm-generic/unistd.h>` 与 `scripts/syscall.tbl` 的通用 64 位系统调用号分配；两者系统调用号与参数寄存器约定完全一致（`a7` 传系统调用号，`a0`–`a5` 传参数，`a0` 返回结果或 `-errno`）：

| 系统调用 | 调用号（RV64 / LA64） | 内核原型与参数（`a0`–`a5`） | 成功返回值 | 源码依据 |
| --- | --- | --- | --- | --- |
| `io_uring_setup` | `425` | `long sys_io_uring_setup(u32 entries, struct io_uring_params __user *params)`<br>(`a0=entries`, `a1=params`) | 新的非负环文件描述符 `fd`（带 `O_RDWR \| O_CLOEXEC`，或在 `IORING_SETUP_REGISTERED_FD_ONLY` 下为已注册索引） | [unistd.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h#L759-L760), [io_uring.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3765-L3772) |
| `io_uring_enter` | `426` | `long sys_io_uring_enter(unsigned int fd, u32 to_submit, u32 min_complete, u32 flags, const void __user *argp, size_t argsz)`<br>(`a0=fd`, `a1=to_submit`, `a2=min_complete`, `a3=flags`, `a4=argp`, `a5=argsz`) | 非负整数：本次成功消费的 SQE 数量（`SQPOLL` 模式下一般为 `to_submit`） | [unistd.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h#L761-L762), [io_uring.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3279-L3281) |
| `io_uring_register` | `427` | `long sys_io_uring_register(unsigned int fd, unsigned int opcode, void __user *arg, unsigned int nr_args)`<br>(`a0=fd`, `a1=opcode`, `a2=arg`, `a3=nr_args`) | 非负整数：多数操作返回 `0`；`IORING_REGISTER_PERSONALITY` 返回正 `id` | [unistd.h](https://github.com/torvalds/linux/blob/v6.12/include/uapi/asm-generic/unistd.h#L763-L764), [register.c](https://github.com/torvalds/linux/blob/v6.12/io_uring/register.c#L591-L592) |

**`io_uring_enter` 第 5/6 参数契约细节**：

- 当 `flags` **未设置** `IORING_ENTER_EXT_ARG` 时，`argp` 解释为 `const sigset_t __user *`，`argsz` 必须等于内核 `sizeof(sigset_t)`（在 RV64 与 LA64 上均为 `_NSIG / 8 = 8` 字节），否则内核 `set_user_sigmask()` 返回 `-EINVAL`；若 `argp == NULL`，即使 `argsz == _NSIG / 8`（LTP `lapi/io_uring.h` 即固定传 `(sig, _NSIG / 8)`），内核也不会解引用 `argp`（[io_uring.c:2556-2567](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2556-L2567)）。
- 当 `flags` **设置** `IORING_ENTER_EXT_ARG` 时，`argp` 解释为 `const struct io_uring_getevents_arg __user *`，`argsz` 必须严格等于 `sizeof(struct io_uring_getevents_arg)`（`24` 字节），否则返回 `-EINVAL`（[io_uring.c:3268-3269](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3268-L3269)）。

---

### 1.2 核心 UAPI 结构体精确布局、大小与对齐

以下所有结构体均在 64 位 LP64 小端 ABI（RV64 与 LA64 完全相同）下通过 Linux `v6.12` `include/uapi/linux/io_uring.h` 与 `gcc` 实测验证；内核 `io_uring_init()` 中亦通过 `BUILD_BUG_ON` 固化了 `io_uring_sqe` 每一字节的偏移（[io_uring.c:3790-3837](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3790-L3837)）。

#### (1) `struct io_sqring_offsets` — 总大小 `40` 字节，对齐 `8` 字节

| 偏移 | 大小 | C 类型 | 字段 | 方向与说明 |
| --- | --- | --- | --- | --- |
| `0` | `4` | `__u32` | `head` | 内核填充：SQ `head` 在 `SQ_RING` 映射内的字节偏移（`0`） |
| `4` | `4` | `__u32` | `tail` | 内核填充：SQ `tail` 偏移（`4`） |
| `8` | `4` | `__u32` | `ring_mask` | 内核填充：`sq_ring_mask` 偏移（`16`） |
| `12` | `4` | `__u32` | `ring_entries` | 内核填充：`sq_ring_entries` 偏移（`24`） |
| `16` | `4` | `__u32` | `flags` | 内核填充：`sq_flags` 偏移（`36`） |
| `20` | `4` | `__u32` | `dropped` | 内核填充：`sq_dropped` 偏移（`32`） |
| `24` | `4` | `__u32` | `array` | 内核填充：SQ 索引数组起始偏移（若设置 `IORING_SETUP_NO_SQARRAY` 则为 `0`） |
| `28` | `4` | `__u32` | `resv1` | 保留字段，内核清 `0` |
| `32` | `8` | `__u64` | `user_addr` | 若设置 `IORING_SETUP_NO_MMAP`，传入 SQE 数组的用户虚地址；否则内核清 `0` |

#### (2) `struct io_cqring_offsets` — 总大小 `40` 字节，对齐 `8` 字节

| 偏移 | 大小 | C 类型 | 字段 | 方向与说明 |
| --- | --- | --- | --- | --- |
| `0` | `4` | `__u32` | `head` | 内核填充：CQ `head` 偏移（`8`） |
| `4` | `4` | `__u32` | `tail` | 内核填充：CQ `tail` 偏移（`12`） |
| `8` | `4` | `__u32` | `ring_mask` | 内核填充：`cq_ring_mask` 偏移（`20`） |
| `12` | `4` | `__u32` | `ring_entries` | 内核填充：`cq_ring_entries` 偏移（`28`） |
| `16` | `4` | `__u32` | `overflow` | 内核填充：`cq_overflow` 偏移（`44`） |
| `20` | `4` | `__u32` | `cqes` | 内核填充：CQE 数组起始偏移（`SMP_CACHE_BYTES=64` 时为 `64`） |
| `24` | `4` | `__u32` | `flags` | 内核填充：`cq_flags` 偏移（`40`） |
| `28` | `4` | `__u32` | `resv1` | 保留字段，内核清 `0` |
| `32` | `8` | `__u64` | `user_addr` | 若设置 `IORING_SETUP_NO_MMAP`，传入 rings 的用户虚地址；否则内核清 `0` |

#### (3) `struct io_uring_params` — 总大小 `120` 字节，对齐 `8` 字节

| 偏移 | 大小 | C 类型 | 字段 | 方向与说明 |
| --- | --- | --- | --- | --- |
| `0` | `4` | `__u32` | `sq_entries` | **OUT**：实际分配的 SQ 项数（2 的幂） |
| `4` | `4` | `__u32` | `cq_entries` | **IN/OUT**：设 `IORING_SETUP_CQSIZE` 时为入参请求数，返回实际 2 的幂项数；否则为 `2 * sq_entries` |
| `8` | `4` | `__u32` | `flags` | **IN/OUT**：`IORING_SETUP_*` 位掩码 |
| `12` | `4` | `__u32` | `sq_thread_cpu` | **IN**：绑定 SQPOLL 线程的 CPU（需 `IORING_SETUP_SQ_AFF`） |
| `16` | `4` | `__u32` | `sq_thread_idle` | **IN**：SQPOLL 空闲超时（ms） |
| `20` | `4` | `__u32` | `features` | **OUT**：内核填写的 `IORING_FEAT_*` 位掩码 |
| `24` | `4` | `__u32` | `wq_fd` | **IN**：共享工作队列的目标 ring fd（需 `IORING_SETUP_ATTACH_WQ`） |
| `28` | `12` | `__u32[3]` | `resv` | **IN**：**必须全为 `0`**，非零返回 `-EINVAL` |
| `40` | `40` | `struct io_sqring_offsets` | `sq_off` | **OUT**（除 `NO_MMAP` 下 `user_addr`） |
| `80` | `40` | `struct io_cqring_offsets` | `cq_off` | **OUT**（除 `NO_MMAP` 下 `user_addr`） |

#### (4) `struct io_uring_sqe` — 总大小 `64` 字节，对齐 `8` 字节（`IORING_SETUP_SQE128` 时步长为 `128` 字节）

| 偏移 | 大小 | C 类型 | 字段（联合体语义） | 说明 |
| --- | --- | --- | --- | --- |
| `0` | `1` | `__u8` | `opcode` | 操作码 `IORING_OP_*` |
| `1` | `1` | `__u8` | `flags` | `IOSQE_*` 位掩码（bit 0..6） |
| `2` | `2` | `__u16` | `ioprio` | I/O 优先级，或 `SEND`/`RECV`/`ACCEPT` 专用标志 |
| `4` | `4` | `__s32` | `fd` | 目标 fd（或 `IOSQE_FIXED_FILE` 下的固定文件索引） |
| `8` | `8` | `__u64` / `{__u32,__u32}` | `off` / `addr2` / `{cmd_op, __pad1}` | 文件偏移（`-1` 配合 `FEAT_RW_CUR_POS` 表示当前偏移）、第二地址或 `URING_CMD` 子命令 |
| `16` | `8` | `__u64` / `{__u32,__u32}` | `addr` / `splice_off_in` / `{level, optname}` | 缓冲区/iovec/sockaddr/timespec 指针等 |
| `24` | `4` | `__u32` | `len` | 字节长度、`iovec` 个数或 `POLL_ADD` 更新标志 |
| `28` | `4` | `__u32` / `__s32` / `__u16` | `rw_flags` / `fsync_flags` / `poll32_events` (`poll_events` 为低 2B) / `msg_flags` / `timeout_flags` / `accept_flags` / `cancel_flags` 等 | 各操作专用 flags（注意小端 RV64/LA64 下 `poll_events` 占偏移 `28..30`） |
| `32` | `8` | `__u64` | `user_data` | 用户上下文标识，原样回传到 `cqe->user_data` |
| `40` | `2` | `__u16` (`packed`) | `buf_index` / `buf_group` | 固定缓冲索引（`READ_FIXED`/`WRITE_FIXED`）或缓冲组 ID（`IOSQE_BUFFER_SELECT`） |
| `42` | `2` | `__u16` | `personality` | 注册凭据 ID（`0` 表示当前任务凭据） |
| `44` | `4` | `__s32` / `__u32` / `{__u16,__u16}` | `splice_fd_in` / `file_index` / `optlen` / `{addr_len, __pad3[1]}` | 目标固定槽位（编码为 `index + 1`，`IORING_FILE_INDEX_ALLOC = ~0U`）或地址长度等 |
| `48` | `8` | `__u64` | `addr3`（`cmd[0]` 起点） | `addr3` 或 80 字节 `SQE128` 扩展载荷起点 |
| `56` | `8` | `__u64` | `__pad2[1]` | 填充保留（`SQE128` 模式下自偏移 `48` 起占用 80 字节 `cmd`，总大小 `128` 字节） |

#### (5) `struct io_uring_cqe` — 基础大小 `16` 字节，对齐 `8` 字节（`IORING_SETUP_CQE32` 时步长为 `32` 字节）

| 偏移 | 大小 | C 类型 | 字段 | 说明 |
| --- | --- | --- | --- | --- |
| `0` | `8` | `__u64` | `user_data` | 回传自对应 SQE 的 `user_data` |
| `8` | `4` | `__s32` | `res` | 有符号结果：成功为非负结果（字节数/fd/`0`），失败为负 errno（`-errno`） |
| `12` | `4` | `__u32` | `flags` | `IORING_CQE_F_*` 位掩码（`BUFFER`、`MORE`、`SOCK_NONEMPTY`、`NOTIF`、`BUF_MORE`） |
| `16` | `0` (`16` in `CQE32`) | `__u64[]` | `big_cqe` | 柔性数组成员，仅在 `IORING_SETUP_CQE32` 下额外占 16 字节 |

#### (6) `struct io_uring_getevents_arg` — 总大小 `24` 字节，对齐 `8` 字节

| 偏移 | 大小 | C 类型 | 字段 | 说明 |
| --- | --- | --- | --- | --- |
| `0` | `8` | `__u64` | `sigmask` | `const sigset_t *` 用户地址（可为 `0`） |
| `8` | `4` | `__u32` | `sigmask_sz` | 信号集字节大小（RV64/LA64 下为 `8`） |
| `12` | `4` | `__u32` | `min_wait_usec` | v6.12 之前为 `pad`（需清 `0`）；v6.12 起（`IORING_FEAT_MIN_TIMEOUT`）为最小批等待微秒数 |
| `16` | `8` | `__u64` | `ts` | `const struct __kernel_timespec *` 用户地址（可为 `0`；超时则以 `-ETIME` 唤醒） |

#### (7) `struct __kernel_timespec` — 总大小 `16` 字节，对齐 `8` 字节

| 偏移 | 大小 | C 类型 | 字段 | 说明 |
| --- | --- | --- | --- | --- |
| `0` | `8` | `__kernel_time64_t` (`__s64`) | `tv_sec` | 有符号 64 位秒数（Y2038-safe，RV64/LA64 均使用 64 位） |
| `8` | `8` | `long long` (`__s64`) | `tv_nsec` | 有符号 64 位纳秒数（合法范围 `[0, 999_999_999]`） |

#### (8) 常用 `io_uring_register` 辅助结构体（参考）

| 结构体 | 大小 / 对齐 | 字段摘要与版本说明 | 源码依据 |
| --- | --- | --- | --- |
| `io_uring_rsrc_register` | `32` / `8` | `nr:u32, flags:u32, resv2:u64, data:u64, tags:u64` | [io_uring.h:641-647](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L641-L647) |
| `io_uring_rsrc_update` / `io_uring_files_update` | `16` / `8` | `offset:u32, resv:u32, data(fds):u64`（内核 `BUILD_BUG_ON` 强制两者同尺寸） | [io_uring.h:629-653](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L629-L653) |
| `io_uring_rsrc_update2` | `32` / `8` | `offset:u32, resv:u32, data:u64, tags:u64, nr:u32, resv2:u32` | [io_uring.h:655-662](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L655-L662) |
| `io_uring_probe_op` | `8` / `4` | `op:u8, resv:u8, flags:u16, resv2:u32` | [io_uring.h:669-674](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L669-L674) |
| `io_uring_probe` | `16`（头部） / `4` | `last_op:u8, ops_len:u8, resv:u16, resv2:[u32;3], ops[]` | [io_uring.h:676-682](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L676-L682) |
| `io_uring_clone_buffers` | `32` / `4` | v6.12：`src_fd:u32, flags:u32, pad:[u32;6]`；v6.13+（及 LTP `lapi/io_uring.h`）：将 `pad[0..3]` 拆分为 `src_off, dst_off, nr` 保留 `pad[3]`，总长仍为 32 字节 | [io_uring.h:704-708](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L704-L708) |

---

## 2. 共享环 `mmap`、弱内存序协议与 `IORING_FEAT_NODROP`

### 2.1 `mmap` 魔数偏移、页对齐与大小计算

Linux 通过 `mmap(..., fd, offset)` 的页对齐 `offset` 高位路由目标区域（`IORING_OFF_MMAP_MASK = 0xf800_0000ULL`；[io_uring.h:464-469](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/io_uring.h#L464-L469)、[memmap.c:201-267](https://github.com/torvalds/linux/blob/v6.12/io_uring/memmap.c#L201-L267)）：

| 区域 | `mmap` 偏移常量 | 内核映射对象 | 大小计算（`PAGE_SIZE = 4096`） |
| --- | --- | --- | --- |
| SQ Ring（统一环头 + CQEs + SQ array） | `IORING_OFF_SQ_RING = 0x0ULL` | `ctx->ring_pages`（`struct io_rings`） | 见下式，向上按 `PAGE_SIZE` 对齐 |
| CQ Ring | `IORING_OFF_CQ_RING = 0x8000000ULL`（128 MiB） | 启用 `IORING_FEAT_SINGLE_MMAP` 时同样指向 `ctx->ring_pages` | 见下式，向上按 `PAGE_SIZE` 对齐 |
| SQEs 数组 | `IORING_OFF_SQES = 0x10000000ULL`（256 MiB） | `ctx->sqe_pages`（`struct io_uring_sqe[]`） | `ALIGN_UP(sq_entries * (SQE128 ? 128 : 64), PAGE_SIZE)` |
| Provided Buffer Ring（#224 范围外） | `IORING_OFF_PBUF_RING = 0x80000000ULL` | 按 `bgid << 16` 索引 | `ring_entries * sizeof(struct io_uring_buf)` |

**`struct io_rings` 精确大小公式**（[io_uring_types.h:115-184](https://github.com/torvalds/linux/blob/v6.12/include/linux/io_uring_types.h#L115-L184)、[io_uring.c:2675-2710](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2675-L2710)）：

1. 环头元数据（`0..48`，共 12 个 `u32`）：
   - `0`: `sq.head` | `4`: `sq.tail` | `8`: `cq.head` | `12`: `cq.tail`
   - `16`: `sq_ring_mask` | `20`: `cq_ring_mask` | `24`: `sq_ring_entries` | `28`: `cq_ring_entries`
   - `32`: `sq_dropped` | `36`: `sq_flags` | `40`: `cq_flags` | `44`: `cq_overflow`
2. `cqes[]` 数组使用 `____cacheline_aligned_in_smp` 对齐（RV64/LA64 SMP 下 cacheline 为 64 字节，故 `cq_off.cqes = 64`）：
   $$\text{off}_1 = \text{ALIGN\_UP}\big(64 + \text{cq\_entries} \times \text{cqe\_size},\; \text{SMP\_CACHE\_BYTES}\big)$$
   其中标准 `cqe_size = 16`（`CQE32` 为 `32`），`cq_entries` 至少为 `sq_entries`（默认 `2 * sq_entries`），`sq_entries = roundup_pow_of_two(entries)`（上限 `IORING_MAX_ENTRIES = 32768`，`cq_entries` 上限 `IORING_MAX_CQ_ENTRIES = 65536`；[io_uring.c:3514-3553](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3514-L3553)）。
3. 除非设置了 `IORING_SETUP_NO_SQARRAY`，`sq_off.array = off_1`，后接 `sq_entries * 4` 字节的 `u32` 索引数组：
   $$\text{rings\_bytes} = \text{off}_1 + \text{sq\_entries} \times 4$$
4. 内核分配页数 `n_ring_pages = DIV_ROUND_UP(rings_bytes, PAGE_SIZE)`。`mmap` 时内核取 `npages = min(ctx->n_ring_pages, DIV_ROUND_UP(sz, PAGE_SIZE))` 映射（[memmap.c:257-258](https://github.com/torvalds/linux/blob/v6.12/io_uring/memmap.c#L257-L258)），并强制设置 `VM_DONTEXPAND`；同时 `io_uring_get_unmapped_area` 拒绝非零 `addr` 提示（`addr != 0` 返回 `-EINVAL`，[memmap.c:280-281](https://github.com/torvalds/linux/blob/v6.12/io_uring/memmap.c#L280-L281)）。用户态应传入 `PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE`（或等价共享可写映射，避免 `MAP_PRIVATE` 写时复制破坏共享视图）。

### 2.2 `IORING_FEAT_SINGLE_MMAP` 布局差异与兼容性陷阱

- **语义**：设置 `IORING_FEAT_SINGLE_MMAP`（`1 << 0`）表示 SQ ring 与 CQ ring 位于同一个 `struct io_rings` 连续对象内，应用仅需**两次** `mmap` 即可完成映射（一次 `IORING_OFF_SQ_RING`，一次 `IORING_OFF_SQES`）。
- **`liburing` 的映射方式**（[setup.c:98-149](https://github.com/axboe/liburing/blob/liburing-2.8/src/setup.c#L98-L149)）：
  - 计算 `sq_sz = sq_off.array + sq_entries * 4` 与 `cq_sz = cq_off.cqes + cq_entries * cqe_size`；
  - 若 `features & IORING_FEAT_SINGLE_MMAP`，令 `ring_sz = max(sq_sz, cq_sz)`，仅调用一次 `mmap(..., IORING_OFF_SQ_RING)` 并令 `cq.ring_ptr = sq.ring_ptr`；否则分别映射 `SQ_RING` 与 `CQ_RING`。
- **LTP 测例的映射方式（关键兼容点！）**：
  - LTP 的 `io_uring_common.h:68-98`（`io_uring01`、`io_uring03`）与 `tst_safe_io_uring.c:33-72`（`io_uring02`）**不检查 `IORING_FEAT_SINGLE_MMAP`**，始终发出 **三次** `mmap`：
    1. `mmap(0, sq_off.array + sq_entries * 4, ..., IORING_OFF_SQ_RING)`
    2. `mmap(0, sq_entries * 64, ..., IORING_OFF_SQES)`
    3. `mmap(0, cq_off.cqes + cq_entries * 16, ..., IORING_OFF_CQ_RING)`
  - 注意 `struct io_rings` 中 `cqes` 在前（偏移 `64`）、`sq_array` 在后（`64 + cq_entries * 16`），因此两者均从偏移 `0` 开始且 `sq_sz >= cq_sz`。Linux `memmap.c:254-258` 对 `IORING_OFF_SQ_RING` 和 `IORING_OFF_CQ_RING` 均直接映射同一份 `ctx->ring_pages`。
  - **对 PulseOS 的硬性约束**：PulseOS 应当在 `params.features` 中宣告 `IORING_FEAT_SINGLE_MMAP`（以支持现代 `liburing` 的 2 次 `mmap`），**同时**在 `FdObject::mmap_prepared` 中让 `IORING_OFF_CQ_RING` 映射与 `IORING_OFF_SQ_RING` 相同的底层 `SharedFrame` 页集合，从而**同时兼容 `liburing` 与 LTP 的 3 次 `mmap` 模式**。

### 2.3 弱内存序架构（RV64 RVWMO / LA64）的 Acquire/Release 协议

RISC-V 64（RVWMO 弱序模型）与 LoongArch64（弱序模型）均可能跨核心乱序执行普通加载/存储；若缺少显式内存序约束，核间（SMP 下内核执行线程/中断底半部 vs 用户线程，或跨核心运行的任务）可能读到尚未写入的 SQE/CQE 载荷。Linux 内核（[io_uring.c:6-37](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L6-L37)、[io_uring.h:253-305](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.h#L253-L305)）与 `liburing`（[barrier.h](https://github.com/axboe/liburing/blob/liburing-2.8/src/include/liburing/barrier.h)、[liburing.h:314-350](https://github.com/axboe/liburing/blob/liburing-2.8/src/include/liburing.h#L314-L350)）采用对称的 **单生产者-单消费者（SPSC）Acquire/Release 配对协议**：

```text
[SQ 路径：用户生产者 -> 内核消费者]
  User:  load sq.head (non-SQPOLL 可 Relaxed; SQPOLL 须 Acquire)
         -> write sqes[idx] & sq_array[tail & mask] = idx
         -> atomic_store_release(&sq.tail, new_tail)        // RV64: fence rw,w; sw | LA64: dbar; st.w
                         ||  synchronizes-with
  Kern:  smp_load_acquire(&sq.tail)                         // RV64: lw; fence r,rw | LA64: ld.w; dbar
         -> READ_ONCE 拷贝 sq_array[i] 与 sqes[idx] 到内核请求副本（防 TOCTOU）
         -> smp_store_release(&sq.head, cached_sq_head)     // 释放 SQ 槽位前确保已读完 SQE

[CQ 路径：内核生产者 -> 用户消费者]
  Kern:  load cq.head (内核用 READ_ONCE+控制依赖; Rust 推荐 Ordering::Acquire)
         -> write cqe.{user_data, res, flags}
         -> smp_store_release(&cq.tail, cached_cq_tail)
                         ||  synchronizes-with
  User:  io_uring_smp_load_acquire(cq.ktail)
         -> read cqe.{user_data, res, flags}
         -> io_uring_smp_store_release(cq.khead, new_head)
```

**补充序规则与共享字段**：

1. **TOCTOU 安全要求**：用户态对 `SQ_RING` 与 `SQES` 保持可写映射，内核在读取 `sq_array[i]` 与 `sqe` 各字段时必须通过 `READ_ONCE` / 单次易失拷贝（`pulse_core` 对共享页的原子/逐字节受控读）读取到内核自有结构体再校验，绝不可二次从共享页重读（[io_uring.c:2254-2267](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2254-L2267)）。
2. **`SQPOLL` 全屏障**：虽超出 `#224` 范围，标准协议规定若启用 `IORING_SETUP_SQPOLL`，用户态更新 `sq.tail` 后读 `sq.flags & IORING_SQ_NEED_WAKEUP` 之前必须执行 `SeqCst` 全屏障（`smp_mb()`），与内核侧睡前置位配对（[queue.c:28-36](https://github.com/axboe/liburing/blob/liburing-2.8/src/queue.c#L28-L36)）。
3. **非索引元数据字段**：
   - `sq.flags`（`IORING_SQ_NEED_WAKEUP=1`、`IORING_SQ_CQ_OVERFLOW=2`、`IORING_SQ_TASKRUN=4`）：内核通过原子位运算更新（`atomic_or`/`atomic_andnot`），用户态通过 `READ_ONCE`（`Acquire`/松弛原子读）检查。
   - `sq.dropped`：内核在 `sq_array[i] >= sq_entries` 时递增（`uring_lock` 下 `READ_ONCE`/`WRITE_ONCE`）。
   - `cq.overflow`：内核在 CQ 满且内核溢出队列也无法分配时递增（`completion_lock` 下更新，不与具体 CQE 序绑定，[io_uring_types.h:172-175](https://github.com/torvalds/linux/blob/v6.12/include/linux/io_uring_types.h#L172-L175)）。
   - `cq.flags`（`IORING_CQ_EVENTFD_DISABLED=1`）：用户态写入 `WRITE_ONCE`，内核在触发 `eventfd` 前读取 `READ_ONCE`（[eventfd.c:48](https://github.com/torvalds/linux/blob/v6.12/io_uring/eventfd.c#L48)）。
4. **LTP 测例实现差异**：`io_uring02.c` 显式使用了 GCC `__atomic_store(..., __ATOMIC_RELEASE)` 与 `__atomic_load(..., __ATOMIC_ACQUIRE)`；而 `io_uring_common.h`（被 `io_uring01`/`03` 使用）使用普通解引用 `*sring->tail = tail;` 与 `*cring->tail`，仅因随后立即通过 `io_uring_enter()` 陷入内核态才未在弱序 SMP 上暴露乱序问题。PulseOS 内核侧在任何并发完成路径（如异步块中断/定时器/其他核唤醒）上**必须严格遵守 Acquire/Release 协议**，以确保与 `liburing` 和无 syscall 轮询用户态代码完全正确互操作。

### 2.4 `IORING_FEAT_NODROP` 精确语义

- **Linux `< 5.5`（无 `IORING_FEAT_NODROP`）**：当 CQ 环已满时，新完成事件直接被丢弃并递增 `cq.overflow`，且继续提交新 SQE 可能返回 `-EBUSY`（[io_uring_setup.2:375-378](https://github.com/axboe/liburing/blob/liburing-2.8/man/io_uring_setup.2#L375-L378)）。
- **Linux `>= 5.5`（带 `IORING_FEAT_NODROP = 1 << 1`）**：
  1. **内核溢出 FIFO 缓存**：当 CQ 环空间不足（`io_fill_cqe_req` 返回 `false`）时，内核调用 `io_cqring_event_overflow()` 动态分配 `struct io_overflow_cqe` 挂载到受 `completion_lock` 保护的 `ctx->cq_overflow_list`，并设置内部状态位 `IO_CHECK_CQ_OVERFLOW_BIT` 与共享环标志 **`sq.flags |= IORING_SQ_CQ_OVERFLOW`**（[io_uring.c:725-763](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L725-L763)）。
  2. **保序防插队**：只要 `ctx->check_cq` 中 `IO_CHECK_CQ_OVERFLOW_BIT` 仍置位，即使应用刚刚消费了几个 CQE 空出环槽位，**新产生的 CQE 也必须继续进入 `cq_overflow_list`**（`io_cqe_cache_refill` 在 `!overflow` 时返回 `false`，[io_uring.c:784-790](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L784-L790)），以保证链路/多发 CQE 顺序不被打乱。
  3. **刷新时机与 `poll` 唤醒**：当 `IO_CHECK_CQ_OVERFLOW_BIT` 置位时，`io_uring_poll()` 返回 `EPOLLIN | EPOLLRDNORM` 以促使使用 `epoll`/`poll` 的应用陷入内核触发刷新（[io_uring.c:2852-2853](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2852-L2853)）；`liburing` 的 `cq_ring_needs_enter()` 检查 `IORING_SQ_CQ_OVERFLOW` 并自动调用 `io_uring_enter(..., IORING_ENTER_GETEVENTS)`。进入 `io_cqring_wait()` 后，内核调用 `__io_cqring_overflow_flush()` 按 FIFO 顺序将溢出项拷入 CQ 环并清理 `IORING_SQ_CQ_OVERFLOW`（[io_uring.c:613-663, 2528-2529](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L613-L663)）。
  4. **极端内存耗尽降级**：仅当内核 `kmalloc(GFP_ATOMIC)` 分配 `io_overflow_cqe` 失败时，才递增 `cq.overflow` 并置位 `IO_CHECK_CQ_DROPPED_BIT`。下一次 `io_uring_enter(..., IORING_ENTER_GETEVENTS)` 等待时若 CQ 环仍为空，将返回 **`-EBADR`** 并清除该错误位（[io_uring.c:739-748, 2621-2624, 3400-3403](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3400-L3403)）。

---

## 3. 标准 Linux 错误处理与边界语义

### 3.1 同步系统调用返回 vs CQE `res` 负错误码的划分

Linux `io_uring` 严格区分“环/系统调用自身故障”与“单个 SQE 请求级故障”（[io_uring_enter.2:1817-1827](https://github.com/axboe/liburing/blob/liburing-2.8/man/io_uring_enter.2#L1817-L1827)、[io_uring.c:2127-2343, 3279-3409](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2127-L2343)）：

- **同步系统调用返回 `-errno`（不产生 CQE）**：
  - `io_uring_setup` / `io_uring_register` / `mmap` 的所有错误。
  - `io_uring_enter` 调用级校验与等待级错误：`flags` 非法、`fd` 无效/非 ring fd、ring 处于 `IORING_SETUP_R_DISABLED`、`DEFER_TASKRUN` 线程不匹配、首个请求 `io_alloc_req` 即内存不足（`-EAGAIN`）、`ext_arg` 长度/指针错误、或等待期间发生的 `-EINTR` / `-ETIME` / `-EBADR`（且满足下文 3.3 节的条件）。
- **通过 CQE `res = -errno` 异步或延迟返回（系统调用计数已消费该 SQE）**：
  - SQE 字段解析/校验失败（在 `io_init_req()` 或 `def->prep()` 阶段失败，如无效 `opcode`、无效 `sqe->flags`、非法 `buf_index`/`personality`、不支持的操作/flag、权限/限制/指针错误等）：内核调用 `io_submit_fail_init()`，**仍为该失败 SQE 生成一条 `cqe->res = -errno` 的 CQE**，并推进 SQ `head` 将其计入 `io_uring_enter` 的成功消费计数 `ret`（[io_uring.c:2127-2162, 2324-2328](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2127-L2162)）。
  - **关键批处理终止规则（`IORING_SETUP_SUBMIT_ALL`）**：
    - 未设置 `IORING_SETUP_SUBMIT_ALL` 时，一旦某个 SQE 在提交初始化/prep 阶段失败（非链表中间节点），内核在为该 SQE 生成错误 CQE 后**立即中止后续 SQE 提交**，直接返回已消费数 `ret`（`1 <= ret < to_submit`），且因为 `ret != to_submit` **跳过 `IORING_ENTER_GETEVENTS` 等待**（[io_uring.c:2324-2328, 3344-3347](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3344-L3347)）。
    - 设置了 `IORING_SETUP_SUBMIT_ALL` 时，即使某 SQE 失败（并生成错误 CQE），仍继续提交后续 SQE 直到达到 `to_submit` 或环空。
  - **链路断裂（`IOSQE_IO_LINK` / `IOSQE_IO_HARDLINK`）**：普通 `IO_LINK` 链中前置 SQE 返回错误或“非预期结果”（如短读）时，后续未开始执行的链节以 `cqe->res = -ECANCELED` 完成；`IO_HARDLINK` 不因完成结果断裂，但仍会因提交初始化阶段失败而整链失败（[io_uring_enter.2:1607-1623](https://github.com/axboe/liburing/blob/liburing-2.8/man/io_uring_enter.2#L1607-L1623)）。
  - **无效 `sq_array[i] >= sq_entries`**：静默丢弃并递增 `sq.dropped`，终止本次提交循环，**不生成 CQE**（[io_uring.c:2268-2276](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2268-L2276)）。

### 3.2 各系统调用与 SQE 标准错误码矩阵

| 接口 | 错误码 | Linux 触发条件 |
| --- | --- | --- |
| `io_uring_setup` | `-EFAULT` | `params` 指针不可访问（先于 `entries` 检查：[io_uring.c:3726](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3726)） |
| | `-EINVAL` | `params.resv` 非零、`flags` 含未知位、`entries == 0`、`entries > 32768`（未设 `CLAMP`）、`CQSIZE` 下 `cq_entries == 0` / `< sq_entries` / `> 65536`（未设 `CLAMP`）、互斥/前置 flag 冲突（如 `SQ_AFF` 无 `SQPOLL`、`REGISTERED_FD_ONLY` 无 `NO_MMAP`、`DEFER_TASKRUN` 无 `SINGLE_ISSUER`） |
| | `-EPERM` | `sysctl_io_uring_disabled == 2`，或为 `1` 且无 `CAP_SYS_ADMIN` / 不在组内；或无权使用 `SQPOLL`（旧内核） |
| | `-ENOMEM` / `-EMFILE` / `-ENFILE` | 内存不足或超过 `RLIMIT_NOFILE`/系统文件句柄上限 |
| | `-ENXIO` | `IORING_SETUP_ATTACH_WQ` 的 `wq_fd` 不是有效的活跃 io_uring fd |
| `io_uring_enter`（同步） | `-EINVAL` | 未知 `flags` 位；`EXT_ARG` 下 `argsz != 24`；未设 `EXT_ARG` 且 `sig != NULL` 时 `argsz != _NSIG/8`（8）；`REGISTERED_RING` 索引 `>= 16` |
| | `-EBADF` | `fd` 未打开或已注册槽位为空 |
| | `-EOPNOTSUPP` | `fd` 打开但不是 io_uring 实例 |
| | `-EBADFD` | 环以 `IORING_SETUP_R_DISABLED` 创建且尚未 `IORING_REGISTER_ENABLE_RINGS` |
| | `-EFAULT` | 非法 `argp`、`sig` 或 `ext_arg.ts` 用户地址 |
| | `-EAGAIN` | 首次请求 `io_kiocb` 分配失败且尚未提交任何 SQE（[io_uring.c:2334-2335](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2334-L2335)） |
| | `-EEXIST` | 启用了 `IORING_SETUP_DEFER_TASKRUN`（或 `SINGLE_ISSUER`），当前线程不是创建/激活线程 |
| | `-EINTR` | `IORING_ENTER_GETEVENTS` 阻塞等待期间被信号中断且 CQ 仍为空（见 3.3） |
| | `-ETIME` | `IORING_ENTER_EXT_ARG` 传入超时到期且 CQ 仍为空（见 3.3） |
| | `-EBADR` | `IORING_FEAT_NODROP` 下因内核 OOM 丢弃过 CQE 且 CQ 为空（随后清错） |
| | `-EBUSY` | 非 `NODROP` 内核下 CQ 已满时过量提交/等待（`NODROP` 内核不再因此拒绝提交） |
| | `-EOWNERDEAD` | `SQPOLL` 内核线程已退出 |
| `io_uring_register` | `-EINVAL` | 未知 `opcode >= IORING_REGISTER_LAST`；`nr_args` 为 0 或超限；注销操作传入非空 `arg`/`nr_args != 0`；`PROBE` 的保留字段非零；无效 `clockid` |
| | `-EBADF` / `-EOPNOTSUPP` | `fd` 无效（`-EBADF`）或非 io_uring 文件（`-EOPNOTSUPP`） |
| | `-EBUSY` | 重复注册 buffers/files/eventfd/restrictions（须先注销或使用 `*_UPDATE`） |
| | `-ENXIO` | 尝试更新或注销尚未注册的资源（buffers/files/eventfd），或环正在退出（dying） |
| | `-EFAULT` | 用户态 `arg`/iovec 地址无效，或单个 `iov_len > 1 GiB`（[rsrc.c:104-105](https://github.com/torvalds/linux/blob/v6.12/io_uring/rsrc.c#L104-L105)） |
| | `-ENOMEM` | 无 `CAP_IPC_LOCK` 时固定缓冲锁页总量超过 `RLIMIT_MEMLOCK`（[rsrc.c:52-58](https://github.com/torvalds/linux/blob/v6.12/io_uring/rsrc.c#L52-L58)）或内核分配失败 |
| | `-EMFILE` | `REGISTER_FILES` 的 `nr_args` 超过 `IORING_MAX_FIXED_FILES`（`1<<20`）或 `RLIMIT_NOFILE` |
| | `-EACCES` | 环已启用 restrictions 且该 register opcode 未列入白名单 |
| | `-EBADFD` | `ENABLE_RINGS` / `REGISTER_RESTRICTIONS` 在非 disabled 环上调用 |
| SQE（写入 `cqe->res`） | `-EINVAL` | `opcode >= IORING_OP_LAST`；`sqe->flags` 含未定义位；不支持 `ioprio` 的操作传入非零 `ioprio`；无效 `personality`；无效操作内参数 |
| | `-EOPNOTSUPP` | 合法 `opcode` 但当前内核未配置/未实现（如 `opdef.c` 中的 `io_eopnotsupp_prep`）；不支持 `IOSQE_BUFFER_SELECT`；`CQE_SKIP_SUCCESS` 后再使用 `IO_DRAIN` |
| | `-EACCES` | `restricted` 环下 opcode 或 flags 违反白名单/必需标志 |
| | `-EBADF` | `fd` 无效，或 `IOSQE_FIXED_FILE` 越界/未注册文件表 |
| | `-EFAULT` | `READ_FIXED`/`WRITE_FIXED` 未注册缓冲、`buf_index >= nr_user_bufs`，或 `[addr, addr+len)` 超出对应已注册槽位范围（[rw.c:341-349](https://github.com/torvalds/linux/blob/v6.12/io_uring/rw.c#L341-L349), [rsrc.c:1097-1101](https://github.com/torvalds/linux/blob/v6.12/io_uring/rsrc.c#L1097-L1101)）；或普通用户缓冲不可访问 |
| | `-ECANCELED` | 被 `ASYNC_CANCEL` 取消，或因前置 `IO_LINK` 失败而级联取消 |
| | `-EINTR` | 底层 VFS/文件 `read`/`write` 返回 `-ERESTARTSYS` 等内部重启码时，转换写入 `-EINTR`（不可重启整次 `io_uring_enter`，[rw.c:570-581](https://github.com/torvalds/linux/blob/v6.12/io_uring/rw.c#L570-L581)） |

### 3.3 `EINTR` 与 `min_complete` 的精确交互契约

`SYSCALL_DEFINE6(io_uring_enter)` 与 `io_cqring_wait()`（[io_uring.c:2485-2639, 3337-3404](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2514-L2639)）的信号与完成数交互有以下三条极易写错的硬契约：

1. **已消费 SQE 优先于等待错误**：若 `to_submit > 0` 且 `io_submit_sqes` 成功消费了 `ret > 0` 个 SQE（`ret == to_submit`），随后 `io_cqring_wait` 返回 `ret2 = -EINTR`（或 `-ETIME` / `-EBADR`），`if (!ret) ret = ret2;` 不成立——**`io_uring_enter` 返回已提交数 `ret`，绝不覆盖为 `-EINTR`**（若 `ret < to_submit`，更是直接跳过 `io_cqring_wait`）。仅当 `to_submit == 0`（`ret == 0`）时，`-EINTR` 才会返回给用户态。
2. **已有 CQE 优先于 `-EINTR` / `-ETIME`**：`io_cqring_wait()` 退出循环后返回表达式为：
   ```c
   return READ_ONCE(rings->cq.head) == READ_ONCE(rings->cq.tail) ? ret : 0;
   ```
   即使待收取数尚未达到 `min_complete`（只要 `CQ` 中至少已有 1 个未读 CQE，即 `cq.head != cq.tail`），被信号中断或超时后 `io_cqring_wait()` 仍返回 `0`（不返回 `-EINTR`/`-ETIME`）。此外，内核主动将 `min_complete` 钳位至 `min(min_complete, ctx->cq_entries)`（[io_uring.c:3385-3386](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L3385-L3386)）。
3. **禁止 `SA_RESTART` 自动重启**：`io_cqring_wait_schedule()` 在 `task_sigpending(current)` 时直接返回 **`-EINTR`**（而非 `-ERESTARTSYS`），因此即便信号处理函数配置了 `SA_RESTART`，`io_uring_enter` 也**不能**自动重启系统调用。同时，若设置了临时 `sigmask`，返回 `-EINTR` 时内核调用 `restore_saved_sigmask_unless(ret == -EINTR)` 保留临时掩码直至信号投递完成再由 `sigreturn` 恢复原掩码（[io_uring.c:2636](https://github.com/torvalds/linux/blob/v6.12/io_uring/io_uring.c#L2636)）。

---

## 4. LTP `io_uring01`–`io_uring04` 逐项审计

### 4.1 测试镜像二进制基线核对

对 `/home/muou/PulseOS/rootfs/base/rootfs-tests-riscv64.tar.xz` 与 `rootfs-tests-loongarch64.tar.xz` 中 `./opt/ltp/testcases/bin/io_uring0{1..4}` 静态 ELF 二进制的只读字符串检查表明，双架构测试镜像内建的 LTP 版本为 **`20260930`**，与上游 LTP commit [`686a331b6`](https://github.com/linux-test-project/ltp/commit/686a331b6)（及本地参考树 `/home/muou/PulseOS/tests/ltp`）逐字节一致。

### 4.2 四个测例共用的框架假设

1. **支持性探针（`io_uring_setup_supported_by_kernel()`）**：见 `lapi/io_uring.h:322-338`。所有 4 个测例的 `setup()` 都会首先调用 `syscall(__NR_io_uring_setup, NULL, 0)`（注意首参 `entries=0`、次参 `params=NULL`）。若返回 `-ENOSYS` 则以 `TCONF` 跳过；若返回其他错误（如 `-EFAULT` / `-EINVAL`）则认定内核支持 `io_uring` 并继续执行。**若内核对该空指针探针 panic 而非安全返回 `-EFAULT`/`-EINVAL`，全部 4 个测例都会崩溃。**
2. **`.save_restore` sysctl 检查**：4 个测例均声明：
   ```c
   {"/proc/sys/kernel/io_uring_disabled", "0", TST_SR_SKIP_MISSING | TST_SR_TCONF_RO}
   ```
   因带有 `TST_SR_SKIP_MISSING`，若 PulseOS 未提供 `/proc/sys/kernel/io_uring_disabled`，LTP 仅打印 `TINFO` 并继续运行（见 `tst_sys_conf.c:65-70`）；若提供了该文件但设为只读，则会触发 `TCONF`。
3. **`mmap` 与 `sigset_t` 约定**：
   - `io_uring01`、`io_uring03`（`io_uring_common.h:68-98`）与 `io_uring02`（`tst_safe_io_uring.c:33-72`）均使用 `PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE` 分别调用三次 `mmap`（`SQ_RING`、`SQES`、`CQ_RING`），**不读取 `IORING_FEAT_SINGLE_MMAP`**。
   - `lapi/io_uring.h:314-319` 中的 `io_uring_enter()` 包装函数固定向第 6 参数传递 `_NSIG / 8`（`8`），即便 `sig == NULL`（如 `io_uring02`）。

### 4.3 逐项依赖矩阵与隐含陷阱

| 测例 | `setup` 参数 / `flags` | `IORING_FEAT_*` 要求 | `IORING_REGISTER_*` | `IORING_OP_*` 与 `IOSQE_*` | 外部系统调用与隐含陷阱 / 对 #224 的影响 |
| --- | --- | --- | --- | --- | --- |
| **`io_uring01`** | `entries = 1`, `flags = 0`<br>（`sq=1, cq=2`） | 不检查特定 `FEAT_*`；要求 `IORING_OFF_CQ_RING` 可单独 `mmap` | `IORING_REGISTER_BUFFERS` (`nr=1`, 1024B)<br>`IORING_UNREGISTER_BUFFERS` (`NULL, 1`) | `IORING_OP_READ_FIXED`<br>`IOSQE` flags = `0` (`buf_index=0`, 普通 `fd`) | **陷阱 1（与 #224 范围衔接）**：#224 正文目前仅点名 `READ`/`WRITE`/`READV`/`WRITEV`，但 **`io_uring01` 依赖固定缓冲注册与 `IORING_OP_READ_FIXED`**，必须纳入兼容范围。<br>**陷阱 2**：`cleanup_io_uring_test()` 调用 `IORING_UNREGISTER_BUFFERS` 时误传 `nr_args = QUEUE_DEPTH (1)`（Linux 内核会按 `register.c:395` 返回 `-EINVAL`，测例忽略返回值，依赖随后 `close(ring_fd)` 自动回收固定缓冲）。<br>**陷阱 3**：`RLIMIT_MEMLOCK` 在无 `CAP_IPC_LOCK` 时会限制 `IORING_REGISTER_BUFFERS`（LTP 默认 root 运行）；且 `io_uring_enter` 传入静态全零 `&sig`（非 `NULL`，8 字节）。<br>**无 `SQPOLL`/`IOPOLL`**。 |
| **`io_uring02`**<br>(CVE-2020-29373) | `entries = 512`, `flags = 0`<br>（`sq=512, cq=1024`） | 不检查特定 `FEAT_*`；要求 `IORING_OFF_CQ_RING` 可单独 `mmap`；使用 `__atomic_store/load` | 无 | **主路径**：`IORING_OP_SENDMSG` + **`IOSQE_ASYNC`**<br>**回退路径**：若返回 `-EINVAL`，改用 256 个 `IORING_OP_SENDMSG` + **`IOSQE_IO_DRAIN`** | **陷阱 1（CAPS + `gettid`）**：声明 `.caps = { CAP_SYS_CHROOT }`，前置调用 `capget(pid = gettid())`（见 `tst_capability.c:43-46`）。<br>**陷阱 2（PulseOS `AF_UNIX` + `chroot` 路径问题，高风险！）**：测例在 `chroot("test_root")` 前创建两个 `AF_UNIX SOCK_DGRAM` socket 并对 `recvsock` 调用 `bind(tmpdir/sock)`，随后在 `chroot` 后通过 `io_uring` `IORING_OP_SENDMSG` 向 `tmpdir/sock` 发包，**断言 CQE `res == -ENOENT`**（验证异步执行不绕过 `chroot`）。当前 PulseOS 的 `sys_socket(AF_UNIX, SOCK_DGRAM)` 退化为 `UdpSocket`（[socket.rs:90-92](../../pulse_syscalls/src/impls/net/socket.rs#L90-L92)），且 `resolve_unix_addr()` 直接用原始字符串查全局 `UNIX_REGISTRY`（[io.rs:46-63](../../pulse_syscalls/src/impls/net/io.rs#L46-L63)），**未经 `chroot` 后的 `fs_context` 路径解析**——若不修正，`chroot` 外的目标仍会命中从而导致 `"Write outside chroot succeeded"` 失败！<br>**陷阱 3（回退路径依赖 `SO_SNDBUF`）**：PulseOS `setsockopt(SO_SNDBUF)` 当前为返回 `0` 的空桩（[opt.rs:510-514](../../pulse_syscalls/src/impls/net/opt.rs#L510-L514)），无法缩小缓冲区迫使 255 次 `socketpair` 发送返回 `-EAGAIN`。因此 **PulseOS 应支持 `IOSQE_ASYNC`** 走主路径（异步执行必须继承提交任务的 `fs_context` / `chroot` 根目录），同时修复 `AF_UNIX` 路径解析。<br>**无 `SQPOLL`/`IOPOLL`**。 |
| **`io_uring03`** | `entries = 2`, `flags = 0`<br>（`sq=2, cq=4`） | 不检查特定 `FEAT_*`；要求 `IORING_OFF_CQ_RING` 可单独 `mmap` | 无 | `IORING_OP_WRITE`<br>`IORING_OP_READ`<br>`IOSQE` flags = `0` | 除 `io_uring_setup/enter` + 3 次 `mmap` 外，仅使用 `open`/`fsync`/`close` 与 `sigemptyset(&sig)`；包含整块 4096B 读写与两次 2048B 偏移写后整块读回校验。<br>**无 `SQPOLL`/`IOPOLL`、无特殊陷阱**，是最纯粹的核心文件读写冒烟基准。 |
| **`io_uring04`**<br>(CVE-2026-43494 / PinTheft) | 两个 ring，均为 `entries = 1`, `flags = 0` | 不做 `mmap`（仅做 `setup` + `register`） | `IORING_REGISTER_BUFFERS`<br>**`IORING_REGISTER_CLONE_BUFFERS`** (`op=30`)<br>`IORING_UNREGISTER_BUFFERS` | 无 SQE 提交（仅触发 `sendmsg(..., MSG_ZEROCOPY)`） | **陷阱 1（无配置前置 `TBROK`！）**：声明 `.needs_kconfigs = { "CONFIG_RDS", "CONFIG_RDS_TCP", "CONFIG_IO_URING" }`。若运行环境无 `/proc/config.gz` 或 `/boot/config-$(uname -r)` 且未导出 **`KCONFIG_SKIP_CHECK=1`**，`tst_kconfig_read()` 会**在 `setup()` 执行前直接 `TBROK: Cannot parse kernel .config`**（见 `tst_kconfig.c:287-289`）。<br>**陷阱 2（`AF_RDS` 依赖，即使跳过 kconfig 也只会 `TCONF`）**：`setup()` 调用 `socket(AF_RDS, SOCK_SEQPACKET \| SOCK_CLOEXEC, 0)`；当前 PulseOS 返回 `-EAFNOSUPPORT`，故测例触发 `TCONF: RDS is not available` 跳过（而非 `TPASS`）。<br>**陷阱 3**：若真要运行其后半段，还依赖 `IORING_REGISTER_CLONE_BUFFERS`（Linux 6.12+）、`SAFE_FORK()`、`mprotect(PROT_NONE)` 以及 `.taint_check` 读取 `/proc/sys/kernel/tainted`（PulseOS 已在 [procfs.rs:415-419, 1009](../../modules/axfs/src/fs/procfs.rs#L415-L419) 提供只读 `"0\n"`）。<br>**无 `SQPOLL`/`IOPOLL`**。 |

### 4.4 与 #224 `Out of scope` 的冲突核对

1. **无 `SQPOLL` / `IOPOLL` / `PBUF_RING` / `MULTISHOT` / `URING_CMD` 冲突**：`io_uring01`–`io_uring04` 全部使用默认中断驱动/同步提交模型（`setup_flags = 0`），**无一触及 `Out of scope` 列表**。
2. **与 #224 正文目标能力清单的两处增量对齐建议**：
   - 须将 **`IORING_REGISTER_BUFFERS` / `IORING_UNREGISTER_BUFFERS` 与 `IORING_OP_READ_FIXED`（及对称的 `WRITE_FIXED`）** 明确纳入 #224 目标能力（`io_uring01` 必需）。
   - 须明确 **`io_uring02` 依赖 `IORING_OP_SENDMSG` + `IOSQE_ASYNC`（异步继承 `chroot` `fs_context`）及 `AF_UNIX SOCK_DGRAM` 路径解析修复**，并明确 **`io_uring04` 在无 RDS 协议栈时的验收口径为 `KCONFIG_SKIP_CHECK=1` 下的确定性 `TCONF`**（不把 `AF_RDS` 纳入 `#224` 范围）。

---

## 5. PulseOS 仓库 Rust Crate 与内核基础现状核对

| 仓库文件 / Crate | 当前状态 | 精确依据与设计启示 |
| --- | --- | --- |
| `syscalls` (`0.8.1`) | **已就绪** | `Cargo.lock:2660-2664` 锁定 `0.8.1`；`pulse_syscalls/Cargo.toml:51-56` 按架构启用 `"riscv64"` / `"loongarch64"`。`src/arch/riscv64.rs:570-574` 与 `src/arch/loongarch64.rs:608-612` 均已定义 `Sysno::io_uring_setup = 425`、`Sysno::io_uring_enter = 426`、`Sysno::io_uring_register = 427`。 |
| `linux-raw-sys` (`0.12.1`) | **已包含完整绑定，仅需启用 feature** | `Cargo.lock:1842-1846` 锁定 `0.12.1`；`src/riscv64/io_uring.rs` 与 `src/loongarch64/io_uring.rs` 内容完全一致，已包含 `io_uring_params`、`io_sqring_offsets`、`io_cqring_offsets`、`io_uring_sqe`、`io_uring_cqe`、`io_uring_getevents_arg`、`__kernel_timespec`、`io_uring_rsrc_*`、`io_uring_probe*`、`io_uring_clone_buffers` 等全部结构与枚举。当前根 `Cargo.toml:109-115`、`pulse_syscalls/Cargo.toml:21`、`crates/pulse_user_abi/Cargo.toml:12` **尚未开启 `"io_uring"` feature**。注意该版本生成自 Linux ~6.14/6.15 头文件（`IORING_OP_LAST=63`, `IORING_REGISTER_LAST=35`, `io_uring_clone_buffers` 含 `src_off`/`dst_off`/`nr`），若以 v6.12 为兼容基线，需在校验掩码中显式限定受支持的 flags 与 opcode 范围。 |
| `pulse_syscalls/src/handler.rs` | **尚未分发** | `syscall_dispatcher()`（[handler.rs:162-486](../../pulse_syscalls/src/handler.rs#L162-L486)）当前未匹配 `io_uring_setup` / `io_uring_enter` / `io_uring_register`，走默认分支返回 `-ENOSYS`。另注意 `syscall_handler`（[handler.rs:70-89](../../pulse_syscalls/src/handler.rs#L70-L89)）仅在返回值为 `-ERESTARTSYS` 时按 `SA_RESTART` 重启；`io_uring_enter` 按 Linux 契约直接返回 `-EINTR` 即可天然避免被 `SA_RESTART` 错误重启。 |
| `crates/pulse_user_abi` | **可直接复用安全 ABI 编解码边界** | 该 crate 声明 `#![forbid(unsafe_code)]`（[lib.rs:1-2](../../crates/pulse_user_abi/src/lib.rs#L1-L2)），当前已实现 `sigevent`、`timespec`（LP64 下与 `__kernel_timespec` 同为 16 字节布局）等 ABI 编解码与 `const _` size/offset 编译期断言；后续可直接将 `io_uring_params`、`io_uring_getevents_arg`、`__kernel_timespec`、`io_uring_rsrc_*` 等纳入其 `UserAbiType` 边界。 |
| `sys_mmap` 与共享页基础设施 | **偏移透传与页生命周期基础已就绪** | `sys_mmap`（[mm.rs:286](../../pulse_syscalls/src/impls/mm.rs#L286)）已校验页对齐 `offset` 并将原始字节偏移直接透传给 `FdObject::mmap_prepared(aligned_length, map_flags, offset, is_shared)`；`modules/axmm/src/backend/shared.rs` 已提供 `SharedFrame`；`pulse_syscalls/src/impls/utils/pinned_buffers.rs` 已提供 `PinnedUserBuffers`；`modules/axfs/src/fs/procfs.rs:415-419, 1009` 已提供 `/proc/sys/kernel/tainted`（`"0\n"`）。 |
