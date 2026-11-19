# 上游 liburing 核心测试子集与 fio --ioengine=io_uring 最小兼容面研究

- 对应地图：[#224 PulseOS io_uring 架构与兼容规划地图](https://github.com/muou000/PulseOS/issues/224)。
- 对应 research：[#226 调研上游 liburing 核心测试子集与 fio --ioengine=io_uring 的最小兼容面](https://github.com/muou000/PulseOS/issues/226)。
- 研究日期：2026-11-19。
- 上游源码依据：直接审计 `axboe/liburing`（`liburing-2.5` 至 `liburing-2.15`，重点锁定 `liburing-2.9`）与 `axboe/fio`（`fio-3.36` 至 `fio-3.43`，重点锁定 `fio-3.39`）一手源码；PulseOS 仓库依据基于 `main` (`4a9a870c49fda8e74cd7b3430522e9e671f29e2f`) 及已验证构建产物。
- 状态：研究结论与兼容基线建议；不表示 PulseOS 内核已实现 `io_uring` 系统调用。

## 执行摘要

1. **推荐固定版本**：
   - **`liburing` 推荐锁定 `liburing-2.9`**（`08468cc3830185c75f9e7edefd88aa01e5c2f8ab`）：完整覆盖稳定 ABI（`LIBURING_2.0`–`LIBURING_2.9`），包含对弱内存序架构（RISC-V 64 / LoongArch64 SMP）至关重要的 C11 `<stdatomic.h>` 内存序修复（`f03becf`，2.6 合入），自带 UAPI 头文件与缺失结构体 `compat.h` 生成机制，默认探测 `IORING_SETUP_NO_SQARRAY` 并在内核返回 `-EINVAL` 时自动降级重试，且不引入 `2.13`–`2.15` 中 Linux 6.15+ 的 BPF filter / ring query / mixed CQE 负担。[S1][S2][S3]
   - **`fio` 推荐锁定 `fio-3.39`**（`a6e474c9e896e4ba1eb40066a03402afb040710a`）：**完全不依赖 `liburing`**（自带 `os/linux/io_uring.h` 并直接调用 `syscall(__NR_io_uring_*)` / RV64 内联 `ecall`），已修复 RV64 时钟源（由 `rdcycle` 改为 `rdtime`，避免 U-mode `SIGILL`）、CQE 负 `errno` 转换错误、`--build-static` 静态链接探测以及非 2 次幂 `iodepth` 误抬高问题，且尚未引入 `3.42`/`3.43` 的 `IORING_FEAT_NO_IOWAIT` 与无条件 `IORING_REGISTER_RING_FDS` 调用。[S4][S5][S6]
2. **关键内核兼容契约（来自 `liburing` 与 `fio` 源码实证）**：
   - **未知/不支持 setup flags 必须返回 `-EINVAL`**：`liburing-2.6+` 启动默认尝试 `IORING_SETUP_NO_SQARRAY`，`fio` 默认启动无条件依次尝试 `IORING_SETUP_CQSIZE | COOP_TASKRUN | SINGLE_ISSUER | DEFER_TASKRUN`；**两者都严格判定 `errno == EINVAL` 才剥离标志重试**，若 PulseOS 返回 `-EOPNOTSUPP` 或 `-ENOSYS` 将直接导致初始化失败。[S1][S4]
   - **`sq_off.array` 映射不可省略**：`fio` 不支持 `IORING_SETUP_NO_SQARRAY`，始终直接向 `sq_ring.array[tail & mask]` 写入 SQE 索引；`liburing` 在非 `NO_SQARRAY` 路径同样写入 `sq->array`。[S1][S4]
   - **`fio` 的 `mmap` 与 `io_uring_enter` 特殊行为**：`fio` **忽略 `IORING_FEAT_SINGLE_MMAP`**，始终对 `IORING_OFF_SQ_RING`、`IORING_OFF_SQES`、`IORING_OFF_CQ_RING` 发起 3 次 `mmap(..., MAP_SHARED | MAP_POPULATE, ...)`，且从不调用 `madvise(MADV_DONTFORK)`；提交路径固定调用 `io_uring_enter(fd, nr, 0, IORING_ENTER_GETEVENTS, NULL, 0)`，要求 `min_complete=0` 时立即刷新而非阻塞，且**必须返回已消费的 SQE 数量 `nr`**（返回 `0` 会导致 `fio` 死循环）。[S4]
   - **`madvise(MADV_DONTFORK)` 风险澄清**：当前 PulseOS `sys_madvise` 对 `MADV_DONTFORK` 返回 `-EINVAL`，但 `liburing` 仅在显式调用 `io_uring_ring_dontfork()` 时才执行该 syscall；`io_uring_queue_init*`、常规核心测例与 `fio` 均不自动调用它。[P1][S1]
3. **双架构交叉编译与 Rootfs 集成可行性**：
   - **RISC-V 64（RV64GC 无 RVV）**：主机已具备 `riscv64-linux-gnu-gcc` 13.3.0；本次在独立暂存区实测交叉构建 `liburing-2.9` 静态库/测例与 `fio-3.39`（`--build-static --disable-native`，`-march=rv64gc -mabi=lp64d`），全部编出静态 ELF，`readelf -A` 均报告 `rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zmmul1p0`，无任何 `v*`/`zv*` 向量指令，可直接通过 `scripts/build_img.sh` 的 `validate_riscv_elf_isa()` 门禁。[P2]
   - **LoongArch64（ABI 分裂关键约束）**：Ubuntu 24.04 仓库提供 `gcc-14-loongarch64-linux-gnu` + `libc6-dev-loong64-cross`（**New-World ABI**, `ld-linux-loongarch-lp64d.so.1` / glibc 2.39），但实测 PulseOS 的 `rootfs-tests-loongarch64.tar.xz` 与 `base-rootfs-loongarch64.tar.xz` 均为 **Loongnix-Server 8（Old-World ABI, `usr/lib64/ld-2.28.so` / glibc 2.28）**。因此，**`loongarch64`（及为一致性的 `riscv64`）必须使用全静态链接（`-static` / `--build-static`）**，避免与 guest 动态链接器产生 ABI 不兼容。[P2][P3]

---

## 1. 上游固定版本候选对比与推荐

### 1.1 `liburing` 候选版本对比（`2.5`–`2.9` 及 `2.10`–`2.15` 参照）

`liburing` 全系列采用严格的符号版本控制（`src/liburing.map` 从 `LIBURING_2.0` 向上兼容至对应版本）与 MIT/LGPL 双协议，源码自身内置了内核 UAPI 头文件 `src/include/liburing/io_uring.h`，并在 `./configure` 阶段自动检测宿主机交叉编译头文件中是否缺失 `__kernel_rwf_t`、`struct __kernel_timespec`、`struct open_how`、`struct futex_waitv`、`idtype_t`、`BLOCK_URING_CMD_DISCARD`，缺失则自动生成 `src/include/liburing/compat.h` 兜底。[S2][S7]

| 版本 tag (commit) | 发布日期 | ABI 与关键内核特性 | 特性探测与退避行为 | 构建/架构差异 | 适配评估 |
| --- | --- | --- | --- | --- | --- |
| `liburing-2.5` (`f4e42a51`) | 2023-11-04 | `LIBURING_2.0`–`2.5`；已有 RV64 `CONFIG_NOLIBC` (`d305ed5`) 与 `--use-libc` (`151f805`) | 不默认发送 `IORING_SETUP_NO_SQARRAY`；支持 `IORING_FEAT_EXT_ARG` 自动回退 `LIBURING_UDATA_TIMEOUT` | 缺少 `f03becf` 内存序修复，弱序多核 SMP 下部分环头尾读取仍依赖普通访存或更严栅栏 | 次选：缺 C11 atomic 完整修复，部分新测试修复未包含 [S3][S8] |
| `liburing-2.6` (`f7dcc1ea`) | 2024-04-30 | 新增 `IORING_SETUP_NO_SQARRAY` 默认尝试 (`3401b06`)；合入 `f03becf` | `io_uring_queue_init_try_nosqarr()` 先尝试 `NO_SQARRAY`，遇 `-EINVAL` 自动回退清标志重试 | `f03becf` 将 `sq.khead`/`cq.ktail`/`cq.khead` 统一到 C11 `<stdatomic.h>` `acquire`/`release`/`relaxed` | 关键分水岭：弱序 SMP 正确性达标，但缺后续 bugfix [S1][S3] |
| `liburing-2.7` (`5227d48b`) | 2024-08-16 | 新增 `IORING_REGISTER_CLOCK` / `PBUF_STATUS` 等 | 延续 `2.6` 探测回退逻辑；`wait-timeout` 探测时钟注册遇 `-EINVAL` 跳过 | 同 `2.6` | 可用，但 `2.9` 修复了更多 `setup`/`queue` 边界问题 |
| `liburing-2.8` (`80272cbe`) | 2024-10-25 | 新增 `IORING_FEAT_MIN_TIMEOUT` 与 sanitizer 辅助 (`fa56f18`) | `io_uring_submit_and_wait_min_timeout()` 检查 `IORING_FEAT_MIN_TIMEOUT` 否则返回 `-EINVAL` | 同 `2.6`，新增 `sanitize.c`（仅启用 `--enable-sanitizer` 时编译） | 可用，`2.9` 包含其全部能力并修复 `alloc_huge` 等问题 |
| **`liburing-2.9`** (`08468cc3`) | 2025-02-03 | `LIBURING_2.0`–`2.9`；含 `RESIZE_RINGS`/`CLONE_BUFFERS`/`MEM_REGION`（均按需显式调用） | 保留对 `NO_SQARRAY`、`-EINVAL`、`IORING_FEAT_EXT_ARG`、`IORING_REGISTER_PROBE` 的完整探测与平滑退避；修复 `ring_enter_flags` 传播与 `SQE128` 映射清理 | 零外部库依赖；RV64 自动 `CONFIG_NOLIBC=y`（也支持 `--use-libc`）；LA64 自动切换 `src/arch/generic/` | **强烈推荐锁定** [S1][S2][S7] |
| `liburing-2.10`–`2.15` (`d41bf922`) | 2025-05 ~ 2026-06 | 引入 Linux 6.15–7.x 的 `bpf_filter.h`、`query.h`、`SQ_REWIND`、`CQE_MIXED` | `2.15` 新增 `IOPOLL && !SQPOLL` 检查及多页/混合 CQE 逻辑 | `2.15` (`284b1a8`) 改写 RV64 libc 模式页大小读取；测试集充斥大量 6.15+ 新特性用例 | 不推荐：超出 #226 候选范围且增加无关内核版本噪音 [S8] |

**结论**：推荐锁定 **`liburing-2.9`**。它在 `2.5`–`2.9` 区间内既吸纳了 `f03becf` 对弱内存模型（RV64/LA64 SMP）的 `<stdatomic.h>` 原子访存修复与 `setup`/`queue` 边界修正，又对不支持的新特性保持 `-EINVAL` / feature-bit 平滑退避，且未引入 `2.10+` 针对 Linux 6.15+ 的新接口与测试负担。[S1][S3][S7]

### 1.2 `fio` 候选版本对比（`3.36`–`3.39` 及 `3.40`–`3.43` 参照）

首先确认一个决定性源码事实：**`fio` 的 `--ioengine=io_uring` 引擎 (`engines/io_uring.c`) 不链接也不依赖 `liburing`**。它直接包含项目内自带的 `os/linux/io_uring.h`，并通过 `arch/arch.h` 无条件启用 `ARCH_HAVE_IOURING`（默认定义 `__NR_io_uring_setup = 425`、`__NR_io_uring_enter = 426`、`__NR_io_uring_register = 427`），直接向内核发起原始系统调用。[S4][S9][S10]

| 版本 tag (commit) | 发布日期 | RV64 / LA64 与交叉构建支持 | `engines/io_uring.c` 兼容行为 | 构建依赖 | 适配评估 |
| --- | --- | --- | --- | --- | --- |
| `fio-3.36` (`624e263f`) | 2023-10-20 | `arch/arch-riscv64.h` 使用 `rdcycle` 实现 `get_cpu_clock()`，且无 RV64 内联 syscall 宏；`arch-loongarch64.h` 已有 `dbar 0` 屏障 | `td->o.iodepth` 被 `roundup_pow2()` 直接覆写；存在 CQE 负 `errno` 转换问题 | 核心仅需 libc/pthread/dl（`zlib` 可选） | **不推荐**：RV64 若 U-mode 禁用 `cycle` CSR 将触发 `SIGILL` [S11] |
| `fio-3.37` (`9213e16d`) | 2024-03-26 | `577b85ec` 将 RV64 时钟改为 `rdtime`；`b823153a` 增加 RV64 `FIO_ARCH_HAS_SYSCALL` (`ecall`)；`1ee0469f` 修复交叉 `pkg-config` | 仍有 CQE 负错误码与队列深度覆写问题 | 同上 | 次选：缺 `3.38`/`3.39` 的 CQE 错误码与静默构建修复 [S5] |
| `fio-3.38` (`5af800ca`) | 2024-10-02 | 保留 RV64 `rdtime` 与 `ecall`；`280b3841` 修复 `--build-static` 探测 | `78831c6b` / `e4e8520b` 修复 CQE 负 `errno` 赋值 | 同上 | 可用，但 `3.39` 进一步修正了非 2 次幂 `iodepth` 处理 |
| **`fio-3.39`** (`a6e474c9`) | 2025-02-18 | 完整涵盖 RV64 (`rdtime` + `__do_syscall6`)、LA64 (`dbar 0` + `clock_gettime`) 与 `--build-static` 修复 | 合入 `af0ad0fa`（仅环形队列 `ld->iodepth` 取 2 次幂，不篡改 `td->o.iodepth`）；包含 CQE 错误码修复；**不**调用 `IORING_REGISTER_RING_FDS` 与 `IORING_FEAT_NO_IOWAIT` | 实测 `--build-static --disable-native` 零第三方库即可编出含 `io_uring` 静态二进制 | **强烈推荐锁定** [S4][S6][S9] |
| `fio-3.40`–`3.43` (`d2dcd7e0`) | 2025-05 ~ 2026-09 | `3.42` (`d200fabf`) 移除 `get_cpu_clock()` 统一走 `clock_gettime()` | `3.42` 引入 `IORING_FEAT_NO_IOWAIT` / `IORING_ENTER_NO_IOWAIT`；`3.43` 无条件先调 `IORING_REGISTER_RING_FDS` | 同上 | 不推荐：`3.43` 增加不必要的 `RING_FDS` 探测调用，且超出 3.36–3.39 基线 [S12] |

**结论**：推荐锁定 **`fio-3.39`**。它彻底规避了 `3.36` 的 RV64 `rdcycle` `SIGILL` 风险，并具备 CQE 错误处理修正、精确 `iodepth` 控制与干净的最小系统调用集。[S4][S5][S6]

---

## 2. `liburing` 初始化、特性探测审计与核心测试子集

以下分析基于 `liburing-2.9` (`08468cc3`) 源码逐行审计。

### 2.1 启动与运行期核心 API 的内核依赖审计

| `liburing` API（源码位置） | 调用的 syscall / 底层操作 | 依赖或探测的 `IORING_SETUP_*` / `IORING_FEAT_*` / 其他条件 | 失败回退与 PulseOS 兼容契约 |
| --- | --- | --- | --- |
| `io_uring_queue_init` / `io_uring_queue_init_params` (`src/setup.c:369-430`) | `io_uring_setup(entries, &p)` -> 成功后调用 `io_uring_queue_mmap` | 先通过 `io_uring_queue_init_try_nosqarr()` 自动叠加 `p->flags \|= IORING_SETUP_NO_SQARRAY`；若未设 `IORING_SETUP_NO_MMAP` 则调 `mmap`；读取 `p->sq_off` 与 `p->cq_off`，并在非 `NO_SQARRAY` 时初始化 `sq->array[i] = i` | **必须对未知/不支持的 `p->flags` 返回 `-EINVAL`**：源码仅当 `ret == -EINVAL` 时剥离 `IORING_SETUP_NO_SQARRAY` 并用原 `flags` 重试 (`src/setup.c:380`)。若不支持 `NO_SQARRAY`，PulseOS 需填好 `sq_off.array` 且对 `NO_SQARRAY` 返回 `-EINVAL`。 |
| `io_uring_queue_mmap` / `io_uring_mmap` (`src/setup.c:97-161`) | 2 次或 3 次 `mmap(0, sz, PROT_READ\|PROT_WRITE, MAP_SHARED\|MAP_POPULATE, fd, offset)` | 检查 `p->features & IORING_FEAT_SINGLE_MMAP` (`src/setup.c:110,121`)：<br>1. **置位时**：只以 `max(sq_sz, cq_sz)` 映射一次 `IORING_OFF_SQ_RING` (`0`)，令 `cq->ring_ptr = sq->ring_ptr`，再映射 `IORING_OFF_SQES` (`0x10000000`)。<br>2. **未置位时**：分别映射 `IORING_OFF_SQ_RING` (`0`)、`IORING_OFF_CQ_RING` (`0x8000000`)、`IORING_OFF_SQES` (`0x10000000`)。 | `sq->ring_sz` 始终按 `p->sq_off.array + p->sq_entries * 4` 计算；`MAP_POPULATE` 须被内核 `sys_mmap` 接受（PulseOS `sys_mmap` 已将其列入 `supported` 掩码，[P1]）。建议 PulseOS 按 #224 架构同时支持 3 个 offset（若置 `SINGLE_MMAP` 则前两者共享同一页框组，且需仍允许单独映射 `IORING_OFF_CQ_RING` 以兼容 `fio`）。 |
| `io_uring_ring_dontfork` (`src/setup.c:167-196`) | 2 次或 3 次 `madvise(ptr, len, MADV_DONTFORK)` | 仅作用于 `sq.sqes`、`sq.ring_ptr` 和（非 `SINGLE_MMAP` 时的）`cq.ring_ptr` | **非自动调用**！`io_uring_queue_init*` 与 `io_uring_queue_mmap` 均**不**调用它；`liburing/test/` 与 `fio` 亦无任何调用处。当前 PulseOS `sys_madvise` 对 `MADV_DONTFORK` 返回 `-EINVAL` [P1]：对默认测试与 `fio` 无阻塞，但若第三方用户代码显式调用会失败，后续可评估将 `MADV_DONTFORK`/`MADV_DOFORK` 纳入 `axmm` 或视语义支持。 |
| `io_uring_submit_and_wait` (`src/queue.c:419-463`) | `io_uring_enter(enter_ring_fd, submitted, wait_nr, flags, NULL)`（`_NSIG/8`） | 无 `SQPOLL`/`IOPOLL` 时：若 `submitted > 0` 或 `wait_nr > 0` 或 `sq.kflags & (IORING_SQ_CQ_OVERFLOW \| IORING_SQ_TASKRUN)`，进入内核；当 `wait_nr > 0` 时附加 `IORING_ENTER_GETEVENTS` | 必须返回已提交 SQE 数量（`>= 0`）；更新 `sq->khead` 必须在 `enter` 返回前可见。`sq->kflags` 指针若支持必须映射可读（无溢出写 0）。 |
| `io_uring_wait_cqe_timeout` / `io_uring_wait_cqes` (`src/queue.c:295-311,407-412`) | `io_uring_enter2` (`_io_uring_get_cqe`) | **探测 `p->features & IORING_FEAT_EXT_ARG`**：<br>1. **置位时** (`EXT_ARG`)：传 `IORING_ENTER_GETEVENTS \| IORING_ENTER_EXT_ARG`，`arg = &io_uring_getevents_arg{sigmask, sigmask_sz, ts}`，`sz = sizeof(arg)`；超时返回 `-ETIME`。<br>2. **未置位时**：回退调用 `__io_uring_submit_timeout()` 在 SQ 环内注入一条 `IORING_OP_TIMEOUT`（`user_data = LIBURING_UDATA_TIMEOUT = -1ULL`），再按 `to_submit` + `wait_nr` 进入内核；`__io_uring_peek_cqe()` (`liburing.h:1468-1476`) 自动吞掉该内部超时 CQE 并将 `-ETIME` 作为返回值上报。 | **重要权衡**：若 PulseOS 支持 `IORING_FEAT_EXT_ARG`，`wait_cqe_timeout` 不会占用 SQ 槽位，也不会限制并发 SQ/CQ 拆分或受 SQ 满影响；若暂不置 `IORING_FEAT_EXT_ARG`，只要支持 `IORING_OP_TIMEOUT` 即可平滑回退工作，但要注意应用不得将 `user_data` 设为 `-1ULL`。 |
| `io_uring_get_probe_ring` / `io_uring_get_probe` (`src/setup.c:461-499`, `src/register.c:232-236`) | `io_uring_register(fd, IORING_REGISTER_PROBE, probe, 256)`（`get_probe` 先建 `entries=2` 临时环） | 探针缓冲区大小为 `sizeof(io_uring_probe) + 256 * sizeof(io_uring_probe_op)`；校验 `p->last_op`、`p->ops_len`（当传入 `nr_ops=0` 时 `ops_len` 仍为 `0` 但填写 `last_op`）与 `p->ops[op].flags & IO_URING_OP_SUPPORTED` | 若内核返回 `< 0`，`io_uring_get_probe_ring` 释放内存返回 `NULL`。为了配合 `fio` 的 `nonvectored` 自动探测与 `liburing/test/probe.c`，建议 PulseOS 实现 `IORING_REGISTER_PROBE`。 |

补充关键事实（来自 `src/lib.h`、`src/syscall.h`、`src/arch/riscv64/`、`src/arch/generic/` 与 `src/nolibc.c`）：
- **页大小获取**：`riscv64` 默认 `CONFIG_NOLIBC=y` 时，`src/arch/riscv64/lib.h:10-35` 读取 `/proc/self/auxv` 寻找 `AT_PAGESZ`，若 `/proc/self/auxv` 不可读/不存在，**安全回退 `4096`**（`get_page_size()` 仅在 `io_uring_queue_init_mem` / `io_uring_mlock_size` 中使用，常规 `io_uring_queue_init` 不触发）；`loongarch64`（及启用 `--use-libc` 时）调用 `sysconf(_SC_PAGESIZE)` 并同样在 `< 0` 时回退 `4096`。[S13][S14]
- **静态初始化与堆**：`CONFIG_NOLIBC=y` 下 `io_uring_get_probe_ring` 使用 `nolibc.c` 中的 `__uring_malloc`，其底层直接调用 `mmap(NULL, ..., PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)`，不依赖 `brk`。[S15]
- **其他 `IORING_FEAT_*` 行为**：`liburing` 本身只在 `setup.c:564` 检查 `IORING_FEAT_NATIVE_WORKERS`（决定 `mlock_size` 返回 `0`）、`register.c:294,322` 检查 `IORING_FEAT_REG_REG_RING`、`queue.c:249,387` 检查 `IORING_FEAT_MIN_TIMEOUT`；其余 `FEAT_*`（如 `NODROP`、`SUBMIT_STABLE`、`RW_CUR_POS`、`FAST_POLL`）主要由测试与上层应用读取 `ring->features` 决定预期语义。[S1][S16]

### 2.2 `liburing-2.9/test/` 核心测试子集清单（按操作域分类）

对 `liburing-2.9/test/` 共 190+ 项测例逐一检查源码后，结合 #224 目标能力与 Out-of-scope 排除项（排除 `SQPOLL`、`IOPOLL`、Provided Buffer Ring `PBUF_RING`、Multishot、`URING_CMD`、跨进程 ring 共享及 `DEFER_TASKRUN`/`SINGLE_ISSUER` 强依赖），将核心测试子集分为三层：

1. **Tier A（可直接纳入，零 OOS 强依赖）**：仅使用标准环或已通过 `if (ret == -EINVAL) skip` / `t_probe_defer_taskrun()` 安全跳过扩展子测试。
2. **Tier B（核心必测，需屏蔽个别 OOS 子测例/修复 `helpers.c` 跳过条件）**：主体功能完全在 #224 范围内，但默认 `main()` 中硬编码调用了 `SQPOLL` 子测试，或因 `test/helpers.c:135` 仅在 `ret == -EPERM && geteuid()` 时跳过 `SQPOLL`（在 rootfs root 用户且内核返回 `-EINVAL` 时不会自动跳过）。
3. **明确排除清单（含易混淆陷阱）**：看似基础但源码中无条件依赖 Out-of-scope 特性的测试。

#### Tier A：开箱即用核心测试子集（共 46 项测例）

| 操作域 | 测例文件 | 覆盖内核接口与主要验证点 | 探测 / 条件跳过说明 |
| --- | --- | --- | --- |
| **基础环** | `nop.c` | `IORING_OP_NOP`、`IOSQE_IO_DRAIN`、`IOSQE_ASYNC` | `FOR_ALL_TEST_CONFIGS` 中 `SQE128`/`CQE32` 遇 `-EINVAL` 自动跳过；`test_nop_inject` 接受 `-EINVAL` [S17] |
| 基础环 | `nop-all-sizes.c` | 1 至 `MAX_ENTRIES` 各 2 次幂深度环初始化与 `NOP` | 纯默认标志 `0` |
| 基础环 | `io_uring_setup.c` | `io_uring_setup` 非法参数契约（0 entries、NULL params、非零 `resv`、全 1 flags、`SQ_AFF` 无 `SQPOLL`、非法 CPU） | 期待 `-EINVAL`/`-EFAULT`，不要求实际启用 `SQPOLL` [S18] |
| 基础环 | `io_uring_enter.c` | `io_uring_enter` 错参校验（`-EINVAL`/`-EBADF`/`-EOPNOTSUPP`）、批量 `READV` + `GETEVENTS`、非法 `sq->array` 索引计数 `kdropped` | 使用 `t_io_uring_init_sqarray`（非 `NO_SQARRAY`）与 `*sq->kdropped` [S19] |
| 基础环 | `probe.c` | `IORING_REGISTER_PROBE`（`nr_ops=0` 与 `256`）与 `io_uring_get_probe_ring` | 校验 `NOP`/`READV`/`WRITE` 支持位；若 PROBE 自身返回 `-EINVAL` 则跳过 [S20] |
| 基础环 | `version.c` | `io_uring_major_version` / `minor_version` / `check_version` | 纯库函数自检 |
| 基础环 | `cq-size.c` | `IORING_SETUP_CQSIZE` 合法与 `cq_entries=0` 非法路径 | 不支持 `CQSIZE` 返回 `-EINVAL` 时打印跳过 |
| 基础环 | `cq-ready.c`, `cq-full.c`, `cq-peek-batch.c` | `io_uring_cq_ready`、`koverflow` / `IORING_FEAT_NODROP`、批量 peek | 需关注 `cq-full.c`：未置 `IORING_FEAT_NODROP` 时要求 `*cq.koverflow == 4` |
| 基础环 | `sq-full.c`, `sq-space_left.c` | `io_uring_get_sqe` 满环边界与 SQ 剩余空间统计 | 纯默认标志 `0` |
| 基础环 | `submit-and-wait.c` | `io_uring_submit_and_wait_timeout` 返回已提交数且不重复等待 | 兼容 `EXT_ARG` 有无两种路径 |
| 基础环 | `submit-reuse.c` | 提交后立即覆写 `iov_base` 验证拷贝稳定性 | 探测 `IORING_FEAT_SUBMIT_STABLE`，未置位则跳过 |
| 基础环 | `drop-submit.c` | 含错误 SQE 的批量提交（对比 `IORING_SETUP_SUBMIT_ALL` 与默认行为） | 不支持 `SUBMIT_ALL` 返回 `-EINVAL` 跳过 |
| 基础环 | `ignore-single-mmap.c` | 置位 `IORING_FEAT_SINGLE_MMAP` 时仅映射 SQ ring 大小 | 未置 `SINGLE_MMAP` 则跳过 |
| **文件读写** | `short-read.c` | `IORING_OP_READV` 读至 EOF 返回实际短读字节数 | 纯默认标志 `0` |
| 文件读写 | `rw_merge_test.c` | 管道 + 普通文件混合 `READV` + `io_uring_wait_cqe_timeout` | 需支持 `pipe` 与 `wait_cqe_timeout` |
| 文件读写 | `stdout.c` | 标准输出/管道 `WRITEV`、`WRITE_FIXED`、`READV` + `REGISTER_BUFFERS` | 纯默认标志 `0` |
| **fsync** | `fsync.c` | `IORING_OP_FSYNC`（含 `IORING_FSYNC_DATASYNC`）、`IOSQE_IO_DRAIN`、`IORING_OP_SYNC_FILE_RANGE` | 若未实现 `IOSQE_IO_DRAIN` 容忍 `-EINVAL`；**注意强依赖 `IORING_OP_SYNC_FILE_RANGE` 返回 `0`** [S21] |
| **poll** | `poll.c` | 管道 `POLL_ADD` 跨进程唤醒与 ring fd 自身 `POLL_ADD` (`test_self_poll`) | `DEFER_TASKRUN`/`SINGLE_ISSUER`/multishot 子测均被 `t_probe_defer_taskrun()` 门控跳过 [S22] |
| poll | `poll-cancel.c` | `POLL_ADD` + `POLL_REMOVE` 取消及 `LINK_TIMEOUT` 组合 | 纯默认标志 `0` |
| poll | `poll-cancel-all.c` | `ASYNC_CANCEL` (`IORING_ASYNC_CANCEL_ALL`) 批量取消悬空 poll | 若不支持 cancel flags 返回 `-EINVAL` 则跳过 |
| poll | `poll-cancel-ton.c` | 大规模 `POLL_ADD` / `POLL_REMOVE`（30,000 次） | `CQSIZE` 返回 `-EINVAL` 时自动降级重试默认 `flags=0` |
| poll | `poll-link.c` | `POLL_ADD` 链接 `LINK_TIMEOUT`（触发超时 vs 正常唤醒） | 纯默认标志 `0` |
| poll | `poll-ring.c` | 对 `ring.ring_fd` 本身提交 `POLL_ADD(POLLIN)` | 纯默认标志 `0` |
| poll | `pipe-eof.c`, `pipe-reuse.c`, `fifo-nonblock-read.c` | 管道 `READ`/`READV` 阻塞唤醒与写端关闭 EOF | 纯默认标志 `0` |
| **timeout** | `link-timeout.c` | `IOSQE_IO_LINK` + `IORING_OP_LINK_TIMEOUT`（含 `TIMEOUT_UPDATE`、`POLL_ADD`、`READV`/`WRITEV`） | `TIMEOUT_UPDATE` 若未实现会回退或返回 `-EINVAL` |
| **cancel** | `files-exit-hang-poll.c`, `files-exit-hang-timeout.c` | `POLL_ADD`/`TIMEOUT` + `ACCEPT` 悬停时进程/环退出不挂死 | 依赖 loopback TCP socket 与 `ALARM` 信号 |
| **socket** | `socket-nb.c`, `socket-rw.c`, `socket-rw-eagain.c` | Socket `RECV`（`MSG_DONTWAIT`）、`READV`/`WRITEV` 双向收发 | 依赖 AF_INET loopback TCP socket（`socket-rw-eagain` 在未设 `FAST_POLL` 时运行） |
| socket | `accept-test.c`, `accept-reuse.c`, `accept-link.c` | `IORING_OP_ACCEPT`（`AF_UNIX` 与 `AF_INET`）+ `LINK_TIMEOUT` | `accept-test` 若 `-EINVAL` 跳过；`accept-reuse` 依赖 `IORING_FEAT_SUBMIT_STABLE` |
| socket | `shutdown.c` | `IORING_OP_SHUTDOWN` + `WRITEV` | 纯默认标志 `0` |
| **fixed buffers** | `fixed-buf-iter.c`, `fixed-buf-merge.c`, `fixed-link.c` | `IORING_REGISTER_BUFFERS` + `READ_FIXED`/`WRITE_FIXED` + `IOSQE_IO_LINK` | 注意 `fixed-buf-iter.c` 默认打开 `/dev/urandom` 与 `/dev/zero` |
| **fixed files** | `file-update.c`, `ooo-file-unreg.c` | `IORING_REGISTER_FILES`、`IORING_REGISTER_FILES_UPDATE`、`IORING_OP_FILES_UPDATE` | `file-update` 对 `OP_FILES_UPDATE == -EINVAL` 跳过；`ooo-file-unreg` 对稀疏注册 `-EINVAL` 跳过 |
| **link** | `submit-link-fail.c`, `link_drain.c` | `IOSQE_IO_LINK`、`IOSQE_IO_HARDLINK`、`IOSQE_IO_DRAIN` 链式执行与失败传递 | `link_drain.c` 通过 `t_probe_defer_taskrun()` 跳过 `DEFER_TASKRUN` [S23] |

#### Tier B：核心必测但含 `SQPOLL`/部分 OOS 子测例的测试（共 8 项，需轻量条件裁剪）

| 测例文件 | 覆盖的核心能力 | 阻断原因（Out of scope 耦合点） | 建议处理方式 |
| --- | --- | --- | --- |
| `read-write.c` | 最核心的文件读写矩阵：`READV`/`WRITEV`/`READ`/`WRITE`/`READ_FIXED`/`WRITE_FIXED` + `register_files`（含 O_DIRECT 与 buffered） | 1. `PROVIDE_BUFFERS` 会自动探测并跳过；<br>2. 但 `sqthread=1` 循环调用 `t_create_ring(64, &ring, IORING_SETUP_SQPOLL)`，而 `helpers.c:135` 仅在 `ret == -EPERM && geteuid()` 时返回 `T_SETUP_SKIP`，root 下 `-EINVAL` 会直接报错退出 [S24] | 放宽 `helpers.c:t_create_ring_params()` 在 `SQPOLL && ret == -EINVAL` 时返回 `T_SETUP_SKIP`（可使多个测试共同受益），或跳过 `sqthread=1` 迭代 |
| `send_recv.c` | `SEND`、`RECV`、`SENDMSG`、`RECVMSG` + `register_files` | 同上：`use_sqthread=1` 调用 `t_create_ring_params(..., IORING_SETUP_SQPOLL)`；`SUBMIT_ALL` 已自容 `-EINVAL` | 同上放宽 `helpers.c` 对 `SQPOLL && -EINVAL` 的跳过处理即可完整运行非 SQPOLL 矩阵 |
| `timeout.c` | `IORING_OP_TIMEOUT`、`TIMEOUT_REMOVE`、`TIMEOUT_UPDATE`、`LINK_TIMEOUT` | 主函数 `sqpoll` 标志会自行跳过，但若支持 `IORING_TIMEOUT_UPDATE` 则 `test_update_multishot_timeouts()` 未检查 `no_multishot` 会直接提交 `IORING_TIMEOUT_MULTISHOT` [S25] | 若内核支持 `TIMEOUT_UPDATE` 但不支持 `MULTISHOT`，需裁剪或给 `test_update_multishot_timeouts` 补 `if (no_multishot) return 0;` |
| `io-cancel.c` | `IORING_OP_ASYNC_CANCEL` 取消进行中文件读写/超时/跨环校验 | `main()` 无条件先执行 `test_sqpoll_cancel_iowq_requests()` 并在 `IORING_SETUP_SQPOLL` 失败时直接 `return T_EXIT_FAIL` [S26] | 跳过 `test_sqpoll_cancel_iowq_requests()` 后运行其余取消子测 |
| `socket.c` | `IORING_OP_SOCKET`、`CONNECT`、`SEND`、`RECV` | `main()` 直接调用 `test(1, 1, 0, 0)`（`IORING_SETUP_SQPOLL`）且不跳过 `-EINVAL` [S27] | 仅执行 `sqthread=0`（及按需排除 `socket_direct`）用例 |
| `connect.c`, `connect-rep.c` | `IORING_OP_CONNECT` + `POLL_ADD` + `LINK_TIMEOUT` | `main()` 直接调用 `test(IORING_SETUP_SQPOLL)` 及 `test(SINGLE_ISSUER\|DEFER_TASKRUN)` 且未判断 `-EINVAL` 跳过 [S28] | 裁剪掉 `SQPOLL`/`DEFER_TASKRUN` 传参，仅跑 `flags=0` |
| `fpos.c` | `READ`/`WRITE` 使用 `offset=-1` 更新 `f_pos` | 未检查 `IORING_FEAT_RW_CUR_POS`，若内核未实现当前文件位置异步推进则失败 [S29] | 若 PulseOS 置 `IORING_FEAT_RW_CUR_POS` 则纳入，否则不纳入首阶段门禁 |

#### 明确排除清单（含易误选陷阱）

- **`link.c`（关键陷阱！）**：尽管名为 `link.c`，但 `main()` 第 448 行无条件创建 `io_uring_queue_init(8, &poll_ring, IORING_SETUP_IOPOLL)` 并要求成功，否则直接 `return T_EXIT_FAIL` [S30] —— **必须排除**，改用 `submit-link-fail.c`、`link_drain.c`、`poll-link.c`、`link-timeout.c` 与 `fixed-link.c` 验证链接语义。
- **`timeout-new.c`（陷阱！）**：直接创建 `IORING_SETUP_SQPOLL` ring 并失败退出，**必须排除**。
- **`io_uring_register.c`（谨慎参考）**：`test_poll_ringfd` 无条件调用 `__test_poll_ringfd(IORING_SETUP_SQPOLL)` 失败退出，且 `test_max_fds` 尝试 `mmap` 16 GiB (`UINT_MAX * 4`) 虚拟地址空间、`test_iovec_size` 测试 `MAP_HUGETLB` [S31]。不建议原样作为门禁二进制直接跑，可拆解或参考其 `EBADF`/`EOPNOTSUPP`/`EINVAL` 参数校验逻辑。
- **其余直接排除的 Out-of-scope 测例**：`sqpoll-*.c` / `sq-poll-*.c` / `sqwait.c`（`SQPOLL`）、`iopoll*.c`（`IOPOLL`）、`buf-ring*.c` / `ringbuf-*.c` / `read-inc-file.c`（使用 `IOU_PBUF_RING_INC`）/ `read-mshot*.c` / `recv-multishot.c` / `poll-mshot-*.c` / `poll-race-mshot.c` / `eploop.c` / `evloop.c` / `recvsend_bundle*.c`（Provided Buffer Ring / Multishot / Bundle）、`uring_cmd_ublk.c` / `cmd-discard.c` / `io_uring_passthrough.c`（`URING_CMD`）、`accept.c`（无条件测 multishot accept）、`linked-defer-close.c` & `multicqes_drain.c`（multishot + `DEFER_TASKRUN`）、`across-fork.c`（若跨进程共享 ring 暂不在首批范围内，可列为可选验证项）。

---

## 3. `fio --ioengine=io_uring` 源码审计（基于 `fio-3.39`）

以下完全基于 `fio-3.39` 的 `engines/io_uring.c`（行号以该 tag 源码为准）、`parse.c`、`filesetup.c`、`init.c` 与 `memory.c`。[S4]

### 3.1 系统调用与环映射完整清单

1. **环初始化 (`fio_ioring_queue_init`, `engines/io_uring.c:1006-1084`)**：
   - 调用 `syscall(__NR_io_uring_setup, depth, &p)`（`depth = roundup_pow2(td->o.iodepth)`）。
   - **默认无条件尝试的标志（第 1038-1051 行）**：
     ```c
     p.flags |= IORING_SETUP_CQSIZE;
     p.cq_entries = depth;
     p.flags |= IORING_SETUP_COOP_TASKRUN;
     p.flags |= IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_DEFER_TASKRUN;
     ```
   - **降级重试逻辑（第 1053-1070 行）**：**仅当 `ret < 0 && errno == EINVAL` 时**，依次剥离：
     1. `~(IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_SINGLE_ISSUER)`
     2. `~IORING_SETUP_COOP_TASKRUN`
     3. `~IORING_SETUP_CQSIZE`
     最终回落至 `p.flags == 0` 再次尝试。
2. **特性探测 (`fio_ioring_probe`, `engines/io_uring.c:973-1004`)**：
   - 当用户未指定 `--nonvectored=0/1`（默认 `-1`）时，无条件调用 `syscall(__NR_io_uring_register, ld->ring_fd, IORING_REGISTER_PROBE, p, 256)`。
   - 若返回 `>= 0` 且 `p->ops_len >= IORING_OP_WRITE`（注意：需包含 `READ` 和 `WRITE` 的槽位，若按 Linux `ops_len = last_op + 1` 则 `>= IORING_OP_WRITE` 成立；按第 996 行写为 `if (IORING_OP_WRITE > p->ops_len)` 存在边界语义需保证 `ops_len > IORING_OP_WRITE`！）且 `IORING_OP_READ` 与 `IORING_OP_WRITE` 均置 `IO_URING_OP_SUPPORTED`，设 `o->nonvectored = 1`；否则回退 `o->nonvectored = 0`（使用 `READV`/`WRITEV`）。
3. **三段共享环 `mmap` (`fio_ioring_mmap`, `engines/io_uring.c:925-971`)**：
   - **不检查 `IORING_FEAT_SINGLE_MMAP`**，固定发起 3 次 `mmap`：
     1. `IORING_OFF_SQ_RING` (`0ULL`)，长度 `p->sq_off.array + p->sq_entries * sizeof(__u32)`，flags = `MAP_SHARED | MAP_POPULATE`
     2. `IORING_OFF_SQES` (`0x10000000ULL`)，长度 `p->sq_entries * sizeof(struct io_uring_sqe)`，flags = `MAP_SHARED | MAP_POPULATE`
     3. `IORING_OFF_CQ_RING` (`0x8000000ULL`)，长度 `p->cq_off.cqes + p->cq_entries * sizeof(struct io_uring_cqe)`，flags = `MAP_SHARED | MAP_POPULATE`
   - **必须实现 `sq_off.array`**：`fio_ioring_queue()` 第 801 行无条件写 `ring->array[tail & ld->sq_ring_mask] = io_u->index;`。
   - **不调用 `madvise(MADV_DONTFORK)`**，cleanup 时通过 `munmap` + `close(ld->ring_fd)` 释放（第 898-905 行）。
4. **提交与收割 (`fio_ioring_commit` & `fio_ioring_getevents`, `engines/io_uring.c:689-724,836-896`)**：
   - RV64 定义 `FIO_ARCH_HAS_SYSCALL`，直接用 `__do_syscall6(__NR_io_uring_enter, ...)`；LA64 与其余架构走 `syscall(__NR_io_uring_enter, ...)`（第 376-386 行）。
   - **提交阶段（第 870 行）**：`io_uring_enter(ld, nr, 0, IORING_ENTER_GETEVENTS)`（`sigmask=NULL, sigsz=0`）。**注意**：`min_complete=0` 但带了 `IORING_ENTER_GETEVENTS`；内核**不可阻塞等待**且**必须返回实际提交的 SQE 个数 `ret > 0`**（若返回 `0` 则第 877-879 行无限 `continue` 死循环；若返回 `-1` 且 `errno == EAGAIN/EINTR` 则尝试收割后 `usleep(1)` 重试）。
   - **收割阶段（第 711 行）**：先在用户态原子读取 `cq_ring.tail` 并推进 `cq_ring.head` 消费就绪 CQE；数量不足 `min` 时才进入 `io_uring_enter(ld, 0, actual_min, IORING_ENTER_GETEVENTS)`。
5. **非 `io_uring` 周边系统调用依赖**：
   - 文件路径：`openat`/`open`（`--direct=1` 时带 `O_DIRECT`）、`fstat`/`statx`、`ftruncate`/`fallocate`（文件预分配）、`fsync`/`fdatasync`。
   - 内存与时钟：`shmget`/`shmat`/`shmctl`（多 job 共享描述符，PulseOS 已实现 [P4]；也可用 `--disable-shm` 编译或 `--thread=1`）、`mmap(MAP_SHARED|MAP_ANONYMOUS)`（`smalloc.c`）、`clock_gettime(CLOCK_MONOTONIC)` 及 RV64 默认 CPU 时钟 `rdtime`（支持 `--clocksource=clock_gettime` 绕开）。

### 3.2 默认模式与核心参数兼容矩阵（必需项 vs 可选参数）

| 运行模式 / CLI 选项 | 触发的 `io_uring_setup` flags | 触发的 `io_uring_register` ops | 触发的 SQE `opcode` / `flags` | 必需性 & 对 #224 Out-of-scope 的影响 |
| --- | --- | --- | --- | --- |
| **默认基本模式**<br>`--ioengine=io_uring --rw=read/write/randread/randwrite --direct=1 --iodepth=N` | 首次试探 `CQSIZE \| COOP_TASKRUN \| SINGLE_ISSUER \| DEFER_TASKRUN`；遇 `-EINVAL` 降级至 `0` | 无条件尝试 `IORING_REGISTER_PROBE`（失败则静默降级 `nonvectored=0`） | 探测支持非向量时：`IORING_OP_READ` / `IORING_OP_WRITE`；否则：`IORING_OP_READV` / `IORING_OP_WRITEV`（`iovcnt=1`） | **核心必需最小面**。`O_DIRECT` 已在 PulseOS 实现 (`open.rs:35`, `validation/io.rs`) [P5]；无任何 `SQPOLL`/`IOPOLL`/multishot/buf-ring 依赖 |
| `--sqthread_poll=0`（默认即为 `0`） | 不设 `IORING_SETUP_SQPOLL` 与 `SQ_AFF` | 不强制 `IORING_REGISTER_FILES` | 不触发 `IORING_ENTER_SQ_WAKEUP` | `FIO_OPT_STR_SET` 类型 (`parse.c:940`)，`=0` 或省略均保持 `0`；**显式传入可确保关闭 Out-of-scope 的 `SQPOLL`** |
| `--hipri=0`（默认即为 `0`） | 不设 `IORING_SETUP_IOPOLL` | 无 | 无 | 同上，**关闭 Out-of-scope 的 `IOPOLL`** |
| `--iodepth=N` | `sq_entries = roundup_pow2(N)`（首次兼作 `cq_entries`） | 若启用 `--fixedbufs` 则按 `roundup_pow2(N)` 长度注册 `iovecs` | 单批最多提交 `N` 条 SQE | `fio-3.39` (`af0ad0fa`) 保持并发深度 `N` 不被虚高；建议支持最小 depth ≥ 1、常用 16/32/64 |
| `--nonvectored=0` / `=1` | 同默认 | **跳过 `IORING_REGISTER_PROBE`** | `=0` 强制 `READV`/`WRITEV`；`=1` 强制 `READ`/`WRITE` | 可选优化：若早期未实现 `PROBE` 或 `READ`/`WRITE`，传 `--nonvectored=0` 即可走纯向量路径 |
| `--fixedbufs` (`=1`) | 同默认 | `IORING_REGISTER_BUFFERS` (`nr=roundup_pow2(iodepth)`)；失败则直接中止报错 | `IORING_OP_READ_FIXED` / `IORING_OP_WRITE_FIXED` (`buf_index = io_u->index`) | **可选**（默认关闭），对应 #224 固定缓冲区进阶里程碑 |
| `--registerfiles` (`=1`) | 同默认 | `IORING_REGISTER_FILES` (`nr=td->o.nr_files`)；失败则中止报错 | SQE 设 `sqe->flags \|= IOSQE_FIXED_FILE`，`sqe->fd = f->engine_pos` | **可选**（默认关闭，仅在 `--sqthread_poll=1` 时被强行打开 `line 1323`） |
| `--fsync=K` / `--fdatasync=K` / `--sync_file_range` | 同默认 | 同默认 | `IORING_OP_FSYNC`（或 `IORING_FSYNC_DATASYNC`）、`IORING_OP_SYNC_FILE_RANGE` | 可选（默认关闭），仅当配置同步频率时触发 |
| `--rw=trim` / `randtrim` / `--ioengine=io_uring_cmd` | `io_uring_cmd` 设 `SQE128 \| CQE32` | 同默认 | **`IORING_OP_URING_CMD`** (`BLOCK_URING_CMD_DISCARD`) | **Out of scope（#224 明确排除）**：必须避免运行 trim 或 `io_uring_cmd` 用例 |

**显著风险提示（与 #224 Out-of-scope 交叉点）**：
1. **默认 `fio --ioengine=io_uring` 会在首次 `io_uring_setup` 主动探测 4 个非核心标志**（`CQSIZE`、`COOP_TASKRUN`、`SINGLE_ISSUER`、`DEFER_TASKRUN`）。这不是报错，而是 Linux 新特性自适应探测；**PulseOS 内核只要严格按 Linux 规范对未支持 flags 返回 `-EINVAL`**，即会自动降级至 `flags=0`，不违反 #224 范围边界。
2. 避免将 `fio` 升级至 `3.42`/`3.43`，避免触发额外的 `IORING_REGISTER_RING_FDS` 或 `IORING_FEAT_NO_IOWAIT` 交互。

---

## 4. RV64GC 与 LA64 交叉构建及镜像集成可行性

### 4.1 宿主工具链与目标 Rootfs 实况核查

通过检查 PulseOS 仓库脚本（`scripts/fetch-rootfs.sh`、`scripts/build_img.sh`、`Makefile`）及实际 Release Tarball（`rootfs-tests-20261116` 与 `rootfs-base-20260929`）与当前 Ubuntu 24.04 (`noble`) apt 源，确认如下事实：

| 检查项 | RISC-V 64 (`riscv64`) | LoongArch64 (`loongarch64`) |
| --- | --- | --- |
| **PulseOS 内核目标三元组** | `riscv64gc-unknown-none-elf`（**无 RVV**，不保存矢量上下文）[P2][P3] | `loongarch64-unknown-none-softfloat` [P6] |
| **镜像内 ELF 校验门禁** | `scripts/build_img.sh:117-136` `validate_riscv_elf_isa()` 扫描所有文件，若 `readelf -A` 的 `Tag_RISCV_arch` 匹配 `(^\|_)(v[0-9]\|zv)` 则直接报错终止 [P2] | 无 RVV 限制；含 `patch_loongarch64_musl_sched_stubs()` 与 `ensure_loongarch64_gnu_libdir_compat()` 补丁 [P2] |
| **`rootfs-tests-20261116` 底层系统与 libc** | Ubuntu 24.04.5 LTS (Noble, RV64GC without RVV)，含 `/usr/lib/riscv64-linux-gnu/libc.so.6` 与 `ld-linux-riscv64-lp64d.so.1` [P7] | **Loongnix-Server 8**，动态库为 **`usr/lib64/ld-2.28.so`（Old-World ABI, glibc 2.28）** 与 `usr/lib64/libc.so.6` [P7] |
| **当前镜像是否含 `liburing`/`fio`** | 均未预装 | 均未预装 |
| **Ubuntu 24.04 主机可用交叉工具链** | `gcc-riscv64-linux-gnu` (`13.3.0-6ubuntu2~24.04.1`，已安装；默认 `-march=rv64imafdc_zicsr_zifencei -mabi=lp64d`) | Ubuntu 仓库提供 `gcc-14-loongarch64-linux-gnu` (`14.2.0-4ubuntu2~24.04cross1`) / `gcc-13-loongarch64-linux-gnu` + `libc6-dev-loong64-cross`（**New-World ABI**, glibc 2.39） |

### 4.2 实测验证（RV64GC 无 RVV 交叉编译）

本次在沙箱暂存区使用主机 `riscv64-linux-gnu-gcc 13.3.0` 对 `liburing-2.9` 与 `fio-3.39` 进行了实际交叉编译验证，结果如下：

1. **`liburing-2.9`**：
   - 配置：`./configure --cc=riscv64-linux-gnu-gcc --cxx=riscv64-linux-gnu-g++`（无任何外部库，自动检测到 `nolibc = yes`、`__kernel_timespec = yes`、`open_how = yes`、`statx = yes`）。
   - 编译静态库及样本测试：`make -C src liburing.a CFLAGS="-O2 -march=rv64gc -mabi=lp64d -Wall"` 与 `make -C test ... LDFLAGS="-static"` 一次通过。
   - `readelf -A` 验证：`Tag_RISCV_arch: "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zmmul1p0"`（**无 `v`/`zv` 向量扩展**）；`strip` 后单测二进制尺寸为 **508 KiB–532 KiB**。
2. **`fio-3.39`**：
   - 配置：`./configure --cc=riscv64-linux-gnu-gcc --extra-cflags="-march=rv64gc -mabi=lp64d" --build-static --disable-native`。
   - 依赖情况：`zlib` 未找到仅发出可选提示，`libaio` / `libnuma` / `pmem` / `rdma` / `xnvme` / `lex` 均自动关闭；`engines/io_uring.c` 默认启用并编译成功，`nm` 确认包含 `ioengine_uring` 符号。
   - 静态二进制验证：`file fio` 为 `ELF 64-bit LSB executable, UCB RISC-V, RVC, double-float ABI, statically linked`；`readelf -A` 为 `rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_zicsr2p0_zifencei2p0_zmmul1p0`（**无 `v`/`zv` 向量扩展**）；未剥离 6.3 MiB，**`strip` 后仅 2.3 MiB**。
   - 静态链接提示：链接时因 `ioengines.o` (`dlopen`) 与 `engines/net.o` (`getaddrinfo`) 触发 glibc 静态链接警告，但本地使用 `--ioengine=io_uring` 不走动态引擎加载也不走网络名称解析，运行不受影响。

### 4.3 关键风险点与集成方案建议

1. **LoongArch64 ABI 分裂风险（决定性）**：
   - Ubuntu 24.04 的 `gcc-14-loongarch64-linux-gnu` 生成 **New-World ABI** ELF；若使用动态链接，其 `PT_INTERP` 指向 `/lib64/ld-linux-loongarch-lp64d.so.1` 且依赖 `GLIBC_2.34+` 符号，在当前 `rootfs-tests-loongarch64.tar.xz`（Loongnix 8 `ld-2.28.so` Old-World 环境）中将**直接无法启动**。
   - **对策**：双架构均采用**全静态链接**（`fio` 传 `--build-static`，`liburing` 测试传 `LDFLAGS="-static"`；且显式配置 `CFLAGS="-O2 -march=rv64gc -mabi=lp64d"` 锁定 RV64GC）。在静态链接下，New-World 二进制仅通过标准 Linux LoongArch64 系统调用号（`a7 = 425/426/427`, `syscall 0`）与 PulseOS 内核交互，完全绕过 guest `ld-2.28.so` 与 `libc.so.6` 差异；如宿主机使用 `loongarch64-linux-musl-gcc` 亦可同样产全静态 ELF。
   - 需注意：`liburing` 在 `loongarch64` 无 `CONFIG_NOLIBC`，`./configure` 会自动禁用 `nolibc` 并选用 `src/arch/generic/`（经 libc `syscall()` 转发），实测/源码审查均不影响静态链接测试二进制；而 `riscv64` 无论默认 `CONFIG_NOLIBC=y` 还是 `--use-libc` 均可正常运行（若统一行为可在双架构都传 `--use-libc`）。
2. **头文件路径自洽，不依赖目标 sysroot `<linux/io_uring.h>`**：
   - `liburing-2.9` 与 `fio-3.39` 均自带完整的 `io_uring.h` UAPI 结构体与宏定义（以及 `__NR_io_uring_* = 425/426/427` 兜底宏），即使旧交叉头文件缺失新结构体或 syscall 号也可编译通过。
   - `fio` 在 `loongarch64` 交叉编译未装 `libc6-dev-loong64-cross` 时会缺基础 C 头文件，因此在主机 CI/开发机只需安装 `gcc-14-loongarch64-linux-gnu` 与 `libc6-dev-loong64-cross`（Ubuntu `noble-updates/universe` 直接可得）即可完成双架构一键构建。
3. **镜像集成与体积管理**：
   - **增量热注入（推荐近期方案）**：参照 `scripts/build_lmbench.sh`、`scripts/build_sysbench.sh` 与 `scripts/install_to_rootfs.sh` 模式，新增 `scripts/build_iouring_tests.sh`（或拆分为 `liburing` + `fio` 构建脚本），将静态 `fio`（~2.3 MiB）与筛选后的 Tier A/B 静态 `liburing` 测试二进制（每个约 508–532 KiB；全量 46 项 Tier A 约 24 MiB，也可按阶段抽选核心子集）通过 `scripts/install_to_rootfs.sh` 注入已构建的 `disk.img` / `disk-la.img` 的 `/opt/io_uring/` 与 `/usr/bin/fio`。
   - **镜像空间余量**：`scripts/build_img.sh` 默认留有 `EXTRA_MARGIN_MIB=128`（约 128 MiB 空闲），足以容纳静态 `fio` 与全部 Tier A/B 静态测例（合计 < 30 MiB）；但运行 `fio --size=...` 基准测试（如 64 MiB–256 MiB 测试文件）时，建议在 `build_img.sh` 阶段或以 `IMG_SIZE=4G` / `EXTRA_MARGIN_MIB=512` 保证 ext4 空闲空间充足。
   - **测试环境前提**：`liburing` 的 socket 类测试需要 guest 内 loopback 接口（`127.0.0.1`）或 `AF_UNIX` 畅通；`fio` 多线程建议配合 `--thread=1` 或确认 guest `/tmp` 可写且具备足够空间。

---

## Primary sources

下列外部事实均直接核查自 `axboe/liburing` 与 `axboe/fio` 上游 Git 仓库对应固定 tag/commit：

- [S1] [`liburing-2.9` `src/setup.c`](https://github.com/axboe/liburing/blob/liburing-2.9/src/setup.c#L69-L499)、[`src/queue.c`](https://github.com/axboe/liburing/blob/liburing-2.9/src/queue.c#L62-L468) 与 [`src/register.c`](https://github.com/axboe/liburing/blob/liburing-2.9/src/register.c#L12-L332)：`NO_SQARRAY` 探测回退、`mmap`、`io_uring_ring_dontfork`、`EXT_ARG` 回退与 `IORING_REGISTER_PROBE`。
- [S2] [`liburing-2.9` `src/liburing.map`](https://github.com/axboe/liburing/blob/liburing-2.9/src/liburing.map) 与 [`src/include/liburing/io_uring.h`](https://github.com/axboe/liburing/blob/liburing-2.9/src/include/liburing/io_uring.h#L148-L600)：符号版本与内嵌 UAPI 定义。
- [S3] [`liburing` commit `f03becf`](https://github.com/axboe/liburing/commit/f03becf5d7c1bc3fd9a426ba8b013346847f8b9e) 与 [`3401b06`](https://github.com/axboe/liburing/commit/3401b06c5e8291a2ad946bb181ab347f18a4c8c3)：C11 `<stdatomic.h>` 内存序修复及 `IORING_SETUP_NO_SQARRAY` 默认化。
- [S4] [`fio-3.39` `engines/io_uring.c`](https://github.com/axboe/fio/blob/fio-3.39/engines/io_uring.c#L128-L1420) 与 [`os/linux/io_uring.h`](https://github.com/axboe/fio/blob/fio-3.39/os/linux/io_uring.h)：无 `liburing` 依赖、三段 `mmap`、setup flags `-EINVAL` 回退链、`PROBE` 探测与 `nonvectored`、`IORING_ENTER_GETEVENTS` 提交语义。
- [S5] [`fio` commits `577b85ec`](https://github.com/axboe/fio/commit/577b85ec41b5560a81a4fb09d1ec7760bcacc49f)、[`b823153a`](https://github.com/axboe/fio/commit/b823153a)、[`78831c6b`](https://github.com/axboe/fio/commit/78831c6b35c53f844748e79711b99218fb58f928)、[`e4e8520b`](https://github.com/axboe/fio/commit/e4e8520b) 与 [`280b3841`](https://github.com/axboe/fio/commit/280b38416874732062d76b898d983ad599e5ca19)：RV64 `rdtime` / 内联 `ecall` 修复、CQE 负错误码修复及 `--build-static` 修正。
- [S6] [`fio` commit `af0ad0fa`](https://github.com/axboe/fio/commit/af0ad0facd45cdf3c8c3b5f725424d6ca2e56dfc)：保持非 2 次幂 `--iodepth` 精确并发深度。
- [S7] [`liburing-2.9` `configure`](https://github.com/axboe/liburing/blob/liburing-2.9/configure#L452-L688) 与 [`src/Makefile`](https://github.com/axboe/liburing/blob/liburing-2.9/src/Makefile#L49-L63)：`CONFIG_NOLIBC` 检测与 `compat.h` 自动生成。
- [S8] [`liburing-2.5` tag](https://github.com/axboe/liburing/tree/liburing-2.5) 与 [`liburing-2.15` `src/setup.c`](https://github.com/axboe/liburing/blob/liburing-2.15/src/setup.c) / [`284b1a8`](https://github.com/axboe/liburing/commit/284b1a8be2ca2ea546204ed2c501414c89bea48f)：版本跨度差异参照。
- [S9] [`fio-3.39` `arch/arch.h`](https://github.com/axboe/fio/blob/fio-3.39/arch/arch.h#L75-L155)、[`arch/arch-riscv64.h`](https://github.com/axboe/fio/blob/fio-3.39/arch/arch-riscv64.h) 与 [`arch/arch-loongarch64.h`](https://github.com/axboe/fio/blob/fio-3.39/arch/arch-loongarch64.h)。
- [S10] [`fio-3.39` `configure`](https://github.com/axboe/fio/blob/fio-3.39/configure#L525-L702) 与 [`Makefile`](https://github.com/axboe/fio/blob/fio-3.39/Makefile#L219-L235)。
- [S11] [`fio-3.36` `arch/arch-riscv64.h`](https://github.com/axboe/fio/blob/fio-3.36/arch/arch-riscv64.h)：早期 `rdcycle` 实现。
- [S12] [`fio-3.42` `d200fabf`](https://github.com/axboe/fio/commit/d200fabfb762010bc7f6f373e0d2ff9f67125b13) 与 [`fio-3.43` `engines/io_uring.c`](https://github.com/axboe/fio/blob/fio-3.43/engines/io_uring.c)：`IORING_FEAT_NO_IOWAIT` 与 `IORING_REGISTER_RING_FDS` 新增调用。
- [S13] [`liburing-2.9` `src/arch/riscv64/lib.h`](https://github.com/axboe/liburing/blob/liburing-2.9/src/arch/riscv64/lib.h) 与 [`syscall.h`](https://github.com/axboe/liburing/blob/liburing-2.9/src/arch/riscv64/syscall.h)。
- [S14] [`liburing-2.9` `src/arch/generic/lib.h`](https://github.com/axboe/liburing/blob/liburing-2.9/src/arch/generic/lib.h) 与 [`syscall.h`](https://github.com/axboe/liburing/blob/liburing-2.9/src/arch/generic/syscall.h)。
- [S15] [`liburing-2.9` `src/nolibc.c`](https://github.com/axboe/liburing/blob/liburing-2.9/src/nolibc.c)。
- [S16] [`liburing-2.9` `src/include/liburing.h`](https://github.com/axboe/liburing/blob/liburing-2.9/src/include/liburing.h#L153-L423,L1445-L1543)。
- [S17]–[S31] `liburing-2.9/test/` 核心测试源码：[`nop.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/nop.c) ([S17])、[`io_uring_setup.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/io_uring_setup.c) ([S18])、[`io_uring_enter.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/io_uring_enter.c) ([S19])、[`probe.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/probe.c) ([S20])、[`fsync.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/fsync.c) ([S21])、[`poll.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/poll.c) ([S22])、[`link_drain.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/link_drain.c) ([S23])、[`read-write.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/read-write.c) & [`helpers.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/helpers.c#L127-L143) ([S24])、[`timeout.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/timeout.c) ([S25])、[`io-cancel.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/io-cancel.c) ([S26])、[`socket.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/socket.c) ([S27])、[`connect.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/connect.c) ([S28])、[`fpos.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/fpos.c) ([S29])、[`link.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/link.c#L433-L453) ([S30])、[`io_uring_register.c`](https://github.com/axboe/liburing/blob/liburing-2.9/test/io_uring_register.c) ([S31])。

## 仓库依据

PulseOS 代码基线为 `4a9a870c49fda8e74cd7b3430522e9e671f29e2f`：

- [P1] [mm.rs](../../pulse_syscalls/src/impls/mm.rs#L189-L503)：`sys_mmap`（支持 `MAP_POPULATE` 等标志）与 `sys_madvise`（当前未将 `MADV_DONTFORK` 列入合法 advice，返回 `-EINVAL`）。
- [P2] [build_img.sh](../../scripts/build_img.sh#L117-L197)：`validate_riscv_elf_isa`（检查 `Tag_RISCV_arch` 禁止 RVV）、`patch_loongarch64_musl_sched_stubs` 与 `ensure_loongarch64_gnu_libdir_compat`。
- [P3] [fetch-rootfs.sh](../../scripts/fetch-rootfs.sh#L94-L118)：`rootfs-tests-20261116` 与 `rootfs-base-20260929` 下载源及 RV64GC 无 RVV 约束说明。
- [P4] [shm.rs](../../pulse_syscalls/src/impls/ipc/shm.rs)：PulseOS 已实现 `sys_shmget`/`sys_shmat`/`sys_shmdt`/`sys_shmctl`。
- [P5] [open.rs](../../pulse_syscalls/src/impls/fs/path/open.rs#L35-L37) 与 [validation/io.rs](../../pulse_syscalls/src/validation/io.rs#L49)：PulseOS 已支持 `O_DIRECT` 打开标志及块对齐校验。
- [P6] [Makefile](../../Makefile#L63-L73)：RV64 (`riscv64gc-unknown-none-elf`) 与 LA64 (`loongarch64-unknown-none-softfloat`) 目标三元组配置。
- [P7] [Release `rootfs-tests-20261116`](https://github.com/muou000/PulseOS/releases/tag/rootfs-tests-20261116)：Ubuntu 24.04.5 Noble (RV64GC) 与 Loongnix-Server 8 (LA64 `ld-2.28.so`) 预编译测试镜像元数据。
