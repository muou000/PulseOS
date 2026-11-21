---
status: accepted
---

# Lock a single Linux io_uring v1 compatibility tier anchored to Linux v6.12 UAPI

PulseOS adopts a single, explicitly versioned **Linux `io_uring` 兼容层级** (`v1`) anchored to the Linux `v6.12` UAPI layout and error semantics (`IORING_OP_LAST = 58`, `IORING_REGISTER_PROBE.last_op = 57`). This single whitelist unifies support across the preinstalled LTP `20260930` suite (`io_uring01`–`io_uring03` `TPASS`; `io_uring04` deterministic `TCONF` under `KCONFIG_SKIP_CHECK=1` due to out-of-scope `AF_RDS`), pinned `liburing-2.9` (`08468cc3`, unmodified library source, Tier A 46 + Tier B 8 static tests with lightweight harness skip tolerance), and pinned `fio-3.39` (`a6e474c9`, `--ioengine=io_uring` static baseline).

## Considered Options

- **Separate tool-specific compatibility profiles (one per suite):** rejected because splitting semantics across LTP, `liburing`, and `fio` creates maintenance duplication and semantic drift inside a single syscall surface.
- **Supporting `IORING_SETUP_NO_SQARRAY` dual SQ consumption paths in v1:** rejected because both `fio-3.39` and LTP unconditionally require `sq_off.array`, whereas `liburing-2.9` transparently strips `IORING_SETUP_NO_SQARRAY` and retries when `io_uring_setup` returns `-EINVAL`; keeping a single `sq_array` consumption path avoids dual-path edge-case bugs without hurting compatibility.
- **Returning CQE `-EINVAL` uniformly for unimplemented legal Linux `v6.12` opcodes:** rejected in favor of Linux `v6.12` `opdef.c` (`io_eopnotsupp_prep`) semantics—distinguishing legal-but-unimplemented opcodes (`0..=57`) and `IOSQE_BUFFER_SELECT` (`-EOPNOTSUPP`) from out-of-range opcodes (`>= 58`), undefined/unsupported flags, and invalid reserved fields (`-EINVAL`), paired with truthful `IORING_REGISTER_PROBE` bitmaps.

## Consequences

- **Frozen v1 capability surface:** Support is strictly bounded to 4 `IORING_SETUP_*` entries (`0`, `CQSIZE`, `CLAMP`, `SUBMIT_ALL`), 8 `IORING_FEAT_*` bits (`SINGLE_MMAP`, `NODROP`, `SUBMIT_STABLE`, `RW_CUR_POS`, `CUR_PERSONALITY`, `FAST_POLL`, `POLL_32BITS`, `EXT_ARG`), 2 non-zero `IORING_ENTER_*` flags (`GETEVENTS`, `EXT_ARG` with `min_wait_usec == 0`), 5 `IOSQE_*` bits (`FIXED_FILE`, `IO_DRAIN`, `IO_LINK`, `IO_HARDLINK`, `ASYNC`), 24 `IORING_OP_*` opcodes, and 9 `IORING_REGISTER_*` operations (buffers, files, eventfd, and probe).
- **Deterministic rejection without silent downgrade:** Unsupported or unknown `setup`/`enter` flags and `register` opcodes return `-EINVAL` synchronously (preserving `liburing-2.9` and `fio-3.39` `-EINVAL` probe-fallback loops); `SQPOLL`, `IOPOLL`, `PBUF_RING`, multishot operations, `URING_CMD`, `SQE128`/`CQE32`, `SINGLE_ISSUER`/`DEFER_TASKRUN`, `R_DISABLED`, `NO_MMAP`, and `AF_RDS`/`CLONE_BUFFERS` remain out of scope and fail deterministically rather than faking success.
- **Dual-architecture static test rootfs distribution:** Because the LoongArch64 rootfs runs Loongnix-Server 8 (Old-World `ld-2.28.so`) while host cross-compilers target New-World glibc (`gcc-13/14-loongarch64-linux-gnu`), and PulseOS RV64 targets RV64GC without RVV vector state, all bundled `fio-3.39` and `liburing-2.9` test binaries are statically linked (with RV64GC ISA validation) and distributed in the `rootfs-tests-20261120` GitHub release.
