# 2026-05-02 cyclictest-musl scheduler syscall investigation

## Background

The `cyclictest-musl` OS COMP test failed with:

```text
unable to get scheduler parameters
```

The log showed `sys_get_mempolicy (stub)` immediately before the failure, so the
first suspicion was that the NUMA compatibility stub might affect `cyclictest`.

## Findings

`sys_get_mempolicy` was not the direct cause. It returned success and execution
continued into scheduler capability checks.

The failing message comes from rt-tests `check_privs()` when libc
`sched_getparam(0, &old_param)` returns an error.

Kernel logs showed `sched_getaffinity` was called and returned successfully, but
there were no kernel-side logs for:

- `sched_getparam`
- `sched_getscheduler`
- `sched_setparam`
- `sched_setscheduler`

This meant the calls were failing before entering the kernel.

I extracted and inspected the LoongArch64 musl loader from the generated rootfs:

```text
/lib64/ld-musl-loongarch-lp64d.so.1
```

Its scheduler entry points were local ENOSYS stubs. For example,
`sched_getparam` loaded `-38` (`ENOSYS`) into `a0` and returned through
`__syscall_ret`, without issuing a syscall.

I also checked `sdcard-la.img:/musl/lib/libc.so` as requested. It is a
LoongArch64 musl shared object, but its implementations of these functions are
also ENOSYS stubs, so it cannot directly fix the issue.

## Changes

### Kernel scheduler compatibility

Updated:

- `pulse_syscalls/src/impls/task/schedule.rs`
- `pulse_syscalls/src/handler.rs`

Added or improved compatibility for:

- `sched_getaffinity`
- `sched_setaffinity`
- `sched_getscheduler`
- `sched_setscheduler`
- `sched_getparam`
- `sched_setparam`
- `sched_get_priority_max`
- `sched_get_priority_min`
- `sched_rr_get_interval`
- `sched_setattr`
- `sched_getattr`

The compatibility behavior reports a fixed RT-style scheduler view sufficient
for `cyclictest` privilege and parameter checks. It does not implement real
per-task RT scheduling semantics.

### LoongArch64 musl loader handling

Updated:

- `build_img.sh`

The image builder now handles LoongArch64 musl scheduler stubs as follows:

1. Check whether `/musl/lib/libc.so` exists in the staged rootfs.
2. If that bundled musl object does not contain the scheduler ENOSYS stubs,
   install it as `/lib64/ld-musl-loongarch-lp64d.so.1`.
3. If the bundled object is also a stub, keep the Alpine loader and apply a
   compatibility patch to only the affected scheduler wrapper bytes.

In the current test image, `/musl/lib/libc.so` is also a stub, so the fallback
patch path is used.

## Verification

Ran:

```sh
make test
```

Result: build and rootfs generation completed successfully.

The LoongArch64 rootfs build printed:

```text
[loongarch64] Patching musl scheduler ENOSYS stubs
```

After rebuilding, I extracted
`rootfs-loongarch64.img:/lib64/ld-musl-loongarch-lp64d.so.1` and confirmed by
disassembly that:

- `sched_getparam` issues syscall `121`
- `sched_getscheduler` issues syscall `120`
- `sched_setparam` issues syscall `118`
- `sched_setscheduler` issues syscall `119`

Attempting to run the LoongArch64 QEMU command locally failed because
`sdcard-la.img` is owned by `root:root` and QEMU could not open it:

```text
Could not open 'sdcard-la.img': Permission denied
```

No permission workaround was attempted.

