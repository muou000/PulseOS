# Shared descriptor readiness waiting

## Status

- Date: 2026-10-07
- Scope: `ppoll(2)` and `pselect6(2)` syscall waiting
- Related issue: #64

## Decision

The syscall layer owns one shared readiness waiter in
`pulse_syscalls/src/impls/fs/io/wait.rs`. It receives the caller's already-decoded
`pollfd` snapshot and the `Arc<dyn FdObject>` snapshot, then owns the common
algorithm:

1. perform a readiness scan;
2. retain the same descriptor objects for the whole syscall;
3. collect `FdObject::get_wait_queues()` results when every monitored object
   supports synchronous queue waiting;
4. add the current thread's signal queue;
5. use `WaitQueue::wait_multiple_timeout_until()` so the check/enroll race is
   closed by a second check and all queue/timer entries are cleaned on exit;
6. recalculate the remaining duration against one absolute deadline after every
   wake; and
7. rescan readiness before deciding between a ready result, `EINTR`, and timeout.

`PidfdObject` exposes its bind queue before `CLONE_PIDFD` binds the child and the
target process's `pid_exit_event` afterward. It retains the target `Process` for
the lifetime of the pidfd object, so returning that borrowed queue remains valid
across reap. The existing async `register_poll` path continues to serve epoll.

If any other monitored object has no synchronous wait-queue implementation, the
waiter uses the existing bounded active-yield plus signal-queue sleep fallback.
The fallback is a correctness-preserving compatibility path, not a new adapter
interface or a performance claim.

## Preserved syscall differences

- `ppoll` snapshots invalid descriptors and reports `POLLNVAL` in-band. It never
  converts an invalid entry into a syscall-level `EBADF`.
- `pselect6` rejects an invalid descriptor with `EBADF` before entering the
  shared waiter.
- Each syscall retains its own user-memory decoding and output encoding.
- The temporary signal mask remains guarded by `SignalMaskGuard` and is restored
  on every return path.
- A readiness result wins over a concurrently pending signal after the final
  scan. A signal wins only when the final scan finds no readiness.
- Zero and very short timeouts keep their existing nonblocking/cooperative
  semantics; positive deadlines are absolute monotonic deadlines and are never
  reset after a spurious notification.

The guest regression is registered in the dedicated `ltp/runtest/pulseos-issue64`
run list and is executed with `runltp -f pulseos-issue64`; it is intentionally
not added to the upstream-style `runtest/syscalls` baseline.

`cargo test -p pulse_syscalls --lib` covers pure ABI and parameter validation.
It cannot exercise guest descriptor state, wait queues, signal delivery, or user
memory. The LTP cases under `ltp/testcases/kernel/syscalls/` remain the guest
behavior evidence and must be run from a guest image or an equivalent LTP
harness. The mixed-adapter regression source added for this issue is therefore
not counted as a host test.
