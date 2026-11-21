//! Request preparation and async/worker execution helpers for PulseOS `io_uring`.

use alloc::{
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{future::poll_fn, task::Poll, time::Duration};

use axerrno::{LinuxError, LinuxResult};
use axhal::time::{monotonic_time, wall_time};
use axpoll::IoEvents;
use axtask::future::{CancelHandle, global_executor, sleep_until};
use linux_raw_sys::{
    general::{O_CLOEXEC, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, POLLRDHUP, iovec},
    io_uring::{__kernel_timespec, io_uring_op},
    net::{AF_INET, AF_INET6},
};
use pulse_io_uring_core::orchestrator::{PreparedRequest, RequestId, RequestKind, TimeoutClock};
use pulse_io_uring_core::whitelist::{
    validate_async_cancel_sqe, validate_link_timeout_sqe, validate_nop_sqe,
    validate_rw_or_poll_sqe, validate_sqe_v1, validate_timeout_remove_sqe, validate_timeout_sqe,
};
use pulse_user_abi::io_uring::{IORING_TIMEOUT_UPDATE, IOSQE_ASYNC, IoUringSqe};

use super::{
    IoUringObject, IoUringState, OwnedInflightGuard,
    context::AsyncExecContext,
    worker_pool::global_worker_pool,
};
use crate::fd_table::{
    EpollObject, FdEntry, FdFlags, FdObject, PipeObject, PollRegistration, SignalFdObject,
};
use crate::net::{Socket, SocketInner};

const UIO_MAXIOV: u32 = 1024;
const RW_CHUNK_CAP: usize = 64 * 1024;

#[derive(Clone, Copy, Debug)]
pub struct UserSegment {
    pub addr: usize,
    pub len: usize,
}

#[derive(Clone)]
pub enum PollTarget {
    Fd(Arc<dyn FdObject>),
    /// Stores only `Weak<IoUringState>` when polling another ring or `self` (`ring_fd`)
    /// so closing the last `IoUringObject` FD can never be defeated by an `Arc` cycle.
    Ring(Weak<IoUringState>),
}

#[derive(Clone)]
pub enum PreparedOpSpec {
    Nop,
    Timeout {
        generation: u64,
        deadline: Duration,
    },
    LinkTimeout {
        generation: u64,
        deadline: Duration,
    },
    TimeoutRemove {
        target_user_data: u64,
        op_flags: u32,
        new_duration: Option<Duration>,
    },
    AsyncCancel {
        target_user_data: u64,
        target_fd: i32,
        cancel_flags: u32,
    },
    Rw {
        outcome: LinuxResult<(FdEntry, Vec<UserSegment>)>,
        is_write: bool,
        offset: u64,
        force_async: bool,
    },
    PollAdd {
        target: PollTarget,
        mask: u32,
        events: IoEvents,
    },
    Accept {
        entry: FdEntry,
        addr: usize,
        addrlen_ptr: usize,
        accept_flags: u32,
    },
}

#[inline]
pub fn compute_monotonic_deadline(clock: TimeoutClock, abs: bool, dur: Duration) -> Duration {
    if !abs {
        return monotonic_time().saturating_add(dur);
    }
    match clock {
        TimeoutClock::Monotonic | TimeoutClock::Boottime => dur,
        TimeoutClock::Realtime => {
            let wall_now = wall_time();
            let mono_now = monotonic_time();
            if dur <= wall_now {
                mono_now
            } else {
                mono_now.saturating_add(dur - wall_now)
            }
        }
    }
}

fn copy_timeout_spec(ctx: &AsyncExecContext, addr: usize) -> LinuxResult<Duration> {
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let ts: __kernel_timespec = ctx.read_value(addr)?;
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

fn prepare_rw_segments(
    sqe: &IoUringSqe,
    ctx: &AsyncExecContext,
    vectored: bool,
) -> LinuxResult<(Vec<UserSegment>, usize)> {
    let mut segments = Vec::new();
    let mut total = 0usize;

    if vectored {
        if sqe.len > UIO_MAXIOV {
            return Err(LinuxError::EINVAL);
        }
        if sqe.len == 0 {
            return Ok((segments, 0));
        }
        let iovecs = ctx.read_array::<iovec>(sqe.addr as usize, sqe.len as usize)?;
        segments.reserve(iovecs.len());
        for iov in iovecs {
            let len = usize::try_from(iov.iov_len).map_err(|_| LinuxError::EINVAL)?;
            let base = iov.iov_base as usize;
            if len > 0 && !ctx.is_user_range(base, len) {
                return Err(LinuxError::EFAULT);
            }
            total = total.checked_add(len).ok_or(LinuxError::EINVAL)?;
            if total > isize::MAX as usize {
                return Err(LinuxError::EINVAL);
            }
            segments.push(UserSegment { addr: base, len });
        }
    } else {
        let len = sqe.len as usize;
        let addr = sqe.addr as usize;
        if len > 0 && !ctx.is_user_range(addr, len) {
            return Err(LinuxError::EFAULT);
        }
        total = len;
        if len > 0 {
            segments.push(UserSegment { addr, len });
        }
    }

    Ok((segments, total))
}

pub fn prepare_sqe(
    sqe: &IoUringSqe,
    ctx: &AsyncExecContext,
    current_cqe_seq: u64,
    in_nonempty_chain: bool,
    prev_was_link_timeout: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    let (prep, spec) =
        prepare_sqe_inner(sqe, ctx, current_cqe_seq, in_nonempty_chain, prev_was_link_timeout)?;
    Ok((prep.with_owner_pid(ctx.process.pid()), spec))
}

fn prepare_sqe_inner(
    sqe: &IoUringSqe,
    ctx: &AsyncExecContext,
    current_cqe_seq: u64,
    in_nonempty_chain: bool,
    prev_was_link_timeout: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    validate_sqe_v1(sqe)?;
    let force_async = (sqe.flags & IOSQE_ASYNC) != 0;

    match sqe.opcode {
        op if op == io_uring_op::IORING_OP_NOP as u8 => {
            validate_nop_sqe(sqe)?;
            Ok((
                PreparedRequest::from_normal(sqe, None, None),
                PreparedOpSpec::Nop,
            ))
        }
        op if op == io_uring_op::IORING_OP_TIMEOUT as u8 => {
            validate_timeout_sqe(sqe)?;
            let dur = copy_timeout_spec(ctx, sqe.addr as usize)?;
            let prep = PreparedRequest::from_timeout(sqe, current_cqe_seq);
            let RequestKind::Timeout {
                clock,
                abs,
                generation,
                ..
            } = prep.kind
            else {
                unreachable!()
            };
            Ok((
                prep,
                PreparedOpSpec::Timeout {
                    generation,
                    deadline: compute_monotonic_deadline(clock, abs, dur),
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_LINK_TIMEOUT as u8 => {
            if !in_nonempty_chain || prev_was_link_timeout {
                return Err(LinuxError::EINVAL);
            }
            validate_link_timeout_sqe(sqe)?;
            let dur = copy_timeout_spec(ctx, sqe.addr as usize)?;
            let prep = PreparedRequest::from_link_timeout(sqe);
            let RequestKind::LinkTimeout {
                clock,
                abs,
                generation,
                ..
            } = prep.kind
            else {
                unreachable!()
            };
            Ok((
                prep,
                PreparedOpSpec::LinkTimeout {
                    generation,
                    deadline: compute_monotonic_deadline(clock, abs, dur),
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_TIMEOUT_REMOVE as u8 => {
            validate_timeout_remove_sqe(sqe)?;
            let new_duration = if (sqe.op_flags & IORING_TIMEOUT_UPDATE) != 0 {
                Some(copy_timeout_spec(ctx, sqe.off as usize)?)
            } else {
                None
            };
            Ok((
                PreparedRequest::from_normal(sqe, None, None),
                PreparedOpSpec::TimeoutRemove {
                    target_user_data: sqe.addr,
                    op_flags: sqe.op_flags,
                    new_duration,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_ASYNC_CANCEL as u8 => {
            validate_async_cancel_sqe(sqe)?;
            Ok((
                PreparedRequest::from_normal(sqe, None, None),
                PreparedOpSpec::AsyncCancel {
                    target_user_data: sqe.addr,
                    target_fd: sqe.fd,
                    cancel_flags: sqe.op_flags,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_READ as u8
            || op == io_uring_op::IORING_OP_READV as u8
            || op == io_uring_op::IORING_OP_WRITE as u8
            || op == io_uring_op::IORING_OP_WRITEV as u8 =>
        {
            validate_rw_or_poll_sqe(sqe)?;
            let is_write = op == io_uring_op::IORING_OP_WRITE as u8
                || op == io_uring_op::IORING_OP_WRITEV as u8;
            let vectored = op == io_uring_op::IORING_OP_READV as u8
                || op == io_uring_op::IORING_OP_WRITEV as u8;
            // Defer FD permission/mode and user-segment validation beyond chain assembly so
            // invalid linked chains cancel queued R/W operations consistently (`-ECANCELED`).
            let outcome = (|| -> LinuxResult<(FdEntry, Vec<UserSegment>, usize)> {
                let entry = ctx.get_fd_entry(sqe.fd)?;
                if entry.flags.contains(FdFlags::PATH) {
                    return Err(LinuxError::EBADF);
                }
                if is_write && !entry.object.is_write_open() {
                    return Err(LinuxError::EBADF);
                }
                if !is_write && !entry.object.is_read_open() {
                    return Err(LinuxError::EBADF);
                }
                let (segments, total_len) = prepare_rw_segments(sqe, ctx, vectored)?;
                Ok((entry, segments, total_len))
            })();
            let (expected, outcome) = match outcome {
                Ok((entry, segments, total_len)) => (
                    if total_len > 0 { Some(total_len) } else { None },
                    Ok((entry, segments)),
                ),
                Err(err) => (None, Err(err)),
            };
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), expected),
                PreparedOpSpec::Rw {
                    outcome,
                    is_write,
                    offset: sqe.off,
                    force_async,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_POLL_ADD as u8 => {
            validate_rw_or_poll_sqe(sqe)?;
            if sqe.addr != 0 || sqe.off != 0 || sqe.len != 0 {
                return Err(LinuxError::EINVAL);
            }
            let entry = ctx.get_fd_entry(sqe.fd)?;
            let mask = sqe.op_flags;
            let mut events = IoEvents::ALWAYS_POLL;
            if mask & POLLIN != 0 {
                events |= IoEvents::IN;
            }
            if mask & POLLPRI != 0 {
                events |= IoEvents::PRI;
            }
            if mask & POLLOUT != 0 {
                events |= IoEvents::OUT;
            }
            if mask & POLLRDHUP != 0 {
                events |= IoEvents::RDHUP;
            }
            let target = if let Some(ring_obj) = entry.object.as_any().downcast_ref::<IoUringObject>() {
                PollTarget::Ring(Arc::downgrade(ring_obj.state()))
            } else {
                PollTarget::Fd(entry.object)
            };
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
                PreparedOpSpec::PollAdd {
                    target,
                    mask,
                    events,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_ACCEPT as u8 => {
            validate_rw_or_poll_sqe(sqe)?;
            let allowed = O_CLOEXEC | O_NONBLOCK;
            if (sqe.op_flags & !allowed) != 0 {
                return Err(LinuxError::EINVAL);
            }
            let entry = ctx.get_fd_entry(sqe.fd)?;
            if !entry.object.as_any().is::<Socket>() {
                return Err(LinuxError::ENOTSOCK);
            }
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
                PreparedOpSpec::Accept {
                    entry,
                    addr: sqe.addr as usize,
                    addrlen_ptr: sqe.off as usize,
                    accept_flags: sqe.op_flags,
                },
            ))
        }
        _ => Err(LinuxError::EOPNOTSUPP),
    }
}

pub fn spawn_timer_future(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    generation: u64,
    deadline: Duration,
    is_link_timeout: bool,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);

    let handle = global_executor().spawn_and_poll_once(async move {
        let _guard = guard;
        sleep_until(deadline).await;
        if is_link_timeout {
            state_cloned.on_link_timeout_expired(req_id, generation);
        } else {
            state_cloned.on_timeout_expired(req_id, generation);
        }
    });

    state.install_cancel_handle_or_cancel(req_id, handle);
}

pub fn execute_rw_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    segments: Vec<UserSegment>,
    offset: u64,
    force_async: bool,
) {
    // Special FDs depend on `current_process()` / `current_thread()`, so keep them
    // inline on the submitting thread rather than dispatching raw onto workers (ADR-0007).
    if entry.object.as_any().is::<EpollObject>() || entry.object.as_any().is::<SignalFdObject>() {
        let res = run_sync_rw(ctx, &entry.object, is_write, &segments, offset);
        state.complete_request(req_id, res, 0, false);
        return;
    }

    if force_async {
        spawn_worker_rw(state, ctx, req_id, entry, is_write, segments, offset);
        return;
    }

    if entry.object.as_any().is::<PipeObject>() {
        // Non-zero explicit file offsets on stream FDs fail with `-ESPIPE`.
        if offset != 0 && offset != u64::MAX {
            state.complete_request(req_id, -LinuxError::ESPIPE.code(), 0, false);
            return;
        }
        let total_len: usize = segments.iter().map(|s| s.len).sum();
        if total_len == 0 {
            state.complete_request(req_id, 0, 0, false);
            return;
        }
        if total_len <= RW_CHUNK_CAP {
            execute_pipe_rw(state, ctx, req_id, entry, is_write, segments, total_len);
        } else {
            spawn_worker_rw(state, ctx, req_id, entry, is_write, segments, offset);
        }
        return;
    }

    if entry.object.as_any().is::<Socket>() {
        // Per-call non-blocking `Socket` try-ops arrive in #239; route blocking socket R/W
        // to the bounded worker pool so `KernelExecutor::poll` never blocks (ADR-0007).
        spawn_worker_rw(state, ctx, req_id, entry, is_write, segments, offset);
        return;
    }

    let res = run_sync_rw(ctx, &entry.object, is_write, &segments, offset);
    state.complete_request(req_id, res, 0, false);
}

fn spawn_worker_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    segments: Vec<UserSegment>,
    offset: u64,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_wk = Arc::clone(state);
    let ctx_wk = ctx.clone();
    global_worker_pool().submit(state.ring_id(), req_id, move || {
        let _guard: OwnedInflightGuard = guard;
        if !state_wk.is_request_active(req_id) {
            return;
        }
        let res = run_sync_rw(&ctx_wk, &entry.object, is_write, &segments, offset);
        state_wk.complete_request(req_id, res, 0, true);
    });
}

fn read_segments(ctx: &AsyncExecContext, segments: &[UserSegment], dst: &mut [u8]) -> LinuxResult<()> {
    let mut off = 0usize;
    for seg in segments {
        if seg.len > 0 {
            ctx.read_bytes(seg.addr, &mut dst[off..off + seg.len])?;
            off += seg.len;
        }
    }
    Ok(())
}

fn write_segments(ctx: &AsyncExecContext, segments: &[UserSegment], src: &[u8]) -> LinuxResult<()> {
    let mut off = 0usize;
    for seg in segments {
        if seg.len == 0 || off >= src.len() {
            continue;
        }
        let n = seg.len.min(src.len() - off);
        ctx.write_bytes(seg.addr, &src[off..off + n])?;
        off += n;
    }
    Ok(())
}

fn execute_pipe_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    mut segments: Vec<UserSegment>,
    total_len: usize,
) {
    let nonblocking_fd = entry.flags.contains(FdFlags::NONBLOCK)
        || entry.object.nonblocking_state().unwrap_or(false);
    let mut kbuf = vec![0u8; total_len];
    let pipe = entry
        .object
        .as_any()
        .downcast_ref::<PipeObject>()
        .expect("PipeObject");

    if is_write {
        if let Err(err) = read_segments(ctx, &segments, &mut kbuf) {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
        match pipe.try_write_nonblocking(&kbuf) {
            Ok(n) => {
                state.complete_request(req_id, n as i32, 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) if nonblocking_fd => {
                state.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) => {}
            Err(err) => {
                state.complete_request(req_id, -err.code(), 0, false);
                return;
            }
        }
    } else {
        for seg in &segments {
            if seg.len > 0 {
                if let Err(err) = ctx.process.try_fault_in_user_range(
                    seg.addr,
                    seg.len,
                    axhal::paging::MappingFlags::WRITE,
                ) {
                    state.complete_request(req_id, -LinuxError::from(err).code(), 0, false);
                    return;
                }
            }
        }
        match pipe.try_read_nonblocking(&mut kbuf) {
            Ok(0) => {
                state.complete_request(req_id, 0, 0, false);
                return;
            }
            Ok(n) => {
                let res = match write_segments(ctx, &segments, &kbuf[..n]) {
                    Ok(()) => n as i32,
                    Err(err) => -err.code(),
                };
                state.complete_request(req_id, res, 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) if nonblocking_fd => {
                state.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) => {}
            Err(err) => {
                state.complete_request(req_id, -err.code(), 0, false);
                return;
            }
        }
    }

    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let ctx_cloned = ctx.clone();
    let mut registrations: Vec<PollRegistration> = Vec::new();
    let mut guard_slot = Some(guard);

    let handle = global_executor().spawn_and_poll_once(poll_fn(move |cx| {
        registrations.clear();
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            let _ = guard_slot.take();
            return Poll::Ready(());
        }
        let pipe = entry
            .object
            .as_any()
            .downcast_ref::<PipeObject>()
            .expect("PipeObject");

        loop {
            if is_write {
                match pipe.try_write_nonblocking(&kbuf) {
                    Ok(n) => {
                        state_cloned.complete_request(req_id, n as i32, 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                    Err(LinuxError::EAGAIN) => {
                        if let Err(e) = Arc::clone(&entry.object).register_poll(
                            cx,
                            IoEvents::OUT | IoEvents::ERR | IoEvents::HUP,
                            &mut registrations,
                        ) {
                            state_cloned.complete_request(req_id, -e.code(), 0, true);
                            let _ = guard_slot.take();
                            return Poll::Ready(());
                        }
                        if entry.object.poll().is_ok_and(|p| p.writable) {
                            registrations.clear();
                            continue;
                        }
                        return Poll::Pending;
                    }
                    Err(err) => {
                        state_cloned.complete_request(req_id, -err.code(), 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                }
            } else {
                match pipe.try_read_nonblocking(&mut kbuf) {
                    Ok(0) => {
                        state_cloned.complete_request(req_id, 0, 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                    Ok(n) => {
                        if !state_cloned.try_begin_completing_request(req_id) {
                            let _ = guard_slot.take();
                            return Poll::Ready(());
                        }
                        let Some(wk_guard) = guard_slot.take() else {
                            return Poll::Ready(());
                        };
                        let state_wk = Arc::clone(&state_cloned);
                        let ctx_wk = ctx_cloned.clone();
                        let data = core::mem::take(&mut kbuf);
                        let segs = core::mem::take(&mut segments);
                        global_worker_pool().submit(state_cloned.ring_id(), req_id, move || {
                            let _guard: OwnedInflightGuard = wk_guard;
                            let res = match write_segments(&ctx_wk, &segs, &data[..n]) {
                                Ok(()) => n as i32,
                                Err(err) => -err.code(),
                            };
                            state_wk.finish_completing_request(req_id, res, 0, true);
                        });
                        return Poll::Ready(());
                    }
                    Err(LinuxError::EAGAIN) => {
                        if let Err(e) = Arc::clone(&entry.object).register_poll(
                            cx,
                            IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR | IoEvents::HUP,
                            &mut registrations,
                        ) {
                            state_cloned.complete_request(req_id, -e.code(), 0, true);
                            let _ = guard_slot.take();
                            return Poll::Ready(());
                        }
                        if entry.object.poll().is_ok_and(|p| p.readable) {
                            registrations.clear();
                            continue;
                        }
                        return Poll::Pending;
                    }
                    Err(err) => {
                        state_cloned.complete_request(req_id, -err.code(), 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                }
            }
        }
    }));

    state.install_cancel_handle_or_cancel(req_id, handle);
}

fn run_sync_rw(
    ctx: &AsyncExecContext,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    segments: &[UserSegment],
    offset: u64,
) -> i32 {
    if segments.iter().all(|s| s.len == 0) {
        return 0;
    }
    let use_positional = offset != u64::MAX;
    let mut cur_off = offset;
    let mut kbuf = vec![0u8; RW_CHUNK_CAP];
    let mut total_done = 0usize;

    for seg in segments {
        let mut off_in_seg = 0usize;
        while off_in_seg < seg.len {
            let chunk = (seg.len - off_in_seg).min(kbuf.len());
            let user_addr = seg.addr + off_in_seg;
            if is_write {
                if let Err(err) = ctx.read_bytes(user_addr, &mut kbuf[..chunk]) {
                    return if total_done > 0 { total_done as i32 } else { -err.code() };
                }
                let res = if use_positional {
                    match obj.write_at(&kbuf[..chunk], cur_off) {
                        Err(LinuxError::ESPIPE) if offset == 0 => obj.write(&kbuf[..chunk]),
                        other => other,
                    }
                } else {
                    obj.write(&kbuf[..chunk])
                };
                match res {
                    Ok(0) => return total_done as i32,
                    Ok(n) => {
                        total_done += n;
                        off_in_seg += n;
                        if use_positional {
                            cur_off = cur_off.saturating_add(n as u64);
                        }
                        if n < chunk {
                            return total_done as i32;
                        }
                    }
                    Err(err) => {
                        return if total_done > 0 { total_done as i32 } else { -err.code() };
                    }
                }
            } else {
                let res = if use_positional {
                    match obj.read_at(&mut kbuf[..chunk], cur_off) {
                        Err(LinuxError::ESPIPE) if offset == 0 => obj.read(&mut kbuf[..chunk]),
                        other => other,
                    }
                } else {
                    obj.read(&mut kbuf[..chunk])
                };
                match res {
                    Ok(0) => return total_done as i32,
                    Ok(n) => {
                        if let Err(err) = ctx.write_bytes(user_addr, &kbuf[..n]) {
                            return if total_done > 0 { total_done as i32 } else { -err.code() };
                        }
                        total_done += n;
                        off_in_seg += n;
                        if use_positional {
                            cur_off = cur_off.saturating_add(n as u64);
                        }
                        if n < chunk {
                            return total_done as i32;
                        }
                    }
                    Err(err) => {
                        return if total_done > 0 { total_done as i32 } else { -err.code() };
                    }
                }
            }
        }
    }

    total_done as i32
}

pub fn spawn_poll_add_future(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    target: PollTarget,
    mask: u32,
    events: IoEvents,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let mut registrations: Vec<PollRegistration> = Vec::new();
    let mut guard_slot = Some(guard);

    let handle = global_executor().spawn_and_poll_once(poll_fn(move |cx| {
        registrations.clear();
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            let _ = guard_slot.take();
            return Poll::Ready(());
        }

        if let Some(revents) = eval_poll_target(&target, mask) {
            state_cloned.complete_request(req_id, revents as i32, 0, true);
            let _ = guard_slot.take();
            return Poll::Ready(());
        }

        match &target {
            PollTarget::Fd(obj) => {
                if let Err(err) = Arc::clone(obj).register_poll(cx, events, &mut registrations) {
                    state_cloned.complete_request(req_id, -err.code(), 0, true);
                    let _ = guard_slot.take();
                    return Poll::Ready(());
                }
            }
            PollTarget::Ring(weak_ring) => {
                if let Some(target_ring) = weak_ring.upgrade() {
                    let reg = target_ring.cq_wait_queue.register_owned_waker(cx.waker());
                    let weak_unreg = Arc::downgrade(&target_ring);
                    registrations.push(PollRegistration::new(move || {
                        if let Some(ring) = weak_unreg.upgrade() {
                            ring.cq_wait_queue.unregister_waker(reg);
                        }
                    }));
                } else {
                    state_cloned.complete_request(req_id, POLLNVAL as i32, 0, true);
                    let _ = guard_slot.take();
                    return Poll::Ready(());
                }
            }
        }

        // Re-check after registering waker so edge transitions never get lost.
        if let Some(revents) = eval_poll_target(&target, mask) {
            registrations.clear();
            state_cloned.complete_request(req_id, revents as i32, 0, true);
            let _ = guard_slot.take();
            return Poll::Ready(());
        }

        Poll::Pending
    }));

    state.install_cancel_handle_or_cancel(req_id, handle);
}

fn eval_poll_target(target: &PollTarget, mask: u32) -> Option<u32> {
    match target {
        PollTarget::Fd(obj) => {
            let st = match obj.poll() {
                Ok(s) => s,
                Err(_) => return Some(POLLERR),
            };
            let mut rev = 0u32;
            if st.readable && (mask & POLLIN != 0) {
                rev |= POLLIN;
            }
            if st.writable && (mask & POLLOUT != 0) {
                rev |= POLLOUT;
            }
            if obj.is_rdhup() {
                if mask & POLLRDHUP != 0 {
                    rev |= POLLRDHUP;
                }
                if mask & POLLHUP != 0 {
                    rev |= POLLHUP;
                }
            }
            (rev != 0).then_some(rev)
        }
        PollTarget::Ring(weak) => {
            let Some(ring) = weak.upgrade() else {
                return Some(POLLNVAL);
            };
            if ring.is_dying() {
                return Some(POLLHUP);
            }
            if (mask & POLLIN != 0) && ring.has_ready_cqes_fast() {
                return Some(POLLIN);
            }
            None
        }
    }
}

pub fn spawn_accept_future(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    addr: usize,
    addrlen_ptr: usize,
    accept_flags: u32,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let ctx_cloned = ctx.clone();
    let mut registrations: Vec<PollRegistration> = Vec::new();
    let mut guard_slot = Some(guard);

    let handle = global_executor().spawn_and_poll_once(poll_fn(move |cx| {
        registrations.clear();
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            let _ = guard_slot.take();
            return Poll::Ready(());
        }

        let Some(sock) = entry.object.as_any().downcast_ref::<Socket>() else {
            state_cloned.complete_request(req_id, -LinuxError::ENOTSOCK.code(), 0, true);
            let _ = guard_slot.take();
            return Poll::Ready(());
        };

        let is_readable = sock.poll().is_ok_and(|p| p.readable);
        if !is_readable {
            if let Err(err) = Arc::clone(&entry.object).register_poll(
                cx,
                IoEvents::IN | IoEvents::ERR | IoEvents::HUP,
                &mut registrations,
            ) {
                state_cloned.complete_request(req_id, -err.code(), 0, true);
                let _ = guard_slot.take();
                return Poll::Ready(());
            }
            if !sock.poll().is_ok_and(|p| p.readable) {
                return Poll::Pending;
            }
            registrations.clear();
        }

        // Claim `Completing` ownership before popping an accepted connection from LISTEN_TABLE,
        // and execute blocking accept + user sockaddr copy on Path 3 so `poll()` never blocks.
        if !state_cloned.try_begin_completing_request(req_id) {
            let _ = guard_slot.take();
            return Poll::Ready(());
        }
        let Some(wk_guard) = guard_slot.take() else {
            return Poll::Ready(());
        };
        let state_wk = Arc::clone(&state_cloned);
        let ctx_wk = ctx_cloned.clone();
        let entry_wk = entry.clone();
        global_worker_pool().submit(state_cloned.ring_id(), req_id, move || {
            let _guard: OwnedInflightGuard = wk_guard;
            let sock = entry_wk
                .object
                .as_any()
                .downcast_ref::<Socket>()
                .expect("Socket");
            let res = match &sock.inner {
                SocketInner::Tcp(tcp) => match tcp.accept().map_err(|e| LinuxError::from(e.canonicalize())) {
                    Ok(new_tcp) => {
                        let remote_addr = new_tcp.peer_addr().ok();
                        let new_sock = Socket::new(
                            sock.domain.load(core::sync::atomic::Ordering::Acquire),
                            SocketInner::Tcp(new_tcp),
                        );
                        if (accept_flags & O_NONBLOCK) != 0 {
                            new_sock.set_nonblocking_inner(true);
                        }
                        let mut new_fd_flags = FdFlags::empty();
                        if (accept_flags & O_CLOEXEC) != 0 {
                            new_fd_flags.insert(FdFlags::CLOEXEC);
                        }
                        if (accept_flags & O_NONBLOCK) != 0 {
                            new_fd_flags.insert(FdFlags::NONBLOCK);
                        }
                        match ctx_wk.insert_fd_entry(FdEntry::new(Arc::new(new_sock), new_fd_flags)) {
                            Ok(new_fd) => {
                                if addr != 0 && addrlen_ptr != 0 {
                                    if let Some(remote) = remote_addr {
                                        write_peer_sockaddr(&ctx_wk, remote, addr, addrlen_ptr);
                                    }
                                }
                                new_fd as i32
                            }
                            Err(err) => -err.code(),
                        }
                    }
                    Err(err) => -err.code(),
                },
                _ => -LinuxError::EOPNOTSUPP.code(),
            };
            state_wk.finish_completing_request(req_id, res, 0, true);
        });
        Poll::Ready(())
    }));

    state.install_cancel_handle_or_cancel(req_id, handle);
}

fn write_peer_sockaddr(
    ctx: &AsyncExecContext,
    remote: core::net::SocketAddr,
    addr: usize,
    addrlen_ptr: usize,
) {
    let Ok(buf_len) = ctx.read_value::<u32>(addrlen_ptr) else {
        return;
    };
    let mut encoded = [0u8; 28];
    let needed = match remote {
        core::net::SocketAddr::V4(v4) => {
            encoded[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            encoded[2..4].copy_from_slice(&v4.port().to_be_bytes());
            encoded[4..8].copy_from_slice(&v4.ip().octets());
            16u32
        }
        core::net::SocketAddr::V6(v6) => {
            encoded[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            encoded[2..4].copy_from_slice(&v6.port().to_be_bytes());
            encoded[4..8].copy_from_slice(&v6.flowinfo().to_be_bytes());
            encoded[8..24].copy_from_slice(&v6.ip().octets());
            encoded[24..28].copy_from_slice(&v6.scope_id().to_be_bytes());
            28u32
        }
    };
    let copy_len = (buf_len as usize).min(needed as usize);
    if copy_len > 0 {
        let _ = ctx.write_bytes(addr, &encoded[..copy_len]);
    }
    let _ = ctx.write_value(addrlen_ptr, &needed);
}
