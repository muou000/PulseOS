//! Request preparation and async/worker execution helpers for PulseOS `io_uring`.

use alloc::{
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{future::poll_fn, task::Poll, time::Duration};

use axerrno::{LinuxError, LinuxResult};
use axhal::time::{monotonic_time, wall_time};
use axio::IoBuf;
use axpoll::IoEvents;
use axtask::future::{global_executor, sleep_until};
use linux_raw_sys::{
    general::{O_CLOEXEC, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, POLLRDHUP, iovec},
    io_uring::{__kernel_timespec, io_uring_op},
    net::{AF_INET, AF_INET6},
};
use pulse_io_uring_core::orchestrator::{PreparedRequest, RequestId, RequestKind, TimeoutClock};
use pulse_io_uring_core::resources::MAX_FIXED_FILES;
use pulse_io_uring_core::whitelist::{
    validate_async_cancel_sqe, validate_files_update_sqe, validate_link_timeout_sqe,
    validate_nop_sqe, validate_rw_fixed_sqe, validate_rw_or_poll_sqe, validate_sqe_v1,
    validate_timeout_remove_sqe, validate_timeout_sqe,
};
use pulse_user_abi::io_uring::{
    IORING_TIMEOUT_UPDATE, IOSQE_ASYNC, IOSQE_FIXED_FILE, IoUringSqe,
};

use super::{
    IoUringObject, IoUringState, OwnedInflightGuard,
    context::AsyncExecContext,
    worker_pool::global_worker_pool,
};
use crate::fd_table::{
    EpollObject, FdEntry, FdFlags, FdObject, PipeObject, PollRegistration, SignalFdObject,
};
use crate::mm::{
    FixedBufferIo, PinnedUserBuffers, UserBufferCursor, UserIoSegment, fits_single_pin_window,
};
use crate::net::{Socket, SocketInner};

const UIO_MAXIOV: u32 = 1024;
const RW_CHUNK_CAP: usize = 64 * 1024;

pub enum PreparedRwBuffer {
    Empty,
    SingleWindow(PinnedUserBuffers),
    Fixed(FixedBufferIo),
    MultiWindow {
        segments: Vec<UserIoSegment>,
        total_len: usize,
    },
}

impl PreparedRwBuffer {
    #[inline]
    fn total_len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::SingleWindow(win) => win.len(),
            Self::Fixed(fixed) => fixed.len(),
            Self::MultiWindow { total_len, .. } => *total_len,
        }
    }

    #[inline]
    fn remaining_bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::SingleWindow(win) => win.remaining(),
            Self::Fixed(fixed) => fixed.remaining_bytes(),
            Self::MultiWindow { total_len, .. } => *total_len,
        }
    }

    #[inline]
    fn terminal_error(&self) -> Option<LinuxError> {
        match self {
            Self::SingleWindow(win) => win.terminal_error(),
            _ => None,
        }
    }

    fn copy_from_user_exact(&mut self, dst: &mut [u8]) -> LinuxResult<()> {
        match self {
            Self::Empty => Err(LinuxError::EFAULT),
            Self::SingleWindow(win) => win.copy_from_user_exact(dst),
            Self::Fixed(fixed) => fixed.copy_from_user_exact(dst),
            Self::MultiWindow { .. } => Err(LinuxError::EFAULT),
        }
    }

    fn copy_to_user_exact(&mut self, src: &[u8]) -> LinuxResult<()> {
        match self {
            Self::Empty => Err(LinuxError::EFAULT),
            Self::SingleWindow(win) => win.copy_to_user_exact(src),
            Self::Fixed(fixed) => fixed.copy_to_user_exact(src),
            Self::MultiWindow { .. } => Err(LinuxError::EFAULT),
        }
    }
}

#[derive(Clone)]
pub enum PollTarget {
    Fd(Arc<dyn FdObject>),
    /// Stores only `Weak<IoUringState>` when polling another ring or `self` (`ring_fd`)
    /// so closing the last `IoUringObject` FD can never be defeated by an `Arc` cycle.
    Ring(Weak<IoUringState>),
}

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
        outcome: LinuxResult<(FdEntry, PreparedRwBuffer)>,
        is_write: bool,
        offset: u64,
        force_async: bool,
    },
    FilesUpdate {
        outcome: LinuxResult<(u32, Vec<i32>)>,
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
        initial_addrlen: Option<u32>,
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

fn resolve_sqe_fd_entry(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
) -> LinuxResult<FdEntry> {
    if (sqe.flags & IOSQE_FIXED_FILE) != 0 {
        let index = u32::try_from(sqe.fd).map_err(|_| LinuxError::EBADF)?;
        state.get_fixed_fd_entry(index)
    } else {
        ctx.get_fd_entry(sqe.fd)
    }
}

fn open_rw_fd_entry(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
    is_write: bool,
) -> LinuxResult<FdEntry> {
    let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
    if entry.flags.contains(FdFlags::PATH) {
        return Err(LinuxError::EBADF);
    }
    if is_write && !entry.object.is_write_open() {
        return Err(LinuxError::EBADF);
    }
    if !is_write && !entry.object.is_read_open() {
        return Err(LinuxError::EBADF);
    }
    Ok(entry)
}

fn prepare_rw_segments(
    sqe: &IoUringSqe,
    ctx: &AsyncExecContext,
    vectored: bool,
) -> LinuxResult<(Vec<UserIoSegment>, usize)> {
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
            segments.push(UserIoSegment::new(base, len));
        }
    } else {
        let len = sqe.len as usize;
        let addr = sqe.addr as usize;
        if len > 0 && !ctx.is_user_range(addr, len) {
            return Err(LinuxError::EFAULT);
        }
        total = len;
        if len > 0 {
            segments.push(UserIoSegment::new(addr, len));
        }
    }

    Ok((segments, total))
}

pub fn prepare_sqe(
    state: &IoUringState,
    sqe: &IoUringSqe,
    ctx: &AsyncExecContext,
    current_cqe_seq: u64,
    in_nonempty_chain: bool,
    prev_was_link_timeout: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    let (prep, spec) = prepare_sqe_inner(
        state,
        sqe,
        ctx,
        current_cqe_seq,
        in_nonempty_chain,
        prev_was_link_timeout,
    )?;
    Ok((prep.with_owner_pid(ctx.process.pid()), spec))
}

fn prepare_sqe_inner(
    state: &IoUringState,
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
            let outcome = (|| -> LinuxResult<(FdEntry, PreparedRwBuffer, usize)> {
                let entry = open_rw_fd_entry(state, ctx, sqe, is_write)?;
                let (segments, total_len) = prepare_rw_segments(sqe, ctx, vectored)?;
                if total_len == 0 {
                    return Ok((entry, PreparedRwBuffer::Empty, 0));
                }
                let pin_inline = !force_async
                    && !entry.object.as_any().is::<Socket>()
                    && fits_single_pin_window(&segments);
                let buffer = if pin_inline {
                    let mut cursor = UserBufferCursor::default();
                    let window = PinnedUserBuffers::pin_with_process(
                        &ctx.process,
                        &segments,
                        &mut cursor,
                        !is_write,
                    )?;
                    PreparedRwBuffer::SingleWindow(window)
                } else {
                    PreparedRwBuffer::MultiWindow {
                        segments,
                        total_len,
                    }
                };
                Ok((entry, buffer, total_len))
            })();
            let (expected, outcome) = match outcome {
                Ok((entry, buffer, total_len)) => (
                    if total_len > 0 { Some(total_len) } else { None },
                    Ok((entry, buffer)),
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
        op if op == io_uring_op::IORING_OP_READ_FIXED as u8
            || op == io_uring_op::IORING_OP_WRITE_FIXED as u8 =>
        {
            validate_rw_fixed_sqe(sqe)?;
            let is_write = op == io_uring_op::IORING_OP_WRITE_FIXED as u8;
            let outcome = (|| -> LinuxResult<(FdEntry, PreparedRwBuffer, usize)> {
                let entry = open_rw_fd_entry(state, ctx, sqe, is_write)?;
                let fixed_io =
                    state.resolve_fixed_buffer(sqe.buf_index, sqe.addr, sqe.len, !is_write)?;
                let total_len = fixed_io.len();
                let buffer = if total_len == 0 {
                    PreparedRwBuffer::Empty
                } else {
                    PreparedRwBuffer::Fixed(fixed_io)
                };
                Ok((entry, buffer, total_len))
            })();
            let (expected, outcome) = match outcome {
                Ok((entry, buffer, total_len)) => (
                    if total_len > 0 { Some(total_len) } else { None },
                    Ok((entry, buffer)),
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
        op if op == io_uring_op::IORING_OP_FILES_UPDATE as u8 => {
            validate_files_update_sqe(sqe)?;
            let outcome = (|| -> LinuxResult<(u32, Vec<i32>)> {
                let offset = u32::try_from(sqe.off).map_err(|_| LinuxError::EINVAL)?;
                let count = sqe.len as usize;
                if count == 0 || count > MAX_FIXED_FILES {
                    return Err(LinuxError::EINVAL);
                }
                state.validate_files_update(offset, sqe.len, 0)?;
                let fds = ctx.read_array::<i32>(sqe.addr as usize, count)?;
                Ok((offset, fds))
            })();
            Ok((
                PreparedRequest::from_normal(sqe, None, None),
                PreparedOpSpec::FilesUpdate {
                    outcome,
                    force_async,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_POLL_ADD as u8 => {
            validate_rw_or_poll_sqe(sqe)?;
            if sqe.addr != 0 || sqe.off != 0 || sqe.len != 0 {
                return Err(LinuxError::EINVAL);
            }
            let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
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
            let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
            if !entry.object.as_any().is::<Socket>() {
                return Err(LinuxError::ENOTSOCK);
            }
            let addr = sqe.addr as usize;
            let addrlen_ptr = sqe.off as usize;
            let initial_addrlen = if addr != 0 && addrlen_ptr != 0 {
                Some(ctx.read_value::<u32>(addrlen_ptr)?)
            } else {
                None
            };
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
                PreparedOpSpec::Accept {
                    entry,
                    addr,
                    addrlen_ptr,
                    initial_addrlen,
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
    buffer: PreparedRwBuffer,
    offset: u64,
    force_async: bool,
) {
    // Special FDs depend on `current_process()` / `current_thread()`, so keep them
    // inline on the submitting thread rather than dispatching raw onto workers (ADR-0007).
    if entry.object.as_any().is::<EpollObject>() || entry.object.as_any().is::<SignalFdObject>() {
        let res = run_sync_rw(ctx, &entry.object, is_write, buffer, offset);
        state.complete_request(req_id, res, 0, false);
        return;
    }

    if force_async {
        spawn_worker_rw(state, ctx, req_id, entry, is_write, buffer, offset);
        return;
    }

    if entry.object.as_any().is::<PipeObject>() {
        // Non-zero explicit file offsets on stream FDs fail with `-ESPIPE`.
        if offset != 0 && offset != u64::MAX {
            state.complete_request(req_id, -LinuxError::ESPIPE.code(), 0, false);
            return;
        }
        let total_len = buffer.total_len();
        if total_len == 0 {
            state.complete_request(req_id, 0, 0, false);
            return;
        }
        if (total_len <= RW_CHUNK_CAP && matches!(buffer, PreparedRwBuffer::SingleWindow(_)))
            || matches!(buffer, PreparedRwBuffer::Fixed(_))
        {
            execute_pipe_rw(state, req_id, entry, is_write, buffer);
        } else {
            spawn_worker_rw(state, ctx, req_id, entry, is_write, buffer, offset);
        }
        return;
    }

    if entry.object.as_any().is::<Socket>() || matches!(buffer, PreparedRwBuffer::MultiWindow { .. }) {
        // Blocking sockets and multi-window (> 64 KiB / > 32 fragments) requests
        // execute on Path 3 so Reactor polling never blocks and user memory pins stream in bounded windows.
        spawn_worker_rw(state, ctx, req_id, entry, is_write, buffer, offset);
        return;
    }

    let res = run_sync_rw(ctx, &entry.object, is_write, buffer, offset);
    state.complete_request(req_id, res, 0, false);
}

fn spawn_worker_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    buffer: PreparedRwBuffer,
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
        let res = run_sync_rw(&ctx_wk, &entry.object, is_write, buffer, offset);
        state_wk.complete_request(req_id, res, 0, true);
    });
}

enum PipeStep {
    Done(usize),
    WouldBlock,
}

fn step_pipe_rw(
    pipe: &PipeObject,
    is_write: bool,
    buffer: &mut PreparedRwBuffer,
    kbuf: &mut [u8],
    staged_off: &mut usize,
    staged_len: &mut usize,
) -> LinuxResult<PipeStep> {
    let mut total_done = 0usize;
    if is_write {
        loop {
            if *staged_off == *staged_len {
                let next = buffer.remaining_bytes().min(kbuf.len());
                if next == 0 {
                    return Ok(PipeStep::Done(total_done));
                }
                buffer.copy_from_user_exact(&mut kbuf[..next])?;
                *staged_off = 0;
                *staged_len = next;
            }
            match pipe.try_write_nonblocking(&kbuf[*staged_off..*staged_len]) {
                Ok(0) => return Ok(PipeStep::Done(total_done)),
                Ok(n) => {
                    *staged_off += n;
                    total_done += n;
                    if buffer.remaining_bytes() == 0 && *staged_off == *staged_len {
                        return Ok(PipeStep::Done(total_done));
                    }
                    if *staged_off < *staged_len {
                        return Ok(PipeStep::Done(total_done));
                    }
                }
                Err(LinuxError::EAGAIN) => {
                    return Ok(if total_done > 0 {
                        PipeStep::Done(total_done)
                    } else {
                        PipeStep::WouldBlock
                    });
                }
                Err(err) => {
                    return if total_done > 0 {
                        Ok(PipeStep::Done(total_done))
                    } else {
                        Err(err)
                    };
                }
            }
        }
    } else {
        loop {
            let next = buffer.remaining_bytes().min(kbuf.len());
            if next == 0 {
                return Ok(PipeStep::Done(total_done));
            }
            match pipe.try_read_nonblocking(&mut kbuf[..next]) {
                Ok(0) => return Ok(PipeStep::Done(total_done)),
                Ok(n) => {
                    buffer.copy_to_user_exact(&kbuf[..n])?;
                    total_done += n;
                    if n < next {
                        return Ok(PipeStep::Done(total_done));
                    }
                }
                Err(LinuxError::EAGAIN) => {
                    return Ok(if total_done > 0 {
                        PipeStep::Done(total_done)
                    } else {
                        PipeStep::WouldBlock
                    });
                }
                Err(err) => {
                    return if total_done > 0 {
                        Ok(PipeStep::Done(total_done))
                    } else {
                        Err(err)
                    };
                }
            }
        }
    }
}

fn execute_pipe_rw(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    mut buffer: PreparedRwBuffer,
) {
    let nonblocking_fd = entry.flags.contains(FdFlags::NONBLOCK)
        || entry.object.nonblocking_state().unwrap_or(false);
    let transfer_len = buffer.total_len();
    let mut kbuf = vec![0u8; transfer_len.min(RW_CHUNK_CAP)];
    let mut staged_off = 0usize;
    let mut staged_len = 0usize;

    if is_write && transfer_len <= kbuf.len() {
        if let Err(err) = buffer.copy_from_user_exact(&mut kbuf[..transfer_len]) {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
        staged_len = transfer_len;
        buffer = PreparedRwBuffer::Empty;
    }

    let pipe = entry
        .object
        .as_any()
        .downcast_ref::<PipeObject>()
        .expect("PipeObject");

    match step_pipe_rw(
        pipe,
        is_write,
        &mut buffer,
        &mut kbuf,
        &mut staged_off,
        &mut staged_len,
    ) {
        Ok(PipeStep::Done(n)) => {
            state.complete_request(req_id, n as i32, 0, false);
            return;
        }
        Ok(PipeStep::WouldBlock) if nonblocking_fd => {
            state.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, false);
            return;
        }
        Ok(PipeStep::WouldBlock) => {}
        Err(err) => {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
    }

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
        let pipe = entry
            .object
            .as_any()
            .downcast_ref::<PipeObject>()
            .expect("PipeObject");

        let (interest, check_ready): (IoEvents, fn(axio::PollState) -> bool) = if is_write {
            (IoEvents::OUT | IoEvents::ERR | IoEvents::HUP, |p| p.writable)
        } else {
            (IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR | IoEvents::HUP, |p| {
                p.readable
            })
        };

        loop {
            match step_pipe_rw(
                pipe,
                is_write,
                &mut buffer,
                &mut kbuf,
                &mut staged_off,
                &mut staged_len,
            ) {
                Ok(PipeStep::Done(n)) => {
                    state_cloned.complete_request(req_id, n as i32, 0, true);
                    let _ = guard_slot.take();
                    return Poll::Ready(());
                }
                Ok(PipeStep::WouldBlock) => {
                    if let Err(e) =
                        Arc::clone(&entry.object).register_poll(cx, interest, &mut registrations)
                    {
                        state_cloned.complete_request(req_id, -e.code(), 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                    if entry.object.poll().is_ok_and(check_ready) {
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
    }));

    state.install_cancel_handle_or_cancel(req_id, handle);
}

#[inline]
fn transfer_obj_chunk(
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    base_offset: u64,
    cur_off: u64,
    buf: &mut [u8],
) -> LinuxResult<usize> {
    if is_write {
        if base_offset != u64::MAX {
            match obj.write_at(buf, cur_off) {
                Err(LinuxError::ESPIPE) if base_offset == 0 => obj.write(buf),
                other => other,
            }
        } else {
            obj.write(buf)
        }
    } else if base_offset != u64::MAX {
        match obj.read_at(buf, cur_off) {
            Err(LinuxError::ESPIPE) if base_offset == 0 => obj.read(buf),
            other => other,
        }
    } else {
        obj.read(buf)
    }
}

fn run_sync_rw_window(
    buffer: &mut PreparedRwBuffer,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    base_offset: u64,
    cur_off: &mut u64,
    kbuf: &mut [u8],
    total_done: &mut usize,
) -> LinuxResult<bool> {
    let total = buffer.total_len();
    let mut off_in_stream = 0usize;
    while off_in_stream < total {
        let chunk = (total - off_in_stream).min(kbuf.len());
        if is_write {
            buffer.copy_from_user_exact(&mut kbuf[..chunk])?;
        }
        let n = transfer_obj_chunk(obj, is_write, base_offset, *cur_off, &mut kbuf[..chunk])?;
        if n == 0 {
            return Ok(true);
        }
        if !is_write {
            buffer.copy_to_user_exact(&kbuf[..n])?;
        }
        *total_done += n;
        off_in_stream += n;
        if base_offset != u64::MAX {
            *cur_off = cur_off.saturating_add(n as u64);
        }
        if n < chunk {
            return Ok(true);
        }
    }
    Ok(buffer.terminal_error().is_some())
}

#[inline]
fn rw_progress_or_error(total_done: usize, err: LinuxError) -> i32 {
    if total_done > 0 {
        total_done as i32
    } else {
        -err.code()
    }
}

fn run_sync_rw(
    ctx: &AsyncExecContext,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    mut buffer: PreparedRwBuffer,
    offset: u64,
) -> i32 {
    let total_len = buffer.total_len();
    if total_len == 0 {
        return 0;
    }

    let mut cur_off = offset;
    let mut kbuf = vec![0u8; total_len.min(RW_CHUNK_CAP)];
    let mut total_done = 0usize;

    match &buffer {
        PreparedRwBuffer::Empty => 0,
        PreparedRwBuffer::SingleWindow(_) | PreparedRwBuffer::Fixed(_) => {
            match run_sync_rw_window(
                &mut buffer,
                obj,
                is_write,
                offset,
                &mut cur_off,
                &mut kbuf,
                &mut total_done,
            ) {
                Ok(_) => total_done as i32,
                Err(err) => rw_progress_or_error(total_done, err),
            }
        }
        PreparedRwBuffer::MultiWindow { .. } => {
            let PreparedRwBuffer::MultiWindow { segments, .. } = buffer else {
                unreachable!()
            };
            let mut cursor = UserBufferCursor::default();
            loop {
                let window = match PinnedUserBuffers::pin_with_process(
                    &ctx.process,
                    &segments,
                    &mut cursor,
                    !is_write,
                ) {
                    Ok(win) => win,
                    Err(err) => return rw_progress_or_error(total_done, err),
                };
                if window.is_empty() {
                    break;
                }
                let mut win_buf = PreparedRwBuffer::SingleWindow(window);
                match run_sync_rw_window(
                    &mut win_buf,
                    obj,
                    is_write,
                    offset,
                    &mut cur_off,
                    &mut kbuf,
                    &mut total_done,
                ) {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(err) => return rw_progress_or_error(total_done, err),
                }
            }
            total_done as i32
        }
    }
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
    initial_addrlen: Option<u32>,
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
                                    if let (Some(remote), Some(buf_len)) = (remote_addr, initial_addrlen) {
                                        write_peer_sockaddr(&ctx_wk, remote, addr, addrlen_ptr, buf_len);
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
    buf_len: u32,
) {
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
