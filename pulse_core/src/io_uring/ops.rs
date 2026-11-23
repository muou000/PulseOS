//! Request preparation and async/worker execution helpers for PulseOS `io_uring`.

use alloc::{
    boxed::Box,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{future::poll_fn, task::Poll, time::Duration};

use axerrno::{LinuxError, LinuxResult};
use axhal::time::{monotonic_time, wall_time};
use axio::{IoBuf, IoBufMut, Write};
use axpoll::IoEvents;
use axtask::future::sleep_until;
use linux_raw_sys::{
    general::{POLLERR, POLLNVAL, RLIMIT_FSIZE, iovec},
    io_uring::{__kernel_timespec, io_uring_op},
};
use pulse_io_uring_core::orchestrator::{PreparedRequest, RequestId, RequestKind, TimeoutClock};
use pulse_io_uring_core::poll::{
    OneShotPollStep, PollReadiness, compute_poll_revents, drive_one_shot_poll_step,
    poll_mask_to_io_events,
};
use pulse_io_uring_core::resources::{
    MAX_FIXED_FILES, validate_direct_io_buffers, validate_direct_io_offset,
};
use pulse_io_uring_core::whitelist::{
    RwOffset, resolve_rw_offset, validate_async_cancel_sqe, validate_files_update_sqe,
    validate_fsync_sqe, validate_link_timeout_sqe, validate_nop_sqe, validate_poll_add_sqe,
    validate_poll_remove_sqe, validate_rw_fixed_sqe, validate_rw_sqe, validate_sqe_v1,
    validate_sync_file_range_sqe, validate_timeout_remove_sqe, validate_timeout_sqe,
};
use pulse_user_abi::io_uring::{
    IORING_FSYNC_DATASYNC, IORING_TIMEOUT_UPDATE, IOSQE_ASYNC, IOSQE_FIXED_FILE, IoUringSqe,
    RWF_APPEND, RWF_DSYNC, RWF_NOWAIT, RWF_SYNC, SYNC_FILE_RANGE_WAIT_AFTER,
    SYNC_FILE_RANGE_WAIT_BEFORE, SYNC_FILE_RANGE_WRITE,
};

use super::{
    IoUringObject, IoUringState, OwnedInflightGuard,
    context::AsyncExecContext,
    net_ops::{
        PreparedAcceptData, PreparedConnectData, PreparedSocketMsgTransfer, PreparedSocketTransfer,
        execute_socket_rw_request, prepare_accept_sqe, prepare_connect_sqe, prepare_send_recv_sqe,
        prepare_sendmsg_recvmsg_sqe, prepare_shutdown_sqe, prepare_socket_sqe,
    },
    worker_pool::global_worker_pool,
};
use crate::fd_table::{
    DirObject, EpollObject, EventFdObject, FdEntry, FdFlags, FdObject, FileObject, PipeObject,
    PollRegistration, SignalFdObject, StdinObject, TimerFdObject,
};
use crate::mm::{
    FixedBufferIo, PinnedUserBuffers, UserBufferCursor, UserIoSegment, fits_single_pin_window,
};
use crate::net::Socket;

const UIO_MAXIOV: u32 = 1024;
const RW_CHUNK_CAP: usize = 64 * 1024;

pub enum PreparedRwBuffer {
    Empty,
    SingleWindow(Box<PinnedUserBuffers>),
    Fixed(FixedBufferIo),
    MultiWindow {
        segments: Vec<UserIoSegment>,
        total_len: usize,
    },
}

impl PreparedRwBuffer {
    #[inline]
    pub(super) fn total_len(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::SingleWindow(win) => win.len(),
            Self::Fixed(fixed) => fixed.len(),
            Self::MultiWindow { total_len, .. } => *total_len,
        }
    }

    #[inline]
    pub(super) fn remaining_bytes(&self) -> usize {
        match self {
            Self::Empty => 0,
            Self::SingleWindow(win) => win.remaining(),
            Self::Fixed(fixed) => fixed.remaining_bytes(),
            Self::MultiWindow { total_len, .. } => *total_len,
        }
    }

    #[inline]
    pub(super) fn terminal_error(&self) -> Option<LinuxError> {
        match self {
            Self::SingleWindow(win) => win.terminal_error(),
            _ => None,
        }
    }

    pub(super) fn copy_from_user_exact(&mut self, dst: &mut [u8]) -> LinuxResult<()> {
        match self {
            Self::Empty => Err(LinuxError::EFAULT),
            Self::SingleWindow(win) => win.copy_from_user_exact(dst),
            Self::Fixed(fixed) => fixed.copy_from_user_exact(dst),
            Self::MultiWindow { .. } => Err(LinuxError::EFAULT),
        }
    }

    pub(super) fn copy_to_user_exact(&mut self, src: &[u8]) -> LinuxResult<()> {
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

pub struct PreparedRwData {
    pub entry: FdEntry,
    pub buffer: PreparedRwBuffer,
    pub offset: Option<u64>,
    pub direct_buf_aligned: bool,
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
        outcome: LinuxResult<Box<PreparedRwData>>,
        is_write: bool,
        rw_flags: u32,
        force_async: bool,
    },
    Fsync {
        outcome: LinuxResult<FdEntry>,
        offset: u64,
        len: u32,
        data_only: bool,
        force_async: bool,
    },
    SyncFileRange {
        outcome: LinuxResult<FdEntry>,
        offset: u64,
        len: u32,
        sync_flags: u32,
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
        force_async: bool,
    },
    PollRemove {
        target_user_data: u64,
    },
    Socket {
        domain: u32,
        raw_ty: u32,
        proto: u32,
        force_async: bool,
    },
    Accept {
        outcome: LinuxResult<Box<PreparedAcceptData>>,
        force_async: bool,
    },
    Connect {
        outcome: LinuxResult<Box<PreparedConnectData>>,
        force_async: bool,
    },
    SendRecv {
        outcome: LinuxResult<Box<PreparedSocketTransfer>>,
        is_send: bool,
        force_async: bool,
    },
    SendRecvMsg {
        outcome: LinuxResult<Box<PreparedSocketMsgTransfer>>,
        is_send: bool,
        force_async: bool,
    },
    Shutdown {
        outcome: LinuxResult<(FdEntry, u32)>,
        force_async: bool,
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

pub(super) fn resolve_sqe_fd_entry(
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
    if !is_write && entry.object.as_any().is::<DirObject>() {
        return Err(LinuxError::EISDIR);
    }
    Ok(entry)
}

#[inline]
fn fd_is_seekable(obj: &dyn FdObject) -> bool {
    if let Some(file) = obj.as_any().downcast_ref::<FileObject>() {
        file.is_seekable()
    } else {
        obj.as_any().is::<DirObject>()
    }
}

#[inline]
fn check_direct_buf_aligned(obj: &dyn FdObject, segments: &[UserIoSegment]) -> bool {
    if let Some(file_obj) = obj.as_any().downcast_ref::<FileObject>()
        && file_obj.inner().is_direct_regular_file()
    {
        return validate_direct_io_buffers(segments, file_obj.inner().block_size() as usize)
            .is_ok();
    }
    true
}

#[inline]
fn rw_offset_to_option(rw_off: RwOffset) -> Option<u64> {
    match rw_off {
        RwOffset::CurrentPosition => None,
        RwOffset::Positional(off) => Some(off),
    }
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
            validate_rw_sqe(sqe)?;
            let is_write = op == io_uring_op::IORING_OP_WRITE as u8
                || op == io_uring_op::IORING_OP_WRITEV as u8;
            let vectored = op == io_uring_op::IORING_OP_READV as u8
                || op == io_uring_op::IORING_OP_WRITEV as u8;
            // Defer FD permission/mode and user-segment validation beyond chain assembly so
            // invalid linked chains cancel queued R/W operations consistently (`-ECANCELED`).
            let outcome = (|| -> LinuxResult<(Box<PreparedRwData>, usize)> {
                let entry = open_rw_fd_entry(state, ctx, sqe, is_write)?;
                let (segments, total_len) = prepare_rw_segments(sqe, ctx, vectored)?;
                let offset = rw_offset_to_option(resolve_rw_offset(
                    sqe.off,
                    total_len,
                    fd_is_seekable(entry.object.as_ref()),
                )?);
                let direct_buf_aligned = check_direct_buf_aligned(entry.object.as_ref(), &segments);
                if total_len == 0 {
                    return Ok((
                        Box::new(PreparedRwData {
                            entry,
                            buffer: PreparedRwBuffer::Empty,
                            offset,
                            direct_buf_aligned,
                        }),
                        0,
                    ));
                }
                let pin_inline = fits_single_pin_window(&segments);
                let buffer = if pin_inline {
                    let mut cursor = UserBufferCursor::default();
                    let window = PinnedUserBuffers::pin_with_aspace(
                        &ctx.aspace,
                        &segments,
                        &mut cursor,
                        !is_write,
                    )?;
                    PreparedRwBuffer::SingleWindow(Box::new(window))
                } else {
                    PreparedRwBuffer::MultiWindow {
                        segments,
                        total_len,
                    }
                };
                Ok((
                    Box::new(PreparedRwData {
                        entry,
                        buffer,
                        offset,
                        direct_buf_aligned,
                    }),
                    total_len,
                ))
            })();
            let (expected, outcome) = match outcome {
                Ok((data, total_len)) => (
                    if total_len > 0 { Some(total_len) } else { None },
                    Ok(data),
                ),
                Err(err) => (None, Err(err)),
            };
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), expected),
                PreparedOpSpec::Rw {
                    outcome,
                    is_write,
                    rw_flags: sqe.op_flags,
                    force_async,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_READ_FIXED as u8
            || op == io_uring_op::IORING_OP_WRITE_FIXED as u8 =>
        {
            validate_rw_fixed_sqe(sqe)?;
            let is_write = op == io_uring_op::IORING_OP_WRITE_FIXED as u8;
            let outcome = (|| -> LinuxResult<(Box<PreparedRwData>, usize)> {
                let entry = open_rw_fd_entry(state, ctx, sqe, is_write)?;
                let offset = rw_offset_to_option(resolve_rw_offset(
                    sqe.off,
                    sqe.len as usize,
                    fd_is_seekable(entry.object.as_ref()),
                )?);
                let fixed_io =
                    state.resolve_fixed_buffer(sqe.buf_index, sqe.addr, sqe.len, !is_write)?;
                let total_len = fixed_io.len();
                let seg = [UserIoSegment::new(sqe.addr as usize, total_len)];
                let seg_slice = if total_len > 0 { &seg[..1] } else { &seg[..0] };
                let direct_buf_aligned =
                    check_direct_buf_aligned(entry.object.as_ref(), seg_slice);
                let buffer = if total_len == 0 {
                    PreparedRwBuffer::Empty
                } else {
                    PreparedRwBuffer::Fixed(fixed_io)
                };
                Ok((
                    Box::new(PreparedRwData {
                        entry,
                        buffer,
                        offset,
                        direct_buf_aligned,
                    }),
                    total_len,
                ))
            })();
            let (expected, outcome) = match outcome {
                Ok((data, total_len)) => (
                    if total_len > 0 { Some(total_len) } else { None },
                    Ok(data),
                ),
                Err(err) => (None, Err(err)),
            };
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), expected),
                PreparedOpSpec::Rw {
                    outcome,
                    is_write,
                    rw_flags: sqe.op_flags,
                    force_async,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_FSYNC as u8 => {
            validate_fsync_sqe(sqe)?;
            let outcome = (|| -> LinuxResult<FdEntry> {
                let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
                if entry.flags.contains(FdFlags::PATH) {
                    return Err(LinuxError::EBADF);
                }
                if fd_is_seekable(entry.object.as_ref()) {
                    Ok(entry)
                } else {
                    Err(LinuxError::EINVAL)
                }
            })();
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
                PreparedOpSpec::Fsync {
                    outcome,
                    offset: sqe.off,
                    len: sqe.len,
                    data_only: (sqe.op_flags & IORING_FSYNC_DATASYNC) != 0,
                    force_async,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_SYNC_FILE_RANGE as u8 => {
            validate_sync_file_range_sqe(sqe)?;
            let outcome = (|| -> LinuxResult<FdEntry> {
                let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
                if entry.flags.contains(FdFlags::PATH) {
                    return Err(LinuxError::EBADF);
                }
                if fd_is_seekable(entry.object.as_ref()) {
                    Ok(entry)
                } else {
                    Err(LinuxError::ESPIPE)
                }
            })();
            Ok((
                PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
                PreparedOpSpec::SyncFileRange {
                    outcome,
                    offset: sqe.off,
                    len: sqe.len,
                    sync_flags: sqe.op_flags,
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
            validate_poll_add_sqe(sqe)?;
            let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
            let mask = sqe.op_flags;
            let events = poll_mask_to_io_events(mask);
            let target =
                if let Some(ring_obj) = entry.object.as_any().downcast_ref::<IoUringObject>() {
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
                    force_async,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_POLL_REMOVE as u8 => {
            validate_poll_remove_sqe(sqe)?;
            Ok((
                PreparedRequest::from_normal(sqe, None, None),
                PreparedOpSpec::PollRemove {
                    target_user_data: sqe.addr,
                },
            ))
        }
        op if op == io_uring_op::IORING_OP_SOCKET as u8 => prepare_socket_sqe(sqe, force_async),
        op if op == io_uring_op::IORING_OP_ACCEPT as u8 => {
            prepare_accept_sqe(state, ctx, sqe, force_async)
        }
        op if op == io_uring_op::IORING_OP_CONNECT as u8 => {
            prepare_connect_sqe(state, ctx, sqe, force_async)
        }
        op if op == io_uring_op::IORING_OP_SEND as u8
            || op == io_uring_op::IORING_OP_RECV as u8 =>
        {
            prepare_send_recv_sqe(
                state,
                ctx,
                sqe,
                op == io_uring_op::IORING_OP_SEND as u8,
                force_async,
            )
        }
        op if op == io_uring_op::IORING_OP_SENDMSG as u8
            || op == io_uring_op::IORING_OP_RECVMSG as u8 =>
        {
            prepare_sendmsg_recvmsg_sqe(
                state,
                ctx,
                sqe,
                op == io_uring_op::IORING_OP_SENDMSG as u8,
                force_async,
            )
        }
        op if op == io_uring_op::IORING_OP_SHUTDOWN as u8 => {
            prepare_shutdown_sqe(state, ctx, sqe, force_async)
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

    state.spawn_native(req_id, async move {
        let _guard = guard;
        sleep_until(deadline).await;
        if is_link_timeout {
            state_cloned.on_link_timeout_expired(req_id, generation);
        } else {
            state_cloned.on_timeout_expired(req_id, generation);
        }
    });
}

struct LimitedRead<'a, R> {
    inner: &'a mut R,
    remaining: usize,
}

impl<'a, R> LimitedRead<'a, R> {
    #[inline]
    fn new(inner: &'a mut R, remaining: usize) -> Self {
        Self { inner, remaining }
    }
}

impl<R: IoBuf> IoBuf for LimitedRead<'_, R> {
    fn remaining(&self) -> usize {
        self.inner.remaining().min(self.remaining)
    }
}

impl<R: axio::Read> axio::Read for LimitedRead<'_, R> {
    fn read(&mut self, dst: &mut [u8]) -> axio::Result<usize> {
        let limit = dst.len().min(self.remaining);
        if limit == 0 {
            return Ok(0);
        }
        let n = self.inner.read(&mut dst[..limit])?;
        self.remaining -= n;
        Ok(n)
    }
}

async fn release_fd_entry_async(entry: FdEntry) {
    if Arc::strong_count(&entry.object) == 1
        && let Some(file_obj) = entry.object.as_any().downcast_ref::<FileObject>()
    {
        file_obj.flush_pending_timestamps_async().await;
    }
    drop(entry);
}

#[inline]
fn fd_serial_key(obj: &Arc<dyn FdObject>) -> u64 {
    Arc::as_ptr(obj) as *const () as usize as u64
}

#[derive(Clone, Copy)]
struct RwExecParams {
    is_write: bool,
    opt_offset: Option<u64>,
    direct_buf_aligned: bool,
    rw_flags: u32,
}

#[inline]
fn process_fsize_limit(ctx: &AsyncExecContext) -> u64 {
    ctx.process
        .get_rlimit(RLIMIT_FSIZE)
        .map(|lim| lim.rlim_cur)
        .unwrap_or(u64::MAX)
}

#[derive(Clone, Copy)]
enum FileSyncOpKind {
    Fsync {
        offset: u64,
        len: u32,
        data_only: bool,
    },
    SyncFileRange {
        offset: u64,
        len: u32,
        wait_before: bool,
        write: bool,
        wait_after: bool,
    },
}

async fn run_file_sync_op(entry: &FdEntry, op: FileSyncOpKind) -> LinuxResult<()> {
    match op {
        FileSyncOpKind::Fsync {
            offset,
            len,
            data_only,
        } => {
            if let Some(file_obj) = entry.object.as_any().downcast_ref::<FileObject>() {
                if data_only && (offset != 0 || len != 0) {
                    file_obj
                        .sync_range_async(offset, len as u64, true, true, true)
                        .await
                } else {
                    file_obj.sync_async(data_only).await
                }
            } else if entry.object.as_any().is::<DirObject>()
                && let Some(loc) = entry.object.location()
            {
                loc.sync(data_only).await.map_err(LinuxError::from)
            } else {
                Err(LinuxError::EINVAL)
            }
        }
        FileSyncOpKind::SyncFileRange {
            offset,
            len,
            wait_before,
            write,
            wait_after,
        } => {
            if let Some(file_obj) = entry.object.as_any().downcast_ref::<FileObject>() {
                file_obj
                    .sync_range_async(offset, len as u64, wait_before, write, wait_after)
                    .await
            } else if entry.object.as_any().is::<DirObject>()
                && (write || wait_after)
                && let Some(loc) = entry.object.location()
            {
                loc.sync(true).await.map_err(LinuxError::from)
            } else {
                Ok(())
            }
        }
    }
}

fn spawn_file_sync_op(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    entry: FdEntry,
    force_async: bool,
    op: FileSyncOpKind,
) {
    let is_blocking = entry
        .object
        .as_any()
        .downcast_ref::<FileObject>()
        .is_some_and(FileObject::is_blocking_node);
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    if force_async || is_blocking {
        global_worker_pool().submit(state.ring_id(), req_id, move || {
            let _guard: OwnedInflightGuard = guard;
            if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
                return;
            }
            let res = axtask::future::block_on(run_file_sync_op(&entry, op));
            drop(entry);
            let code = res.map(|()| 0).unwrap_or_else(|err| -err.code());
            state_cloned.complete_request(req_id, code, 0, true);
        });
        return;
    }

    state.spawn_native(req_id, async move {
        let _guard = guard;
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            release_fd_entry_async(entry).await;
            return;
        }
        let res = run_file_sync_op(&entry, op).await;
        release_fd_entry_async(entry).await;
        let code = res.map(|()| 0).unwrap_or_else(|err| -err.code());
        state_cloned.complete_request(req_id, code, 0, true);
    });
}

pub fn execute_fsync_request(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    entry: FdEntry,
    offset: u64,
    len: u32,
    data_only: bool,
    force_async: bool,
) {
    spawn_file_sync_op(
        state,
        req_id,
        entry,
        force_async,
        FileSyncOpKind::Fsync {
            offset,
            len,
            data_only,
        },
    );
}

pub fn execute_sync_file_range_request(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    entry: FdEntry,
    offset: u64,
    len: u32,
    sync_flags: u32,
    force_async: bool,
) {
    spawn_file_sync_op(
        state,
        req_id,
        entry,
        force_async,
        FileSyncOpKind::SyncFileRange {
            offset,
            len,
            wait_before: (sync_flags & SYNC_FILE_RANGE_WAIT_BEFORE) != 0,
            write: (sync_flags & SYNC_FILE_RANGE_WRITE) != 0,
            wait_after: (sync_flags & SYNC_FILE_RANGE_WAIT_AFTER) != 0,
        },
    );
}

pub fn execute_rw_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    data: Box<PreparedRwData>,
    is_write: bool,
    rw_flags: u32,
    force_async: bool,
) {
    let PreparedRwData {
        entry,
        buffer,
        offset,
        direct_buf_aligned,
    } = *data;

    if entry.object.as_any().is::<EpollObject>() {
        let res = run_sync_rw((state, req_id), ctx, &entry.object, is_write, buffer, offset.unwrap_or(u64::MAX), false);
        state.complete_request(req_id, res, 0, false);
        return;
    }

    if let Some(file_obj) = entry.object.as_any().downcast_ref::<FileObject>() {
        let params = RwExecParams {
            is_write,
            opt_offset: offset,
            direct_buf_aligned,
            rw_flags,
        };
        if file_obj.supports_file_io() {
            execute_regular_file_rw(state, ctx, req_id, entry, buffer, params, force_async);
            return;
        }
        if file_obj.is_seekable() {
            execute_seekable_special_file_rw(
                state,
                ctx,
                req_id,
                entry,
                buffer,
                params,
                force_async,
            );
            return;
        }
    }

    if is_stream_ready_fd(entry.object.as_ref()) {
        let total_len = buffer.total_len();
        if let Err(err) = validate_stream_rw_len(entry.object.as_ref(), is_write, total_len) {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
        if !force_async
            && ((total_len <= RW_CHUNK_CAP && !matches!(buffer, PreparedRwBuffer::MultiWindow { .. }))
                || matches!(buffer, PreparedRwBuffer::Fixed(_)))
        {
            execute_stream_rw(
                state,
                ctx,
                req_id,
                entry,
                is_write,
                buffer,
                rw_flags,
            );
        } else {
            let serial_key = Some(fd_serial_key(&entry.object));
            spawn_worker_rw(
                state,
                ctx,
                req_id,
                entry,
                is_write,
                buffer,
                offset.unwrap_or(u64::MAX),
                (rw_flags & RWF_NOWAIT) != 0,
                serial_key,
            );
        }
        return;
    }

    if entry.object.as_any().is::<Socket>() {
        execute_socket_rw_request(state, ctx, req_id, entry, is_write, buffer, rw_flags, force_async);
        return;
    }

    if force_async
        || matches!(buffer, PreparedRwBuffer::MultiWindow { .. })
    {
        spawn_worker_rw(
            state,
            ctx,
            req_id,
            entry,
            is_write,
            buffer,
            offset.unwrap_or(u64::MAX),
            (rw_flags & RWF_NOWAIT) != 0,
            None,
        );
        return;
    }

    let res = run_sync_rw(
        (state, req_id),
        ctx,
        &entry.object,
        is_write,
        buffer,
        offset.unwrap_or(u64::MAX),
        (rw_flags & RWF_NOWAIT) != 0,
    );
    state.complete_request(req_id, res, 0, false);
}

#[inline]
fn is_stream_ready_fd(obj: &dyn FdObject) -> bool {
    obj.as_any().is::<PipeObject>()
        || obj.as_any().is::<EventFdObject>()
        || obj.as_any().is::<StdinObject>()
        || obj.as_any().is::<SignalFdObject>()
        || obj.as_any().is::<TimerFdObject>()
}

#[inline]
fn validate_stream_rw_len(obj: &dyn FdObject, is_write: bool, len: usize) -> LinuxResult<()> {
    if obj.as_any().is::<EventFdObject>() && ((is_write && len != 8) || (!is_write && len < 8)) {
        return Err(LinuxError::EINVAL);
    }
    if obj.as_any().is::<TimerFdObject>() && (is_write || len < 8) {
        return Err(LinuxError::EINVAL);
    }
    if obj.as_any().is::<SignalFdObject>() && (is_write || len < 128) {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

fn try_read_with_staging<W: Write + IoBufMut>(
    file_obj: &FileObject,
    opt_offset: Option<u64>,
    dst: &mut W,
    mut staging_cache: Option<&mut Vec<u8>>,
    terminal_error: impl FnOnce(&W) -> Option<LinuxError>,
) -> Option<i32> {
    let mut io = file_obj.try_begin_read_io(opt_offset)?.ok()?;
    if let Some(cache) = staging_cache.as_deref_mut() {
        let _ = io.replace_staging(core::mem::take(cache));
    }
    let maybe_res = io.try_read(dst);
    if let Some(cache) = staging_cache {
        *cache = io.replace_staging(Vec::new());
    }
    let res = maybe_res?;
    Some(match res {
        Ok(0) => match terminal_error(dst) {
            Some(err) => -err.code(),
            None => 0,
        },
        Ok(n) => n as i32,
        Err(err) => -LinuxError::from(err).code(),
    })
}

fn try_path1_regular_read(
    file_obj: &FileObject,
    opt_offset: Option<u64>,
    buffer: &mut PreparedRwBuffer,
) -> Option<i32> {
    match buffer {
        PreparedRwBuffer::SingleWindow(win) => try_read_with_staging(
            file_obj,
            opt_offset,
            win.as_mut(),
            None,
            |w| w.terminal_error(),
        ),
        PreparedRwBuffer::Fixed(fixed) => {
            try_read_with_staging(file_obj, opt_offset, fixed, None, |_| None)
        }
        _ => None,
    }
}

/// Attempts a zero-future Path 1 cached read directly inside `submit_sqes` without
/// allocating orchestrator nodes or staging buffers per SQE.
///
/// Validation failures, non-resident pages, and lock contention return `None` so the
/// caller falls back cleanly to `prepare_sqe` and preserves exact error/drain semantics.
pub(crate) fn try_inline_fast_path_read(
    state: &Arc<IoUringState>,
    sqe: &IoUringSqe,
    ctx: &AsyncExecContext,
    batch_staging: &mut Vec<u8>,
    cached_fixed_fd: &mut Option<(u32, u64, FdEntry)>,
) -> Option<i32> {
    if (sqe.flags & !IOSQE_FIXED_FILE) != 0 || sqe.op_flags != 0 || sqe.len == 0 {
        return None;
    }
    let is_fixed_op = match sqe.opcode {
        op if op == io_uring_op::IORING_OP_READ_FIXED as u8 => true,
        op if op == io_uring_op::IORING_OP_READ as u8 => false,
        _ => return None,
    };
    validate_sqe_v1(sqe).ok()?;
    if is_fixed_op {
        validate_rw_fixed_sqe(sqe).ok()?;
    } else {
        validate_rw_sqe(sqe).ok()?;
    }

    let is_fixed_file = (sqe.flags & IOSQE_FIXED_FILE) != 0;
    let file_obj_storage: FdEntry;
    let file_obj: &FileObject = if is_fixed_file {
        let index = u32::try_from(sqe.fd).ok()?;
        let current_gen = state.fixed_files_generation();
        let cache_hit = cached_fixed_fd
            .as_ref()
            .is_some_and(|(idx, cached_gen, _)| *idx == index && *cached_gen == current_gen);
        if !cache_hit {
            let (entry, files_gen) = state.get_fixed_fd_entry_with_gen(index).ok()?;
            if entry.flags.contains(FdFlags::PATH)
                || !entry.object.is_read_open()
                || entry.object.as_any().is::<DirObject>()
            {
                return None;
            }
            *cached_fixed_fd = Some((index, files_gen, entry));
        }
        let (_, _, entry) = cached_fixed_fd.as_ref()?;
        entry.object.as_any().downcast_ref::<FileObject>()?
    } else {
        file_obj_storage = open_rw_fd_entry(state, ctx, sqe, false).ok()?;
        file_obj_storage.object.as_any().downcast_ref::<FileObject>()?
    };
    if !file_obj.supports_file_io() || file_obj.is_direct_regular_file() {
        return None;
    }
    let opt_offset =
        rw_offset_to_option(resolve_rw_offset(sqe.off, sqe.len as usize, true).ok()?);

    if is_fixed_op {
        let mut fixed_io = state
            .resolve_fixed_buffer(sqe.buf_index, sqe.addr, sqe.len, true)
            .ok()?;
        return try_read_with_staging(
            file_obj,
            opt_offset,
            &mut fixed_io,
            Some(batch_staging),
            |_| None,
        );
    }

    let len = sqe.len as usize;
    let addr = sqe.addr as usize;
    if !ctx.is_user_range(addr, len) {
        return None;
    }
    let segs = [UserIoSegment::new(addr, len)];
    if !fits_single_pin_window(&segs) {
        return None;
    }
    let mut cursor = UserBufferCursor::default();
    let mut win =
        PinnedUserBuffers::pin_with_aspace(&ctx.aspace, &segs, &mut cursor, true).ok()?;
    try_read_with_staging(
        file_obj,
        opt_offset,
        &mut win,
        Some(batch_staging),
        |w| w.terminal_error(),
    )
}

async fn transfer_file_io_buf(
    io: &mut axfs::FileIo<'_>,
    buffer: &mut PreparedRwBuffer,
    is_write: bool,
    fsize_limit: u64,
) -> LinuxResult<usize> {
    let total_len = buffer.total_len();
    if total_len == 0 {
        return Ok(0);
    }
    if is_write {
        let cur_off = io.current_offset();
        if cur_off >= fsize_limit {
            return Err(LinuxError::EFBIG);
        }
        let max_write = (fsize_limit - cur_off).min(total_len as u64) as usize;
        let written = match buffer {
            PreparedRwBuffer::SingleWindow(win) => {
                let mut limited = LimitedRead::new(win.as_mut(), max_write);
                io.write(&mut limited).await.map_err(LinuxError::from)?
            }
            PreparedRwBuffer::Fixed(fixed) => {
                let mut limited = LimitedRead::new(fixed, max_write);
                io.write(&mut limited).await.map_err(LinuxError::from)?
            }
            PreparedRwBuffer::Empty | PreparedRwBuffer::MultiWindow { .. } => {
                return Err(LinuxError::EINVAL);
            }
        };
        if written == 0 && let Some(err) = buffer.terminal_error() {
            return Err(err);
        }
        Ok(written)
    } else {
        let read = match buffer {
            PreparedRwBuffer::SingleWindow(win) => {
                io.read(win.as_mut()).await.map_err(LinuxError::from)?
            }
            PreparedRwBuffer::Fixed(fixed) => io.read(fixed).await.map_err(LinuxError::from)?,
            PreparedRwBuffer::Empty | PreparedRwBuffer::MultiWindow { .. } => {
                return Err(LinuxError::EINVAL);
            }
        };
        if read == 0 && let Some(err) = buffer.terminal_error() {
            return Err(err);
        }
        Ok(read)
    }
}

async fn transfer_regular_file_buffer(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    io: &mut axfs::FileIo<'_>,
    buffer: PreparedRwBuffer,
    is_write: bool,
    fsize_limit: u64,
) -> LinuxResult<usize> {
    match buffer {
        PreparedRwBuffer::Empty => Ok(0),
        mut single @ (PreparedRwBuffer::SingleWindow(_) | PreparedRwBuffer::Fixed(_)) => {
            transfer_file_io_buf(io, &mut single, is_write, fsize_limit).await
        }
        PreparedRwBuffer::MultiWindow {
            segments,
            total_len,
        } => {
            let mut cursor = UserBufferCursor::default();
            let mut total_done = 0usize;
            while total_done < total_len {
                if !state.is_request_active(req_id) || state.is_dying() {
                    return Ok(total_done);
                }
                if is_write && io.current_offset() >= fsize_limit {
                    if total_done == 0 {
                        return Err(LinuxError::EFBIG);
                    }
                    break;
                }
                let window = match PinnedUserBuffers::pin_with_aspace(
                    &ctx.aspace,
                    &segments,
                    &mut cursor,
                    !is_write,
                ) {
                    Ok(win) => win,
                    Err(err) => {
                        return if total_done > 0 {
                            Ok(total_done)
                        } else {
                            Err(err)
                        };
                    }
                };
                let submitted = window.len();
                if submitted == 0 {
                    if total_done == 0
                        && let Some(err) = window.terminal_error()
                    {
                        return Err(err);
                    }
                    break;
                }
                let mut win_buf = PreparedRwBuffer::SingleWindow(Box::new(window));
                let transferred =
                    match transfer_file_io_buf(io, &mut win_buf, is_write, fsize_limit).await {
                        Ok(n) => n,
                        Err(err) => {
                            return if total_done > 0 {
                                Ok(total_done)
                            } else {
                                Err(err)
                            };
                        }
                    };
                total_done += transferred;
                if transferred < submitted || win_buf.terminal_error().is_some() {
                    break;
                }
            }
            Ok(total_done)
        }
    }
}

async fn run_regular_file_io_transaction(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    file_obj: &FileObject,
    buffer: PreparedRwBuffer,
    pos_ticket: Option<axfs::FilePositionTicket>,
    params: RwExecParams,
) -> LinuxResult<usize> {
    let force_append = (params.rw_flags & RWF_APPEND) != 0;
    let sync_after = (params.rw_flags & (RWF_DSYNC | RWF_SYNC)) != 0;
    let data_only = (params.rw_flags & RWF_SYNC) == 0;
    let total_len = buffer.total_len();

    let mut io = if params.is_write {
        file_obj
            .begin_write_io_with_ticket(pos_ticket, params.opt_offset, force_append)
            .await?
    } else {
        file_obj
            .begin_read_io_with_ticket(pos_ticket, params.opt_offset)
            .await?
    };

    if file_obj.is_direct_regular_file() {
        if !params.direct_buf_aligned {
            return Err(LinuxError::EINVAL);
        }
        let block_size = file_obj.block_size_async().await as usize;
        validate_direct_io_offset(io.validation_offset(), block_size)?;
    }

    if total_len == 0 {
        drop(io);
        if params.is_write && sync_after {
            file_obj.sync_async(data_only).await?;
        }
        return Ok(0);
    }

    let fsize_limit = process_fsize_limit(ctx);
    let transferred = transfer_regular_file_buffer(
        state,
        ctx,
        req_id,
        &mut io,
        buffer,
        params.is_write,
        fsize_limit,
    )
    .await?;
    drop(io);

    if params.is_write && sync_after && transferred > 0 {
        file_obj.sync_async(data_only).await?;
    }
    Ok(transferred)
}

fn execute_regular_file_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    mut buffer: PreparedRwBuffer,
    params: RwExecParams,
    force_async: bool,
) {
    let file_obj = entry
        .object
        .as_any()
        .downcast_ref::<FileObject>()
        .expect("FileObject");
    let is_direct = file_obj.is_direct_regular_file();
    let nowait = (params.rw_flags & RWF_NOWAIT) != 0;

    if is_direct && !params.direct_buf_aligned {
        state.complete_request(req_id, -LinuxError::EINVAL.code(), 0, false);
        return;
    }

    // Path 1: non-IOSQE_ASYNC cached read hitting resident pages on a bounded single window.
    if !force_async
        && !params.is_write
        && !is_direct
        && !matches!(buffer, PreparedRwBuffer::MultiWindow { .. })
    {
        if matches!(buffer, PreparedRwBuffer::Empty) {
            state.complete_request(req_id, 0, 0, false);
            return;
        }
        if let Some(code) = try_path1_regular_read(file_obj, params.opt_offset, &mut buffer) {
            state.complete_request(req_id, code, 0, false);
            return;
        }
    }

    if nowait {
        state.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, false);
        return;
    }

    // Reserve before handing off to either executor so later implicit-offset I/O
    // cannot overtake this request while its first poll is queued on another CPU.
    let pos_ticket = params
        .opt_offset
        .is_none()
        .then(|| file_obj.reserve_position_ticket())
        .flatten();
    if !force_async && !matches!(buffer, PreparedRwBuffer::MultiWindow { .. }) {
        // Path 2: native multi-Future execution on KernelExecutor.
        let Some(guard) = state.try_enter_inflight_owned() else {
            return;
        };
        let state_cloned = Arc::clone(state);
        let ctx_cloned = ctx.clone();

        state.spawn_native(req_id, async move {
            let _guard = guard;
            if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
                drop(pos_ticket);
                release_fd_entry_async(entry).await;
                return;
            }
            let file_obj = entry
                .object
                .as_any()
                .downcast_ref::<FileObject>()
                .expect("FileObject");
            let res = run_regular_file_io_transaction(
                &state_cloned,
                &ctx_cloned,
                req_id,
                file_obj,
                buffer,
                pos_ticket,
                params,
            )
            .await;
            release_fd_entry_async(entry).await;
            let code = match res {
                Ok(n) => n as i32,
                Err(err) => -err.code(),
            };
            state_cloned.complete_request(req_id, code, 0, true);
        });
        return;
    }

    // Path 3: IOSQE_ASYNC or Multi-window (> 64 KiB / > 32 fragments) on worker pool.
    let force_append = (params.rw_flags & RWF_APPEND) != 0;
    let needs_serial = params.opt_offset.is_none()
        || (params.is_write && (force_append || file_obj.is_append_open()));
    let serial_key = needs_serial.then(|| fd_serial_key(&entry.object));

    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_wk = Arc::clone(state);
    let ctx_wk = ctx.clone();

    global_worker_pool().submit_ordered(state.ring_id(), req_id, serial_key, move || {
        let _guard: OwnedInflightGuard = guard;
        if !state_wk.is_request_active(req_id) || state_wk.is_dying() {
            drop(pos_ticket);
            return;
        }

        let res = axtask::future::block_on(async {
            let file_obj = entry
                .object
                .as_any()
                .downcast_ref::<FileObject>()
                .expect("FileObject");
            run_regular_file_io_transaction(
                &state_wk,
                &ctx_wk,
                req_id,
                file_obj,
                buffer,
                pos_ticket,
                params,
            )
            .await
        });
        drop(entry);

        let code = match res {
            Ok(done) => done as i32,
            Err(err) => -err.code(),
        };
        state_wk.complete_request(req_id, code, 0, true);
    });
}

async fn transfer_seekable_special_buf(
    file_obj: &FileObject,
    buffer: &mut PreparedRwBuffer,
    is_write: bool,
    opt_offset: Option<u64>,
    limit: usize,
) -> LinuxResult<usize> {
    if is_write {
        match buffer {
            PreparedRwBuffer::SingleWindow(win) => {
                let mut limited = LimitedRead::new(win.as_mut(), limit);
                match opt_offset {
                    Some(off) => file_obj.write_at_async(&mut limited, off).await,
                    None => file_obj.write_async(&mut limited).await,
                }
            }
            PreparedRwBuffer::Fixed(fixed) => {
                let mut limited = LimitedRead::new(fixed, limit);
                match opt_offset {
                    Some(off) => file_obj.write_at_async(&mut limited, off).await,
                    None => file_obj.write_async(&mut limited).await,
                }
            }
            _ => Err(LinuxError::EINVAL),
        }
    } else {
        match buffer {
            PreparedRwBuffer::SingleWindow(win) => match opt_offset {
                Some(off) => file_obj.read_at_async(win.as_mut(), off).await,
                None => file_obj.read_async(win.as_mut()).await,
            },
            PreparedRwBuffer::Fixed(fixed) => match opt_offset {
                Some(off) => file_obj.read_at_async(fixed, off).await,
                None => file_obj.read_async(fixed).await,
            },
            _ => Err(LinuxError::EINVAL),
        }
    }
}

fn execute_seekable_special_file_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    mut buffer: PreparedRwBuffer,
    params: RwExecParams,
    force_async: bool,
) {
    let nowait = (params.rw_flags & RWF_NOWAIT) != 0;
    let file_obj = entry
        .object
        .as_any()
        .downcast_ref::<FileObject>()
        .expect("FileObject");
    let is_blocking = file_obj.is_blocking_node();
    if nowait && is_blocking {
        state.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, false);
        return;
    }

    if force_async || is_blocking || matches!(buffer, PreparedRwBuffer::MultiWindow { .. }) {
        let serial_key = params
            .opt_offset
            .is_none()
            .then(|| fd_serial_key(&entry.object));
        spawn_worker_rw(
            state,
            ctx,
            req_id,
            entry,
            params.is_write,
            buffer,
            params.opt_offset.unwrap_or(u64::MAX),
            nowait,
            serial_key,
        );
        return;
    }

    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let ctx_cloned = ctx.clone();
    let sync_after = (params.rw_flags & (RWF_DSYNC | RWF_SYNC)) != 0;
    let data_only = (params.rw_flags & RWF_SYNC) == 0;

    state.spawn_native(req_id, async move {
        let _guard = guard;
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            release_fd_entry_async(entry).await;
            return;
        }
        let file_obj = entry
            .object
            .as_any()
            .downcast_ref::<FileObject>()
            .expect("FileObject");
        let total_len = buffer.total_len();
        let fsize_limit = process_fsize_limit(&ctx_cloned);

        let res: LinuxResult<usize> = async {
            if total_len == 0 {
                if params.is_write && sync_after {
                    file_obj.sync_async(data_only).await?;
                }
                return Ok(0);
            }
            let limit = if params.is_write {
                if let Some(off) = params.opt_offset {
                    if off >= fsize_limit {
                        return Err(LinuxError::EFBIG);
                    }
                    (fsize_limit - off).min(total_len as u64) as usize
                } else {
                    total_len
                }
            } else {
                total_len
            };
            let transferred = transfer_seekable_special_buf(
                file_obj,
                &mut buffer,
                params.is_write,
                params.opt_offset,
                limit,
            )
            .await?;
            if transferred == 0 && let Some(err) = buffer.terminal_error() {
                return Err(err);
            }
            if params.is_write && sync_after && transferred > 0 {
                file_obj.sync_async(data_only).await?;
            }
            Ok(transferred)
        }
        .await;

        release_fd_entry_async(entry).await;
        let code = match res {
            Ok(n) => n as i32,
            Err(err) => -err.code(),
        };
        state_cloned.complete_request(req_id, code, 0, true);
    });
}

#[allow(clippy::too_many_arguments)]
fn spawn_worker_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    buffer: PreparedRwBuffer,
    offset: u64,
    nowait: bool,
    serial_key: Option<u64>,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_wk = Arc::clone(state);
    let ctx_wk = ctx.clone();
    global_worker_pool().submit_ordered(state.ring_id(), req_id, serial_key, move || {
        let _guard: OwnedInflightGuard = guard;
        if !state_wk.is_request_active(req_id) {
            return;
        }
        let res = run_sync_rw((&state_wk, req_id), &ctx_wk, &entry.object, is_write, buffer, offset, nowait);
        state_wk.complete_request(req_id, res, 0, true);
    });
}

enum StreamStep {
    Done(usize),
    WouldBlock,
}

fn try_stream_rw_once(
    thread: Option<&Arc<crate::task::Thread>>,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    buf: &mut [u8],
) -> LinuxResult<usize> {
    if let Some(pipe) = obj.as_any().downcast_ref::<PipeObject>() {
        return if is_write {
            pipe.try_write_nonblocking(buf)
        } else {
            pipe.try_read_nonblocking(buf)
        };
    }
    if let Some(ev) = obj.as_any().downcast_ref::<EventFdObject>() {
        return if is_write {
            ev.try_write_nonblocking(buf)
        } else {
            ev.try_read_nonblocking(buf)
        };
    }
    if let Some(stdin) = obj.as_any().downcast_ref::<StdinObject>() {
        return if is_write {
            Err(LinuxError::EPERM)
        } else {
            stdin.try_read_nonblocking(buf)
        };
    }
    if let Some(sigfd) = obj.as_any().downcast_ref::<SignalFdObject>() {
        return if is_write {
            Err(LinuxError::EINVAL)
        } else {
            let th = thread.ok_or(LinuxError::EINVAL)?;
            sigfd.try_read_nonblocking_for_thread(th.as_ref(), buf)
        };
    }
    if let Some(timerfd) = obj.as_any().downcast_ref::<TimerFdObject>() {
        return if is_write {
            Err(LinuxError::EINVAL)
        } else {
            timerfd.try_read_nonblocking(buf)
        };
    }
    Err(LinuxError::EINVAL)
}

fn step_stream_rw(
    thread: Option<&Arc<crate::task::Thread>>,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    buffer: &mut PreparedRwBuffer,
    kbuf: &mut [u8],
    staged_off: &mut usize,
    staged_len: &mut usize,
) -> LinuxResult<StreamStep> {
    let mut total_done = 0usize;
    if is_write {
        loop {
            if *staged_off == *staged_len {
                let next = buffer.remaining_bytes().min(kbuf.len());
                if next == 0 {
                    return Ok(StreamStep::Done(total_done));
                }
                buffer.copy_from_user_exact(&mut kbuf[..next])?;
                *staged_off = 0;
                *staged_len = next;
            }
            match try_stream_rw_once(thread, obj, true, &mut kbuf[*staged_off..*staged_len]) {
                Ok(0) => return Ok(StreamStep::Done(total_done)),
                Ok(n) => {
                    *staged_off += n;
                    total_done += n;
                    if buffer.remaining_bytes() == 0 && *staged_off == *staged_len {
                        return Ok(StreamStep::Done(total_done));
                    }
                    if *staged_off < *staged_len {
                        return Ok(StreamStep::Done(total_done));
                    }
                }
                Err(LinuxError::EAGAIN) => {
                    return Ok(if total_done > 0 {
                        StreamStep::Done(total_done)
                    } else {
                        StreamStep::WouldBlock
                    });
                }
                Err(err) => {
                    return if total_done > 0 {
                        Ok(StreamStep::Done(total_done))
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
                return Ok(StreamStep::Done(total_done));
            }
            match try_stream_rw_once(thread, obj, false, &mut kbuf[..next]) {
                Ok(0) => return Ok(StreamStep::Done(total_done)),
                Ok(n) => {
                    buffer.copy_to_user_exact(&kbuf[..n])?;
                    total_done += n;
                    if n < next {
                        return Ok(StreamStep::Done(total_done));
                    }
                }
                Err(LinuxError::EAGAIN) => {
                    return Ok(if total_done > 0 {
                        StreamStep::Done(total_done)
                    } else {
                        StreamStep::WouldBlock
                    });
                }
                Err(err) => {
                    return if total_done > 0 {
                        Ok(StreamStep::Done(total_done))
                    } else {
                        Err(err)
                    };
                }
            }
        }
    }
}

fn execute_stream_rw(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    mut buffer: PreparedRwBuffer,
    rw_flags: u32,
) {
    let transfer_len = buffer.total_len();
    let nowait = (rw_flags & RWF_NOWAIT) != 0;

    if let Err(err) = validate_stream_rw_len(entry.object.as_ref(), is_write, transfer_len) {
        state.complete_request(req_id, -err.code(), 0, false);
        return;
    }

    let mut kbuf = vec![0u8; transfer_len.min(RW_CHUNK_CAP)];
    let mut staged_off = 0usize;
    let mut staged_len = 0usize;

    if is_write && transfer_len <= kbuf.len() && transfer_len > 0 {
        if let Err(err) = buffer.copy_from_user_exact(&mut kbuf[..transfer_len]) {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
        staged_len = transfer_len;
        buffer = PreparedRwBuffer::Empty;
    }

    let ctx_thread = ctx.thread.clone();
    match step_stream_rw(
        ctx_thread.as_ref(),
        &entry.object,
        is_write,
        &mut buffer,
        &mut kbuf,
        &mut staged_off,
        &mut staged_len,
    ) {
        Ok(StreamStep::Done(n)) => {
            state.complete_request(req_id, n as i32, 0, false);
            return;
        }
        Ok(StreamStep::WouldBlock) if nowait => {
            state.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, false);
            return;
        }
        Ok(StreamStep::WouldBlock) => {}
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

    state.spawn_native(req_id, poll_fn(move |cx| {
        registrations.clear();
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            let _ = guard_slot.take();
            return Poll::Ready(());
        }

        let interest = if is_write {
            IoEvents::OUT | IoEvents::ERR | IoEvents::HUP
        } else {
            IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR | IoEvents::HUP
        };

        let mut registered = false;
        loop {
            match step_stream_rw(
                ctx_thread.as_ref(),
                &entry.object,
                is_write,
                &mut buffer,
                &mut kbuf,
                &mut staged_off,
                &mut staged_len,
            ) {
                Ok(StreamStep::Done(n)) => {
                    state_cloned.complete_request(req_id, n as i32, 0, true);
                    let _ = guard_slot.take();
                    return Poll::Ready(());
                }
                Ok(StreamStep::WouldBlock) => {
                    if nowait {
                        state_cloned.complete_request(req_id, -LinuxError::EAGAIN.code(), 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                    if registered {
                        return Poll::Pending;
                    }
                    let reg_res = if let Some(ref th) = ctx_thread {
                        Arc::clone(&entry.object).register_poll_for_thread(
                            th,
                            cx,
                            interest,
                            &mut registrations,
                        )
                    } else {
                        Arc::clone(&entry.object).register_poll(cx, interest, &mut registrations)
                    };
                    if let Err(e) = reg_res {
                        state_cloned.complete_request(req_id, -e.code(), 0, true);
                        let _ = guard_slot.take();
                        return Poll::Ready(());
                    }
                    registered = true;
                }
                Err(err) => {
                    state_cloned.complete_request(req_id, -err.code(), 0, true);
                    let _ = guard_slot.take();
                    return Poll::Ready(());
                }
            }
        }
    }));
}

#[inline]
fn transfer_obj_chunk(
    request: (&IoUringState, RequestId),
    ctx: &AsyncExecContext,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    base_offset: u64,
    cur_off: u64,
    buf: &mut [u8],
    nowait: bool,
) -> LinuxResult<usize> {
    if is_stream_ready_fd(obj.as_ref()) {
        let thread = ctx.thread.as_ref();
        match try_stream_rw_once(thread, obj, is_write, buf) {
            Err(LinuxError::EAGAIN) if !nowait => {}
            result => return result,
        }
        let (ring, id) = request;
        let interest = if is_write {
            IoEvents::OUT | IoEvents::ERR | IoEvents::HUP
        } else {
            IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR | IoEvents::HUP
        };
        let mut registrations = Vec::new();
        let mut wake_on_completion = None;
        // A pending worker holds an inflight guard. Teardown must be able to wake it
        // even when no peer ever makes the stream ready (for example a linked write).
        let result = axtask::future::block_on(poll_fn(|cx| {
            registrations.clear();
            if let Some(reg) = wake_on_completion.take() {
                ring.cq_wait_queue.unregister_waker(reg);
            }
            wake_on_completion = Some(ring.cq_wait_queue.register_owned_waker(cx.waker()));
            obj.clone().register_poll_with_context(
                &ctx.process, thread, cx, interest, &mut registrations,
            )?;
            // Register both sources before rechecking to avoid losing a readiness or cancel wake.
            if ring.is_dying() || !ring.is_request_active(id) {
                return Poll::Ready(Err(LinuxError::ECANCELED));
            }
            match try_stream_rw_once(thread, obj, is_write, buf) {
                Err(LinuxError::EAGAIN) => Poll::Pending,
                result => Poll::Ready(result),
            }
        }));
        if let Some(reg) = wake_on_completion {
            ring.cq_wait_queue.unregister_waker(reg);
        }
        return result;
    }
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

#[allow(clippy::too_many_arguments)]
fn run_sync_rw_window(
    request: (&IoUringState, RequestId),
    ctx: &AsyncExecContext,
    buffer: &mut PreparedRwBuffer,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    base_offset: u64,
    cur_off: &mut u64,
    kbuf: &mut [u8],
    total_done: &mut usize,
    nowait: bool,
) -> LinuxResult<bool> {
    let total = buffer.total_len();
    let mut off_in_stream = 0usize;
    while off_in_stream < total {
        let chunk = (total - off_in_stream).min(kbuf.len());
        if is_write {
            buffer.copy_from_user_exact(&mut kbuf[..chunk])?;
        }
        let n = transfer_obj_chunk(
            request,
            ctx,
            obj,
            is_write,
            base_offset,
            *cur_off,
            &mut kbuf[..chunk],
            nowait,
        )?;
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
    request: (&IoUringState, RequestId),
    ctx: &AsyncExecContext,
    obj: &Arc<dyn FdObject>,
    is_write: bool,
    mut buffer: PreparedRwBuffer,
    offset: u64,
    nowait: bool,
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
                request,
                ctx,
                &mut buffer,
                obj,
                is_write,
                offset,
                &mut cur_off,
                &mut kbuf,
                &mut total_done,
                nowait,
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
                let window = match PinnedUserBuffers::pin_with_aspace(
                    &ctx.aspace,
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
                let mut win_buf = PreparedRwBuffer::SingleWindow(Box::new(window));
                match run_sync_rw_window(
                    request,
                    ctx,
                    &mut win_buf,
                    obj,
                    is_write,
                    offset,
                    &mut cur_off,
                    &mut kbuf,
                    &mut total_done,
                    nowait,
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
    ctx: &AsyncExecContext,
    req_id: RequestId,
    target: PollTarget,
    mask: u32,
    events: IoEvents,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let ctx_cloned = ctx.clone();
    let registrations: core::cell::RefCell<Vec<PollRegistration>> =
        core::cell::RefCell::new(Vec::new());
    let mut guard_slot = Some(guard);

    state.spawn_native(req_id, poll_fn(move |cx| {
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            registrations.borrow_mut().clear();
            let _ = guard_slot.take();
            return Poll::Ready(());
        }

        let step = drive_one_shot_poll_step(
            || eval_poll_target_with_context(&target, &ctx_cloned, mask),
            || match &target {
                PollTarget::Fd(obj) => Arc::clone(obj).register_poll_with_context(
                    &ctx_cloned.process,
                    ctx_cloned.thread.as_ref(),
                    cx,
                    events,
                    &mut registrations.borrow_mut(),
                ),
                PollTarget::Ring(weak_ring) => {
                    let Some(target_ring) = weak_ring.upgrade() else {
                        return Err(LinuxError::EBADF);
                    };
                    let reg = target_ring.cq_wait_queue.register_owned_waker(cx.waker());
                    let weak_unreg = Arc::downgrade(&target_ring);
                    registrations.borrow_mut().push(PollRegistration::new(move || {
                        if let Some(ring) = weak_unreg.upgrade() {
                            ring.cq_wait_queue.unregister_waker(reg);
                        }
                    }));
                    Ok(())
                }
            },
            || registrations.borrow_mut().clear(),
        );

        match step {
            Ok(OneShotPollStep::Ready(revents)) => {
                registrations.borrow_mut().clear();
                state_cloned.complete_request(req_id, revents as i32, 0, true);
                let _ = guard_slot.take();
                Poll::Ready(())
            }
            Ok(OneShotPollStep::Pending) => Poll::Pending,
            Err(err) => {
                registrations.borrow_mut().clear();
                let res = if err == LinuxError::EBADF && matches!(target, PollTarget::Ring(_)) {
                    POLLNVAL as i32
                } else {
                    -err.code()
                };
                state_cloned.complete_request(req_id, res, 0, true);
                let _ = guard_slot.take();
                Poll::Ready(())
            }
        }
    }));
}

pub(super) fn eval_poll_target_with_context(
    target: &PollTarget,
    ctx: &AsyncExecContext,
    mask: u32,
) -> Option<u32> {
    let rev = match target {
        PollTarget::Fd(obj) => {
            match obj.poll_readiness_with_context(&ctx.process, ctx.thread.as_deref()) {
                Ok(readiness) => compute_poll_revents(mask, readiness),
                Err(_) => POLLERR,
            }
        }
        PollTarget::Ring(weak) => {
            let Some(ring) = weak.upgrade() else {
                return Some(POLLNVAL);
            };
            let readiness = PollReadiness {
                readable: ring.has_ready_cqes_fast(),
                writable: false,
                rdhup: false,
                hup: ring.is_dying(),
                err: false,
            };
            compute_poll_revents(mask, readiness)
        }
    };
    (rev != 0).then_some(rev)
}
