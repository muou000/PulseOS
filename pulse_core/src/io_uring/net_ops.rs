//! Async Socket and unified Socket R/W execution engine for PulseOS `io_uring`.

use alloc::{boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{
    future::poll_fn,
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::atomic::Ordering,
    task::Poll,
};

use axerrno::{LinuxError, LinuxResult};
use axpoll::IoEvents;
use axtask::future::global_executor;
use linux_raw_sys::{
    general::{O_CLOEXEC, O_NONBLOCK, SIGPIPE, iovec},
    net::{AF_INET, AF_INET6, AF_UNIX, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_PEEK, MSG_WAITALL, UNIX_PATH_MAX},
};
use pulse_io_uring_core::orchestrator::{PreparedRequest, RequestId};
use pulse_io_uring_core::whitelist::{
    validate_accept_sqe, validate_connect_sqe, validate_send_recv_sqe,
    validate_sendmsg_recvmsg_sqe, validate_shutdown_sqe, validate_socket_sqe,
};
use pulse_user_abi::{
    encode_to_buffer,
    io_uring::{IoUringSqe, RWF_NOWAIT},
    net::MessageHeader,
};

use super::{
    IoUringState, OwnedInflightGuard,
    context::AsyncExecContext,
    ops::{PreparedOpSpec, PreparedRwBuffer, resolve_sqe_fd_entry},
    worker_pool::global_worker_pool,
};
use crate::fd_table::{FdEntry, FdFlags, PollRegistration};
use crate::mm::{PinnedUserBuffers, UserBufferCursor, UserIoSegment, fits_single_pin_window};
use crate::net::{
    Socket, SocketInner, adapt_sockaddr_for_domain, lookup_unix_path_by_addr,
    lookup_unix_socket_by_key, normalize_connect_addr, resolve_unix_path_async,
    resolve_unix_path_sync,
};
use crate::task::{queue_signal_to_process, queue_signal_to_thread};

const MAX_IOV_COUNT: usize = 1024;
const RW_CHUNK_CAP: usize = 64 * 1024;
const UNIX_FAMILY_LEN: usize = 2;
const UNIX_ADDR_MAX: usize = UNIX_FAMILY_LEN + (UNIX_PATH_MAX as usize);
const MAX_PIN_SOCKADDR_LEN: usize = 128;
const SOCKADDR_BUF_MAX: usize = if UNIX_ADDR_MAX > 28 { UNIX_ADDR_MAX } else { 28 };

#[derive(Clone, Debug)]
pub enum ParsedSocketAddr {
    Inet(SocketAddr),
    UnixPath(String),
}

pub struct PreparedAcceptData {
    pub entry: FdEntry,
    pub addr_pin: Option<Box<PinnedUserBuffers>>,
    pub addrlen_pin: Option<Box<PinnedUserBuffers>>,
    pub addr_cap: usize,
    pub accept_flags: u32,
}

pub struct PreparedConnectData {
    pub entry: FdEntry,
    pub addr: ParsedSocketAddr,
}

pub struct PreparedSocketTransfer {
    pub entry: FdEntry,
    pub buffer: PreparedRwBuffer,
    pub dest_addr: Option<ParsedSocketAddr>,
    pub msg_flags: u32,
    pub pid: u32,
}

pub struct MsgHdrSnapshot {
    pub msg_name: usize,
    pub msg_namelen: u32,
    pub msg_iov: usize,
    pub msg_iovlen: usize,
    pub msg_control: usize,
    pub msg_controllen: usize,
    pub msg_flags: u32,
}

impl MsgHdrSnapshot {
    fn from_header(hdr: &MessageHeader) -> Self {
        Self {
            msg_name: hdr.msg_name as usize,
            msg_namelen: hdr.msg_namelen,
            msg_iov: hdr.msg_iov as usize,
            msg_iovlen: hdr.msg_iovlen,
            msg_control: hdr.msg_control as usize,
            msg_controllen: hdr.msg_controllen,
            msg_flags: hdr.msg_flags,
        }
    }

    fn to_header(&self) -> MessageHeader {
        MessageHeader {
            msg_name: self.msg_name as *mut _,
            msg_namelen: self.msg_namelen,
            msg_iov: self.msg_iov as *mut _,
            msg_iovlen: self.msg_iovlen,
            msg_control: self.msg_control as *mut _,
            msg_controllen: self.msg_controllen,
            msg_flags: self.msg_flags,
        }
    }
}

pub struct PreparedSocketMsgTransfer {
    pub entry: FdEntry,
    pub buffer: PreparedRwBuffer,
    pub hdr_pin: Option<Box<PinnedUserBuffers>>,
    pub initial_hdr: MsgHdrSnapshot,
    pub name_pin: Option<Box<PinnedUserBuffers>>,
    pub name_cap: usize,
    pub dest_addr: Option<ParsedSocketAddr>,
    pub msg_flags: u32,
    pub pid: u32,
}

fn pin_exact_rw(
    ctx: &AsyncExecContext,
    ptr: usize,
    len: usize,
    writable: bool,
) -> LinuxResult<Box<PinnedUserBuffers>> {
    if len == 0 {
        return Err(LinuxError::EINVAL);
    }
    if ptr == 0 || !ctx.is_user_range(ptr, len) {
        return Err(LinuxError::EFAULT);
    }
    let seg = [UserIoSegment::new(ptr, len)];
    let mut cursor = UserBufferCursor::default();
    let pinned = PinnedUserBuffers::pin_with_aspace(&ctx.aspace, &seg, &mut cursor, writable)?;
    if let Some(err) = pinned.terminal_error() {
        return Err(err);
    }
    if pinned.len() < len {
        return Err(LinuxError::EFAULT);
    }
    Ok(Box::new(pinned))
}

fn parse_user_sockaddr(
    ctx: &AsyncExecContext,
    addr: usize,
    addrlen: u32,
) -> LinuxResult<ParsedSocketAddr> {
    if addrlen > 128 || (addrlen as usize) < 2 {
        return Err(LinuxError::EINVAL);
    }
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let len = addrlen as usize;
    let mut raw = [0u8; 128];
    ctx.read_bytes(addr, &mut raw[..len])?;
    let family = u16::from_ne_bytes([raw[0], raw[1]]) as u32;

    match family {
        f if f == AF_UNIX => {
            if len <= UNIX_FAMILY_LEN || len > UNIX_ADDR_MAX {
                return Err(LinuxError::EINVAL);
            }
            let path_bytes = &raw[UNIX_FAMILY_LEN..len];
            let trimmed = if path_bytes[0] == 0 {
                path_bytes
            } else {
                let end = path_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(path_bytes.len());
                &path_bytes[..end]
            };
            Ok(ParsedSocketAddr::UnixPath(
                String::from_utf8_lossy(trimmed).into_owned(),
            ))
        }
        f if f == AF_INET => {
            if len < 16 {
                return Err(LinuxError::EINVAL);
            }
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let ip = Ipv4Addr::new(raw[4], raw[5], raw[6], raw[7]);
            Ok(ParsedSocketAddr::Inet(normalize_connect_addr(SocketAddr::V4(
                SocketAddrV4::new(ip, port),
            ))))
        }
        f if f == AF_INET6 => {
            if len < 28 {
                return Err(LinuxError::EINVAL);
            }
            let port = u16::from_be_bytes([raw[2], raw[3]]);
            let flowinfo = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
            let mut ip_octets = [0u8; 16];
            ip_octets.copy_from_slice(&raw[8..24]);
            let scope_id = u32::from_ne_bytes([raw[24], raw[25], raw[26], raw[27]]);
            Ok(ParsedSocketAddr::Inet(normalize_connect_addr(SocketAddr::V6(
                SocketAddrV6::new(Ipv6Addr::from(ip_octets), port, flowinfo, scope_id),
            ))))
        }
        _ => Err(LinuxError::EAFNOSUPPORT),
    }
}

fn encode_sockaddr_bytes(
    domain: u32,
    remote: Option<SocketAddr>,
) -> ([u8; SOCKADDR_BUF_MAX], usize) {
    let mut out = [0u8; SOCKADDR_BUF_MAX];
    if domain == AF_UNIX {
        out[0..2].copy_from_slice(&(AF_UNIX as u16).to_ne_bytes());
        let mut len = 2;
        if let Some(path) = remote.and_then(lookup_unix_path_by_addr) {
            let bytes = path.as_bytes();
            let copy = bytes.len().min(UNIX_PATH_MAX as usize);
            out[len..len + copy].copy_from_slice(&bytes[..copy]);
            len += copy;
            if !path.starts_with('\0') && copy < UNIX_PATH_MAX as usize {
                out[len] = 0;
                len += 1;
            }
        }
        return (out, len);
    }

    match remote.map(|addr| adapt_sockaddr_for_domain(domain, addr)) {
        Some(SocketAddr::V4(v4)) => {
            out[0..2].copy_from_slice(&(AF_INET as u16).to_ne_bytes());
            out[2..4].copy_from_slice(&v4.port().to_be_bytes());
            out[4..8].copy_from_slice(&v4.ip().octets());
            (out, 16)
        }
        Some(SocketAddr::V6(v6)) => {
            out[0..2].copy_from_slice(&(AF_INET6 as u16).to_ne_bytes());
            out[2..4].copy_from_slice(&v6.port().to_be_bytes());
            out[4..8].copy_from_slice(&v6.flowinfo().to_be_bytes());
            out[8..24].copy_from_slice(&v6.ip().octets());
            out[24..28].copy_from_slice(&v6.scope_id().to_ne_bytes());
            (out, 28)
        }
        None => (out, 0),
    }
}

fn prepare_socket_rw_buffer(
    ctx: &AsyncExecContext,
    segments: Vec<UserIoSegment>,
    total_len: usize,
    to_user: bool,
    force_async: bool,
) -> LinuxResult<PreparedRwBuffer> {
    if total_len == 0 {
        return Ok(PreparedRwBuffer::Empty);
    }
    if !force_async && fits_single_pin_window(&segments) {
        let mut cursor = UserBufferCursor::default();
        let window =
            PinnedUserBuffers::pin_with_aspace(&ctx.aspace, &segments, &mut cursor, to_user)?;
        if let Some(err) = window.terminal_error() {
            return Err(err);
        }
        if window.len() < total_len {
            return Err(LinuxError::EFAULT);
        }
        Ok(PreparedRwBuffer::SingleWindow(Box::new(window)))
    } else {
        Ok(PreparedRwBuffer::MultiWindow {
            segments,
            total_len,
        })
    }
}

fn prepare_segments_from_iovecs(
    ctx: &AsyncExecContext,
    iov_ptr: usize,
    iov_len: usize,
) -> LinuxResult<(Vec<UserIoSegment>, usize)> {
    if iov_len > MAX_IOV_COUNT {
        return Err(LinuxError::EMSGSIZE);
    }
    if iov_len == 0 {
        return Ok((Vec::new(), 0));
    }
    if iov_ptr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let iovecs = ctx.read_array::<iovec>(iov_ptr, iov_len)?;
    let mut segments = Vec::with_capacity(iovecs.len());
    let mut total = 0usize;
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
    Ok((segments, total))
}

pub fn prepare_socket_sqe(
    sqe: &IoUringSqe,
    force_async: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    validate_socket_sqe(sqe)?;
    Ok((
        PreparedRequest::from_normal(sqe, None, None),
        PreparedOpSpec::Socket {
            domain: sqe.fd as u32,
            raw_ty: sqe.off as u32,
            proto: sqe.len,
            force_async,
        },
    ))
}

pub fn prepare_accept_sqe(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
    force_async: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    validate_accept_sqe(sqe)?;
    let outcome = (|| -> LinuxResult<Box<PreparedAcceptData>> {
        let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
        if !entry.object.as_any().is::<Socket>() {
            return Err(LinuxError::ENOTSOCK);
        }
        let addr = sqe.addr as usize;
        let addrlen_ptr = sqe.off as usize;
        let (addr_pin, addrlen_pin, addr_cap) = if addr != 0 {
            if addrlen_ptr == 0 {
                return Err(LinuxError::EFAULT);
            }
            let raw_len: i32 = ctx.read_value(addrlen_ptr)?;
            if raw_len < 0 {
                return Err(LinuxError::EINVAL);
            }
            let addrlen_pin = Some(pin_exact_rw(ctx, addrlen_ptr, 4, true)?);
            let cap = (raw_len as usize).min(MAX_PIN_SOCKADDR_LEN);
            let addr_pin = if cap > 0 {
                Some(pin_exact_rw(ctx, addr, cap, true)?)
            } else {
                None
            };
            (addr_pin, addrlen_pin, cap)
        } else {
            (None, None, 0)
        };
        Ok(Box::new(PreparedAcceptData {
            entry,
            addr_pin,
            addrlen_pin,
            addr_cap,
            accept_flags: sqe.op_flags,
        }))
    })();
    Ok((
        PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
        PreparedOpSpec::Accept {
            outcome,
            force_async,
        },
    ))
}

pub fn prepare_connect_sqe(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
    force_async: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    validate_connect_sqe(sqe)?;
    let outcome = (|| -> LinuxResult<Box<PreparedConnectData>> {
        let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
        if !entry.object.as_any().is::<Socket>() {
            return Err(LinuxError::ENOTSOCK);
        }
        let addrlen = u32::try_from(sqe.off).map_err(|_| LinuxError::EINVAL)?;
        let addr = parse_user_sockaddr(ctx, sqe.addr as usize, addrlen)?;
        Ok(Box::new(PreparedConnectData { entry, addr }))
    })();
    Ok((
        PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
        PreparedOpSpec::Connect {
            outcome,
            force_async,
        },
    ))
}

pub fn prepare_send_recv_sqe(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
    is_send: bool,
    force_async: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    let dest_opt = validate_send_recv_sqe(sqe)?;
    let outcome = (|| -> LinuxResult<(Box<PreparedSocketTransfer>, usize)> {
        let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
        if !entry.object.as_any().is::<Socket>() {
            return Err(LinuxError::ENOTSOCK);
        }
        let dest_addr = if let Some((addr_ptr, addr_len)) = dest_opt {
            Some(parse_user_sockaddr(ctx, addr_ptr as usize, addr_len)?)
        } else {
            None
        };
        let total_len = sqe.len as usize;
        let ptr = sqe.addr as usize;
        if total_len > 0 && (ptr == 0 || !ctx.is_user_range(ptr, total_len)) {
            return Err(LinuxError::EFAULT);
        }
        let mut segments = Vec::new();
        if total_len > 0 {
            segments.push(UserIoSegment::new(ptr, total_len));
        }
        let buffer = prepare_socket_rw_buffer(ctx, segments, total_len, !is_send, force_async)?;
        Ok((
            Box::new(PreparedSocketTransfer {
                entry,
                buffer,
                dest_addr,
                msg_flags: sqe.op_flags,
                pid: ctx.process.pid() as u32,
            }),
            total_len,
        ))
    })();
    let (expected, outcome) = match outcome {
        Ok((data, len)) => (if len > 0 { Some(len) } else { None }, Ok(data)),
        Err(err) => (None, Err(err)),
    };
    Ok((
        PreparedRequest::from_normal(sqe, Some(sqe.fd), expected),
        PreparedOpSpec::SendRecv {
            outcome,
            is_send,
            force_async,
        },
    ))
}

pub fn prepare_sendmsg_recvmsg_sqe(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
    is_send: bool,
    force_async: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    validate_sendmsg_recvmsg_sqe(sqe)?;
    let outcome = (|| -> LinuxResult<(Box<PreparedSocketMsgTransfer>, usize)> {
        let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
        if !entry.object.as_any().is::<Socket>() {
            return Err(LinuxError::ENOTSOCK);
        }
        let msg_ptr = sqe.addr as usize;
        if msg_ptr == 0 {
            return Err(LinuxError::EFAULT);
        }
        let mut initial_hdr: MessageHeader = ctx.read_value(msg_ptr)?;
        if !initial_hdr.msg_name.is_null() && (initial_hdr.msg_namelen as i32) < 0 {
            return Err(LinuxError::EINVAL);
        }
        let iovlen = initial_hdr.msg_iovlen as i32;
        if iovlen < 0 || initial_hdr.msg_iovlen > MAX_IOV_COUNT {
            return Err(LinuxError::EMSGSIZE);
        }

        let (segments, total_len) =
            prepare_segments_from_iovecs(ctx, initial_hdr.msg_iov as usize, initial_hdr.msg_iovlen)?;

        let (dest_addr, name_pin, name_cap) = if is_send {
            let dest = if !initial_hdr.msg_name.is_null() && initial_hdr.msg_namelen != 0 {
                Some(parse_user_sockaddr(
                    ctx,
                    initial_hdr.msg_name as usize,
                    initial_hdr.msg_namelen,
                )?)
            } else {
                None
            };
            (dest, None, 0)
        } else {
            if !initial_hdr.msg_control.is_null() {
                initial_hdr.msg_controllen = 0;
            }
            let cap = if !initial_hdr.msg_name.is_null() {
                (initial_hdr.msg_namelen as usize).min(MAX_PIN_SOCKADDR_LEN)
            } else {
                0
            };
            let pin = if cap > 0 {
                Some(pin_exact_rw(
                    ctx,
                    initial_hdr.msg_name as usize,
                    cap,
                    true,
                )?)
            } else {
                None
            };
            (None, pin, cap)
        };

        let hdr_pin = if is_send {
            None
        } else {
            Some(pin_exact_rw(
                ctx,
                msg_ptr,
                size_of::<MessageHeader>(),
                true,
            )?)
        };
        let buffer = prepare_socket_rw_buffer(ctx, segments, total_len, !is_send, force_async)?;
        Ok((
            Box::new(PreparedSocketMsgTransfer {
                entry,
                buffer,
                hdr_pin,
                initial_hdr: MsgHdrSnapshot::from_header(&initial_hdr),
                name_pin,
                name_cap,
                dest_addr,
                msg_flags: sqe.op_flags,
                pid: ctx.process.pid() as u32,
            }),
            total_len,
        ))
    })();
    let (expected, outcome) = match outcome {
        Ok((data, len)) => (if len > 0 { Some(len) } else { None }, Ok(data)),
        Err(err) => (None, Err(err)),
    };
    Ok((
        PreparedRequest::from_normal(sqe, Some(sqe.fd), expected),
        PreparedOpSpec::SendRecvMsg {
            outcome,
            is_send,
            force_async,
        },
    ))
}

pub fn prepare_shutdown_sqe(
    state: &IoUringState,
    ctx: &AsyncExecContext,
    sqe: &IoUringSqe,
    force_async: bool,
) -> LinuxResult<(PreparedRequest, PreparedOpSpec)> {
    validate_shutdown_sqe(sqe)?;
    let outcome = (|| -> LinuxResult<(FdEntry, u32)> {
        let entry = resolve_sqe_fd_entry(state, ctx, sqe)?;
        if !entry.object.as_any().is::<Socket>() {
            return Err(LinuxError::ENOTSOCK);
        }
        Ok((entry, sqe.len))
    })();
    Ok((
        PreparedRequest::from_normal(sqe, Some(sqe.fd), None),
        PreparedOpSpec::Shutdown {
            outcome,
            force_async,
        },
    ))
}

#[inline]
fn downcast_sock(entry: &FdEntry) -> LinuxResult<&Socket> {
    entry
        .object
        .as_any()
        .downcast_ref::<Socket>()
        .ok_or(LinuxError::ENOTSOCK)
}

#[inline]
fn is_stream_socket(sock: &Socket) -> bool {
    matches!(sock.inner, SocketInner::Tcp(_) | SocketInner::Local(_))
}

fn queue_sigpipe(ctx: &AsyncExecContext) {
    let sig = SIGPIPE as usize;
    if let Some(ref thread) = ctx.thread {
        let _ = queue_signal_to_thread(thread, sig);
    } else {
        let _ = queue_signal_to_process(&ctx.process, sig);
    }
}

async fn run_socket_retry<T, F>(
    entry: &FdEntry,
    ctx: &AsyncExecContext,
    events: IoEvents,
    mut step: F,
) -> LinuxResult<T>
where
    F: FnMut() -> LinuxResult<T>,
{
    let mut regs: Vec<PollRegistration> = Vec::new();
    poll_fn(move |cx| {
        regs.clear();
        match step() {
            Err(LinuxError::EAGAIN) => {}
            other => return Poll::Ready(other),
        }
        if let Err(err) = Arc::clone(&entry.object).register_poll_with_context(
            &ctx.process,
            ctx.thread.as_ref(),
            cx,
            events,
            &mut regs,
        ) {
            return Poll::Ready(Err(err));
        }
        match step() {
            Err(LinuxError::EAGAIN) => Poll::Pending,
            other => {
                regs.clear();
                Poll::Ready(other)
            }
        }
    })
    .await
}

async fn resolve_parsed_addr_async(
    ctx: &AsyncExecContext,
    parsed: &ParsedSocketAddr,
) -> LinuxResult<SocketAddr> {
    match parsed {
        ParsedSocketAddr::Inet(addr) => Ok(*addr),
        ParsedSocketAddr::UnixPath(path) => {
            let key = resolve_unix_path_async(&ctx.fs_context, path).await?;
            let (addr, _) = lookup_unix_socket_by_key(&key)?;
            Ok(addr)
        }
    }
}

fn resolve_parsed_addr_sync(
    ctx: &AsyncExecContext,
    parsed: &ParsedSocketAddr,
) -> LinuxResult<SocketAddr> {
    match parsed {
        ParsedSocketAddr::Inet(addr) => Ok(*addr),
        ParsedSocketAddr::UnixPath(path) => {
            let key = resolve_unix_path_sync(&ctx.fs_context, path)?;
            let (addr, _) = lookup_unix_socket_by_key(&key)?;
            Ok(addr)
        }
    }
}

struct MultiWindowCursor {
    segments: Vec<UserIoSegment>,
    seg_idx: usize,
    seg_off: usize,
    total_remaining: usize,
}

impl MultiWindowCursor {
    fn new(segments: Vec<UserIoSegment>, total_remaining: usize) -> Self {
        Self {
            segments,
            seg_idx: 0,
            seg_off: 0,
            total_remaining,
        }
    }

    fn advance_segments<F>(&mut self, mut len: usize, mut chunk_fn: F) -> LinuxResult<()>
    where
        F: FnMut(usize, usize, usize) -> LinuxResult<()>,
    {
        let mut buf_off = 0usize;
        while len > 0 {
            let seg = self.segments.get(self.seg_idx).ok_or(LinuxError::EFAULT)?;
            let avail = seg.len.saturating_sub(self.seg_off);
            if avail == 0 {
                self.seg_idx += 1;
                self.seg_off = 0;
                continue;
            }
            let take = len.min(avail);
            chunk_fn(seg.addr + self.seg_off, buf_off, take)?;
            self.seg_off += take;
            self.total_remaining -= take;
            buf_off += take;
            len -= take;
        }
        Ok(())
    }

    fn copy_from_user(&mut self, ctx: &AsyncExecContext, dst: &mut [u8]) -> LinuxResult<()> {
        self.advance_segments(dst.len(), |user_addr, buf_off, n| {
            ctx.read_bytes(user_addr, &mut dst[buf_off..buf_off + n])
        })
    }

    fn copy_to_user(&mut self, ctx: &AsyncExecContext, src: &[u8]) -> LinuxResult<()> {
        self.advance_segments(src.len(), |user_addr, buf_off, n| {
            ctx.write_bytes(user_addr, &src[buf_off..buf_off + n])
        })
    }
}

enum BufferCursor {
    Inline(PreparedRwBuffer),
    Multi(MultiWindowCursor),
}

impl BufferCursor {
    fn from_prepared(buf: PreparedRwBuffer) -> Self {
        match buf {
            PreparedRwBuffer::MultiWindow {
                segments,
                total_len,
            } => Self::Multi(MultiWindowCursor::new(segments, total_len)),
            other => Self::Inline(other),
        }
    }

    fn total_remaining(&self) -> usize {
        match self {
            Self::Inline(buf) => buf.remaining_bytes(),
            Self::Multi(multi) => multi.total_remaining,
        }
    }

    fn copy_from_user(&mut self, ctx: &AsyncExecContext, dst: &mut [u8]) -> LinuxResult<()> {
        match self {
            Self::Inline(buf) => buf.copy_from_user_exact(dst),
            Self::Multi(multi) => multi.copy_from_user(ctx, dst),
        }
    }

    fn copy_to_user(&mut self, ctx: &AsyncExecContext, src: &[u8]) -> LinuxResult<()> {
        match self {
            Self::Inline(buf) => buf.copy_to_user_exact(src),
            Self::Multi(multi) => multi.copy_to_user(ctx, src),
        }
    }
}

struct SocketTransferEngine {
    cursor: BufferCursor,
    is_send: bool,
    dontwait: bool,
    waitall: bool,
    msg_flags: u32,
    pid: u32,
    total_done: usize,
    staging: Vec<u8>,
    staged_off: usize,
    staged_len: usize,
    zero_attempted: bool,
    last_src: Option<SocketAddr>,
}

impl SocketTransferEngine {
    fn new(
        buffer: PreparedRwBuffer,
        is_send: bool,
        dontwait: bool,
        msg_flags: u32,
        pid: u32,
    ) -> LinuxResult<Self> {
        let total = buffer.remaining_bytes();
        let waitall = !is_send && (msg_flags & MSG_WAITALL) != 0 && (msg_flags & MSG_PEEK) == 0;
        let cap = total.min(RW_CHUNK_CAP);
        let mut staging = Vec::new();
        if cap > 0 {
            staging.try_reserve_exact(cap).map_err(|_| LinuxError::ENOMEM)?;
            staging.resize(cap, 0);
        }
        Ok(Self {
            cursor: BufferCursor::from_prepared(buffer),
            is_send,
            dontwait,
            waitall,
            msg_flags,
            pid,
            total_done: 0,
            staging,
            staged_off: 0,
            staged_len: 0,
            zero_attempted: false,
            last_src: None,
        })
    }

    fn step(
        &mut self,
        ctx: &AsyncExecContext,
        sock: &Socket,
        dest: Option<SocketAddr>,
    ) -> LinuxResult<(usize, Option<SocketAddr>)> {
        if self.is_send {
            self.step_send(ctx, sock, dest)
        } else {
            self.step_recv(ctx, sock)
        }
    }

    fn step_send(
        &mut self,
        ctx: &AsyncExecContext,
        sock: &Socket,
        dest: Option<SocketAddr>,
    ) -> LinuxResult<(usize, Option<SocketAddr>)> {
        if !self.zero_attempted && self.cursor.total_remaining() == 0 && self.staged_off == self.staged_len
        {
            match sock.try_send_to(&[], dest, self.msg_flags, self.pid) {
                Ok(n) => {
                    self.zero_attempted = true;
                    return Ok((n, None));
                }
                Err(LinuxError::EPIPE) => {
                    if (self.msg_flags & MSG_NOSIGNAL) == 0 {
                        queue_sigpipe(ctx);
                    }
                    return Err(LinuxError::EPIPE);
                }
                Err(LinuxError::EAGAIN) if self.dontwait => return Err(LinuxError::EAGAIN),
                Err(err) => return Err(err),
            }
        }

        if !is_stream_socket(sock) {
            if self.staged_len == 0 && self.cursor.total_remaining() > 0 {
                let total = self.cursor.total_remaining();
                let mut full = Vec::new();
                full.try_reserve_exact(total).map_err(|_| LinuxError::ENOMEM)?;
                full.resize(total, 0);
                self.cursor.copy_from_user(ctx, &mut full)?;
                self.staging = full;
                self.staged_off = 0;
                self.staged_len = total;
            }
            return match sock.try_send_to(
                &self.staging[self.staged_off..self.staged_len],
                dest,
                self.msg_flags,
                self.pid,
            ) {
                Ok(n) => Ok((n, None)),
                Err(LinuxError::EPIPE) => {
                    if (self.msg_flags & MSG_NOSIGNAL) == 0 {
                        queue_sigpipe(ctx);
                    }
                    Err(LinuxError::EPIPE)
                }
                Err(LinuxError::EAGAIN) if self.dontwait => Err(LinuxError::EAGAIN),
                Err(err) => Err(err),
            };
        }

        loop {
            if self.staged_off == self.staged_len {
                let next = self.cursor.total_remaining().min(self.staging.len());
                if next == 0 {
                    return Ok((self.total_done, None));
                }
                self.cursor.copy_from_user(ctx, &mut self.staging[..next])?;
                self.staged_off = 0;
                self.staged_len = next;
            }
            match sock.try_send_to(
                &self.staging[self.staged_off..self.staged_len],
                dest,
                self.msg_flags,
                self.pid,
            ) {
                Ok(0) => return Ok((self.total_done, None)),
                Ok(n) => {
                    self.staged_off += n;
                    self.total_done += n;
                    if self.cursor.total_remaining() == 0 && self.staged_off == self.staged_len {
                        return Ok((self.total_done, None));
                    }
                }
                Err(LinuxError::EAGAIN) => {
                    if self.dontwait {
                        return if self.total_done > 0 {
                            Ok((self.total_done, None))
                        } else {
                            Err(LinuxError::EAGAIN)
                        };
                    }
                    return Err(LinuxError::EAGAIN);
                }
                Err(LinuxError::EPIPE) => {
                    if self.total_done > 0 {
                        return Ok((self.total_done, None));
                    }
                    if (self.msg_flags & MSG_NOSIGNAL) == 0 {
                        queue_sigpipe(ctx);
                    }
                    return Err(LinuxError::EPIPE);
                }
                Err(err) => {
                    return if self.total_done > 0 {
                        Ok((self.total_done, None))
                    } else {
                        Err(err)
                    };
                }
            }
        }
    }

    fn step_recv(
        &mut self,
        ctx: &AsyncExecContext,
        sock: &Socket,
    ) -> LinuxResult<(usize, Option<SocketAddr>)> {
        if is_stream_socket(sock) && self.cursor.total_remaining() == 0 {
            return Ok((0, None));
        }
        if !self.zero_attempted && self.cursor.total_remaining() == 0 {
            return match sock.try_recv_from(&mut [], self.msg_flags) {
                Ok((n, src)) => {
                    self.zero_attempted = true;
                    Ok((n, src))
                }
                Err(LinuxError::EAGAIN) if self.dontwait => Err(LinuxError::EAGAIN),
                Err(err) => Err(err),
            };
        }

        if !is_stream_socket(sock) {
            let want = self.cursor.total_remaining();
            if self.staging.len() < want {
                self.staging.resize(want, 0);
            }
            return match sock.try_recv_from(&mut self.staging[..want], self.msg_flags) {
                Ok((n, src)) => {
                    if n > 0 {
                        self.cursor.copy_to_user(ctx, &self.staging[..n])?;
                    }
                    Ok((n, src))
                }
                Err(LinuxError::EAGAIN) if self.dontwait => Err(LinuxError::EAGAIN),
                Err(err) => Err(err),
            };
        }

        loop {
            let next = self.cursor.total_remaining().min(self.staging.len());
            if next == 0 {
                return Ok((self.total_done, self.last_src));
            }
            match sock.try_recv_from(&mut self.staging[..next], self.msg_flags) {
                Ok((0, src)) => {
                    if self.last_src.is_none() {
                        self.last_src = src;
                    }
                    return Ok((self.total_done, self.last_src));
                }
                Ok((n, src)) => {
                    if self.last_src.is_none() {
                        self.last_src = src;
                    }
                    self.cursor.copy_to_user(ctx, &self.staging[..n])?;
                    self.total_done += n;
                    if !self.waitall || self.cursor.total_remaining() == 0 {
                        return Ok((self.total_done, self.last_src));
                    }
                }
                Err(LinuxError::EAGAIN) => {
                    if self.total_done > 0 && (!self.waitall || self.dontwait) {
                        return Ok((self.total_done, self.last_src));
                    }
                    return Err(LinuxError::EAGAIN);
                }
                Err(err) => {
                    return if self.total_done > 0 {
                        Ok((self.total_done, self.last_src))
                    } else {
                        Err(err)
                    };
                }
            }
        }
    }
}

pub fn execute_socket_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    domain: u32,
    raw_ty: u32,
    proto: u32,
    force_async: bool,
) {
    let run = move |ctx: &AsyncExecContext| -> LinuxResult<i32> {
        let (sock, cloexec, nonblock) = Socket::create(domain, raw_ty, proto)?;
        let mut flags = FdFlags::empty();
        if cloexec {
            flags.insert(FdFlags::CLOEXEC);
        }
        if nonblock {
            flags.insert(FdFlags::NONBLOCK);
        }
        let fd = ctx.insert_fd_entry(FdEntry::new(Arc::new(sock), flags))?;
        Ok(fd as i32)
    };

    if !force_async {
        let code = run(ctx).unwrap_or_else(|e| -e.code());
        let _ = state.complete_request(req_id, code, 0, false);
        return;
    }

    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_wk = Arc::clone(state);
    let ctx_wk = ctx.clone();
    global_worker_pool().submit(state.ring_id(), req_id, move || {
        let _guard: OwnedInflightGuard = guard;
        if !state_wk.is_request_active(req_id) || state_wk.is_dying() {
            return;
        }
        let code = run(&ctx_wk).unwrap_or_else(|e| -e.code());
        state_wk.complete_request(req_id, code, 0, true);
    });
}

fn run_shutdown(entry: &FdEntry, how: u32) -> i32 {
    match downcast_sock(entry).and_then(|sock| sock.shutdown_how(how)) {
        Ok(()) => 0,
        Err(err) => -err.code(),
    }
}

pub fn execute_shutdown_request(
    state: &Arc<IoUringState>,
    req_id: RequestId,
    entry: FdEntry,
    how: u32,
    force_async: bool,
) {
    if !force_async {
        let code = run_shutdown(&entry, how);
        drop(entry);
        let _ = state.complete_request(req_id, code, 0, false);
        return;
    }

    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_wk = Arc::clone(state);
    global_worker_pool().submit(state.ring_id(), req_id, move || {
        let _guard: OwnedInflightGuard = guard;
        if !state_wk.is_request_active(req_id) || state_wk.is_dying() {
            return;
        }
        let code = run_shutdown(&entry, how);
        drop(entry);
        state_wk.complete_request(req_id, code, 0, true);
    });
}

fn complete_accepted_socket(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    parent_domain: u32,
    mut accept_data: Box<PreparedAcceptData>,
    new_sock: Socket,
    from_async: bool,
) {
    if !state.try_begin_completing_request(req_id) {
        drop(new_sock);
        return;
    }
    let remote = new_sock.peer_addr().ok();
    if (accept_data.accept_flags & O_NONBLOCK) != 0 {
        new_sock.set_nonblocking_inner(true);
    }
    let mut new_fd_flags = FdFlags::empty();
    if (accept_data.accept_flags & O_CLOEXEC) != 0 {
        new_fd_flags.insert(FdFlags::CLOEXEC);
    }
    if (accept_data.accept_flags & O_NONBLOCK) != 0 {
        new_fd_flags.insert(FdFlags::NONBLOCK);
    }
    let res = match ctx.insert_fd_entry(FdEntry::new(Arc::new(new_sock), new_fd_flags)) {
        Ok(new_fd) => {
            if let Some(ref mut len_pin) = accept_data.addrlen_pin {
                let (encoded, needed) = encode_sockaddr_bytes(parent_domain, remote);
                let copy_len = accept_data.addr_cap.min(needed);
                if copy_len > 0
                    && let Some(ref mut addr_pin) = accept_data.addr_pin
                {
                    let _ = addr_pin.copy_to_user_exact(&encoded[..copy_len]);
                }
                let needed_u32 = needed as u32;
                let _ = len_pin.copy_to_user_exact(&needed_u32.to_ne_bytes());
            }
            new_fd as i32
        }
        Err(err) => -err.code(),
    };
    drop(accept_data);
    state.finish_completing_request(req_id, res, 0, from_async);
}

pub fn execute_accept_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    data: Box<PreparedAcceptData>,
    force_async: bool,
) {
    let parent_domain = match downcast_sock(&data.entry) {
        Ok(s) => s.domain.load(Ordering::Acquire),
        Err(err) => {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
    };

    if !force_async {
        let sock = downcast_sock(&data.entry).expect("Socket");
        match sock.try_accept() {
            Ok(new_sock) => {
                complete_accepted_socket(state, ctx, req_id, parent_domain, data, new_sock, false);
                return;
            }
            Err(LinuxError::EAGAIN) => {}
            Err(err) => {
                drop(data);
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

    if force_async {
        global_worker_pool().submit(state.ring_id(), req_id, move || {
            let _guard: OwnedInflightGuard = guard;
            if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
                return;
            }
            let res = axtask::future::block_on(run_socket_retry(
                &data.entry,
                &ctx_cloned,
                IoEvents::IN | IoEvents::ERR | IoEvents::HUP,
                || downcast_sock(&data.entry)?.try_accept(),
            ));
            match res {
                Ok(new_sock) => complete_accepted_socket(
                    &state_cloned,
                    &ctx_cloned,
                    req_id,
                    parent_domain,
                    data,
                    new_sock,
                    true,
                ),
                Err(err) => {
                    drop(data);
                    state_cloned.complete_request(req_id, -err.code(), 0, true);
                }
            }
        });
        return;
    }

    let handle = global_executor().spawn_and_poll_once(async move {
        let _guard = guard;
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            return;
        }
        let res = run_socket_retry(
            &data.entry,
            &ctx_cloned,
            IoEvents::IN | IoEvents::ERR | IoEvents::HUP,
            || downcast_sock(&data.entry)?.try_accept(),
        )
        .await;
        match res {
            Ok(new_sock) => complete_accepted_socket(
                &state_cloned,
                &ctx_cloned,
                req_id,
                parent_domain,
                data,
                new_sock,
                true,
            ),
            Err(err) => {
                drop(data);
                state_cloned.complete_request(req_id, -err.code(), 0, true);
            }
        }
    });
    state.install_cancel_handle_or_cancel(req_id, handle);
}

async fn finish_connect_async(
    entry: &FdEntry,
    ctx: &AsyncExecContext,
    addr: &ParsedSocketAddr,
) -> LinuxResult<()> {
    let target = resolve_parsed_addr_async(ctx, addr).await?;
    let sock = downcast_sock(entry)?;
    if sock.try_connect_begin(target)? {
        return Ok(());
    }
    run_socket_retry(
        entry,
        ctx,
        IoEvents::OUT | IoEvents::ERR | IoEvents::HUP,
        || match sock.try_connect_poll()? {
            true => Ok(()),
            false => Err(LinuxError::EAGAIN),
        },
    )
    .await
}

pub fn execute_connect_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    data: Box<PreparedConnectData>,
    force_async: bool,
) {
    if !force_async && !matches!(data.addr, ParsedSocketAddr::UnixPath(_)) {
        let quick = match data.addr {
            ParsedSocketAddr::Inet(target) => downcast_sock(&data.entry)
                .and_then(|sock| sock.try_connect_begin(target)),
            ParsedSocketAddr::UnixPath(_) => unreachable!(),
        };
        match quick {
            Ok(true) => {
                drop(data);
                state.complete_request(req_id, 0, 0, false);
                return;
            }
            Ok(false) => {}
            Err(err) => {
                drop(data);
                state.complete_request(req_id, -err.code(), 0, false);
                return;
            }
        }

        let Some(guard) = state.try_enter_inflight_owned() else {
            return;
        };
        let state_cloned = Arc::clone(state);
        let ctx_cloned = ctx.clone();
        let handle = global_executor().spawn_and_poll_once(async move {
            let _guard = guard;
            if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
                return;
            }
            let res = run_socket_retry(
                &data.entry,
                &ctx_cloned,
                IoEvents::OUT | IoEvents::ERR | IoEvents::HUP,
                || match downcast_sock(&data.entry)?.try_connect_poll()? {
                    true => Ok(()),
                    false => Err(LinuxError::EAGAIN),
                },
            )
            .await;
            drop(data);
            let code = res.map(|()| 0).unwrap_or_else(|e| -e.code());
            state_cloned.complete_request(req_id, code, 0, true);
        });
        state.install_cancel_handle_or_cancel(req_id, handle);
        return;
    }

    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let ctx_cloned = ctx.clone();

    if force_async {
        global_worker_pool().submit(state.ring_id(), req_id, move || {
            let _guard: OwnedInflightGuard = guard;
            if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
                return;
            }
            let res = axtask::future::block_on(finish_connect_async(
                &data.entry,
                &ctx_cloned,
                &data.addr,
            ));
            drop(data);
            let code = res.map(|()| 0).unwrap_or_else(|e| -e.code());
            state_cloned.complete_request(req_id, code, 0, true);
        });
        return;
    }

    let handle = global_executor().spawn_and_poll_once(async move {
        let _guard = guard;
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            return;
        }
        let res = finish_connect_async(&data.entry, &ctx_cloned, &data.addr).await;
        drop(data);
        let code = res.map(|()| 0).unwrap_or_else(|e| -e.code());
        state_cloned.complete_request(req_id, code, 0, true);
    });
    state.install_cancel_handle_or_cancel(req_id, handle);
}

struct RecvMsgWriteback {
    parent_domain: u32,
    initial_hdr: MsgHdrSnapshot,
    hdr_pin: Option<Box<PinnedUserBuffers>>,
    name_pin: Option<Box<PinnedUserBuffers>>,
    name_cap: usize,
}

impl RecvMsgWriteback {
    fn finish(mut self, maybe_src: Option<SocketAddr>) {
        finish_recvmsg_writeback(
            self.parent_domain,
            self.initial_hdr,
            self.hdr_pin.as_deref_mut(),
            self.name_pin.as_deref_mut(),
            self.name_cap,
            maybe_src,
        );
    }
}

fn complete_transfer_result(
    res: LinuxResult<(usize, Option<SocketAddr>)>,
    writeback: Option<RecvMsgWriteback>,
) -> i32 {
    match res {
        Ok((n, src)) => {
            if let Some(wb) = writeback {
                wb.finish(src);
            }
            n as i32
        }
        Err(err) => -err.code(),
    }
}

fn spawn_socket_transfer(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_send: bool,
    dontwait: bool,
    mut engine: SocketTransferEngine,
    dest_opt: Option<ParsedSocketAddr>,
    resolved_dest: Option<SocketAddr>,
    writeback: Option<RecvMsgWriteback>,
    needs_worker: bool,
) {
    let Some(guard) = state.try_enter_inflight_owned() else {
        return;
    };
    let state_cloned = Arc::clone(state);
    let ctx_cloned = ctx.clone();
    let events = if is_send {
        IoEvents::OUT | IoEvents::ERR | IoEvents::HUP
    } else {
        IoEvents::IN | IoEvents::RDHUP | IoEvents::ERR | IoEvents::HUP
    };

    if needs_worker {
        global_worker_pool().submit(state.ring_id(), req_id, move || {
            let _guard: OwnedInflightGuard = guard;
            if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
                return;
            }
            let dest = match dest_opt.as_ref() {
                Some(parsed) => match resolve_parsed_addr_sync(&ctx_cloned, parsed) {
                    Ok(addr) => Some(addr),
                    Err(err) => {
                        state_cloned.complete_request(req_id, -err.code(), 0, true);
                        return;
                    }
                },
                None => resolved_dest,
            };
            let res = if dontwait {
                downcast_sock(&entry).and_then(|sock| engine.step(&ctx_cloned, sock, dest))
            } else {
                axtask::future::block_on(run_socket_retry(&entry, &ctx_cloned, events, || {
                    engine.step(&ctx_cloned, downcast_sock(&entry)?, dest)
                }))
            };
            drop(entry);
            let code = complete_transfer_result(res, writeback);
            state_cloned.complete_request(req_id, code, 0, true);
        });
        return;
    }

    let handle = global_executor().spawn_and_poll_once(async move {
        let _guard = guard;
        if !state_cloned.is_request_active(req_id) || state_cloned.is_dying() {
            return;
        }
        let dest = match dest_opt.as_ref() {
            Some(parsed) => match resolve_parsed_addr_async(&ctx_cloned, parsed).await {
                Ok(addr) => Some(addr),
                Err(err) => {
                    state_cloned.complete_request(req_id, -err.code(), 0, true);
                    return;
                }
            },
            None => resolved_dest,
        };
        let res = if dontwait {
            downcast_sock(&entry).and_then(|sock| engine.step(&ctx_cloned, sock, dest))
        } else {
            run_socket_retry(&entry, &ctx_cloned, events, || {
                engine.step(&ctx_cloned, downcast_sock(&entry)?, dest)
            })
            .await
        };
        drop(entry);
        let code = complete_transfer_result(res, writeback);
        state_cloned.complete_request(req_id, code, 0, true);
    });
    state.install_cancel_handle_or_cancel(req_id, handle);
}

pub fn execute_send_recv_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    data: Box<PreparedSocketTransfer>,
    is_send: bool,
    force_async: bool,
) {
    let PreparedSocketTransfer {
        entry,
        buffer,
        dest_addr,
        msg_flags,
        pid,
    } = *data;
    let dontwait = (msg_flags & MSG_DONTWAIT) != 0;
    let is_multi = matches!(buffer, PreparedRwBuffer::MultiWindow { .. });
    let has_unix_dest = matches!(dest_addr, Some(ParsedSocketAddr::UnixPath(_)));

    let mut engine = match SocketTransferEngine::new(buffer, is_send, dontwait, msg_flags, pid) {
        Ok(e) => e,
        Err(err) => {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
    };

    if !force_async && !is_multi && !has_unix_dest {
        let resolved_dest = dest_addr
            .as_ref()
            .and_then(|p| match p {
                ParsedSocketAddr::Inet(a) => Some(*a),
                _ => None,
            });
        match downcast_sock(&entry).and_then(|sock| engine.step(ctx, sock, resolved_dest)) {
            Ok((n, _)) => {
                drop(entry);
                state.complete_request(req_id, n as i32, 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) if !dontwait => {
                spawn_socket_transfer(
                    state,
                    ctx,
                    req_id,
                    entry,
                    is_send,
                    false,
                    engine,
                    None,
                    resolved_dest,
                    None,
                    false,
                );
                return;
            }
            Err(err) => {
                drop(entry);
                state.complete_request(req_id, -err.code(), 0, false);
                return;
            }
        }
    }

    spawn_socket_transfer(
        state,
        ctx,
        req_id,
        entry,
        is_send,
        dontwait,
        engine,
        dest_addr,
        None,
        None,
        force_async || is_multi,
    );
}

fn finish_recvmsg_writeback(
    parent_domain: u32,
    mut msg_hdr: MsgHdrSnapshot,
    hdr_pin: Option<&mut PinnedUserBuffers>,
    name_pin: Option<&mut PinnedUserBuffers>,
    name_cap: usize,
    maybe_src: Option<SocketAddr>,
) {
    if let Some(src) = maybe_src {
        if msg_hdr.msg_name != 0 {
            let (encoded, needed) = encode_sockaddr_bytes(parent_domain, Some(src));
            let copy_len = name_cap.min(needed);
            if copy_len > 0
                && let Some(np) = name_pin
            {
                let _ = np.copy_to_user_exact(&encoded[..copy_len]);
            }
            msg_hdr.msg_namelen = needed as u32;
        }
    } else if msg_hdr.msg_name != 0 {
        msg_hdr.msg_namelen = 0;
    }
    msg_hdr.msg_flags = 0;
    if let Some(hp) = hdr_pin {
        let abi_hdr = msg_hdr.to_header();
        let encoded_hdr = encode_to_buffer(&abi_hdr);
        let _ = hp.copy_to_user_exact(&encoded_hdr);
    }
}

pub fn execute_sendmsg_recvmsg_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    data: Box<PreparedSocketMsgTransfer>,
    is_send: bool,
    force_async: bool,
) {
    let PreparedSocketMsgTransfer {
        entry,
        buffer,
        hdr_pin,
        initial_hdr,
        name_pin,
        name_cap,
        dest_addr,
        msg_flags,
        pid,
    } = *data;
    let dontwait = (msg_flags & MSG_DONTWAIT) != 0;
    let is_multi = matches!(buffer, PreparedRwBuffer::MultiWindow { .. });
    let has_unix_dest = matches!(dest_addr, Some(ParsedSocketAddr::UnixPath(_)));
    let parent_domain = downcast_sock(&entry)
        .map(|s| s.domain.load(Ordering::Acquire))
        .unwrap_or(0);

    let mut engine = match SocketTransferEngine::new(buffer, is_send, dontwait, msg_flags, pid) {
        Ok(e) => e,
        Err(err) => {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
    };

    let mut writeback = (!is_send).then_some(RecvMsgWriteback {
        parent_domain,
        initial_hdr,
        hdr_pin,
        name_pin,
        name_cap,
    });

    if !force_async && !is_multi && !has_unix_dest {
        let resolved_dest = dest_addr
            .as_ref()
            .and_then(|p| match p {
                ParsedSocketAddr::Inet(a) => Some(*a),
                _ => None,
            });
        match downcast_sock(&entry).and_then(|sock| engine.step(ctx, sock, resolved_dest)) {
            Ok((n, src)) => {
                let code = complete_transfer_result(Ok((n, src)), writeback.take());
                drop(entry);
                state.complete_request(req_id, code, 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) if !dontwait => {}
            Err(err) => {
                drop(entry);
                state.complete_request(req_id, -err.code(), 0, false);
                return;
            }
        }
    }

    spawn_socket_transfer(
        state,
        ctx,
        req_id,
        entry,
        is_send,
        dontwait,
        engine,
        dest_addr,
        None,
        writeback,
        force_async || is_multi,
    );
}

pub fn execute_socket_rw_request(
    state: &Arc<IoUringState>,
    ctx: &AsyncExecContext,
    req_id: RequestId,
    entry: FdEntry,
    is_write: bool,
    buffer: PreparedRwBuffer,
    rw_flags: u32,
    force_async: bool,
) {
    let sock_nonblocking = downcast_sock(&entry)
        .map(Socket::is_nonblocking)
        .unwrap_or(false);
    let dontwait =
        (rw_flags & RWF_NOWAIT) != 0 || entry.flags.contains(FdFlags::NONBLOCK) || sock_nonblocking;
    let is_multi = matches!(buffer, PreparedRwBuffer::MultiWindow { .. });
    let pid = ctx.process.pid() as u32;

    let mut engine = match SocketTransferEngine::new(buffer, is_write, dontwait, 0, pid) {
        Ok(e) => e,
        Err(err) => {
            state.complete_request(req_id, -err.code(), 0, false);
            return;
        }
    };

    if !force_async && !is_multi {
        match downcast_sock(&entry).and_then(|sock| engine.step(ctx, sock, None)) {
            Ok((n, _)) => {
                drop(entry);
                state.complete_request(req_id, n as i32, 0, false);
                return;
            }
            Err(LinuxError::EAGAIN) if !dontwait => {}
            Err(err) => {
                drop(entry);
                state.complete_request(req_id, -err.code(), 0, false);
                return;
            }
        }
    }

    spawn_socket_transfer(
        state,
        ctx,
        req_id,
        entry,
        is_write,
        dontwait,
        engine,
        None,
        None,
        None,
        force_async || is_multi,
    );
}
