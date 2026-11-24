use alloc::vec::Vec;

use axerrno::LinuxError;
use kernel_log::*;
use process::socket::{Socket, SocketInner};
use pulse_user_abi::net::MessageHeader as MsgHdr;

use super::{
    addr::{NetSocketAddr, read_unix_path},
    get_socket,
};
use crate::impls::utils::{read_user_value, write_user_value};

const MMSGHDR_SIZE: usize = core::mem::size_of::<linux_raw_sys::net::mmsghdr>();
const MMSGHDR_MSG_LEN_OFFSET: usize = core::mem::offset_of!(linux_raw_sys::net::mmsghdr, msg_len);
const MAX_MMSG_VLEN: usize = linux_raw_sys::general::UIO_MAXIOV as usize;

fn reserve_additional(buffer: &mut Vec<u8>, additional: usize) -> Result<(), LinuxError> {
    buffer
        .try_reserve(additional)
        .map_err(|_| LinuxError::ENOMEM)
}

fn mmsghdr_addr(msgvec: usize, index: usize) -> Result<usize, LinuxError> {
    let offset = index.checked_mul(MMSGHDR_SIZE).ok_or(LinuxError::EFAULT)?;
    let addr = msgvec.checked_add(offset).ok_or(LinuxError::EFAULT)?;
    addr.checked_add(MMSGHDR_SIZE - 1)
        .ok_or(LinuxError::EFAULT)?;
    Ok(addr)
}

fn read_family(addr: usize, addrlen: u32) -> Result<u16, LinuxError> {
    if addrlen > 128 {
        return Err(LinuxError::EINVAL);
    }
    if addrlen < 2 {
        return Err(LinuxError::EINVAL);
    }
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let family = read_user_value::<u16>(addr)?;
    Ok(family)
}

fn resolve_unix_addr(addr: usize, addrlen: usize) -> Result<core::net::SocketAddr, LinuxError> {
    let path = read_unix_path(addr, addrlen)?;
    let fs =
        crate::impls::utils::with_process(|process| process.fs_context_handle().lock().clone())?;
    let key = process::socket::resolve_unix_path_sync(&fs, &path)?;
    let (target_addr, _) = process::socket::lookup_unix_socket_by_key(&key)?;
    Ok(target_addr)
}

fn send_socket_data(
    socket: &Socket,
    data: &[u8],
    dest_addr: Option<core::net::SocketAddr>,
    flags: usize,
) -> Result<usize, LinuxError> {
    let dont_wait = (flags & (linux_raw_sys::net::MSG_DONTWAIT as usize)) != 0;
    if dont_wait || socket.is_nonblocking() {
        let pid = process::current_process()
            .map(|p| p.pid() as u32)
            .unwrap_or(0);
        return socket.try_send_to(data, dest_addr, flags as u32, pid);
    }

    if socket.tx_shutdown.load(core::sync::atomic::Ordering::Acquire) {
        return Err(LinuxError::EPIPE);
    }
    match &socket.inner {
        SocketInner::Tcp(s) => s.send(data).map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => {
            if (flags & (linux_raw_sys::net::MSG_OOB as usize)) != 0 {
                Err(LinuxError::EOPNOTSUPP)
            } else if data.len() > 65507 {
                Err(LinuxError::EMSGSIZE)
            } else if let Some(daddr) = dest_addr {
                s.send_to(data, daddr)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                s.send(data).map_err(|e| LinuxError::from(e.canonicalize()))
            }
        }
        SocketInner::Icmp(s) => {
            if (flags & (linux_raw_sys::net::MSG_OOB as usize)) != 0 {
                Err(LinuxError::EOPNOTSUPP)
            } else if let Some(destination) = dest_addr {
                s.send_to(data, destination)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                Err(LinuxError::EDESTADDRREQ)
            }
        }
        SocketInner::Local(s) => s.write(data),
        SocketInner::Packet(_) => Ok(data.len()),
        SocketInner::Netlink(s) => s.write(data),
    }
}

fn recv_socket_data(
    socket: &Socket,
    buf: &mut [u8],
    flags: usize,
) -> Result<(usize, Option<core::net::SocketAddr>), LinuxError> {
    let msg_flags = flags as u32;
    let dont_wait = (flags & (linux_raw_sys::net::MSG_DONTWAIT as usize)) != 0;
    let peek = (flags & (linux_raw_sys::net::MSG_PEEK as usize)) != 0;
    if dont_wait || socket.is_nonblocking() {
        return socket.try_recv_from(buf, msg_flags);
    }
    if peek {
        loop {
            match socket.try_recv_from(buf, msg_flags) {
                Err(LinuxError::EAGAIN) => {
                    let _ = process::fd::FdObject::wait_ready(
                        socket,
                        linux_raw_sys::general::POLLIN as i16,
                        None,
                    )?;
                    if process::current_have_signals() {
                        return Err(LinuxError::EINTR);
                    }
                }
                other => return other,
            }
        }
    }
    if socket.rx_shutdown.load(core::sync::atomic::Ordering::Acquire) {
        return Ok((0, None));
    }
    match &socket.inner {
        SocketInner::Tcp(s) => s
            .recv(buf)
            .map(|n| (n, None))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => s
            .recv_from(buf)
            .map(|(n, src)| (n, Some(src)))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Icmp(s) => s
            .recv_from(buf)
            .map(|(n, src)| (n, Some(src)))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Local(s) => s.read(buf).map(|n| (n, None)),
        SocketInner::Packet(_) => Ok((0, None)),
        SocketInner::Netlink(s) => s.read(buf).map(|n| (n, None)),
    }
}

pub fn sys_sendto(
    fd: usize,
    buf: usize,
    len: usize,
    flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    debug!("sys_sendto <= fd: {fd}, len: {len}, flags: {flags}");
    if buf == 0 && len != 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }

    let mut tmp = match crate::impls::utils::alloc_zeroed_bytes(len, "sys_sendto") {
        Ok(b) => b,
        Err(e) => return -(e.code() as isize),
    };
    if len > 0 {
        if let Err(e) = crate::impls::utils::read_user_bytes(buf, &mut tmp) {
            return -(e.code() as isize);
        }
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    // Resolve destination address if provided
    let mut dest_addr = None;
    if addr != 0 && addrlen != 0 {
        let family = match read_family(addr, addrlen as u32) {
            Ok(f) => f as u32,
            Err(e) => return -(e.code() as isize),
        };
        if family == 16 || family == 17 {
            // AF_NETLINK or AF_PACKET, bypass resolution
        } else if family == linux_raw_sys::net::AF_UNIX as u32 {
            match resolve_unix_addr(addr, addrlen) {
                Ok(target_addr) => dest_addr = Some(target_addr),
                Err(e) => return -(e.code() as isize),
            }
        } else {
            match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
                Ok(net_addr) => {
                    let mut std_addr = core::net::SocketAddr::from(net_addr);
                    if let core::net::SocketAddr::V4(v4) = &mut std_addr {
                        if v4.ip().is_unspecified() {
                            *v4 = core::net::SocketAddrV4::new(
                                core::net::Ipv4Addr::new(127, 0, 0, 1),
                                v4.port(),
                            );
                        }
                    } else if let core::net::SocketAddr::V6(v6) = &mut std_addr {
                        if v6.ip().is_unspecified() {
                            *v6 = core::net::SocketAddrV6::new(
                                core::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                                v6.port(),
                                v6.flowinfo(),
                                v6.scope_id(),
                            );
                        }
                    }
                    dest_addr = Some(std_addr);
                }
                Err(e) => return -(e.code() as isize),
            }
        }
    }

    // Handle MSG_MORE (0x8000)
    let msg_more = (flags & 0x8000) != 0;
    if msg_more {
        let mut pending = socket.pending_send.lock();
        if let Err(e) = reserve_additional(&mut pending, tmp.len()) {
            return -(e.code() as isize);
        }
        pending.extend_from_slice(&tmp);
        if let Some(daddr) = dest_addr {
            *socket.pending_addr.lock() = Some(daddr);
        }
        return len as isize;
    }

    let mut combined_data;
    let mut pending = socket.pending_send.lock();
    let pending_len = pending.len();
    let data: &[u8] = if pending.is_empty() {
        &tmp
    } else {
        if let Err(e) = reserve_additional(&mut pending, tmp.len()) {
            return -(e.code() as isize);
        }
        combined_data = core::mem::take(&mut *pending);
        combined_data.extend_from_slice(&tmp);
        &combined_data
    };
    drop(pending);

    let final_dest_addr = dest_addr.or_else(|| socket.pending_addr.lock().take());

    let result = send_socket_data(&socket, data, final_dest_addr, flags);

    match result {
        Ok(n) => {
            if n >= pending_len {
                (n - pending_len) as isize
            } else {
                0
            }
        }
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_recvfrom(
    fd: usize,
    buf: usize,
    len: usize,
    flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    debug!("sys_recvfrom <= fd: {fd}, len: {len}, flags: {flags}");

    if (flags & 1) != 0 {
        // MSG_OOB
        return -(LinuxError::EINVAL.code() as isize);
    }
    if (flags & 8192) != 0 {
        // MSG_ERRQUEUE
        return -(LinuxError::EAGAIN.code() as isize);
    }

    if addr != 0 {
        if addrlen == 0 {
            return -(LinuxError::EINVAL.code() as isize);
        }
        let current_len: i32 = match read_user_value(addrlen) {
            Ok(len) => len,
            Err(e) => return -(e.code() as isize),
        };
        if current_len < 0 {
            return -(LinuxError::EINVAL.code() as isize);
        }
    }

    if buf == 0 && len != 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }

    let mut tmp = match crate::impls::utils::alloc_zeroed_bytes(len, "sys_recvfrom") {
        Ok(b) => b,
        Err(e) => return -(e.code() as isize),
    };

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = recv_socket_data(&socket, &mut tmp, flags);

    match result {
        Ok((n, maybe_src)) => {
            if n > 0 {
                if let Err(e) = crate::impls::utils::write_user_bytes(buf, &tmp[..n]) {
                    return -(e.code() as isize);
                }
            }
            if let Some(src_addr) = maybe_src {
                if addr != 0 {
                    let net_addr = NetSocketAddr::from(src_addr);
                    if addrlen != 0 {
                        if let Ok(current_len) = read_user_value::<u32>(addrlen) {
                            let mut alen = current_len;
                            if net_addr.write_to_raw(addr, &mut alen).is_ok() {
                                let _ = write_user_value(addrlen, &alen);
                            }
                        }
                    }
                }
            } else if let SocketInner::Netlink(_) = &socket.inner {
                if addr != 0 && addrlen != 0 {
                    if let Ok(current_len) = read_user_value::<u32>(addrlen) {
                        let mut nladdr = [0u8; 12];
                        nladdr[0..2].copy_from_slice(&16u16.to_ne_bytes()); // nl_family = 16 (AF_NETLINK)
                        let to_write = core::cmp::min(current_len as usize, 12);
                        if crate::impls::utils::write_user_bytes(addr, &nladdr[..to_write]).is_ok()
                        {
                            let _ = write_user_value(addrlen, &(to_write as u32));
                        }
                    }
                }
            }
            n as isize
        }
        Err(e) => -(e.code() as isize),
    }
}

fn do_sendmsg_core(socket: &Socket, msg: usize, flags: usize) -> Result<usize, LinuxError> {
    if msg == 0 {
        return Err(LinuxError::EFAULT);
    }
    let msg_hdr: MsgHdr = read_user_value(msg)?;

    if !msg_hdr.msg_name.is_null() && (msg_hdr.msg_namelen as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }

    let iovlen = msg_hdr.msg_iovlen as i32;
    if iovlen < 0 || msg_hdr.msg_iovlen > 1024 {
        return Err(LinuxError::EMSGSIZE);
    }

    if !msg_hdr.msg_control.is_null() {
        warn!("sys_sendmsg: ancillary data (cmsg) is not supported, ignoring");
    }

    let iovecs = if msg_hdr.msg_iovlen == 0 {
        Vec::new()
    } else {
        crate::impls::utils::read_user_iovec_array(msg_hdr.msg_iov as usize, msg_hdr.msg_iovlen)?
    };

    // Flatten iov segments without allowing the user supplied lengths to wrap
    // or force an infallible allocation.
    let mut total_len = 0usize;
    for iov in &iovecs {
        let iov_len = usize::try_from(iov.iov_len).map_err(|_| LinuxError::EINVAL)?;
        total_len = total_len.checked_add(iov_len).ok_or(LinuxError::EINVAL)?;
    }
    let mut flat = Vec::new();
    reserve_additional(&mut flat, total_len)?;
    for iov in iovecs {
        let iov_len = match usize::try_from(iov.iov_len) {
            Ok(l) => l,
            Err(_) => return Err(LinuxError::EINVAL),
        };
        if iov_len == 0 {
            continue;
        }
        let mut seg = crate::impls::utils::alloc_zeroed_bytes(iov_len, "sys_sendmsg.seg")?;
        crate::impls::utils::read_user_bytes(iov.iov_base as usize, &mut seg)?;
        flat.extend_from_slice(&seg);
    }

    let dest_addr = msg_hdr.msg_name as usize;
    let dest_addrlen = msg_hdr.msg_namelen;

    // Resolve destination address if provided
    let mut resolved_addr = None;
    if dest_addr != 0 && dest_addrlen != 0 {
        let family = read_family(dest_addr, dest_addrlen)?;
        if family == 16 || family == 17 {
            // AF_NETLINK or AF_PACKET, bypass resolution
        } else if family == linux_raw_sys::net::AF_UNIX as u16 {
            resolved_addr = Some(resolve_unix_addr(dest_addr, dest_addrlen as usize)?);
        } else {
            let net_addr = NetSocketAddr::read_from_raw(dest_addr, dest_addrlen)?;
            let mut std_addr = core::net::SocketAddr::from(net_addr);
            if let core::net::SocketAddr::V4(v4) = &mut std_addr {
                if v4.ip().is_unspecified() {
                    *v4 = core::net::SocketAddrV4::new(
                        core::net::Ipv4Addr::new(127, 0, 0, 1),
                        v4.port(),
                    );
                }
            } else if let core::net::SocketAddr::V6(v6) = &mut std_addr {
                if v6.ip().is_unspecified() {
                    *v6 = core::net::SocketAddrV6::new(
                        core::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                        v6.port(),
                        v6.flowinfo(),
                        v6.scope_id(),
                    );
                }
            }
            resolved_addr = Some(std_addr);
        }
    }

    // Handle MSG_MORE (0x8000)
    let flat_len = flat.len();
    let msg_more = (flags & 0x8000) != 0;
    if msg_more {
        let mut pending = socket.pending_send.lock();
        reserve_additional(&mut pending, flat.len())?;
        pending.extend_from_slice(&flat);
        if let Some(daddr) = resolved_addr {
            *socket.pending_addr.lock() = Some(daddr);
        }
        return Ok(flat_len);
    }

    let mut combined_data;
    {
        let mut pending = socket.pending_send.lock();
        if pending.is_empty() {
            combined_data = flat;
        } else {
            reserve_additional(&mut pending, flat.len())?;
            combined_data = core::mem::take(&mut *pending);
            combined_data.extend_from_slice(&flat);
        }
    }
    let final_dest_addr = resolved_addr.or_else(|| socket.pending_addr.lock().take());

    let result = send_socket_data(socket, &combined_data, final_dest_addr, flags);

    let pending_len = combined_data.len() - flat_len;
    match result {
        Ok(n) => {
            if n >= pending_len {
                Ok(n - pending_len)
            } else {
                Ok(0)
            }
        }
        Err(e) => Err(e),
    }
}

pub fn sys_sendmsg(fd: usize, msg: usize, flags: usize) -> isize {
    debug!("sys_sendmsg <= fd: {fd}, flags: {flags}");

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    match do_sendmsg_core(&socket, msg, flags) {
        Ok(n) => n as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_sendmmsg(fd: usize, msgvec: usize, vlen: usize, flags: usize) -> isize {
    debug!("sys_sendmmsg <= fd: {fd}, msgvec: {msgvec:#x}, vlen: {vlen}, flags: {flags}");

    if vlen == 0 {
        return 0;
    }
    if vlen > MAX_MMSG_VLEN {
        return -(LinuxError::EINVAL.code() as isize);
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let mut sent_count = 0;

    while sent_count < vlen {
        let msg_addr = match mmsghdr_addr(msgvec, sent_count) {
            Ok(addr) => addr,
            Err(e) => {
                return if sent_count > 0 {
                    sent_count as isize
                } else {
                    -(e.code() as isize)
                };
            }
        };

        match do_sendmsg_core(&socket, msg_addr, flags) {
            Ok(bytes_sent) => {
                let msg_len_addr = msg_addr + MMSGHDR_MSG_LEN_OFFSET;
                let bytes_u32 = bytes_sent as u32;
                if let Err(e) = write_user_value(msg_len_addr, &bytes_u32) {
                    if sent_count > 0 {
                        break;
                    } else {
                        return -(e.code() as isize);
                    }
                }
                sent_count += 1;
            }
            Err(e) => {
                if sent_count > 0 {
                    break;
                } else {
                    return -(e.code() as isize);
                }
            }
        }
    }

    sent_count as isize
}

fn do_recvmsg_core(socket: &Socket, msg: usize, flags: usize) -> Result<usize, LinuxError> {
    if (flags & 1) != 0 {
        // MSG_OOB
        return Err(LinuxError::EINVAL);
    }
    if (flags & 8192) != 0 {
        // MSG_ERRQUEUE
        return Err(LinuxError::EAGAIN);
    }

    if msg == 0 {
        return Err(LinuxError::EFAULT);
    }
    let mut msg_hdr: MsgHdr = read_user_value(msg)?;

    if !msg_hdr.msg_name.is_null() && (msg_hdr.msg_namelen as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }

    let iovlen = msg_hdr.msg_iovlen as i32;
    if iovlen < 0 || msg_hdr.msg_iovlen > 1024 {
        return Err(LinuxError::EMSGSIZE);
    }

    if !msg_hdr.msg_control.is_null() {
        warn!("sys_recvmsg: ancillary data output is not supported");
        msg_hdr.msg_controllen = 0;
    }

    let iovecs = if msg_hdr.msg_iovlen == 0 {
        Vec::new()
    } else {
        crate::impls::utils::read_user_iovec_array(msg_hdr.msg_iov as usize, msg_hdr.msg_iovlen)?
    };

    // Compute total capacity.
    let mut total_len: usize = 0;
    for iov in &iovecs {
        let iov_len = match usize::try_from(iov.iov_len) {
            Ok(l) => l,
            Err(_) => return Err(LinuxError::EINVAL),
        };
        total_len = match total_len.checked_add(iov_len) {
            Some(sum) => sum,
            None => return Err(LinuxError::EINVAL),
        };
    }

    let mut flat = crate::impls::utils::alloc_zeroed_bytes(total_len, "sys_recvmsg.flat")?;

    let result = recv_socket_data(socket, &mut flat, flags);

    match result {
        Ok((recv, maybe_src)) => {
            if let Some(src_addr) = maybe_src {
                let name_ptr = msg_hdr.msg_name as usize;
                if name_ptr != 0 {
                    let net_addr = NetSocketAddr::from(src_addr);
                    let mut alen = msg_hdr.msg_namelen;
                    if net_addr.write_to_raw(name_ptr, &mut alen).is_ok() {
                        msg_hdr.msg_namelen = alen;
                    }
                }
            } else if let SocketInner::Netlink(_) = &socket.inner {
                let name_ptr = msg_hdr.msg_name as usize;
                if name_ptr != 0 && msg_hdr.msg_namelen > 0 {
                    let mut nladdr = [0u8; 12];
                    nladdr[0..2].copy_from_slice(&16u16.to_ne_bytes()); // nl_family = 16 (AF_NETLINK)
                    let to_write = core::cmp::min(msg_hdr.msg_namelen as usize, 12);
                    if crate::impls::utils::write_user_bytes(name_ptr, &nladdr[..to_write]).is_ok()
                    {
                        msg_hdr.msg_namelen = to_write as u32;
                    }
                }
            }

            // Scatter received data back into iov buffers.
            let mut written = 0;
            for iov in &iovecs {
                if written >= recv {
                    break;
                }
                let iov_len = match usize::try_from(iov.iov_len) {
                    Ok(l) => l,
                    Err(_) => return Err(LinuxError::EINVAL),
                };
                let seg_len = iov_len.min(recv - written);
                if seg_len > 0 {
                    crate::impls::utils::write_user_bytes(
                        iov.iov_base as usize,
                        &flat[written..written + seg_len],
                    )?;
                    written += seg_len;
                }
            }

            // Write updated msg_hdr back to user space.
            write_user_value(msg, &msg_hdr)?;

            Ok(recv)
        }
        Err(e) => Err(e),
    }
}

pub fn sys_recvmsg(fd: usize, msg: usize, flags: usize) -> isize {
    debug!("sys_recvmsg <= fd: {fd}, flags: {flags}");

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    match do_recvmsg_core(&socket, msg, flags) {
        Ok(n) => n as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_recvmmsg(fd: usize, msgvec: usize, vlen: usize, flags: usize, timeout: usize) -> isize {
    debug!(
        "sys_recvmmsg <= fd: {fd}, msgvec: {msgvec:#x}, vlen: {vlen}, flags: {flags}, timeout: \
         {timeout:#x}"
    );

    if vlen == 0 {
        return 0;
    }
    if vlen > MAX_MMSG_VLEN {
        return -(LinuxError::EINVAL.code() as isize);
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let timeout_val = if timeout != 0 {
        match read_user_value::<linux_raw_sys::general::timespec>(timeout) {
            Ok(ts) => {
                let nsec = ts.tv_nsec as i64;
                if !(0..1_000_000_000).contains(&nsec) || ts.tv_sec < 0 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                Some(core::time::Duration::new(ts.tv_sec as u64, nsec as u32))
            }
            Err(e) => return -(e.code() as isize),
        }
    } else {
        None
    };

    let start_ns = hal::time::monotonic_time_nanos() as u64;
    let timeout_ns = timeout_val.map(|d| d.as_nanos() as u64);

    let originally_nonblocking = socket.is_nonblocking();

    const MSG_WAITFORONE: usize = 0x10000;

    let mut received_count = 0;

    while received_count < vlen {
        let msg_addr = match mmsghdr_addr(msgvec, received_count) {
            Ok(addr) => addr,
            Err(e) => {
                return if received_count > 0 {
                    received_count as isize
                } else {
                    -(e.code() as isize)
                };
            }
        };

        let current_flags = flags | (linux_raw_sys::net::MSG_DONTWAIT as usize);

        match do_recvmsg_core(&socket, msg_addr, current_flags) {
            Ok(bytes_received) => {
                let msg_len_addr = msg_addr + MMSGHDR_MSG_LEN_OFFSET;
                let bytes_u32 = bytes_received as u32;
                if let Err(e) = write_user_value(msg_len_addr, &bytes_u32) {
                    if received_count > 0 {
                        break;
                    } else {
                        return -(e.code() as isize);
                    }
                }
                received_count += 1;
            }
            Err(e) if e == LinuxError::EAGAIN => {
                if received_count > 0 && (flags & MSG_WAITFORONE) != 0 {
                    break;
                }

                if originally_nonblocking || (flags & (linux_raw_sys::net::MSG_DONTWAIT as usize)) != 0 {
                    if received_count > 0 {
                        break;
                    } else {
                        return -(e.code() as isize);
                    }
                }

                if let Some(limit_ns) = timeout_ns {
                    let now_ns = hal::time::monotonic_time_nanos() as u64;
                    if now_ns >= start_ns.saturating_add(limit_ns) {
                        if received_count > 0 {
                            break;
                        } else {
                            return -(LinuxError::EAGAIN.code() as isize);
                        }
                    }
                }

                if process::current_have_signals() {
                    if received_count > 0 {
                        break;
                    } else {
                        return -(LinuxError::EINTR.code() as isize);
                    }
                }

                task::yield_now();
            }
            Err(e) => {
                if received_count > 0 {
                    break;
                } else {
                    return -(e.code() as isize);
                }
            }
        }
    }

    if timeout != 0 {
        if let Some(limit_ns) = timeout_ns {
            let now_ns = hal::time::monotonic_time_nanos() as u64;
            let elapsed_ns = now_ns.saturating_sub(start_ns);
            let remaining_ns = limit_ns.saturating_sub(elapsed_ns);
            let remaining_ts = linux_raw_sys::general::timespec {
                tv_sec: (remaining_ns / 1_000_000_000) as i64,
                tv_nsec: (remaining_ns % 1_000_000_000) as i64,
            };
            let _ = write_user_value(timeout, &remaining_ts);
        }
    }

    received_count as isize
}
