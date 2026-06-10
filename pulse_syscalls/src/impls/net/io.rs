use alloc::vec::Vec;

use axerrno::LinuxError;
use axlog::*;
use linux_raw_sys::general::iovec;

use super::{addr::NetSocketAddr, get_socket};
use crate::net::SocketInner;

fn read_user_plain<T: Copy>(user_addr: usize) -> Result<T, LinuxError> {
    crate::impls::utils::with_process(|process| {
        pulse_core::task::uaccess::read_user_plain(process, user_addr)
    })?
    .map_err(|e| LinuxError::from(e.canonicalize()))
}

fn write_user_plain<T: Copy>(user_addr: usize, value: &T) -> Result<(), LinuxError> {
    crate::impls::utils::with_process(|process| {
        pulse_core::task::uaccess::write_user_plain(process, user_addr, value)
    })?
    .map_err(|e| LinuxError::from(e.canonicalize()))
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
    let family = read_user_plain::<u16>(addr)?;
    Ok(family)
}

fn resolve_unix_addr(addr: usize, addrlen: usize) -> Result<core::net::SocketAddr, LinuxError> {
    let family = read_family(addr, addrlen as u32)?;
    if family != linux_raw_sys::net::AF_UNIX as u16 {
        return Err(LinuxError::EINVAL);
    }
    let path = if addrlen <= 2 {
        alloc::string::String::new()
    } else {
        let first_byte = read_user_plain::<u8>(addr + 2)?;
        if first_byte == 0 {
            let len = (addrlen as usize).saturating_sub(3);
            let mut buf = alloc::vec![0u8; len];
            crate::impls::utils::read_user_bytes(addr + 3, &mut buf)?;
            let name = alloc::string::String::from_utf8_lossy(&buf).into_owned();
            let mut res = alloc::string::String::with_capacity(name.len() + 1);
            res.push('\0');
            res.push_str(&name);
            res
        } else {
            let path_c = crate::impls::utils::read_user_cstring(addr + 2)?;
            path_c.to_str().map(alloc::string::String::from).unwrap_or_else(|_| alloc::string::String::new())
        }
    };
    if path.is_empty() {
        return Err(LinuxError::EINVAL);
    }
    let mut registry = super::socket::UNIX_REGISTRY.lock();
    let target_addr = match registry.get(&path) {
        Some(&(a, ref weak_sock)) => {
            if weak_sock.upgrade().is_some() {
                a
            } else {
                registry.remove(&path);
                return Err(LinuxError::ECONNREFUSED);
            }
        }
        None => {
            return Err(LinuxError::ECONNREFUSED);
        }
    };
    Ok(target_addr)
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

    // Handle MSG_DONTWAIT (0x40)
    let originally_nonblocking = socket.is_nonblocking();
    let dont_wait = (flags & 0x40) != 0;
    struct TemporaryNonblocking<'a> {
        socket: &'a crate::net::Socket,
        originally_nonblocking: bool,
        active: bool,
    }
    impl<'a> Drop for TemporaryNonblocking<'a> {
        fn drop(&mut self) {
            if self.active {
                self.socket.set_nonblocking_inner(self.originally_nonblocking);
            }
        }
    }
    let _guard = TemporaryNonblocking {
        socket: &socket,
        originally_nonblocking,
        active: dont_wait,
    };
    if dont_wait {
        socket.set_nonblocking_inner(true);
    }

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
                            *v4 = core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(127, 0, 0, 1), v4.port());
                        }
                    } else if let core::net::SocketAddr::V6(v6) = &mut std_addr {
                        if v6.ip().is_unspecified() {
                            *v6 = core::net::SocketAddrV6::new(core::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), v6.port(), v6.flowinfo(), v6.scope_id());
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
        socket.pending_send.lock().extend_from_slice(&tmp);
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
        combined_data = core::mem::take(&mut *pending);
        combined_data.extend_from_slice(&tmp);
        &combined_data
    };
    drop(pending);

    let final_dest_addr = dest_addr.or_else(|| socket.pending_addr.lock().take());

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s
            .send(data)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => {
            if (flags & 1) != 0 {
                // MSG_OOB
                Err(LinuxError::EOPNOTSUPP)
            } else if data.len() > 65507 {
                Err(LinuxError::EMSGSIZE)
            } else if let Some(daddr) = final_dest_addr {
                s.send_to(data, daddr)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                s.send(data)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            }
        }
        SocketInner::Local(s) => s.write(data),
        SocketInner::Packet(_) => Ok(data.len()),
        SocketInner::Netlink(s) => s.write(data),
    };

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
        let current_len: i32 = match read_user_plain(addrlen) {
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

    // Handle MSG_DONTWAIT (0x40)
    let originally_nonblocking = socket.is_nonblocking();
    let dont_wait = (flags & 0x40) != 0;
    struct TemporaryNonblocking<'a> {
        socket: &'a crate::net::Socket,
        originally_nonblocking: bool,
        active: bool,
    }
    impl<'a> Drop for TemporaryNonblocking<'a> {
        fn drop(&mut self) {
            if self.active {
                self.socket.set_nonblocking_inner(self.originally_nonblocking);
            }
        }
    }
    let _guard = TemporaryNonblocking {
        socket: &socket,
        originally_nonblocking,
        active: dont_wait,
    };
    if dont_wait {
        socket.set_nonblocking_inner(true);
    }

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s
            .recv(&mut tmp)
            .map(|n| (n, None))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => s
            .recv_from(&mut tmp)
            .map(|(n, src)| (n, Some(src)))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Local(s) => s.read(&mut tmp).map(|n| (n, None)),
        SocketInner::Packet(_) => Ok((0, None)),
        SocketInner::Netlink(s) => s.read(&mut tmp).map(|n| (n, None)),
    };

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
                        if let Ok(current_len) = read_user_plain::<u32>(addrlen) {
                            let mut alen = current_len;
                            if net_addr.write_to_raw(addr, &mut alen).is_ok() {
                                let _ = write_user_plain(addrlen, &alen);
                            }
                        }
                    }
                }
            } else if let SocketInner::Netlink(_) = &socket.inner {
                if addr != 0 && addrlen != 0 {
                    if let Ok(current_len) = read_user_plain::<u32>(addrlen) {
                        let mut nladdr = [0u8; 12];
                        nladdr[0..2].copy_from_slice(&16u16.to_ne_bytes()); // nl_family = 16 (AF_NETLINK)
                        let to_write = core::cmp::min(current_len as usize, 12);
                        if crate::impls::utils::write_user_bytes(addr, &nladdr[..to_write]).is_ok() {
                            let _ = write_user_plain(addrlen, &(to_write as u32));
                        }
                    }
                }
            }
            n as isize
        }
        Err(e) => -(e.code() as isize),
    }
}

/// msghdr structure (simplified, for sendmsg/recvmsg).
#[derive(Copy, Clone)]
#[repr(C)]
struct MsgHdr {
    msg_name: *mut u8,
    msg_namelen: u32,
    msg_iov: *mut iovec,
    msg_iovlen: usize,
    msg_control: *mut u8,
    msg_controllen: usize,
    msg_flags: u32,
}

fn do_sendmsg_core(
    socket: &crate::net::Socket,
    msg: usize,
    flags: usize,
) -> Result<usize, LinuxError> {
    if msg == 0 {
        return Err(LinuxError::EFAULT);
    }
    let msg_hdr: MsgHdr = read_user_plain(msg)?;

    if !msg_hdr.msg_name.is_null() && (msg_hdr.msg_namelen as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }

    let iovlen = msg_hdr.msg_iovlen as i32;
    if iovlen <= 0 || msg_hdr.msg_iovlen > 1024 {
        return Err(LinuxError::EMSGSIZE);
    }

    if !msg_hdr.msg_control.is_null() {
        warn!("sys_sendmsg: ancillary data (cmsg) is not supported, ignoring");
    }

    let iovecs = crate::impls::utils::read_user_iovec_array(msg_hdr.msg_iov as usize, msg_hdr.msg_iovlen)?;

    // Flatten iov segments.
    let mut flat: Vec<u8> = Vec::new();
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
                    *v4 = core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(127, 0, 0, 1), v4.port());
                }
            } else if let core::net::SocketAddr::V6(v6) = &mut std_addr {
                if v6.ip().is_unspecified() {
                    *v6 = core::net::SocketAddrV6::new(core::net::Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), v6.port(), v6.flowinfo(), v6.scope_id());
                }
            }
            resolved_addr = Some(std_addr);
        }
    }

    // Handle MSG_MORE (0x8000)
    let flat_len = flat.len();
    let msg_more = (flags & 0x8000) != 0;
    if msg_more {
        socket.pending_send.lock().extend_from_slice(&flat);
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
            combined_data = core::mem::take(&mut *pending);
            combined_data.extend_from_slice(&flat);
        }
    }
    let final_dest_addr = resolved_addr.or_else(|| socket.pending_addr.lock().take());

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s
            .send(&combined_data)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => {
            if (flags & 1) != 0 {
                // MSG_OOB
                Err(LinuxError::EOPNOTSUPP)
            } else if combined_data.len() > 65507 {
                Err(LinuxError::EMSGSIZE)
            } else if let Some(daddr) = final_dest_addr {
                s.send_to(&combined_data, daddr)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                s.send(&combined_data)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            }
        }
        SocketInner::Local(s) => s.write(&combined_data),
        SocketInner::Packet(_) => Ok(combined_data.len()),
        SocketInner::Netlink(s) => s.write(&combined_data),
    };

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

    // Handle MSG_DONTWAIT (0x40)
    let originally_nonblocking = socket.is_nonblocking();
    let dont_wait = (flags & 0x40) != 0;
    struct TemporaryNonblocking<'a> {
        socket: &'a crate::net::Socket,
        originally_nonblocking: bool,
        active: bool,
    }
    impl<'a> Drop for TemporaryNonblocking<'a> {
        fn drop(&mut self) {
            if self.active {
                self.socket.set_nonblocking_inner(self.originally_nonblocking);
            }
        }
    }
    let _guard = TemporaryNonblocking {
        socket: &socket,
        originally_nonblocking,
        active: dont_wait,
    };
    if dont_wait {
        socket.set_nonblocking_inner(true);
    }

    match do_sendmsg_core(&socket, msg, flags) {
        Ok(n) => n as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_sendmmsg(
    fd: usize,
    msgvec: usize,
    vlen: usize,
    flags: usize,
) -> isize {
    debug!("sys_sendmmsg <= fd: {fd}, msgvec: {msgvec:#x}, vlen: {vlen}, flags: {flags}");

    if vlen == 0 {
        return 0;
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let mut sent_count = 0;

    while sent_count < vlen {
        let msg_addr = msgvec + sent_count * 64; // sizeof(MMsgHdr) = 64

        match do_sendmsg_core(&socket, msg_addr, flags) {
            Ok(bytes_sent) => {
                let msg_len_addr = msg_addr + 56; // offset of msg_len = 56
                let bytes_u32 = bytes_sent as u32;
                if let Err(e) = write_user_plain(msg_len_addr, &bytes_u32) {
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

fn do_recvmsg_core(socket: &crate::net::Socket, msg: usize, flags: usize) -> Result<usize, LinuxError> {
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
    let mut msg_hdr: MsgHdr = read_user_plain(msg)?;

    if !msg_hdr.msg_name.is_null() && (msg_hdr.msg_namelen as i32) < 0 {
        return Err(LinuxError::EINVAL);
    }

    let iovlen = msg_hdr.msg_iovlen as i32;
    if iovlen <= 0 || msg_hdr.msg_iovlen > 1024 {
        return Err(LinuxError::EMSGSIZE);
    }

    if !msg_hdr.msg_control.is_null() {
        warn!("sys_recvmsg: ancillary data output is not supported");
        msg_hdr.msg_controllen = 0;
    }

    let iovecs = crate::impls::utils::read_user_iovec_array(msg_hdr.msg_iov as usize, msg_hdr.msg_iovlen)?;

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

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s
            .recv(&mut flat)
            .map(|n| (n, None))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => s
            .recv_from(&mut flat)
            .map(|(n, src)| (n, Some(src)))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Local(s) => s.read(&mut flat).map(|n| (n, None)),
        SocketInner::Packet(_) => Ok((0, None)),
        SocketInner::Netlink(s) => s.read(&mut flat).map(|n| (n, None)),
    };

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
                    if crate::impls::utils::write_user_bytes(name_ptr, &nladdr[..to_write]).is_ok() {
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
            write_user_plain(msg, &msg_hdr)?;

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

    // Handle MSG_DONTWAIT (0x40)
    let originally_nonblocking = socket.is_nonblocking();
    let dont_wait = (flags & 0x40) != 0;
    struct TemporaryNonblocking<'a> {
        socket: &'a crate::net::Socket,
        originally_nonblocking: bool,
        active: bool,
    }
    impl<'a> Drop for TemporaryNonblocking<'a> {
        fn drop(&mut self) {
            if self.active {
                self.socket.set_nonblocking_inner(self.originally_nonblocking);
            }
        }
    }
    let _guard = TemporaryNonblocking {
        socket: &socket,
        originally_nonblocking,
        active: dont_wait,
    };
    if dont_wait {
        socket.set_nonblocking_inner(true);
    }

    match do_recvmsg_core(&socket, msg, flags) {
        Ok(n) => n as isize,
        Err(e) => -(e.code() as isize),
    }
}

#[allow(dead_code)]
#[derive(Copy, Clone)]
#[repr(C)]
struct MMsgHdr {
    msg_hdr: MsgHdr,
    msg_len: u32,
    _pad: u32,
}

pub fn sys_recvmmsg(
    fd: usize,
    msgvec: usize,
    vlen: usize,
    flags: usize,
    timeout: usize,
) -> isize {
    debug!("sys_recvmmsg <= fd: {fd}, msgvec: {msgvec:#x}, vlen: {vlen}, flags: {flags}, timeout: {timeout:#x}");

    if vlen == 0 {
        return 0;
    }

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let timeout_val = if timeout != 0 {
        match read_user_plain::<linux_raw_sys::general::timespec>(timeout) {
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

    let start_ns = axhal::time::monotonic_time_nanos() as u64;
    let timeout_ns = timeout_val.map(|d| d.as_nanos() as u64);

    let originally_nonblocking = socket.is_nonblocking();

    struct TemporaryNonblocking<'a> {
        socket: &'a crate::net::Socket,
        originally_nonblocking: bool,
    }

    impl<'a> Drop for TemporaryNonblocking<'a> {
        fn drop(&mut self) {
            self.socket.set_nonblocking_inner(self.originally_nonblocking);
        }
    }

    let _guard = TemporaryNonblocking {
        socket: &socket,
        originally_nonblocking,
    };

    // Temporarily set socket to nonblocking so that we handle yield/timeouts here at syscall level.
    socket.set_nonblocking_inner(true);

    const MSG_DONTWAIT: usize = 0x40;
    const MSG_WAITFORONE: usize = 0x10000;

    let mut received_count = 0;

    while received_count < vlen {
        let msg_addr = msgvec + received_count * 64; // sizeof(MMsgHdr) = 64

        let current_flags = if received_count > 0 && (flags & MSG_WAITFORONE) != 0 {
            flags | MSG_DONTWAIT
        } else {
            flags
        };

        match do_recvmsg_core(&socket, msg_addr, current_flags) {
            Ok(bytes_received) => {
                let msg_len_addr = msg_addr + 56; // offset of msg_len = 56
                let bytes_u32 = bytes_received as u32;
                if let Err(e) = write_user_plain(msg_len_addr, &bytes_u32) {
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

                if originally_nonblocking || (flags & MSG_DONTWAIT) != 0 {
                    if received_count > 0 {
                        break;
                    } else {
                        return -(e.code() as isize);
                    }
                }

                if let Some(limit_ns) = timeout_ns {
                    let now_ns = axhal::time::monotonic_time_nanos() as u64;
                    if now_ns >= start_ns.saturating_add(limit_ns) {
                        if received_count > 0 {
                            break;
                        } else {
                            return -(LinuxError::EAGAIN.code() as isize);
                        }
                    }
                }

                if pulse_core::task::current_have_signals() {
                    if received_count > 0 {
                        break;
                    } else {
                        return -(LinuxError::EINTR.code() as isize);
                    }
                }

                axtask::yield_now();
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
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            let elapsed_ns = now_ns.saturating_sub(start_ns);
            let remaining_ns = limit_ns.saturating_sub(elapsed_ns);
            let remaining_ts = linux_raw_sys::general::timespec {
                tv_sec: (remaining_ns / 1_000_000_000) as i64,
                tv_nsec: (remaining_ns % 1_000_000_000) as i64,
            };
            let _ = write_user_plain(timeout, &remaining_ts);
        }
    }

    received_count as isize
}
