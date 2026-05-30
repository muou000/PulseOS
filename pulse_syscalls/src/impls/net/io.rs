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
            alloc::format!("\0{}", name)
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
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    debug!("sys_sendto <= fd: {fd}, len: {len}");
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

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s
            .send(&tmp)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => {
            if addr == 0 || addrlen == 0 {
                s.send(&tmp)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                let family = match read_family(addr, addrlen as u32) {
                    Ok(f) => f as u32,
                    Err(e) => return -(e.code() as isize),
                };
                if family == linux_raw_sys::net::AF_UNIX as u32 {
                    match resolve_unix_addr(addr, addrlen) {
                        Ok(target_addr) => s.send_to(&tmp, target_addr)
                            .map_err(|e| LinuxError::from(e.canonicalize())),
                        Err(e) => Err(e),
                    }
                } else {
                    match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
                        Ok(net_addr) => {
                            let std_addr = core::net::SocketAddr::from(net_addr);
                            s.send_to(&tmp, std_addr)
                                .map_err(|e| LinuxError::from(e.canonicalize()))
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
        SocketInner::Local(s) => s.write(&tmp),
        SocketInner::Packet => Ok(tmp.len()),
    };

    match result {
        Ok(n) => n as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_recvfrom(
    fd: usize,
    buf: usize,
    len: usize,
    _flags: usize,
    addr: usize,
    addrlen: usize,
) -> isize {
    debug!("sys_recvfrom <= fd: {fd}, len: {len}");
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
        SocketInner::Packet => Ok((0, None)),
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

pub fn sys_sendmsg(fd: usize, msg: usize, _flags: usize) -> isize {
    if msg == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let msg_hdr: MsgHdr = match read_user_plain(msg) {
        Ok(m) => m,
        Err(e) => return -(e.code() as isize),
    };

    if !msg_hdr.msg_control.is_null() {
        warn!("sys_sendmsg: ancillary data (cmsg) is not supported, ignoring");
    }

    let iovecs = match crate::impls::utils::read_user_iovec_array(msg_hdr.msg_iov as usize, msg_hdr.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return -(e.code() as isize),
    };

    // Flatten iov segments.
    let mut flat: Vec<u8> = Vec::new();
    for iov in iovecs {
        let iov_len = match usize::try_from(iov.iov_len) {
            Ok(l) => l,
            Err(_) => return -(LinuxError::EINVAL.code() as isize),
        };
        if iov_len == 0 {
            continue;
        }
        let mut seg = match crate::impls::utils::alloc_zeroed_bytes(iov_len, "sys_sendmsg.seg") {
            Ok(buf) => buf,
            Err(e) => return -(e.code() as isize),
        };
        if let Err(e) = crate::impls::utils::read_user_bytes(iov.iov_base as usize, &mut seg) {
            return -(e.code() as isize);
        }
        flat.extend_from_slice(&seg);
    }

    let dest_addr = msg_hdr.msg_name as usize;
    let dest_addrlen = msg_hdr.msg_namelen;

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s
            .send(&flat)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Udp(s) => {
            if dest_addr == 0 || dest_addrlen == 0 {
                s.send(&flat)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                let family = match read_family(dest_addr, dest_addrlen) {
                    Ok(f) => f as u32,
                    Err(e) => return -(e.code() as isize),
                };
                if family == linux_raw_sys::net::AF_UNIX as u32 {
                    match resolve_unix_addr(dest_addr, dest_addrlen as usize) {
                        Ok(target_addr) => s.send_to(&flat, target_addr)
                            .map_err(|e| LinuxError::from(e.canonicalize())),
                        Err(e) => Err(e),
                    }
                } else {
                    match NetSocketAddr::read_from_raw(dest_addr, dest_addrlen) {
                        Ok(net_addr) => {
                            let std_addr = core::net::SocketAddr::from(net_addr);
                            s.send_to(&flat, std_addr)
                                .map_err(|e| LinuxError::from(e.canonicalize()))
                        }
                        Err(e) => Err(e),
                    }
                }
            }
        }
        SocketInner::Local(s) => s.write(&flat),
        SocketInner::Packet => Ok(flat.len()),
    };

    match result {
        Ok(n) => n as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_recvmsg(fd: usize, msg: usize, _flags: usize) -> isize {
    if msg == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut msg_hdr: MsgHdr = match read_user_plain(msg) {
        Ok(m) => m,
        Err(e) => return -(e.code() as isize),
    };

    if !msg_hdr.msg_control.is_null() {
        warn!("sys_recvmsg: ancillary data output is not supported");
        msg_hdr.msg_controllen = 0;
    }

    let iovecs = match crate::impls::utils::read_user_iovec_array(msg_hdr.msg_iov as usize, msg_hdr.msg_iovlen) {
        Ok(v) => v,
        Err(e) => return -(e.code() as isize),
    };

    // Compute total capacity.
    let mut total_len: usize = 0;
    for iov in &iovecs {
        let iov_len = match usize::try_from(iov.iov_len) {
            Ok(l) => l,
            Err(_) => return -(LinuxError::EINVAL.code() as isize),
        };
        total_len = match total_len.checked_add(iov_len) {
            Some(sum) => sum,
            None => return -(LinuxError::EINVAL.code() as isize),
        };
    }

    let mut flat = match crate::impls::utils::alloc_zeroed_bytes(total_len, "sys_recvmsg.flat") {
        Ok(buf) => buf,
        Err(e) => return -(e.code() as isize),
    };

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

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
        SocketInner::Packet => Ok((0, None)),
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
            }

            // Scatter received data back into iov buffers.
            let mut written = 0;
            for iov in &iovecs {
                if written >= recv {
                    break;
                }
                let iov_len = match usize::try_from(iov.iov_len) {
                    Ok(l) => l,
                    Err(_) => return -(LinuxError::EINVAL.code() as isize),
                };
                let seg_len = iov_len.min(recv - written);
                if seg_len > 0 {
                    if let Err(e) = crate::impls::utils::write_user_bytes(
                        iov.iov_base as usize,
                        &flat[written..written + seg_len],
                    ) {
                        return -(e.code() as isize);
                    }
                    written += seg_len;
                }
            }

            // Write updated msg_hdr back to user space.
            if let Err(e) = write_user_plain(msg, &msg_hdr) {
                return -(e.code() as isize);
            }

            recv as isize
        }
        Err(e) => -(e.code() as isize),
    }
}
