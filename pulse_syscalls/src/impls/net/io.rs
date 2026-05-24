use alloc::vec::Vec;

use axerrno::LinuxError;
use axlog::*;
use pulse_core::task::with_current_process;

use super::addr::NetSocketAddr;
use crate::net::Socket;

/// Helper: get a socket from fd.
fn get_socket(fd: usize) -> Result<alloc::sync::Arc<Socket>, LinuxError> {
    let entry = with_current_process(|p| p.fd_table.lock().get_entry_cloned(fd))??;
    Socket::from_fd_entry(&entry.object)
}

/// iovec structure (POSIX).
#[repr(C)]
struct IoVec {
    iov_base: *mut u8,
    iov_len: usize,
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

    let slice = unsafe { core::slice::from_raw_parts(buf as *const u8, len) };

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = match &*socket {
        Socket::Tcp(s) => s
            .send(slice)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        Socket::Udp(s) => {
            if addr == 0 || addrlen == 0 {
                s.send(slice)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            } else {
                match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
                    Ok(net_addr) => {
                        let std_addr = core::net::SocketAddr::from(net_addr);
                        s.send_to(slice, std_addr)
                            .map_err(|e| LinuxError::from(e.canonicalize()))
                    }
                    Err(e) => Err(e),
                }
            }
        }
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

    let buf_slice = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = match &*socket {
        Socket::Tcp(s) => s
            .recv(buf_slice)
            .map(|n| (n, None))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        Socket::Udp(s) => s
            .recv_from(buf_slice)
            .map(|(n, src)| (n, Some(src)))
            .map_err(|e| LinuxError::from(e.canonicalize())),
    };

    match result {
        Ok((n, maybe_src)) => {
            if let Some(src_addr) = maybe_src {
                if addr != 0 {
                    let net_addr = NetSocketAddr::from(src_addr);
                    let addrlen_ptr = addrlen as *mut u32;
                    if !addrlen_ptr.is_null() {
                        let mut alen = unsafe { addrlen_ptr.read() };
                        if net_addr.write_to_raw(addr, &mut alen).is_ok() {
                            unsafe { addrlen_ptr.write(alen) };
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
#[repr(C)]
struct MsgHdr {
    msg_name: *mut u8,
    msg_namelen: u32,
    msg_iov: *mut IoVec,
    msg_iovlen: usize,
    msg_control: *mut u8,
    msg_controllen: usize,
    msg_flags: u32,
}

pub fn sys_sendmsg(fd: usize, msg: usize, _flags: usize) -> isize {
    if msg == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let msg = unsafe { &*(msg as *const MsgHdr) };

    if !msg.msg_control.is_null() {
        warn!("sys_sendmsg: ancillary data (cmsg) is not supported, ignoring");
    }

    // Flatten iov segments.
    let mut flat: Vec<u8> = Vec::new();
    let iov_count = msg.msg_iovlen;
    for i in 0..iov_count {
        let iov = unsafe { &*msg.msg_iov.add(i) };
        if iov.iov_len == 0 {
            continue;
        }
        let seg = unsafe { core::slice::from_raw_parts(iov.iov_base as *const u8, iov.iov_len) };
        flat.extend_from_slice(seg);
    }

    let dest_addr = msg.msg_name as usize;
    let dest_addrlen = msg.msg_namelen;

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = match &*socket {
        Socket::Tcp(s) => s
            .send(&flat)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        Socket::Udp(s) => {
            if dest_addr == 0 || dest_addrlen == 0 {
                s.send(&flat)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
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
    let msg = unsafe { &mut *(msg as *mut MsgHdr) };

    if !msg.msg_control.is_null() {
        warn!("sys_recvmsg: ancillary data output is not supported");
        msg.msg_controllen = 0;
    }

    // Compute total capacity.
    let iov_count = msg.msg_iovlen;
    let total_len: usize = (0..iov_count)
        .map(|i| unsafe { (*msg.msg_iov.add(i)).iov_len })
        .sum();

    let mut flat = alloc::vec![0u8; total_len];

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = match &*socket {
        Socket::Tcp(s) => s
            .recv(&mut flat)
            .map(|n| (n, None))
            .map_err(|e| LinuxError::from(e.canonicalize())),
        Socket::Udp(s) => s
            .recv_from(&mut flat)
            .map(|(n, src)| (n, Some(src)))
            .map_err(|e| LinuxError::from(e.canonicalize())),
    };

    match result {
        Ok((recv, maybe_src)) => {
            if let Some(src_addr) = maybe_src {
                let name_ptr = msg.msg_name as usize;
                if name_ptr != 0 {
                    let net_addr = NetSocketAddr::from(src_addr);
                    let mut alen = msg.msg_namelen;
                    if net_addr.write_to_raw(name_ptr, &mut alen).is_ok() {
                        msg.msg_namelen = alen;
                    }
                }
            }

            // Scatter received data back into iov buffers.
            let mut written = 0;
            for i in 0..iov_count {
                if written >= recv {
                    break;
                }
                let iov = unsafe { &*msg.msg_iov.add(i) };
                let seg_len = iov.iov_len.min(recv - written);
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        flat.as_ptr().add(written),
                        iov.iov_base,
                        seg_len,
                    );
                }
                written += seg_len;
            }

            recv as isize
        }
        Err(e) => -(e.code() as isize),
    }
}
