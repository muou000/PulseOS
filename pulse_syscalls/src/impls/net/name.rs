use axerrno::LinuxError;
use axlog::*;

use super::{addr::NetSocketAddr, get_socket};

pub fn sys_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    debug!("sys_getsockname <= fd: {fd}, addr: {local_addr:?}");

    let net_addr = NetSocketAddr::from(local_addr);
    let addrlen_ptr = addrlen as *mut u32;
    if addrlen_ptr.is_null() {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut alen = unsafe { addrlen_ptr.read() };
    match net_addr.write_to_raw(addr, &mut alen) {
        Ok(()) => {
            unsafe { addrlen_ptr.write(alen) };
            0
        }
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    let peer_addr = match socket.peer_addr() {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    debug!("sys_getpeername <= fd: {fd}, addr: {peer_addr:?}");

    let net_addr = NetSocketAddr::from(peer_addr);
    let addrlen_ptr = addrlen as *mut u32;
    if addrlen_ptr.is_null() {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut alen = unsafe { addrlen_ptr.read() };
    match net_addr.write_to_raw(addr, &mut alen) {
        Ok(()) => {
            unsafe { addrlen_ptr.write(alen) };
            0
        }
        Err(e) => -(e.code() as isize),
    }
}
