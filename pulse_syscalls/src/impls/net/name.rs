use core::sync::atomic::Ordering;
use axerrno::LinuxError;
use axlog::*;

use super::{addr::{NetSocketAddr, write_unix_addr}, get_socket};
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

pub fn sys_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    
    if socket.domain.load(Ordering::Acquire) == linux_raw_sys::net::AF_UNIX {
        if let SocketInner::Local(_) = &socket.inner {
            match write_unix_addr(None, addr, addrlen) {
                Ok(()) => return 0,
                Err(e) => return -(e.code() as isize),
            }
        }
        let path = {
            let registry = crate::impls::net::UNIX_REGISTRY.lock();
            registry.iter().find_map(|(k, v)| {
                if let Some(s) = v.1.upgrade() {
                    if alloc::sync::Arc::ptr_eq(&s, &socket) {
                        return Some(k.clone());
                    }
                }
                None
            })
        };
        match write_unix_addr(path, addr, addrlen) {
            Ok(()) => return 0,
            Err(e) => return -(e.code() as isize),
        }
    }

    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    debug!("sys_getsockname <= fd: {fd}, addr: {local_addr:?}");

    let net_addr = NetSocketAddr::from(local_addr);
    if addrlen == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut alen: u32 = match read_user_plain(addrlen) {
        Ok(l) => l,
        Err(e) => return -(e.code() as isize),
    };
    match net_addr.write_to_raw(addr, &mut alen) {
        Ok(()) => {
            if let Err(e) = write_user_plain(addrlen, &alen) {
                -(e.code() as isize)
            } else {
                0
            }
        }
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_getpeername(fd: usize, addr: usize, addrlen: usize) -> isize {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    
    if socket.domain.load(Ordering::Acquire) == linux_raw_sys::net::AF_UNIX {
        if let SocketInner::Local(_) = &socket.inner {
            match write_unix_addr(None, addr, addrlen) {
                Ok(()) => return 0,
                Err(e) => return -(e.code() as isize),
            }
        }
        let peer_addr = match socket.peer_addr() {
            Ok(a) => a,
            Err(e) => return -(e.code() as isize),
        };
        let path = {
            let registry = crate::impls::net::UNIX_REGISTRY.lock();
            registry.iter().find_map(|(k, v)| {
                if v.0 == peer_addr {
                    Some(k.clone())
                } else {
                    None
                }
            })
        };
        match write_unix_addr(path, addr, addrlen) {
            Ok(()) => return 0,
            Err(e) => return -(e.code() as isize),
        }
    }

    let peer_addr = match socket.peer_addr() {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    debug!("sys_getpeername <= fd: {fd}, addr: {peer_addr:?}");

    let net_addr = NetSocketAddr::from(peer_addr);
    if addrlen == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut alen: u32 = match read_user_plain(addrlen) {
        Ok(l) => l,
        Err(e) => return -(e.code() as isize),
    };
    match net_addr.write_to_raw(addr, &mut alen) {
        Ok(()) => {
            if let Err(e) = write_user_plain(addrlen, &alen) {
                -(e.code() as isize)
            } else {
                0
            }
        }
        Err(e) => -(e.code() as isize),
    }
}
