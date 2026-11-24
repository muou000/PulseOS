use core::sync::atomic::Ordering;
use axerrno::LinuxError;
use kernel_log::*;

use super::{addr::{NetSocketAddr, write_unix_addr}, get_socket};
use process::socket::{SocketInner, adapt_sockaddr_for_domain};

use crate::impls::utils::{read_user_value, write_user_value};

pub fn sys_getsockname(fd: usize, addr: usize, addrlen: usize) -> isize {
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    
    let domain = socket.domain.load(Ordering::Acquire);
    if domain == linux_raw_sys::net::AF_UNIX {
        if let SocketInner::Local(_) = &socket.inner {
            match write_unix_addr(None, addr, addrlen) {
                Ok(()) => return 0,
                Err(e) => return -(e.code() as isize),
            }
        }
        let path = process::socket::lookup_unix_path_by_socket(&socket);
        match write_unix_addr(path, addr, addrlen) {
            Ok(()) => return 0,
            Err(e) => return -(e.code() as isize),
        }
    } else if domain == 16 { // AF_NETLINK
        if addrlen == 0 {
            return -(LinuxError::EFAULT.code() as isize);
        }
        let alen: u32 = match read_user_value(addrlen) {
            Ok(l) => l,
            Err(e) => return -(e.code() as isize),
        };
        let mut nladdr = [0u8; 12]; // sockaddr_nl is 12 bytes
        nladdr[0..2].copy_from_slice(&16u16.to_ne_bytes()); // nl_family = 16 (AF_NETLINK)
        let pid = process::current_process().map(|p| p.pid() as u32).unwrap_or(0);
        nladdr[4..8].copy_from_slice(&pid.to_ne_bytes());
        
        let to_write = core::cmp::min(alen as usize, 12);
        if let Err(e) = crate::impls::utils::write_user_bytes(addr, &nladdr[..to_write]) {
            return -(e.code() as isize);
        }
        if let Err(e) = write_user_value(addrlen, &(to_write as u32)) {
            return -(e.code() as isize);
        }
        return 0;
    }

    let local_addr = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => {
            if matches!(socket.inner, SocketInner::Udp(_)) && e == LinuxError::ENOTCONN {
                let domain = socket.domain.load(Ordering::Acquire);
                if domain == 10 { // AF_INET6
                    core::net::SocketAddr::V6(core::net::SocketAddrV6::new(core::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                } else {
                    core::net::SocketAddr::V4(core::net::SocketAddrV4::new(core::net::Ipv4Addr::UNSPECIFIED, 0))
                }
            } else {
                return -(e.code() as isize);
            }
        }
    };
    let local_addr = adapt_sockaddr_for_domain(domain, local_addr);
    debug!("sys_getsockname <= fd: {fd}, addr: {local_addr:?}");

    let net_addr = NetSocketAddr::from(local_addr);
    if addrlen == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut alen: u32 = match read_user_value(addrlen) {
        Ok(l) => l,
        Err(e) => return -(e.code() as isize),
    };
    match net_addr.write_to_raw(addr, &mut alen) {
        Ok(()) => {
            if let Err(e) = write_user_value(addrlen, &alen) {
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
    
    let domain = socket.domain.load(Ordering::Acquire);
    if domain == linux_raw_sys::net::AF_UNIX {
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
        let path = process::socket::lookup_unix_path_by_addr(peer_addr);
        match write_unix_addr(path, addr, addrlen) {
            Ok(()) => return 0,
            Err(e) => return -(e.code() as isize),
        }
    } else if domain == 16 { // AF_NETLINK
        if addrlen == 0 {
            return -(LinuxError::EFAULT.code() as isize);
        }
        let alen: u32 = match read_user_value(addrlen) {
            Ok(l) => l,
            Err(e) => return -(e.code() as isize),
        };
        let mut nladdr = [0u8; 12]; // sockaddr_nl is 12 bytes
        nladdr[0..2].copy_from_slice(&16u16.to_ne_bytes()); // nl_family = 16 (AF_NETLINK)
        // Peer PID for Netlink is usually 0 (kernel)
        let to_write = core::cmp::min(alen as usize, 12);
        if let Err(e) = crate::impls::utils::write_user_bytes(addr, &nladdr[..to_write]) {
            return -(e.code() as isize);
        }
        if let Err(e) = write_user_value(addrlen, &(to_write as u32)) {
            return -(e.code() as isize);
        }
        return 0;
    }

    let peer_addr = match socket.peer_addr() {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    let peer_addr = adapt_sockaddr_for_domain(domain, peer_addr);
    debug!("sys_getpeername <= fd: {fd}, addr: {peer_addr:?}");

    let net_addr = NetSocketAddr::from(peer_addr);
    if addrlen == 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }
    let mut alen: u32 = match read_user_value(addrlen) {
        Ok(l) => l,
        Err(e) => return -(e.code() as isize),
    };
    match net_addr.write_to_raw(addr, &mut alen) {
        Ok(()) => {
            if let Err(e) = write_user_value(addrlen, &alen) {
                -(e.code() as isize)
            } else {
                0
            }
        }
        Err(e) => -(e.code() as isize),
    }
}
