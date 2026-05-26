use alloc::sync::Arc;

use axerrno::LinuxError;
use axlog::*;
use axnet::{TcpSocket, UdpSocket};
use linux_raw_sys::{
    general::{O_CLOEXEC, O_NONBLOCK},
    net::{AF_INET, AF_INET6, IPPROTO_TCP, IPPROTO_UDP, SHUT_RD, SHUT_RDWR, SHUT_WR},
};
use pulse_core::fd_table::{FdEntry, FdFlags};

use super::{addr::NetSocketAddr, get_socket};
use crate::{impls::fs::common::insert_fd_entry, net::Socket};

/// Helper: insert a socket into the fd table.
fn insert_socket(socket: Socket, flags: FdFlags) -> Result<usize, LinuxError> {
    let entry = FdEntry::new(Arc::new(socket), flags);
    insert_fd_entry(entry)
}

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

pub fn sys_socket(domain: usize, raw_ty: usize, proto: usize) -> isize {
    let domain = domain as u32;
    let raw_ty = raw_ty as u32;
    let proto = proto as u32;
    debug!("sys_socket <= domain: {domain}, ty: {raw_ty}, proto: {proto}");

    let ty = raw_ty & 0xFF;

    let socket = match (domain, ty) {
        (AF_INET | AF_INET6, d) if d == linux_raw_sys::net::SOCK_STREAM => {
            if proto != 0 && proto != IPPROTO_TCP as u32 {
                return -(LinuxError::EPROTONOSUPPORT.code() as isize);
            }
            Socket::Tcp(TcpSocket::new())
        }
        (AF_INET | AF_INET6, d) if d == linux_raw_sys::net::SOCK_DGRAM => {
            if proto != 0 && proto != IPPROTO_UDP as u32 {
                return -(LinuxError::EPROTONOSUPPORT.code() as isize);
            }
            Socket::Udp(UdpSocket::new())
        }
        (AF_INET | AF_INET6, _) => {
            warn!("Unsupported socket type: domain={domain}, ty={ty}");
            return -(LinuxError::ESOCKTNOSUPPORT.code() as isize);
        }
        _ => {
            warn!("Unsupported address family: domain={domain}");
            return -(LinuxError::EAFNOSUPPORT.code() as isize);
        }
    };

    if raw_ty & O_NONBLOCK != 0 {
        socket.set_nonblocking_inner(true);
    }

    let mut flags = FdFlags::empty();
    if raw_ty & O_CLOEXEC != 0 {
        flags.insert(FdFlags::CLOEXEC);
    }
    if raw_ty & O_NONBLOCK != 0 {
        flags.insert(FdFlags::NONBLOCK);
    }

    match insert_socket(socket, flags) {
        Ok(fd) => fd as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_bind(fd: usize, addr: usize, addrlen: usize) -> isize {
    debug!("sys_bind <= fd: {fd}");
    let addr = match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let result = match (&*socket, core::net::SocketAddr::from(addr)) {
        (Socket::Tcp(s), std_addr) => s
            .bind(std_addr)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        (Socket::Udp(s), std_addr) => s
            .bind(std_addr)
            .map_err(|e| LinuxError::from(e.canonicalize())),
    };
    match result {
        Ok(()) => 0,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_connect(fd: usize, addr: usize, addrlen: usize) -> isize {
    debug!("sys_connect <= fd: {fd}");
    let addr = match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    let std_addr = core::net::SocketAddr::from(addr);
    let result = match &*socket {
        Socket::Tcp(s) => s.connect(std_addr).map_err(|e| {
            let le = LinuxError::from(e.canonicalize());
            // EINPROGRESS for non-blocking connect
            if le == LinuxError::EAGAIN {
                LinuxError::EINPROGRESS
            } else {
                le
            }
        }),
        Socket::Udp(s) => s
            .connect(std_addr)
            .map_err(|e| LinuxError::from(e.canonicalize())),
    };
    match result {
        Ok(()) => 0,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_listen(fd: usize, _backlog: usize) -> isize {
    debug!("sys_listen <= fd: {fd}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    match &*socket {
        Socket::Tcp(s) => match s.listen().map_err(|e| LinuxError::from(e.canonicalize())) {
            Ok(()) => 0,
            Err(e) => -(e.code() as isize),
        },
        Socket::Udp(_) => -(LinuxError::EOPNOTSUPP.code() as isize),
    }
}

pub fn sys_accept(fd: usize, addr: usize, addrlen: usize) -> isize {
    sys_accept4(fd, addr, addrlen, 0)
}

pub fn sys_accept4(fd: usize, addr: usize, addrlen: usize, flags: usize) -> isize {
    let flags = flags as u32;
    debug!("sys_accept4 <= fd: {fd}, flags: {flags}");

    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let new_tcp = match &*socket {
        Socket::Tcp(s) => match s.accept().map_err(|e| LinuxError::from(e.canonicalize())) {
            Ok(t) => t,
            Err(e) => return -(e.code() as isize),
        },
        Socket::Udp(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
    };

    let remote_addr = new_tcp.peer_addr().ok();

    let new_socket = Socket::Tcp(new_tcp);
    if flags & O_NONBLOCK != 0 {
        new_socket.set_nonblocking_inner(true);
    }

    let mut new_flags = FdFlags::empty();
    if flags & O_CLOEXEC != 0 {
        new_flags.insert(FdFlags::CLOEXEC);
    }
    if flags & O_NONBLOCK != 0 {
        new_flags.insert(FdFlags::NONBLOCK);
    }

    let new_fd = match insert_socket(new_socket, new_flags) {
        Ok(fd) => fd as isize,
        Err(e) => return -(e.code() as isize),
    };
    debug!("sys_accept4 => new_fd: {new_fd}");

    // Write remote address to user if addr pointer is non-null.
    if addr != 0 {
        if let Some(remote) = remote_addr {
            let net_addr = NetSocketAddr::from(remote);
            if addrlen != 0 {
                if let Ok(current_len) = read_user_plain::<u32>(addrlen) {
                    let mut len = current_len;
                    if net_addr.write_to_raw(addr, &mut len).is_ok() {
                        let _ = write_user_plain(addrlen, &len);
                    }
                }
            }
        }
    }

    new_fd
}

pub fn sys_shutdown(fd: usize, how: usize) -> isize {
    debug!("sys_shutdown <= fd: {fd}, how: {how}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };
    let how = how as u32;
    let result = match &*socket {
        Socket::Tcp(s) => match how {
            SHUT_RD | SHUT_RDWR => s.shutdown().map_err(|e| LinuxError::from(e.canonicalize())),
            SHUT_WR => {
                s.close();
                Ok(())
            }
            _ => Err(LinuxError::EINVAL),
        },
        Socket::Udp(s) => s.shutdown().map_err(|e| LinuxError::from(e.canonicalize())),
    };
    match result {
        Ok(()) => 0,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_socketpair(_domain: usize, _raw_ty: usize, _proto: usize, _fds: usize) -> isize {
    warn!("sys_socketpair: not supported (AF_UNIX degraded)");
    -(LinuxError::EOPNOTSUPP.code() as isize)
}
