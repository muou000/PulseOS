use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use axerrno::LinuxError;
use axlog::*;
use linux_raw_sys::{
    general::{O_CLOEXEC, O_NONBLOCK},
    net::{AF_INET, AF_INET6, AF_UNIX, IPPROTO_TCP, IPPROTO_UDP},
};
use pulse_core::{
    fd_table::{FdEntry, FdFlags},
    net::{
        LocalSocket, Socket, SocketInner, adapt_sockaddr_for_domain, bind_unix_socket_with_fs,
        check_unix_bind_available, lookup_unix_path_by_addr, lookup_unix_socket_by_key,
        normalize_connect_addr, resolve_unix_path_sync,
    },
};

use super::{
    addr::{NetSocketAddr, read_unix_path, write_unix_addr},
    get_socket,
};
use crate::impls::{
    fs::common::{insert_fd_entry, remove_fd_entry},
    utils::{read_user_value, write_user_value},
};

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

/// Helper: insert a socket into the fd table.
fn insert_socket(socket: Socket, flags: FdFlags) -> Result<usize, LinuxError> {
    let entry = FdEntry::new(Arc::new(socket), flags);
    insert_fd_entry(entry)
}

pub fn sys_socket(domain: usize, raw_ty: usize, proto: usize) -> isize {
    let domain = domain as u32;
    let raw_ty = raw_ty as u32;
    let proto = proto as u32;
    debug!("sys_socket <= domain: {domain}, ty: {raw_ty}, proto: {proto}");

    let (socket, cloexec, nonblock) = match Socket::create(domain, raw_ty, proto) {
        Ok(created) => created,
        Err(e) => return -(e.code() as isize),
    };

    let mut flags = FdFlags::empty();
    if cloexec {
        flags.insert(FdFlags::CLOEXEC);
    }
    if nonblock {
        flags.insert(FdFlags::NONBLOCK);
    }

    match insert_socket(socket, flags) {
        Ok(fd) => fd as isize,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_bind(fd: usize, addr: usize, addrlen: usize) -> isize {
    debug!("sys_bind <= fd: {fd}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let family = match read_family(addr, addrlen as u32) {
        Ok(f) => f as u32,
        Err(e) => return -(e.code() as isize),
    };

    let socket_domain = socket.domain.load(Ordering::Acquire);
    if socket_domain != family {
        if !(socket_domain == AF_INET6 as u32 && family == AF_INET as u32) {
            return -(LinuxError::EAFNOSUPPORT.code() as isize);
        }
    }

    if family == 16 || family == 17 {
        // AF_NETLINK or AF_PACKET
        return 0;
    }

    if family == AF_UNIX as u32 {
        let path = match read_unix_path(addr, addrlen) {
            Ok(path) => path,
            Err(e) => return -(e.code() as isize),
        };
        let fs = match crate::impls::utils::with_process(|process| {
            process.fs_context_handle().lock().clone()
        }) {
            Ok(fs) => fs,
            Err(e) => return -(e.code() as isize),
        };

        if let Err(e) = check_unix_bind_available(&fs, &path) {
            return -(e.code() as isize);
        }

        // Bind the degraded TCP/UDP socket to loopback (127.0.0.1:0)
        let bind_addr = core::net::SocketAddr::new(
            core::net::IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, 1)),
            0,
        );
        let res = match &socket.inner {
            SocketInner::Tcp(s) => s
                .bind(bind_addr)
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s
                .bind(bind_addr)
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Local(_) | SocketInner::Packet(_) | SocketInner::Netlink(_) => {
                Err(LinuxError::EINVAL)
            }
        };

        if let Err(e) = res {
            return -(e.code() as isize);
        }

        let local_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => return -(e.code() as isize),
        };

        if let Err(e) = bind_unix_socket_with_fs(&fs, &path, local_addr, &socket) {
            return -(e.code() as isize);
        }
        return 0;
    }

    let addr = match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };
    let std_addr = core::net::SocketAddr::from(addr);

    // Validate local IP
    if !axnet::is_local_ip(&std_addr.ip()) {
        return -(LinuxError::EADDRNOTAVAIL.code() as isize);
    }

    // Validate privileged port
    let port = std_addr.port();
    let is_privileged = port > 0 && port < 1024;
    let euid = crate::impls::utils::with_process(|process| process.euid()).unwrap_or(0);
    if is_privileged && euid != 0 {
        return -(LinuxError::EACCES.code() as isize);
    }

    let result = match (&socket.inner, std_addr) {
        (SocketInner::Tcp(s), std_addr) => s
            .bind(std_addr)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        (SocketInner::Udp(s), std_addr) => s
            .bind(std_addr)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        (SocketInner::Icmp(_), _) => Err(LinuxError::EOPNOTSUPP),
        (SocketInner::Local(_), _) => Err(LinuxError::EINVAL),
        (SocketInner::Packet(_), _) => Err(LinuxError::EINVAL),
        (SocketInner::Netlink(_), _) => Err(LinuxError::EINVAL),
    };
    match result {
        Ok(()) => 0,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_connect(fd: usize, addr: usize, addrlen: usize) -> isize {
    debug!("sys_connect <= fd: {fd}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    let family = match read_family(addr, addrlen as u32) {
        Ok(f) => f as u32,
        Err(e) => return -(e.code() as isize),
    };

    if family == 0
    // AF_UNSPEC
    {
        match &socket.inner {
            SocketInner::Tcp(s) => {
                let _ = s.shutdown();
            }
            SocketInner::Udp(s) => {
                let _ = s.shutdown();
            }
            _ => {}
        }
        return 0;
    }

    let socket_domain = socket.domain.load(Ordering::Acquire);
    if socket_domain != family {
        if !(socket_domain == AF_INET6 as u32 && family == AF_INET as u32) {
            return -(LinuxError::EAFNOSUPPORT.code() as isize);
        }
    }

    if family == 16 || family == 17 {
        // AF_NETLINK or AF_PACKET
        return 0;
    }

    if family == AF_UNIX as u32 {
        let path = match read_unix_path(addr, addrlen) {
            Ok(path) => path,
            Err(e) => return -(e.code() as isize),
        };

        let fs = match crate::impls::utils::with_process(|process| {
            process.fs_context_handle().lock().clone()
        }) {
            Ok(fs) => fs,
            Err(e) => return -(e.code() as isize),
        };
        let key = match resolve_unix_path_sync(&fs, &path) {
            Ok(k) => k,
            Err(e) => return -(e.code() as isize),
        };
        let (target_addr, _) = match lookup_unix_socket_by_key(&key) {
            Ok(found) => found,
            Err(e) => return -(e.code() as isize),
        };

        // Connect to the TCP/UDP target_addr
        let res = match &socket.inner {
            SocketInner::Tcp(s) => s.connect(target_addr).map_err(|e| {
                let le = LinuxError::from(e.canonicalize());
                if le == LinuxError::EAGAIN {
                    LinuxError::EINPROGRESS
                } else {
                    le
                }
            }),
            SocketInner::Udp(s) => s
                .connect(target_addr)
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Local(_) => Err(LinuxError::EISCONN),
            SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Netlink(_) => Err(LinuxError::EOPNOTSUPP),
        };

        return match res {
            Ok(()) => 0,
            Err(e) => -(e.code() as isize),
        };
    }

    let addr = match NetSocketAddr::read_from_raw(addr, addrlen as u32) {
        Ok(a) => a,
        Err(e) => return -(e.code() as isize),
    };

    // EISCONN check for TCP
    if let SocketInner::Tcp(s) = &socket.inner {
        if s.peer_addr().is_ok() {
            return -(LinuxError::EISCONN.code() as isize);
        }
    }

    let std_addr = normalize_connect_addr(core::net::SocketAddr::from(addr));

    let result = match &socket.inner {
        SocketInner::Tcp(s) => s.connect(std_addr).map_err(|e| {
            let le = LinuxError::from(e.canonicalize());
            // EISCONN for already connected, EINPROGRESS for non-blocking connect
            if le == LinuxError::EEXIST {
                LinuxError::EISCONN
            } else if le == LinuxError::EAGAIN {
                LinuxError::EINPROGRESS
            } else {
                le
            }
        }),
        SocketInner::Udp(s) => s
            .connect(std_addr)
            .map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Icmp(_) => Err(LinuxError::EOPNOTSUPP),
        SocketInner::Local(_) => Err(LinuxError::EISCONN),
        SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
        SocketInner::Netlink(_) => Err(LinuxError::EOPNOTSUPP),
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
    match &socket.inner {
        SocketInner::Tcp(s) => match s.listen().map_err(|e| LinuxError::from(e.canonicalize())) {
            Ok(()) => 0,
            Err(e) => -(e.code() as isize),
        },
        SocketInner::Udp(_) => -(LinuxError::EOPNOTSUPP.code() as isize),
        SocketInner::Icmp(_) => -(LinuxError::EOPNOTSUPP.code() as isize),
        SocketInner::Local(_) => -(LinuxError::EINVAL.code() as isize),
        SocketInner::Packet(_) => -(LinuxError::EOPNOTSUPP.code() as isize),
        SocketInner::Netlink(_) => -(LinuxError::EOPNOTSUPP.code() as isize),
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

    let new_tcp = match &socket.inner {
        SocketInner::Tcp(s) => match s.accept().map_err(|e| LinuxError::from(e.canonicalize())) {
            Ok(t) => t,
            Err(e) => return -(e.code() as isize),
        },
        SocketInner::Udp(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
        SocketInner::Icmp(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
        SocketInner::Local(_) => return -(LinuxError::EINVAL.code() as isize),
        SocketInner::Packet(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
        SocketInner::Netlink(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
    };

    let remote_addr = new_tcp.peer_addr().ok();

    let new_socket = Socket::new(
        socket.domain.load(Ordering::Acquire),
        SocketInner::Tcp(new_tcp),
    );
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
        let domain = socket.domain.load(Ordering::Acquire);
        if domain == AF_UNIX {
            let path = remote_addr.and_then(lookup_unix_path_by_addr);
            let _ = write_unix_addr(path, addr, addrlen);
        } else if let Some(remote) = remote_addr {
            let net_addr = NetSocketAddr::from(adapt_sockaddr_for_domain(domain, remote));
            if addrlen != 0 {
                if let Ok(current_len) = read_user_value::<u32>(addrlen) {
                    let mut len = current_len;
                    if net_addr.write_to_raw(addr, &mut len).is_ok() {
                        let _ = write_user_value(addrlen, &len);
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
    match socket.shutdown_how(how as u32) {
        Ok(()) => 0,
        Err(e) => -(e.code() as isize),
    }
}

pub fn sys_socketpair(domain: usize, raw_ty: usize, proto: usize, fds: usize) -> isize {
    let domain = domain as u32;
    let raw_ty = raw_ty as u32;
    let proto = proto as u32;
    debug!("sys_socketpair <= domain: {domain}, ty: {raw_ty}, proto: {proto}, fds: {fds:#x}");

    // 1. Validate fds pointer (non-null and aligned)
    if fds == 0 || fds % 4 != 0 {
        return -(LinuxError::EFAULT.code() as isize);
    }

    // 2. Validate type flags
    const SOCK_TYPE_MASK: u32 = 0xf;
    if (raw_ty & !SOCK_TYPE_MASK & !(O_CLOEXEC as u32) & !(O_NONBLOCK as u32)) != 0 {
        return -(LinuxError::EINVAL.code() as isize);
    }

    let ty = raw_ty & SOCK_TYPE_MASK;
    if ty < 1 || ty >= 11 {
        return -(LinuxError::EINVAL.code() as isize);
    }

    // 3. Match Linux socketpair error logic
    if domain != AF_UNIX {
        if domain != AF_INET && domain != AF_INET6 {
            return -(LinuxError::EAFNOSUPPORT.code() as isize);
        }
        if ty == linux_raw_sys::net::SOCK_STREAM {
            if proto != 0 && proto != IPPROTO_TCP as u32 {
                return -(LinuxError::EPROTONOSUPPORT.code() as isize);
            }
            return -(LinuxError::EOPNOTSUPP.code() as isize);
        } else if ty == linux_raw_sys::net::SOCK_DGRAM {
            if proto != 0 && proto != IPPROTO_UDP as u32 {
                return -(LinuxError::EPROTONOSUPPORT.code() as isize);
            }
            return -(LinuxError::EOPNOTSUPP.code() as isize);
        } else {
            return -(LinuxError::EPROTONOSUPPORT.code() as isize);
        }
    }

    // Local sockets share the same in-kernel transport. Accept SEQPACKET as
    // well so Linux's fork/exec error channel can use socketpair(2).
    if ty != linux_raw_sys::net::SOCK_STREAM
        && ty != linux_raw_sys::net::SOCK_DGRAM
        && ty != linux_raw_sys::net::SOCK_SEQPACKET
    {
        return -(LinuxError::EPROTOTYPE.code() as isize);
    }
    if proto != 0 {
        return -(LinuxError::EPROTONOSUPPORT.code() as isize);
    }

    // 4. Create the LocalSocket pair
    let (s1, s2) = LocalSocket::new_pair();

    if raw_ty & O_NONBLOCK != 0 {
        s1.nonblocking.store(true, Ordering::Release);
        s2.nonblocking.store(true, Ordering::Release);
    }

    let mut flags = FdFlags::empty();
    if raw_ty & O_CLOEXEC != 0 {
        flags.insert(FdFlags::CLOEXEC);
    }
    if raw_ty & O_NONBLOCK != 0 {
        flags.insert(FdFlags::NONBLOCK);
    }

    let socket1 = Socket::new(domain, SocketInner::Local(s1));
    let socket2 = Socket::new(domain, SocketInner::Local(s2));

    // 5. Insert sockets into the current process's FD table
    let new_fds =
        match crate::impls::utils::with_process(|process| -> Result<[i32; 2], LinuxError> {
            let fd1 = process.insert_fd_entry(FdEntry::new(Arc::new(socket1), flags))?;
            let fd2 = match process.insert_fd_entry(FdEntry::new(Arc::new(socket2), flags)) {
                Ok(fd) => fd,
                Err(e) => {
                    let _ = process.remove_fd_entry(fd1);
                    return Err(e);
                }
            };
            Ok([fd1 as i32, fd2 as i32])
        }) {
            Ok(Ok(fds)) => fds,
            Ok(Err(e)) | Err(e) => return -(e.code() as isize),
        };

    // 6. Write fds back to user space
    if let Err(e) = write_user_value(fds, &new_fds) {
        let _ = remove_fd_entry(new_fds[0] as usize);
        let _ = remove_fd_entry(new_fds[1] as usize);
        return -(e.code() as isize);
    }

    0
}
