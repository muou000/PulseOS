use alloc::sync::Arc;

use axerrno::LinuxError;
use axlog::*;
use axnet::{TcpSocket, UdpSocket};
use linux_raw_sys::{
    general::{O_CLOEXEC, O_NONBLOCK},
    net::{AF_INET, AF_INET6, AF_UNIX, SOCK_RAW, IPPROTO_TCP, IPPROTO_UDP, SHUT_RD, SHUT_RDWR, SHUT_WR},
};
use pulse_core::fd_table::{FdEntry, FdFlags};

use super::{addr::{NetSocketAddr, write_unix_addr}, get_socket};
use crate::{impls::fs::common::{insert_fd_entry, remove_fd_entry}, net::{Socket, LocalSocket, SocketInner}};
use core::sync::atomic::{AtomicU32, Ordering};
use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use alloc::string::String;
use spin::Mutex as SpinMutex;

pub(crate) static UNIX_REGISTRY: SpinMutex<BTreeMap<String, (core::net::SocketAddr, Weak<Socket>)>> = SpinMutex::new(BTreeMap::new());

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

    const SOCK_TYPE_MASK: u32 = 0xf;
    if (raw_ty & !SOCK_TYPE_MASK & !(O_CLOEXEC as u32) & !(O_NONBLOCK as u32)) != 0 {
        return -(LinuxError::EINVAL.code() as isize);
    }

    let ty = raw_ty & SOCK_TYPE_MASK;
    if ty < 1 || ty >= 11 {
        return -(LinuxError::EINVAL.code() as isize);
    }

    let socket = match (domain, ty) {
        (AF_INET | AF_INET6, d) if d == linux_raw_sys::net::SOCK_STREAM => {
            if proto != 0 && proto != IPPROTO_TCP as u32 && proto != 132 {
                return -(LinuxError::EPROTONOSUPPORT.code() as isize);
            }
            Socket::new(domain, SocketInner::Tcp(TcpSocket::new()))
        }
        (AF_INET | AF_INET6, d) if d == linux_raw_sys::net::SOCK_DGRAM => {
            if proto != 0 && proto != IPPROTO_UDP as u32 && proto != 136 {
                return -(LinuxError::EPROTONOSUPPORT.code() as isize);
            }
            Socket::new(domain, SocketInner::Udp(UdpSocket::new()))
        }
        (AF_INET | AF_INET6, d) if d == SOCK_RAW => {
            return -(LinuxError::EPROTONOSUPPORT.code() as isize);
        }
        (AF_UNIX, d) if d == linux_raw_sys::net::SOCK_STREAM || d == linux_raw_sys::net::SOCK_SEQPACKET => {
            Socket::new(domain, SocketInner::Tcp(TcpSocket::new()))
        }
        (AF_UNIX, d) if d == linux_raw_sys::net::SOCK_DGRAM => {
            Socket::new(domain, SocketInner::Udp(UdpSocket::new()))
        }
        (17, d) if d == linux_raw_sys::net::SOCK_DGRAM || d == SOCK_RAW => {
            Socket::new(domain, SocketInner::Packet(crate::net::PacketSocket::new()))
        }
        (AF_INET | AF_INET6 | AF_UNIX | 17, _) => {
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

    if family == 17 { // AF_PACKET
        return 0;
    }

    if family == AF_UNIX as u32 {
        let path = if addrlen <= 2 {
            String::new()
        } else {
            let first_byte = match read_user_plain::<u8>(addr + 2) {
                Ok(b) => b,
                Err(e) => return -(e.code() as isize),
            };
            if first_byte == 0 {
                // Abstract socket
                let len = (addrlen as usize).saturating_sub(3);
                let mut buf = alloc::vec![0u8; len];
                if let Err(e) = crate::impls::utils::read_user_bytes(addr + 3, &mut buf) {
                    return -(e.code() as isize);
                }
                let name = String::from_utf8_lossy(&buf).into_owned();
                alloc::format!("\0{}", name)
            } else {
                // Pathname socket
                let path_c = match crate::impls::utils::read_user_cstring(addr + 2) {
                    Ok(c) => c,
                    Err(e) => return -(e.code() as isize),
                };
                path_c.to_str().map(String::from).unwrap_or_else(|_| String::new())
            }
        };

        if path.is_empty() {
            return -(LinuxError::EINVAL.code() as isize);
        }

        let is_abstract = path.starts_with('\0');

        if !is_abstract {
            // Check parent directory component
            let parent_res = crate::impls::utils::with_process(|process| {
                let binding = process.fs_context_handle();
                let fs = binding.lock();
                fs.resolve_parent(axfs_ng_vfs::path::Path::new(&path))
            });
            match parent_res {
                Ok(Ok((_parent, _name))) => {}
                Ok(Err(e)) => {
                    let le = LinuxError::from(e.canonicalize());
                    return -(le.code() as isize);
                }
                Err(e) => {
                    return -(e.code() as isize);
                }
            }

            // Check if file already exists in filesystem
            let exists = crate::impls::utils::with_process(|process| {
                let binding = process.fs_context_handle();
                let fs = binding.lock();
                fs.resolve(axfs_ng_vfs::path::Path::new(&path)).is_ok()
            }).unwrap_or(false);

            if exists {
                return -(LinuxError::EADDRINUSE.code() as isize);
            }
        }

        // Look up in registry (brief lock)
        {
            let mut registry = UNIX_REGISTRY.lock();
            if let Some((_addr, weak_sock)) = registry.get(&path) {
                if weak_sock.upgrade().is_some() {
                    return -(LinuxError::EADDRINUSE.code() as isize);
                } else {
                    registry.remove(&path);
                }
            }
        }

        // Bind the degraded TCP/UDP socket to loopback (127.0.0.1:0)
        let bind_addr = core::net::SocketAddr::new(core::net::IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, 1)), 0);
        let res = match &socket.inner {
            SocketInner::Tcp(s) => s.bind(bind_addr).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s.bind(bind_addr).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(_) => Err(LinuxError::EINVAL),
            SocketInner::Packet(_) => Err(LinuxError::EINVAL),
        };

        if let Err(e) = res {
            return -(e.code() as isize);
        }

        // Get dynamic local address
        let local_addr = match socket.local_addr() {
            Ok(a) => a,
            Err(e) => return -(e.code() as isize),
        };

        // If pathname, write dummy file to VFS
        if !is_abstract {
            let create_res = crate::impls::utils::with_process(|process| {
                let binding = process.fs_context_handle();
                let fs = binding.lock();
                fs.write(axfs_ng_vfs::path::Path::new(&path), [])
            });
            match create_res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    let le = LinuxError::from(e.canonicalize());
                    return -(le.code() as isize);
                }
                Err(e) => {
                    return -(e.code() as isize);
                }
            }
        }

        // Insert into registry (brief lock)
        {
            let mut registry = UNIX_REGISTRY.lock();
            if let Some((_addr, weak_sock)) = registry.get(&path) {
                if weak_sock.upgrade().is_some() {
                    return -(LinuxError::EADDRINUSE.code() as isize);
                }
            }
            registry.insert(path, (local_addr, Arc::downgrade(&socket)));
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
        (SocketInner::Local(_), _) => Err(LinuxError::EINVAL),
        (SocketInner::Packet(_), _) => Err(LinuxError::EINVAL),
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

    if family == 0 /* AF_UNSPEC */ {
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

    if family == AF_UNIX as u32 {
        let path = if addrlen <= 2 {
            String::new()
        } else {
            let first_byte = match read_user_plain::<u8>(addr + 2) {
                Ok(b) => b,
                Err(e) => return -(e.code() as isize),
            };
            if first_byte == 0 {
                // Abstract
                let len = (addrlen as usize).saturating_sub(3);
                let mut buf = alloc::vec![0u8; len];
                if let Err(e) = crate::impls::utils::read_user_bytes(addr + 3, &mut buf) {
                    return -(e.code() as isize);
                }
                let name = String::from_utf8_lossy(&buf).into_owned();
                alloc::format!("\0{}", name)
            } else {
                // Pathname
                let path_c = match crate::impls::utils::read_user_cstring(addr + 2) {
                    Ok(c) => c,
                    Err(e) => return -(e.code() as isize),
                };
                path_c.to_str().map(String::from).unwrap_or_else(|_| String::new())
            }
        };

        if path.is_empty() {
            return -(LinuxError::EINVAL.code() as isize);
        }

        let is_abstract = path.starts_with('\0');

        if !is_abstract {
            // Check if file exists in VFS
            let exists = crate::impls::utils::with_process(|process| {
                let binding = process.fs_context_handle();
                let fs = binding.lock();
                fs.resolve(axfs_ng_vfs::path::Path::new(&path)).is_ok()
            }).unwrap_or(false);

            if !exists {
                return -(LinuxError::ENOENT.code() as isize);
            }
        }

        // Look up in registry and drop the lock immediately
        let target_addr = {
            let mut registry = UNIX_REGISTRY.lock();
            match registry.get(&path) {
                Some(&(a, ref weak_sock)) => {
                    if weak_sock.upgrade().is_some() {
                        a
                    } else {
                        registry.remove(&path);
                        return -(LinuxError::ECONNREFUSED.code() as isize);
                    }
                }
                None => {
                    return -(LinuxError::ECONNREFUSED.code() as isize);
                }
            }
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
            SocketInner::Udp(s) => s.connect(target_addr).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(_) => Err(LinuxError::EISCONN),
            SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
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

    let mut std_addr = core::net::SocketAddr::from(addr);
    if let core::net::SocketAddr::V4(v4) = &mut std_addr {
        if v4.ip().is_unspecified() {
            *v4 = core::net::SocketAddrV4::new(core::net::Ipv4Addr::new(127, 0, 0, 1), v4.port());
        }
    }

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
        SocketInner::Local(_) => Err(LinuxError::EISCONN),
        SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
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
        SocketInner::Local(_) => -(LinuxError::EINVAL.code() as isize),
        SocketInner::Packet(_) => -(LinuxError::EOPNOTSUPP.code() as isize),
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
        SocketInner::Local(_) => return -(LinuxError::EINVAL.code() as isize),
        SocketInner::Packet(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
    };

    let remote_addr = new_tcp.peer_addr().ok();

    let new_socket = Socket::new(socket.domain.load(Ordering::Acquire), SocketInner::Tcp(new_tcp));
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
        if socket.domain.load(Ordering::Acquire) == AF_UNIX {
            let peer_addr = remote_addr;
            let path = peer_addr.and_then(|pa| {
                let registry = crate::impls::net::UNIX_REGISTRY.lock();
                registry.iter().find_map(|(k, v)| {
                    if v.0 == pa {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
            });
            let _ = write_unix_addr(path, addr, addrlen);
        } else if let Some(remote) = remote_addr {
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
    let result = match &socket.inner {
        SocketInner::Tcp(s) => match how {
            SHUT_RD | SHUT_RDWR => s.shutdown().map_err(|e| LinuxError::from(e.canonicalize())),
            SHUT_WR => {
                s.close();
                Ok(())
            }
            _ => Err(LinuxError::EINVAL),
        },
        SocketInner::Udp(s) => s.shutdown().map_err(|e| LinuxError::from(e.canonicalize())),
        SocketInner::Local(s) => match how {
            SHUT_RD => {
                s.rx.write_wait_queue.notify_all(false);
                Ok(())
            }
            SHUT_WR => {
                s.tx.read_wait_queue.notify_all(false);
                Ok(())
            }
            SHUT_RDWR => {
                s.tx.read_wait_queue.notify_all(false);
                s.rx.write_wait_queue.notify_all(false);
                Ok(())
            }
            _ => Err(LinuxError::EINVAL),
        },
        SocketInner::Packet(_) => Ok(()),
    };
    match result {
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

    // AF_UNIX: we only support SOCK_STREAM and SOCK_DGRAM
    if ty != linux_raw_sys::net::SOCK_STREAM && ty != linux_raw_sys::net::SOCK_DGRAM {
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
    let new_fds = match crate::impls::utils::with_process(|process| -> Result<[i32; 2], LinuxError> {
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
    if let Err(e) = write_user_plain(fds, &new_fds) {
        let _ = remove_fd_entry(new_fds[0] as usize);
        let _ = remove_fd_entry(new_fds[1] as usize);
        return -(e.code() as isize);
    }

    0
}
