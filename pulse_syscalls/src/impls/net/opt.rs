//! Socket option syscalls.
//!
//! Exposes getsockopt/setsockopt support for SO_REUSEADDR, TCP_NODELAY,
//! and stub success returns for other standard socket configuration options.

use alloc::sync::Arc;

use axerrno::LinuxError;
use axlog::*;
use super::get_socket;
use crate::net::Socket;

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
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

pub fn sys_getsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    info!("sys_getsockopt: fd={fd}, level={level}, optname={optname}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    if level == 0 {
        // IPPROTO_IP
        match optname {
            1 | 10 => {
                // IP_TOS, IP_MTU_DISCOVER
                info!("sys_getsockopt: level IPPROTO_IP, optname {optname} (stub success)");
                let val: i32 = 0;
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            _ => {}
        }
    } else if level == 1 {
        // SOL_SOCKET
        match optname {
            2 => {
                // SO_REUSEADDR
                let reuse = match &*socket {
                    Socket::Tcp(s) => s.is_reuse_addr(),
                    Socket::Udp(s) => s.is_reuse_addr(),
                };
                let val: i32 = if reuse { 1 } else { 0 };
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            7 | 8 => {
                // SO_SNDBUF, SO_RCVBUF
                let val: i32 = 65536; // Sensible default buffer size
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            9 | 6 => {
                // SO_KEEPALIVE, SO_BROADCAST
                let val: i32 = 0; // Default disabled/false
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            4 => {
                // SO_ERROR
                let val: i32 = 0; // No error
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            20 | 21 => {
                // SO_RCVTIMEO, SO_SNDTIMEO
                let val = TimeVal { tv_sec: 0, tv_usec: 0 };
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                let expected_len = core::mem::size_of::<TimeVal>() as u32;
                if len >= expected_len {
                    len = expected_len;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            _ => {}
        }
    } else if level == 6 {
        // IPPROTO_TCP
        match optname {
            1 => {
                // TCP_NODELAY
                let val: i32 = match &*socket {
                    Socket::Tcp(s) => {
                        if !s.nagle_enabled() {
                            1
                        } else {
                            0
                        }
                    }
                    Socket::Udp(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
                };
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            11 => {
                // TCP_INFO
                info!("sys_getsockopt: level IPPROTO_TCP, optname TCP_INFO (stub success)");
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                let to_copy = core::cmp::min(len as usize, 104); // Typical size of tcp_info
                let buf = [0u8; 104];
                let res = crate::impls::utils::with_process(|process| {
                    pulse_core::task::uaccess::write_user_bytes(process, optval, &buf[..to_copy])
                });
                if res.is_err() {
                    return -LinuxError::EFAULT.code() as isize;
                }
                len = to_copy as u32;
                if let Err(e) = write_user_plain(optlen, &len) {
                    return -(e.code() as isize);
                }
                return 0;
            }
            13 => {
                // TCP_CONGESTION
                info!("sys_getsockopt: level IPPROTO_TCP, optname TCP_CONGESTION (stub success)");
                let val = "cubic\0";
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                let to_copy = core::cmp::min(len as usize, val.len());
                let res = crate::impls::utils::with_process(|process| {
                    pulse_core::task::uaccess::write_user_bytes(
                        process,
                        optval,
                        val.as_bytes()[..to_copy].as_ref(),
                    )
                });
                if res.is_err() {
                    return -LinuxError::EFAULT.code() as isize;
                }
                len = to_copy as u32;
                if let Err(e) = write_user_plain(optlen, &len) {
                    return -(e.code() as isize);
                }
                return 0;
            }
            _ => {}
        }
    } else if level == 41 {
        // IPPROTO_IPV6
        match optname {
            26 => {
                // IPV6_V6ONLY
                let val: i32 = 1; // Default to dual-stack off (IPv6 only)
                if let Err(e) = write_user_plain(optval, &val) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                if len >= 4 {
                    len = 4;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
                }
                return 0;
            }
            _ => {}
        }
    }

    info!("sys_getsockopt (unsupported) <= fd: {fd}, level: {level}, optname: {optname}");
    -(LinuxError::ENOPROTOOPT.code() as isize)
}

pub fn sys_setsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    info!("sys_setsockopt: fd={fd}, level={level}, optname={optname}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    if level == 1 {
        // SOL_SOCKET
        match optname {
            2 => {
                // SO_REUSEADDR
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                let reuse = val != 0;
                match &*socket {
                    Socket::Tcp(s) => s.set_reuse_addr(reuse),
                    Socket::Udp(s) => s.set_reuse_addr(reuse),
                }
                return 0;
            }
            7 | 8 | 9 | 6 => {
                // SO_SNDBUF, SO_RCVBUF, SO_KEEPALIVE, SO_BROADCAST
                // Stub: return success to avoid failures in applications tuning buffers/keepalives
                return 0;
            }
            20 | 21 => {
                // SO_RCVTIMEO, SO_SNDTIMEO
                // Stub: return success to avoid failures in applications setting timeouts
                info!("sys_setsockopt: stub success returning 0 for optname={optname}");
                return 0;
            }
            _ => {}
        }
    } else if level == 6 {
        // IPPROTO_TCP
        match optname {
            1 => {
                // TCP_NODELAY
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                let nodelay = val != 0;
                match &*socket {
                    Socket::Tcp(s) => {
                        if let Err(e) = s.set_nagle_enabled(!nodelay) {
                            return -(LinuxError::from(e.canonicalize()).code() as isize);
                        }
                    }
                    Socket::Udp(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
                return 0;
            }
            _ => {}
        }
    } else if level == 41 {
        // IPPROTO_IPV6
        match optname {
            26 => {
                // IPV6_V6ONLY
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                debug!("setsockopt: IPV6_V6ONLY set to {val}");
                return 0;
            }
            _ => {}
        }
    }

    warn!(
        "sys_setsockopt (stub) <= fd: {fd}, level: {level}, optname: {optname} — returning \
         ENOPROTOOPT"
    );
    -(LinuxError::ENOPROTOOPT.code() as isize)
}
