//! Socket option syscalls.
//!
//! Exposes getsockopt/setsockopt support for SO_REUSEADDR, TCP_NODELAY,
//! and stub success returns for other standard socket configuration options.

use core::sync::atomic::Ordering;
use axerrno::LinuxError;
use axlog::*;
use super::get_socket;
use pulse_core::net::SocketInner;

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
struct TimeVal {
    tv_sec: i64,
    tv_usec: i64,
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
struct TpacketReq {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
}

#[derive(Copy, Clone, Default, Debug)]
#[repr(C)]
struct TpacketReq3 {
    tp_block_size: u32,
    tp_block_nr: u32,
    tp_frame_size: u32,
    tp_frame_nr: u32,
    tp_retire_blk_tov: u32,
    tp_sizeof_priv: u32,
    tp_feature_req_word: u32,
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
    debug!("sys_getsockopt: fd={fd}, level={level}, optname={optname}");
    let socket = match get_socket(fd) {
        Ok(s) => s,
        Err(e) => return -(e.code() as isize),
    };

    if level == 0 {
        // IPPROTO_IP
        match optname {
            1 | 10 | 11 => {
                // IP_TOS, IP_MTU_DISCOVER, IP_RECVERR
                debug!("sys_getsockopt: level IPPROTO_IP, optname {optname} (stub success)");
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
                let reuse = match &socket.inner {
                    SocketInner::Tcp(s) => s.is_reuse_addr(),
                    SocketInner::Udp(s) => s.is_reuse_addr(),
                    SocketInner::Local(_) => false,
                    SocketInner::Packet(_) => false,
                    SocketInner::Netlink(_) => false,
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
            9 | 6 | 5 | 15 => {
                // SO_KEEPALIVE, SO_BROADCAST, SO_DONTROUTE, SO_REUSEPORT
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
            10 => {
                // SO_OOBINLINE
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
            _ => {}
        }
    } else if level == 6 {
        // IPPROTO_TCP
        match optname {
            1 => {
                // TCP_NODELAY
                let val: i32 = match &socket.inner {
                    SocketInner::Tcp(s) => {
                        if !s.nagle_enabled() {
                            1
                        } else {
                            0
                        }
                    }
                    SocketInner::Udp(_) | SocketInner::Local(_) | SocketInner::Packet(_) | SocketInner::Netlink(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
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
            2 => {
                // TCP_MAXSEG
                debug!("sys_getsockopt: level IPPROTO_TCP, optname TCP_MAXSEG (stub success)");
                let val: i32 = 1460;
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
                debug!("sys_getsockopt: level IPPROTO_TCP, optname TCP_INFO (stub success)");
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
                debug!("sys_getsockopt: level IPPROTO_TCP, optname TCP_CONGESTION (stub success)");
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
            20 | 21 => {
                // SO_RCVTIMEO, SO_SNDTIMEO
                let ticks = match &socket.inner {
                    SocketInner::Tcp(s) => {
                        if optname == 20 {
                            s.rcv_timeout()
                        } else {
                            s.snd_timeout()
                        }
                    }
                    SocketInner::Udp(s) => {
                        if optname == 20 {
                            s.rcv_timeout()
                        } else {
                            s.snd_timeout()
                        }
                    }
                    _ => 0,
                };
                let nanos = axhal::time::ticks_to_nanos(ticks);
                let tv = TimeVal {
                    tv_sec: (nanos / 1_000_000_000) as i64,
                    tv_usec: ((nanos % 1_000_000_000) / 1_000) as i64,
                };
                if let Err(e) = write_user_plain(optval, &tv) {
                    return -(e.code() as isize);
                }
                let mut len: u32 = match read_user_plain(optlen) {
                    Ok(l) => l,
                    Err(e) => return -(e.code() as isize),
                };
                let required_len = core::mem::size_of::<TimeVal>() as u32;
                if len >= required_len {
                    len = required_len;
                    if let Err(e) = write_user_plain(optlen, &len) {
                        return -(e.code() as isize);
                    }
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
    } else if level == 263 {
        // SOL_PACKET
        match optname {
            10 => {
                // PACKET_VERSION
                let val = match &socket.inner {
                    SocketInner::Packet(p) => p.version.load(Ordering::Acquire) as i32,
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
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
            12 => {
                // PACKET_RESERVE
                let val = match &socket.inner {
                    SocketInner::Packet(p) => p.reserve.load(Ordering::Acquire) as i32,
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
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
            15 => {
                // PACKET_VNET_HDR
                let val = match &socket.inner {
                    SocketInner::Packet(p) => if p.has_vnet_hdr.load(Ordering::Acquire) { 1i32 } else { 0i32 },
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
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
            _ => {}
        }
    }

    debug!("sys_getsockopt (unsupported) <= fd: {fd}, level: {level}, optname: {optname}");
    let err = match level {
        0 | 1 | 6 | 41 | 263 => LinuxError::ENOPROTOOPT,
        _ => LinuxError::EOPNOTSUPP,
    };
    -(err.code() as isize)
}

pub fn sys_setsockopt(
    fd: usize,
    level: usize,
    optname: usize,
    optval: usize,
    optlen: usize,
) -> isize {
    debug!("sys_setsockopt: fd={fd}, level={level}, optname={optname}");
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
                match &socket.inner {
                    SocketInner::Tcp(s) => s.set_reuse_addr(reuse),
                    SocketInner::Udp(s) => s.set_reuse_addr(reuse),
                    SocketInner::Local(_) => {}
                    SocketInner::Packet(_) => {}
                    SocketInner::Netlink(_) => {}
                }
                return 0;
            }
            7 | 8 | 9 | 6 | 5 | 15 | 32 | 33 => {
                // SO_SNDBUF, SO_RCVBUF, SO_KEEPALIVE, SO_BROADCAST, SO_DONTROUTE, SO_REUSEPORT, SO_SNDBUFFORCE, SO_RCVBUFFORCE
                // Stub: return success to avoid failures in applications tuning buffers/keepalives
                return 0;
            }
            20 | 21 => {
                // SO_RCVTIMEO, SO_SNDTIMEO
                if optlen < core::mem::size_of::<TimeVal>() {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let tv: TimeVal = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                let nanos = tv.tv_sec as u64 * 1_000_000_000 + tv.tv_usec as u64 * 1_000;
                let ticks = axhal::time::nanos_to_ticks(nanos);
                match &socket.inner {
                    SocketInner::Tcp(s) => {
                        if optname == 20 {
                            s.set_rcv_timeout(ticks);
                        } else {
                            s.set_snd_timeout(ticks);
                        }
                    }
                    SocketInner::Udp(s) => {
                        if optname == 20 {
                            s.set_rcv_timeout(ticks);
                        } else {
                            s.set_snd_timeout(ticks);
                        }
                    }
                    SocketInner::Local(_) | SocketInner::Packet(_) | SocketInner::Netlink(_) => {}
                }
                return 0;
            }
            10 => {
                // SO_OOBINLINE
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let _val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
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
                match &socket.inner {
                    SocketInner::Tcp(s) => {
                        if let Err(e) = s.set_nagle_enabled(!nodelay) {
                            return -(LinuxError::from(e.canonicalize()).code() as isize);
                        }
                    }
                    SocketInner::Udp(_) | SocketInner::Local(_) | SocketInner::Packet(_) | SocketInner::Netlink(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
                return 0;
            }
            2 => {
                // TCP_MAXSEG
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let _val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                return 0;
            }
            _ => {}
        }
    } else if level == 0 {
        // IPPROTO_IP
        match optname {
            42 | 45 => {
                // MCAST_JOIN_GROUP (42), MCAST_LEAVE_GROUP (45)
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let mut gr_buf = alloc::vec![0u8; optlen];
                if let Err(e) = crate::impls::utils::read_user_bytes(optval, &mut gr_buf) {
                    return -(e.code() as isize);
                }

                match &socket.inner {
                    SocketInner::Tcp(s) => {
                        let mut groups = s.multicast_groups.lock();
                        if optname == 42 {
                            if !groups.contains(&gr_buf) {
                                groups.push(gr_buf);
                            }
                            return 0;
                        } else {
                            if let Some(pos) = groups.iter().position(|x| x == &gr_buf) {
                                groups.remove(pos);
                                return 0;
                            } else {
                                return -(LinuxError::EADDRNOTAVAIL.code() as isize);
                            }
                        }
                    }
                    SocketInner::Udp(s) => {
                        let mut groups = s.multicast_groups.lock();
                        if optname == 42 {
                            if !groups.contains(&gr_buf) {
                                groups.push(gr_buf);
                            }
                            return 0;
                        } else {
                            if let Some(pos) = groups.iter().position(|x| x == &gr_buf) {
                                groups.remove(pos);
                                return 0;
                            } else {
                                return -(LinuxError::EADDRNOTAVAIL.code() as isize);
                            }
                        }
                    }
                    SocketInner::Local(_) | SocketInner::Packet(_) | SocketInner::Netlink(_) => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
            }
            1 | 10 | 11 => {
                // IP_TOS (1), IP_MTU_DISCOVER (10), IP_RECVERR (11)
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let _val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                return 0;
            }
            _ => {}
        }
    } else if level == 41 {
        // IPPROTO_IPV6
        match optname {
            1 => {
                // IPV6_ADDRFORM: convert IPv6 socket to IPv4
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                if val != 2 /* AF_INET */ {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                // Update socket domain to AF_INET
                socket.domain.store(2, Ordering::Release);
                debug!("setsockopt: IPV6_ADDRFORM -> AF_INET");
                return 0;
            }
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
    } else if level == 263 {
        // SOL_PACKET
        match optname {
            10 => {
                // PACKET_VERSION
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                if val != 0 && val != 1 && val != 2 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                match &socket.inner {
                    SocketInner::Packet(p) => {
                        if p.rx_ring_active.load(Ordering::Acquire) || p.tx_ring_active.load(Ordering::Acquire) {
                            return -(LinuxError::EBUSY.code() as isize);
                        }
                        p.version.store(val as u32, Ordering::Release);
                    }
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
                return 0;
            }
            12 => {
                // PACKET_RESERVE
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: u32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                if val > i32::MAX as u32 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                match &socket.inner {
                    SocketInner::Packet(p) => {
                        if p.rx_ring_active.load(Ordering::Acquire) || p.tx_ring_active.load(Ordering::Acquire) {
                            return -(LinuxError::EBUSY.code() as isize);
                        }
                        p.reserve.store(val, Ordering::Release);
                    }
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
                return 0;
            }
            15 => {
                // PACKET_VNET_HDR
                if optlen < 4 {
                    return -(LinuxError::EINVAL.code() as isize);
                }
                let val: i32 = match read_user_plain(optval) {
                    Ok(v) => v,
                    Err(e) => return -(e.code() as isize),
                };
                match &socket.inner {
                    SocketInner::Packet(p) => {
                        if p.rx_ring_active.load(Ordering::Acquire) || p.tx_ring_active.load(Ordering::Acquire) {
                            return -(LinuxError::EBUSY.code() as isize);
                        }
                        p.has_vnet_hdr.store(val != 0, Ordering::Release);
                    }
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
                return 0;
            }
            5 | 6 => {
                // PACKET_RX_RING (5) / PACKET_TX_RING (6)
                match &socket.inner {
                    SocketInner::Packet(p) => {
                        let has_vnet_hdr = p.has_vnet_hdr.load(Ordering::Acquire);
                        let version = p.version.load(Ordering::Acquire);
                        if has_vnet_hdr && version < 2 {
                            return -(LinuxError::EINVAL.code() as isize);
                        }

                        if optlen == 0 {
                            return -(LinuxError::EINVAL.code() as isize);
                        }

                        if version == 2 {
                            // TPACKET_V3
                            if optlen < core::mem::size_of::<TpacketReq3>() {
                                return -(LinuxError::EINVAL.code() as isize);
                            }
                            let req: TpacketReq3 = match read_user_plain(optval) {
                                Ok(r) => r,
                                Err(e) => return -(e.code() as isize),
                            };
                            if req.tp_block_nr > 0 {
                                if req.tp_block_size == 0 || req.tp_block_size % 4096 != 0 {
                                    return -(LinuxError::EINVAL.code() as isize);
                                }
                                if req.tp_sizeof_priv >= req.tp_block_size {
                                    return -(LinuxError::EINVAL.code() as isize);
                                }
                                if req.tp_sizeof_priv > 0x7fffffff {
                                    return -(LinuxError::EINVAL.code() as isize);
                                }
                                if optname == 5 {
                                    p.rx_ring_active.store(true, Ordering::Release);
                                } else {
                                    p.tx_ring_active.store(true, Ordering::Release);
                                }
                            } else {
                                if optname == 5 {
                                    p.rx_ring_active.store(false, Ordering::Release);
                                } else {
                                    p.tx_ring_active.store(false, Ordering::Release);
                                }
                            }
                        } else {
                            // TPACKET_V1 / TPACKET_V2
                            if optlen < core::mem::size_of::<TpacketReq>() {
                                return -(LinuxError::EINVAL.code() as isize);
                            }
                            let req: TpacketReq = match read_user_plain(optval) {
                                Ok(r) => r,
                                Err(e) => return -(e.code() as isize),
                            };
                            if req.tp_block_nr > 0 {
                                if req.tp_block_size == 0 || req.tp_block_size % 4096 != 0 {
                                    return -(LinuxError::EINVAL.code() as isize);
                                }
                                if optname == 5 {
                                    p.rx_ring_active.store(true, Ordering::Release);
                                } else {
                                    p.tx_ring_active.store(true, Ordering::Release);
                                }
                            } else {
                                if optname == 5 {
                                    p.rx_ring_active.store(false, Ordering::Release);
                                } else {
                                    p.tx_ring_active.store(false, Ordering::Release);
                                }
                            }
                        }
                        return 0;
                    }
                    _ => return -(LinuxError::EOPNOTSUPP.code() as isize),
                }
            }
            _ => {}
        }
    }

    debug!(
        "sys_setsockopt (stub) <= fd: {fd}, level: {level}, optname: {optname} — returning \
         ENOPROTOOPT"
    );
    -(LinuxError::ENOPROTOOPT.code() as isize)
}
