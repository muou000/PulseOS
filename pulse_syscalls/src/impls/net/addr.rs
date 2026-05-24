//! Socket address conversion utilities.
//!
//! Only AF_INET (IPv4) and AF_INET6 (IPv6) are supported.
//! AF_UNIX and AF_VSOCK are intentionally omitted (functional degradation).

use core::{
    mem::size_of,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use axerrno::LinuxError;
use linux_raw_sys::net::*;

fn read_family(addr: usize, addrlen: u32) -> Result<u16, LinuxError> {
    if size_of::<__kernel_sa_family_t>() > addrlen as usize {
        return Err(LinuxError::EINVAL);
    }
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let family = unsafe { *(addr as *const __kernel_sa_family_t) };
    Ok(family)
}

fn read_v4(addr: usize, addrlen: u32) -> Result<SocketAddrV4, LinuxError> {
    if addrlen < size_of::<sockaddr_in>() as u32 {
        return Err(LinuxError::EINVAL);
    }
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let addr_in = unsafe { &*(addr as *const sockaddr_in) };
    if addr_in.sin_family as u32 != AF_INET {
        return Err(LinuxError::EAFNOSUPPORT);
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from_bits(u32::from_be(addr_in.sin_addr.s_addr)),
        u16::from_be(addr_in.sin_port),
    ))
}

fn read_v6(addr: usize, addrlen: u32) -> Result<SocketAddrV6, LinuxError> {
    if addrlen < size_of::<sockaddr_in6>() as u32 {
        return Err(LinuxError::EINVAL);
    }
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let addr_in6 = unsafe { &*(addr as *const sockaddr_in6) };
    if addr_in6.sin6_family as u32 != AF_INET6 {
        return Err(LinuxError::EAFNOSUPPORT);
    }
    Ok(SocketAddrV6::new(
        Ipv6Addr::from(unsafe { addr_in6.sin6_addr.in6_u.u6_addr8 }),
        u16::from_be(addr_in6.sin6_port),
        u32::from_be(addr_in6.sin6_flowinfo),
        addr_in6.sin6_scope_id,
    ))
}

fn write_v4(v4: &SocketAddrV4, dst: usize, addrlen: &mut u32) -> Result<(), LinuxError> {
    let src = sockaddr_in {
        sin_family: AF_INET as _,
        sin_port: v4.port().to_be(),
        sin_addr: in_addr {
            s_addr: u32::from_ne_bytes(v4.ip().octets()),
        },
        __pad: [0_u8; 8],
    };
    let src_len = size_of::<sockaddr_in>();
    let copy_len = (*addrlen as usize).min(src_len);
    if dst == 0 {
        return Err(LinuxError::EFAULT);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            &src as *const sockaddr_in as *const u8,
            dst as *mut u8,
            copy_len,
        );
    }
    *addrlen = src_len as u32;
    Ok(())
}

fn write_v6(v6: &SocketAddrV6, dst: usize, addrlen: &mut u32) -> Result<(), LinuxError> {
    let src = sockaddr_in6 {
        sin6_family: AF_INET6 as _,
        sin6_port: v6.port().to_be(),
        sin6_flowinfo: v6.flowinfo().to_be(),
        sin6_addr: in6_addr {
            in6_u: linux_raw_sys::net::in6_addr__bindgen_ty_1 {
                u6_addr8: v6.ip().octets(),
            },
        },
        sin6_scope_id: v6.scope_id(),
    };
    let src_len = size_of::<sockaddr_in6>();
    let copy_len = (*addrlen as usize).min(src_len);
    if dst == 0 {
        return Err(LinuxError::EFAULT);
    }
    unsafe {
        core::ptr::copy_nonoverlapping(
            &src as *const sockaddr_in6 as *const u8,
            dst as *mut u8,
            copy_len,
        );
    }
    *addrlen = src_len as u32;
    Ok(())
}

/// A unified IP socket address (IPv4 or IPv6), used internally across all
/// network syscall implementations.
///
/// UNIX domain and VSOCK are not supported (returns EAFNOSUPPORT).
pub enum NetSocketAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
}

impl NetSocketAddr {
    /// Read a `NetSocketAddr` from a raw user-space sockaddr pointer.
    pub fn read_from_raw(addr: usize, addrlen: u32) -> Result<Self, LinuxError> {
        match read_family(addr, addrlen)? as u32 {
            AF_INET => read_v4(addr, addrlen).map(Self::V4),
            AF_INET6 => read_v6(addr, addrlen).map(Self::V6),
            _ => Err(LinuxError::EAFNOSUPPORT),
        }
    }

    /// Write a `NetSocketAddr` into a raw user-space sockaddr pointer.
    pub fn write_to_raw(&self, dst: usize, addrlen: &mut u32) -> Result<(), LinuxError> {
        match self {
            Self::V4(v4) => write_v4(v4, dst, addrlen),
            Self::V6(v6) => write_v6(v6, dst, addrlen),
        }
    }
}

impl From<SocketAddr> for NetSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(v4) => Self::V4(v4),
            SocketAddr::V6(v6) => Self::V6(v6),
        }
    }
}

impl From<NetSocketAddr> for SocketAddr {
    fn from(addr: NetSocketAddr) -> Self {
        match addr {
            NetSocketAddr::V4(v4) => Self::V4(v4),
            NetSocketAddr::V6(v6) => Self::V6(v6),
        }
    }
}
