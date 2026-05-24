use alloc::sync::Arc;
use core::{any::Any, net::SocketAddr};

use axerrno::LinuxError;
use axio::PollState;
use axnet::{TcpSocket, UdpSocket};
use linux_raw_sys::general::{S_IFSOCK, stat};
use pulse_core::fd_table::FdObject;

/// A unified socket type wrapping either a TCP or UDP socket from standard axnet.
/// Implements `pulse_core::fd_table::FdObject` for integration with the process fd table.
pub enum Socket {
    Tcp(TcpSocket),
    Udp(UdpSocket),
}

impl Socket {
    pub fn local_addr(&self) -> Result<SocketAddr, LinuxError> {
        match self {
            Socket::Tcp(s) => s.local_addr().map_err(|e| LinuxError::from(e.canonicalize())),
            Socket::Udp(s) => s.local_addr().map_err(|e| LinuxError::from(e.canonicalize())),
        }
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, LinuxError> {
        match self {
            Socket::Tcp(s) => s.peer_addr().map_err(|e| LinuxError::from(e.canonicalize())),
            Socket::Udp(s) => s.peer_addr().map_err(|e| LinuxError::from(e.canonicalize())),
        }
    }

    pub fn is_nonblocking(&self) -> bool {
        match self {
            Socket::Tcp(s) => s.is_nonblocking(),
            Socket::Udp(s) => s.is_nonblocking(),
        }
    }

    pub fn set_nonblocking_inner(&self, nonblocking: bool) {
        match self {
            Socket::Tcp(s) => s.set_nonblocking(nonblocking),
            Socket::Udp(s) => s.set_nonblocking(nonblocking),
        }
    }

    /// Downcast an `Arc<dyn FdObject>` to `Arc<Socket>`.
    pub fn from_fd_entry(
        object: &Arc<dyn FdObject>,
    ) -> Result<Arc<Socket>, LinuxError> {
        object
            .as_any()
            .downcast_ref::<Socket>()
            .map(|_| {
                // SAFETY: We've verified the type. Transmute the Arc reference.
                // We clone the Arc with the correct type via unsafe pointer cast.
                let ptr = Arc::as_ptr(object) as *const Socket;
                // SAFETY: Arc originally points to a Socket, we verified with downcast_ref.
                unsafe { Arc::increment_strong_count(ptr) };
                unsafe { Arc::from_raw(ptr) }
            })
            .ok_or(LinuxError::ENOTSOCK)
    }
}

impl FdObject for Socket {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        match self {
            Socket::Tcp(s) => s.recv(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            Socket::Udp(s) => s
                .recv_from(buf)
                .map(|(n, _)| n)
                .map_err(|e| LinuxError::from(e.canonicalize())),
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        match self {
            Socket::Tcp(s) => s.send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            Socket::Udp(s) => s.send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
        }
    }

    fn stat(&self) -> Result<stat, LinuxError> {
        let mut s: stat = unsafe { core::mem::zeroed() };
        s.st_mode = S_IFSOCK | 0o777u32;
        s.st_blksize = 4096;
        s.st_ino = 1;
        s.st_nlink = 1;
        Ok(s)
    }

    fn poll(&self) -> Result<PollState, LinuxError> {
        axnet::poll_interfaces();
        match self {
            Socket::Tcp(s) => s.poll().map_err(|e| LinuxError::from(e.canonicalize())),
            Socket::Udp(s) => s.poll().map_err(|e| LinuxError::from(e.canonicalize())),
        }
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), LinuxError> {
        self.set_nonblocking_inner(nonblocking);
        Ok(())
    }
}
