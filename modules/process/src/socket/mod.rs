use alloc::sync::Arc;
use core::{
    any::Any,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use axerrno::{LinuxError, LinuxResult};
use axio::PollState;
use axnet::{IcmpSocket, TcpSocket, UdpSocket};
use axpoll::IoEvents;
use linux_raw_sys::general::{O_CLOEXEC, O_NONBLOCK, S_IFSOCK, stat};
use linux_raw_sys::ioctl::{SIOCATMARK, SIOCGIFCONF};
use linux_raw_sys::net::{
    AF_INET, AF_INET6, AF_UNIX, IPPROTO_TCP, IPPROTO_UDP, MSG_ERRQUEUE, MSG_OOB, MSG_PEEK,
    SHUT_RD, SHUT_RDWR, SHUT_WR, SOCK_DGRAM, SOCK_RAW, SOCK_SEQPACKET, SOCK_STREAM,
};
use crate::fd::{FdObject, PollRegistration};

const RING_BUFFER_SIZE: usize = 65536;

fn eth0_ipv4_config() -> ([u8; 4], u8) {
    axnet::interface_ipv4_address()
}

fn ipv4_netmask(prefix_len: u8) -> [u8; 4] {
    let prefix_len = prefix_len.min(32);
    if prefix_len == 0 {
        [0; 4]
    } else {
        (u32::MAX << (32 - u32::from(prefix_len))).to_be_bytes()
    }
}

fn ipv4_broadcast(address: [u8; 4], prefix_len: u8) -> [u8; 4] {
    let mask = ipv4_netmask(prefix_len);
    core::array::from_fn(|index| address[index] | !mask[index])
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnixSocketKey {
    Abstract(alloc::string::String),
    Pathname { fs_id: u64, inode: u64 },
}

pub struct UnixRegistryEntry {
    pub addr: core::net::SocketAddr,
    pub path: alloc::string::String,
    pub socket: alloc::sync::Weak<Socket>,
}

pub static UNIX_REGISTRY: spin::Mutex<
    alloc::collections::BTreeMap<UnixSocketKey, UnixRegistryEntry>,
> = spin::Mutex::new(alloc::collections::BTreeMap::new());

/// Derives `(filesystem_id, inode)` for a resolved VFS [`axfs_ng_vfs::Location`].
#[inline]
pub fn vfs_node_key(loc: &axfs_ng_vfs::Location) -> (u64, u64) {
    let fs_id =
        loc.filesystem() as *const dyn axfs_ng_vfs::FilesystemOps as *const () as usize as u64;
    (fs_id, loc.inode())
}

#[inline]
fn is_abstract_unix_path(path: &str) -> bool {
    path.is_empty() || path.starts_with('\0')
}

/// Resolves an `AF_UNIX` path through an explicit `FsContext` (honoring `chroot` root),
/// returning `UnixSocketKey::Abstract` for abstract names and `UnixSocketKey::Pathname`
/// for VFS-backed pathname sockets (or `-ENOENT` when missing or outside `chroot`).
pub async fn resolve_unix_path_async(
    fs: &axfs::FsContext,
    path: &str,
) -> LinuxResult<UnixSocketKey> {
    if is_abstract_unix_path(path) {
        return Ok(UnixSocketKey::Abstract(alloc::string::String::from(path)));
    }
    let loc = fs
        .resolve(axfs_ng_vfs::path::Path::new(path))
        .await
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    let (fs_id, inode) = vfs_node_key(&loc);
    Ok(UnixSocketKey::Pathname { fs_id, inode })
}

/// Synchronous wrapper around [`resolve_unix_path_async`].
pub fn resolve_unix_path_sync(fs: &axfs::FsContext, path: &str) -> LinuxResult<UnixSocketKey> {
    axtask::future::block_on(resolve_unix_path_async(fs, path))
}

/// Pre-checks whether binding an `AF_UNIX` socket to `path` within `fs` can succeed
/// before allocating an underlying loopback endpoint.
pub fn check_unix_bind_available(fs: &axfs::FsContext, path: &str) -> LinuxResult {
    if is_abstract_unix_path(path) {
        let key = UnixSocketKey::Abstract(alloc::string::String::from(path));
        let mut registry = UNIX_REGISTRY.lock();
        if let Some(entry) = registry.get(&key) {
            if entry.socket.upgrade().is_some() {
                return Err(LinuxError::EADDRINUSE);
            }
            registry.remove(&key);
        }
        return Ok(());
    }

    axtask::future::block_on(async {
        let vfs_path = axfs_ng_vfs::path::Path::new(path);
        fs.resolve_parent(vfs_path)
            .await
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        if fs.resolve(vfs_path).await.is_ok() {
            return Err(LinuxError::EADDRINUSE);
        }
        Ok(())
    })
}

/// Binds a pathname (inside `fs`) or abstract `AF_UNIX` socket and records it in [`UNIX_REGISTRY`].
pub fn bind_unix_socket_with_fs(
    fs: &axfs::FsContext,
    path: &str,
    addr: SocketAddr,
    sock: &Arc<Socket>,
) -> LinuxResult<UnixSocketKey> {
    let key = if is_abstract_unix_path(path) {
        UnixSocketKey::Abstract(alloc::string::String::from(path))
    } else {
        axtask::future::block_on(async {
            let vfs_path = axfs_ng_vfs::path::Path::new(path);
            if fs.resolve(vfs_path).await.is_ok() {
                return Err(LinuxError::EADDRINUSE);
            }
            fs.write(vfs_path, [])
                .await
                .map_err(|e| LinuxError::from(e.canonicalize()))?;
            let loc = fs
                .resolve(vfs_path)
                .await
                .map_err(|e| LinuxError::from(e.canonicalize()))?;
            let (fs_id, inode) = vfs_node_key(&loc);
            Ok(UnixSocketKey::Pathname { fs_id, inode })
        })?
    };

    let mut registry = UNIX_REGISTRY.lock();
    if let Some(entry) = registry.get(&key) {
        if entry.socket.upgrade().is_some() {
            return Err(LinuxError::EADDRINUSE);
        }
        registry.remove(&key);
    }
    registry.insert(
        key.clone(),
        UnixRegistryEntry {
            addr,
            path: alloc::string::String::from(path),
            socket: Arc::downgrade(sock),
        },
    );
    Ok(key)
}

/// Looks up an active bound `AF_UNIX` socket by its [`UnixSocketKey`].
pub fn lookup_unix_socket_by_key(key: &UnixSocketKey) -> LinuxResult<(SocketAddr, Arc<Socket>)> {
    let mut registry = UNIX_REGISTRY.lock();
    match registry.get(key) {
        Some(entry) => {
            if let Some(sock) = entry.socket.upgrade() {
                Ok((entry.addr, sock))
            } else {
                registry.remove(key);
                Err(LinuxError::ECONNREFUSED)
            }
        }
        None => Err(LinuxError::ECONNREFUSED),
    }
}

/// Looks up the bound path string for an `AF_UNIX` socket object.
pub fn lookup_unix_path_by_socket(sock: &Socket) -> Option<alloc::string::String> {
    let registry = UNIX_REGISTRY.lock();
    let target_ptr = sock as *const Socket;
    registry.values().find_map(|entry| {
        entry
            .socket
            .upgrade()
            .filter(|s| core::ptr::eq(Arc::as_ptr(s), target_ptr))
            .map(|_| entry.path.clone())
    })
}

/// Looks up the bound path string for an `AF_UNIX` loopback address.
pub fn lookup_unix_path_by_addr(addr: SocketAddr) -> Option<alloc::string::String> {
    let registry = UNIX_REGISTRY.lock();
    registry.values().find_map(|entry| {
        (entry.addr == addr && entry.socket.upgrade().is_some()).then(|| entry.path.clone())
    })
}

/// Normalizes unspecified and IPv4-mapped connect addresses (`0.0.0.0`/`::ffff:0.0.0.0` -> `127.0.0.1`,
/// `::ffff:a.b.c.d` -> `a.b.c.d`, `::` -> `::1`).
pub fn normalize_connect_addr(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, v4.port()))
        }
        SocketAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.ip().to_ipv4_mapped() {
                let ip = if mapped_v4.is_unspecified() {
                    Ipv4Addr::LOCALHOST
                } else {
                    mapped_v4
                };
                SocketAddr::V4(SocketAddrV4::new(ip, v6.port()))
            } else if v6.ip().is_unspecified() {
                SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    v6.port(),
                    v6.flowinfo(),
                    v6.scope_id(),
                ))
            } else {
                SocketAddr::V6(v6)
            }
        }
        other => other,
    }
}

/// Adapts an internal socket address to the userspace socket address family of `domain`
/// (e.g., presenting IPv4 addresses on `AF_INET6` sockets as `::` or IPv4-mapped `::ffff:x.x.x.x`).
pub fn adapt_sockaddr_for_domain(domain: u32, addr: SocketAddr) -> SocketAddr {
    if domain == AF_INET6 {
        if let SocketAddr::V4(v4) = addr {
            let ip6 = if v4.ip().is_unspecified() {
                Ipv6Addr::UNSPECIFIED
            } else {
                v4.ip().to_ipv6_mapped()
            };
            return SocketAddr::V6(SocketAddrV6::new(ip6, v4.port(), 0, 0));
        }
    }
    addr
}

pub struct LocalSocketRingBuffer {
    arr: [u8; RING_BUFFER_SIZE],
    head: usize,
    tail: usize,
    is_full: bool,
}

impl LocalSocketRingBuffer {
    fn new() -> Self {
        Self {
            arr: [0; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            is_full: false,
        }
    }

    fn available_read(&self) -> usize {
        if self.is_full {
            RING_BUFFER_SIZE
        } else if self.tail >= self.head {
            self.tail - self.head
        } else {
            self.tail + RING_BUFFER_SIZE - self.head
        }
    }

    fn available_write(&self) -> usize {
        RING_BUFFER_SIZE - self.available_read()
    }

    fn write(&mut self, buf: &[u8]) -> usize {
        let avail = self.available_write();
        let to_write = core::cmp::min(buf.len(), avail);
        if to_write == 0 {
            return 0;
        }
        
        let chunk1 = core::cmp::min(to_write, RING_BUFFER_SIZE - self.tail);
        self.arr[self.tail..self.tail + chunk1].copy_from_slice(&buf[..chunk1]);
        if chunk1 < to_write {
            let chunk2 = to_write - chunk1;
            self.arr[..chunk2].copy_from_slice(&buf[chunk1..to_write]);
            self.tail = chunk2;
        } else {
            self.tail = (self.tail + chunk1) % RING_BUFFER_SIZE;
        }
        if self.tail == self.head {
            self.is_full = true;
        }
        to_write
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        let avail = self.available_read();
        let to_read = core::cmp::min(buf.len(), avail);
        if to_read == 0 {
            return 0;
        }
        
        let chunk1 = core::cmp::min(to_read, RING_BUFFER_SIZE - self.head);
        buf[..chunk1].copy_from_slice(&self.arr[self.head..self.head + chunk1]);
        if chunk1 < to_read {
            let chunk2 = to_read - chunk1;
            buf[chunk1..to_read].copy_from_slice(&self.arr[..chunk2]);
            self.head = chunk2;
        } else {
            self.head = (self.head + chunk1) % RING_BUFFER_SIZE;
        }
        if to_read > 0 {
            self.is_full = false;
        }
        to_read
    }

    fn peek(&self, buf: &mut [u8]) -> usize {
        let avail = self.available_read();
        let to_read = core::cmp::min(buf.len(), avail);
        if to_read == 0 {
            return 0;
        }
        let chunk1 = core::cmp::min(to_read, RING_BUFFER_SIZE - self.head);
        buf[..chunk1].copy_from_slice(&self.arr[self.head..self.head + chunk1]);
        if chunk1 < to_read {
            let chunk2 = to_read - chunk1;
            buf[chunk1..to_read].copy_from_slice(&self.arr[..chunk2]);
        }
        to_read
    }
}

pub struct LocalSocketBuffer {
    pub buffer: axsync::Mutex<LocalSocketRingBuffer>,
    pub read_wait_queue: axtask::WaitQueue,
    pub write_wait_queue: axtask::WaitQueue,
    pub write_closed: AtomicBool,
    pub read_closed: AtomicBool,
}

impl LocalSocketBuffer {
    pub fn new() -> Self {
        Self {
            buffer: axsync::Mutex::new(LocalSocketRingBuffer::new()),
            read_wait_queue: axtask::WaitQueue::new(),
            write_wait_queue: axtask::WaitQueue::new(),
            write_closed: AtomicBool::new(false),
            read_closed: AtomicBool::new(false),
        }
    }

    // This sleeping lock must only be acquired from ordinary task context.
    // WaitQueue conditions and poll use `try_lock` instead because they can
    // hold scheduler or epoll bookkeeping locks.
    fn lock_buffer(&self) -> axsync::MutexGuard<'_, LocalSocketRingBuffer> {
        self.buffer.lock()
    }
}

pub struct LocalSocket {
    pub rx: Arc<LocalSocketBuffer>,
    pub tx: Arc<LocalSocketBuffer>,
    pub nonblocking: AtomicBool,
    closed: Arc<AtomicBool>,
    peer_closed: Arc<AtomicBool>,
}

impl LocalSocket {
    pub fn new_pair() -> (Self, Self) {
        let buf1 = Arc::new(LocalSocketBuffer::new());
        let buf2 = Arc::new(LocalSocketBuffer::new());
        let closed1 = Arc::new(AtomicBool::new(false));
        let closed2 = Arc::new(AtomicBool::new(false));
        
        let socket1 = Self {
            rx: buf1.clone(),
            tx: buf2.clone(),
            nonblocking: AtomicBool::new(false),
            closed: closed1.clone(),
            peer_closed: closed2.clone(),
        };
        
        let socket2 = Self {
            rx: buf2,
            tx: buf1,
            nonblocking: AtomicBool::new(false),
            closed: closed2,
            peer_closed: closed1,
        };
        
        (socket1, socket2)
    }

    fn current_has_pending_signal(&self) -> bool {
        crate::current_thread()
            .map(|thread| thread.has_pending_signal())
            .unwrap_or(false)
    }

    pub fn try_read(&self, buf: &mut [u8], peek: bool) -> Result<usize, LinuxError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut ring = self.rx.lock_buffer();
        let n = if peek { ring.peek(buf) } else { ring.read(buf) };
        if n > 0 {
            drop(ring);
            if !peek {
                self.rx.write_wait_queue.notify_all(true);
            }
            return Ok(n);
        }
        if self.peer_closed.load(Ordering::Acquire) || self.rx.write_closed.load(Ordering::Acquire)
        {
            return Ok(0);
        }
        Err(LinuxError::EAGAIN)
    }

    pub fn try_write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.peer_closed.load(Ordering::Acquire) || self.tx.read_closed.load(Ordering::Acquire) {
            return Err(LinuxError::EPIPE);
        }
        let mut ring = self.tx.lock_buffer();
        let n = ring.write(buf);
        drop(ring);
        if n > 0 {
            self.tx.read_wait_queue.notify_all(true);
            Ok(n)
        } else {
            Err(LinuxError::EAGAIN)
        }
    }

    pub fn shutdown_how(&self, how: u32) -> Result<(), LinuxError> {
        match how {
            SHUT_RD => {
                self.rx.read_closed.store(true, Ordering::Release);
                self.rx.read_wait_queue.notify_all(true);
                self.rx.write_wait_queue.notify_all(true);
                Ok(())
            }
            SHUT_WR => {
                self.tx.write_closed.store(true, Ordering::Release);
                self.tx.read_wait_queue.notify_all(true);
                self.tx.write_wait_queue.notify_all(true);
                Ok(())
            }
            SHUT_RDWR => {
                self.rx.read_closed.store(true, Ordering::Release);
                self.tx.write_closed.store(true, Ordering::Release);
                self.rx.read_wait_queue.notify_all(true);
                self.rx.write_wait_queue.notify_all(true);
                self.tx.read_wait_queue.notify_all(true);
                self.tx.write_wait_queue.notify_all(true);
                Ok(())
            }
            _ => Err(LinuxError::EINVAL),
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read_size = 0usize;
        while read_size < buf.len() {
            let mut ring = self.rx.lock_buffer();
            let n = ring.read(&mut buf[read_size..]);
            if n > 0 {
                read_size += n;
                drop(ring);
                continue;
            }
            if self.peer_closed.load(Ordering::Acquire)
                || self.rx.write_closed.load(Ordering::Acquire)
            {
                break;
            }
            if read_size > 0 {
                break;
            }
            if self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }
            drop(ring);

            self.rx.read_wait_queue.wait_until(|| {
                self.rx.buffer.try_lock().map_or(true, |ring| {
                    ring.available_read() > 0
                        || self.peer_closed.load(Ordering::Acquire)
                        || self.rx.write_closed.load(Ordering::Acquire)
                        || self.current_has_pending_signal()
                })
            });
            if self.current_has_pending_signal() {
                if read_size > 0 {
                    break;
                }
                return Err(LinuxError::EINTR);
            }
        }
        if read_size > 0 {
            self.rx.write_wait_queue.notify_all(true);
            if self.rx.lock_buffer().available_read() > 0 {
                self.rx.read_wait_queue.notify_all(false);
            }
        }
        Ok(read_size)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut write_size = 0usize;
        while write_size < buf.len() {
            if self.peer_closed.load(Ordering::Acquire)
                || self.tx.read_closed.load(Ordering::Acquire)
            {
                if write_size > 0 {
                    break;
                }
                return Err(LinuxError::EPIPE);
            }
            let mut ring = self.tx.lock_buffer();
            let n = ring.write(&buf[write_size..]);
            if n > 0 {
                write_size += n;
                drop(ring);
                continue;
            }
            if write_size > 0 {
                break;
            }
            if self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }
            drop(ring);

            self.tx.write_wait_queue.wait_until(|| {
                self.tx.buffer.try_lock().map_or(true, |ring| {
                    ring.available_write() > 0
                        || self.peer_closed.load(Ordering::Acquire)
                        || self.tx.read_closed.load(Ordering::Acquire)
                        || self.current_has_pending_signal()
                })
            });
            if self.current_has_pending_signal() {
                if write_size > 0 {
                    break;
                }
                return Err(LinuxError::EINTR);
            }
        }
        if write_size > 0 {
            self.tx.read_wait_queue.notify_all(true);
            if self.tx.lock_buffer().available_write() > 0 {
                self.tx.write_wait_queue.notify_all(false);
            }
        }
        Ok(write_size)
    }
}

impl Drop for LocalSocket {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.tx.write_closed.store(true, Ordering::Release);
        self.rx.read_closed.store(true, Ordering::Release);
        self.tx.read_wait_queue.notify_all(false);
        self.rx.write_wait_queue.notify_all(false);
        self.rx.read_wait_queue.notify_all(false);
        self.tx.write_wait_queue.notify_all(false);
    }
}

pub struct Socket {
    pub domain: AtomicU32,
    pub inner: SocketInner,
    pub pending_send: Mutex<alloc::vec::Vec<u8>>,
    pub pending_addr: Mutex<Option<core::net::SocketAddr>>,
    pub rx_shutdown: AtomicBool,
    pub tx_shutdown: AtomicBool,
}

impl Socket {
    pub fn new(domain: u32, inner: SocketInner) -> Self {
        Self {
            domain: AtomicU32::new(domain),
            inner,
            pending_send: Mutex::new(alloc::vec::Vec::new()),
            pending_addr: Mutex::new(None),
            rx_shutdown: AtomicBool::new(false),
            tx_shutdown: AtomicBool::new(false),
        }
    }
}

#[derive(Debug)]
pub struct PacketSocket {
    pub version: AtomicU32,
    pub reserve: AtomicU32,
    pub has_vnet_hdr: AtomicBool,
    pub rx_ring_active: AtomicBool,
    pub tx_ring_active: AtomicBool,
    pub nonblocking: AtomicBool,
}

impl PacketSocket {
    pub fn new() -> Self {
        Self {
            version: AtomicU32::new(0),
            reserve: AtomicU32::new(0),
            has_vnet_hdr: AtomicBool::new(false),
            rx_ring_active: AtomicBool::new(false),
            tx_ring_active: AtomicBool::new(false),
            nonblocking: AtomicBool::new(false),
        }
    }
}

pub struct NetlinkSocket {
    pub rx_data: Mutex<alloc::vec::Vec<u8>>,
    pub read_offset: Mutex<usize>,
    pub nonblocking: AtomicBool,
}

impl NetlinkSocket {
    pub fn new() -> Self {
        Self {
            rx_data: Mutex::new(alloc::vec::Vec::new()),
            read_offset: Mutex::new(0),
            nonblocking: AtomicBool::new(false),
        }
    }

    pub fn try_read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        self.read_inner(buf, true)
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        self.read_inner(buf, self.nonblocking.load(Ordering::Acquire))
    }

    fn read_inner(&self, buf: &mut [u8], nonblocking: bool) -> Result<usize, LinuxError> {
        let rx = self.rx_data.lock();
        let mut offset = self.read_offset.lock();
        if *offset >= rx.len() {
            if nonblocking {
                return Err(LinuxError::EAGAIN);
            } else {
                return Ok(0);
            }
        }
        let avail = rx.len() - *offset;
        let to_read = core::cmp::min(buf.len(), avail);
        buf[..to_read].copy_from_slice(&rx[*offset..*offset + to_read]);
        *offset += to_read;
        Ok(to_read)
    }

    pub fn try_write_with_pid(&self, buf: &[u8], process_pid: u32) -> Result<usize, LinuxError> {
        if buf.len() < 16 {
            return Err(LinuxError::EINVAL);
        }
        let _nlmsg_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let nlmsg_pid_val = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
        let nlmsg_pid = if nlmsg_pid_val == 0 {
            process_pid
        } else {
            nlmsg_pid_val
        };

        let mut rx = self.rx_data.lock();
        let mut offset = self.read_offset.lock();

        let response = match nlmsg_type {
            18 => {
                // RTM_GETLINK
                Self::handle_rtm_getlink(nlmsg_seq, nlmsg_pid)
            }
            22 => {
                // RTM_GETADDR
                Self::handle_rtm_getaddr(nlmsg_seq, nlmsg_pid)
            }
            _ => {
                let mut resp = alloc::vec::Vec::new();
                resp.extend_from_slice(&20u32.to_ne_bytes());
                resp.extend_from_slice(&3u16.to_ne_bytes()); // NLMSG_DONE
                resp.extend_from_slice(&2u16.to_ne_bytes()); // NLM_F_MULTI
                resp.extend_from_slice(&nlmsg_seq.to_ne_bytes());
                resp.extend_from_slice(&nlmsg_pid.to_ne_bytes());
                resp.extend_from_slice(&0i32.to_ne_bytes());
                resp
            }
        };

        *rx = response;
        *offset = 0;

        Ok(buf.len())
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        let process_pid = crate::current_process()
            .map(|p| p.pid() as u32)
            .unwrap_or(0);
        self.try_write_with_pid(buf, process_pid)
    }

    fn handle_rtm_getlink(seq: u32, pid: u32) -> alloc::vec::Vec<u8> {
        let mut resp = alloc::vec::Vec::new();
        let eth_mac = axnet::interface_mac_address();

        // 1. "lo" link
        let mut lo_msg = alloc::vec::Vec::new();
        lo_msg.push(0); // ifi_family
        lo_msg.push(0); // __ifi_pad
        lo_msg.extend_from_slice(&772u16.to_ne_bytes()); // ifi_type = ARPHRD_LOOPBACK (772)
        lo_msg.extend_from_slice(&1i32.to_ne_bytes());   // ifi_index
        lo_msg.extend_from_slice(&0xdu32.to_ne_bytes());  // ifi_flags (IFF_UP|IFF_RUNNING|IFF_LOOPBACK)
        lo_msg.extend_from_slice(&0u32.to_ne_bytes());   // ifi_change

        let mut rta = alloc::vec::Vec::new();
        rta.extend_from_slice(&7u16.to_ne_bytes()); // rta_len (4 + 3)
        rta.extend_from_slice(&3u16.to_ne_bytes()); // rta_type = IFLA_IFNAME (3)
        rta.extend_from_slice(b"lo\0");
        while rta.len() % 4 != 0 {
            rta.push(0);
        }
        rta.extend_from_slice(&10u16.to_ne_bytes()); // rta_len (4 + 6)
        rta.extend_from_slice(&1u16.to_ne_bytes());  // rta_type = IFLA_ADDRESS (1)
        rta.extend_from_slice(&[0u8; 6]);
        while rta.len() % 4 != 0 {
            rta.push(0);
        }
        lo_msg.extend_from_slice(&rta);

        let lo_len = 16 + lo_msg.len();
        let mut lo_hdr = alloc::vec::Vec::new();
        lo_hdr.extend_from_slice(&(lo_len as u32).to_ne_bytes());
        lo_hdr.extend_from_slice(&16u16.to_ne_bytes()); // RTM_NEWLINK (16)
        lo_hdr.extend_from_slice(&2u16.to_ne_bytes());  // NLM_F_MULTI (2)
        lo_hdr.extend_from_slice(&seq.to_ne_bytes());
        lo_hdr.extend_from_slice(&pid.to_ne_bytes());

        resp.extend_from_slice(&lo_hdr);
        resp.extend_from_slice(&lo_msg);

        // 2. "eth0" link
        let mut eth_msg = alloc::vec::Vec::new();
        eth_msg.push(0);
        eth_msg.push(0);
        eth_msg.extend_from_slice(&1u16.to_ne_bytes()); // ifi_type = ARPHRD_ETHER (1)
        eth_msg.extend_from_slice(&2i32.to_ne_bytes());   // ifi_index
        eth_msg.extend_from_slice(&0x1005u32.to_ne_bytes()); // ifi_flags (IFF_UP|IFF_RUNNING|IFF_MULTICAST)
        eth_msg.extend_from_slice(&0u32.to_ne_bytes());   // ifi_change

        let mut eth_rta = alloc::vec::Vec::new();
        eth_rta.extend_from_slice(&9u16.to_ne_bytes()); // rta_len (4 + 5)
        eth_rta.extend_from_slice(&3u16.to_ne_bytes()); // rta_type = IFLA_IFNAME (3)
        eth_rta.extend_from_slice(b"eth0\0");
        while eth_rta.len() % 4 != 0 {
            eth_rta.push(0);
        }
        eth_rta.extend_from_slice(&10u16.to_ne_bytes()); // rta_len (4 + 6)
        eth_rta.extend_from_slice(&1u16.to_ne_bytes());  // rta_type = IFLA_ADDRESS (1)
        eth_rta.extend_from_slice(&eth_mac);
        while eth_rta.len() % 4 != 0 {
            eth_rta.push(0);
        }
        eth_msg.extend_from_slice(&eth_rta);

        let eth_len = 16 + eth_msg.len();
        let mut eth_hdr = alloc::vec::Vec::new();
        eth_hdr.extend_from_slice(&(eth_len as u32).to_ne_bytes());
        eth_hdr.extend_from_slice(&16u16.to_ne_bytes()); // RTM_NEWLINK (16)
        eth_hdr.extend_from_slice(&2u16.to_ne_bytes());  // NLM_F_MULTI (2)
        eth_hdr.extend_from_slice(&seq.to_ne_bytes());
        eth_hdr.extend_from_slice(&pid.to_ne_bytes());

        resp.extend_from_slice(&eth_hdr);
        resp.extend_from_slice(&eth_msg);

        // 3. NLMSG_DONE
        resp.extend_from_slice(&20u32.to_ne_bytes());
        resp.extend_from_slice(&3u16.to_ne_bytes()); // NLMSG_DONE (3)
        resp.extend_from_slice(&2u16.to_ne_bytes());  // NLM_F_MULTI (2)
        resp.extend_from_slice(&seq.to_ne_bytes());
        resp.extend_from_slice(&pid.to_ne_bytes());
        resp.extend_from_slice(&0i32.to_ne_bytes());

        resp
    }

    fn handle_rtm_getaddr(seq: u32, pid: u32) -> alloc::vec::Vec<u8> {
        let mut resp = alloc::vec::Vec::new();
        let (eth_address, eth_prefix_len) = eth0_ipv4_config();

        // 1. "lo" address
        let mut lo_msg = alloc::vec::Vec::new();
        lo_msg.push(2); // ifa_family = AF_INET (2)
        lo_msg.push(8); // ifa_prefixlen = 8
        lo_msg.push(0x80); // ifa_flags = IFA_F_PERMANENT (0x80)
        lo_msg.push(254); // ifa_scope = RT_SCOPE_HOST (254)
        lo_msg.extend_from_slice(&1u32.to_ne_bytes()); // ifa_index = 1

        // IFA_ADDRESS (1)
        lo_msg.extend_from_slice(&8u16.to_ne_bytes()); // rta_len
        lo_msg.extend_from_slice(&1u16.to_ne_bytes()); // rta_type
        lo_msg.extend_from_slice(&[127, 0, 0, 1]);

        // IFA_LABEL (3)
        let mut rta_label = alloc::vec::Vec::new();
        rta_label.extend_from_slice(&7u16.to_ne_bytes()); // rta_len (4 + 3)
        rta_label.extend_from_slice(&3u16.to_ne_bytes()); // rta_type
        rta_label.extend_from_slice(b"lo\0");
        while rta_label.len() % 4 != 0 {
            rta_label.push(0);
        }
        lo_msg.extend_from_slice(&rta_label);

        let lo_len = 16 + lo_msg.len();
        let mut lo_hdr = alloc::vec::Vec::new();
        lo_hdr.extend_from_slice(&(lo_len as u32).to_ne_bytes());
        lo_hdr.extend_from_slice(&20u16.to_ne_bytes()); // RTM_NEWADDR (20)
        lo_hdr.extend_from_slice(&2u16.to_ne_bytes());  // NLM_F_MULTI (2)
        lo_hdr.extend_from_slice(&seq.to_ne_bytes());
        lo_hdr.extend_from_slice(&pid.to_ne_bytes());

        resp.extend_from_slice(&lo_hdr);
        resp.extend_from_slice(&lo_msg);

        // 2. "eth0" address
        let mut eth_msg = alloc::vec::Vec::new();
        eth_msg.push(2); // ifa_family = AF_INET (2)
        eth_msg.push(eth_prefix_len); // ifa_prefixlen
        eth_msg.push(0); // ifa_flags
        eth_msg.push(0); // ifa_scope = RT_SCOPE_UNIVERSE (0)
        eth_msg.extend_from_slice(&2u32.to_ne_bytes()); // ifa_index = 2

        // IFA_ADDRESS (1)
        eth_msg.extend_from_slice(&8u16.to_ne_bytes()); // rta_len
        eth_msg.extend_from_slice(&1u16.to_ne_bytes()); // rta_type
        eth_msg.extend_from_slice(&eth_address);

        // IFA_LABEL (3)
        let mut eth_label = alloc::vec::Vec::new();
        eth_label.extend_from_slice(&9u16.to_ne_bytes()); // rta_len (4 + 5)
        eth_label.extend_from_slice(&3u16.to_ne_bytes()); // rta_type
        eth_label.extend_from_slice(b"eth0\0");
        while eth_label.len() % 4 != 0 {
            eth_label.push(0);
        }
        eth_msg.extend_from_slice(&eth_label);

        let eth_len = 16 + eth_msg.len();
        let mut eth_hdr = alloc::vec::Vec::new();
        eth_hdr.extend_from_slice(&(eth_len as u32).to_ne_bytes());
        eth_hdr.extend_from_slice(&20u16.to_ne_bytes()); // RTM_NEWADDR (20)
        eth_hdr.extend_from_slice(&2u16.to_ne_bytes());  // NLM_F_MULTI (2)
        eth_hdr.extend_from_slice(&seq.to_ne_bytes());
        eth_hdr.extend_from_slice(&pid.to_ne_bytes());

        resp.extend_from_slice(&eth_hdr);
        resp.extend_from_slice(&eth_msg);

        // 3. NLMSG_DONE
        resp.extend_from_slice(&20u32.to_ne_bytes());
        resp.extend_from_slice(&3u16.to_ne_bytes()); // NLMSG_DONE (3)
        resp.extend_from_slice(&2u16.to_ne_bytes());  // NLM_F_MULTI (2)
        resp.extend_from_slice(&seq.to_ne_bytes());
        resp.extend_from_slice(&pid.to_ne_bytes());
        resp.extend_from_slice(&0i32.to_ne_bytes());

        resp
    }
}

pub enum SocketInner {
    Tcp(TcpSocket),
    Udp(UdpSocket),
    Icmp(IcmpSocket),
    Local(LocalSocket),
    Packet(PacketSocket),
    Netlink(NetlinkSocket),
}

impl Socket {
    /// Creates a new `Socket` plus `(cloexec, nonblock)` FD flags from Linux `socket(2)` args.
    pub fn create(domain: u32, raw_ty: u32, proto: u32) -> LinuxResult<(Self, bool, bool)> {
        const SOCK_TYPE_MASK: u32 = 0xf;
        if (raw_ty & !SOCK_TYPE_MASK & !O_CLOEXEC & !O_NONBLOCK) != 0 {
            return Err(LinuxError::EINVAL);
        }
        let ty = raw_ty & SOCK_TYPE_MASK;
        if ty < 1 || ty >= 11 {
            return Err(LinuxError::EINVAL);
        }

        let socket = match (domain, ty) {
            (AF_INET | AF_INET6, d) if d == SOCK_STREAM => {
                if proto != 0 && proto != IPPROTO_TCP as u32 && proto != 132 {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
                Socket::new(domain, SocketInner::Tcp(TcpSocket::new()))
            }
            (AF_INET | AF_INET6, d) if d == SOCK_DGRAM => {
                if proto != 0 && proto != IPPROTO_UDP as u32 && proto != 136 {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
                Socket::new(domain, SocketInner::Udp(UdpSocket::new()))
            }
            (AF_INET, d) if d == SOCK_RAW => {
                if proto != 1 {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
                Socket::new(domain, SocketInner::Icmp(IcmpSocket::new()))
            }
            (AF_INET6, d) if d == SOCK_RAW => {
                return Err(LinuxError::EPROTONOSUPPORT);
            }
            (AF_UNIX, d) if d == SOCK_STREAM || d == SOCK_SEQPACKET => {
                Socket::new(domain, SocketInner::Tcp(TcpSocket::new()))
            }
            (AF_UNIX, d) if d == SOCK_DGRAM => {
                Socket::new(domain, SocketInner::Udp(UdpSocket::new()))
            }
            (17, d) if d == SOCK_DGRAM || d == SOCK_RAW => {
                Socket::new(domain, SocketInner::Packet(PacketSocket::new()))
            }
            (16, d) if d == SOCK_RAW => {
                if proto != 0 {
                    return Err(LinuxError::EPROTONOSUPPORT);
                }
                Socket::new(domain, SocketInner::Netlink(NetlinkSocket::new()))
            }
            (AF_INET | AF_INET6 | AF_UNIX | 17 | 16, _) => {
                return Err(LinuxError::ESOCKTNOSUPPORT);
            }
            _ => return Err(LinuxError::EAFNOSUPPORT),
        };

        let cloexec = (raw_ty & O_CLOEXEC) != 0;
        let nonblock = (raw_ty & O_NONBLOCK) != 0;
        if nonblock {
            socket.set_nonblocking_inner(true);
        }
        Ok((socket, cloexec, nonblock))
    }

    pub fn try_accept(&self) -> LinuxResult<Self> {
        match &self.inner {
            SocketInner::Tcp(tcp) => {
                let child = tcp
                    .try_accept()
                    .map_err(|e| LinuxError::from(e.canonicalize()))?;
                Ok(Socket::new(
                    self.domain.load(Ordering::Acquire),
                    SocketInner::Tcp(child),
                ))
            }
            _ => Err(LinuxError::EOPNOTSUPP),
        }
    }

    pub fn try_connect_begin(&self, addr: SocketAddr) -> LinuxResult<bool> {
        let addr = normalize_connect_addr(addr);
        match &self.inner {
            SocketInner::Tcp(tcp) => {
                if tcp.peer_addr().is_ok() && !tcp.is_connecting() {
                    return Err(LinuxError::EISCONN);
                }
                tcp.try_connect_begin(addr).map_err(|e| {
                    let le = LinuxError::from(e.canonicalize());
                    if le == LinuxError::EEXIST {
                        if tcp.is_connecting() {
                            LinuxError::EALREADY
                        } else {
                            LinuxError::EISCONN
                        }
                    } else {
                        le
                    }
                })
            }
            SocketInner::Udp(udp) => {
                udp.connect(addr)
                    .map(|()| true)
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            }
            SocketInner::Icmp(_) | SocketInner::Packet(_) | SocketInner::Netlink(_) => {
                Err(LinuxError::EOPNOTSUPP)
            }
            SocketInner::Local(_) => Err(LinuxError::EISCONN),
        }
    }

    pub fn try_connect_poll(&self) -> LinuxResult<bool> {
        match &self.inner {
            SocketInner::Tcp(tcp) => tcp
                .try_connect_poll()
                .map_err(|e| LinuxError::from(e.canonicalize())),
            _ => Ok(true),
        }
    }

    pub fn try_recv_from(
        &self,
        buf: &mut [u8],
        msg_flags: u32,
    ) -> LinuxResult<(usize, Option<SocketAddr>)> {
        if (msg_flags & MSG_OOB) != 0 {
            return Err(LinuxError::EINVAL);
        }
        if (msg_flags & MSG_ERRQUEUE) != 0 {
            return Err(LinuxError::EAGAIN);
        }
        if self.rx_shutdown.load(Ordering::Acquire) {
            return Ok((0, None));
        }
        let peek = (msg_flags & MSG_PEEK) != 0;
        match &self.inner {
            SocketInner::Tcp(s) => {
                let res = if peek { s.try_peek(buf) } else { s.try_recv(buf) };
                res.map(|n| (n, None))
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            }
            SocketInner::Udp(s) => {
                let res = if peek {
                    s.try_peek_from(buf)
                } else {
                    s.try_recv_from(buf)
                };
                res.map(|(n, src)| (n, Some(src)))
                    .map_err(|e| LinuxError::from(e.canonicalize()))
            }
            SocketInner::Icmp(s) => s
                .try_recv_from(buf)
                .map(|(n, src)| (n, Some(src)))
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(s) => s.try_read(buf, peek).map(|n| (n, None)),
            SocketInner::Packet(_) => Ok((0, None)),
            SocketInner::Netlink(s) => s.try_read(buf).map(|n| (n, None)),
        }
    }

    pub fn try_send_to(
        &self,
        buf: &[u8],
        dest: Option<SocketAddr>,
        msg_flags: u32,
        pid: u32,
    ) -> LinuxResult<usize> {
        if (msg_flags & MSG_OOB) != 0 {
            return Err(LinuxError::EOPNOTSUPP);
        }
        if self.tx_shutdown.load(Ordering::Acquire) {
            return Err(LinuxError::EPIPE);
        }
        match &self.inner {
            SocketInner::Tcp(s) => s.try_send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => {
                if buf.len() > 65507 {
                    return Err(LinuxError::EMSGSIZE);
                }
                let res = if let Some(daddr) = dest {
                    s.try_send_to(buf, normalize_connect_addr(daddr))
                } else {
                    s.try_send(buf)
                };
                res.map_err(|e| LinuxError::from(e.canonicalize()))
            }
            SocketInner::Icmp(s) => {
                if let Some(daddr) = dest {
                    s.try_send_to(buf, normalize_connect_addr(daddr))
                        .map_err(|e| LinuxError::from(e.canonicalize()))
                } else {
                    Err(LinuxError::EDESTADDRREQ)
                }
            }
            SocketInner::Local(s) => s.try_write(buf),
            SocketInner::Packet(_) => Ok(buf.len()),
            SocketInner::Netlink(s) => s.try_write_with_pid(buf, pid),
        }
    }

    pub fn shutdown_how(&self, how: u32) -> LinuxResult {
        if how > 2 {
            return Err(LinuxError::EINVAL);
        }
        match how {
            SHUT_RD => self.rx_shutdown.store(true, Ordering::Release),
            SHUT_WR => self.tx_shutdown.store(true, Ordering::Release),
            SHUT_RDWR => {
                self.rx_shutdown.store(true, Ordering::Release);
                self.tx_shutdown.store(true, Ordering::Release);
            }
            _ => unreachable!(),
        }
        match &self.inner {
            SocketInner::Tcp(s) => match how {
                SHUT_RD => {
                    s.notify_wait_queues(IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP);
                    Ok(())
                }
                SHUT_WR => {
                    s.close();
                    Ok(())
                }
                SHUT_RDWR => s.shutdown().map_err(|e| LinuxError::from(e.canonicalize())),
                _ => Err(LinuxError::EINVAL),
            },
            SocketInner::Udp(s) => s.shutdown().map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(s) => {
                s.shutdown();
                Ok(())
            }
            SocketInner::Local(s) => s.shutdown_how(how),
            SocketInner::Packet(_) | SocketInner::Netlink(_) => Ok(()),
        }
    }

    pub fn notify_wait_queues(&self, events: IoEvents) {
        match &self.inner {
            SocketInner::Tcp(s) => s.notify_wait_queues(events),
            SocketInner::Udp(s) => s.notify_wait_queues(events),
            SocketInner::Icmp(s) => s.notify_wait_queues(events),
            SocketInner::Local(s) => {
                if events.intersects(IoEvents::IN | IoEvents::RDHUP | IoEvents::HUP | IoEvents::ERR) {
                    s.rx.read_wait_queue.notify_all(true);
                }
                if events.intersects(IoEvents::OUT | IoEvents::HUP | IoEvents::ERR) {
                    s.tx.write_wait_queue.notify_all(true);
                }
            }
            SocketInner::Packet(_) | SocketInner::Netlink(_) => {}
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr, LinuxError> {
        match &self.inner {
            SocketInner::Tcp(s) => s
                .local_addr()
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s
                .local_addr()
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Local(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Netlink(_) => Err(LinuxError::EOPNOTSUPP),
        }
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, LinuxError> {
        match &self.inner {
            SocketInner::Tcp(s) => s
                .peer_addr()
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s
                .peer_addr()
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Local(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Netlink(_) => Err(LinuxError::EOPNOTSUPP),
        }
    }

    pub fn is_nonblocking(&self) -> bool {
        match &self.inner {
            SocketInner::Tcp(s) => s.is_nonblocking(),
            SocketInner::Udp(s) => s.is_nonblocking(),
            SocketInner::Icmp(s) => s.is_nonblocking(),
            SocketInner::Local(s) => s.nonblocking.load(Ordering::Acquire),
            SocketInner::Packet(s) => s.nonblocking.load(Ordering::Acquire),
            SocketInner::Netlink(s) => s.nonblocking.load(Ordering::Acquire),
        }
    }

    pub fn set_nonblocking_inner(&self, nonblocking: bool) {
        match &self.inner {
            SocketInner::Tcp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Udp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Icmp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Local(s) => s.nonblocking.store(nonblocking, Ordering::Release),
            SocketInner::Packet(s) => s.nonblocking.store(nonblocking, Ordering::Release),
            SocketInner::Netlink(s) => s.nonblocking.store(nonblocking, Ordering::Release),
        }
    }

    pub fn recv_queue(&self) -> usize {
        match &self.inner {
            SocketInner::Tcp(s) => s.recv_queue(),
            SocketInner::Udp(s) => s.recv_queue(),
            SocketInner::Icmp(s) => s.recv_queue(),
            SocketInner::Local(s) => s.rx.lock_buffer().available_read(),
            SocketInner::Packet(_) => 0,
            SocketInner::Netlink(s) => {
                let rx = s.rx_data.lock();
                let offset = s.read_offset.lock();
                rx.len().saturating_sub(*offset)
            }
        }
    }

    /// Downcast an `Arc<dyn FdObject>` to `Arc<Socket>`.
    pub fn from_fd_entry(object: &Arc<dyn FdObject>) -> Result<Arc<Socket>, LinuxError> {
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

    fn ioctl(&self, cmd: u32, arg: usize) -> Result<isize, LinuxError> {
        if cmd == 0x541B { // FIONREAD
            let n = self.recv_queue() as i32;
            let process = crate::current_process()?;
            process.write_user_value(arg, &n)?;
            return Ok(0);
        }
        if cmd == SIOCATMARK {
            match &self.inner {
                SocketInner::Tcp(_) => {
                    if arg == 0 {
                        return Err(LinuxError::EFAULT);
                    }
                    let process = crate::current_process()?;
                    let val = 0i32;
                    process.write_user_value(arg, &val)?;
                    return Ok(0);
                }
                _ => return Err(LinuxError::ENOTTY),
            }
        }
        if cmd == SIOCGIFCONF {
            if arg == 0 {
                return Err(LinuxError::EFAULT);
            }
            let process = crate::current_process()?;
            
            let mut len_bytes = [0u8; 4];
            let mut buf_bytes = [0u8; 8];
            process.read_user_bytes(arg, &mut len_bytes)?;
            process.read_user_bytes(arg + 8, &mut buf_bytes)?;
            
            let ifc_len = i32::from_ne_bytes(len_bytes);
            let ifc_buf = usize::from_ne_bytes(buf_bytes);
            
            let mut lo_ifr = [0u8; 40];
            lo_ifr[..2].copy_from_slice(b"lo");
            let family_inet = 2u16; // AF_INET
            lo_ifr[16..18].copy_from_slice(&family_inet.to_ne_bytes());
            lo_ifr[20..24].copy_from_slice(&[127, 0, 0, 1]);

            let mut eth_ifr = [0u8; 40];
            eth_ifr[..4].copy_from_slice(b"eth0");
            eth_ifr[16..18].copy_from_slice(&family_inet.to_ne_bytes());
            eth_ifr[20..24].copy_from_slice(&eth0_ipv4_config().0);
            
            if ifc_buf == 0 {
                let needed_len = 80i32;
                process.write_user_value(arg, &needed_len)?;
                return Ok(0);
            }
            
            let limit = ifc_len as usize;
            let mut bytes_to_write = alloc::vec::Vec::new();
            if limit >= 40 {
                bytes_to_write.extend_from_slice(&lo_ifr);
            }
            if limit >= 80 {
                bytes_to_write.extend_from_slice(&eth_ifr);
            }
            
            if !bytes_to_write.is_empty() {
                process.write_user_bytes(ifc_buf, &bytes_to_write)?;
            }
            
            let written_len = bytes_to_write.len() as i32;
            process.write_user_value(arg, &written_len)?;
            return Ok(0);
        }

        // Interface ioctls
        match cmd {
            0x8913 => { // SIOCGIFFLAGS
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let flags: u16 = if name.starts_with("lo") {
                    0x1 | 0x4 | 0x8 // IFF_UP | IFF_RUNNING | IFF_LOOPBACK
                } else {
                    0x1 | 0x4 | 0x1000 // IFF_UP | IFF_RUNNING | IFF_MULTICAST
                };
                process.write_user_value(arg + 16, &flags)?;
                return Ok(0);
            }
            0x8914 => { // SIOCSIFFLAGS
                return Ok(0); // Stub success
            }
            0x8921 => { // SIOCGIFMTU
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mtu = 1500i32;
                process.write_user_value(arg + 16, &mtu)?;
                return Ok(0);
            }
            0x8922 => { // SIOCSIFMTU
                return Ok(0); // Stub success
            }
            0x8927 => { // SIOCGIFHWADDR
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut hwaddr = [0u8; 16];
                hwaddr[0..2].copy_from_slice(&1u16.to_ne_bytes()); // ARPHRD_ETHER
                if name.starts_with("lo") {
                    // Loopback MAC is all zeros
                } else {
                    hwaddr[2..8].copy_from_slice(&axnet::interface_mac_address());
                }
                process.write_user_bytes(arg + 16, &hwaddr)?;
                return Ok(0);
            }
            0x8924 => { // SIOCSIFHWADDR
                return Ok(0); // Stub success
            }
            0x8942 => { // SIOCGIFTXQLEN
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let txqlen = 1000i32;
                process.write_user_value(arg + 16, &txqlen)?;
                return Ok(0);
            }
            0x8943 => { // SIOCSIFTXQLEN
                return Ok(0); // Stub success
            }
            0x8910 => { // SIOCGIFNAME
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut index_bytes = [0u8; 4];
                process.read_user_bytes(arg + 16, &mut index_bytes)?;
                let index = i32::from_ne_bytes(index_bytes);
                let name = match index {
                    1 => "lo",
                    2 => "eth0",
                    _ => return Err(LinuxError::ENODEV),
                };
                let mut name_bytes = [0u8; 16];
                let bytes = name.as_bytes();
                name_bytes[..bytes.len()].copy_from_slice(bytes);
                process.write_user_bytes(arg, &name_bytes)?;
                return Ok(0);
            }
            0x8933 => { // SIOCGIFINDEX
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let index: i32 = if name.starts_with("lo") {
                    1
                } else if name.starts_with("eth") {
                    2
                } else {
                    return Err(LinuxError::ENODEV);
                };
                process.write_user_value(arg + 16, &index)?;
                return Ok(0);
            }
            0x8915 => { // SIOCGIFADDR
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut addr = [0u8; 16];
                addr[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                if name.starts_with("lo") {
                    addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
                } else {
                    addr[4..8].copy_from_slice(&eth0_ipv4_config().0);
                }
                process.write_user_bytes(arg + 16, &addr)?;
                return Ok(0);
            }
            0x8916 => { // SIOCSIFADDR
                return Ok(0); // Stub success
            }
            0x891b => { // SIOCGIFNETMASK
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut mask = [0u8; 16];
                mask[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                if name.starts_with("lo") {
                    mask[4..8].copy_from_slice(&[255, 0, 0, 0]);
                } else {
                    mask[4..8].copy_from_slice(&ipv4_netmask(eth0_ipv4_config().1));
                }
                process.write_user_bytes(arg + 16, &mask)?;
                return Ok(0);
            }
            0x891c => { // SIOCSIFNETMASK
                return Ok(0); // Stub success
            }
            0x8919 => { // SIOCGIFBRDADDR
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut brd = [0u8; 16];
                brd[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                if name.starts_with("lo") {
                    brd[4..8].copy_from_slice(&[127, 255, 255, 255]);
                } else {
                    let (address, prefix_len) = eth0_ipv4_config();
                    brd[4..8].copy_from_slice(&ipv4_broadcast(address, prefix_len));
                }
                process.write_user_bytes(arg + 16, &brd)?;
                return Ok(0);
            }
            0x891a => { // SIOCSIFBRDADDR
                return Ok(0); // Stub success
            }
            _ => {}
        }
        Err(LinuxError::ENOTTY)
    }

    fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        if self.rx_shutdown.load(Ordering::Acquire) {
            return Ok(0);
        }
        match &self.inner {
            SocketInner::Tcp(s) => s.recv(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s
                .recv_from(buf)
                .map(|(n, _)| n)
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(s) => s
                .recv_from(buf)
                .map(|(n, _)| n)
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(s) => s.read(buf),
            SocketInner::Packet(_) => Ok(0),
            SocketInner::Netlink(s) => s.read(buf),
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        if self.tx_shutdown.load(Ordering::Acquire) {
            return Err(LinuxError::EPIPE);
        }
        match &self.inner {
            SocketInner::Tcp(s) => s.send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s.send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(_) => Err(LinuxError::EDESTADDRREQ),
            SocketInner::Local(s) => s.write(buf),
            SocketInner::Packet(_) => Ok(buf.len()),
            SocketInner::Netlink(s) => s.write(buf),
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
        let mut state = match &self.inner {
            SocketInner::Tcp(s) => s.poll().map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s.poll().map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Icmp(s) => s.poll().map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(s) => {
                let peer_write_closed = s.peer_closed.load(Ordering::Acquire)
                    || s.rx.write_closed.load(Ordering::Acquire);
                let peer_read_closed = s.peer_closed.load(Ordering::Acquire)
                    || s.tx.read_closed.load(Ordering::Acquire);
                // poll can execute beneath epoll's bookkeeping lock, so a
                // contended ring is conservatively reported as ready instead
                // of yielding while that lock is held.
                let readable = s.rx.buffer.try_lock().map_or(true, |rx_ring| {
                    rx_ring.available_read() > 0 || peer_write_closed
                });
                let writable = s.tx.buffer.try_lock().map_or(true, |tx_ring| {
                    tx_ring.available_write() > 0 || peer_read_closed
                });
                Ok(PollState {
                    readable,
                    writable,
                })
            }
            SocketInner::Packet(_) => Ok(PollState { readable: false, writable: true }),
            SocketInner::Netlink(s) => {
                let rx = s.rx_data.lock();
                let offset = s.read_offset.lock();
                Ok(PollState {
                    readable: *offset < rx.len(),
                    writable: true,
                })
            }
        }?;
        if self.rx_shutdown.load(Ordering::Acquire) {
            state.readable = true;
        }
        if self.tx_shutdown.load(Ordering::Acquire) {
            state.writable = true;
        }
        Ok(state)
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut alloc::vec::Vec<&'a axtask::WaitQueue>,
    ) -> Result<bool, LinuxError> {
        let mut push_pair = |read_wq: &'a axtask::WaitQueue, write_wq: &'a axtask::WaitQueue| {
            let mut supported = false;
            if (events & (linux_raw_sys::general::POLLIN as i16)) != 0 {
                wqs.push(read_wq);
                supported = true;
            }
            if (events & (linux_raw_sys::general::POLLOUT as i16)) != 0 {
                wqs.push(write_wq);
                supported = true;
            }
            if !supported && events == 0 {
                wqs.push(read_wq);
                supported = true;
            }
            Ok(supported || events == 0)
        };
        match &self.inner {
            SocketInner::Local(s) => push_pair(&s.rx.read_wait_queue, &s.tx.write_wait_queue),
            SocketInner::Tcp(s) => push_pair(s.read_wait_queue(), s.write_wait_queue()),
            SocketInner::Udp(s) => push_pair(s.read_wait_queue(), s.write_wait_queue()),
            SocketInner::Icmp(s) => push_pair(s.read_wait_queue(), s.write_wait_queue()),
            _ => Ok(false),
        }
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: axpoll::IoEvents,
        registrations: &mut alloc::vec::Vec<PollRegistration>,
    ) -> Result<(), LinuxError> {
        match &self.inner {
            SocketInner::Local(s) => {
                if events.intersects(
                    IoEvents::IN | IoEvents::RDHUP | IoEvents::PRI | IoEvents::ERR | IoEvents::HUP,
                ) {
                    let owner = s.rx.clone();
                    let registration = owner.read_wait_queue.register_owned_waker(cx.waker());
                    registrations.push(PollRegistration::new(move || {
                        owner.read_wait_queue.unregister_waker(registration);
                    }));
                }
                if events.contains(IoEvents::OUT) {
                    let owner = s.tx.clone();
                    let registration = owner.write_wait_queue.register_owned_waker(cx.waker());
                    registrations.push(PollRegistration::new(move || {
                        owner.write_wait_queue.unregister_waker(registration);
                    }));
                }
            }
            SocketInner::Tcp(s) => {
                let reg = s.register_poll_waker(cx.waker(), events);
                registrations.push(PollRegistration::new(move || {
                    drop(reg);
                }));
            }
            SocketInner::Udp(s) => {
                let reg = s.register_poll_waker(cx.waker(), events);
                registrations.push(PollRegistration::new(move || {
                    drop(reg);
                }));
            }
            SocketInner::Icmp(s) => {
                let reg = s.register_poll_waker(cx.waker(), events);
                registrations.push(PollRegistration::new(move || {
                    drop(reg);
                }));
            }
            _ => {}
        }
        Ok(())
    }

    fn set_nonblocking(&self, nonblocking: bool) -> Result<(), LinuxError> {
        self.set_nonblocking_inner(nonblocking);
        Ok(())
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        true
    }

    fn poll_hup(&self) -> bool {
        if self.rx_shutdown.load(Ordering::Acquire) && self.tx_shutdown.load(Ordering::Acquire) {
            return true;
        }
        match &self.inner {
            SocketInner::Tcp(s) => s.is_hup(),
            SocketInner::Local(s) => {
                s.peer_closed.load(Ordering::Acquire)
                    || (s.rx.write_closed.load(Ordering::Acquire)
                        && s.tx.read_closed.load(Ordering::Acquire))
            }
            _ => false,
        }
    }

    fn is_rdhup(&self) -> bool {
        if self.rx_shutdown.load(Ordering::Acquire) {
            return true;
        }
        match &self.inner {
            SocketInner::Tcp(tcp_sock) => {
                tcp_sock.with_socket(|socket_opt| {
                    socket_opt.map_or(false, |s| !s.may_recv())
                })
            }
            SocketInner::Local(local_sock) => {
                local_sock.peer_closed.load(Ordering::Acquire)
                    || local_sock.rx.write_closed.load(Ordering::Acquire)
            }
            _ => false,
        }
    }
}
