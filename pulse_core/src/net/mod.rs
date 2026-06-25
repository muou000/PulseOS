use alloc::sync::Arc;
use core::{any::Any, net::SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use crate::sync::Mutex;

use axerrno::LinuxError;
use axio::PollState;
use axnet::{TcpSocket, UdpSocket};
use linux_raw_sys::general::{S_IFSOCK, stat};
use linux_raw_sys::ioctl::{SIOCATMARK, SIOCGIFCONF};
use crate::fd_table::FdObject;

const RING_BUFFER_SIZE: usize = 65536;

pub static UNIX_REGISTRY: Mutex<alloc::collections::BTreeMap<alloc::string::String, (core::net::SocketAddr, alloc::sync::Weak<Socket>)>> = Mutex::new(alloc::collections::BTreeMap::new());

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
}

pub struct LocalSocketBuffer {
    pub buffer: Mutex<LocalSocketRingBuffer>,
    pub read_wait_queue: axtask::WaitQueue,
    pub write_wait_queue: axtask::WaitQueue,
}

impl LocalSocketBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Mutex::new(LocalSocketRingBuffer::new()),
            read_wait_queue: axtask::WaitQueue::new(),
            write_wait_queue: axtask::WaitQueue::new(),
        }
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
        crate::task::current_thread()
            .map(|thread| thread.has_pending_signal())
            .unwrap_or(false)
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut read_size = 0usize;
        while read_size < buf.len() {
            let mut ring = self.rx.buffer.lock();
            let n = ring.read(&mut buf[read_size..]);
            if n > 0 {
                read_size += n;
                drop(ring);
                self.rx.write_wait_queue.notify_all(true);
                continue;
            }
            if self.peer_closed.load(Ordering::Acquire) {
                return Ok(read_size);
            }
            if read_size > 0 {
                return Ok(read_size);
            }
            if self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }
            drop(ring);
            
            self.rx.read_wait_queue.wait_until(|| {
                let ring = self.rx.buffer.lock();
                ring.available_read() > 0
                    || self.peer_closed.load(Ordering::Acquire)
                    || self.current_has_pending_signal()
            });
            if self.current_has_pending_signal() {
                return Err(LinuxError::EINTR);
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
            if self.peer_closed.load(Ordering::Acquire) {
                return if write_size > 0 {
                    Ok(write_size)
                } else {
                    Err(LinuxError::EPIPE)
                };
            }
            let mut ring = self.tx.buffer.lock();
            let n = ring.write(&buf[write_size..]);
            if n > 0 {
                write_size += n;
                drop(ring);
                self.tx.read_wait_queue.notify_all(true);
                continue;
            }
            if write_size > 0 {
                return Ok(write_size);
            }
            if self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }
            drop(ring);
            
            self.tx.write_wait_queue.wait_until(|| {
                let ring = self.tx.buffer.lock();
                ring.available_write() > 0
                    || self.peer_closed.load(Ordering::Acquire)
                    || self.current_has_pending_signal()
            });
            if self.current_has_pending_signal() {
                return if write_size > 0 {
                    Ok(write_size)
                } else {
                    Err(LinuxError::EINTR)
                };
            }
        }
        Ok(write_size)
    }
}

impl Drop for LocalSocket {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.tx.read_wait_queue.notify_all(false);
        self.rx.write_wait_queue.notify_all(false);
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

    pub fn read(&self, buf: &mut [u8]) -> Result<usize, LinuxError> {
        let rx = self.rx_data.lock();
        let mut offset = self.read_offset.lock();
        if *offset >= rx.len() {
            if self.nonblocking.load(Ordering::Acquire) {
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

    pub fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        if buf.len() < 16 {
            return Err(LinuxError::EINVAL);
        }
        let _nlmsg_len = u32::from_ne_bytes(buf[0..4].try_into().unwrap());
        let nlmsg_type = u16::from_ne_bytes(buf[4..6].try_into().unwrap());
        let nlmsg_seq = u32::from_ne_bytes(buf[8..12].try_into().unwrap());
        let nlmsg_pid_val = u32::from_ne_bytes(buf[12..16].try_into().unwrap());
        let process_pid = crate::task::current_process().map(|p| p.pid() as u32).unwrap_or(0);
        let nlmsg_pid = if nlmsg_pid_val == 0 { process_pid } else { nlmsg_pid_val };

        let mut rx = self.rx_data.lock();
        let mut offset = self.read_offset.lock();

        let response = match nlmsg_type {
            18 => { // RTM_GETLINK
                Self::handle_rtm_getlink(nlmsg_seq, nlmsg_pid)
            }
            22 => { // RTM_GETADDR
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

    fn handle_rtm_getlink(seq: u32, pid: u32) -> alloc::vec::Vec<u8> {
        let mut resp = alloc::vec::Vec::new();

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
        eth_rta.extend_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
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
        eth_msg.push(24); // ifa_prefixlen = 24
        eth_msg.push(0); // ifa_flags
        eth_msg.push(0); // ifa_scope = RT_SCOPE_UNIVERSE (0)
        eth_msg.extend_from_slice(&2u32.to_ne_bytes()); // ifa_index = 2

        // IFA_ADDRESS (1)
        eth_msg.extend_from_slice(&8u16.to_ne_bytes()); // rta_len
        eth_msg.extend_from_slice(&1u16.to_ne_bytes()); // rta_type
        eth_msg.extend_from_slice(&[10, 0, 2, 15]);

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
    Local(LocalSocket),
    Packet(PacketSocket),
    Netlink(NetlinkSocket),
}

impl Socket {
    pub fn local_addr(&self) -> Result<SocketAddr, LinuxError> {
        match &self.inner {
            SocketInner::Tcp(s) => s
                .local_addr()
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s
                .local_addr()
                .map_err(|e| LinuxError::from(e.canonicalize())),
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
            SocketInner::Local(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Packet(_) => Err(LinuxError::EOPNOTSUPP),
            SocketInner::Netlink(_) => Err(LinuxError::EOPNOTSUPP),
        }
    }

    #[allow(dead_code)]
    pub fn is_nonblocking(&self) -> bool {
        match &self.inner {
            SocketInner::Tcp(s) => s.is_nonblocking(),
            SocketInner::Udp(s) => s.is_nonblocking(),
            SocketInner::Local(s) => s.nonblocking.load(Ordering::Acquire),
            SocketInner::Packet(s) => s.nonblocking.load(Ordering::Acquire),
            SocketInner::Netlink(s) => s.nonblocking.load(Ordering::Acquire),
        }
    }

    pub fn set_nonblocking_inner(&self, nonblocking: bool) {
        match &self.inner {
            SocketInner::Tcp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Udp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Local(s) => s.nonblocking.store(nonblocking, Ordering::Release),
            SocketInner::Packet(s) => s.nonblocking.store(nonblocking, Ordering::Release),
            SocketInner::Netlink(s) => s.nonblocking.store(nonblocking, Ordering::Release),
        }
    }

    pub fn recv_queue(&self) -> usize {
        match &self.inner {
            SocketInner::Tcp(s) => s.recv_queue(),
            SocketInner::Udp(s) => s.recv_queue(),
            SocketInner::Local(s) => s.rx.buffer.lock().available_read(),
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
            let process = crate::task::current_process()?;
            process.write_user_bytes(arg, &n.to_ne_bytes())?;
            return Ok(0);
        }
        if cmd == SIOCATMARK {
            match &self.inner {
                SocketInner::Tcp(_) => {
                    if arg == 0 {
                        return Err(LinuxError::EFAULT);
                    }
                    let process = crate::task::current_process()?;
                    let val = 0i32;
                    process.write_user_bytes(arg, &val.to_ne_bytes())?;
                    return Ok(0);
                }
                _ => return Err(LinuxError::ENOTTY),
            }
        }
        if cmd == SIOCGIFCONF {
            if arg == 0 {
                return Err(LinuxError::EFAULT);
            }
            let process = crate::task::current_process()?;
            
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
            eth_ifr[20..24].copy_from_slice(&[10, 0, 2, 15]);
            
            if ifc_buf == 0 {
                let needed_len = 80i32;
                process.write_user_bytes(arg, &needed_len.to_ne_bytes())?;
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
            process.write_user_bytes(arg, &written_len.to_ne_bytes())?;
            return Ok(0);
        }

        // Interface ioctls
        match cmd {
            0x8913 => { // SIOCGIFFLAGS
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::task::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let flags: u16 = if name.starts_with("lo") {
                    0x1 | 0x4 | 0x8 // IFF_UP | IFF_RUNNING | IFF_LOOPBACK
                } else {
                    0x1 | 0x4 | 0x1000 // IFF_UP | IFF_RUNNING | IFF_MULTICAST
                };
                process.write_user_bytes(arg + 16, &flags.to_ne_bytes())?;
                return Ok(0);
            }
            0x8914 => { // SIOCSIFFLAGS
                return Ok(0); // Stub success
            }
            0x8921 => { // SIOCGIFMTU
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::task::current_process()?;
                let mtu = 1500i32;
                process.write_user_bytes(arg + 16, &mtu.to_ne_bytes())?;
                return Ok(0);
            }
            0x8922 => { // SIOCSIFMTU
                return Ok(0); // Stub success
            }
            0x8927 => { // SIOCGIFHWADDR
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::task::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut hwaddr = [0u8; 16];
                hwaddr[0..2].copy_from_slice(&1u16.to_ne_bytes()); // ARPHRD_ETHER
                if name.starts_with("lo") {
                    // Loopback MAC is all zeros
                } else {
                    hwaddr[2..8].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]); // Dummy MAC
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
                let process = crate::task::current_process()?;
                let txqlen = 1000i32;
                process.write_user_bytes(arg + 16, &txqlen.to_ne_bytes())?;
                return Ok(0);
            }
            0x8943 => { // SIOCSIFTXQLEN
                return Ok(0); // Stub success
            }
            0x8910 => { // SIOCGIFNAME
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::task::current_process()?;
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
                let process = crate::task::current_process()?;
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
                process.write_user_bytes(arg + 16, &index.to_ne_bytes())?;
                return Ok(0);
            }
            0x8915 => { // SIOCGIFADDR
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = crate::task::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut addr = [0u8; 16];
                addr[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                if name.starts_with("lo") {
                    addr[4..8].copy_from_slice(&[127, 0, 0, 1]);
                } else {
                    addr[4..8].copy_from_slice(&[10, 0, 2, 15]);
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
                let process = crate::task::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut mask = [0u8; 16];
                mask[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                if name.starts_with("lo") {
                    mask[4..8].copy_from_slice(&[255, 0, 0, 0]);
                } else {
                    mask[4..8].copy_from_slice(&[255, 255, 255, 0]);
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
                let process = crate::task::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let mut brd = [0u8; 16];
                brd[0..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
                if name.starts_with("lo") {
                    brd[4..8].copy_from_slice(&[127, 255, 255, 255]);
                } else {
                    brd[4..8].copy_from_slice(&[10, 0, 2, 255]);
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
            SocketInner::Local(s) => {
                let rx_ring = s.rx.buffer.lock();
                let tx_ring = s.tx.buffer.lock();
                Ok(PollState {
                    readable: rx_ring.available_read() > 0 || s.peer_closed.load(Ordering::Acquire),
                    writable: tx_ring.available_write() > 0 || s.peer_closed.load(Ordering::Acquire),
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
        match &self.inner {
            SocketInner::Local(s) => {
                let mut supported = false;
                if (events & (linux_raw_sys::general::POLLIN as i16)) != 0 {
                    wqs.push(&s.rx.read_wait_queue);
                    supported = true;
                }
                if (events & (linux_raw_sys::general::POLLOUT as i16)) != 0 {
                    wqs.push(&s.tx.write_wait_queue);
                    supported = true;
                }
                Ok(supported || events == 0)
            }
            _ => Ok(false),
        }
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
            }
            _ => false,
        }
    }
}
