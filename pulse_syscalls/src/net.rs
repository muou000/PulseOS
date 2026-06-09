use alloc::sync::Arc;
use core::{any::Any, net::SocketAddr};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use axerrno::LinuxError;
use axio::PollState;
use axnet::{TcpSocket, UdpSocket};
use linux_raw_sys::general::{S_IFSOCK, stat};
use linux_raw_sys::ioctl::{SIOCATMARK, SIOCGIFCONF};
use pulse_core::fd_table::FdObject;

const RING_BUFFER_SIZE: usize = 65536;

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
        pulse_core::task::current_thread()
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
}

impl Socket {
    pub fn new(domain: u32, inner: SocketInner) -> Self {
        Self {
            domain: AtomicU32::new(domain),
            inner,
            pending_send: Mutex::new(alloc::vec::Vec::new()),
            pending_addr: Mutex::new(None),
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
}

impl PacketSocket {
    pub fn new() -> Self {
        Self {
            version: AtomicU32::new(0),
            reserve: AtomicU32::new(0),
            has_vnet_hdr: AtomicBool::new(false),
            rx_ring_active: AtomicBool::new(false),
            tx_ring_active: AtomicBool::new(false),
        }
    }
}

pub enum SocketInner {
    Tcp(TcpSocket),
    Udp(UdpSocket),
    Local(LocalSocket),
    Packet(PacketSocket),
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
        }
    }

    #[allow(dead_code)]
    pub fn is_nonblocking(&self) -> bool {
        match &self.inner {
            SocketInner::Tcp(s) => s.is_nonblocking(),
            SocketInner::Udp(s) => s.is_nonblocking(),
            SocketInner::Local(s) => s.nonblocking.load(Ordering::Acquire),
            SocketInner::Packet(_) => false,
        }
    }

    pub fn set_nonblocking_inner(&self, nonblocking: bool) {
        match &self.inner {
            SocketInner::Tcp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Udp(s) => s.set_nonblocking(nonblocking),
            SocketInner::Local(s) => s.nonblocking.store(nonblocking, Ordering::Release),
            SocketInner::Packet(_) => {}
        }
    }

    pub fn recv_queue(&self) -> usize {
        match &self.inner {
            SocketInner::Tcp(s) => s.recv_queue(),
            SocketInner::Udp(s) => s.recv_queue(),
            SocketInner::Local(s) => s.rx.buffer.lock().available_read(),
            SocketInner::Packet(_) => 0,
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
            let process = pulse_core::task::current_process()?;
            process.write_user_bytes(arg, &n.to_ne_bytes())?;
            return Ok(0);
        }
        if cmd == SIOCATMARK {
            match &self.inner {
                SocketInner::Tcp(_) => {
                    if arg == 0 {
                        return Err(LinuxError::EFAULT);
                    }
                    let process = pulse_core::task::current_process()?;
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
            let process = pulse_core::task::current_process()?;
            
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
                let process = pulse_core::task::current_process()?;
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
                let process = pulse_core::task::current_process()?;
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
                let process = pulse_core::task::current_process()?;
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
            0x8933 => { // SIOCGIFINDEX
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = pulse_core::task::current_process()?;
                let mut name_bytes = [0u8; 16];
                process.read_user_bytes(arg, &mut name_bytes)?;
                let name = core::str::from_utf8(&name_bytes).unwrap_or("").trim_matches('\0');
                let index: i32 = if name.starts_with("lo") {
                    1
                } else if name.starts_with("eth") {
                    2
                } else {
                    3
                };
                process.write_user_bytes(arg + 16, &index.to_ne_bytes())?;
                return Ok(0);
            }
            0x8915 => { // SIOCGIFADDR
                if arg == 0 {
                    return Err(LinuxError::EFAULT);
                }
                let process = pulse_core::task::current_process()?;
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
                let process = pulse_core::task::current_process()?;
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
                let process = pulse_core::task::current_process()?;
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
        match &self.inner {
            SocketInner::Tcp(s) => s.recv(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s
                .recv_from(buf)
                .map(|(n, _)| n)
                .map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(s) => s.read(buf),
            SocketInner::Packet(_) => Ok(0),
        }
    }

    fn write(&self, buf: &[u8]) -> Result<usize, LinuxError> {
        match &self.inner {
            SocketInner::Tcp(s) => s.send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Udp(s) => s.send(buf).map_err(|e| LinuxError::from(e.canonicalize())),
            SocketInner::Local(s) => s.write(buf),
            SocketInner::Packet(_) => Ok(buf.len()),
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
        match &self.inner {
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
}
