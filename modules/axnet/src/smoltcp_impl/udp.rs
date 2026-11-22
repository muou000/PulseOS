use alloc::sync::Arc;
use core::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use axerrno::{AxError, AxResult, ax_err, ax_err_type};
use axio::{PollState, Read, Write};
use axpoll::{IoEvents, Pollable};
use axsync::Mutex;
use smoltcp::{
    iface::SocketHandle,
    socket::udp::{self, BindError, SendError},
    wire::{IpAddress, IpEndpoint, IpListenEndpoint, Ipv4Address},
};
use spin::RwLock;

use super::{
    SOCKET_SET, SocketPollRegistration, SocketSetWrapper, SocketWaitQueues,
    addr::{UNSPECIFIED_ENDPOINT, from_core_sockaddr, into_core_sockaddr, is_unspecified},
    block_on_socket_io, deadline_from_ticks, register_wait_queue, schedule_poll, socket_deadline,
};

/// A UDP socket that provides POSIX-like APIs.
pub struct UdpSocket {
    handle: SocketHandle,
    local_addr: RwLock<Option<IpEndpoint>>,
    peer_addr: RwLock<Option<IpEndpoint>>,
    nonblock: AtomicBool,
    reuse_addr: AtomicBool,
    rcv_timeout: AtomicU64,
    snd_timeout: AtomicU64,
    pub multicast_groups: Mutex<alloc::vec::Vec<alloc::vec::Vec<u8>>>,
    wait_queues: Arc<SocketWaitQueues>,
}

impl UdpSocket {
    /// Creates a new UDP socket.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let socket = SocketSetWrapper::new_udp_socket();
        let handle = SOCKET_SET.add(socket);
        let wait_queues = Arc::new(SocketWaitQueues::new());
        register_wait_queue(handle, wait_queues.clone());
        Self {
            handle,
            local_addr: RwLock::new(None),
            peer_addr: RwLock::new(None),
            nonblock: AtomicBool::new(false),
            reuse_addr: AtomicBool::new(false),
            rcv_timeout: AtomicU64::new(0),
            snd_timeout: AtomicU64::new(0),
            multicast_groups: Mutex::new(alloc::vec::Vec::new()),
            wait_queues,
        }
    }

    fn select_ipv4_source(dest: Ipv4Address) -> Ipv4Addr {
        let ip4 = Ipv4Addr::from(dest.0);
        if ip4.is_loopback() || ip4.is_unspecified() {
            return Ipv4Addr::LOCALHOST;
        }
        if super::ETH0.is_inited() {
            if let Some(addr) = super::ETH0
                .iface
                .lock()
                .ip_addrs()
                .iter()
                .find_map(|c| match c.address() {
                    IpAddress::Ipv4(addr) => Some(Ipv4Addr::from(addr.0)),
                    IpAddress::Ipv6(_) => None,
                })
            {
                return addr;
            }
        }
        Ipv4Addr::LOCALHOST
    }

    /// Returns the local address and port, or
    /// [`Err(NotConnected)`](AxError::NotConnected) if not connected.
    pub fn local_addr(&self) -> AxResult<SocketAddr> {
        let local = match self.local_addr.try_read() {
            Some(guard) => (*guard).ok_or(AxError::NotConnected)?,
            None => return Err(AxError::NotConnected),
        };
        if is_unspecified(local.addr) {
            let peer = self.peer_addr.try_read().and_then(|g| *g);
            if let Some(peer) = peer {
                let resolved_ip = match peer.addr {
                    IpAddress::Ipv4(v4) => IpAddr::V4(Self::select_ipv4_source(v4)),
                    IpAddress::Ipv6(v6) => {
                        let ip6 = Ipv6Addr::from(v6.0);
                        if let Some(mapped) = ip6.to_ipv4_mapped() {
                            let src_v4 = Self::select_ipv4_source(Ipv4Address(mapped.octets()));
                            IpAddr::V6(src_v4.to_ipv6_mapped())
                        } else if ip6.is_loopback() || ip6.is_unspecified() {
                            IpAddr::V6(Ipv6Addr::LOCALHOST)
                        } else {
                            let eth_ip6 = if super::ETH0.is_inited() {
                                super::ETH0
                                    .iface
                                    .lock()
                                    .ip_addrs()
                                    .iter()
                                    .find_map(|c| match c.address() {
                                        IpAddress::Ipv6(addr) => Some(Ipv6Addr::from(addr.0)),
                                        IpAddress::Ipv4(_) => None,
                                    })
                            } else {
                                None
                            };
                            IpAddr::V6(eth_ip6.unwrap_or(Ipv6Addr::LOCALHOST))
                        }
                    }
                };
                return Ok(SocketAddr::new(resolved_ip, local.port));
            }
        }
        Ok(into_core_sockaddr(local))
    }

    /// Returns the remote address and port, or
    /// [`Err(NotConnected)`](AxError::NotConnected) if not connected.
    pub fn peer_addr(&self) -> AxResult<SocketAddr> {
        self.remote_endpoint().map(into_core_sockaddr)
    }

    /// Returns whether this socket is in nonblocking mode.
    #[inline]
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Acquire)
    }

    /// Moves this UDP socket into or out of nonblocking mode.
    ///
    /// This will result in `recv`, `recv_from`, `send`, and `send_to`
    /// operations becoming nonblocking, i.e., immediately returning from their
    /// calls. If the IO operation is successful, `Ok` is returned and no
    /// further action is required. If the IO operation could not be completed
    /// and needs to be retried, an error with kind
    /// [`Err(WouldBlock)`](AxError::WouldBlock) is returned.
    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblock.store(nonblocking, Ordering::Release);
    }

    /// Set the TTL (time-to-live) option for this socket.
    ///
    /// The TTL is the number of hops that a packet is allowed to live.
    pub fn set_socket_ttl(&self, ttl: u8) {
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            socket.set_hop_limit(Some(ttl))
        });
    }

    /// Returns whether this socket is in reuse address mode.
    #[inline]
    pub fn is_reuse_addr(&self) -> bool {
        self.reuse_addr.load(Ordering::Acquire)
    }

    /// Moves this UDP socket into or out of reuse address mode.
    ///
    /// When a socket is bound, the `SO_REUSEADDR` option allows multiple sockets to be bound to the
    /// same address if they are bound to different local addresses. This option must be set before
    /// calling `bind`.
    #[inline]
    pub fn set_reuse_addr(&self, reuse_addr: bool) {
        self.reuse_addr.store(reuse_addr, Ordering::Release);
    }

    /// Returns the send timeout of this UDP socket.
    #[inline]
    pub fn snd_timeout(&self) -> u64 {
        self.snd_timeout.load(Ordering::Acquire)
    }

    /// Sets the send timeout of this UDP socket.
    #[inline]
    pub fn set_snd_timeout(&self, timeout: u64) {
        self.snd_timeout.store(timeout, Ordering::Release);
    }

    /// Returns the receive timeout of this UDP socket.
    #[inline]
    pub fn rcv_timeout(&self) -> u64 {
        self.rcv_timeout.load(Ordering::Acquire)
    }

    /// Sets the receive timeout of this UDP socket.
    #[inline]
    pub fn set_rcv_timeout(&self, timeout: u64) {
        self.rcv_timeout.store(timeout, Ordering::Release);
    }

    /// Binds an unbound socket to the given address and port.
    ///
    /// It's must be called before [`send_to`](Self::send_to) and
    /// [`recv_from`](Self::recv_from).
    pub fn bind(&self, mut local_addr: SocketAddr) -> AxResult {
        let mut self_local_addr = self.local_addr.write();

        if local_addr.port() == 0 {
            local_addr.set_port(get_ephemeral_port()?);
        }
        if self_local_addr.is_some() {
            return ax_err!(InvalidInput, "socket bind() failed: already bound");
        }

        let local_endpoint = from_core_sockaddr(local_addr);
        let endpoint = IpListenEndpoint {
            addr: (!is_unspecified(local_endpoint.addr)).then_some(local_endpoint.addr),
            port: local_endpoint.port,
        };

        if !self.is_reuse_addr() {
            // Check if the address is already in use
            SOCKET_SET.bind_check(local_endpoint.addr, local_endpoint.port, Some(self.handle))?;
        }

        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            socket.bind(endpoint).or_else(|e| match e {
                BindError::InvalidState => ax_err!(AlreadyExists, "socket bind() failed"),
                BindError::Unaddressable => ax_err!(InvalidInput, "socket bind() failed"),
            })
        })?;

        *self_local_addr = Some(local_endpoint);
        debug!("UDP socket {}: bound on {}", self.handle, endpoint);
        Ok(())
    }

    /// Sends data on the socket to the given address. On success, returns the
    /// number of bytes written.
    pub fn send_to(&self, buf: &[u8], remote_addr: SocketAddr) -> AxResult<usize> {
        if remote_addr.port() == 0 || remote_addr.ip().is_unspecified() {
            return ax_err!(InvalidInput, "socket send_to() failed: invalid address");
        }
        self.send_impl(buf, from_core_sockaddr(remote_addr))
    }

    /// Attempts to send a datagram to `remote_addr` without blocking or mutating `self.nonblock`.
    pub fn try_send_to(&self, buf: &[u8], remote_addr: SocketAddr) -> AxResult<usize> {
        if remote_addr.port() == 0 || remote_addr.ip().is_unspecified() {
            return ax_err!(InvalidInput, "socket send_to() failed: invalid address");
        }
        self.ensure_bound_for_remote(&remote_addr)?;
        SOCKET_SET.poll_interfaces();
        self.try_send_endpoint(buf, from_core_sockaddr(remote_addr))
    }

    /// Attempts to send a datagram on a connected UDP socket without blocking.
    pub fn try_send(&self, buf: &[u8]) -> AxResult<usize> {
        let remote_endpoint = self.remote_endpoint()?;
        let remote_addr = into_core_sockaddr(remote_endpoint);
        self.ensure_bound_for_remote(&remote_addr)?;
        SOCKET_SET.poll_interfaces();
        self.try_send_endpoint(buf, remote_endpoint)
    }

    fn ensure_bound_for_remote(&self, remote_addr: &SocketAddr) -> AxResult {
        if self.local_addr.read().is_none() {
            let unspec = match remote_addr {
                SocketAddr::V4(_) => SocketAddr::new(
                    core::net::IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED),
                    0,
                ),
                SocketAddr::V6(_) => SocketAddr::new(
                    core::net::IpAddr::V6(core::net::Ipv6Addr::UNSPECIFIED),
                    0,
                ),
            };
            self.bind(unspec)?;
        }
        Ok(())
    }

    /// Receives a single datagram message on the socket. On success, returns
    /// the number of bytes read and the origin.
    pub fn recv_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        self.recv_impl(socket_deadline(self.rcv_timeout()), |socket| {
            Self::copy_datagram(socket.recv().map(|(p, m)| (p, m.endpoint)), buf)
        })
    }

    /// Attempts to receive a single datagram without blocking or mutating `self.nonblock`.
    pub fn try_recv_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        self.try_recv_impl(|socket| {
            Self::copy_datagram(socket.recv().map(|(p, m)| (p, m.endpoint)), buf)
        })
    }

    /// Receives data from the socket, stores it in the given buffer.
    ///
    /// It will return [`Err(Timeout)`](AxError::Timeout) if expired.
    pub fn recv_from_timeout(&self, buf: &mut [u8], ticks: u64) -> AxResult<(usize, SocketAddr)> {
        self.recv_impl(Some(deadline_from_ticks(ticks)), |socket| {
            match socket.recv() {
                Ok((packet_buf, meta)) => {
                    let copied_len = core::cmp::min(buf.len(), packet_buf.len());
                    buf[..copied_len].copy_from_slice(&packet_buf[..copied_len]);
                    Ok((copied_len, into_core_sockaddr(meta.endpoint)))
                }
                Err(_) => Err(AxError::WouldBlock),
            }
        })
    }

    /// Receives a single datagram message on the socket, without removing it from
    /// the queue. On success, returns the number of bytes read and the origin.
    pub fn peek_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        self.recv_impl(socket_deadline(self.rcv_timeout()), |socket| {
            Self::copy_datagram(socket.peek().map(|(p, m)| (p, m.endpoint)), buf)
        })
    }

    /// Attempts to peek a single datagram without blocking or removing it from the queue.
    pub fn try_peek_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        self.try_recv_impl(|socket| {
            Self::copy_datagram(socket.peek().map(|(p, m)| (p, m.endpoint)), buf)
        })
    }

    fn copy_datagram<E>(
        res: Result<(&[u8], IpEndpoint), E>,
        buf: &mut [u8],
    ) -> AxResult<(usize, SocketAddr)> {
        match res {
            Ok((packet_buf, endpoint)) => {
                let copied_len = core::cmp::min(buf.len(), packet_buf.len());
                buf[..copied_len].copy_from_slice(&packet_buf[..copied_len]);
                Ok((copied_len, into_core_sockaddr(endpoint)))
            }
            Err(_) => ax_err!(BadState, "socket recv_from() failed"),
        }
    }

    /// Connects this UDP socket to a remote address, allowing the `send` and
    /// `recv` to be used to send data and also applies filters to only receive
    /// data from the specified address.
    ///
    /// The local port will be generated automatically if the socket is not bound.
    /// It's must be called before [`send`](Self::send) and
    /// [`recv`](Self::recv).
    pub fn connect(&self, addr: SocketAddr) -> AxResult {
        let mut self_peer_addr = self.peer_addr.write();

        if self.local_addr.read().is_none() {
            self.bind(into_core_sockaddr(UNSPECIFIED_ENDPOINT))?;
        }

        let endpoint = from_core_sockaddr(addr);
        *self_peer_addr = Some(endpoint);

        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            socket.set_peer_endpoint(Some(endpoint));
        });

        debug!("UDP socket {}: connected to {}", self.handle, addr);
        Ok(())
    }

    /// Sends data on the socket to the remote address to which it is connected.
    pub fn send(&self, buf: &[u8]) -> AxResult<usize> {
        let remote_endpoint = self.remote_endpoint()?;
        self.send_impl(buf, remote_endpoint)
    }

    /// Receives a single datagram message on the socket from the remote address
    /// to which it is connected. On success, returns the number of bytes read.
    pub fn recv(&self, buf: &mut [u8]) -> AxResult<usize> {
        let remote_endpoint = self.remote_endpoint()?;
        loop {
            let res = self.recv_impl(socket_deadline(self.rcv_timeout()), |socket| {
                let (packet_buf, meta) = socket
                    .recv()
                    .map_err(|_| ax_err_type!(BadState, "socket recv() failed"))?;
                if !is_unspecified(remote_endpoint.addr)
                    && remote_endpoint.addr != meta.endpoint.addr
                {
                    return Err(AxError::WouldBlock);
                }
                if remote_endpoint.port != 0 && remote_endpoint.port != meta.endpoint.port {
                    return Err(AxError::WouldBlock);
                }
                let copied_len = core::cmp::min(buf.len(), packet_buf.len());
                buf[..copied_len].copy_from_slice(&packet_buf[..copied_len]);
                Ok(copied_len)
            });

            match res {
                Ok(len) => return Ok(len),
                Err(AxError::WouldBlock) if !self.is_nonblocking() => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// Attempts to receive a datagram from the connected peer without blocking.
    pub fn try_recv(&self, buf: &mut [u8]) -> AxResult<usize> {
        let remote_endpoint = self.remote_endpoint()?;
        if self.local_addr.read().is_none() {
            self.bind(into_core_sockaddr(UNSPECIFIED_ENDPOINT))?;
        }
        SOCKET_SET.poll_interfaces();
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            if !socket.is_open() {
                return ax_err!(NotConnected, "socket recv() failed");
            }
            while socket.can_recv() {
                let (packet_buf, meta) = socket
                    .recv()
                    .map_err(|_| ax_err_type!(BadState, "socket recv() failed"))?;
                if (!is_unspecified(remote_endpoint.addr)
                    && remote_endpoint.addr != meta.endpoint.addr)
                    || (remote_endpoint.port != 0 && remote_endpoint.port != meta.endpoint.port)
                {
                    continue;
                }
                let copied_len = core::cmp::min(buf.len(), packet_buf.len());
                buf[..copied_len].copy_from_slice(&packet_buf[..copied_len]);
                return Ok(copied_len);
            }
            Err(AxError::WouldBlock)
        })
    }

    /// Close the socket.
    pub fn shutdown(&self) -> AxResult {
        SOCKET_SET.poll_interfaces();
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            debug!("UDP socket {}: shutting down", self.handle);
            socket.close();
        });
        self.notify_wait_queues(IoEvents::IN | IoEvents::OUT | IoEvents::HUP);
        Ok(())
    }

    pub fn poll(&self) -> AxResult<PollState> {
        if self.local_addr.read().is_none() {
            return Ok(PollState {
                readable: false,
                writable: false,
            });
        }
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            Ok(PollState {
                readable: socket.can_recv(),
                writable: socket.can_send(),
            })
        })
    }
}

impl Pollable for UdpSocket {
    fn poll(&self) -> IoEvents {
        if self.local_addr.read().is_none() {
            return IoEvents::empty();
        }
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            let mut events = IoEvents::empty();
            if socket.can_recv() {
                events |= IoEvents::IN;
            }
            if socket.can_send() {
                events |= IoEvents::OUT;
            }
            events
        })
    }

    fn register(&self, context: &mut core::task::Context<'_>, events: IoEvents) {
        self.wait_queues.register(context, events);
    }
}

/// Private methods
impl UdpSocket {
    fn remote_endpoint(&self) -> AxResult<IpEndpoint> {
        match self.peer_addr.try_read() {
            Some(addr) => addr.ok_or(AxError::NotConnected),
            None => Err(AxError::NotConnected),
        }
    }

    fn try_send_endpoint(&self, buf: &[u8], remote_endpoint: IpEndpoint) -> AxResult<usize> {
        let result = SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            if !socket.is_open() {
                ax_err!(NotConnected, "socket send() failed")
            } else if socket.can_send() {
                socket
                    .send_slice(buf, remote_endpoint)
                    .map_err(|e| match e {
                        SendError::BufferFull => AxError::WouldBlock,
                        SendError::Unaddressable => {
                            ax_err_type!(ConnectionRefused, "socket send() failed")
                        }
                    })?;
                Ok(buf.len())
            } else {
                Err(AxError::WouldBlock)
            }
        });
        if result.as_ref().is_ok_and(|len| *len != 0) {
            schedule_poll();
        }
        result
    }

    fn send_impl(&self, buf: &[u8], remote_endpoint: IpEndpoint) -> AxResult<usize> {
        self.ensure_bound_for_remote(&into_core_sockaddr(remote_endpoint))?;
        self.block_on(IoEvents::OUT, socket_deadline(self.snd_timeout()), || {
            self.try_send_endpoint(buf, remote_endpoint)
        })
    }

    fn try_recv_impl<F, T>(&self, mut op: F) -> AxResult<T>
    where
        F: FnMut(&mut udp::Socket) -> AxResult<T>,
    {
        if self.local_addr.read().is_none() {
            self.bind(into_core_sockaddr(UNSPECIFIED_ENDPOINT))?;
        }
        SOCKET_SET.poll_interfaces();
        self.recv_once_locked(&mut op)
    }

    fn recv_once_locked<F, T>(&self, op: &mut F) -> AxResult<T>
    where
        F: FnMut(&mut udp::Socket) -> AxResult<T>,
    {
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| {
            if !socket.is_open() {
                ax_err!(NotConnected, "socket recv() failed")
            } else if socket.can_recv() {
                op(socket)
            } else {
                Err(AxError::WouldBlock)
            }
        })
    }

    fn recv_impl<F, T>(&self, deadline: Option<axhal::time::TimeValue>, mut op: F) -> AxResult<T>
    where
        F: FnMut(&mut udp::Socket) -> AxResult<T>,
    {
        if self.local_addr.read().is_none() {
            self.bind(into_core_sockaddr(UNSPECIFIED_ENDPOINT))?;
        }

        self.block_on(IoEvents::IN, deadline, || self.recv_once_locked(&mut op))
    }

    fn block_on<F, T>(
        &self,
        events: IoEvents,
        deadline: Option<axhal::time::TimeValue>,
        mut f: F,
    ) -> AxResult<T>
    where
        F: FnMut() -> AxResult<T>,
    {
        block_on_socket_io(
            self.wait_queues.queue(events),
            self.is_nonblocking(),
            deadline,
            || {
                #[cfg(feature = "monolithic")]
                if crate::current_have_signals() {
                    return Err(AxError::Interrupted);
                }

                SOCKET_SET.poll_interfaces();
                f()
            },
        )
    }

    /// To get the socket and call the given function.
    ///
    /// If the socket is not connected, it will return None.
    ///
    /// Or it will return the result of the given function.
    pub fn with_socket<R>(&self, f: impl FnOnce(&udp::Socket) -> R) -> R {
        SOCKET_SET.with_socket(self.handle, |s| f(s))
    }

    pub fn recv_queue(&self) -> usize {
        SOCKET_SET.with_socket_mut::<udp::Socket, _, _>(self.handle, |socket| match socket.peek() {
            Ok((packet, _)) => packet.len(),
            Err(_) => 0,
        })
    }

    /// Returns the wait queue for this socket.
    pub fn get_wait_queue(&self) -> &axtask::WaitQueue {
        &self.wait_queues.any
    }

    /// Registers an RAII per-socket waker on this socket's readiness wait queues.
    pub fn register_poll_waker(
        &self,
        waker: &core::task::Waker,
        events: IoEvents,
    ) -> SocketPollRegistration {
        self.wait_queues.register_owned(waker, events)
    }

    /// Returns the read readiness wait queue for this socket.
    pub fn read_wait_queue(&self) -> &axtask::WaitQueue {
        &self.wait_queues.read
    }

    /// Returns the write readiness wait queue for this socket.
    pub fn write_wait_queue(&self) -> &axtask::WaitQueue {
        &self.wait_queues.write
    }

    /// Wakes waiters on this socket's wait queues matching `events`.
    pub fn notify_wait_queues(&self, events: IoEvents) {
        self.wait_queues.notify(events);
    }
}

impl Read for UdpSocket {
    fn read(&mut self, buf: &mut [u8]) -> AxResult<usize> {
        self.recv(buf)
    }
}

impl Write for UdpSocket {
    fn write(&mut self, buf: &[u8]) -> AxResult<usize> {
        self.send(buf)
    }

    fn flush(&mut self) -> AxResult {
        Err(AxError::Unsupported)
    }
}

impl Drop for UdpSocket {
    fn drop(&mut self) {
        self.shutdown().ok();
        SOCKET_SET.remove_and_unregister(self.handle);
    }
}

fn get_ephemeral_port() -> AxResult<u16> {
    const PORT_START: u16 = 0xc000;
    const PORT_END: u16 = 0xffff;
    static CURR: Mutex<u16> = Mutex::new(PORT_START);
    let mut curr = CURR.lock();
    let mut tries = 0;
    while tries <= PORT_END - PORT_START {
        let port = *curr;
        if *curr == PORT_END {
            *curr = PORT_START;
        } else {
            *curr += 1;
        }
        if SOCKET_SET
            .bind_check(super::addr::UNSPECIFIED_IP, port, None)
            .is_ok()
        {
            return Ok(port);
        }
        tries += 1;
    }
    ax_err!(AddrInUse, "no available ports!")
}
