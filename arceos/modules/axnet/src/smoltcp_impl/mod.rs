mod addr;
mod bench;
mod dns;
mod listen_table;

mod tcp;
mod udp;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use axerrno::{AxError, AxResult};
use core::cell::RefCell;
use core::future::{Future, poll_fn};
use core::ops::DerefMut;
use core::pin::pin;
use core::task::Poll;

use axdriver::prelude::*;
use axhal::time::{
    NANOS_PER_MICROS, TimeValue, monotonic_time, monotonic_time_nanos as current_time_nanos,
    ticks_to_nanos,
};
use axpoll::IoEvents;
use axsync::Mutex;
use axdriver_net::{DevError, NetBufPtr};
use lazyinit::LazyInit;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{self, AnySocket, Socket};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr};

use self::listen_table::ListenTable;

pub use self::dns::dns_query;
pub use self::tcp::TcpSocket;
pub use self::udp::UdpSocket;
pub use addr::{from_core_sockaddr, into_core_sockaddr};
#[allow(unused)]
macro_rules! env_or_default {
    ($key:literal) => {
        match option_env!($key) {
            Some(val) => val,
            None => "",
        }
    };
}

const DNS_SEVER: &str = "8.8.8.8";

const RANDOM_SEED: u64 = 0xA2CE_05A2_CE05_A2CE;
const STANDARD_MTU: usize = 1500;
const TCP_RX_BUF_LEN: usize = 256 * 1024;
const TCP_TX_BUF_LEN: usize = 256 * 1024;
const UDP_RX_BUF_LEN: usize = 4 * 1024 * 1024;
const UDP_TX_BUF_LEN: usize = 4 * 1024 * 1024;
const LISTEN_QUEUE_SIZE: usize = 512;

static LISTEN_TABLE: LazyInit<ListenTable> = LazyInit::new();
static SOCKET_SET: LazyInit<SocketSetWrapper> = LazyInit::new();
static SOCKET_WAIT_QUEUES: LazyInit<Mutex<BTreeMap<SocketHandle, SocketWaitEntry>>> =
    LazyInit::new();
pub static NET_WAIT_QUEUE: axtask::WaitQueue = axtask::WaitQueue::new();

pub(crate) struct SocketWaitQueues {
    read: axtask::WaitQueue,
    write: axtask::WaitQueue,
    any: axtask::WaitQueue,
}

impl SocketWaitQueues {
    pub(crate) const fn new() -> Self {
        Self {
            read: axtask::WaitQueue::new(),
            write: axtask::WaitQueue::new(),
            any: axtask::WaitQueue::new(),
        }
    }

    fn queue(&self, events: IoEvents) -> &axtask::WaitQueue {
        if events.intersects(IoEvents::IN | IoEvents::RDHUP) {
            &self.read
        } else {
            debug_assert!(events.intersects(IoEvents::OUT));
            &self.write
        }
    }

    fn notify(&self, events: IoEvents) {
        if events.intersects(IoEvents::IN | IoEvents::RDHUP) {
            self.read.notify_all(true);
        }
        if events.intersects(IoEvents::OUT) {
            self.write.notify_all(true);
        }
        if !events.is_empty() {
            self.any.notify_all(true);
        }
    }

    fn register(&self, context: &mut core::task::Context<'_>, events: IoEvents) {
        if events.intersects(IoEvents::IN | IoEvents::RDHUP) {
            self.read.register_waker(context.waker());
        }
        if events.intersects(IoEvents::OUT) {
            self.write.register_waker(context.waker());
        }
    }
}

#[derive(Clone, Copy)]
enum SocketWaitKind {
    Normal,
    ListenerChild,
}

struct SocketWaitEntry {
    queues: Arc<SocketWaitQueues>,
    kind: SocketWaitKind,
}

mod loopback;
static LOOPBACK_DEV: LazyInit<Mutex<LoopbackDev>> = LazyInit::new();
static LOOPBACK: LazyInit<Mutex<Interface>> = LazyInit::new();
use self::loopback::LoopbackDev;

const IP: &str = env_or_default!("AX_IP");
const GATEWAY: &str = env_or_default!("AX_GW");
const IP_PREFIX: u8 = 24;

static ETH0: LazyInit<InterfaceWrapper> = LazyInit::new();

struct SocketSetWrapper<'a>(Mutex<SocketSet<'a>>);

struct DeviceWrapper {
    inner: RefCell<AxNetDevice>, // use `RefCell` is enough since it's wrapped in `Mutex` in `InterfaceWrapper`.
}

struct InterfaceWrapper {
    name: &'static str,
    ether_addr: EthernetAddress,
    dev: Mutex<DeviceWrapper>,
    iface: Mutex<Interface>,
}

impl<'a> SocketSetWrapper<'a> {
    fn new() -> Self {
        Self(Mutex::new(SocketSet::new(vec![])))
    }

    pub fn new_tcp_socket() -> socket::tcp::Socket<'a> {
        let tcp_rx_buffer = socket::tcp::SocketBuffer::new(vec![0; TCP_RX_BUF_LEN]);
        let tcp_tx_buffer = socket::tcp::SocketBuffer::new(vec![0; TCP_TX_BUF_LEN]);
        socket::tcp::Socket::new(tcp_rx_buffer, tcp_tx_buffer)
    }

    pub fn new_udp_socket() -> socket::udp::Socket<'a> {
        let udp_rx_buffer = socket::udp::PacketBuffer::new(
            vec![socket::udp::PacketMetadata::EMPTY; 4096],
            vec![0; UDP_RX_BUF_LEN],
        );
        let udp_tx_buffer = socket::udp::PacketBuffer::new(
            vec![socket::udp::PacketMetadata::EMPTY; 4096],
            vec![0; UDP_TX_BUF_LEN],
        );
        socket::udp::Socket::new(udp_rx_buffer, udp_tx_buffer)
    }

    pub fn new_dns_socket() -> socket::dns::Socket<'a> {
        let server_addr = DNS_SEVER.parse().expect("invalid DNS server address");
        socket::dns::Socket::new(&[server_addr], vec![])
    }

    pub fn add<T: AnySocket<'a>>(&self, socket: T) -> SocketHandle {
        let handle = self.0.lock().add(socket);
        debug!("socket {}: created", handle);
        handle
    }

    pub fn with_socket<T: AnySocket<'a>, R, F>(&self, handle: SocketHandle, f: F) -> R
    where
        F: FnOnce(&T) -> R,
    {
        let set = self.0.lock();
        let socket = set.get(handle);
        f(socket)
    }

    pub fn with_socket_mut<T: AnySocket<'a>, R, F>(&self, handle: SocketHandle, f: F) -> R
    where
        F: FnOnce(&mut T) -> R,
    {
        let mut set = self.0.lock();
        let socket = set.get_mut(handle);
        f(socket)
    }

    pub fn bind_check(&self, addr: IpAddress, port: u16, self_handle: Option<SocketHandle>) -> AxResult {
        let mut sockets = self.0.lock();
        for item in sockets.iter_mut() {
            if Some(item.0) == self_handle {
                continue;
            }
            match item.1 {
                Socket::Tcp(s) => {
                    let local_addr = s.get_bound_endpoint();
                    let addr_conflict = local_addr.addr.is_none()
                        || addr::is_unspecified(addr)
                        || local_addr.addr == Some(addr);
                    if addr_conflict && local_addr.port == port {
                        return Err(AxError::AddrInUse);
                    }
                }
                Socket::Udp(s) => {
                    let endpoint = s.endpoint();
                    let addr_conflict = endpoint.addr.is_none()
                        || addr::is_unspecified(addr)
                        || endpoint.addr == Some(addr);
                    if addr_conflict && endpoint.port == port {
                        return Err(AxError::AddrInUse);
                    }
                }
                _ => continue,
            };
        }
        Ok(())
    }

    pub fn poll_interfaces(&self) {
        let timestamp =
            Instant::from_micros_const((current_time_nanos() / NANOS_PER_MICROS) as i64);
        let mut readiness_may_have_changed = false;
        #[cfg(feature = "monolithic")]
        {
            readiness_may_have_changed |= LOOPBACK.lock().poll(
                timestamp,
                LOOPBACK_DEV.lock().deref_mut(),
                &mut self.0.lock(),
            );
        }

        readiness_may_have_changed |= ETH0.poll(&self.0);

        // Determine which sockets are ready while holding the socket-set lock,
        // but wake their tasks only after all network locks have been released.
        // Waking a task may enter the scheduler synchronously and must not leave
        // the global socket set locked if scheduling is delayed.
        let ready_wait_queues: Vec<_> = {
            let mut sockets = self.0.lock();
            // Incoming TCP packets register listener children while holding
            // this lock, so all paths acquire the socket set before the map.
            let wq_map = SOCKET_WAIT_QUEUES.lock();
            sockets
                .iter_mut()
                .filter_map(|(handle, socket)| {
                    let entry = wq_map.get(&handle)?;
                    let events = match (socket, entry.kind) {
                        (Socket::Tcp(s), SocketWaitKind::Normal) => {
                            let mut events = IoEvents::empty();
                            if s.can_recv() || !s.may_recv() {
                                events |= IoEvents::IN;
                            }
                            if s.can_send() || !s.may_send() {
                                events |= IoEvents::OUT;
                            }
                            events
                        }
                        (Socket::Tcp(s), SocketWaitKind::ListenerChild) => {
                            if matches!(
                                s.state(),
                                socket::tcp::State::Listen | socket::tcp::State::SynReceived
                            ) {
                                IoEvents::empty()
                            } else {
                                IoEvents::IN
                            }
                        }
                        (Socket::Udp(s), SocketWaitKind::Normal) => {
                            let mut events = IoEvents::empty();
                            if s.can_recv() {
                                events |= IoEvents::IN;
                            }
                            if s.can_send() {
                                events |= IoEvents::OUT;
                            }
                            events
                        }
                        _ => IoEvents::empty(),
                    };
                    (!events.is_empty()).then(|| (Arc::clone(&entry.queues), events))
                })
                .collect()
        };
        for (queues, events) in ready_wait_queues {
            queues.notify(events);
        }
        if readiness_may_have_changed {
            NET_WAIT_QUEUE.notify_all(true);
        }
    }

    pub fn remove(&self, handle: SocketHandle) {
        self.0.lock().remove(handle);
        debug!("socket {}: destroyed", handle);
    }
}

#[allow(unused)]
impl InterfaceWrapper {
    fn new(name: &'static str, dev: AxNetDevice, ether_addr: EthernetAddress) -> Self {
        let mut config = Config::new(HardwareAddress::Ethernet(ether_addr));
        config.random_seed = RANDOM_SEED;

        let mut dev = DeviceWrapper::new(dev);
        let iface = Mutex::new(Interface::new(config, &mut dev, Self::current_time()));
        Self {
            name,
            ether_addr,
            dev: Mutex::new(dev),
            iface,
        }
    }

    fn current_time() -> Instant {
        Instant::from_micros_const((current_time_nanos() / NANOS_PER_MICROS) as i64)
    }

    pub fn name(&self) -> &str {
        self.name
    }

    pub fn ethernet_address(&self) -> EthernetAddress {
        self.ether_addr
    }

    pub fn setup_ip_addr(&self, ip: IpAddress, prefix_len: u8) {
        let mut iface = self.iface.lock();
        iface.update_ip_addrs(|ip_addrs| {
            ip_addrs.push(IpCidr::new(ip, prefix_len)).unwrap();
        });
    }

    pub fn setup_gateway(&self, gateway: IpAddress) {
        let mut iface = self.iface.lock();
        match gateway {
            IpAddress::Ipv4(v4) => iface.routes_mut().add_default_ipv4_route(v4).unwrap(),
            IpAddress::Ipv6(v6) => iface.routes_mut().add_default_ipv6_route(v6).unwrap(),
        };
    }

    pub fn poll(&self, sockets: &Mutex<SocketSet>) -> bool {
        let mut dev = self.dev.lock();
        let mut iface = self.iface.lock();
        let mut sockets = sockets.lock();
        let timestamp = Self::current_time();
        iface.poll(timestamp, dev.deref_mut(), &mut sockets)
    }
}

impl DeviceWrapper {
    fn new(inner: AxNetDevice) -> Self {
        Self {
            inner: RefCell::new(inner),
        }
    }
}

impl Device for DeviceWrapper {
    type RxToken<'a> = AxNetRxToken<'a> where Self: 'a;
    type TxToken<'a> = AxNetTxToken<'a> where Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut dev = self.inner.borrow_mut();
        if let Err(e) = dev.recycle_tx_buffers() {
            warn!("recycle_tx_buffers failed: {:?}", e);
            return None;
        }

        if !dev.can_transmit() {
            return None;
        }
        let rx_buf = match dev.receive() {
            Ok(buf) => buf,
            Err(err) => {
                if !matches!(err, DevError::Again) {
                    warn!("receive failed: {:?}", err);
                }
                return None;
            }
        };
        Some((AxNetRxToken(&self.inner, rx_buf), AxNetTxToken(&self.inner)))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let mut dev = self.inner.borrow_mut();
        if let Err(e) = dev.recycle_tx_buffers() {
            warn!("recycle_tx_buffers failed: {:?}", e);
            return None;
        }
        if dev.can_transmit() {
            Some(AxNetTxToken(&self.inner))
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = 1514;
        caps.max_burst_size = None;
        caps.medium = Medium::Ethernet;
        caps
    }
}

struct AxNetRxToken<'a>(&'a RefCell<AxNetDevice>, NetBufPtr);
struct AxNetTxToken<'a>(&'a RefCell<AxNetDevice>);

impl<'a> RxToken for AxNetRxToken<'a> {
    fn preprocess(&self, sockets: &mut SocketSet<'_>) {
        snoop_tcp_packet(self.1.packet(), sockets).ok();
    }

    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut rx_buf = self.1;
        trace!(
            "RECV {} bytes: {:02X?}",
            rx_buf.packet_len(),
            rx_buf.packet()
        );
        let result = f(rx_buf.packet_mut());
        self.0.borrow_mut().recycle_rx_buffer(rx_buf).unwrap();
        result
    }
}

impl<'a> TxToken for AxNetTxToken<'a> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut dev = self.0.borrow_mut();
        let mut tx_buf = dev.alloc_tx_buffer(len).unwrap();
        let ret = f(tx_buf.packet_mut());
        trace!("SEND {} bytes: {:02X?}", len, tx_buf.packet());
        dev.transmit(tx_buf).unwrap();
        ret
    }
}

fn snoop_tcp_packet(buf: &[u8], sockets: &mut SocketSet<'_>) -> Result<(), smoltcp::wire::Error> {
    use smoltcp::wire::{EthernetFrame, IpProtocol, Ipv4Packet, TcpPacket};

    let ether_frame = EthernetFrame::new_checked(buf)?;
    let ipv4_packet = Ipv4Packet::new_checked(ether_frame.payload())?;

    if ipv4_packet.next_header() == IpProtocol::Tcp {
        let tcp_packet = TcpPacket::new_checked(ipv4_packet.payload())?;
        let src_addr = (ipv4_packet.src_addr(), tcp_packet.src_port()).into();
        let dst_addr = (ipv4_packet.dst_addr(), tcp_packet.dst_port()).into();
        let is_first = tcp_packet.syn() && !tcp_packet.ack();
        if is_first {
            // create a socket for the first incoming TCP packet, as the later accept() returns.
            LISTEN_TABLE.incoming_tcp_packet(src_addr, dst_addr, sockets);
        }
    }
    Ok(())
}

/// Poll the network stack.
///
/// It may receive packets from the NIC and process them, and transmit queued
/// packets to the NIC.
pub fn poll_interfaces() {
    SOCKET_SET.poll_interfaces();
}

/// Returns the delay until the next timer expires.
pub fn poll_delay() -> Option<smoltcp::time::Duration> {
    let timestamp = Instant::from_micros_const((current_time_nanos() / NANOS_PER_MICROS) as i64);

    #[cfg(feature = "monolithic")]
    let delay_loopback = {
        if LOOPBACK.is_inited() {
            // Keep the same lock order as `poll_interfaces`: interface first,
            // then the global socket set. Reversing this order can deadlock
            // with an application task polling the network stack.
            let mut iface = LOOPBACK.lock();
            let sockets = SOCKET_SET.0.lock();
            iface.poll_delay(timestamp, &sockets)
        } else {
            None
        }
    };
    #[cfg(not(feature = "monolithic"))]
    let delay_loopback = None;

    let delay_eth0 = if ETH0.is_inited() {
        let mut iface = ETH0.iface.lock();
        let sockets = SOCKET_SET.0.lock();
        iface.poll_delay(timestamp, &sockets)
    } else {
        None
    };

    match (delay_loopback, delay_eth0) {
        (Some(d1), Some(d2)) => Some(d1.min(d2)),
        (Some(d), None) | (None, Some(d)) => Some(d),
        (None, None) => None,
    }
}

/// Benchmark raw socket transmit bandwidth.
pub fn bench_transmit() {
    ETH0.dev.lock().bench_transmit_bandwidth();
}

/// Benchmark raw socket receive bandwidth.
pub fn bench_receive() {
    ETH0.dev.lock().bench_receive_bandwidth();
}

/// Add multicast_addr to the loopback device.
pub fn add_membership(multicast_addr: IpAddress, _interface_addr: IpAddress) {
    let timestamp = Instant::from_micros_const((current_time_nanos() / NANOS_PER_MICROS) as i64);
    let _ = LOOPBACK.lock().join_multicast_group(
        LOOPBACK_DEV.lock().deref_mut(),
        multicast_addr,
        timestamp,
    );
}

pub(crate) fn init(_net_dev: AxNetDevice) {
    let mut device = LoopbackDev::new(Medium::Ip);
    let config = Config::new(smoltcp::wire::HardwareAddress::Ip);

    let mut iface = Interface::new(
        config,
        &mut device,
        Instant::from_micros_const((current_time_nanos() / NANOS_PER_MICROS) as i64),
    );
    iface.update_ip_addrs(|ip_addrs| {
        ip_addrs
            .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
            .unwrap();
    });
    LOOPBACK.init_once(Mutex::new(iface));
    LOOPBACK_DEV.init_once(Mutex::new(device));

    let ether_addr = EthernetAddress(_net_dev.mac_address().0);
    let eth0 = InterfaceWrapper::new("eth0", _net_dev, ether_addr);

    let ip = IP.parse().expect("invalid IP address");
    let gateway = GATEWAY.parse().expect("invalid gateway IP address");
    eth0.setup_ip_addr(ip, IP_PREFIX);
    eth0.setup_gateway(gateway);

    ETH0.init_once(eth0);
    info!("created net interface {:?}:", ETH0.name());
    info!("  ether:    {}", ETH0.ethernet_address());
    info!("  ip:       {}/{}", ip, IP_PREFIX);
    info!("  gateway:  {}", gateway);

    SOCKET_SET.init_once(SocketSetWrapper::new());
    SOCKET_WAIT_QUEUES.init_once(Mutex::new(BTreeMap::new()));
    LISTEN_TABLE.init_once(ListenTable::new());

    #[cfg(feature = "multitask")]
    axtask::spawn(|| {
        struct NetWaker;
        impl alloc::task::Wake for NetWaker {
            fn wake(self: Arc<Self>) {
                crate::NET_WAIT_QUEUE.notify_all(true);
            }
            fn wake_by_ref(self: &Arc<Self>) {
                crate::NET_WAIT_QUEUE.notify_all(true);
            }
        }

        let waker = core::task::Waker::from(Arc::new(NetWaker));

        loop {
            poll_interfaces();

            if ETH0.is_inited() {
                let dev = ETH0.dev.lock();
                let inner = dev.inner.borrow();
                if let Some(poll_set) = inner.poll_set() {
                    poll_set.register(&waker);
                }
            }

            let delay = poll_delay();
            if let Some(d) = delay {
                let duration = core::time::Duration::from_micros(d.total_micros());
                crate::NET_WAIT_QUEUE.wait_timeout(duration);
            } else {
                crate::NET_WAIT_QUEUE.wait();
            }
        }
    });
}

pub(crate) fn register_wait_queue(handle: SocketHandle, queues: Arc<SocketWaitQueues>) {
    SOCKET_WAIT_QUEUES.lock().insert(
        handle,
        SocketWaitEntry {
            queues,
            kind: SocketWaitKind::Normal,
        },
    );
}

pub(crate) fn register_listener_wait_queue(handle: SocketHandle, queues: Arc<SocketWaitQueues>) {
    SOCKET_WAIT_QUEUES.lock().insert(
        handle,
        SocketWaitEntry {
            queues,
            kind: SocketWaitKind::ListenerChild,
        },
    );
}

pub(crate) fn unregister_wait_queue(handle: SocketHandle) {
    SOCKET_WAIT_QUEUES.lock().remove(&handle);
}

pub(crate) fn deadline_from_ticks(ticks: u64) -> TimeValue {
    monotonic_time()
        .checked_add(core::time::Duration::from_nanos(ticks_to_nanos(ticks)))
        .unwrap_or(core::time::Duration::MAX)
}

pub(crate) fn socket_deadline(ticks: u64) -> Option<TimeValue> {
    (ticks != 0).then(|| deadline_from_ticks(ticks))
}

pub(crate) fn block_on_socket_io<F, T>(
    queue: &axtask::WaitQueue,
    nonblocking: bool,
    deadline: Option<TimeValue>,
    mut op: F,
) -> AxResult<T>
where
    F: FnMut() -> AxResult<T>,
{
    if nonblocking {
        return op();
    }

    let wait_for_io = async {
        loop {
            match op() {
                Err(AxError::WouldBlock) => {}
                result => return result,
            }

            // Register before checking readiness again. This closes the window
            // where an event could arrive after the first check but before the
            // task became visible to the notifier.
            let mut wait = pin!(queue.wait_async());
            let already_notified =
                poll_fn(|cx| Poll::Ready(wait.as_mut().poll(cx).is_ready())).await;

            match op() {
                Err(AxError::WouldBlock) => {}
                result => return result,
            }

            if !already_notified {
                wait.await;
            }
        }
    };

    axtask::future::block_on(async {
        axtask::future::timeout_at(deadline, wait_for_io)
            .await
            .map_err(|_| AxError::TimedOut)?
    })
}

/// Check if an IP address is a local interface IP (loopback, unspecified, or dynamic ETH0 IP).
pub fn is_local_ip(ip: &core::net::IpAddr) -> bool {
    if ip.is_unspecified() || ip.is_loopback() {
        return true;
    }
    if ETH0.is_inited() {
        let iface = ETH0.iface.lock();
        for cidr in iface.ip_addrs() {
            let addr = cidr.address();
            match (ip, addr) {
                (core::net::IpAddr::V4(v4), smoltcp::wire::IpAddress::Ipv4(smol_v4)) => {
                    if v4.octets() == smol_v4.0 {
                        return true;
                    }
                }
                (core::net::IpAddr::V6(v6), smoltcp::wire::IpAddress::Ipv6(smol_v6)) => {
                    if v6.octets() == smol_v6.0 {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    false
}
