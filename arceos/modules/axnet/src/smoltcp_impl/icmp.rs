use alloc::sync::Arc;
use core::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use axerrno::{AxError, AxResult, ax_err, ax_err_type};
use axio::PollState;
use axpoll::{IoEvents, Pollable};
use axsync::Mutex;
use smoltcp::{
    iface::SocketHandle,
    socket::icmp::{self, BindError, RecvError, SendError},
    wire::IpAddress,
};

use super::{
    SOCKET_SET, SocketSetWrapper, SocketWaitQueues, block_on_socket_io, interface_ipv4_address,
    register_wait_queue, schedule_poll, socket_deadline, unregister_wait_queue,
};

const IPV4_HEADER_LEN: usize = 20;
const IPPROTO_ICMP: u8 = 1;
const DEFAULT_TTL: u8 = 64;

/// An IPv4 ICMP raw socket backed by smoltcp's identifier-filtered ICMP socket.
pub struct IcmpSocket {
    handle: SocketHandle,
    ident: Mutex<Option<u16>>,
    nonblock: AtomicBool,
    rcv_timeout: AtomicU64,
    snd_timeout: AtomicU64,
    wait_queues: Arc<SocketWaitQueues>,
}

impl IcmpSocket {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let handle = SOCKET_SET.add(SocketSetWrapper::new_icmp_socket());
        let wait_queues = Arc::new(SocketWaitQueues::new());
        register_wait_queue(handle, wait_queues.clone());
        Self {
            handle,
            ident: Mutex::new(None),
            nonblock: AtomicBool::new(false),
            rcv_timeout: AtomicU64::new(0),
            snd_timeout: AtomicU64::new(0),
            wait_queues,
        }
    }

    #[inline]
    pub fn is_nonblocking(&self) -> bool {
        self.nonblock.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_nonblocking(&self, nonblocking: bool) {
        self.nonblock.store(nonblocking, Ordering::Release);
    }

    #[inline]
    pub fn snd_timeout(&self) -> u64 {
        self.snd_timeout.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_snd_timeout(&self, timeout: u64) {
        self.snd_timeout.store(timeout, Ordering::Release);
    }

    #[inline]
    pub fn rcv_timeout(&self) -> u64 {
        self.rcv_timeout.load(Ordering::Acquire)
    }

    #[inline]
    pub fn set_rcv_timeout(&self, timeout: u64) {
        self.rcv_timeout.store(timeout, Ordering::Release);
    }

    pub fn set_socket_ttl(&self, ttl: u8) {
        SOCKET_SET.with_socket_mut::<icmp::Socket, _, _>(self.handle, |socket| {
            socket.set_hop_limit(Some(ttl));
        });
    }

    /// Sends an ICMP Echo packet. The socket is bound lazily to its wire identifier.
    pub fn send_to(&self, buf: &[u8], remote_addr: SocketAddr) -> AxResult<usize> {
        if !matches!(remote_addr.ip(), IpAddr::V4(addr) if !addr.is_unspecified()) {
            return ax_err!(InvalidInput, "ICMP send_to() failed: invalid IPv4 address");
        }
        if buf.len() < 8 || !matches!(buf[0], 0 | 8) {
            return ax_err!(Unsupported, "ICMP raw socket only supports Echo packets");
        }

        let ident = u16::from_be_bytes([buf[4], buf[5]]);
        self.bind_identifier(ident)?;
        let remote_ip = match remote_addr.ip() {
            IpAddr::V4(addr) => IpAddress::Ipv4(smoltcp::wire::Ipv4Address(addr.octets())),
            IpAddr::V6(_) => unreachable!(),
        };

        self.block_on(IoEvents::OUT, socket_deadline(self.snd_timeout()), || {
            let result = SOCKET_SET.with_socket_mut::<icmp::Socket, _, _>(self.handle, |socket| {
                if !socket.is_open() {
                    ax_err!(NotConnected, "ICMP send_to() failed")
                } else if socket.can_send() {
                    socket
                        .send_slice(buf, remote_ip)
                        .map_err(|error| match error {
                            SendError::BufferFull => AxError::WouldBlock,
                            SendError::Unaddressable => {
                                ax_err_type!(InvalidInput, "ICMP send_to() failed")
                            }
                        })?;
                    Ok(buf.len())
                } else {
                    Err(AxError::WouldBlock)
                }
            });
            if result.is_ok() {
                schedule_poll();
            }
            result
        })
    }

    /// Receives a Linux-style IPv4 raw packet, including the IPv4 header.
    pub fn recv_from(&self, buf: &mut [u8]) -> AxResult<(usize, SocketAddr)> {
        self.block_on(IoEvents::IN, socket_deadline(self.rcv_timeout()), || {
            SOCKET_SET.with_socket_mut::<icmp::Socket, _, _>(self.handle, |socket| {
                if !socket.is_open() {
                    return ax_err!(NotConnected, "ICMP recv_from() failed");
                }
                if !socket.can_recv() {
                    return Err(AxError::WouldBlock);
                }

                let (packet, source) = socket.recv().map_err(|error| match error {
                    RecvError::Exhausted => AxError::WouldBlock,
                    RecvError::Truncated => {
                        ax_err_type!(BadState, "ICMP recv_from() failed: truncated packet")
                    }
                })?;
                let source = match source {
                    IpAddress::Ipv4(address) => Ipv4Addr::from(address.0),
                    IpAddress::Ipv6(_) => {
                        return ax_err!(Unsupported, "ICMP recv_from() received IPv6 packet");
                    }
                };
                let destination = if source.is_loopback() {
                    Ipv4Addr::LOCALHOST
                } else {
                    Ipv4Addr::from(interface_ipv4_address().0)
                };
                let copied = copy_raw_ipv4_packet(buf, packet, source, destination);
                Ok((copied, SocketAddr::V4(SocketAddrV4::new(source, 0))))
            })
        })
    }

    pub fn poll(&self) -> AxResult<PollState> {
        SOCKET_SET.with_socket_mut::<icmp::Socket, _, _>(self.handle, |socket| {
            Ok(PollState {
                readable: socket.can_recv(),
                writable: socket.is_open() && socket.can_send(),
            })
        })
    }

    pub fn recv_queue(&self) -> usize {
        SOCKET_SET.with_socket::<icmp::Socket, _, _>(self.handle, |socket| {
            if socket.can_recv() {
                IPV4_HEADER_LEN
            } else {
                0
            }
        })
    }

    pub fn shutdown(&self) {
        // smoltcp ICMP sockets have no close operation; removal happens in Drop.
    }

    fn bind_identifier(&self, ident: u16) -> AxResult {
        let mut bound_ident = self.ident.lock();
        if let Some(current) = *bound_ident {
            return if current == ident {
                Ok(())
            } else {
                ax_err!(InvalidInput, "ICMP identifier changed after socket bind")
            };
        }

        SOCKET_SET.with_socket_mut::<icmp::Socket, _, _>(self.handle, |socket| {
            socket
                .bind(icmp::Endpoint::Ident(ident))
                .map_err(|error| match error {
                    BindError::InvalidState => {
                        ax_err_type!(AlreadyExists, "ICMP socket already bound")
                    }
                    BindError::Unaddressable => {
                        ax_err_type!(InvalidInput, "invalid ICMP identifier")
                    }
                })
        })?;
        *bound_ident = Some(ident);
        Ok(())
    }

    fn block_on<F, T>(
        &self,
        events: IoEvents,
        deadline: Option<axhal::time::TimeValue>,
        mut operation: F,
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
                operation()
            },
        )
    }
}

impl Pollable for IcmpSocket {
    fn poll(&self) -> IoEvents {
        SOCKET_SET.with_socket_mut::<icmp::Socket, _, _>(self.handle, |socket| {
            let mut events = IoEvents::empty();
            if socket.can_recv() {
                events |= IoEvents::IN;
            }
            if socket.is_open() && socket.can_send() {
                events |= IoEvents::OUT;
            }
            events
        })
    }

    fn register(&self, context: &mut core::task::Context<'_>, events: IoEvents) {
        self.wait_queues.register(context, events);
    }
}

impl Drop for IcmpSocket {
    fn drop(&mut self) {
        unregister_wait_queue(self.handle);
        SOCKET_SET.remove(self.handle);
    }
}

fn copy_raw_ipv4_packet(
    output: &mut [u8],
    payload: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> usize {
    let packet_len = IPV4_HEADER_LEN.saturating_add(payload.len());
    let total_len = packet_len.min(u16::MAX as usize);
    let copied_len = output.len().min(total_len);
    if copied_len == 0 {
        return 0;
    }

    let mut header = [0u8; IPV4_HEADER_LEN];
    header[0] = 0x45;
    header[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    header[8] = DEFAULT_TTL;
    header[9] = IPPROTO_ICMP;
    header[12..16].copy_from_slice(&source.octets());
    header[16..20].copy_from_slice(&destination.octets());
    let checksum = internet_checksum(&header);
    header[10..12].copy_from_slice(&checksum.to_be_bytes());

    let header_copied = copied_len.min(IPV4_HEADER_LEN);
    output[..header_copied].copy_from_slice(&header[..header_copied]);
    if copied_len > IPV4_HEADER_LEN {
        output[IPV4_HEADER_LEN..copied_len]
            .copy_from_slice(&payload[..copied_len - IPV4_HEADER_LEN]);
    }
    copied_len
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let Some(byte) = chunks.remainder().first() {
        sum += u16::from_be_bytes([*byte, 0]) as u32;
    }
    while sum > u16::MAX as u32 {
        sum = (sum & u16::MAX as u32) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_ipv4_packet_has_valid_header_and_payload() {
        let payload = [8, 0, 0xf7, 0xff, 0x12, 0x34, 0, 1];
        let mut packet = [0u8; 28];
        assert_eq!(
            copy_raw_ipv4_packet(
                &mut packet,
                &payload,
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
            ),
            packet.len()
        );
        assert_eq!(packet[0], 0x45);
        assert_eq!(u16::from_be_bytes([packet[2], packet[3]]), 28);
        assert_eq!(packet[8], DEFAULT_TTL);
        assert_eq!(packet[9], IPPROTO_ICMP);
        assert_eq!(internet_checksum(&packet[..IPV4_HEADER_LEN]), 0);
        assert_eq!(&packet[IPV4_HEADER_LEN..], payload);
    }

    #[test]
    fn raw_ipv4_packet_respects_short_user_buffer() {
        let mut packet = [0u8; 24];
        assert_eq!(
            copy_raw_ipv4_packet(
                &mut packet,
                &[0xaa; 16],
                Ipv4Addr::LOCALHOST,
                Ipv4Addr::LOCALHOST,
            ),
            packet.len()
        );
        assert_eq!(&packet[IPV4_HEADER_LEN..], &[0xaa; 4]);
    }
}
