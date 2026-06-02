use alloc::{boxed::Box, collections::VecDeque};
use core::ops::{Deref, DerefMut};

use axerrno::{ax_err, AxError, AxResult};
use axsync::Mutex;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp::{self, State};
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};

use super::{SocketSetWrapper, LISTEN_QUEUE_SIZE, SOCKET_SET};

const PORT_NUM: usize = 65536;

struct ListenTableEntry {
    listen_endpoint: IpListenEndpoint,
    syn_queue: VecDeque<SocketHandle>,
}

impl ListenTableEntry {
    pub fn new(listen_endpoint: IpListenEndpoint) -> Self {
        Self {
            listen_endpoint,
            syn_queue: VecDeque::with_capacity(LISTEN_QUEUE_SIZE),
        }
    }

    #[inline]
    fn can_accept(&self, dst: IpAddress) -> bool {
        match self.listen_endpoint.addr {
            Some(addr) => addr == dst,
            None => true,
        }
    }
}

impl Drop for ListenTableEntry {
    fn drop(&mut self) {
        for &handle in &self.syn_queue {
            SOCKET_SET.remove(handle);
        }
    }
}

pub struct ListenTable {
    tcp: Box<[Mutex<Option<Box<ListenTableEntry>>>]>,
}

impl ListenTable {
    pub fn new() -> Self {
        let tcp = unsafe {
            let mut buf = Box::new_uninit_slice(PORT_NUM);
            for i in 0..PORT_NUM {
                buf[i].write(Mutex::new(None));
            }
            buf.assume_init()
        };
        Self { tcp }
    }

    pub fn can_listen(&self, port: u16) -> bool {
        self.tcp[port as usize].lock().is_none()
    }

    pub fn listen(&self, listen_endpoint: IpListenEndpoint) -> AxResult {
        let port = listen_endpoint.port;
        assert_ne!(port, 0);
        let mut entry = self.tcp[port as usize].lock();
        if entry.is_none() {
            *entry = Some(Box::new(ListenTableEntry::new(listen_endpoint)));
            Ok(())
        } else {
            ax_err!(AddrInUse, "socket listen() failed")
        }
    }

    pub fn unlisten(&self, port: u16) {
        debug!("TCP socket unlisten on {}", port);
        let entry = {
            let mut guard = self.tcp[port as usize].lock();
            guard.take()
        };
        drop(entry);
    }

    pub fn can_accept(&self, port: u16) -> AxResult<bool> {
        let handles: alloc::vec::Vec<SocketHandle> = {
            if let Some(entry) = self.tcp[port as usize].lock().deref() {
                entry.syn_queue.iter().copied().collect()
            } else {
                return ax_err!(InvalidInput, "socket accept() failed: not listen");
            }
        };
        let res = handles.into_iter().any(|handle| is_connected(handle));
        log::debug!("LISTEN_TABLE::can_accept: port={}, res={}", port, res);
        Ok(res)
    }

    pub fn accept(&self, port: u16) -> AxResult<(SocketHandle, (IpEndpoint, IpEndpoint))> {
        log::debug!("LISTEN_TABLE::accept: port={}", port);
        loop {
            let handles: alloc::vec::Vec<SocketHandle> = {
                if let Some(entry) = self.tcp[port as usize].lock().deref() {
                    entry.syn_queue.iter().copied().collect()
                } else {
                    return ax_err!(InvalidInput, "socket accept() failed: not listen");
                }
            };

            let connected_idx = handles
                .iter()
                .position(|&handle| is_connected(handle));

            let idx = match connected_idx {
                Some(idx) => idx,
                None => return Err(AxError::WouldBlock),
            };

            let handle_to_remove = handles[idx];

            let mut entry_guard = self.tcp[port as usize].lock();
            if let Some(entry) = entry_guard.deref_mut() {
                let syn_queue = &mut entry.syn_queue;
                if let Some(actual_idx) = syn_queue.iter().position(|&h| h == handle_to_remove) {
                    let handle = syn_queue.swap_remove_front(actual_idx).unwrap();
                    drop(entry_guard);
                    if is_closed(handle) {
                        SOCKET_SET.remove(handle);
                        return ax_err!(ConnectionReset, "socket accept() failed: connection reset");
                    } else {
                        log::debug!("LISTEN_TABLE::accept: successfully returning handle {}", handle);
                        return Ok((handle, get_addr_tuple(handle)));
                    }
                }
                // If the handle was accepted/removed by another thread/call, loop back and try again.
            } else {
                return ax_err!(InvalidInput, "socket accept() failed: not listen");
            }
        }
    }

    pub fn incoming_tcp_packet(
        &self,
        src: IpEndpoint,
        dst: IpEndpoint,
        sockets: &mut SocketSet<'_>,
    ) {
        log::debug!("incoming_tcp_packet: src={}, dst={}", src, dst);
        if let Some(entry) = self.tcp[dst.port as usize].lock().deref_mut() {
            log::debug!("incoming_tcp_packet: found entry for port {}", dst.port);
            if !entry.can_accept(dst.addr) {
                log::warn!("incoming_tcp_packet: cannot accept address {}", dst.addr);
                return;
            }
            if entry.syn_queue.len() >= LISTEN_QUEUE_SIZE {
                warn!("SYN queue overflow!");
                return;
            }
            let mut socket = SocketSetWrapper::new_tcp_socket();
            if socket.listen(entry.listen_endpoint).is_ok() {
                let handle = sockets.add(socket);
                debug!(
                    "TCP socket {}: prepare for connection {} -> {}",
                    handle, src, entry.listen_endpoint
                );
                entry.syn_queue.push_back(handle);
                log::debug!("incoming_tcp_packet: added new socket handle {} to syn_queue", handle);
            } else {
                log::error!("incoming_tcp_packet: failed to listen on new socket");
            }
        } else {
            log::warn!("incoming_tcp_packet: no listening socket on port {}", dst.port);
        }
    }
}

fn is_connected(handle: SocketHandle) -> bool {
    SOCKET_SET.with_socket::<tcp::Socket, _, _>(handle, |socket| {
        !matches!(socket.state(), State::Listen | State::SynReceived)
    })
}

fn is_closed(handle: SocketHandle) -> bool {
    SOCKET_SET
        .with_socket::<tcp::Socket, _, _>(handle, |socket| matches!(socket.state(), State::Closed))
}

fn get_addr_tuple(handle: SocketHandle) -> (IpEndpoint, IpEndpoint) {
    SOCKET_SET.with_socket::<tcp::Socket, _, _>(handle, |socket| {
        (
            socket.local_endpoint().unwrap(),
            socket.remote_endpoint().unwrap(),
        )
    })
}
