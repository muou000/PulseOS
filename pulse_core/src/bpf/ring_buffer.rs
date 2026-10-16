//! BPF Ring Buffer core model, shared memory layout, and MPSC producer (#107).
//!
//! This module provides the `BPF_MAP_TYPE_RINGBUF` backend matching Linux ring buffer
//! semantics:
//! - 2 control pages: Page 0 is consumer page (`consumer_pos` at offset 0), Page 1 is
//!   producer page (`producer_pos` at offset 0, i.e. 4096 bytes from map base).
//! - Data pages start at offset 8192 (`2 * PAGE_SIZE`).
//! - 8-byte header per record with length, busy, and discard flags.
//! - Shared MPSC nonblocking reservation with explicit loss accounting (`ringbuf_lost`).
//! - Readiness notification for epoll/poll.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use axerrno::LinuxError;

pub const BPF_RINGBUF_BUSY_BIT: u32 = 1 << 31;
pub const BPF_RINGBUF_DISCARD_BIT: u32 = 1 << 30;
pub const BPF_RINGBUF_LEN_MASK: u32 = !(BPF_RINGBUF_BUSY_BIT | BPF_RINGBUF_DISCARD_BIT);
pub const BPF_RINGBUF_HDR_SZ: usize = 8;

pub const BPF_RINGBUF_PAGE_SIZE: usize = 4096;
pub const BPF_RINGBUF_CONTROL_PAGES: usize = 2;
pub const BPF_RINGBUF_DATA_OFFSET: usize = BPF_RINGBUF_CONTROL_PAGES * BPF_RINGBUF_PAGE_SIZE; // 8192

pub const BPF_RB_NO_WAKEUP: u64 = 1 << 0;
pub const BPF_RB_FORCE_WAKEUP: u64 = 1 << 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingBufRecord {
    pub data: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RingBufConsumerCounters {
    pub corrupt_records: u64,
    pub discarded_records: u64,
}

pub struct BpfRingBuf {
    data_size: usize,
    raw_base: usize,
    total_size: usize,
    ringbuf_lost: AtomicU64,
    readable_sequence: AtomicU64,
    lock: spin::Mutex<()>,
    consumer_corrupt_records: AtomicU64,
    consumer_discarded_records: AtomicU64,
    #[cfg(target_os = "none")]
    shared_frame: Option<Arc<axmm::SharedFrame>>,
    #[cfg(not(target_os = "none"))]
    _host_storage: Option<Vec<u8>>,
    #[cfg(target_os = "none")]
    read_wait_queue: axtask::WaitQueue,
}

impl core::fmt::Debug for BpfRingBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BpfRingBuf")
            .field("data_size", &self.data_size)
            .field("total_size", &self.total_size)
            .field("consumer_pos", &self.consumer_pos())
            .field("producer_pos", &self.producer_pos())
            .field("ringbuf_lost", &self.ringbuf_lost())
            .finish()
    }
}

impl BpfRingBuf {
    #[cfg(target_os = "none")]
    pub fn new(data_size: usize) -> Result<Arc<Self>, LinuxError> {
        if data_size == 0
            || data_size % BPF_RINGBUF_PAGE_SIZE != 0
            || !data_size.is_power_of_two()
        {
            return Err(LinuxError::EINVAL);
        }
        let nr_data_pages = data_size / BPF_RINGBUF_PAGE_SIZE;
        let total_pages = BPF_RINGBUF_CONTROL_PAGES + nr_data_pages;
        let total_size = total_pages * BPF_RINGBUF_PAGE_SIZE;

        let vaddr = axalloc::global_allocator()
            .alloc_pages(total_pages, memory_addr::PAGE_SIZE_4K)
            .map_err(|_| LinuxError::ENOMEM)?;

        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, total_size);
        }

        let shared_frame = Arc::new(axmm::SharedFrame {
            vaddr,
            page_count: total_pages,
        });

        let rb = Arc::new(Self {
            data_size,
            raw_base: vaddr,
            total_size,
            ringbuf_lost: AtomicU64::new(0),
            readable_sequence: AtomicU64::new(0),
            lock: spin::Mutex::new(()),
            consumer_corrupt_records: AtomicU64::new(0),
            consumer_discarded_records: AtomicU64::new(0),
            shared_frame: Some(shared_frame),
            read_wait_queue: axtask::WaitQueue::new(),
        });
        Ok(rb)
    }

    #[cfg(not(target_os = "none"))]
    pub fn new(data_size: usize) -> Result<Arc<Self>, LinuxError> {
        if data_size == 0
            || data_size % BPF_RINGBUF_PAGE_SIZE != 0
            || !data_size.is_power_of_two()
        {
            return Err(LinuxError::EINVAL);
        }
        let nr_data_pages = data_size / BPF_RINGBUF_PAGE_SIZE;
        let total_pages = BPF_RINGBUF_CONTROL_PAGES + nr_data_pages;
        let total_size = total_pages * BPF_RINGBUF_PAGE_SIZE;

        let mut storage = alloc::vec![0u8; total_size];
        let raw_base = storage.as_mut_ptr() as usize;

        let rb = Arc::new(Self {
            data_size,
            raw_base,
            total_size,
            ringbuf_lost: AtomicU64::new(0),
            readable_sequence: AtomicU64::new(0),
            lock: spin::Mutex::new(()),
            consumer_corrupt_records: AtomicU64::new(0),
            consumer_discarded_records: AtomicU64::new(0),
            _host_storage: Some(storage),
        });
        Ok(rb)
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn total_size(&self) -> usize {
        self.total_size
    }

    pub fn raw_base(&self) -> usize {
        self.raw_base
    }

    pub fn ringbuf_lost(&self) -> u64 {
        self.ringbuf_lost.load(Ordering::Relaxed)
    }

    #[cfg(target_os = "none")]
    pub fn shared_frame(&self) -> Option<Arc<axmm::SharedFrame>> {
        self.shared_frame.clone()
    }

    #[cfg(target_os = "none")]
    pub fn read_wait_queue(&self) -> &axtask::WaitQueue {
        &self.read_wait_queue
    }

    pub fn consumer_pos(&self) -> u64 {
        unsafe {
            // Consumer page is page 0: offset 0
            let ptr = self.raw_base as *const AtomicU64;
            (*ptr).load(Ordering::Acquire)
        }
    }

    pub fn set_consumer_pos(&self, val: u64) {
        unsafe {
            let ptr = self.raw_base as *const AtomicU64;
            (*ptr).store(val, Ordering::Release);
        }
    }

    pub fn producer_pos(&self) -> u64 {
        unsafe {
            // Producer page is page 1: offset 4096
            let ptr = (self.raw_base + BPF_RINGBUF_PAGE_SIZE) as *const AtomicU64;
            (*ptr).load(Ordering::Acquire)
        }
    }

    pub fn set_producer_pos(&self, val: u64) {
        unsafe {
            let ptr = (self.raw_base + BPF_RINGBUF_PAGE_SIZE) as *const AtomicU64;
            (*ptr).store(val, Ordering::Release);
        }
    }

    pub fn is_readable(&self) -> bool {
        self.producer_pos() > self.consumer_pos()
    }

    pub fn poll_event_sequence(&self) -> u64 {
        self.readable_sequence.load(Ordering::Acquire)
    }

    pub fn notify_readable(&self) {
        self.readable_sequence.fetch_add(1, Ordering::Release);
        #[cfg(target_os = "none")]
        self.read_wait_queue.notify_all(true);
    }

    fn write_circular(&self, offset_in_data: usize, bytes: &[u8]) {
        let data_start = (self.raw_base + BPF_RINGBUF_DATA_OFFSET) as *mut u8;
        let space_to_end = self.data_size - offset_in_data;
        if bytes.len() <= space_to_end {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_start.add(offset_in_data), bytes.len());
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), data_start.add(offset_in_data), space_to_end);
                core::ptr::copy_nonoverlapping(
                    bytes.as_ptr().add(space_to_end),
                    data_start,
                    bytes.len() - space_to_end,
                );
            }
        }
    }

    pub fn read_circular(&self, offset_in_data: usize, buf: &mut [u8]) {
        let data_start = (self.raw_base + BPF_RINGBUF_DATA_OFFSET) as *const u8;
        let space_to_end = self.data_size - offset_in_data;
        if buf.len() <= space_to_end {
            unsafe {
                core::ptr::copy_nonoverlapping(data_start.add(offset_in_data), buf.as_mut_ptr(), buf.len());
            }
        } else {
            unsafe {
                core::ptr::copy_nonoverlapping(data_start.add(offset_in_data), buf.as_mut_ptr(), space_to_end);
                core::ptr::copy_nonoverlapping(
                    data_start,
                    buf.as_mut_ptr().add(space_to_end),
                    buf.len() - space_to_end,
                );
            }
        }
    }

    /// Output data using bpf_ringbuf_output semantics with MPSC ordering and explicit loss accounting.
    pub fn output(&self, data: &[u8], flags: u64) -> Result<(), LinuxError> {
        if flags & !(BPF_RB_NO_WAKEUP | BPF_RB_FORCE_WAKEUP) != 0 {
            return Err(LinuxError::EINVAL);
        }

        let payload_len = data.len();
        let rec_size = (BPF_RINGBUF_HDR_SZ + payload_len + 7) & !7;
        if rec_size > self.data_size {
            return Err(LinuxError::E2BIG);
        }

        let _guard = self.lock.lock();
        let prod = self.producer_pos();
        let cons = self.consumer_pos();
        let used = prod.wrapping_sub(cons) as usize;

        if used > self.data_size {
            self.ringbuf_lost.fetch_add(1, Ordering::Relaxed);
            return Err(LinuxError::EAGAIN);
        }

        let avail = self.data_size - used;
        if avail < rec_size {
            self.ringbuf_lost.fetch_add(1, Ordering::Relaxed);
            return Err(LinuxError::EAGAIN);
        }

        // Reservation succeeds: write record header with BUSY bit set
        let data_offset = (prod % self.data_size as u64) as usize;

        // Write header: [len | BUSY, pg_off]
        let mut hdr_bytes = [0u8; 8];
        let busy_len = (payload_len as u32) | BPF_RINGBUF_BUSY_BIT;
        hdr_bytes[0..4].copy_from_slice(&busy_len.to_ne_bytes());
        hdr_bytes[4..8].copy_from_slice(&0u32.to_ne_bytes()); // pg_off = 0
        self.write_circular(data_offset, &hdr_bytes);

        // Write payload
        let payload_offset = (data_offset + BPF_RINGBUF_HDR_SZ) % self.data_size;
        self.write_circular(payload_offset, data);

        // Zero out padding
        let pad_len = rec_size - (BPF_RINGBUF_HDR_SZ + payload_len);
        if pad_len > 0 {
            let pad_offset = (payload_offset + payload_len) % self.data_size;
            let zeroes = [0u8; 8];
            self.write_circular(pad_offset, &zeroes[..pad_len]);
        }

        // Commit: clear BUSY bit in header
        let committed_len = payload_len as u32;
        hdr_bytes[0..4].copy_from_slice(&committed_len.to_ne_bytes());
        self.write_circular(data_offset, &hdr_bytes);

        // Advance producer position
        let new_prod = prod.wrapping_add(rec_size as u64);
        self.set_producer_pos(new_prod);

        // Wakeup / notify if requested or default
        if flags & BPF_RB_NO_WAKEUP == 0 || flags & BPF_RB_FORCE_WAKEUP != 0 {
            self.notify_readable();
        }

        Ok(())
    }

    /// Parse available committed records and advance consumer position.
    pub fn parse_records(&self) -> Result<(Vec<RingBufRecord>, RingBufConsumerCounters), LinuxError> {
        let prod = self.producer_pos();
        let mut cons = self.consumer_pos();

        let used = prod.wrapping_sub(cons) as usize;
        if used > self.data_size {
            self.consumer_corrupt_records.fetch_add(1, Ordering::Relaxed);
            return Err(LinuxError::EINVAL);
        }

        let mut records = Vec::new();
        while prod.wrapping_sub(cons) >= BPF_RINGBUF_HDR_SZ as u64 {
            let offset = (cons % self.data_size as u64) as usize;
            let mut hdr_bytes = [0u8; 8];
            self.read_circular(offset, &mut hdr_bytes);
            let raw_len = u32::from_ne_bytes(hdr_bytes[0..4].try_into().unwrap());

            // If still busy, producer is not done
            if raw_len & BPF_RINGBUF_BUSY_BIT != 0 {
                break;
            }

            let is_discarded = (raw_len & BPF_RINGBUF_DISCARD_BIT) != 0;
            let payload_len = (raw_len & BPF_RINGBUF_LEN_MASK) as usize;
            let rec_size = (BPF_RINGBUF_HDR_SZ + payload_len + 7) & !7;

            if (rec_size as u64) > prod.wrapping_sub(cons) || rec_size > self.data_size {
                self.consumer_corrupt_records.fetch_add(1, Ordering::Relaxed);
                return Err(LinuxError::EINVAL);
            }

            if is_discarded {
                self.consumer_discarded_records.fetch_add(1, Ordering::Relaxed);
            } else {
                let mut data = alloc::vec![0u8; payload_len];
                let payload_offset = (offset + BPF_RINGBUF_HDR_SZ) % self.data_size;
                self.read_circular(payload_offset, &mut data);
                records.push(RingBufRecord { data });
            }

            cons = cons.wrapping_add(rec_size as u64);
            self.set_consumer_pos(cons);
        }

        Ok((
            records,
            RingBufConsumerCounters {
                corrupt_records: self.consumer_corrupt_records.load(Ordering::Relaxed),
                discarded_records: self.consumer_discarded_records.load(Ordering::Relaxed),
            },
        ))
    }
}

impl Drop for BpfRingBuf {
    fn drop(&mut self) {
        #[cfg(target_os = "none")]
        self.read_wait_queue.notify_all(true);
    }
}
