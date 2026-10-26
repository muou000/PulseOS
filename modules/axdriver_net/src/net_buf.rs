extern crate alloc;

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::ptr::NonNull;

use spin::Mutex;

use crate::{DevError, DevResult, NetBufPtr};

const MIN_BUFFER_LEN: usize = 1526;
const MAX_BUFFER_LEN: usize = 65535;

/// A RAII network buffer wrapped in a [`Box`].
pub type NetBufBox = Box<NetBuf>;

/// A RAII network buffer.
///
/// It should be allocated from the [`NetBufPool`], and it will be
/// deallocated into the pool automatically when dropped.
///
/// The layout of the buffer is:
///
/// ```text
///   ______________________ capacity ______________________
///  /                                                      \
/// +------------------+------------------+------------------+
/// |      Header      |      Packet      |      Unused      |
/// +------------------+------------------+------------------+
/// |\__ header_len __/ \__ packet_len __/
/// |
/// buf_ptr
/// ```
pub struct NetBuf {
    header_len: usize,
    packet_len: usize,
    capacity: usize,
    buf_ptr: NonNull<u8>,
    pool_offset: usize,
    pool: Arc<NetBufPool>,
    is_borrowed_as_ptr: bool,
}

unsafe impl Send for NetBuf {}
unsafe impl Sync for NetBuf {}

impl NetBuf {
    const unsafe fn get_slice(&self, start: usize, len: usize) -> &[u8] {
        core::slice::from_raw_parts(self.buf_ptr.as_ptr().add(start), len)
    }

    const unsafe fn get_slice_mut(&mut self, start: usize, len: usize) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.buf_ptr.as_ptr().add(start), len)
    }

    /// Returns the capacity of the buffer.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the length of the header part.
    pub const fn header_len(&self) -> usize {
        self.header_len
    }

    /// Returns the header part of the buffer.
    pub const fn header(&self) -> &[u8] {
        unsafe { self.get_slice(0, self.header_len) }
    }

    /// Returns the packet part of the buffer.
    pub const fn packet(&self) -> &[u8] {
        unsafe { self.get_slice(self.header_len, self.packet_len) }
    }

    /// Returns the mutable reference to the packet part.
    pub const fn packet_mut(&mut self) -> &mut [u8] {
        unsafe { self.get_slice_mut(self.header_len, self.packet_len) }
    }

    /// Returns both the header and the packet parts, as a contiguous slice.
    pub const fn packet_with_header(&self) -> &[u8] {
        unsafe { self.get_slice(0, self.header_len + self.packet_len) }
    }

    /// Returns the entire buffer.
    pub const fn raw_buf(&self) -> &[u8] {
        unsafe { self.get_slice(0, self.capacity) }
    }

    /// Returns the mutable reference to the entire buffer.
    pub const fn raw_buf_mut(&mut self) -> &mut [u8] {
        unsafe { self.get_slice_mut(0, self.capacity) }
    }

    /// Set the length of the header part.
    pub fn set_header_len(&mut self, header_len: usize) {
        assert!(
            header_len
                .checked_add(self.packet_len)
                .is_some_and(|sum| sum <= self.capacity),
            "header_len ({header_len}) + packet_len ({}) exceeds capacity ({})",
            self.packet_len,
            self.capacity
        );
        self.header_len = header_len;
    }

    /// Set the length of the packet part.
    pub fn set_packet_len(&mut self, packet_len: usize) {
        assert!(
            self.header_len
                .checked_add(packet_len)
                .is_some_and(|sum| sum <= self.capacity),
            "header_len ({}) + packet_len ({packet_len}) exceeds capacity ({})",
            self.header_len,
            self.capacity
        );
        self.packet_len = packet_len;
    }

    /// Sets both the header and packet lengths atomically, validating that their
    /// sum does not exceed the buffer capacity.
    pub fn set_header_and_packet_len(&mut self, header_len: usize, packet_len: usize) {
        assert!(
            header_len
                .checked_add(packet_len)
                .is_some_and(|sum| sum <= self.capacity),
            "header_len ({header_len}) + packet_len ({packet_len}) exceeds capacity ({})",
            self.capacity
        );
        self.header_len = header_len;
        self.packet_len = packet_len;
    }

    /// Resets the header and packet lengths to 0.
    pub fn reset(&mut self) {
        self.header_len = 0;
        self.packet_len = 0;
    }

    /// Converts the buffer into a [`NetBufPtr`].
    pub fn into_buf_ptr(mut self: Box<Self>) -> NetBufPtr {
        assert!(
            !self.is_borrowed_as_ptr,
            "NetBuf is already borrowed as a NetBufPtr"
        );
        self.is_borrowed_as_ptr = true;
        let buf_ptr = self.packet_mut().as_mut_ptr();
        let len = self.packet_len;
        NetBufPtr::new(
            NonNull::new(Box::into_raw(self) as *mut u8).unwrap(),
            NonNull::new(buf_ptr).unwrap(),
            len,
        )
    }

    /// Restore [`NetBuf`] struct from a raw pointer.
    ///
    /// # Safety
    ///
    /// The caller must uphold all of the following invariants:
    ///
    /// - **Provenance**: `ptr` must have originated from a prior call to
    ///   [`NetBuf::into_buf_ptr`] on a valid [`Box<NetBuf>`]. It must not have
    ///   originated from arbitrary pointers, a different allocator, or an
    ///   incompatible driver buffer representation.
    /// - **Unique consumption**: The caller must transfer exclusive ownership of
    ///   the underlying allocation to this function. The allocation must not have been
    ///   previously restored, freed, or duplicated; calling this function more than once
    ///   for the same original buffer is undefined behavior.
    /// - **Allocation layout**: The memory referenced by `ptr.raw_ptr::<Self>()` must
    ///   still be allocated with the exact layout expected by `Box<NetBuf>`, and its
    ///   internal fields (including pool references and offsets) must remain valid
    ///   and unmodified.
    /// - **Matching buffer pointer**: The packet buffer pointer (`ptr.buf_ptr()`) and
    ///   packet length (`ptr.packet_len()`) must precisely match the packet slice of
    ///   the underlying [`NetBuf`] established by [`NetBuf::into_buf_ptr`] (specifically,
    ///   `ptr.buf_ptr()` must equal `buf.buf_ptr + buf.header_len` and `ptr.packet_len()`
    ///   must equal `buf.packet_len`). They must not have been forged, altered, or
    ///   redirected outside the buffer bounds.
    pub unsafe fn from_buf_ptr(ptr: NetBufPtr) -> Box<Self> {
        // SAFETY: The caller guarantees that `ptr` originated from `into_buf_ptr` on a
        // valid `Box<NetBuf>`, has valid layout, and has not been restored or freed yet.
        // We wrap in `ManuallyDrop` so that assertion panics do not trigger double-free
        // or drop corrupted memory during unwinding.
        let mut raw_buf =
            core::mem::ManuallyDrop::new(unsafe { Box::from_raw(ptr.raw_ptr::<Self>()) });

        assert!(
            raw_buf.is_borrowed_as_ptr,
            "NetBuf restoration invariant violated: buffer was not borrowed via into_buf_ptr or was already restored"
        );
        raw_buf.is_borrowed_as_ptr = false;

        let expected_packet_ptr = unsafe { raw_buf.buf_ptr.as_ptr().add(raw_buf.header_len) };
        assert_eq!(
            ptr.buf_ptr().as_ptr(),
            expected_packet_ptr,
            "NetBufPtr buf_ptr ({:?}) does not match expected packet buffer start ({:?})",
            ptr.buf_ptr().as_ptr(),
            expected_packet_ptr
        );
        assert_eq!(
            ptr.packet_len(),
            raw_buf.packet_len,
            "NetBufPtr packet_len ({}) does not match NetBuf packet_len ({})",
            ptr.packet_len(),
            raw_buf.packet_len
        );

        core::mem::ManuallyDrop::into_inner(raw_buf)
    }
}

impl Drop for NetBuf {
    /// Deallocates the buffer into the [`NetBufPool`].
    fn drop(&mut self) {
        assert!(
            !self.is_borrowed_as_ptr,
            "NetBuf dropped while still borrowed as NetBufPtr"
        );
        self.pool.dealloc(self.pool_offset);
    }
}

/// A pool of [`NetBuf`]s to speed up buffer allocation.
///
/// It divides a large memory into several equal parts for each buffer.
pub struct NetBufPool {
    capacity: usize,
    buf_len: usize,
    pool: Vec<u8>,
    free_list: Mutex<Vec<usize>>,
}

impl NetBufPool {
    /// Creates a new pool with the given `capacity`, and all buffer lengths are
    /// set to `buf_len`.
    pub fn new(capacity: usize, buf_len: usize) -> DevResult<Arc<Self>> {
        if capacity == 0 {
            return Err(DevError::InvalidParam);
        }
        if !(MIN_BUFFER_LEN..=MAX_BUFFER_LEN).contains(&buf_len) {
            return Err(DevError::InvalidParam);
        }

        let pool = vec![0; capacity * buf_len];
        let mut free_list = Vec::with_capacity(capacity);
        for i in 0..capacity {
            free_list.push(i * buf_len);
        }
        Ok(Arc::new(Self {
            capacity,
            buf_len,
            pool,
            free_list: Mutex::new(free_list),
        }))
    }

    /// Returns the capacity of the pool.
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Returns the length of each buffer.
    pub const fn buffer_len(&self) -> usize {
        self.buf_len
    }

    /// Allocates a buffer from the pool.
    ///
    /// Returns `None` if no buffer is available.
    pub fn alloc(self: &Arc<Self>) -> Option<NetBuf> {
        let pool_offset = self.free_list.lock().pop()?;
        let buf_ptr =
            unsafe { NonNull::new(self.pool.as_ptr().add(pool_offset) as *mut u8).unwrap() };
        Some(NetBuf {
            header_len: 0,
            packet_len: 0,
            capacity: self.buf_len,
            buf_ptr,
            pool_offset,
            pool: Arc::clone(self),
            is_borrowed_as_ptr: false,
        })
    }

    /// Allocates a buffer wrapped in a [`Box`] from the pool.
    ///
    /// Returns `None` if no buffer is available.
    pub fn alloc_boxed(self: &Arc<Self>) -> Option<NetBufBox> {
        Some(Box::new(self.alloc()?))
    }

    /// Deallocates a buffer at the given offset.
    ///
    /// `pool_offset` must be a multiple of `buf_len`.
    fn dealloc(&self, pool_offset: usize) {
        assert_eq!(
            pool_offset % self.buf_len,
            0,
            "pool_offset must be a multiple of buf_len"
        );
        assert!(
            pool_offset / self.buf_len < self.capacity,
            "pool_offset out of bounds"
        );
        let mut free_list = self.free_list.lock();
        assert!(
            !free_list.contains(&pool_offset),
            "double free in NetBufPool: offset {pool_offset} already freed"
        );
        free_list.push(pool_offset);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_boundary_lengths_valid() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        assert_eq!(buf.capacity(), 1600);
        assert_eq!(buf.header_len(), 0);
        assert_eq!(buf.packet().len(), 0);

        // Boundary: exact fit
        buf.set_header_len(100);
        buf.set_packet_len(1500);
        assert_eq!(buf.header().len(), 100);
        assert_eq!(buf.packet().len(), 1500);
        assert_eq!(buf.packet_with_header().len(), 1600);
        assert_eq!(buf.raw_buf().len(), 1600);

        // Boundary: 0 and capacity
        buf.set_header_len(0);
        buf.set_packet_len(1600);
        assert_eq!(buf.header().len(), 0);
        assert_eq!(buf.packet().len(), 1600);

        buf.set_packet_len(0);
        buf.set_header_len(1600);
        assert_eq!(buf.header().len(), 1600);
        assert_eq!(buf.packet().len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_header_len_exceeds_capacity_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_header_len(1601);
    }

    #[test]
    #[should_panic]
    fn test_packet_len_exceeds_capacity_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_packet_len(1601);
    }

    #[test]
    #[should_panic]
    fn test_sum_exceeds_capacity_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_header_len(1000);
        buf.set_packet_len(601);
    }

    #[test]
    #[should_panic]
    fn test_header_len_overflow_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_packet_len(100);
        buf.set_header_len(usize::MAX);
    }

    #[test]
    #[should_panic]
    fn test_packet_len_overflow_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_header_len(100);
        buf.set_packet_len(usize::MAX);
    }

    #[test]
    fn test_reset_and_set_header_and_packet_len() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_header_and_packet_len(200, 1200);
        assert_eq!(buf.header_len(), 200);
        assert_eq!(buf.packet().len(), 1200);

        buf.reset();
        assert_eq!(buf.header_len(), 0);
        assert_eq!(buf.packet().len(), 0);
    }

    #[test]
    #[should_panic]
    fn test_set_header_and_packet_len_exceeds_capacity() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc().unwrap();
        buf.set_header_and_packet_len(800, 801);
    }

    #[test]
    fn test_safe_netbufptr_construction_and_access() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc_boxed().unwrap();
        buf.set_header_and_packet_len(14, 100);
        buf.packet_mut()[0] = 0x42;
        buf.packet_mut()[99] = 0x99;

        let mut ptr = NetBufPtr::from(buf);
        assert_eq!(ptr.packet_len(), 100);
        assert_eq!(ptr.packet()[0], 0x42);
        assert_eq!(ptr.packet()[99], 0x99);

        ptr.packet_mut()[0] = 0x43;
        assert_eq!(ptr.packet()[0], 0x43);

        let restored = unsafe { NetBuf::from_buf_ptr(ptr) };
        assert_eq!(restored.header_len(), 14);
        assert_eq!(restored.packet().len(), 100);
        assert_eq!(restored.packet()[0], 0x43);
    }

    #[test]
    #[should_panic]
    fn test_forged_pointer_length_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc_boxed().unwrap();
        buf.set_header_and_packet_len(14, 100);

        let ptr = buf.into_buf_ptr();
        // Tamper with packet length in NetBufPtr
        let forged = NetBufPtr::new(
            NonNull::new(ptr.raw_ptr::<NetBuf>() as *mut u8).unwrap(),
            NonNull::new(ptr.packet().as_ptr() as *mut u8).unwrap(),
            101, // Mismatched length!
        );
        // Forget original to prevent drop
        core::mem::forget(ptr);

        // This must panic due to forged metadata
        let _ = unsafe { NetBuf::from_buf_ptr(forged) };
    }

    #[test]
    #[should_panic]
    fn test_forged_pointer_address_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc_boxed().unwrap();
        buf.set_header_and_packet_len(14, 100);

        let ptr = buf.into_buf_ptr();
        // Tamper with buffer pointer in NetBufPtr
        let forged = NetBufPtr::new(
            NonNull::new(ptr.raw_ptr::<NetBuf>() as *mut u8).unwrap(),
            NonNull::new(unsafe { (ptr.packet().as_ptr() as *mut u8).add(1) }).unwrap(), // Shifted pointer!
            100,
        );
        core::mem::forget(ptr);

        // This must panic due to forged pointer address
        let _ = unsafe { NetBuf::from_buf_ptr(forged) };
    }

    #[test]
    #[should_panic]
    fn test_duplicate_restoration_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let mut buf = pool.alloc_boxed().unwrap();
        buf.set_header_and_packet_len(14, 100);

        let ptr = buf.into_buf_ptr();
        let duplicate = NetBufPtr::new(
            NonNull::new(ptr.raw_ptr::<NetBuf>() as *mut u8).unwrap(),
            NonNull::new(ptr.packet().as_ptr() as *mut u8).unwrap(),
            100,
        );

        // First restoration succeeds
        let _buf1 = unsafe { NetBuf::from_buf_ptr(ptr) };

        // Duplicate restoration must panic
        let _buf2 = unsafe { NetBuf::from_buf_ptr(duplicate) };
    }

    #[test]
    #[should_panic]
    fn test_restoring_unborrowed_netbuf_rejected() {
        let pool = NetBufPool::new(1, 1600).unwrap();
        let buf = pool.alloc_boxed().unwrap();

        // buf was never passed to into_buf_ptr!
        let raw_buf_ptr = Box::into_raw(buf);
        let fake_ptr = NetBufPtr::new(
            NonNull::new(raw_buf_ptr as *mut u8).unwrap(),
            NonNull::new(raw_buf_ptr as *mut u8).unwrap(),
            0,
        );

        // Must panic because buffer is not in borrowed state
        let _ = unsafe { NetBuf::from_buf_ptr(fake_ptr) };
    }

    #[test]
    fn test_pool_reuse_lifecycle() {
        let pool = NetBufPool::new(2, 1600).unwrap();
        assert_eq!(pool.capacity(), 2);

        // Allocate 2 buffers
        let buf1 = pool.alloc_boxed().unwrap();
        let buf2 = pool.alloc_boxed().unwrap();
        assert!(pool.alloc_boxed().is_none());

        // Process buf1 through NetBufPtr
        let mut ptr1 = NetBufPtr::from(buf1);
        ptr1.packet_mut();
        let restored1 = unsafe { NetBuf::from_buf_ptr(ptr1) };
        drop(restored1);

        // Buffer 1 is back in the pool
        let mut reused1 = pool.alloc_boxed().unwrap();
        assert_eq!(reused1.header_len(), 0);
        assert_eq!(reused1.packet().len(), 0);
        reused1.set_header_and_packet_len(20, 100);
        assert_eq!(reused1.header_len(), 20);

        // Free buf2 as well
        let ptr2 = NetBufPtr::from(buf2);
        drop(unsafe { NetBuf::from_buf_ptr(ptr2) });
        drop(reused1);

        // Both are back in the pool
        let b1 = pool.alloc_boxed().unwrap();
        let b2 = pool.alloc_boxed().unwrap();
        assert!(pool.alloc_boxed().is_none());
        drop(b1);
        drop(b2);
    }
}
