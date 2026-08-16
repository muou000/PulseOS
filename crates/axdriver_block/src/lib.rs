//! Common traits and types for block storage device drivers (i.e. disk).

#![no_std]
#![cfg_attr(doc, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "ramdisk")]
pub mod ramdisk;

#[cfg(feature = "bcm2835-sdhci")]
pub mod bcm2835sdhci;

#[cfg(feature = "starfive-jh7110-sdmmc")]
pub mod starfive_jh7110;

#[cfg(feature = "ls2k1000-ahci")]
pub mod ls2k1000_ahci;

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc};
use core::{
    any::Any,
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
};

#[doc(no_inline)]
pub use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use spin::Mutex;

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnedBufferDirection {
    Read,
    Write,
}

struct OwnedBufferEntry {
    id: u64,
    direction: OwnedBufferDirection,
    range: Arc<OwnedBufferRange>,
}

struct OwnedBufferRange {
    start: usize,
    end: usize,
    claim_start: AtomicUsize,
    claim_len: AtomicUsize,
    claimed: AtomicBool,
    _owner: Arc<dyn Any + Send + Sync>,
}

// Both directions share one range registry so a source cannot accidentally be
// registered for a device read and write at the same time.
static OWNED_DMA_BUFFERS: Mutex<BTreeMap<usize, OwnedBufferEntry>> = Mutex::new(BTreeMap::new());
static OWNED_DMA_BUFFER_COUNT: AtomicUsize = AtomicUsize::new(0);
static NEXT_OWNED_DMA_BUFFER_ID: AtomicU64 = AtomicU64::new(1);

fn unregister_owned_buffer(id: u64, start: usize) {
    let mut buffers = OWNED_DMA_BUFFERS.lock();
    if buffers.get(&start).is_some_and(|entry| entry.id == id) {
        buffers.remove(&start);
        OWNED_DMA_BUFFER_COUNT.fetch_sub(1, Ordering::Release);
    }
}

fn register_owned_buffer<T>(
    direction: OwnedBufferDirection,
    start: NonNull<u8>,
    len: usize,
    owner: Arc<T>,
) -> DevResult<(u64, usize)>
where
    T: Any + Send + Sync,
{
    if len == 0 {
        return Err(DevError::InvalidParam);
    }
    let start = start.as_ptr() as usize;
    let end = start.checked_add(len).ok_or(DevError::InvalidParam)?;
    let mut buffers = OWNED_DMA_BUFFERS.lock();
    let overlaps_predecessor = buffers
        .range(..=start)
        .next_back()
        .is_some_and(|(_, entry)| start < entry.range.end);
    let overlaps_successor = buffers
        .range(start..)
        .next()
        .is_some_and(|(_, entry)| entry.range.start < end);
    if overlaps_predecessor || overlaps_successor {
        return Err(DevError::ResourceBusy);
    }
    let id = NEXT_OWNED_DMA_BUFFER_ID.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        return Err(DevError::BadState);
    }
    buffers.insert(
        start,
        OwnedBufferEntry {
            id,
            direction,
            range: Arc::new(OwnedBufferRange {
                start,
                end,
                claim_start: AtomicUsize::new(0),
                claim_len: AtomicUsize::new(0),
                claimed: AtomicBool::new(false),
                _owner: owner,
            }),
        },
    );
    OWNED_DMA_BUFFER_COUNT.fetch_add(1, Ordering::Release);
    Ok((id, start))
}

fn claim_owned_buffer(
    direction: OwnedBufferDirection,
    buffer: NonNull<[u8]>,
) -> Option<Arc<OwnedBufferRange>> {
    if OWNED_DMA_BUFFER_COUNT.load(Ordering::Acquire) == 0 {
        return None;
    }
    let len = buffer.len();
    if len == 0 {
        return None;
    }
    let start = buffer.as_ptr() as *mut u8 as usize;
    let end = start.checked_add(len)?;
    let buffers = OWNED_DMA_BUFFERS.lock();
    let entry = buffers
        .range(..=start)
        .next_back()
        .map(|(_, entry)| entry)
        .filter(|entry| entry.direction == direction && end <= entry.range.end)?;
    if entry
        .range
        .claimed
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return None;
    }
    entry.range.claim_start.store(start, Ordering::Relaxed);
    entry.range.claim_len.store(len, Ordering::Release);
    Some(entry.range.clone())
}

/// Keeps a registered DMA-readable destination alive until its registration is
/// dropped.
///
/// A registration is only an eligibility marker. The block driver clones its
/// owner into an [`OwnedReadBufferLease`] before submitting a direct DMA read,
/// so dropping this value while a request is in flight does not release the
/// backing allocation early.
pub struct OwnedReadBufferRegistration {
    id: u64,
    start: usize,
}

impl Drop for OwnedReadBufferRegistration {
    fn drop(&mut self) {
        unregister_owned_buffer(self.id, self.start);
    }
}

/// Keeps a registered DMA-readable source alive until its registration is
/// dropped.
///
/// The block driver turns a matching source into an [`OwnedWriteBufferLease`]
/// before it submits the descriptor chain. The lease owns a clone of the
/// backing allocation through normal completion or cancellation.
pub struct OwnedWriteBufferRegistration {
    id: u64,
    start: usize,
}

impl Drop for OwnedWriteBufferRegistration {
    fn drop(&mut self) {
        unregister_owned_buffer(self.id, self.start);
    }
}

/// A request-owned reference to a registered direct-read destination.
///
/// The lease is retained by the driver's pending-request table until the
/// device has stopped accessing the buffer, including when the waiting future
/// is cancelled.
pub struct OwnedReadBufferLease {
    range: Arc<OwnedBufferRange>,
}

// SAFETY: Registration requires the owner to keep this stable memory range
// alive and exclusively reserved for device writes. Moving or sharing the
// lease does not change the address or grant safe access to the bytes.
unsafe impl Send for OwnedReadBufferLease {}
unsafe impl Sync for OwnedReadBufferLease {}

impl OwnedReadBufferLease {
    /// Returns the registered subrange length.
    pub fn len(&self) -> usize {
        self.range.claim_len.load(Ordering::Acquire)
    }

    /// Returns whether the registered subrange is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Exposes the destination while the caller has exclusive request access.
    ///
    /// # Safety
    ///
    /// The device must not be accessing the range concurrently unless the
    /// architecture's DMA contract explicitly permits that access through this
    /// same mutable slice. No other reference may access the range until the
    /// corresponding device request is complete.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.range.claim_len.load(Ordering::Acquire);
        let start = self.range.claim_start.load(Ordering::Relaxed);
        // SAFETY: Guaranteed by the registration and caller contracts.
        unsafe { core::slice::from_raw_parts_mut(start as *mut u8, len) }
    }
}

impl Drop for OwnedReadBufferLease {
    fn drop(&mut self) {
        self.range.claimed.store(false, Ordering::Release);
    }
}

/// A request-owned reference to a registered direct-write source.
///
/// The driver retains this lease in its pending-request table until the device
/// has finished reading the source bytes, including when the waiting future is
/// cancelled.
pub struct OwnedWriteBufferLease {
    range: Arc<OwnedBufferRange>,
}

// SAFETY: Registration requires an immutable, stable source range. The lease
// only exposes a shared slice and retains the owner until DMA completion.
unsafe impl Send for OwnedWriteBufferLease {}
unsafe impl Sync for OwnedWriteBufferLease {}

impl OwnedWriteBufferLease {
    /// Returns the registered subrange length.
    pub fn len(&self) -> usize {
        self.range.claim_len.load(Ordering::Acquire)
    }

    /// Returns whether the registered subrange is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Exposes the immutable source while the request owns its DMA lifetime.
    ///
    /// # Safety
    ///
    /// No mutable access to the source may occur while the device can still
    /// read it. Registration and the lease ownership contract enforce that for
    /// the direct-write call sites.
    pub unsafe fn as_slice(&self) -> &[u8] {
        let len = self.range.claim_len.load(Ordering::Acquire);
        let start = self.range.claim_start.load(Ordering::Relaxed);
        // SAFETY: Guaranteed by the registration and caller contracts.
        unsafe { core::slice::from_raw_parts(start as *const u8, len) }
    }
}

impl Drop for OwnedWriteBufferLease {
    fn drop(&mut self) {
        self.range.claimed.store(false, Ordering::Release);
    }
}

/// Registers a physically contiguous destination for cancellation-safe direct
/// block reads.
///
/// The registered range may be claimed in smaller subranges. Claims clone
/// `owner`, extending the allocation lifetime independently of the returned
/// registration guard.
///
/// # Safety
///
/// - `start..start + len` must remain valid, writable, and at a stable virtual
///   and physical address until both the registration and all driver leases are
///   dropped.
/// - The range must be physically contiguous because the current block queue
///   describes it with one VirtIO descriptor.
/// - Safe code must not access the range while a read using this registration
///   may be in flight, including after the waiting future is cancelled.
/// - The allocation represented by `owner` must cover the entire range.
pub unsafe fn register_owned_read_buffer<T>(
    start: NonNull<u8>,
    len: usize,
    owner: Arc<T>,
) -> DevResult<OwnedReadBufferRegistration>
where
    T: Any + Send + Sync,
{
    let (id, start) = register_owned_buffer(OwnedBufferDirection::Read, start, len, owner)?;
    Ok(OwnedReadBufferRegistration { id, start })
}

/// Claims a registered range for one direct block read.
///
/// Returns `None` for ordinary borrowed buffers, which keeps the existing
/// request-owned bounce-buffer path as the safe fallback.
pub fn claim_owned_read_buffer(buffer: NonNull<[u8]>) -> Option<OwnedReadBufferLease> {
    claim_owned_buffer(OwnedBufferDirection::Read, buffer)
        .map(|range| OwnedReadBufferLease { range })
}

/// Registers a physically contiguous immutable source for cancellation-safe
/// direct block writes.
///
/// The registered range may be claimed in smaller subranges. Claims clone the
/// owner, extending allocation lifetime independently of the registration.
///
/// # Safety
///
/// - `start..start + len` must remain valid, readable, and stable until both
///   the registration and all driver leases are dropped.
/// - The range must be physically contiguous because the current VirtIO queue
///   describes it with one data descriptor.
/// - Safe code must not mutate the range while a write using this registration
///   may be in flight, including after the waiting future is cancelled.
/// - The allocation represented by `owner` must cover the entire range.
pub unsafe fn register_owned_write_buffer<T>(
    start: NonNull<u8>,
    len: usize,
    owner: Arc<T>,
) -> DevResult<OwnedWriteBufferRegistration>
where
    T: Any + Send + Sync,
{
    let (id, start) = register_owned_buffer(OwnedBufferDirection::Write, start, len, owner)?;
    Ok(OwnedWriteBufferRegistration { id, start })
}

/// Claims a registered range for one direct block write.
///
/// Ordinary borrowed sources return `None` and continue through the driver's
/// request-owned bounce-buffer path.
pub fn claim_owned_write_buffer(buffer: NonNull<[u8]>) -> Option<OwnedWriteBufferLease> {
    claim_owned_buffer(OwnedBufferDirection::Write, buffer)
        .map(|range| OwnedWriteBufferLease { range })
}

/// Operations that require a block storage device driver to implement.
pub trait BlockDriverOps: BaseDriverOps {
    /// The number of blocks in this storage device.
    ///
    /// The total size of the device is `num_blocks() * block_size()`.
    fn num_blocks(&self) -> u64;
    /// The size of each block in bytes.
    fn block_size(&self) -> usize;

    /// Reads blocked data from the given block.
    ///
    /// The size of the buffer may exceed the block size, in which case multiple
    /// contiguous blocks will be read.
    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult;

    /// Writes blocked data to the given block.
    ///
    /// The size of the buffer may exceed the block size, in which case multiple
    /// contiguous blocks will be written.
    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult;

    /// Flushes the device to write all pending data to the storage.
    fn flush(&mut self) -> DevResult;
}

/// Async operations for block storage devices, backed by interrupt-driven I/O.
///
/// This trait uses Generic Associated Types (GAT) to return zero-cost futures
/// without boxing. Requires the `async` feature to be enabled.
///
/// # Design Notes
///
/// The implementation should:
/// 1. Submit request-owned buffers via `*_nb()` while holding only the
///    driver's queue-state lock.
/// 2. Return `Pending` after associating the current waker with the request's
///    queue token.
/// 3. Drain used descriptors in the interrupt path and wake the matching
///    request plus any submitters waiting for queue space.
/// 4. Retain request buffers after cancellation until the device has completed
///    the descriptor chain.
///
/// # Object safety
///
/// `+ Send + Sync` is required on the trait itself so that
/// `Arc<dyn AsyncBlockDriverOps + Send + Sync>` (the unified handle used by
/// `arceos::axfs::disk::SharedBlockDevice`) is valid. Implementors do not need
/// to provide separate `unsafe impl Send/Sync` — the bound enforces them.
///
/// # Integration Points
///
/// - `axfs` block I/O path is built around `SharedBlockDevice`, whose inner
///   handle is `Arc<dyn DynAsyncBlockDriverOps + Send + Sync>`. Async methods
///   take `&self`, allowing independent requests to be in flight without an
///   outer device mutex.
/// - RISC-V MMIO and LoongArch64 PCI/MSI-X use the same request state machine.
#[cfg(feature = "async")]
pub trait AsyncBlockDriverOps: BlockDriverOps + Send + Sync {
    /// Future type returned by [`read_block_async`](Self::read_block_async).
    type ReadFuture<'a>: core::future::Future<Output = DevResult> + Send + 'a
    where
        Self: 'a;

    /// Future type returned by [`write_block_async`](Self::write_block_async).
    type WriteFuture<'a>: core::future::Future<Output = DevResult> + Send + 'a
    where
        Self: 'a;

    /// Future type returned by [`flush_async`](Self::flush_async).
    type FlushFuture<'a>: core::future::Future<Output = DevResult> + Send + 'a
    where
        Self: 'a;

    /// Asynchronously reads blocked data from the given block.
    ///
    /// The returned future must be `.await`-ed. Implementations may suspend the
    /// task until an interrupt signals that the transfer is complete.
    ///
    /// # Safety / Lifetime
    ///
    /// `buf` must remain valid for the entire lifetime `'a` of the returned future,
    /// including across any `.await` suspension points. Implementations must also
    /// be cancellation-safe: after the returned future is dropped, the driver must
    /// not access `buf` or any other storage owned by the future.
    fn read_block_async<'a>(&'a self, block_id: u64, buf: &'a mut [u8]) -> Self::ReadFuture<'a>;

    /// Asynchronously writes blocked data to the given block.
    ///
    /// Same lifetime and cancellation-safety constraints as
    /// [`read_block_async`](Self::read_block_async).
    fn write_block_async<'a>(&'a self, block_id: u64, buf: &'a [u8]) -> Self::WriteFuture<'a>;

    /// Asynchronously flushes all writes accepted before this call.
    fn flush_async(&self) -> Self::FlushFuture<'_>;
}

/// Object-safe counterpart to [`AsyncBlockDriverOps`].
///
/// Because [`AsyncBlockDriverOps`] carries a generic associated type, it is
/// **not** dyn-compatible: `Box<dyn AsyncBlockDriverOps>` is rejected by the
/// compiler (`E0038`). To represent a clonable, type-erased handle such as
/// `Arc<dyn DynAsyncBlockDriverOps + Send + Sync>` (used by
/// `arceos::axfs::disk::SharedBlockDevice`), we provide this alternate trait
/// whose futures are boxed.
///
/// # Blanket implementation
///
/// Every `T: AsyncBlockDriverOps + Send + Sync + 'static` automatically
/// obtains a `DynAsyncBlockDriverOps` impl via the blanket impl below, so
/// concrete drivers do not need to implement this trait by hand.
#[cfg(feature = "async")]
pub trait DynAsyncBlockDriverOps: BlockDriverOps + Send + Sync + 'static {
    fn read_block_async_dyn<'a>(
        &'a self,
        block_id: u64,
        buf: &'a mut [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>;

    fn write_block_async_dyn<'a>(
        &'a self,
        block_id: u64,
        buf: &'a [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>;

    fn flush_async_dyn(
        &self,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + '_>>;
}

#[cfg(feature = "async")]
impl<T> DynAsyncBlockDriverOps for T
where
    T: AsyncBlockDriverOps + Send + Sync + 'static,
{
    fn read_block_async_dyn<'a>(
        &'a self,
        block_id: u64,
        buf: &'a mut [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>> {
        Box::pin(<Self as AsyncBlockDriverOps>::read_block_async(
            self, block_id, buf,
        ))
    }

    fn write_block_async_dyn<'a>(
        &'a self,
        block_id: u64,
        buf: &'a [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>> {
        Box::pin(<Self as AsyncBlockDriverOps>::write_block_async(
            self, block_id, buf,
        ))
    }

    fn flush_async_dyn(
        &self,
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + '_>> {
        Box::pin(<Self as AsyncBlockDriverOps>::flush_async(self))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::{boxed::Box, sync::Arc, vec};
    use core::{
        ptr::NonNull,
        sync::atomic::{AtomicUsize, Ordering},
    };

    use super::*;

    struct TestOwner {
        data: Box<[u8]>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for TestOwner {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn test_owner(len: usize) -> (Arc<TestOwner>, NonNull<u8>, Arc<AtomicUsize>) {
        let drops = Arc::new(AtomicUsize::new(0));
        let mut owner = Arc::new(TestOwner {
            data: vec![0; len].into_boxed_slice(),
            drops: drops.clone(),
        });
        let ptr = NonNull::new(Arc::get_mut(&mut owner).unwrap().data.as_mut_ptr()).unwrap();
        (owner, ptr, drops)
    }

    #[test]
    fn registered_subrange_keeps_owner_alive_after_guard_drop() {
        assert_eq!(
            core::mem::size_of::<OwnedReadBufferLease>(),
            core::mem::size_of::<usize>()
        );
        let (owner, ptr, drops) = test_owner(128);
        let registration = unsafe {
            register_owned_read_buffer(ptr, 128, owner.clone()).expect("registration failed")
        };
        let subrange = NonNull::slice_from_raw_parts(
            NonNull::new(unsafe { ptr.as_ptr().add(32) }).unwrap(),
            64,
        );
        let mut lease = claim_owned_read_buffer(subrange).expect("registered subrange not claimed");
        assert!(claim_owned_read_buffer(subrange).is_none());

        drop(registration);
        drop(owner);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        unsafe { lease.as_mut_slice() }.fill(0xa5);
        drop(lease);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(claim_owned_read_buffer(subrange).is_none());
    }

    #[test]
    fn registered_write_subrange_keeps_owner_alive_after_guard_drop() {
        assert_eq!(
            core::mem::size_of::<OwnedWriteBufferLease>(),
            core::mem::size_of::<usize>()
        );
        let (owner, ptr, drops) = test_owner(128);
        let registration = unsafe {
            register_owned_write_buffer(ptr, 128, owner.clone()).expect("registration failed")
        };
        let subrange = NonNull::slice_from_raw_parts(
            NonNull::new(unsafe { ptr.as_ptr().add(32) }).unwrap(),
            64,
        );
        let lease = claim_owned_write_buffer(subrange).expect("registered subrange not claimed");
        assert!(claim_owned_write_buffer(subrange).is_none());

        drop(registration);
        drop(owner);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(unsafe { lease.as_slice() }.iter().all(|byte| *byte == 0));
        drop(lease);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(claim_owned_write_buffer(subrange).is_none());
    }

    #[test]
    fn overlapping_registration_is_rejected() {
        let (owner, ptr, _) = test_owner(64);
        let registration = unsafe {
            register_owned_read_buffer(ptr, 64, owner.clone()).expect("registration failed")
        };
        let overlap = NonNull::new(unsafe { ptr.as_ptr().add(16) }).unwrap();
        assert!(matches!(
            unsafe { register_owned_read_buffer(overlap, 16, owner) },
            Err(DevError::ResourceBusy)
        ));
        drop(registration);
    }

    #[test]
    fn read_and_write_registrations_cannot_overlap() {
        let (owner, ptr, _) = test_owner(64);
        let registration = unsafe {
            register_owned_read_buffer(ptr, 64, owner.clone()).expect("registration failed")
        };
        assert!(matches!(
            unsafe { register_owned_write_buffer(ptr, 64, owner) },
            Err(DevError::ResourceBusy)
        ));
        drop(registration);
    }

    #[test]
    fn ordered_registry_checks_successors_and_allows_adjacent_ranges() {
        let (owner, ptr, _) = test_owner(192);
        let upper = NonNull::new(unsafe { ptr.as_ptr().add(128) }).unwrap();
        let upper_registration = unsafe {
            register_owned_read_buffer(upper, 64, owner.clone()).expect("registration failed")
        };
        let overlaps_successor = NonNull::new(unsafe { ptr.as_ptr().add(96) }).unwrap();
        assert!(matches!(
            unsafe { register_owned_read_buffer(overlaps_successor, 64, owner.clone()) },
            Err(DevError::ResourceBusy)
        ));

        let lower_registration = unsafe {
            register_owned_read_buffer(ptr, 128, owner).expect("adjacent registration failed")
        };
        drop(lower_registration);
        drop(upper_registration);
    }

    #[test]
    fn unregistered_and_empty_ranges_are_not_claimed() {
        let (owner, ptr, _) = test_owner(32);
        let empty = NonNull::slice_from_raw_parts(ptr, 0);
        assert!(claim_owned_read_buffer(empty).is_none());
        assert!(claim_owned_read_buffer(NonNull::slice_from_raw_parts(ptr, 32)).is_none());
        assert!(matches!(
            unsafe { register_owned_read_buffer(ptr, 0, owner) },
            Err(DevError::InvalidParam)
        ));
    }
}
