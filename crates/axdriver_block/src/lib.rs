//! Common traits and types for block storage device drivers (i.e. disk).

#![no_std]
#![cfg_attr(doc, feature(doc_auto_cfg))]

extern crate alloc;

#[cfg(feature = "ramdisk")]
pub mod ramdisk;

#[cfg(feature = "bcm2835-sdhci")]
pub mod bcm2835sdhci;

use alloc::boxed::Box;

#[doc(no_inline)]
pub use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};

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
/// 1. Acquire the device lock, submit the request via `*_nb()`, then release the lock.
/// 2. Enter a `loop`: check `peek_used() == Some(token)`; if not ready, `.await`
///    a [`WaitFuture`] registered on the device's `WaitQueue`.
/// 3. When the interrupt fires, `notify_all()` wakes up all registered wakers,
///    resuming the future. Re-check the condition to handle spurious wakeups.
/// 4. Acquire the lock again and call `complete_*()`.
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
///   handle is `Arc<dyn AsyncBlockDriverOps + Send + Sync>`. The Arc is
///   cloned across the async boundary (no outer `Mutex<Box<dyn …>>`), which
///   avoids `E0599: Box<dyn BlockDriverOps> not Clone`.
/// - LoongArch64 path: interrupt delivery via MSI-X is wired up but end-to-end
///   async I/O on LA64 should be validated separately.
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
    fn read_block_async<'a>(&'a mut self, block_id: u64, buf: &'a mut [u8])
        -> Self::ReadFuture<'a>;

    /// Asynchronously writes blocked data to the given block.
    ///
    /// Same lifetime and cancellation-safety constraints as
    /// [`read_block_async`](Self::read_block_async).
    fn write_block_async<'a>(&'a mut self, block_id: u64, buf: &'a [u8])
        -> Self::WriteFuture<'a>;
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
        &'a mut self,
        block_id: u64,
        buf: &'a mut [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>;

    fn write_block_async_dyn<'a>(
        &'a mut self,
        block_id: u64,
        buf: &'a [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>;
}

#[cfg(feature = "async")]
impl<T> DynAsyncBlockDriverOps for T
where
    T: AsyncBlockDriverOps + Send + Sync + 'static,
{
    fn read_block_async_dyn<'a>(
        &'a mut self,
        block_id: u64,
        buf: &'a mut [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>> {
        Box::pin(<Self as AsyncBlockDriverOps>::read_block_async(self, block_id, buf))
    }

    fn write_block_async_dyn<'a>(
        &'a mut self,
        block_id: u64,
        buf: &'a [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>> {
        Box::pin(<Self as AsyncBlockDriverOps>::write_block_async(self, block_id, buf))
    }
}
