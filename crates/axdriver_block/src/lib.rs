//! Common traits and types for block storage device drivers (i.e. disk).

#![no_std]
#![cfg_attr(doc, feature(doc_auto_cfg))]

#[cfg(feature = "ramdisk")]
pub mod ramdisk;

#[cfg(feature = "bcm2835-sdhci")]
pub mod bcm2835sdhci;

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
/// # TODO: Integration Points
///
/// - `axfs` block I/O path currently uses synchronous [`BlockDriverOps`]. To fully
///   leverage async I/O, the filesystem layer needs to be wrapped in async tasks
///   and use `axtask::future::block_on()` or native async context.
/// - The `dyn AsyncBlockDriverOps` (object-safe) variant is NOT yet implemented.
///   If dynamic dispatch is needed, a `DynAsyncBlockDriverOps` wrapper trait
///   returning `Pin<Box<dyn Future>>` should be added.
/// - LoongArch64 path: interrupt delivery via MSI-X is wired up but end-to-end
///   async I/O on LA64 should be validated separately.
#[cfg(feature = "async")]
pub trait AsyncBlockDriverOps: BlockDriverOps {
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
    /// The returned future must be `.await`-ed. The task will suspend via
    /// `WaitFuture` until an interrupt signals that the DMA transfer is complete.
    ///
    /// # Safety / Lifetime
    ///
    /// `buf` must remain valid for the entire lifetime `'a` of the returned future,
    /// including across any `.await` suspension points.
    fn read_block_async<'a>(&'a mut self, block_id: u64, buf: &'a mut [u8])
        -> Self::ReadFuture<'a>;

    /// Asynchronously writes blocked data to the given block.
    ///
    /// Same lifetime constraints as [`read_block_async`](Self::read_block_async).
    fn write_block_async<'a>(&'a mut self, block_id: u64, buf: &'a [u8])
        -> Self::WriteFuture<'a>;
}
