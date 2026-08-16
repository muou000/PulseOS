//! Loongson 2K1000 AHCI block-device adapter.

use core::{
    future::{Ready, ready},
    sync::atomic::{Ordering, compiler_fence},
};

use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use simple_ahci::{AhciDriver, Hal};
use spin::Mutex;

use crate::BlockDriverOps;

const NANOS_PER_MILLIS: u64 = 1_000_000;

struct AxAhciHal;

impl Hal for AxAhciHal {
    fn virt_to_phys(vaddr: usize) -> usize {
        axhal::mem::virt_to_phys(vaddr.into()).as_usize()
    }

    fn current_ms() -> u64 {
        axhal::time::monotonic_time_nanos() / NANOS_PER_MILLIS
    }

    fn flush_dcache() {
        // The 2K1000 AHCI engine observes physical DMA buffers. Order CPU
        // stores before a command is issued and after a completed transfer.
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            core::arch::asm!("dbar 0", options(nostack, preserves_flags))
        };
        compiler_fence(Ordering::SeqCst);
    }
}

/// Serialized polling AHCI device for the SATA port wired on the 2K1000.
///
/// The controller is not registered through an IRQ completion path yet. Each
/// operation completes synchronously while holding the controller lock, so the
/// ready futures below remain cancellation-safe and never retain caller DMA
/// buffers after their return.
pub struct Ls2k1000Ahci {
    inner: Mutex<AhciDriver<AxAhciHal>>,
    capacity_blocks: u64,
    block_size: usize,
}

impl Ls2k1000Ahci {
    /// Creates the exclusively-owned AHCI controller at an already mapped MMIO
    /// address.
    ///
    /// # Safety
    ///
    /// `base` must be a valid uncached/device mapping of the board AHCI block,
    /// and no other code may access that controller concurrently.
    pub unsafe fn try_new(base: usize) -> DevResult<Self> {
        if base == 0 {
            return Err(DevError::InvalidParam);
        }
        let driver = unsafe { AhciDriver::<AxAhciHal>::try_new(base) }.ok_or(DevError::Io)?;
        let capacity_blocks = driver.capacity();
        let block_size = driver.block_size();
        if capacity_blocks == 0 || block_size == 0 {
            return Err(DevError::Io);
        }
        log::info!(
            "LS2K1000 AHCI ready: {} blocks, {} bytes/block",
            capacity_blocks,
            block_size
        );
        Ok(Self {
            inner: Mutex::new(driver),
            capacity_blocks,
            block_size,
        })
    }

    fn validate_request(&self, block_id: u64, len: usize) -> DevResult {
        if len == 0 || !len.is_multiple_of(self.block_size) {
            return Err(DevError::InvalidParam);
        }
        let blocks = u64::try_from(len / self.block_size).map_err(|_| DevError::InvalidParam)?;
        let end = block_id.checked_add(blocks).ok_or(DevError::InvalidParam)?;
        (end <= self.capacity_blocks)
            .then_some(())
            .ok_or(DevError::Io)
    }

    fn read_blocks(&self, block_id: u64, buf: &mut [u8]) -> DevResult {
        self.validate_request(block_id, buf.len())?;
        let mut driver = self.inner.lock();
        driver.read(block_id, buf).then_some(()).ok_or(DevError::Io)
    }

    fn write_blocks(&self, block_id: u64, buf: &[u8]) -> DevResult {
        self.validate_request(block_id, buf.len())?;
        let mut driver = self.inner.lock();
        driver
            .write(block_id, buf)
            .then_some(())
            .ok_or(DevError::Io)
    }
}

impl BaseDriverOps for Ls2k1000Ahci {
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn device_name(&self) -> &str {
        "ls2k1000-ahci"
    }
}

impl BlockDriverOps for Ls2k1000Ahci {
    fn num_blocks(&self) -> u64 {
        self.capacity_blocks
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        self.read_blocks(block_id, buf)
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        self.write_blocks(block_id, buf)
    }

    fn flush(&mut self) -> DevResult {
        Ok(())
    }
}

#[cfg(feature = "async")]
impl crate::AsyncBlockDriverOps for Ls2k1000Ahci {
    type ReadFuture<'a>
        = Ready<DevResult>
    where
        Self: 'a;
    type WriteFuture<'a>
        = Ready<DevResult>
    where
        Self: 'a;
    type FlushFuture<'a>
        = Ready<DevResult>
    where
        Self: 'a;

    fn read_block_async<'a>(&'a self, block_id: u64, buf: &'a mut [u8]) -> Self::ReadFuture<'a> {
        ready(self.read_blocks(block_id, buf))
    }

    fn write_block_async<'a>(&'a self, block_id: u64, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        ready(self.write_blocks(block_id, buf))
    }

    fn flush_async(&self) -> Self::FlushFuture<'_> {
        ready(Ok(()))
    }
}
