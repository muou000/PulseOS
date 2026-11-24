//! Deterministic block-driver boundary checks for target-window provenance.
//! The counted driver supplies bytes in memory; real virtio evidence is separate.

use alloc::{sync::Arc, vec::Vec};
use core::future::{Ready, ready};

use driver::prelude::{
    AsyncBlockDriverOps, BaseDriverOps, BlockDriverOps, DevError, DevResult, DeviceType,
};
use ext4plus::Ext4Read;

#[derive(Clone, Default)]
struct CountedDisk(Arc<spin::Mutex<Vec<(u64, usize)>>>);

impl CountedDisk {
    fn read(&self, sector: u64, bytes: &mut [u8]) -> DevResult {
        if sector >= 128 || bytes.len() % 512 != 0 || bytes.len() / 512 > 128 - sector as usize {
            return Err(DevError::InvalidParam);
        }
        self.0.lock().push((sector, bytes.len()));
        bytes.fill(0x73);
        Ok(())
    }
}

impl BaseDriverOps for CountedDisk {
    fn device_name(&self) -> &str {
        "fault-io-check"
    }
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for CountedDisk {
    fn num_blocks(&self) -> u64 {
        128
    }
    fn block_size(&self) -> usize {
        512
    }
    fn read_block(&mut self, sector: u64, bytes: &mut [u8]) -> DevResult {
        self.read(sector, bytes)
    }
    fn write_block(&mut self, _sector: u64, _bytes: &[u8]) -> DevResult {
        Err(DevError::Unsupported)
    }
    fn flush(&mut self) -> DevResult {
        Ok(())
    }
}

impl AsyncBlockDriverOps for CountedDisk {
    type ReadFuture<'a> = Ready<DevResult>;
    type WriteFuture<'a> = Ready<DevResult>;
    type FlushFuture<'a> = Ready<DevResult>;

    fn read_block_async<'a>(&'a self, sector: u64, bytes: &'a mut [u8]) -> Self::ReadFuture<'a> {
        ready(self.read(sector, bytes))
    }
    fn write_block_async<'a>(&'a self, _sector: u64, _bytes: &'a [u8]) -> Self::WriteFuture<'a> {
        ready(Err(DevError::Unsupported))
    }
    fn flush_async(&self) -> Self::FlushFuture<'_> {
        ready(Ok(()))
    }
}

pub(super) fn run() -> vfs::VfsResult<()> {
    let device = CountedDisk::default();
    let reader = super::Ext4DiskWrapper(super::Ext4Disk::new(device.clone()));
    let mut page = alloc::vec![0; 4096];
    let mut batch = alloc::vec![0; 8192];
    task::future::block_on(async {
        let cold = reader
            .read_with_io(4096, &mut page, 0..4096)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if cold != Some(true) || &*device.0.lock() != &[(8, 4096)] {
            return Err(vfs::VfsError::BadState);
        }
        device.0.lock().clear();
        // First block is resident; the second block really invokes the driver.
        // The selected first-page window must still report no storage read.
        let neighbor = reader
            .read_with_io(4096, &mut batch, 0..4096)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if neighbor != Some(false) || &*device.0.lock() != &[(16, 4096)] {
            return Err(vfs::VfsError::BadState);
        }
        device.0.lock().clear();
        // Select the second page of a different mixed hit/miss run instead.
        let target = reader
            .read_with_io(8192, &mut batch, 4096..8192)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if target != Some(true) || &*device.0.lock() != &[(24, 4096)] {
            return Err(vfs::VfsError::BadState);
        }
        if !batch.iter().all(|byte| *byte == 0x73) {
            return Err(vfs::VfsError::BadState);
        }
        Ok(())
    })?;
    log::info!("MLC_KERNEL PASS fault_io_block_cache_neighbor");
    Ok(())
}
