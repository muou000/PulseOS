mod fs;
mod inode;
mod util;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

#[allow(unused_imports)]
use axdriver::{AxBlockDevice, prelude::BlockDriverOps};
use ext4_rs::{BLOCK_SIZE, BlockDevice};
pub use fs::*;
pub use inode::*;
use kspin::SpinNoPreempt as Mutex;

pub(crate) struct Ext4Disk {
    dev: Mutex<AxBlockDevice>,
    sector_size: usize,
}

impl Ext4Disk {
    pub(crate) fn new(dev: AxBlockDevice) -> Arc<Self> {
        let sector_size = dev.block_size();
        Arc::new(Self {
            dev: Mutex::new(dev),
            sector_size,
        })
    }

    fn byte_range(&self, offset: usize, len: usize) -> (u64, usize, usize) {
        let first_block = (offset / self.sector_size) as u64;
        let inner_offset = offset % self.sector_size;
        let touched = inner_offset + len;
        let blocks = touched.div_ceil(self.sector_size);
        (first_block, inner_offset, blocks)
    }
}

impl BlockDevice for Ext4Disk {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        let (first_block, inner_offset, blocks) = self.byte_range(offset, BLOCK_SIZE);
        let mut raw = vec![0; blocks * self.sector_size];
        let mut dev = self.dev.lock();
        for i in 0..blocks {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            dev.read_block(first_block + i as u64, &mut raw[start..end])
                .expect("failed to read block for ext4_rs");
        }
        raw[inner_offset..inner_offset + BLOCK_SIZE].to_vec()
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        let (first_block, inner_offset, blocks) = self.byte_range(offset, data.len());
        let mut raw = vec![0; blocks * self.sector_size];
        let mut dev = self.dev.lock();
        for i in 0..blocks {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            dev.read_block(first_block + i as u64, &mut raw[start..end])
                .expect("failed to read block before writing ext4_rs data");
        }
        raw[inner_offset..inner_offset + data.len()].copy_from_slice(data);
        for i in 0..blocks {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            dev.write_block(first_block + i as u64, &raw[start..end])
                .expect("failed to write block for ext4_rs");
        }
    }
}
