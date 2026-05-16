mod fs;
mod inode;
mod util;

use alloc::{sync::Arc, vec, vec::Vec};

use axdriver::prelude::BlockDriverOps;
use ext4_rs::{BLOCK_SIZE, BlockDevice};
pub use fs::*;
pub use inode::*;
use kspin::SpinNoPreempt as Mutex;

pub(crate) struct Ext4Disk<D: BlockDriverOps> {
    dev: Mutex<D>,
    sector_size: usize,
}

impl<D: BlockDriverOps> Ext4Disk<D> {
    pub(crate) fn new(dev: D) -> Arc<Self> {
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

impl<D: BlockDriverOps + 'static> BlockDevice for Ext4Disk<D> {
    fn read_offset(&self, offset: usize) -> Vec<u8> {
        let (first_block, inner_offset, blocks) = self.byte_range(offset, BLOCK_SIZE);
        let mut raw = vec![0; blocks * self.sector_size];
        let mut dev = self.dev.lock();
        let total_blocks = dev.num_blocks();
        // Boundary check: reject obviously invalid block addresses
        if first_block + blocks as u64 > total_blocks {
            log::error!(
                "ext4 read_offset OOB: offset={:#x}, first_block={}, blocks={}, num_blocks={}",
                offset, first_block, blocks, total_blocks
            );
            // Return zeroed buffer instead of panicking
            return raw[inner_offset..inner_offset + BLOCK_SIZE].to_vec();
        }
        for i in 0..blocks {
            let start = i * self.sector_size;
            let end = start + self.sector_size;
            let block_id = first_block + i as u64;
            if let Err(err) = dev.read_block(block_id, &mut raw[start..end]) {
                log::error!(
                    "ext4 read_offset failed: offset={}, first_block={}, block_id={}, blocks={}, \
                     sector_size={}, num_blocks={}, buf_len={}, err={:?}",
                    offset,
                    first_block,
                    block_id,
                    blocks,
                    self.sector_size,
                    total_blocks,
                    raw[start..end].len(),
                    err
                );
                // Return zeroed buffer instead of panicking
                return raw[inner_offset..inner_offset + BLOCK_SIZE].to_vec();
            }
        }
        raw[inner_offset..inner_offset + BLOCK_SIZE].to_vec()
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let (first_block, inner_offset, blocks) = self.byte_range(offset, data.len());
        let mut dev = self.dev.lock();
        let total_blocks = dev.num_blocks();
        // Boundary check: reject obviously invalid block addresses
        if first_block + blocks as u64 > total_blocks {
            log::error!(
                "ext4 write_offset OOB: offset={:#x}, first_block={}, blocks={}, num_blocks={}",
                offset, first_block, blocks, total_blocks
            );
            return; // Silently drop the write instead of panicking
        }

        let mut block_buf = Vec::with_capacity(self.sector_size);
        // SAFETY: The buffer will be completely filled before we write it to disk.
        // In the case of a partial write, it is populated by `dev.read_block`.
        // In the case of a full write, it is populated by `copy_from_slice`.
        unsafe { block_buf.set_len(self.sector_size) };
        let mut data_written = 0;

        for i in 0..blocks {
            let block_id = first_block + i as u64;
            let is_first = i == 0;

            let block_inner_offset = if is_first { inner_offset } else { 0 };
            let write_len = core::cmp::min(self.sector_size - block_inner_offset, data.len() - data_written);

            if write_len < self.sector_size {
                if let Err(err) = dev.read_block(block_id, &mut block_buf) {
                    log::error!(
                        "ext4 write_offset pre-read failed: offset={}, first_block={}, block_id={}, \
                         blocks={}, sector_size={}, num_blocks={}, err={:?}",
                        offset,
                        first_block,
                        block_id,
                        blocks,
                        self.sector_size,
                        total_blocks,
                        err
                    );
                    return;
                }
            }

            block_buf[block_inner_offset..block_inner_offset + write_len]
                .copy_from_slice(&data[data_written..data_written + write_len]);

            if let Err(err) = dev.write_block(block_id, &block_buf) {
                log::error!(
                    "ext4 write_offset failed: offset={}, first_block={}, block_id={}, blocks={}, \
                     sector_size={}, num_blocks={}, err={:?}",
                    offset,
                    first_block,
                    block_id,
                    blocks,
                    self.sector_size,
                    total_blocks,
                    err
                );
                return;
            }

            data_written += write_len;
        }
    }
}
