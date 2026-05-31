mod fs;
mod inode;
mod util;

use alloc::{sync::Arc, vec, vec::Vec};
use core::num::NonZeroUsize;
use lru::LruCache;

use axdriver::prelude::BlockDriverOps;
use ext4_rs::{BLOCK_SIZE, BlockDevice};
pub use fs::*;
pub use inode::*;
use axsync::Mutex;

pub(crate) struct Ext4Disk<D: BlockDriverOps> {
    dev: Mutex<D>,
    sector_size: usize,
    block_cache: Mutex<LruCache<usize, Vec<u8>>>,
}

impl<D: BlockDriverOps> Ext4Disk<D> {
    pub(crate) fn new(dev: D) -> Arc<Self> {
        let sector_size = dev.block_size();
        Arc::new(Self {
            dev: Mutex::new(dev),
            sector_size,
            block_cache: Mutex::new(LruCache::new(NonZeroUsize::new(512).unwrap())),
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
        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&offset) {
                return data.clone();
            }
        }

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
            raw.drain(0..inner_offset);
            raw.truncate(BLOCK_SIZE);
            return raw;
        }
        if let Err(err) = dev.read_block(first_block, &mut raw) {
            log::error!(
                "ext4 read_offset failed: offset={}, first_block={}, blocks={}, \
                 sector_size={}, num_blocks={}, err={:?}",
                offset,
                first_block,
                blocks,
                self.sector_size,
                total_blocks,
                err
            );
            // Return zeroed buffer instead of panicking
            raw.drain(0..inner_offset);
            raw.truncate(BLOCK_SIZE);
            return raw;
        }
        raw.drain(0..inner_offset);
        raw.truncate(BLOCK_SIZE);

        {
            let mut cache = self.block_cache.lock();
            cache.put(offset, raw.clone());
        }
        raw
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        {
            let mut cache = self.block_cache.lock();
            let mut keys_to_remove = Vec::new();
            for (key, _) in cache.iter() {
                let cached_start = *key;
                let cached_end = cached_start + BLOCK_SIZE;
                let write_start = offset;
                let write_end = offset + data.len();
                if cached_start < write_end && write_start < cached_end {
                    keys_to_remove.push(*key);
                }
            }
            for key in keys_to_remove {
                cache.pop(&key);
            }
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

        // To avoid torn writes, we first pre-read any partial blocks. Since partial
        // blocks can only occur at the beginning (i=0) and the end (i=blocks-1) of
        // the write, we need at most two buffers.
        let mut first_block_buf = None;
        let mut last_block_buf = None;

        let first_block_inner_offset = inner_offset;
        let first_block_write_len = core::cmp::min(self.sector_size - first_block_inner_offset, data.len());

        if first_block_write_len < self.sector_size {
            let mut buf = Vec::with_capacity(self.sector_size);
            unsafe { buf.set_len(self.sector_size) };
            if let Err(err) = dev.read_block(first_block, &mut buf) {
                log::error!(
                    "ext4 write_offset pre-read failed: offset={}, first_block={}, block_id={}, \
                     blocks={}, sector_size={}, num_blocks={}, err={:?}",
                    offset, first_block, first_block, blocks, self.sector_size, total_blocks, err
                );
                return;
            }
            first_block_buf = Some(buf);
        }

        if blocks > 1 {
            let last_data_written = data.len() - ((blocks - 1) * self.sector_size - first_block_inner_offset);
            let last_block_write_len = core::cmp::min(self.sector_size, last_data_written);

            if last_block_write_len < self.sector_size {
                let mut buf = Vec::with_capacity(self.sector_size);
                unsafe { buf.set_len(self.sector_size) };
                let block_id = first_block + (blocks - 1) as u64;
                if let Err(err) = dev.read_block(block_id, &mut buf) {
                    log::error!(
                        "ext4 write_offset pre-read failed: offset={}, first_block={}, block_id={}, \
                         blocks={}, sector_size={}, num_blocks={}, err={:?}",
                        offset, first_block, block_id, blocks, self.sector_size, total_blocks, err
                    );
                    return;
                }
                last_block_buf = Some(buf);
            }
        }

        let mut write_buf = vec![0; blocks * self.sector_size];
        if let Some(ref first_buf) = first_block_buf {
            write_buf[..self.sector_size].copy_from_slice(first_buf);
        }
        if let Some(ref last_buf) = last_block_buf {
            let last_start = (blocks - 1) * self.sector_size;
            write_buf[last_start..].copy_from_slice(last_buf);
        }

        write_buf[inner_offset..inner_offset + data.len()].copy_from_slice(data);

        if let Err(err) = dev.write_block(first_block, &write_buf) {
            log::error!(
                "ext4 write_offset failed: offset={}, first_block={}, blocks={}, \
                 sector_size={}, num_blocks={}, err={:?}",
                offset,
                first_block,
                blocks,
                self.sector_size,
                total_blocks,
                err
            );
        }
    }
}
