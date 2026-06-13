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

impl<D: BlockDriverOps + 'static> Ext4Disk<D> {
    fn read_block_aligned(&self, block_offset: usize, buf: &mut [u8]) {
        {
            let mut cache = self.block_cache.lock();
            if let Some(data) = cache.get(&block_offset) {
                buf.copy_from_slice(data);
                return;
            }
        }

        let (first_block, inner_offset, blocks) = self.byte_range(block_offset, BLOCK_SIZE);
        let mut raw = vec![0; blocks * self.sector_size];
        let mut dev = self.dev.lock();
        let total_blocks = dev.num_blocks();
        if first_block + blocks as u64 > total_blocks {
            log::error!(
                "ext4 read_block_aligned OOB: block_offset={:#x}, first_block={}, blocks={}, num_blocks={}",
                block_offset, first_block, blocks, total_blocks
            );
            raw.drain(0..inner_offset);
            raw.truncate(BLOCK_SIZE);
            buf.copy_from_slice(&raw);
            return;
        }
        if let Err(err) = dev.read_block(first_block, &mut raw) {
            log::error!(
                "ext4 read_block_aligned failed: block_offset={}, first_block={}, blocks={}, \
                 sector_size={}, num_blocks={}, err={:?}",
                block_offset,
                first_block,
                blocks,
                self.sector_size,
                total_blocks,
                err
            );
            raw.drain(0..inner_offset);
            raw.truncate(BLOCK_SIZE);
            buf.copy_from_slice(&raw);
            return;
        }
        raw.drain(0..inner_offset);
        raw.truncate(BLOCK_SIZE);

        buf.copy_from_slice(&raw);
        {
            let mut cache = self.block_cache.lock();
            cache.put(block_offset, raw);
        }
    }
}

impl<D: BlockDriverOps + 'static> BlockDevice for Ext4Disk<D> {
    fn read_offset(&self, offset: usize, buf: &mut [u8]) {
        let mut bytes_read = 0;
        while bytes_read < buf.len() {
            let current_offset = offset + bytes_read;
            let block_offset = (current_offset / BLOCK_SIZE) * BLOCK_SIZE;
            let inner_offset = current_offset % BLOCK_SIZE;
            let current_len = core::cmp::min(BLOCK_SIZE - inner_offset, buf.len() - bytes_read);

            if inner_offset == 0 && current_len == BLOCK_SIZE {
                self.read_block_aligned(block_offset, &mut buf[bytes_read..bytes_read + current_len]);
            } else {
                let mut block_data = [0u8; BLOCK_SIZE];
                self.read_block_aligned(block_offset, &mut block_data);
                buf[bytes_read..bytes_read + current_len]
                    .copy_from_slice(&block_data[inner_offset..inner_offset + current_len]);
            }
            bytes_read += current_len;
        }
    }

    fn write_offset(&self, offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        {
            let start_align = (offset / BLOCK_SIZE) * BLOCK_SIZE;
            let end_align = ((offset + data.len() - 1) / BLOCK_SIZE) * BLOCK_SIZE;
            let mut cache = self.block_cache.lock();
            let mut current = start_align;
            while current <= end_align {
                let start = core::cmp::max(offset, current);
                let end = core::cmp::min(offset + data.len(), current + BLOCK_SIZE);
                if start < end {
                    let overlap_start = start - current;
                    let overlap_end = end - current;
                    let data_start = start - offset;
                    let data_len = end - start;

                    if let Some(cached_data) = cache.get_mut(&current) {
                        cached_data[overlap_start..overlap_end]
                            .copy_from_slice(&data[data_start..data_start + data_len]);
                    } else if overlap_start == 0 && overlap_end == BLOCK_SIZE {
                        cache.put(current, data[data_start..data_start + data_len].to_vec());
                    }
                }
                current += BLOCK_SIZE;
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
            let mut buf = vec![0u8; self.sector_size];
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
                let mut buf = vec![0u8; self.sector_size];
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
