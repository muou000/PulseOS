mod fs;
mod inode;
mod util;

use alloc::{sync::Arc, vec, vec::Vec};
use core::num::NonZeroUsize;
use lru::LruCache;

use axdriver::prelude::BlockDriverOps;
pub use fs::*;
pub use inode::*;
use axsync::Mutex;

struct CacheBlock {
    data: Vec<u8>,
    dirty: bool,
}

pub(crate) struct Ext4Disk<D: BlockDriverOps> {
    dev: Mutex<D>,
    sector_size: usize,
    block_cache: Mutex<LruCache<usize, CacheBlock>>,
    block_size: core::sync::atomic::AtomicUsize,
}

impl<D: BlockDriverOps + 'static> crate::disk::DiskFlushable for Ext4Disk<D> {
    fn flush_disk(&self) -> axdriver::prelude::DevResult<()> {
        let dirty_blocks = {
            let mut cache = self.block_cache.lock();
            let mut list = vec![];
            for (&offset, block) in cache.iter_mut() {
                if block.dirty {
                    list.push((offset, block.data.clone()));
                    block.dirty = false;
                }
            }
            list
        };
        for (offset, data) in dirty_blocks {
            self.write_block_to_disk(offset, &data);
        }
        self.dev.lock().flush()
    }
}

impl<D: BlockDriverOps + 'static> Ext4Disk<D> {
    pub(crate) fn new(dev: D) -> Arc<Self> {
        let sector_size = dev.block_size();
        let disk = Arc::new(Self {
            dev: Mutex::new(dev),
            sector_size,
            block_cache: Mutex::new(LruCache::new(NonZeroUsize::new(512).unwrap())),
            block_size: core::sync::atomic::AtomicUsize::new(4096),
        });
        crate::disk::DISK_FLUSHERS.lock().push(Arc::downgrade(&disk) as _);
        disk
    }

    fn byte_range(&self, offset: usize, len: usize) -> (u64, usize, usize) {
        let first_block = (offset / self.sector_size) as u64;
        let inner_offset = offset % self.sector_size;
        let touched = inner_offset + len;
        let blocks = touched.div_ceil(self.sector_size);
        (first_block, inner_offset, blocks)
    }

    fn write_block_to_disk(&self, block_offset: usize, data: &[u8]) {
        let (first_block, _, _) = self.byte_range(block_offset, data.len());
        let mut dev = self.dev.lock();
        if let Err(err) = dev.write_block(first_block, data) {
            log::error!(
                "ext4 write_block_to_disk failed: block_offset={}, err={:?}",
                block_offset,
                err
            );
        }
    }

    fn read_block_aligned(&self, block_offset: usize, buf: &mut [u8]) {
        let block_size = self.block_size();
        {
            let mut cache = self.block_cache.lock();
            if let Some(block) = cache.get(&block_offset) {
                buf.copy_from_slice(&block.data);
                return;
            }
        }

        let (first_block, inner_offset, blocks) = self.byte_range(block_offset, block_size);
        let mut raw = vec![0; blocks * self.sector_size];
        let mut dev = self.dev.lock();

        // Re-check the cache under dev.lock()
        {
            let mut cache = self.block_cache.lock();
            if let Some(block) = cache.get(&block_offset) {
                buf.copy_from_slice(&block.data);
                return;
            }
        }

        let total_blocks = dev.num_blocks();
        if first_block + blocks as u64 > total_blocks {
            log::error!(
                "ext4 read_block_aligned OOB: block_offset={:#x}, first_block={}, blocks={}, num_blocks={}",
                block_offset, first_block, blocks, total_blocks
            );
            raw.drain(0..inner_offset);
            raw.truncate(block_size);
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
            raw.truncate(block_size);
            buf.copy_from_slice(&raw);
            return;
        }
        
        // Drop the device lock before doing cache update and possible writeback
        drop(dev);

        raw.drain(0..inner_offset);
        raw.truncate(block_size);

        buf.copy_from_slice(&raw);

        let mut to_write = None;
        {
            let mut cache = self.block_cache.lock();
            let block = CacheBlock { data: raw, dirty: false };
            if !cache.contains(&block_offset) && cache.len() >= cache.cap().get() {
                if let Some((ev_offset, ev_block)) = cache.pop_lru() {
                    if ev_block.dirty {
                        to_write = Some((ev_offset, ev_block.data));
                    }
                }
            }
            cache.put(block_offset, block);
        }
        if let Some((offset, data)) = to_write {
            self.write_block_to_disk(offset, &data);
        }
    }

    pub fn read_offset(&self, offset: usize, buf: &mut [u8]) {
        log::debug!("ext4 read_offset: offset={}, len={}", offset, buf.len());
        let block_size = self.block_size();
        let mut bytes_read = 0;
        while bytes_read < buf.len() {
            let current_offset = offset + bytes_read;
            let block_offset = (current_offset / block_size) * block_size;
            let inner_offset = current_offset % block_size;
            let current_len = core::cmp::min(block_size - inner_offset, buf.len() - bytes_read);

            if inner_offset == 0 && current_len == block_size {
                self.read_block_aligned(block_offset, &mut buf[bytes_read..bytes_read + current_len]);
            } else {
                let mut block_data = vec![0u8; block_size];
                self.read_block_aligned(block_offset, &mut block_data);
                buf[bytes_read..bytes_read + current_len]
                    .copy_from_slice(&block_data[inner_offset..inner_offset + current_len]);
            }
            bytes_read += current_len;
        }
        log::debug!("ext4 read_offset done: offset={}", offset);
    }

    pub fn write_offset(&self, offset: usize, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        log::debug!("ext4 write_offset: offset={}, len={}", offset, data.len());
        let block_size = self.block_size();

        let mut bytes_written = 0;
        while bytes_written < data.len() {
            let current_offset = offset + bytes_written;
            let block_offset = (current_offset / block_size) * block_size;
            let inner_offset = current_offset % block_size;
            let current_len = core::cmp::min(block_size - inner_offset, data.len() - bytes_written);

            let mut to_write = None;
            let block_data = {
                let mut cache = self.block_cache.lock();
                if let Some(block) = cache.get_mut(&block_offset) {
                    block.data[inner_offset..inner_offset + current_len]
                        .copy_from_slice(&data[bytes_written..bytes_written + current_len]);
                    block.dirty = true;
                    bytes_written += current_len;
                    continue;
                }

                // Cache miss
                if inner_offset == 0 && current_len == block_size {
                    data[bytes_written..bytes_written + current_len].to_vec()
                } else {
                    drop(cache);
                    let mut temp = vec![0u8; block_size];
                    self.read_block_aligned(block_offset, &mut temp);
                    temp[inner_offset..inner_offset + current_len]
                        .copy_from_slice(&data[bytes_written..bytes_written + current_len]);
                    let _ = self.block_cache.lock();
                    temp
                }
            };

            {
                let mut cache = self.block_cache.lock();
                let block = CacheBlock { data: block_data, dirty: true };
                if !cache.contains(&block_offset) && cache.len() >= cache.cap().get() {
                    if let Some((ev_offset, ev_block)) = cache.pop_lru() {
                        if ev_block.dirty {
                            to_write = Some((ev_offset, ev_block.data));
                        }
                    }
                }
                cache.put(block_offset, block);
            }
            if let Some((offset, data)) = to_write {
                self.write_block_to_disk(offset, &data);
            }

            bytes_written += current_len;
        }
        log::debug!("ext4 write_offset done: offset={}", offset);
    }

    pub fn block_size(&self) -> usize {
        self.block_size.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_block_size(&self, size: usize) {
        self.block_size.store(size, core::sync::atomic::Ordering::Relaxed);
    }
}

pub struct Ext4DiskWrapper<D: BlockDriverOps>(pub(crate) Arc<Ext4Disk<D>>);

impl<D: BlockDriverOps> Clone for Ext4DiskWrapper<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<D: BlockDriverOps + 'static> ext4plus::Ext4Read for Ext4DiskWrapper<D> {
    fn read(&self, start_byte: u64, dst: &mut [u8]) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.read_offset(start_byte as usize, dst);
        Ok(())
    }
}

impl<D: BlockDriverOps + 'static> ext4plus::Ext4Write for Ext4DiskWrapper<D> {
    fn write(&self, start_byte: u64, src: &[u8]) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.write_offset(start_byte as usize, src);
        Ok(())
    }
}
