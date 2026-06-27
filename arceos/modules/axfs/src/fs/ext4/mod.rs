mod fs;
mod inode;
mod util;

use alloc::{sync::Arc, vec, vec::Vec, collections::BTreeMap};
use core::num::NonZeroUsize;
use lru::LruCache;

use axdriver::prelude::BlockDriverOps;
pub use fs::*;
pub use inode::*;
use axsync::Mutex;

struct CacheBlock {
    data: Vec<u8>,
    dirty: bool,
    flushing: bool,
}

pub(crate) struct Ext4Disk<D: BlockDriverOps> {
    dev: Mutex<D>,
    sector_size: usize,
    block_cache: Mutex<LruCache<usize, CacheBlock>>,
    block_size: core::sync::atomic::AtomicUsize,
    flushing_evicted: Mutex<BTreeMap<usize, Vec<u8>>>,
}

struct FlushingGuard<'a, D: BlockDriverOps> {
    disk: &'a Ext4Disk<D>,
    offsets: Vec<usize>,
}

impl<'a, D: BlockDriverOps> Drop for FlushingGuard<'a, D> {
    fn drop(&mut self) {
        let mut cache = self.disk.block_cache.lock();
        for offset in &self.offsets {
            if let Some(block) = cache.get_mut(offset) {
                block.flushing = false;
            }
        }
    }
}

impl<D: BlockDriverOps + 'static> crate::disk::DiskFlushable for Ext4Disk<D> {
    fn flush_disk(&self) -> axdriver::prelude::DevResult<()> {
        let block_size = self.block_size();
        let (dirty_blocks, flushing_offsets) = {
            let mut cache = self.block_cache.lock();
            let mut list = vec![];
            let mut offsets = vec![];
            for (&offset, block) in cache.iter_mut() {
                if block.dirty {
                    block.flushing = true;
                    list.push((offset, block.data.clone()));
                    offsets.push(offset);
                }
            }
            (list, offsets)
        };
        
        let _guard = FlushingGuard {
            disk: self,
            offsets: flushing_offsets,
        };

        let mut dirty_blocks = dirty_blocks;
        dirty_blocks.sort_by_key(|(offset, _)| *offset);

        let mut i = 0;
        while i < dirty_blocks.len() {
            let mut j = i + 1;
            while j < dirty_blocks.len() && dirty_blocks[j].0 == dirty_blocks[j - 1].0 + block_size {
                j += 1;
            }
            
            let start_offset = dirty_blocks[i].0;
            let mut merged_data = Vec::with_capacity((j - i) * block_size);
            for k in i..j {
                merged_data.extend_from_slice(&dirty_blocks[k].1);
            }
            self.write_block_to_disk(start_offset, &merged_data)?;
            
            {
                let mut cache = self.block_cache.lock();
                for k in i..j {
                    let offset = dirty_blocks[k].0;
                    let written_data = &dirty_blocks[k].1;
                    if let Some(block) = cache.get_mut(&offset) {
                        if &block.data == written_data {
                            if block.flushing {
                                block.dirty = false;
                                block.flushing = false;
                            }
                        }
                    }
                }
            }
            i = j;
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
            flushing_evicted: Mutex::new(BTreeMap::new()),
        });
        crate::disk::DISK_FLUSHERS.lock().push(Arc::downgrade(&disk) as _);
        disk
    }

    fn evict_if_full(&self, cache: &mut LruCache<usize, CacheBlock>, to_write: &mut Vec<(usize, Vec<u8>)>) {
        if cache.len() >= cache.cap().get() {
            let ev_key = cache.iter()
                .rev()
                .filter(|(_, block)| !block.flushing)
                .map(|(key, _)| *key)
                .next();
            if let Some(key) = ev_key {
                if let Some((ev_offset, ev_block)) = cache.pop_entry(&key) {
                    if ev_block.dirty {
                        to_write.push((ev_offset, ev_block.data.clone()));
                        self.flushing_evicted.lock().insert(ev_offset, ev_block.data);
                    }
                }
            }
        }
    }

    fn byte_range(&self, offset: usize, len: usize) -> (u64, usize, usize) {
        let first_block = (offset / self.sector_size) as u64;
        let inner_offset = offset % self.sector_size;
        let touched = inner_offset + len;
        let blocks = touched.div_ceil(self.sector_size);
        (first_block, inner_offset, blocks)
    }

    fn write_block_to_disk(&self, block_offset: usize, data: &[u8]) -> axdriver::prelude::DevResult<()> {
        let (first_block, _, _) = self.byte_range(block_offset, data.len());
        let mut dev = self.dev.lock();
        if let Err(err) = dev.write_block(first_block, data) {
            log::error!(
                "ext4 write_block_to_disk failed: block_offset={}, err={:?}",
                block_offset,
                err
            );
            return Err(err);
        }
        Ok(())
    }

    fn read_blocks_from_disk(&self, block_offset: usize, num_blocks: usize, dest: &mut [u8]) -> axdriver::prelude::DevResult<()> {
        let block_size = self.block_size();
        let (first_block, inner_offset, blocks) = self.byte_range(block_offset, num_blocks * block_size);
        let mut raw = vec![0; blocks * self.sector_size];
        let mut dev = self.dev.lock();
        let total_blocks = dev.num_blocks();
        if first_block + blocks as u64 > total_blocks {
            log::error!(
                "ext4 read_blocks_from_disk OOB: block_offset={:#x}, num_blocks={}, first_block={}, blocks={}, num_blocks={}",
                block_offset, num_blocks, first_block, blocks, total_blocks
            );
            return Err(axdriver::prelude::DevError::InvalidParam);
        }
        if let Err(err) = dev.read_block(first_block, &mut raw) {
            log::error!(
                "ext4 read_blocks_from_disk failed: block_offset={}, num_blocks={}, err={:?}",
                block_offset,
                num_blocks,
                err
            );
            return Err(err);
        }
        dest.copy_from_slice(&raw[inner_offset..inner_offset + num_blocks * block_size]);
        Ok(())
    }

    pub fn read_offset(&self, offset: usize, buf: &mut [u8]) -> axdriver::prelude::DevResult<()> {
        if buf.is_empty() {
            return Ok(());
        }
        log::debug!("ext4 read_offset: offset={}, len={}", offset, buf.len());
        let block_size = self.block_size();
        
        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((offset + buf.len() - 1) / block_size) * block_size;
        
        let mut current_block_offset = start_block_offset;
        while current_block_offset <= end_block_offset {
            // Check cache hit
            let hit = {
                let mut cache = self.block_cache.lock();
                if let Some(block) = cache.get(&current_block_offset) {
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(offset + buf.len(), current_block_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - current_block_offset;
                    buf[buf_start..buf_start + overlap_len]
                        .copy_from_slice(&block.data[block_start..block_start + overlap_len]);
                    true
                } else {
                    false
                }
            };
            
            if hit {
                current_block_offset += block_size;
            } else {
                // Cache miss. Find consecutive cache misses.
                let mut consecutive_misses = 1;
                {
                    let cache = self.block_cache.lock();
                    while current_block_offset + consecutive_misses * block_size <= end_block_offset {
                        let next_block_offset = current_block_offset + consecutive_misses * block_size;
                        if cache.contains(&next_block_offset) {
                            break;
                        }
                        consecutive_misses += 1;
                    }
                }
                
                // Read all consecutive misses from disk in one go
                let mut run_data = vec![0u8; consecutive_misses * block_size];
                self.read_blocks_from_disk(current_block_offset, consecutive_misses, &mut run_data)?;
                
                // Populate cache and copy to buf
                let mut to_write = Vec::new();
                {
                    let mut cache = self.block_cache.lock();
                    for b in 0..consecutive_misses {
                        let b_offset = current_block_offset + b * block_size;
                        let b_data = run_data[b * block_size..(b + 1) * block_size].to_vec();
                        
                        let start = core::cmp::max(offset, b_offset);
                        let end = core::cmp::min(offset + buf.len(), b_offset + block_size);
                        let overlap_len = end - start;
                        let buf_start = start - offset;
                        let block_start = start - b_offset;
                        
                        if let Some(existing) = cache.get(&b_offset) {
                            buf[buf_start..buf_start + overlap_len]
                                .copy_from_slice(&existing.data[block_start..block_start + overlap_len]);
                        } else {
                            let flushing_data = self.flushing_evicted.lock().get(&b_offset).cloned();
                            if let Some(flushing_data) = flushing_data {
                                buf[buf_start..buf_start + overlap_len]
                                    .copy_from_slice(&flushing_data[block_start..block_start + overlap_len]);
                                let block = CacheBlock { data: flushing_data, dirty: false, flushing: false };
                                self.evict_if_full(&mut cache, &mut to_write);
                                cache.put(b_offset, block);
                            } else {
                                buf[buf_start..buf_start + overlap_len].copy_from_slice(&b_data[block_start..block_start + overlap_len]);
                                let block = CacheBlock { data: b_data, dirty: false, flushing: false };
                                self.evict_if_full(&mut cache, &mut to_write);
                                cache.put(b_offset, block);
                            }
                        }
                    }
                }
                
                // Flush evicted dirty blocks
                for (ev_offset, ev_data) in to_write {
                    let res = self.write_block_to_disk(ev_offset, &ev_data);
                    self.flushing_evicted.lock().remove(&ev_offset);
                    res?;
                }
                
                current_block_offset += consecutive_misses * block_size;
            }
        }
        log::debug!("ext4 read_offset done: offset={}", offset);
        Ok(())
    }

    pub fn write_offset(&self, offset: usize, data: &[u8]) -> axdriver::prelude::DevResult<()> {
        if data.is_empty() {
            return Ok(());
        }
        log::debug!("ext4 write_offset: offset={}, len={}", offset, data.len());
        let block_size = self.block_size();
        
        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((offset + data.len() - 1) / block_size) * block_size;
        
        let mut current_block_offset = start_block_offset;
        while current_block_offset <= end_block_offset {
            let start = core::cmp::max(offset, current_block_offset);
            let end = core::cmp::min(offset + data.len(), current_block_offset + block_size);
            let overlap_len = end - start;
            let data_start = start - offset;
            let block_start = start - current_block_offset;
            
            // Check cache hit
            let has_cache = {
                let mut cache = self.block_cache.lock();
                if let Some(block) = cache.get_mut(&current_block_offset) {
                    block.data[block_start..block_start + overlap_len]
                        .copy_from_slice(&data[data_start..data_start + overlap_len]);
                    block.dirty = true;
                    block.flushing = false;
                    true
                } else {
                    false
                }
            };
            
            if has_cache {
                current_block_offset += block_size;
                continue;
            }
            
            // Cache miss. Check if we can write a full block directly without pre-reading.
            if block_start == 0 && overlap_len == block_size {
                let block_data = data[data_start..data_start + block_size].to_vec();
                let mut to_write = None;
                {
                    let mut cache = self.block_cache.lock();
                    let block = CacheBlock { data: block_data, dirty: true, flushing: false };
                    if !cache.contains(&current_block_offset) {
                        let mut ev_write = Vec::new();
                        self.evict_if_full(&mut cache, &mut ev_write);
                        if let Some((offset, data)) = ev_write.pop() {
                            to_write = Some((offset, data));
                        }
                    }
                    cache.put(current_block_offset, block);
                }
                if let Some((offset, data)) = to_write {
                    let res = self.write_block_to_disk(offset, &data);
                    self.flushing_evicted.lock().remove(&offset);
                    res?;
                }
                current_block_offset += block_size;
            } else {
                // Partial block write with cache miss. Find consecutive cache misses that need partial write.
                let mut consecutive_misses = 1;
                {
                    let cache = self.block_cache.lock();
                    while current_block_offset + consecutive_misses * block_size <= end_block_offset {
                        let next_block_offset = current_block_offset + consecutive_misses * block_size;
                        if cache.contains(&next_block_offset) {
                            break;
                        }
                        let next_start = core::cmp::max(offset, next_block_offset);
                        let next_end = core::cmp::min(offset + data.len(), next_block_offset + block_size);
                        let next_overlap = next_end - next_start;
                        if next_overlap == block_size {
                            break;
                        }
                        consecutive_misses += 1;
                    }
                }
                
                // Pre-read consecutive partial miss blocks from disk in one go
                let mut run_data = vec![0u8; consecutive_misses * block_size];
                self.read_blocks_from_disk(current_block_offset, consecutive_misses, &mut run_data)?;
                
                // Populate cache, apply writes, and copy
                let mut to_write = Vec::new();
                {
                    let mut cache = self.block_cache.lock();
                    for b in 0..consecutive_misses {
                        let b_offset = current_block_offset + b * block_size;
                        let mut b_data = run_data[b * block_size..(b + 1) * block_size].to_vec();
                        
                        let start = core::cmp::max(offset, b_offset);
                        let end = core::cmp::min(offset + data.len(), b_offset + block_size);
                        let overlap_len = end - start;
                        let data_start = start - offset;
                        let block_start = start - b_offset;
                        
                        if let Some(existing) = cache.get_mut(&b_offset) {
                            existing.data[block_start..block_start + overlap_len]
                                .copy_from_slice(&data[data_start..data_start + overlap_len]);
                            existing.dirty = true;
                            existing.flushing = false;
                        } else {
                            let flushing_data = self.flushing_evicted.lock().get(&b_offset).cloned();
                            if let Some(flushing_data) = flushing_data {
                                let mut b_data = flushing_data;
                                b_data[block_start..block_start + overlap_len]
                                    .copy_from_slice(&data[data_start..data_start + overlap_len]);
                                let block = CacheBlock { data: b_data, dirty: true, flushing: false };
                                self.evict_if_full(&mut cache, &mut to_write);
                                cache.put(b_offset, block);
                            } else {
                                b_data[block_start..block_start + overlap_len]
                                    .copy_from_slice(&data[data_start..data_start + overlap_len]);
                                let block = CacheBlock { data: b_data, dirty: true, flushing: false };
                                self.evict_if_full(&mut cache, &mut to_write);
                                cache.put(b_offset, block);
                            }
                        }
                    }
                }
                
                // Flush evicted dirty blocks
                for (ev_offset, ev_data) in to_write {
                    let res = self.write_block_to_disk(ev_offset, &ev_data);
                    self.flushing_evicted.lock().remove(&ev_offset);
                    res?;
                }
                
                current_block_offset += consecutive_misses * block_size;
            }
        }
        log::debug!("ext4 write_offset done: offset={}", offset);
        Ok(())
    }

    pub fn block_size(&self) -> usize {
        self.block_size.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub fn set_block_size(&self, size: usize) {
        self.block_size.store(size, core::sync::atomic::Ordering::Relaxed);
        self.block_cache.lock().clear();
    }
}

pub struct Ext4DiskWrapper<D: BlockDriverOps>(pub(crate) Arc<Ext4Disk<D>>);

impl<D: BlockDriverOps> Clone for Ext4DiskWrapper<D> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[derive(Debug)]
struct Ext4DevError(axdriver::prelude::DevError);

impl core::fmt::Display for Ext4DevError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Device error: {:?}", self.0)
    }
}

impl core::error::Error for Ext4DevError {}

impl<D: BlockDriverOps + 'static> ext4plus::Ext4Read for Ext4DiskWrapper<D> {
    fn read(&self, start_byte: u64, dst: &mut [u8]) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.read_offset(start_byte as usize, dst).map_err(|err| alloc::boxed::Box::new(Ext4DevError(err)) as _)
    }
}

impl<D: BlockDriverOps + 'static> ext4plus::Ext4Write for Ext4DiskWrapper<D> {
    fn write(&self, start_byte: u64, src: &[u8]) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.write_offset(start_byte as usize, src).map_err(|err| alloc::boxed::Box::new(Ext4DevError(err)) as _)
    }
}
