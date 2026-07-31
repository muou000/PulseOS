mod fs;
mod inode;
mod util;

use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::{
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use async_trait::async_trait;
use axdriver::prelude::{AsyncBlockDriverOps, BlockDriverOps};
use axsync::Mutex;
pub use fs::*;
use futures_util::{StreamExt, stream::FuturesUnordered};
pub use inode::*;
use lru::LruCache;

struct CacheBlock {
    data: Vec<u8>,
    dirty: bool,
    flushing: bool,
    reused: bool,
}

struct DirtyOwnerState {
    sequence: u64,
    owners: BTreeSet<u64>,
}

struct WriteScopeState {
    owners: Vec<u64>,
    dirty_offsets: BTreeSet<usize>,
}

#[derive(Default)]
struct WriteScopeRegistry {
    scopes: BTreeMap<u64, WriteScopeState>,
    active_by_task: BTreeMap<u64, Vec<u64>>,
}

const CACHE_EVICTION_SCAN_LIMIT: usize = 64;
const DEVICE_READ_MAX_ATTEMPTS: usize = 2;
const IO_LOCK_STRIPES: usize = 64;
const FLUSH_BATCH_BLOCKS: usize = 32;
const FLUSH_WRITE_CONCURRENCY: usize = 4;

fn bypass_block_cache(offset: usize, len: usize, block_size: usize) -> bool {
    len > block_size && offset % block_size == 0 && len % block_size == 0
}

fn retryable_device_read_error(error: &axdriver::prelude::DevError) -> bool {
    matches!(
        error,
        axdriver::prelude::DevError::Again | axdriver::prelude::DevError::Io
    )
}

fn group_flush_offsets(offsets: &[usize], block_size: usize) -> Vec<Vec<usize>> {
    let mut batches = Vec::new();
    for &offset in offsets {
        let append = batches.last().is_some_and(|batch: &Vec<usize>| {
            batch.len() < FLUSH_BATCH_BLOCKS
                && batch.last().and_then(|last| last.checked_add(block_size)) == Some(offset)
        });
        if append {
            batches.last_mut().unwrap().push(offset);
        } else {
            batches.push(vec![offset]);
        }
    }
    batches
}

fn pop_cache_victim(cache: &mut LruCache<usize, CacheBlock>) -> Option<(usize, CacheBlock)> {
    let scan_limit = cache.len().min(CACHE_EVICTION_SCAN_LIMIT);
    for _ in 0..scan_limit {
        let (&offset, block) = cache.peek_lru()?;
        if !block.flushing && !block.reused {
            return cache.pop_lru();
        }
        cache.promote(&offset);
    }
    for _ in 0..scan_limit {
        let (&offset, block) = cache.peek_lru()?;
        if !block.flushing {
            return cache.pop_lru();
        }
        cache.promote(&offset);
    }
    None
}

pub(crate) struct Ext4Disk<D: BlockDriverOps> {
    dev: Mutex<D>,
    sector_size: usize,
    block_cache: Mutex<LruCache<usize, CacheBlock>>,
    block_size: AtomicUsize,
    flushing_evicted: Mutex<BTreeMap<usize, Vec<u8>>>,
    io_locks: [async_lock::RwLock<()>; IO_LOCK_STRIPES],
    checkpoint_lock: async_lock::RwLock<()>,
    flush_lock: async_lock::Mutex<()>,
    write_generation: AtomicU64,
    flushed_generation: AtomicU64,
    dirty_owners: Mutex<BTreeMap<usize, DirtyOwnerState>>,
    next_write_scope_id: AtomicU64,
    write_scopes: Mutex<WriteScopeRegistry>,
}

struct FlushingGuard<'a, D: BlockDriverOps> {
    disk: &'a Ext4Disk<D>,
    offsets: Vec<usize>,
}

enum ReadRangeGuards<'a> {
    One(async_lock::RwLockReadGuard<'a, ()>),
    Many(Vec<async_lock::RwLockReadGuard<'a, ()>>),
}

impl ReadRangeGuards<'_> {
    fn len(&self) -> usize {
        match self {
            Self::One(guard) => {
                let _ = &**guard;
                1
            }
            Self::Many(guards) => guards.len(),
        }
    }
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

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> crate::disk::DiskFlushable for Ext4Disk<D> {
    async fn flush_disk(&self) -> axdriver::prelude::DevResult<()> {
        let _flush_guard = self.flush_lock.lock().await;
        let (target_generation, batches) = {
            // Wait only for writes which started before this checkpoint. New
            // writes may continue while the selected ranges are written back.
            let _checkpoint = self.checkpoint_lock.write().await;
            let target_generation = self.write_generation.load(Ordering::Acquire);
            if self.flushed_generation.load(Ordering::Acquire) == target_generation {
                return Ok(());
            }
            let offsets = self.dirty_offsets();
            (
                target_generation,
                group_flush_offsets(&offsets, self.block_size()),
            )
        };

        let first_error = self.flush_batches(batches).await;

        let flush_result = self.dev.lock().clone().flush_async().await;
        if first_error.is_none() && flush_result.is_ok() {
            self.flushed_generation
                .store(target_generation, Ordering::Release);
            self.dirty_owners
                .lock()
                .retain(|_, state| state.sequence > target_generation);
        }
        first_error.map_or(flush_result, Err)
    }

    async fn flush_owner(&self, owner: u64) -> axdriver::prelude::DevResult<()> {
        let _flush_guard = self.flush_lock.lock().await;
        let (owner_snapshot, batches) = {
            let _checkpoint = self.checkpoint_lock.write().await;
            let owner_snapshot = self.owner_snapshot(owner);
            let dirty_offsets = self.dirty_offsets();
            let selected = owner_snapshot
                .iter()
                .filter_map(|(offset, _)| {
                    dirty_offsets
                        .binary_search(offset)
                        .is_ok()
                        .then_some(*offset)
                })
                .collect::<Vec<_>>();
            (
                owner_snapshot,
                group_flush_offsets(&selected, self.block_size()),
            )
        };

        let first_error = self.flush_batches(batches).await;
        let flush_result = self.dev.lock().clone().flush_async().await;
        if first_error.is_none() && flush_result.is_ok() {
            let mut dirty_owners = self.dirty_owners.lock();
            for (offset, sequence) in owner_snapshot {
                if dirty_owners.get(&offset).map(|state| state.sequence) == Some(sequence) {
                    dirty_owners.remove(&offset);
                }
            }
        }
        first_error.map_or(flush_result, Err)
    }

    fn begin_write_scope(&self, owners: &[u64]) -> u64 {
        let scope_id = self
            .next_write_scope_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .expect("ext4 write scope identifier exhausted");
        let mut owners = owners.to_vec();
        owners.sort_unstable();
        owners.dedup();
        let previous = self.write_scopes.lock().scopes.insert(
            scope_id,
            WriteScopeState {
                owners,
                dirty_offsets: BTreeSet::new(),
            },
        );
        debug_assert!(previous.is_none());
        scope_id
    }

    fn enter_write_scope(&self, scope_id: u64) {
        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return;
        };
        let mut registry = self.write_scopes.lock();
        debug_assert!(registry.scopes.contains_key(&scope_id));
        registry
            .active_by_task
            .entry(task_id)
            .or_default()
            .push(scope_id);
    }

    fn include_write_owner(&self, scope_id: u64, owner: u64) {
        let dirty_offsets = {
            let mut registry = self.write_scopes.lock();
            let Some(scope) = registry.scopes.get_mut(&scope_id) else {
                return;
            };
            if !scope.owners.contains(&owner) {
                scope.owners.push(owner);
                scope.owners.sort_unstable();
            }
            scope.dirty_offsets.clone()
        };
        let mut dirty_owners = self.dirty_owners.lock();
        for offset in dirty_offsets {
            if let Some(state) = dirty_owners.get_mut(&offset) {
                state.owners.insert(owner);
            }
        }
    }

    fn leave_write_scope(&self, scope_id: u64) {
        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return;
        };
        let mut registry = self.write_scopes.lock();
        if let Some(stack) = registry.active_by_task.get_mut(&task_id) {
            let position = stack.iter().rposition(|id| *id == scope_id);
            debug_assert_eq!(position, stack.len().checked_sub(1));
            if let Some(position) = position {
                stack.remove(position);
            }
            if stack.is_empty() {
                registry.active_by_task.remove(&task_id);
            }
        }
    }

    fn end_write_scope(&self, scope_id: u64) {
        let mut registry = self.write_scopes.lock();
        debug_assert!(
            registry
                .active_by_task
                .values()
                .all(|stack| !stack.contains(&scope_id))
        );
        registry.scopes.remove(&scope_id);
    }
}

impl<D: AsyncBlockDriverOps + Clone + 'static> Ext4Disk<D> {
    pub(crate) fn new(dev: D) -> Arc<Self> {
        let sector_size = dev.block_size();
        let disk = Arc::new(Self {
            dev: Mutex::new(dev),
            sector_size,
            block_cache: Mutex::new(LruCache::new(NonZeroUsize::new(512).unwrap())),
            block_size: AtomicUsize::new(4096),
            flushing_evicted: Mutex::new(BTreeMap::new()),
            io_locks: core::array::from_fn(|_| async_lock::RwLock::new(())),
            checkpoint_lock: async_lock::RwLock::new(()),
            flush_lock: async_lock::Mutex::new(()),
            write_generation: AtomicU64::new(0),
            flushed_generation: AtomicU64::new(0),
            dirty_owners: Mutex::new(BTreeMap::new()),
            next_write_scope_id: AtomicU64::new(1),
            write_scopes: Mutex::new(WriteScopeRegistry::default()),
        });
        crate::disk::DISK_FLUSHERS
            .lock()
            .push(Arc::downgrade(&disk) as _);
        disk
    }

    fn evict_if_full(
        &self,
        cache: &mut LruCache<usize, CacheBlock>,
        to_write: &mut Vec<(usize, Vec<u8>)>,
    ) -> bool {
        if cache.len() < cache.cap().get() {
            return true;
        }
        let Some((ev_offset, ev_block)) = pop_cache_victim(cache) else {
            return false;
        };
        if ev_block.dirty {
            to_write.push((ev_offset, ev_block.data.clone()));
            self.flushing_evicted
                .lock()
                .insert(ev_offset, ev_block.data);
        }
        true
    }

    fn insert_cache_block(
        &self,
        cache: &mut LruCache<usize, CacheBlock>,
        to_write: &mut Vec<(usize, Vec<u8>)>,
        offset: usize,
        block: CacheBlock,
    ) {
        if self.evict_if_full(cache, to_write) {
            cache.put(offset, block);
        } else if block.dirty {
            to_write.push((offset, block.data.clone()));
            self.flushing_evicted.lock().insert(offset, block.data);
        }
    }

    fn byte_range(&self, offset: usize, len: usize) -> (u64, usize, usize) {
        let first_block = (offset / self.sector_size) as u64;
        let inner_offset = offset % self.sector_size;
        let touched = inner_offset + len;
        let blocks = touched.div_ceil(self.sector_size);
        (first_block, inner_offset, blocks)
    }

    fn stripe_indices(&self, offset: usize, len: usize) -> Vec<usize> {
        if len == 0 {
            return Vec::new();
        }

        let block_size = self.block_size();
        let first_block = offset / block_size;
        let last_block = offset
            .saturating_add(len.saturating_sub(1))
            .saturating_div(block_size);
        let block_count = last_block.saturating_sub(first_block).saturating_add(1);
        if block_count >= IO_LOCK_STRIPES {
            return (0..IO_LOCK_STRIPES).collect();
        }

        let mut present = [false; IO_LOCK_STRIPES];
        for block in first_block..=last_block {
            present[block % IO_LOCK_STRIPES] = true;
        }
        present
            .iter()
            .enumerate()
            .filter_map(|(index, present)| present.then_some(index))
            .collect()
    }

    async fn lock_read_range<'a>(&'a self, offset: usize, len: usize) -> ReadRangeGuards<'a> {
        debug_assert!(len > 0);
        let block_size = self.block_size();
        let first_block = offset / block_size;
        let last_block = offset.saturating_add(len - 1).saturating_div(block_size);
        if first_block == last_block {
            let lock = &self.io_locks[first_block % IO_LOCK_STRIPES];
            let guard = if let Some(guard) = lock.try_read() {
                guard
            } else {
                lock.read().await
            };
            return ReadRangeGuards::One(guard);
        }

        let indices = self.stripe_indices(offset, len);
        let mut guards = Vec::with_capacity(indices.len());
        for index in indices {
            let lock = &self.io_locks[index];
            guards.push(if let Some(guard) = lock.try_read() {
                guard
            } else {
                lock.read().await
            });
        }
        ReadRangeGuards::Many(guards)
    }

    async fn lock_write_range<'a>(
        &'a self,
        offset: usize,
        len: usize,
    ) -> Vec<async_lock::RwLockWriteGuard<'a, ()>> {
        let indices = self.stripe_indices(offset, len);
        let mut guards = Vec::with_capacity(indices.len());
        for index in indices {
            guards.push(self.io_locks[index].write().await);
        }
        guards
    }

    async fn lock_all_write_stripes(&self) -> Vec<async_lock::RwLockWriteGuard<'_, ()>> {
        let mut guards = Vec::with_capacity(IO_LOCK_STRIPES);
        for lock in &self.io_locks {
            guards.push(lock.write().await);
        }
        guards
    }

    fn dirty_offsets(&self) -> Vec<usize> {
        let cache = self.block_cache.lock();
        let evicted = self.flushing_evicted.lock();
        let mut offsets = cache
            .iter()
            .filter_map(|(&offset, block)| block.dirty.then_some(offset))
            .chain(evicted.keys().copied())
            .collect::<Vec<_>>();
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    fn current_write_owners(&self) -> Vec<u64> {
        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return Vec::new();
        };
        let registry = self.write_scopes.lock();
        let mut owners = registry
            .active_by_task
            .get(&task_id)
            .into_iter()
            .flat_map(|stack| stack.iter().filter_map(|id| registry.scopes.get(id)))
            .flat_map(|scope| scope.owners.iter().copied())
            .collect::<Vec<_>>();
        owners.sort_unstable();
        owners.dedup();
        owners
    }

    fn mark_dirty_block(&self, offset: usize, sequence: u64, owners: &[u64]) {
        {
            let mut dirty_owners = self.dirty_owners.lock();
            let state = dirty_owners
                .entry(offset)
                .or_insert_with(|| DirtyOwnerState {
                    sequence,
                    owners: BTreeSet::new(),
                });
            state.sequence = sequence;
            state.owners.extend(owners.iter().copied());
        }

        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return;
        };
        let mut registry = self.write_scopes.lock();
        let active_scope_ids = registry
            .active_by_task
            .get(&task_id)
            .cloned()
            .unwrap_or_default();
        for scope_id in active_scope_ids {
            if let Some(scope) = registry.scopes.get_mut(&scope_id) {
                scope.dirty_offsets.insert(offset);
            }
        }
    }

    fn forget_submitted_offset(&self, offset: usize) {
        let still_dirty = self
            .block_cache
            .lock()
            .peek(&offset)
            .is_some_and(|block| block.dirty)
            || self.flushing_evicted.lock().contains_key(&offset);
        if !still_dirty {
            self.dirty_owners.lock().remove(&offset);
        }
    }

    fn owner_snapshot(&self, owner: u64) -> Vec<(usize, u64)> {
        self.dirty_owners
            .lock()
            .iter()
            .filter_map(|(&offset, state)| {
                state
                    .owners
                    .contains(&owner)
                    .then_some((offset, state.sequence))
            })
            .collect()
    }

    async fn flush_batches(&self, batches: Vec<Vec<usize>>) -> Option<axdriver::prelude::DevError> {
        let mut batches = batches.into_iter();
        let mut pending = FuturesUnordered::new();
        let mut first_error = None;
        loop {
            while pending.len() < FLUSH_WRITE_CONCURRENCY {
                let Some(batch) = batches.next() else {
                    break;
                };
                pending.push(self.flush_offset_batch(batch));
            }
            let Some(result) = pending.next().await else {
                break;
            };
            if let Err(error) = result
                && first_error.is_none()
            {
                first_error = Some(error);
            }
        }
        first_error
    }

    async fn flush_offset_batch(&self, offsets: Vec<usize>) -> axdriver::prelude::DevResult<()> {
        let Some((&first_offset, &last_offset)) = offsets.first().zip(offsets.last()) else {
            return Ok(());
        };
        let block_size = self.block_size();
        let span = last_offset
            .checked_sub(first_offset)
            .and_then(|span| span.checked_add(block_size))
            .ok_or(axdriver::prelude::DevError::InvalidParam)?;
        let _io_guards = self.lock_write_range(first_offset, span).await;

        let (blocks, flushing_offsets) = {
            let mut cache = self.block_cache.lock();
            let evicted = self.flushing_evicted.lock();
            let mut blocks = Vec::with_capacity(offsets.len());
            let mut flushing_offsets = Vec::new();
            for offset in offsets {
                if let Some(block) = cache.get_mut(&offset)
                    && block.dirty
                {
                    block.flushing = true;
                    blocks.push((offset, block.data.clone()));
                    flushing_offsets.push(offset);
                    continue;
                }
                if let Some(data) = evicted.get(&offset) {
                    blocks.push((offset, data.clone()));
                }
            }
            (blocks, flushing_offsets)
        };
        let _flushing_guard = FlushingGuard {
            disk: self,
            offsets: flushing_offsets,
        };

        let mut start = 0;
        while start < blocks.len() {
            let mut end = start + 1;
            while end < blocks.len()
                && blocks[end - 1].0.checked_add(block_size) == Some(blocks[end].0)
                && end - start < FLUSH_BATCH_BLOCKS
            {
                end += 1;
            }

            let mut merged = Vec::with_capacity((end - start) * block_size);
            for (_, data) in &blocks[start..end] {
                merged.extend_from_slice(data);
            }
            self.write_block_to_disk_async(blocks[start].0, &merged)
                .await?;

            let mut cache = self.block_cache.lock();
            let mut evicted = self.flushing_evicted.lock();
            for (offset, written_data) in &blocks[start..end] {
                if let Some(block) = cache.get_mut(offset)
                    && block.flushing
                    && block.data == *written_data
                {
                    block.dirty = false;
                    block.flushing = false;
                }
                if evicted.get(offset) == Some(written_data) {
                    evicted.remove(offset);
                }
            }
            start = end;
        }
        Ok(())
    }

    async fn flush_evicted_blocks(
        &self,
        blocks: Vec<(usize, Vec<u8>)>,
    ) -> axdriver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        for (offset, data) in blocks {
            let _guard = self.lock_write_range(offset, data.len()).await;
            if self.flushing_evicted.lock().get(&offset) != Some(&data) {
                continue;
            }

            self.write_block_to_disk_async(offset, &data).await?;
            let mut flushing = self.flushing_evicted.lock();
            if flushing.get(&offset) == Some(&data) {
                flushing.remove(&offset);
            }
            drop(flushing);
            self.forget_submitted_offset(offset);
        }
        Ok(())
    }

    async fn write_block_to_disk_async(
        &self,
        block_offset: usize,
        data: &[u8],
    ) -> axdriver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        let (first_block, ..) = self.byte_range(block_offset, data.len());
        let dev = self.dev.lock().clone();
        dev.write_block_async(first_block, data)
            .await
            .map_err(|err| {
                log::error!(
                    "ext4 async write failed: block_offset={}, err={:?}",
                    block_offset,
                    err
                );
                err
            })
    }

    async fn read_blocks_from_disk_async(
        &self,
        block_offset: usize,
        num_blocks: usize,
        dest: &mut [u8],
    ) -> axdriver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        let block_size = self.block_size();
        let (first_block, inner_offset, blocks) =
            self.byte_range(block_offset, num_blocks * block_size);
        let dev = self.dev.lock().clone();
        let total_blocks = dev.num_blocks();
        if first_block + blocks as u64 > total_blocks {
            log::error!(
                "ext4 async read OOB: block_offset={:#x}, num_blocks={}, first_block={}, \
                 blocks={}, device_blocks={}",
                block_offset,
                num_blocks,
                first_block,
                blocks,
                total_blocks
            );
            return Err(axdriver::prelude::DevError::InvalidParam);
        }
        if inner_offset == 0 && dest.len() == blocks * self.sector_size {
            Self::read_device_blocks(&dev, first_block, dest).await
        } else {
            let mut raw = vec![0; blocks * self.sector_size];
            Self::read_device_blocks(&dev, first_block, &mut raw).await?;
            dest.copy_from_slice(&raw[inner_offset..inner_offset + num_blocks * block_size]);
            Ok(())
        }
    }

    async fn read_device_blocks(
        dev: &D,
        first_block: u64,
        dest: &mut [u8],
    ) -> axdriver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps,
    {
        for attempt in 1..=DEVICE_READ_MAX_ATTEMPTS {
            match dev.read_block_async(first_block, dest).await {
                Ok(()) => return Ok(()),
                Err(error)
                    if attempt < DEVICE_READ_MAX_ATTEMPTS
                        && retryable_device_read_error(&error) =>
                {
                    log::warn!(
                        "ext4 device read failed; retrying: first_block={}, len={}, \
                         attempt={}/{}, error={:?}",
                        first_block,
                        dest.len(),
                        attempt,
                        DEVICE_READ_MAX_ATTEMPTS,
                        error
                    );
                }
                Err(error) => {
                    log::error!(
                        "ext4 device read failed: first_block={}, len={}, attempt={}/{}, \
                         error={:?}",
                        first_block,
                        dest.len(),
                        attempt,
                        DEVICE_READ_MAX_ATTEMPTS,
                        error
                    );
                    return Err(error);
                }
            }
        }
        unreachable!("ext4 device read attempt loop exhausted")
    }

    pub async fn read_offset(
        &self,
        offset: usize,
        buf: &mut [u8],
    ) -> axdriver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        if buf.is_empty() {
            return Ok(());
        }
        let io_guards = self.lock_read_range(offset, buf.len()).await;
        debug_assert!(io_guards.len() > 0);
        let mut deferred_writes = Vec::new();
        log::debug!("ext4 read_offset: offset={}, len={}", offset, buf.len());
        let block_size = self.block_size();

        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((offset + buf.len() - 1) / block_size) * block_size;

        // Keep one-block metadata I/O in the cache. Directly forwarding those
        // requests makes every directory, bitmap, and inode access pay an IRQ
        // completion plus task block/wake; multi-block transfers still bypass
        // the cache to avoid copying and cache pollution.
        if bypass_block_cache(offset, buf.len(), block_size) {
            let has_any_cache = {
                let cache = self.block_cache.lock();
                let flushing = self.flushing_evicted.lock();
                let mut current = start_block_offset;
                let mut found = false;
                while current <= end_block_offset {
                    if cache.contains(&current) || flushing.contains_key(&current) {
                        found = true;
                        break;
                    }
                    current += block_size;
                }
                found
            };
            if !has_any_cache {
                return self
                    .read_blocks_from_disk_async(offset, buf.len() / block_size, buf)
                    .await;
            }
        }

        let mut current_block_offset = start_block_offset;
        while current_block_offset <= end_block_offset {
            // Check cache hit
            let hit = {
                let mut cache = self.block_cache.lock();
                if let Some(block) = cache.get_mut(&current_block_offset) {
                    block.reused = true;
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(offset + buf.len(), current_block_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - current_block_offset;
                    buf[buf_start..buf_start + overlap_len]
                        .copy_from_slice(&block.data[block_start..block_start + overlap_len]);
                    true
                } else {
                    let flushing = self.flushing_evicted.lock();
                    if let Some(data) = flushing.get(&current_block_offset) {
                        let start = core::cmp::max(offset, current_block_offset);
                        let end =
                            core::cmp::min(offset + buf.len(), current_block_offset + block_size);
                        let overlap_len = end - start;
                        let buf_start = start - offset;
                        let block_start = start - current_block_offset;
                        buf[buf_start..buf_start + overlap_len]
                            .copy_from_slice(&data[block_start..block_start + overlap_len]);
                        true
                    } else {
                        false
                    }
                }
            };

            if hit {
                current_block_offset += block_size;
            } else {
                // Cache miss. Find consecutive cache misses.
                let mut consecutive_misses = 1;
                {
                    let cache = self.block_cache.lock();
                    let flushing = self.flushing_evicted.lock();
                    while current_block_offset + consecutive_misses * block_size <= end_block_offset
                    {
                        let next_block_offset =
                            current_block_offset + consecutive_misses * block_size;
                        if cache.contains(&next_block_offset)
                            || flushing.contains_key(&next_block_offset)
                        {
                            break;
                        }
                        consecutive_misses += 1;
                    }
                }

                // Read all consecutive misses from disk in one go
                let mut run_data = vec![0u8; consecutive_misses * block_size];
                self.read_blocks_from_disk_async(
                    current_block_offset,
                    consecutive_misses,
                    &mut run_data,
                )
                .await?;

                // Populate cache and copy to buf
                let mut to_write = Vec::new();
                {
                    let mut cache = self.block_cache.lock();
                    for b in 0..consecutive_misses {
                        let b_offset = current_block_offset + b * block_size;
                        let b_data = &run_data[b * block_size..(b + 1) * block_size];

                        let start = core::cmp::max(offset, b_offset);
                        let end = core::cmp::min(offset + buf.len(), b_offset + block_size);
                        let overlap_len = end - start;
                        let buf_start = start - offset;
                        let block_start = start - b_offset;

                        if let Some(existing) = cache.get_mut(&b_offset) {
                            existing.reused = true;
                            buf[buf_start..buf_start + overlap_len].copy_from_slice(
                                &existing.data[block_start..block_start + overlap_len],
                            );
                        } else {
                            let flushing_data =
                                self.flushing_evicted.lock().get(&b_offset).cloned();
                            if let Some(flushing_data) = flushing_data {
                                buf[buf_start..buf_start + overlap_len].copy_from_slice(
                                    &flushing_data[block_start..block_start + overlap_len],
                                );
                            } else {
                                buf[buf_start..buf_start + overlap_len].copy_from_slice(
                                    &b_data[block_start..block_start + overlap_len],
                                );
                                let block = CacheBlock {
                                    data: b_data.to_vec(),
                                    dirty: false,
                                    flushing: false,
                                    reused: false,
                                };
                                self.insert_cache_block(&mut cache, &mut to_write, b_offset, block);
                            }
                        }
                    }
                }

                deferred_writes.extend(to_write);

                current_block_offset += consecutive_misses * block_size;
            }
        }
        drop(io_guards);
        self.flush_evicted_blocks(deferred_writes).await?;
        log::debug!("ext4 read_offset done: offset={}", offset);
        Ok(())
    }

    pub async fn write_offset(&self, offset: usize, data: &[u8]) -> axdriver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        if data.is_empty() {
            return Ok(());
        }
        // A flush checkpoint briefly takes the exclusive side to include every
        // write that started before it. Writes otherwise share this lock and
        // retain range-level concurrency.
        let _checkpoint = self.checkpoint_lock.read().await;
        let sequence = self
            .write_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let owners = self.current_write_owners();
        let io_guards = self.lock_write_range(offset, data.len()).await;
        let mut deferred_writes = Vec::new();
        log::debug!("ext4 write_offset: offset={}, len={}", offset, data.len());
        let block_size = self.block_size();

        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((offset + data.len() - 1) / block_size) * block_size;

        if bypass_block_cache(offset, data.len(), block_size) {
            self.write_block_to_disk_async(offset, data).await?;
            {
                let mut cache = self.block_cache.lock();
                let mut flushing = self.flushing_evicted.lock();
                let mut current = start_block_offset;
                while current <= end_block_offset {
                    cache.pop(&current);
                    flushing.remove(&current);
                    current += block_size;
                }
            }
            let mut current = start_block_offset;
            while current <= end_block_offset {
                self.forget_submitted_offset(current);
                current += block_size;
            }
            return Ok(());
        }

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
                    block.reused = true;
                    true
                } else {
                    false
                }
            };

            if has_cache {
                self.mark_dirty_block(current_block_offset, sequence, &owners);
                current_block_offset += block_size;
                continue;
            }

            // A complete cache-miss block needs no pre-read. Keep it dirty in
            // the cache so repeated metadata updates collapse into one later
            // writeback instead of one VirtIO completion per update.
            if block_start == 0 && overlap_len == block_size {
                let block = CacheBlock {
                    data: data[data_start..data_start + block_size].to_vec(),
                    dirty: true,
                    flushing: false,
                    reused: true,
                };
                {
                    let mut cache = self.block_cache.lock();
                    self.flushing_evicted.lock().remove(&current_block_offset);
                    self.insert_cache_block(
                        &mut cache,
                        &mut deferred_writes,
                        current_block_offset,
                        block,
                    );
                }
                self.mark_dirty_block(current_block_offset, sequence, &owners);
                current_block_offset += block_size;
            } else {
                // Partial block write with cache miss. Find consecutive cache misses that need partial write.
                let mut consecutive_misses = 1;
                {
                    let cache = self.block_cache.lock();
                    let flushing = self.flushing_evicted.lock();
                    while current_block_offset + consecutive_misses * block_size <= end_block_offset
                    {
                        let next_block_offset =
                            current_block_offset + consecutive_misses * block_size;
                        if cache.contains(&next_block_offset)
                            || flushing.contains_key(&next_block_offset)
                        {
                            break;
                        }
                        let next_start = core::cmp::max(offset, next_block_offset);
                        let next_end =
                            core::cmp::min(offset + data.len(), next_block_offset + block_size);
                        let next_overlap = next_end - next_start;
                        if next_overlap == block_size {
                            break;
                        }
                        consecutive_misses += 1;
                    }
                }

                // Pre-read consecutive partial miss blocks from disk in one go
                let mut run_data = vec![0u8; consecutive_misses * block_size];
                self.read_blocks_from_disk_async(
                    current_block_offset,
                    consecutive_misses,
                    &mut run_data,
                )
                .await?;

                // Populate cache, apply writes, and copy
                let mut to_write = Vec::new();
                let mut marked_offsets = Vec::with_capacity(consecutive_misses);
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
                            existing.reused = true;
                        } else {
                            let flushing_data = self.flushing_evicted.lock().remove(&b_offset);
                            if let Some(flushing_data) = flushing_data {
                                let mut b_data = flushing_data;
                                b_data[block_start..block_start + overlap_len]
                                    .copy_from_slice(&data[data_start..data_start + overlap_len]);
                                let block = CacheBlock {
                                    data: b_data,
                                    dirty: true,
                                    flushing: false,
                                    reused: true,
                                };
                                self.insert_cache_block(&mut cache, &mut to_write, b_offset, block);
                            } else {
                                b_data[block_start..block_start + overlap_len]
                                    .copy_from_slice(&data[data_start..data_start + overlap_len]);
                                let block = CacheBlock {
                                    data: b_data,
                                    dirty: true,
                                    flushing: false,
                                    reused: true,
                                };
                                self.insert_cache_block(&mut cache, &mut to_write, b_offset, block);
                            }
                        }
                        marked_offsets.push(b_offset);
                    }
                }

                for offset in marked_offsets {
                    self.mark_dirty_block(offset, sequence, &owners);
                }

                deferred_writes.extend(to_write);

                current_block_offset += consecutive_misses * block_size;
            }
        }
        drop(io_guards);
        self.flush_evicted_blocks(deferred_writes).await?;
        log::debug!("ext4 write_offset done: offset={}", offset);
        Ok(())
    }

    pub fn block_size(&self) -> usize {
        self.block_size.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub async fn set_block_size(&self, size: usize) {
        let _io_guards = self.lock_all_write_stripes().await;
        self.block_size
            .store(size, core::sync::atomic::Ordering::Relaxed);
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

impl Ext4DevError {
    fn to_vfs_error(&self) -> axfs_ng_vfs::VfsError {
        use axdriver::prelude::DevError;
        use axfs_ng_vfs::VfsError;

        match &self.0 {
            DevError::AlreadyExists => VfsError::AlreadyExists,
            DevError::Again => VfsError::WouldBlock,
            DevError::BadState => VfsError::BadState,
            DevError::InvalidParam => VfsError::InvalidInput,
            DevError::Io => VfsError::Io,
            DevError::NoMemory => VfsError::NoMemory,
            DevError::ResourceBusy => VfsError::ResourceBusy,
            DevError::Unsupported => VfsError::OperationNotSupported,
        }
    }
}

impl core::fmt::Display for Ext4DevError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Device error: {:?}", self.0)
    }
}

impl core::error::Error for Ext4DevError {}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> ext4plus::Ext4Read for Ext4DiskWrapper<D> {
    async fn read(
        &self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        let result = self
            .0
            .read_offset(start_byte as usize, dst)
            .await
            .map_err(|err| alloc::boxed::Box::new(Ext4DevError(err)) as _);
        result
    }
}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> ext4plus::Ext4Write for Ext4DiskWrapper<D> {
    async fn write(
        &self,
        start_byte: u64,
        src: &[u8],
    ) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0
            .write_offset(start_byte as usize, src)
            .await
            .map_err(|err| alloc::boxed::Box::new(Ext4DevError(err)) as _)
    }
}

#[cfg(test)]
mod tests {
    use axdriver::prelude::DevError;

    use super::{
        FLUSH_BATCH_BLOCKS, bypass_block_cache, group_flush_offsets, retryable_device_read_error,
    };

    #[test]
    fn single_metadata_block_uses_cache_while_large_aligned_io_bypasses_it() {
        const BLOCK_SIZE: usize = 4096;

        assert!(!bypass_block_cache(0, BLOCK_SIZE, BLOCK_SIZE));
        assert!(bypass_block_cache(0, 2 * BLOCK_SIZE, BLOCK_SIZE));
        assert!(!bypass_block_cache(1, 2 * BLOCK_SIZE, BLOCK_SIZE));
        assert!(!bypass_block_cache(0, BLOCK_SIZE + 1, BLOCK_SIZE));
    }

    #[test]
    fn only_transient_device_read_errors_are_retried() {
        assert!(retryable_device_read_error(&DevError::Again));
        assert!(retryable_device_read_error(&DevError::Io));
        assert!(!retryable_device_read_error(&DevError::BadState));
        assert!(!retryable_device_read_error(&DevError::NoMemory));
    }

    #[test]
    fn flush_batches_are_contiguous_and_bounded() {
        let block_size = 4096;
        let mut offsets = (0..=FLUSH_BATCH_BLOCKS)
            .map(|index| index * block_size)
            .collect::<alloc::vec::Vec<_>>();
        offsets.push((FLUSH_BATCH_BLOCKS + 2) * block_size);

        let batches = group_flush_offsets(&offsets, block_size);
        assert_eq!(batches.len(), 3);
        assert_eq!(batches[0].len(), FLUSH_BATCH_BLOCKS);
        assert_eq!(batches[1], alloc::vec![FLUSH_BATCH_BLOCKS * block_size]);
        assert_eq!(
            batches[2],
            alloc::vec![(FLUSH_BATCH_BLOCKS + 2) * block_size]
        );
    }
}
