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

struct WriteScopeRegistry {
    scopes: [Mutex<BTreeMap<u64, Arc<Mutex<WriteScopeState>>>>; WRITE_SCOPE_SHARDS],
    active_by_task: [Mutex<BTreeMap<u64, Vec<u64>>>; WRITE_SCOPE_SHARDS],
}

impl Default for WriteScopeRegistry {
    fn default() -> Self {
        Self {
            scopes: core::array::from_fn(|_| Mutex::new(BTreeMap::new())),
            active_by_task: core::array::from_fn(|_| Mutex::new(BTreeMap::new())),
        }
    }
}

impl WriteScopeRegistry {
    fn scope(&self, scope_id: u64) -> Option<Arc<Mutex<WriteScopeState>>> {
        self.scopes[write_scope_shard(scope_id)]
            .lock()
            .get(&scope_id)
            .cloned()
    }

    fn active_scopes(&self, task_id: u64) -> Vec<u64> {
        self.active_by_task[write_scope_shard(task_id)]
            .lock()
            .get(&task_id)
            .cloned()
            .unwrap_or_default()
    }
}

const BLOCK_CACHE_STRIPES: usize = 16;
const DIRTY_OWNER_SHARDS: usize = BLOCK_CACHE_STRIPES;
const WRITE_SCOPE_SHARDS: usize = 32;
const CACHE_CAPACITY_PER_STRIPE: usize = 32;
const CACHE_EVICTION_SCAN_LIMIT: usize = 64;
const DEVICE_READ_MAX_ATTEMPTS: usize = 2;
const FLUSH_BATCH_BLOCKS: usize = 32;
const FLUSH_WRITE_CONCURRENCY: usize = 4;
const IO_RANGE_LOCK_BUCKETS: usize = 128;
const IO_RANGE_LOCK_BUCKET_BLOCKS: usize = 64;

fn write_scope_shard(id: u64) -> usize {
    (id as usize ^ (id >> 32) as usize) % WRITE_SCOPE_SHARDS
}

struct CacheStripeInner {
    cache: LruCache<usize, CacheBlock>,
    flushing_evicted: BTreeMap<usize, Vec<u8>>,
}

impl CacheStripeInner {
    fn evict_if_full(&mut self, to_write: &mut Vec<(usize, Vec<u8>)>) -> bool {
        if self.cache.len() < self.cache.cap().get() {
            return true;
        }
        let Some((ev_offset, ev_block)) = pop_cache_victim(&mut self.cache) else {
            return false;
        };
        if ev_block.dirty {
            to_write.push((ev_offset, ev_block.data.clone()));
            self.flushing_evicted.insert(ev_offset, ev_block.data);
        }
        true
    }

    fn insert_cache_block(
        &mut self,
        to_write: &mut Vec<(usize, Vec<u8>)>,
        offset: usize,
        block: CacheBlock,
    ) {
        if self.evict_if_full(to_write) {
            self.cache.put(offset, block);
        } else if block.dirty {
            to_write.push((offset, block.data.clone()));
            self.flushing_evicted.insert(offset, block.data);
        }
    }
}

struct CacheStripe {
    inner: Mutex<CacheStripeInner>,
}

enum IoRangeLockIndices {
    One(usize),
    Two([usize; 2]),
    Many(Vec<usize>),
}

impl IoRangeLockIndices {
    fn len(&self) -> usize {
        match self {
            Self::One(_) => 1,
            Self::Two(_) => 2,
            Self::Many(indices) => indices.len(),
        }
    }

    fn get(&self, index: usize) -> usize {
        match self {
            Self::One(value) => {
                debug_assert_eq!(index, 0);
                *value
            }
            Self::Two(values) => values[index],
            Self::Many(values) => values[index],
        }
    }

    #[cfg(test)]
    fn contains(&self, target: usize) -> bool {
        (0..self.len()).any(|index| self.get(index) == target)
    }
}

enum IoReadRangeGuards<'a> {
    One {
        _guard: async_lock::RwLockReadGuard<'a, ()>,
    },
    Many(Vec<async_lock::RwLockReadGuard<'a, ()>>),
}

impl IoReadRangeGuards<'_> {
    fn len(&self) -> usize {
        match self {
            Self::One { .. } => 1,
            Self::Many(guards) => guards.len(),
        }
    }
}

enum IoWriteRangeGuards<'a> {
    One {
        _guard: async_lock::RwLockWriteGuard<'a, ()>,
    },
    Many(Vec<async_lock::RwLockWriteGuard<'a, ()>>),
}

impl IoWriteRangeGuards<'_> {
    fn len(&self) -> usize {
        match self {
            Self::One { .. } => 1,
            Self::Many(guards) => guards.len(),
        }
    }
}

struct IoRangeLocks {
    buckets: [async_lock::RwLock<()>; IO_RANGE_LOCK_BUCKETS],
}

impl IoRangeLocks {
    fn new() -> Self {
        Self {
            buckets: core::array::from_fn(|_| async_lock::RwLock::new(())),
        }
    }

    async fn read(
        &self,
        offset: usize,
        len: usize,
        block_size: usize,
    ) -> axdriver::prelude::DevResult<IoReadRangeGuards<'_>> {
        let indices = io_range_lock_indices(offset, len, block_size)?;
        crate::buildstorm_stat_add!(EXT4_RANGE_BUCKETS_LOCKED, indices.len());

        if indices.len() == 1 {
            let lock = &self.buckets[indices.get(0)];
            if let Some(guard) = lock.try_read() {
                crate::buildstorm_stat_inc!(EXT4_RANGE_READ_FAST);
                return Ok(IoReadRangeGuards::One { _guard: guard });
            }
            crate::buildstorm_stat_inc!(EXT4_RANGE_READ_WAIT);
            return Ok(IoReadRangeGuards::One {
                _guard: lock.read().await,
            });
        }

        let mut waited = false;
        let mut guards = Vec::with_capacity(indices.len());
        for slot in 0..indices.len() {
            let index = indices.get(slot);
            let lock = &self.buckets[index];
            if let Some(guard) = lock.try_read() {
                guards.push(guard);
            } else {
                waited = true;
                guards.push(lock.read().await);
            }
        }
        if waited {
            crate::buildstorm_stat_inc!(EXT4_RANGE_READ_WAIT);
        } else {
            crate::buildstorm_stat_inc!(EXT4_RANGE_READ_FAST);
        }
        Ok(IoReadRangeGuards::Many(guards))
    }

    async fn write(
        &self,
        offset: usize,
        len: usize,
        block_size: usize,
    ) -> axdriver::prelude::DevResult<IoWriteRangeGuards<'_>> {
        let indices = io_range_lock_indices(offset, len, block_size)?;
        crate::buildstorm_stat_add!(EXT4_RANGE_BUCKETS_LOCKED, indices.len());

        if indices.len() == 1 {
            let lock = &self.buckets[indices.get(0)];
            if let Some(guard) = lock.try_write() {
                crate::buildstorm_stat_inc!(EXT4_RANGE_WRITE_FAST);
                return Ok(IoWriteRangeGuards::One { _guard: guard });
            }
            crate::buildstorm_stat_inc!(EXT4_RANGE_WRITE_WAIT);
            return Ok(IoWriteRangeGuards::One {
                _guard: lock.write().await,
            });
        }

        let mut waited = false;
        let mut guards = Vec::with_capacity(indices.len());
        for slot in 0..indices.len() {
            let index = indices.get(slot);
            let lock = &self.buckets[index];
            if let Some(guard) = lock.try_write() {
                guards.push(guard);
            } else {
                waited = true;
                guards.push(lock.write().await);
            }
        }
        if waited {
            crate::buildstorm_stat_inc!(EXT4_RANGE_WRITE_WAIT);
        } else {
            crate::buildstorm_stat_inc!(EXT4_RANGE_WRITE_FAST);
        }
        Ok(IoWriteRangeGuards::Many(guards))
    }

    async fn write_all(&self) -> IoWriteRangeGuards<'_> {
        let mut guards = Vec::with_capacity(IO_RANGE_LOCK_BUCKETS);
        for lock in &self.buckets {
            guards.push(lock.write().await);
        }
        IoWriteRangeGuards::Many(guards)
    }
}

fn io_range_lock_indices(
    offset: usize,
    len: usize,
    block_size: usize,
) -> axdriver::prelude::DevResult<IoRangeLockIndices> {
    let (first_block, end_block) = checked_io_block_range(offset, len, block_size)?;
    let first_bucket = first_block / IO_RANGE_LOCK_BUCKET_BLOCKS;
    let last_bucket = (end_block - 1) / IO_RANGE_LOCK_BUCKET_BLOCKS;
    let bucket_count = last_bucket - first_bucket + 1;
    if bucket_count == 1 {
        return Ok(IoRangeLockIndices::One(
            first_bucket % IO_RANGE_LOCK_BUCKETS,
        ));
    }
    if bucket_count == 2 {
        let first = first_bucket % IO_RANGE_LOCK_BUCKETS;
        let second = last_bucket % IO_RANGE_LOCK_BUCKETS;
        return Ok(IoRangeLockIndices::Two(if first < second {
            [first, second]
        } else {
            [second, first]
        }));
    }

    if bucket_count >= IO_RANGE_LOCK_BUCKETS {
        return Ok(IoRangeLockIndices::Many(
            (0..IO_RANGE_LOCK_BUCKETS).collect(),
        ));
    }

    // An overlapping pair shares at least one logical block, hence the same
    // bucket. Modulo mapping may add false conflicts but never loses one.
    let mut present = [false; IO_RANGE_LOCK_BUCKETS];
    for bucket in first_bucket..=last_bucket {
        present[bucket % IO_RANGE_LOCK_BUCKETS] = true;
    }
    Ok(IoRangeLockIndices::Many(
        present
            .iter()
            .enumerate()
            .filter_map(|(index, present)| (*present).then_some(index))
            .collect(),
    ))
}

fn checked_io_block_range(
    offset: usize,
    len: usize,
    block_size: usize,
) -> axdriver::prelude::DevResult<(usize, usize)> {
    if len == 0 || block_size == 0 {
        return Err(axdriver::prelude::DevError::InvalidParam);
    }
    let end = offset
        .checked_add(len)
        .ok_or(axdriver::prelude::DevError::InvalidParam)?;
    Ok((offset / block_size, end.div_ceil(block_size)))
}

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
    block_cache_stripes: [CacheStripe; BLOCK_CACHE_STRIPES],
    block_size: AtomicUsize,
    io_ranges: IoRangeLocks,
    checkpoint_lock: async_lock::RwLock<()>,
    device_flush_lock: async_lock::Mutex<()>,
    write_generation: AtomicU64,
    flushed_generation: AtomicU64,
    dirty_owners: [Mutex<BTreeMap<usize, DirtyOwnerState>>; DIRTY_OWNER_SHARDS],
    next_write_scope_id: AtomicU64,
    write_scopes: WriteScopeRegistry,
}

impl<D: BlockDriverOps> Ext4Disk<D> {
    fn stripe_index(&self, offset: usize) -> usize {
        let block_size = self.block_size.load(Ordering::Relaxed);
        (offset / block_size) % BLOCK_CACHE_STRIPES
    }
}

struct FlushingGuard<'a, D: BlockDriverOps> {
    disk: &'a Ext4Disk<D>,
    offsets: Vec<usize>,
}

impl<'a, D: BlockDriverOps> Drop for FlushingGuard<'a, D> {
    fn drop(&mut self) {
        for &offset in &self.offsets {
            let stripe_idx = self.disk.stripe_index(offset);
            let mut stripe = self.disk.block_cache_stripes[stripe_idx].inner.lock();
            if let Some(block) = stripe.cache.get_mut(&offset) {
                block.flushing = false;
            }
        }
    }
}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> crate::disk::DiskFlushable for Ext4Disk<D> {
    async fn flush_disk(&self) -> axdriver::prelude::DevResult<()> {
        let (target_generation, batches) = {
            // Wait only for writes which started before this checkpoint. New
            // writes may continue while the selected ranges are written back.
            let _checkpoint = self.checkpoint_lock.write().await;
            let target_generation = self.write_generation.load(Ordering::Acquire);
            if self.flushed_generation.load(Ordering::Acquire) >= target_generation {
                return Ok(());
            }
            let offsets = self.dirty_offsets();
            (
                target_generation,
                group_flush_offsets(&offsets, self.block_size()),
            )
        };

        let first_error = self.flush_batches(batches).await;

        let flush_result = {
            let _device_flush = self.device_flush_lock.lock().await;
            let dev = self.dev.lock().clone();
            crate::buildstorm_stat_inc!(EXT4_DEVICE_FLUSHES);
            #[cfg(feature = "buildstorm-stats")]
            let _device_io = crate::buildstorm_stats::begin_device_io();
            dev.flush_async().await
        };
        if first_error.is_none() && flush_result.is_ok() {
            self.flushed_generation
                .fetch_max(target_generation, Ordering::AcqRel);
            for owners in &self.dirty_owners {
                owners
                    .lock()
                    .retain(|_, state| state.sequence > target_generation);
            }
        }
        first_error.map_or(flush_result, Err)
    }

    async fn flush_owner(&self, owner: u64) -> axdriver::prelude::DevResult<()> {
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
        let flush_result = {
            let _device_flush = self.device_flush_lock.lock().await;
            let dev = self.dev.lock().clone();
            crate::buildstorm_stat_inc!(EXT4_DEVICE_FLUSHES);
            #[cfg(feature = "buildstorm-stats")]
            let _device_io = crate::buildstorm_stats::begin_device_io();
            dev.flush_async().await
        };
        if first_error.is_none() && flush_result.is_ok() {
            for (offset, sequence) in owner_snapshot {
                let mut dirty_owners = self.dirty_owners[self.stripe_index(offset)].lock();
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
        let previous = self.write_scopes.scopes[write_scope_shard(scope_id)]
            .lock()
            .insert(
                scope_id,
                Arc::new(Mutex::new(WriteScopeState {
                    owners,
                    dirty_offsets: BTreeSet::new(),
                })),
            );
        debug_assert!(previous.is_none());
        scope_id
    }

    fn enter_write_scope(&self, scope_id: u64) {
        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return;
        };
        debug_assert!(self.write_scopes.scope(scope_id).is_some());
        self.write_scopes.active_by_task[write_scope_shard(task_id)]
            .lock()
            .entry(task_id)
            .or_default()
            .push(scope_id);
    }

    fn include_write_owner(&self, scope_id: u64, owner: u64) {
        let dirty_offsets = {
            let Some(scope) = self.write_scopes.scope(scope_id) else {
                return;
            };
            let mut scope = scope.lock();
            if !scope.owners.contains(&owner) {
                scope.owners.push(owner);
                scope.owners.sort_unstable();
            }
            scope.dirty_offsets.clone()
        };
        for offset in dirty_offsets {
            let mut dirty_owners = self.dirty_owners[self.stripe_index(offset)].lock();
            if let Some(state) = dirty_owners.get_mut(&offset) {
                state.owners.insert(owner);
            }
        }
    }

    fn leave_write_scope(&self, scope_id: u64) {
        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return;
        };
        let mut active_by_task =
            self.write_scopes.active_by_task[write_scope_shard(task_id)].lock();
        if let Some(stack) = active_by_task.get_mut(&task_id) {
            let position = stack.iter().rposition(|id| *id == scope_id);
            debug_assert_eq!(position, stack.len().checked_sub(1));
            if let Some(position) = position {
                stack.remove(position);
            }
            if stack.is_empty() {
                active_by_task.remove(&task_id);
            }
        }
    }

    fn end_write_scope(&self, scope_id: u64) {
        debug_assert!(self.write_scopes.active_by_task.iter().all(|tasks| {
            tasks
                .lock()
                .values()
                .all(|stack| !stack.contains(&scope_id))
        }));
        self.write_scopes.scopes[write_scope_shard(scope_id)]
            .lock()
            .remove(&scope_id);
    }
}

impl<D: AsyncBlockDriverOps + Clone + 'static> Ext4Disk<D> {
    pub(crate) fn new(dev: D) -> Arc<Self> {
        let sector_size = dev.block_size();
        let disk = Arc::new(Self {
            dev: Mutex::new(dev),
            sector_size,
            block_cache_stripes: core::array::from_fn(|_| CacheStripe {
                inner: Mutex::new(CacheStripeInner {
                    cache: LruCache::new(NonZeroUsize::new(CACHE_CAPACITY_PER_STRIPE).unwrap()),
                    flushing_evicted: BTreeMap::new(),
                }),
            }),
            block_size: AtomicUsize::new(4096),
            io_ranges: IoRangeLocks::new(),
            checkpoint_lock: async_lock::RwLock::new(()),
            device_flush_lock: async_lock::Mutex::new(()),
            write_generation: AtomicU64::new(0),
            flushed_generation: AtomicU64::new(0),
            dirty_owners: core::array::from_fn(|_| Mutex::new(BTreeMap::new())),
            next_write_scope_id: AtomicU64::new(1),
            write_scopes: WriteScopeRegistry::default(),
        });
        crate::disk::DISK_FLUSHERS
            .lock()
            .push(Arc::downgrade(&disk) as _);
        disk
    }

    fn byte_range(&self, offset: usize, len: usize) -> (u64, usize, usize) {
        let first_block = (offset / self.sector_size) as u64;
        let inner_offset = offset % self.sector_size;
        let touched = inner_offset + len;
        let blocks = touched.div_ceil(self.sector_size);
        (first_block, inner_offset, blocks)
    }

    async fn lock_read_range(
        &self,
        offset: usize,
        len: usize,
    ) -> axdriver::prelude::DevResult<IoReadRangeGuards<'_>> {
        let guards = self.io_ranges.read(offset, len, self.block_size()).await?;
        debug_assert!(guards.len() > 0);
        Ok(guards)
    }

    async fn lock_write_range(
        &self,
        offset: usize,
        len: usize,
    ) -> axdriver::prelude::DevResult<IoWriteRangeGuards<'_>> {
        let guards = self.io_ranges.write(offset, len, self.block_size()).await?;
        debug_assert!(guards.len() > 0);
        Ok(guards)
    }

    async fn lock_all_io(&self) -> IoWriteRangeGuards<'_> {
        let guards = self.io_ranges.write_all().await;
        debug_assert_eq!(guards.len(), IO_RANGE_LOCK_BUCKETS);
        guards
    }

    fn dirty_offsets(&self) -> Vec<usize> {
        let mut offsets = Vec::new();
        for stripe in &self.block_cache_stripes {
            let stripe = stripe.inner.lock();
            offsets.extend(
                stripe
                    .cache
                    .iter()
                    .filter_map(|(&offset, block)| block.dirty.then_some(offset))
                    .chain(stripe.flushing_evicted.keys().copied()),
            );
        }
        offsets.sort_unstable();
        offsets.dedup();
        offsets
    }

    fn current_write_owners(&self) -> Vec<u64> {
        let Some(task_id) = axtask::current_may_uninit().map(|task| task.id().as_u64()) else {
            return Vec::new();
        };
        let active_scope_ids = self.write_scopes.active_scopes(task_id);
        let mut owners = Vec::new();
        for scope_id in active_scope_ids {
            if let Some(scope) = self.write_scopes.scope(scope_id) {
                owners.extend(scope.lock().owners.iter().copied());
            }
        }
        owners.sort_unstable();
        owners.dedup();
        owners
    }

    fn mark_dirty_block(&self, offset: usize, sequence: u64, owners: &[u64]) {
        crate::buildstorm_stat_inc!(EXT4_DIRTY_BLOCKS);
        {
            let mut dirty_owners = self.dirty_owners[self.stripe_index(offset)].lock();
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
        let active_scope_ids = self.write_scopes.active_scopes(task_id);
        for scope_id in active_scope_ids {
            if let Some(scope) = self.write_scopes.scope(scope_id) {
                scope.lock().dirty_offsets.insert(offset);
            }
        }
    }

    fn forget_submitted_offset(&self, offset: usize) {
        let stripe_idx = self.stripe_index(offset);
        let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
        let still_dirty = stripe.cache.peek(&offset).is_some_and(|block| block.dirty)
            || stripe.flushing_evicted.contains_key(&offset);
        drop(stripe);
        if !still_dirty {
            self.dirty_owners[self.stripe_index(offset)]
                .lock()
                .remove(&offset);
        }
    }

    fn owner_snapshot(&self, owner: u64) -> Vec<(usize, u64)> {
        let mut snapshot = Vec::new();
        for owners in &self.dirty_owners {
            snapshot.extend(owners.lock().iter().filter_map(|(&offset, state)| {
                (state.owners.is_empty() || state.owners.contains(&owner))
                    .then_some((offset, state.sequence))
            }));
        }
        snapshot.sort_unstable_by_key(|(offset, _)| *offset);
        snapshot
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
        let _io_guard = self.lock_write_range(first_offset, span).await?;

        let (blocks, flushing_offsets) = {
            let mut blocks = Vec::with_capacity(offsets.len());
            let mut flushing_offsets = Vec::new();
            for offset in offsets {
                let stripe_idx = self.stripe_index(offset);
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if let Some(block) = stripe.cache.get_mut(&offset)
                    && block.dirty
                {
                    block.flushing = true;
                    blocks.push((offset, block.data.clone()));
                    flushing_offsets.push(offset);
                    continue;
                }
                if let Some(data) = stripe.flushing_evicted.get(&offset) {
                    blocks.push((offset, data.clone()));
                }
            }
            (blocks, flushing_offsets)
        };
        let _flushing_guard = FlushingGuard {
            disk: self,
            offsets: flushing_offsets,
        };
        crate::buildstorm_stat_inc!(EXT4_FLUSH_BATCHES);
        crate::buildstorm_stat_add!(EXT4_FLUSH_BLOCKS, blocks.len());

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

            for (offset, written_data) in &blocks[start..end] {
                let stripe_idx = self.stripe_index(*offset);
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if let Some(block) = stripe.cache.get_mut(offset)
                    && block.flushing
                    && block.data == *written_data
                {
                    block.dirty = false;
                    block.flushing = false;
                }
                if stripe.flushing_evicted.get(offset) == Some(written_data) {
                    stripe.flushing_evicted.remove(offset);
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
            let _guard = self.lock_write_range(offset, data.len()).await?;
            let stripe_idx = self.stripe_index(offset);
            {
                let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if stripe.flushing_evicted.get(&offset) != Some(&data) {
                    continue;
                }
            }

            self.write_block_to_disk_async(offset, &data).await?;
            {
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if stripe.flushing_evicted.get(&offset) == Some(&data) {
                    stripe.flushing_evicted.remove(&offset);
                }
            }
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
        crate::buildstorm_stat_inc!(EXT4_DEVICE_WRITE_OPS);
        crate::buildstorm_stat_add!(EXT4_DEVICE_WRITE_BYTES, data.len());
        #[cfg(feature = "buildstorm-stats")]
        let _device_io = crate::buildstorm_stats::begin_device_io();
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
            crate::buildstorm_stat_inc!(EXT4_DEVICE_READ_OPS);
            crate::buildstorm_stat_add!(EXT4_DEVICE_READ_BYTES, dest.len());
            #[cfg(feature = "buildstorm-stats")]
            let _device_io = crate::buildstorm_stats::begin_device_io();
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
        let io_guard = self.lock_read_range(offset, buf.len()).await?;
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
                let mut current = start_block_offset;
                let mut found = false;
                while current <= end_block_offset {
                    let stripe_idx = self.stripe_index(current);
                    let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    if stripe.cache.contains(&current)
                        || stripe.flushing_evicted.contains_key(&current)
                    {
                        found = true;
                        break;
                    }
                    current += block_size;
                }
                found
            };
            if !has_any_cache {
                crate::buildstorm_stat_inc!(EXT4_BYPASS_READS);
                return self
                    .read_blocks_from_disk_async(offset, buf.len() / block_size, buf)
                    .await;
            }
        }

        let mut current_block_offset = start_block_offset;
        while current_block_offset <= end_block_offset {
            // Check cache hit
            let hit = {
                let stripe_idx = self.stripe_index(current_block_offset);
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if let Some(block) = stripe.cache.get_mut(&current_block_offset) {
                    block.reused = true;
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(offset + buf.len(), current_block_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - current_block_offset;
                    buf[buf_start..buf_start + overlap_len]
                        .copy_from_slice(&block.data[block_start..block_start + overlap_len]);
                    true
                } else if let Some(data) = stripe.flushing_evicted.get(&current_block_offset) {
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(offset + buf.len(), current_block_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - current_block_offset;
                    buf[buf_start..buf_start + overlap_len]
                        .copy_from_slice(&data[block_start..block_start + overlap_len]);
                    true
                } else {
                    false
                }
            };

            if hit {
                crate::buildstorm_stat_inc!(EXT4_BLOCK_CACHE_HITS);
                current_block_offset += block_size;
            } else {
                // Cache miss. Find consecutive cache misses.
                let mut consecutive_misses = 1;
                {
                    while current_block_offset + consecutive_misses * block_size <= end_block_offset
                    {
                        let next_block_offset =
                            current_block_offset + consecutive_misses * block_size;
                        let stripe_idx = self.stripe_index(next_block_offset);
                        let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                        if stripe.cache.contains(&next_block_offset)
                            || stripe.flushing_evicted.contains_key(&next_block_offset)
                        {
                            break;
                        }
                        consecutive_misses += 1;
                    }
                }
                crate::buildstorm_stat_add!(EXT4_BLOCK_CACHE_MISSES, consecutive_misses);

                // Read all consecutive misses from disk in one go
                let mut run_data = vec![0u8; consecutive_misses * block_size];
                self.read_blocks_from_disk_async(
                    current_block_offset,
                    consecutive_misses,
                    &mut run_data,
                )
                .await?;

                if consecutive_misses == 1 {
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(offset + buf.len(), current_block_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - current_block_offset;
                    let mut to_write = Vec::new();
                    {
                        let stripe_idx = self.stripe_index(current_block_offset);
                        let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                        if let Some(existing) = stripe.cache.get_mut(&current_block_offset) {
                            existing.reused = true;
                            buf[buf_start..buf_start + overlap_len].copy_from_slice(
                                &existing.data[block_start..block_start + overlap_len],
                            );
                        } else if let Some(data) =
                            stripe.flushing_evicted.get(&current_block_offset)
                        {
                            buf[buf_start..buf_start + overlap_len]
                                .copy_from_slice(&data[block_start..block_start + overlap_len]);
                        } else {
                            buf[buf_start..buf_start + overlap_len]
                                .copy_from_slice(&run_data[block_start..block_start + overlap_len]);
                            let block = CacheBlock {
                                data: run_data,
                                dirty: false,
                                flushing: false,
                                reused: false,
                            };
                            stripe.insert_cache_block(&mut to_write, current_block_offset, block);
                        }
                    }
                    deferred_writes.extend(to_write);
                    current_block_offset += block_size;
                    continue;
                }

                // Populate cache and copy to buf
                let mut to_write = Vec::new();
                for b in 0..consecutive_misses {
                    let b_offset = current_block_offset + b * block_size;
                    let b_data = &run_data[b * block_size..(b + 1) * block_size];

                    let start = core::cmp::max(offset, b_offset);
                    let end = core::cmp::min(offset + buf.len(), b_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - b_offset;

                    let stripe_idx = self.stripe_index(b_offset);
                    let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    if let Some(existing) = stripe.cache.get_mut(&b_offset) {
                        existing.reused = true;
                        buf[buf_start..buf_start + overlap_len].copy_from_slice(
                            &existing.data[block_start..block_start + overlap_len],
                        );
                    } else if let Some(data) = stripe.flushing_evicted.get(&b_offset) {
                        buf[buf_start..buf_start + overlap_len]
                            .copy_from_slice(&data[block_start..block_start + overlap_len]);
                    } else {
                        buf[buf_start..buf_start + overlap_len]
                            .copy_from_slice(&b_data[block_start..block_start + overlap_len]);
                        let block = CacheBlock {
                            data: b_data.to_vec(),
                            dirty: false,
                            flushing: false,
                            reused: false,
                        };
                        stripe.insert_cache_block(&mut to_write, b_offset, block);
                    }
                }

                deferred_writes.extend(to_write);

                current_block_offset += consecutive_misses * block_size;
            }
        }
        drop(io_guard);
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
        let io_guard = self.lock_write_range(offset, data.len()).await?;
        let mut deferred_writes = Vec::new();
        log::debug!("ext4 write_offset: offset={}, len={}", offset, data.len());
        let block_size = self.block_size();

        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((offset + data.len() - 1) / block_size) * block_size;

        if bypass_block_cache(offset, data.len(), block_size) {
            crate::buildstorm_stat_inc!(EXT4_BYPASS_WRITES);
            self.write_block_to_disk_async(offset, data).await?;
            {
                let mut current = start_block_offset;
                while current <= end_block_offset {
                    let stripe_idx = self.stripe_index(current);
                    let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    stripe.cache.pop(&current);
                    stripe.flushing_evicted.remove(&current);
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
                let stripe_idx = self.stripe_index(current_block_offset);
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if let Some(block) = stripe.cache.get_mut(&current_block_offset) {
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
                crate::buildstorm_stat_inc!(EXT4_BLOCK_CACHE_HITS);
                self.mark_dirty_block(current_block_offset, sequence, &owners);
                current_block_offset += block_size;
                continue;
            }

            // A complete cache-miss block needs no pre-read. Keep it dirty in
            // the cache so repeated metadata updates collapse into one later
            // writeback instead of one VirtIO completion per update.
            if block_start == 0 && overlap_len == block_size {
                crate::buildstorm_stat_inc!(EXT4_BLOCK_CACHE_MISSES);
                let block = CacheBlock {
                    data: data[data_start..data_start + block_size].to_vec(),
                    dirty: true,
                    flushing: false,
                    reused: true,
                };
                {
                    let stripe_idx = self.stripe_index(current_block_offset);
                    let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    stripe.flushing_evicted.remove(&current_block_offset);
                    stripe.insert_cache_block(&mut deferred_writes, current_block_offset, block);
                }
                self.mark_dirty_block(current_block_offset, sequence, &owners);
                current_block_offset += block_size;
            } else {
                // Partial block write with cache miss. Find consecutive cache misses that need partial write.
                let mut consecutive_misses = 1;
                {
                    while current_block_offset + consecutive_misses * block_size <= end_block_offset
                    {
                        let next_block_offset =
                            current_block_offset + consecutive_misses * block_size;
                        let stripe_idx = self.stripe_index(next_block_offset);
                        let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                        if stripe.cache.contains(&next_block_offset)
                            || stripe.flushing_evicted.contains_key(&next_block_offset)
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
                crate::buildstorm_stat_add!(EXT4_BLOCK_CACHE_MISSES, consecutive_misses);

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
                for b in 0..consecutive_misses {
                    let b_offset = current_block_offset + b * block_size;
                    let mut b_data = run_data[b * block_size..(b + 1) * block_size].to_vec();

                    let start = core::cmp::max(offset, b_offset);
                    let end = core::cmp::min(offset + data.len(), b_offset + block_size);
                    let overlap_len = end - start;
                    let data_start = start - offset;
                    let block_start = start - b_offset;

                    let stripe_idx = self.stripe_index(b_offset);
                    let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    if let Some(existing) = stripe.cache.get_mut(&b_offset) {
                        existing.data[block_start..block_start + overlap_len]
                            .copy_from_slice(&data[data_start..data_start + overlap_len]);
                        existing.dirty = true;
                        existing.flushing = false;
                        existing.reused = true;
                    } else {
                        let flushing_data = stripe.flushing_evicted.remove(&b_offset);
                        if let Some(mut flushing_data) = flushing_data {
                            flushing_data[block_start..block_start + overlap_len]
                                .copy_from_slice(&data[data_start..data_start + overlap_len]);
                            let block = CacheBlock {
                                data: flushing_data,
                                dirty: true,
                                flushing: false,
                                reused: true,
                            };
                            stripe.insert_cache_block(&mut to_write, b_offset, block);
                        } else {
                            b_data[block_start..block_start + overlap_len]
                                .copy_from_slice(&data[data_start..data_start + overlap_len]);
                            let block = CacheBlock {
                                data: b_data,
                                dirty: true,
                                flushing: false,
                                reused: true,
                            };
                            stripe.insert_cache_block(&mut to_write, b_offset, block);
                        }
                    }
                    marked_offsets.push(b_offset);
                }

                for offset in marked_offsets {
                    self.mark_dirty_block(offset, sequence, &owners);
                }

                deferred_writes.extend(to_write);

                current_block_offset += consecutive_misses * block_size;
            }
        }
        drop(io_guard);
        self.flush_evicted_blocks(deferred_writes).await?;
        log::debug!("ext4 write_offset done: offset={}", offset);
        Ok(())
    }

    pub fn block_size(&self) -> usize {
        self.block_size.load(core::sync::atomic::Ordering::Relaxed)
    }

    pub async fn set_block_size(&self, size: usize) {
        let _io_guard = self.lock_all_io().await;
        for stripe in &self.block_cache_stripes {
            let mut stripe = stripe.inner.lock();
            assert!(
                stripe.cache.iter().all(|(_, block)| !block.dirty),
                "set_block_size must not discard dirty blocks"
            );
            assert!(
                stripe.flushing_evicted.is_empty(),
                "set_block_size must not discard evicted writes"
            );
            stripe.cache.clear();
        }
        for owners in &self.dirty_owners {
            owners.lock().clear();
        }
        self.block_size
            .store(size, core::sync::atomic::Ordering::Relaxed);
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
        FLUSH_BATCH_BLOCKS, IO_RANGE_LOCK_BUCKET_BLOCKS, IO_RANGE_LOCK_BUCKETS, bypass_block_cache,
        checked_io_block_range, group_flush_offsets, io_range_lock_indices,
        retryable_device_read_error,
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

    #[test]
    fn io_range_buckets_cover_half_open_ranges_and_reject_overflow() {
        const BLOCK_SIZE: usize = 4096;

        assert_eq!(
            checked_io_block_range(0, BLOCK_SIZE, BLOCK_SIZE),
            Ok((0, 1))
        );
        assert_eq!(
            checked_io_block_range(BLOCK_SIZE - 1, 2, BLOCK_SIZE),
            Ok((0, 2))
        );
        let one_bucket = io_range_lock_indices(0, BLOCK_SIZE, BLOCK_SIZE).unwrap();
        assert_eq!(one_bucket.len(), 1);
        assert_eq!(one_bucket.get(0), 0);
        let two_buckets = io_range_lock_indices(
            (IO_RANGE_LOCK_BUCKET_BLOCKS - 1) * BLOCK_SIZE,
            2 * BLOCK_SIZE,
            BLOCK_SIZE,
        )
        .unwrap();
        assert_eq!(two_buckets.len(), 2);
        assert_eq!([two_buckets.get(0), two_buckets.get(1)], [0, 1]);
        let modulo_crossing = io_range_lock_indices(
            (IO_RANGE_LOCK_BUCKETS * IO_RANGE_LOCK_BUCKET_BLOCKS - 1) * BLOCK_SIZE,
            2 * BLOCK_SIZE,
            BLOCK_SIZE,
        )
        .unwrap();
        assert_eq!(
            [modulo_crossing.get(0), modulo_crossing.get(1)],
            [0, IO_RANGE_LOCK_BUCKETS - 1]
        );
        let left = io_range_lock_indices(
            (IO_RANGE_LOCK_BUCKETS * IO_RANGE_LOCK_BUCKET_BLOCKS - 1) * BLOCK_SIZE,
            BLOCK_SIZE,
            BLOCK_SIZE,
        )
        .unwrap();
        let right = io_range_lock_indices(
            IO_RANGE_LOCK_BUCKETS * IO_RANGE_LOCK_BUCKET_BLOCKS * BLOCK_SIZE,
            BLOCK_SIZE,
            BLOCK_SIZE,
        )
        .unwrap();
        assert!(modulo_crossing.contains(left.get(0)));
        assert!(modulo_crossing.contains(right.get(0)));
        let all_buckets = io_range_lock_indices(
            0,
            IO_RANGE_LOCK_BUCKETS * IO_RANGE_LOCK_BUCKET_BLOCKS * BLOCK_SIZE,
            BLOCK_SIZE,
        )
        .unwrap();
        assert_eq!(all_buckets.len(), IO_RANGE_LOCK_BUCKETS);
        assert!(
            (1..all_buckets.len())
                .all(|index| { all_buckets.get(index - 1) < all_buckets.get(index) })
        );
        assert_eq!(
            checked_io_block_range(usize::MAX, 1, BLOCK_SIZE),
            Err(DevError::InvalidParam)
        );
    }
}
