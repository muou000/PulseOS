mod fs;
mod inode;
mod util;

#[cfg(feature = "mapping-lifecycle-test")]
mod fault_io_checks;

#[cfg(feature = "mapping-lifecycle-test")]
pub(crate) fn run_fault_io_checks() -> vfs::VfsResult<()> {
    fault_io_checks::run()
}

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
    time::Duration,
};

use async_trait::async_trait;
use driver::prelude::{AsyncBlockDriverOps, BlockDriverOps, DevError};
use kspin::SpinNoPreempt;
pub use fs::*;
use futures_util::{StreamExt, future::join, stream::FuturesUnordered};
pub use inode::*;
use lru::LruCache;

#[derive(Clone, Debug, PartialEq, Eq)]
enum OwnerSet {
    Any,
    One(u64),
    Two(u64, u64),
    Many(BTreeSet<u64>),
}

impl OwnerSet {
    fn from_slice(owners: &[u64]) -> Self {
        let mut set = match owners {
            [] => return Self::Any,
            [a] => return Self::One(*a),
            [a, b] => {
                if a == b {
                    return Self::One(*a);
                }
                return Self::Two((*a).min(*b), (*a).max(*b));
            }
            _ => Self::One(owners[0]),
        };
        for &owner in &owners[1..] {
            set.insert(owner);
        }
        set
    }

    fn insert(&mut self, owner: u64) {
        match self {
            Self::Any => {}
            Self::One(a) => {
                if *a != owner {
                    *self = Self::Two((*a).min(owner), (*a).max(owner));
                }
            }
            Self::Two(a, b) => {
                if *a != owner && *b != owner {
                    let mut set = BTreeSet::new();
                    set.insert(*a);
                    set.insert(*b);
                    set.insert(owner);
                    *self = Self::Many(set);
                }
            }
            Self::Many(set) => {
                set.insert(owner);
            }
        }
    }

    fn merge_from(&mut self, other: &Self) {
        if matches!(self, Self::Any) {
            return;
        }
        match other {
            Self::Any => *self = Self::Any,
            Self::One(a) => self.insert(*a),
            Self::Two(a, b) => {
                self.insert(*a);
                self.insert(*b);
            }
            Self::Many(set) => {
                for &owner in set {
                    self.insert(owner);
                }
            }
        }
    }

    fn matches(&self, owner: u64) -> bool {
        match self {
            Self::Any => true,
            Self::One(a) => *a == owner,
            Self::Two(a, b) => *a == owner || *b == owner,
            Self::Many(set) => set.contains(&owner),
        }
    }
}

struct CacheBlock {
    data: Vec<u8>,
    dirty: bool,
    flushing: bool,
    reused: bool,
    generation: u64,
}

struct DirtyOwnerState {
    sequence: u64,
    owners: OwnerSet,
}

struct WriteScopeState {
    owners: OwnerSet,
    dirty_offsets: Option<Vec<usize>>,
}

struct WriteScopeRegistry {
    scopes: [SpinNoPreempt<BTreeMap<u64, Arc<SpinNoPreempt<WriteScopeState>>>>; WRITE_SCOPE_SHARDS],
    active_by_task: [SpinNoPreempt<BTreeMap<u64, Vec<u64>>>; WRITE_SCOPE_SHARDS],
}

impl Default for WriteScopeRegistry {
    fn default() -> Self {
        Self {
            scopes: core::array::from_fn(|_| SpinNoPreempt::new(BTreeMap::new())),
            active_by_task: core::array::from_fn(|_| SpinNoPreempt::new(BTreeMap::new())),
        }
    }
}

impl WriteScopeRegistry {
    fn scope(&self, scope_id: u64) -> Option<Arc<SpinNoPreempt<WriteScopeState>>> {
        self.scopes[write_scope_shard(scope_id)]
            .lock()
            .get(&scope_id)
            .cloned()
    }

    fn copy_active_scopes(&self, task_id: u64, stack: &mut [u64; 4], overflow: &mut Vec<u64>) -> usize {
        let active_by_task = self.active_by_task[write_scope_shard(task_id)].lock();
        let Some(scopes) = active_by_task.get(&task_id) else {
            return 0;
        };
        if scopes.len() <= stack.len() {
            for (idx, &id) in scopes.iter().enumerate() {
                stack[idx] = id;
            }
            scopes.len()
        } else {
            overflow.extend_from_slice(scopes);
            scopes.len()
        }
    }
}

const BLOCK_CACHE_STRIPES: usize = 16;
const DIRTY_OWNER_SHARDS: usize = BLOCK_CACHE_STRIPES;
const WRITE_SCOPE_SHARDS: usize = 32;
// Keep a bounded 4 MiB metadata/block cache for the common 4 KiB ext4 layout.
// Thirty-two entries per stripe evicted inode tables, bitmaps, and directory
// blocks too aggressively during metadata-heavy builds; doubling this remains
// small relative to the guest memory budget and avoids dirty-eviction copies.
const CACHE_CAPACITY_PER_STRIPE: usize = 64;
const CACHE_EVICTION_SCAN_LIMIT: usize = 64;
const DEVICE_READ_MAX_ATTEMPTS: usize = 2;
// A missing SD/MMC completion interrupt must become an I/O error instead of
// keeping the filesystem task blocked forever. Normal JH7110 transfers are
// well below this bound even at the conservative board clock.
const DEVICE_IO_TIMEOUT: Duration = Duration::from_secs(5);
const FLUSH_BATCH_BLOCKS: usize = 32;
const FLUSH_WRITE_CONCURRENCY: usize = 4;
// A cache miss used to coalesce the whole remaining caller range into one
// temporary Vec.  Besides making a mixed cached/direct I/O request consume a
// second full-sized buffer, a malformed or unexpectedly large request could
// turn that Vec into a multi-hundred-MiB kernel allocation.  Keep the scratch
// buffer aligned with the normal metadata flush batch instead.
const CACHE_MISS_BATCH_BLOCKS: usize = FLUSH_BATCH_BLOCKS;
// One range-lock bucket covers one maximum coalesced metadata flush. This lets
// adjacent non-overlapping flush batches use the configured concurrency rather
// than serializing every pair in the same 64-block bucket. Doubling the table
// preserves the previous 8192-block modulo coverage for distant I/O ranges.
const IO_RANGE_LOCK_BUCKETS: usize = 256;
const IO_RANGE_LOCK_BUCKET_BLOCKS: usize = FLUSH_BATCH_BLOCKS;

#[inline]
fn bounded_cached_miss_blocks(blocks: usize) -> usize {
    blocks.min(CACHE_MISS_BATCH_BLOCKS)
}

fn write_scope_shard(id: u64) -> usize {
    (id as usize ^ (id >> 32) as usize) % WRITE_SCOPE_SHARDS
}

struct CacheStripeInner {
    cache: LruCache<usize, CacheBlock>,
    flushing_evicted: BTreeMap<usize, (u64, Vec<u8>)>,
}

impl CacheStripeInner {
    fn evict_if_full(&mut self, to_write: &mut Vec<(usize, u64, Vec<u8>)>) -> bool {
        if self.cache.len() < self.cache.cap().get() {
            return true;
        }
        let Some((ev_offset, ev_block)) = pop_cache_victim(&mut self.cache) else {
            return false;
        };
        if ev_block.dirty {
            to_write.push((ev_offset, ev_block.generation, ev_block.data.clone()));
            self.flushing_evicted
                .insert(ev_offset, (ev_block.generation, ev_block.data));
        }
        true
    }

    fn insert_cache_block(
        &mut self,
        to_write: &mut Vec<(usize, u64, Vec<u8>)>,
        offset: usize,
        block: CacheBlock,
    ) {
        if self.evict_if_full(to_write) {
            self.cache.put(offset, block);
        } else if block.dirty {
            to_write.push((offset, block.generation, block.data.clone()));
            self.flushing_evicted
                .insert(offset, (block.generation, block.data));
        }
    }
}

struct CacheStripe {
    inner: SpinNoPreempt<CacheStripeInner>,
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
    ) -> driver::prelude::DevResult<IoReadRangeGuards<'_>> {
        let indices = io_range_lock_indices(offset, len, block_size)?;

        if indices.len() == 1 {
            let lock = &self.buckets[indices.get(0)];
            if let Some(guard) = lock.try_read() {
                return Ok(IoReadRangeGuards::One { _guard: guard });
            }
            return Ok(IoReadRangeGuards::One {
                _guard: lock.read().await,
            });
        }

        let mut guards = Vec::with_capacity(indices.len());
        for slot in 0..indices.len() {
            let index = indices.get(slot);
            let lock = &self.buckets[index];
            if let Some(guard) = lock.try_read() {
                guards.push(guard);
            } else {
                guards.push(lock.read().await);
            }
        }
        Ok(IoReadRangeGuards::Many(guards))
    }

    async fn write(
        &self,
        offset: usize,
        len: usize,
        block_size: usize,
    ) -> driver::prelude::DevResult<IoWriteRangeGuards<'_>> {
        let indices = io_range_lock_indices(offset, len, block_size)?;

        if indices.len() == 1 {
            let lock = &self.buckets[indices.get(0)];
            if let Some(guard) = lock.try_write() {
                return Ok(IoWriteRangeGuards::One { _guard: guard });
            }
            return Ok(IoWriteRangeGuards::One {
                _guard: lock.write().await,
            });
        }

        let mut guards = Vec::with_capacity(indices.len());
        for slot in 0..indices.len() {
            let index = indices.get(slot);
            let lock = &self.buckets[index];
            if let Some(guard) = lock.try_write() {
                guards.push(guard);
            } else {
                guards.push(lock.write().await);
            }
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
) -> driver::prelude::DevResult<IoRangeLockIndices> {
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
) -> driver::prelude::DevResult<(usize, usize)> {
    if len == 0 || block_size == 0 {
        return Err(driver::prelude::DevError::InvalidParam);
    }
    let end = offset
        .checked_add(len)
        .ok_or(driver::prelude::DevError::InvalidParam)?;
    Ok((offset / block_size, end.div_ceil(block_size)))
}

fn bypass_block_cache(offset: usize, len: usize, block_size: usize) -> bool {
    len > block_size && offset % block_size == 0 && len % block_size == 0
}

fn retryable_device_read_error(error: &driver::prelude::DevError) -> bool {
    matches!(
        error,
        driver::prelude::DevError::Again | driver::prelude::DevError::Io
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
    dev: D,
    sector_size: usize,
    block_cache_stripes: [CacheStripe; BLOCK_CACHE_STRIPES],
    block_size: AtomicUsize,
    io_ranges: IoRangeLocks,
    checkpoint_lock: async_lock::RwLock<()>,
    device_flush_lock: async_lock::Mutex<()>,
    write_generation: AtomicU64,
    flushed_generation: AtomicU64,
    disk_write_generation: AtomicU64,
    flushed_disk_write_generation: AtomicU64,
    dirty_owners: [SpinNoPreempt<BTreeMap<usize, DirtyOwnerState>>; DIRTY_OWNER_SHARDS],
    dirty_owner_counts: [AtomicUsize; DIRTY_OWNER_SHARDS],
    next_write_scope_id: AtomicU64,
    write_scopes: WriteScopeRegistry,
    flush_scratch: SpinNoPreempt<Vec<Vec<u8>>>,
}

struct ScratchIoBuf<'a> {
    pool: &'a SpinNoPreempt<Vec<Vec<u8>>>,
    buf: Vec<u8>,
}

impl Drop for ScratchIoBuf<'_> {
    fn drop(&mut self) {
        if self.buf.len() == 4096 {
            let mut pool = self.pool.lock();
            if pool.len() < 8 {
                pool.push(core::mem::take(&mut self.buf));
            }
        }
    }
}

impl<D: BlockDriverOps> Ext4Disk<D> {
    fn stripe_index(&self, offset: usize) -> usize {
        let block_size = self.block_size.load(Ordering::Relaxed);
        (offset / block_size) % BLOCK_CACHE_STRIPES
    }
}

struct SingleFlushingGuard<'a, D: BlockDriverOps> {
    disk: &'a Ext4Disk<D>,
    offset: Option<usize>,
}

impl<'a, D: BlockDriverOps> Drop for SingleFlushingGuard<'a, D> {
    fn drop(&mut self) {
        if let Some(offset) = self.offset {
            let stripe_idx = self.disk.stripe_index(offset);
            let mut stripe = self.disk.block_cache_stripes[stripe_idx].inner.lock();
            if let Some(block) = stripe.cache.get_mut(&offset) {
                block.flushing = false;
            }
        }
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
    async fn flush_disk(&self) -> driver::prelude::DevResult<()> {
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

        let first_error = self.flush_batches_with_mode(batches, true).await;

        let flush_result = self.flush_device_with_timeout_async().await;
        if first_error.is_none() && flush_result.is_ok() {
            self.flushed_generation
                .fetch_max(target_generation, Ordering::AcqRel);
            for (shard_idx, owners) in self.dirty_owners.iter().enumerate() {
                if self.dirty_owner_counts[shard_idx].load(Ordering::Acquire) == 0 {
                    continue;
                }
                let mut owners = owners.lock();
                owners.retain(|_, state| state.sequence > target_generation);
                self.dirty_owner_counts[shard_idx].store(owners.len(), Ordering::Release);
            }
        }
        first_error.map_or(flush_result, Err)
    }

    async fn flush_owner(&self, owner: u64) -> driver::prelude::DevResult<()> {
        let (owner_snapshot, batches) = {
            let _checkpoint = self.checkpoint_lock.write().await;
            let owner_snapshot = self.owner_snapshot(owner);
            if owner_snapshot.is_empty() {
                (owner_snapshot, Vec::new())
            } else {
                let block_size = self.block_size();
                let mut selected = Vec::with_capacity(owner_snapshot.len());
                for &(offset, _) in &owner_snapshot {
                    let stripe_idx = (offset / block_size) % BLOCK_CACHE_STRIPES;
                    let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    if stripe.cache.peek(&offset).is_some_and(|block| block.dirty)
                        || stripe.flushing_evicted.contains_key(&offset)
                    {
                        selected.push(offset);
                    }
                }
                (owner_snapshot, group_flush_offsets(&selected, block_size))
            }
        };

        if batches.is_empty()
            && self.flushed_disk_write_generation.load(Ordering::Acquire)
                >= self.disk_write_generation.load(Ordering::Acquire)
        {
            self.clear_flushed_owner_entries(&owner_snapshot);
            return Ok(());
        }

        let (first_error, flush_result) = if batches.len() <= FLUSH_WRITE_CONCURRENCY {
            match task::future::timeout(Some(DEVICE_IO_TIMEOUT), async {
                let first_error = self.flush_batches_with_mode(batches, false).await;
                let flush_result = self.flush_device_raw_async().await;
                (first_error, flush_result)
            })
            .await
            {
                Ok(pair) => pair,
                Err(_) => {
                    log::error!(
                        "ext4 flush_owner timed out after {:?}",
                        DEVICE_IO_TIMEOUT
                    );
                    (None, Err(DevError::Io))
                }
            }
        } else {
            let first_error = self.flush_batches_with_mode(batches, true).await;
            let flush_result = self.flush_device_with_timeout_async().await;
            (first_error, flush_result)
        };

        if first_error.is_none() && flush_result.is_ok() {
            self.clear_flushed_owner_entries(&owner_snapshot);
        }
        first_error.map_or(flush_result, Err)
    }

    fn begin_write_scope(&self, owners: &[u64]) -> u64 {
        self.begin_write_scope_with_tracking(owners, false)
    }

    fn begin_retroactive_write_scope(&self, owners: &[u64]) -> u64 {
        self.begin_write_scope_with_tracking(owners, true)
    }

    fn enter_write_scope(&self, scope_id: u64) {
        let Some(task_id) = task::current_may_uninit().map(|task| task.id().as_u64()) else {
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
            debug_assert!(
                scope.dirty_offsets.is_some(),
                "include_write_owner requires a retroactive write scope"
            );
            scope.owners.insert(owner);
            scope.dirty_offsets.clone().unwrap_or_default()
        };
        for offset in dirty_offsets {
            let shard = self.stripe_index(offset);
            let mut dirty_owners = self.dirty_owners[shard].lock();
            if let Some(state) = dirty_owners.get_mut(&offset) {
                state.owners.insert(owner);
            }
        }
    }

    fn leave_write_scope(&self, scope_id: u64) {
        let Some(task_id) = task::current_may_uninit().map(|task| task.id().as_u64()) else {
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
            dev,
            sector_size,
            block_cache_stripes: core::array::from_fn(|_| CacheStripe {
                inner: SpinNoPreempt::new(CacheStripeInner {
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
            disk_write_generation: AtomicU64::new(0),
            flushed_disk_write_generation: AtomicU64::new(0),
            dirty_owners: core::array::from_fn(|_| SpinNoPreempt::new(BTreeMap::new())),
            dirty_owner_counts: core::array::from_fn(|_| AtomicUsize::new(0)),
            next_write_scope_id: AtomicU64::new(1),
            write_scopes: WriteScopeRegistry::default(),
            flush_scratch: SpinNoPreempt::new(Vec::new()),
        });
        crate::disk::DISK_FLUSHERS
            .lock()
            .push(Arc::downgrade(&disk) as _);
        disk
    }

    fn begin_write_scope_with_tracking(&self, owners: &[u64], track_offsets: bool) -> u64 {
        let scope_id = self
            .next_write_scope_id
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |id| id.checked_add(1))
            .expect("ext4 write scope identifier exhausted");
        let previous = self.write_scopes.scopes[write_scope_shard(scope_id)]
            .lock()
            .insert(
                scope_id,
                Arc::new(SpinNoPreempt::new(WriteScopeState {
                    owners: OwnerSet::from_slice(owners),
                    dirty_offsets: track_offsets.then(Vec::new),
                })),
            );
        debug_assert!(previous.is_none());
        scope_id
    }

    async fn flush_device_raw_async(&self) -> driver::prelude::DevResult<()> {
        let _device_flush = self.device_flush_lock.lock().await;
        let target_disk_gen = self.disk_write_generation.load(Ordering::Acquire);
        self.dev.flush_async().await?;
        self.flushed_disk_write_generation
            .fetch_max(target_disk_gen, Ordering::AcqRel);
        Ok(())
    }

    async fn flush_device_with_timeout_async(&self) -> driver::prelude::DevResult<()> {
        match task::future::timeout(Some(DEVICE_IO_TIMEOUT), self.flush_device_raw_async()).await {
            Ok(result) => result,
            Err(_) => {
                log::error!("ext4 device flush timed out after {:?}", DEVICE_IO_TIMEOUT);
                Err(DevError::Io)
            }
        }
    }

    fn clear_flushed_owner_entries(&self, owner_snapshot: &[(usize, u64)]) {
        for &(offset, sequence) in owner_snapshot {
            let shard = self.stripe_index(offset);
            let mut dirty_owners = self.dirty_owners[shard].lock();
            if dirty_owners.get(&offset).map(|state| state.sequence) == Some(sequence) {
                dirty_owners.remove(&offset);
                self.dirty_owner_counts[shard].store(dirty_owners.len(), Ordering::Release);
            }
        }
    }

    fn byte_range(
        &self,
        offset: usize,
        len: usize,
    ) -> driver::prelude::DevResult<(u64, usize, usize)> {
        let first_block = (offset / self.sector_size) as u64;
        let inner_offset = offset % self.sector_size;
        let touched = inner_offset
            .checked_add(len)
            .ok_or(driver::prelude::DevError::InvalidParam)?;
        let blocks = touched.div_ceil(self.sector_size);
        Ok((first_block, inner_offset, blocks))
    }

    fn zeroed_io_buffer(len: usize) -> driver::prelude::DevResult<Vec<u8>> {
        let mut data = Vec::new();
        // `vec![0; len]` is an infallible allocation path and would panic on
        // allocation failure. Propagate that failure as a device NoMemory
        // error instead; all callers already return DevResult.
        data.try_reserve_exact(len)
            .map_err(|_| driver::prelude::DevError::NoMemory)?;
        data.resize(len, 0);
        Ok(data)
    }

    async fn lock_read_range(
        &self,
        offset: usize,
        len: usize,
    ) -> driver::prelude::DevResult<IoReadRangeGuards<'_>> {
        let guards = self.io_ranges.read(offset, len, self.block_size()).await?;
        debug_assert!(guards.len() > 0);
        Ok(guards)
    }

    async fn lock_write_range(
        &self,
        offset: usize,
        len: usize,
    ) -> driver::prelude::DevResult<IoWriteRangeGuards<'_>> {
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

    fn current_write_owners(&self) -> (OwnerSet, [u64; 4], Vec<u64>, usize) {
        let Some(task_id) = task::current_may_uninit().map(|task| task.id().as_u64()) else {
            return (OwnerSet::Any, [0; 4], Vec::new(), 0);
        };
        let mut stack = [0u64; 4];
        let mut overflow = Vec::new();
        let count = self.write_scopes.copy_active_scopes(task_id, &mut stack, &mut overflow);
        if count == 0 {
            return (OwnerSet::Any, stack, overflow, 0);
        }
        let scope_ids: &[u64] = if overflow.is_empty() {
            &stack[..count]
        } else {
            &overflow
        };
        let mut combined: Option<OwnerSet> = None;
        for &scope_id in scope_ids {
            if let Some(scope) = self.write_scopes.scope(scope_id) {
                let scope_owners = &scope.lock().owners;
                match &mut combined {
                    Some(existing) => existing.merge_from(scope_owners),
                    None => combined = Some(scope_owners.clone()),
                }
            }
        }
        (combined.unwrap_or(OwnerSet::Any), stack, overflow, count)
    }

    fn mark_dirty_block(
        &self,
        offset: usize,
        sequence: u64,
        owners: &OwnerSet,
        scope_stack: &[u64; 4],
        scope_overflow: &[u64],
        scope_count: usize,
    ) {
        {
            let shard = self.stripe_index(offset);
            let mut dirty_owners = self.dirty_owners[shard].lock();
            match dirty_owners.entry(offset) {
                alloc::collections::btree_map::Entry::Occupied(mut entry) => {
                    let state = entry.get_mut();
                    state.sequence = sequence;
                    state.owners.merge_from(owners);
                }
                alloc::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(DirtyOwnerState {
                        sequence,
                        owners: owners.clone(),
                    });
                    self.dirty_owner_counts[shard].store(dirty_owners.len(), Ordering::Release);
                }
            }
        }

        if scope_count == 0 {
            return;
        }
        let scope_ids: &[u64] = if scope_overflow.is_empty() {
            &scope_stack[..scope_count]
        } else {
            scope_overflow
        };
        for &scope_id in scope_ids {
            if let Some(scope) = self.write_scopes.scope(scope_id) {
                let mut scope = scope.lock();
                if let Some(dirty_offsets) = &mut scope.dirty_offsets {
                    dirty_offsets.push(offset);
                }
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
            let mut dirty_owners = self.dirty_owners[stripe_idx].lock();
            dirty_owners.remove(&offset);
            self.dirty_owner_counts[stripe_idx].store(dirty_owners.len(), Ordering::Release);
        }
    }

    fn owner_snapshot(&self, owner: u64) -> Vec<(usize, u64)> {
        let mut snapshot = Vec::new();
        for (shard_idx, owners) in self.dirty_owners.iter().enumerate() {
            if self.dirty_owner_counts[shard_idx].load(Ordering::Acquire) == 0 {
                continue;
            }
            snapshot.extend(owners.lock().iter().filter_map(|(&offset, state)| {
                state.owners.matches(owner).then_some((offset, state.sequence))
            }));
        }
        if snapshot.len() > 1 {
            snapshot.sort_unstable_by_key(|(offset, _)| *offset);
        }
        snapshot
    }

    async fn flush_batches_with_mode(
        &self,
        mut batches: Vec<Vec<usize>>,
        with_per_batch_timeout: bool,
    ) -> Option<driver::prelude::DevError> {
        match batches.len() {
            0 => None,
            1 => {
                let batch = batches.pop().unwrap();
                self.flush_offset_batch(batch, with_per_batch_timeout)
                    .await
                    .err()
            }
            2 => {
                let second = batches.pop().unwrap();
                let first = batches.pop().unwrap();
                let (r1, r2) = join(
                    self.flush_offset_batch(first, with_per_batch_timeout),
                    self.flush_offset_batch(second, with_per_batch_timeout),
                )
                .await;
                r1.err().or_else(|| r2.err())
            }
            _ => {
                let mut batches = batches.into_iter();
                let mut pending = FuturesUnordered::new();
                let mut first_error = None;
                loop {
                    while pending.len() < FLUSH_WRITE_CONCURRENCY {
                        let Some(batch) = batches.next() else {
                            break;
                        };
                        pending.push(self.flush_offset_batch(batch, with_per_batch_timeout));
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
        }
    }

    fn complete_flushed_block(&self, offset: usize, written_gen: u64, clear_flushing_on_mismatch: bool) {
        let stripe_idx = self.stripe_index(offset);
        let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
        if let Some(block) = stripe.cache.get_mut(&offset)
            && block.flushing
        {
            if block.generation == written_gen {
                block.dirty = false;
                block.flushing = false;
            } else if clear_flushing_on_mismatch {
                block.flushing = false;
            }
        }
        if stripe
            .flushing_evicted
            .get(&offset)
            .is_some_and(|(evicted_gen, _)| *evicted_gen == written_gen)
        {
            stripe.flushing_evicted.remove(&offset);
        }
    }

    async fn flush_offset_batch(
        &self,
        offsets: Vec<usize>,
        with_timeout: bool,
    ) -> driver::prelude::DevResult<()> {
        let Some((&first_offset, &last_offset)) = offsets.first().zip(offsets.last()) else {
            return Ok(());
        };
        let block_size = self.block_size();
        let span = last_offset
            .checked_sub(first_offset)
            .and_then(|span| span.checked_add(block_size))
            .ok_or(driver::prelude::DevError::InvalidParam)?;
        let _io_guard = self.lock_write_range(first_offset, span).await?;

        if offsets.len() == 1 && block_size == 4096 {
            let offset = first_offset;
            let mut scratch = {
                let pooled = self.flush_scratch.lock().pop();
                let mut buf = match pooled {
                    Some(buf) => buf,
                    None => Self::zeroed_io_buffer(4096)?,
                };
                buf.resize(4096, 0);
                ScratchIoBuf {
                    pool: &self.flush_scratch,
                    buf,
                }
            };
            let (written_gen, flushing_offset) = {
                let stripe_idx = self.stripe_index(offset);
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if let Some(block) = stripe.cache.get_mut(&offset)
                    && block.dirty
                {
                    block.flushing = true;
                    scratch.buf.copy_from_slice(&block.data);
                    (Some(block.generation), Some(offset))
                } else if let Some((evicted_gen, data)) = stripe.flushing_evicted.get(&offset) {
                    scratch.buf.copy_from_slice(data);
                    (Some(*evicted_gen), None)
                } else {
                    (None, None)
                }
            };
            let mut flushing_guard = SingleFlushingGuard {
                disk: self,
                offset: flushing_offset,
            };
            let Some(written_gen) = written_gen else {
                return Ok(());
            };
            if with_timeout {
                self.write_block_to_disk_async(offset, &scratch.buf).await?;
            } else {
                self.write_block_to_disk_raw_async(offset, &scratch.buf)
                    .await?;
            }

            self.complete_flushed_block(offset, written_gen, true);
            flushing_guard.offset = None;
            return Ok(());
        }

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
                    blocks.push((offset, block.generation, block.data.clone()));
                    flushing_offsets.push(offset);
                    continue;
                }
                if let Some((evicted_gen, data)) = stripe.flushing_evicted.get(&offset) {
                    blocks.push((offset, *evicted_gen, data.clone()));
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
            for (_, _, data) in &blocks[start..end] {
                merged.extend_from_slice(data);
            }
            if with_timeout {
                self.write_block_to_disk_async(blocks[start].0, &merged)
                    .await?;
            } else {
                self.write_block_to_disk_raw_async(blocks[start].0, &merged)
                    .await?;
            }

            for (offset, written_gen, _) in &blocks[start..end] {
                self.complete_flushed_block(*offset, *written_gen, false);
            }
            start = end;
        }
        Ok(())
    }

    async fn flush_evicted_blocks(
        &self,
        blocks: Vec<(usize, u64, Vec<u8>)>,
    ) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        for (offset, evicted_gen, data) in blocks {
            let _guard = self.lock_write_range(offset, data.len()).await?;
            let stripe_idx = self.stripe_index(offset);
            {
                let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if !stripe
                    .flushing_evicted
                    .get(&offset)
                    .is_some_and(|(current_gen, _)| *current_gen == evicted_gen)
                {
                    continue;
                }
            }

            self.write_block_to_disk_async(offset, &data).await?;
            {
                let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                if stripe
                    .flushing_evicted
                    .get(&offset)
                    .is_some_and(|(current_gen, _)| *current_gen == evicted_gen)
                {
                    stripe.flushing_evicted.remove(&offset);
                }
            }
            self.forget_submitted_offset(offset);
        }
        Ok(())
    }

    async fn write_block_to_disk_raw_async(
        &self,
        block_offset: usize,
        data: &[u8],
    ) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        let (first_block, ..) = self.byte_range(block_offset, data.len())?;
        self.dev.write_block_async(first_block, data).await?;
        self.disk_write_generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    async fn write_block_to_disk_async(
        &self,
        block_offset: usize,
        data: &[u8],
    ) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        let (first_block, ..) = self.byte_range(block_offset, data.len())?;
        match task::future::timeout(
            Some(DEVICE_IO_TIMEOUT),
            self.dev.write_block_async(first_block, data),
        )
        .await
        {
            Ok(Ok(())) => {
                self.disk_write_generation.fetch_add(1, Ordering::AcqRel);
                Ok(())
            }
            Ok(Err(err)) => {
                log::error!(
                    "ext4 async write failed: block_offset={}, err={:?}",
                    block_offset,
                    err
                );
                Err(err)
            }
            Err(_) => {
                log::error!(
                    "ext4 async write timed out: block_offset={}, first_block={}, len={}, \
                     timeout={:?}",
                    block_offset,
                    first_block,
                    data.len(),
                    DEVICE_IO_TIMEOUT
                );
                Err(DevError::Io)
            }
        }
    }

    async fn read_blocks_from_disk_async(
        &self,
        block_offset: usize,
        num_blocks: usize,
        dest: &mut [u8],
    ) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        let block_size = self.block_size();
        let requested_len = num_blocks
            .checked_mul(block_size)
            .ok_or(driver::prelude::DevError::InvalidParam)?;
        if dest.len() != requested_len {
            return Err(driver::prelude::DevError::InvalidParam);
        }
        let (first_block, inner_offset, blocks) = self.byte_range(block_offset, requested_len)?;
        let raw_len = blocks
            .checked_mul(self.sector_size)
            .ok_or(driver::prelude::DevError::InvalidParam)?;
        let total_blocks = self.dev.num_blocks();
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
            return Err(driver::prelude::DevError::InvalidParam);
        }
        if inner_offset == 0 && dest.len() == raw_len {
            Self::read_device_blocks(&self.dev, first_block, dest).await
        } else {
            let mut raw = Self::zeroed_io_buffer(raw_len)?;
            Self::read_device_blocks(&self.dev, first_block, &mut raw).await?;
            let end = inner_offset
                .checked_add(requested_len)
                .ok_or(driver::prelude::DevError::InvalidParam)?;
            dest.copy_from_slice(&raw[inner_offset..end]);
            Ok(())
        }
    }

    async fn read_device_blocks(
        dev: &D,
        first_block: u64,
        dest: &mut [u8],
    ) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps,
    {
        for attempt in 1..=DEVICE_READ_MAX_ATTEMPTS {
            let read_result = match task::future::timeout(
                Some(DEVICE_IO_TIMEOUT),
                dev.read_block_async(first_block, dest),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => {
                    log::error!(
                        "ext4 device read timed out: first_block={}, len={}, attempt={}/{}, \
                         timeout={:?}",
                        first_block,
                        dest.len(),
                        attempt,
                        DEVICE_READ_MAX_ATTEMPTS,
                        DEVICE_IO_TIMEOUT
                    );
                    Err(DevError::Io)
                }
            };
            match read_result {
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
    ) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        self.read_offset_with_io(offset, buf, 0..0).await.map(|_| ())
    }

    pub async fn read_offset_with_io(
        &self,
        offset: usize,
        buf: &mut [u8],
        observed: core::ops::Range<usize>,
    ) -> driver::prelude::DevResult<bool>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        if buf.is_empty() {
            return Ok(false);
        }
        if observed.start > observed.end || observed.end > buf.len() {
            return Err(driver::prelude::DevError::InvalidParam);
        }
        let observed_start = offset.checked_add(observed.start)
            .ok_or(driver::prelude::DevError::InvalidParam)?;
        let observed_end = offset.checked_add(observed.end)
            .ok_or(driver::prelude::DevError::InvalidParam)?;
        let overlaps = |start: usize, len: usize| {
            observed_start < observed_end && start < observed_end
                && observed_start.saturating_sub(start) < len
        };
        let mut storage_read = false;
        let io_guard = self.lock_read_range(offset, buf.len()).await?;
        let mut deferred_writes = Vec::new();
        log::debug!("ext4 read_offset: offset={}, len={}", offset, buf.len());
        let block_size = self.block_size();

        if block_size == 0 {
            return Err(driver::prelude::DevError::InvalidParam);
        }
        let request_end = offset
            .checked_add(buf.len())
            .ok_or(driver::prelude::DevError::InvalidParam)?;

        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((request_end - 1) / block_size) * block_size;

        // Keep one-block metadata I/O in the cache. Directly forwarding those
        // requests makes every directory, bitmap, and inode access pay an IRQ
        // completion plus task block/wake; multi-block transfers still bypass
        // the cache to avoid copying and cache pollution.
        let direct_block_io = bypass_block_cache(offset, buf.len(), block_size);
        if direct_block_io {
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
                return self
                    .read_blocks_from_disk_async(offset, buf.len() / block_size, buf)
                    .await.map(|()| !observed.is_empty());
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
                    let end = core::cmp::min(request_end, current_block_offset + block_size);
                    let overlap_len = end - start;
                    let buf_start = start - offset;
                    let block_start = start - current_block_offset;
                    buf[buf_start..buf_start + overlap_len]
                        .copy_from_slice(&block.data[block_start..block_start + overlap_len]);
                    true
                } else if let Some((_, data)) = stripe.flushing_evicted.get(&current_block_offset) {
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(request_end, current_block_offset + block_size);
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
                current_block_offset += block_size;
            } else {
                // Cache miss. Find consecutive cache misses.
                let remaining_blocks = end_block_offset
                    .checked_sub(current_block_offset)
                    .ok_or(driver::prelude::DevError::InvalidParam)?
                    .checked_div(block_size)
                    .and_then(|blocks| blocks.checked_add(1))
                    .ok_or(driver::prelude::DevError::InvalidParam)?;
                let batch_limit = bounded_cached_miss_blocks(remaining_blocks);
                let mut consecutive_misses = 1;
                {
                    while consecutive_misses < batch_limit {
                        let next_block_offset = current_block_offset
                            .checked_add(
                                consecutive_misses
                                    .checked_mul(block_size)
                                    .ok_or(driver::prelude::DevError::InvalidParam)?,
                            )
                            .ok_or(driver::prelude::DevError::InvalidParam)?;
                        if next_block_offset > end_block_offset {
                            break;
                        }
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

                // For an aligned multi-block data request, a mixed cache hit
                // should not force an uncached run through a temporary buffer
                // and then duplicate every block into the metadata cache.
                if direct_block_io && consecutive_misses > 1 {
                    let buf_start = current_block_offset - offset;
                    let run_len = consecutive_misses
                        .checked_mul(block_size)
                        .ok_or(driver::prelude::DevError::InvalidParam)?;
                    self.read_blocks_from_disk_async(
                        current_block_offset,
                        consecutive_misses,
                        &mut buf[buf_start..buf_start + run_len],
                    )
                    .await?;
                    storage_read |= overlaps(current_block_offset, run_len);
                    current_block_offset += run_len;
                    continue;
                }

                // Read all consecutive misses from disk in one go
                let run_len = consecutive_misses
                    .checked_mul(block_size)
                    .ok_or(driver::prelude::DevError::InvalidParam)?;
                let mut run_data = Self::zeroed_io_buffer(run_len)?;
                self.read_blocks_from_disk_async(
                    current_block_offset,
                    consecutive_misses,
                    &mut run_data,
                )
                .await?;
                storage_read |= overlaps(current_block_offset, run_len);

                if consecutive_misses == 1 {
                    let start = core::cmp::max(offset, current_block_offset);
                    let end = core::cmp::min(request_end, current_block_offset + block_size);
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
                        } else if let Some((_, data)) =
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
                                generation: 0,
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
                    let end = core::cmp::min(request_end, b_offset + block_size);
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
                    } else if let Some((_, data)) = stripe.flushing_evicted.get(&b_offset) {
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
                            generation: 0,
                        };
                        stripe.insert_cache_block(&mut to_write, b_offset, block);
                    }
                }

                deferred_writes.extend(to_write);

                current_block_offset = current_block_offset
                    .checked_add(run_len)
                    .ok_or(driver::prelude::DevError::InvalidParam)?;
            }
        }
        drop(io_guard);
        self.flush_evicted_blocks(deferred_writes).await?;
        log::debug!("ext4 read_offset done: offset={}", offset);
        Ok(storage_read)
    }

    pub async fn write_offset(&self, offset: usize, data: &[u8]) -> driver::prelude::DevResult<()>
    where
        D: AsyncBlockDriverOps + Clone,
    {
        if data.is_empty() {
            return Ok(());
        }
        crate::request_writeback();
        // A flush checkpoint briefly takes the exclusive side to include every
        // write that started before it. Writes otherwise share this lock and
        // retain range-level concurrency.
        let _checkpoint = self.checkpoint_lock.read().await;
        let sequence = self
            .write_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let (owners, scope_stack, scope_overflow, scope_count) = self.current_write_owners();
        let io_guard = self.lock_write_range(offset, data.len()).await?;
        let mut deferred_writes = Vec::new();
        log::debug!("ext4 write_offset: offset={}, len={}", offset, data.len());
        let block_size = self.block_size();

        if block_size == 0 {
            return Err(driver::prelude::DevError::InvalidParam);
        }
        let request_end = offset
            .checked_add(data.len())
            .ok_or(driver::prelude::DevError::InvalidParam)?;

        let start_block_offset = (offset / block_size) * block_size;
        let end_block_offset = ((request_end - 1) / block_size) * block_size;

        if bypass_block_cache(offset, data.len(), block_size) {
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
            let end = core::cmp::min(request_end, current_block_offset + block_size);
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
                    block.generation = sequence;
                    true
                } else {
                    false
                }
            };

            if has_cache {
                self.mark_dirty_block(
                    current_block_offset,
                    sequence,
                    &owners,
                    &scope_stack,
                    &scope_overflow,
                    scope_count,
                );
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
                    generation: sequence,
                };
                {
                    let stripe_idx = self.stripe_index(current_block_offset);
                    let mut stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                    stripe.flushing_evicted.remove(&current_block_offset);
                    stripe.insert_cache_block(&mut deferred_writes, current_block_offset, block);
                }
                self.mark_dirty_block(
                    current_block_offset,
                    sequence,
                    &owners,
                    &scope_stack,
                    &scope_overflow,
                    scope_count,
                );
                current_block_offset += block_size;
            } else {
                // Partial block write with cache miss. Find consecutive cache misses that need partial write.
                let remaining_blocks = end_block_offset
                    .checked_sub(current_block_offset)
                    .ok_or(driver::prelude::DevError::InvalidParam)?
                    .checked_div(block_size)
                    .and_then(|blocks| blocks.checked_add(1))
                    .ok_or(driver::prelude::DevError::InvalidParam)?;
                let batch_limit = bounded_cached_miss_blocks(remaining_blocks);
                let mut consecutive_misses = 1;
                {
                    while consecutive_misses < batch_limit {
                        let next_block_offset = current_block_offset
                            .checked_add(
                                consecutive_misses
                                    .checked_mul(block_size)
                                    .ok_or(driver::prelude::DevError::InvalidParam)?,
                            )
                            .ok_or(driver::prelude::DevError::InvalidParam)?;
                        if next_block_offset > end_block_offset {
                            break;
                        }
                        let stripe_idx = self.stripe_index(next_block_offset);
                        let stripe = self.block_cache_stripes[stripe_idx].inner.lock();
                        if stripe.cache.contains(&next_block_offset)
                            || stripe.flushing_evicted.contains_key(&next_block_offset)
                        {
                            break;
                        }
                        let next_start = core::cmp::max(offset, next_block_offset);
                        let next_end = core::cmp::min(request_end, next_block_offset + block_size);
                        let next_overlap = next_end - next_start;
                        if next_overlap == block_size {
                            break;
                        }
                        consecutive_misses += 1;
                    }
                }

                // Pre-read consecutive partial miss blocks from disk in one go
                let run_len = consecutive_misses
                    .checked_mul(block_size)
                    .ok_or(driver::prelude::DevError::InvalidParam)?;
                let mut run_data = Self::zeroed_io_buffer(run_len)?;
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
                    let end = core::cmp::min(request_end, b_offset + block_size);
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
                        existing.generation = sequence;
                    } else {
                        let flushing_data = stripe.flushing_evicted.remove(&b_offset);
                        if let Some((_, mut flushing_data)) = flushing_data {
                            flushing_data[block_start..block_start + overlap_len]
                                .copy_from_slice(&data[data_start..data_start + overlap_len]);
                            let block = CacheBlock {
                                data: flushing_data,
                                dirty: true,
                                flushing: false,
                                reused: true,
                                generation: sequence,
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
                                generation: sequence,
                            };
                            stripe.insert_cache_block(&mut to_write, b_offset, block);
                        }
                    }
                    marked_offsets.push(b_offset);
                }

                for offset in marked_offsets {
                    self.mark_dirty_block(
                        offset,
                        sequence,
                        &owners,
                        &scope_stack,
                        &scope_overflow,
                        scope_count,
                    );
                }

                deferred_writes.extend(to_write);

                current_block_offset = current_block_offset
                    .checked_add(run_len)
                    .ok_or(driver::prelude::DevError::InvalidParam)?;
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
        for (shard_idx, owners) in self.dirty_owners.iter().enumerate() {
            owners.lock().clear();
            self.dirty_owner_counts[shard_idx].store(0, Ordering::Release);
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
struct Ext4DevError(driver::prelude::DevError);

impl Ext4DevError {
    fn to_vfs_error(&self) -> vfs::VfsError {
        use driver::prelude::DevError;
        use vfs::VfsError;

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

    async fn read_with_io(
        &self,
        start_byte: u64,
        dst: &mut [u8],
        observed: core::ops::Range<usize>,
    ) -> Result<Option<bool>, alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.read_offset_with_io(start_byte as usize, dst, observed).await
            .map(Some)
            .map_err(|err| alloc::boxed::Box::new(Ext4DevError(err)) as _)
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
    use driver::prelude::DevError;

    use super::{
        CACHE_MISS_BATCH_BLOCKS, FLUSH_BATCH_BLOCKS, IO_RANGE_LOCK_BUCKET_BLOCKS,
        IO_RANGE_LOCK_BUCKETS, bounded_cached_miss_blocks, bypass_block_cache,
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
    fn cached_miss_scratch_buffer_is_bounded() {
        // 163840 ext4 4 KiB blocks equal the 640 MiB allocation seen on the
        // board. It must now be split before a temporary I/O Vec is created.
        assert_eq!(bounded_cached_miss_blocks(163_840), CACHE_MISS_BATCH_BLOCKS);
        assert_eq!(bounded_cached_miss_blocks(1), 1);
    }

    #[test]
    fn adjacent_flush_batches_use_independent_range_locks() {
        const BLOCK_SIZE: usize = 4096;
        let batch_len = FLUSH_BATCH_BLOCKS * BLOCK_SIZE;
        let first = io_range_lock_indices(0, batch_len, BLOCK_SIZE).unwrap();
        let second = io_range_lock_indices(batch_len, batch_len, BLOCK_SIZE).unwrap();

        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        assert_ne!(first.get(0), second.get(0));
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
