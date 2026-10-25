//! Opt-in guest checks using real cache frames and asynchronous FileNode I/O.
//! The backend injects storage errors; it does not claim physical disk coverage.

use alloc::{boxed::Box, sync::Arc, task::Wake, vec::Vec};
use core::{
    any::Any,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use axfs_ng_vfs::{
    FileNode, FileNodeOps, FilesystemOps, Metadata, MetadataUpdate, NodeOps, VfsError, VfsResult,
};
use axhal::mem::PhysAddr;
use axpoll::{IoEvents, Pollable};
use spin::Mutex;

use super::{
    CachedFileShared, FileCacheKey, PAGE_SIZE, PageCache, UnlinkedFileCacheLease, WritebackPage,
    active_disk_file_cache_snapshot, detach_file_cache_state, discard_unlinked_file_cache_after,
    file_state_registry_shard, flush_all_file_caches_async, flush_file_cache_state,
    flush_pending_file_caches_async, page_cache_reclaim_inner,
    release_unreferenced_disk_file_caches, FILE_SHARED_STATES,
};

macro_rules! check {
    ($condition:expr) => {
        if !$condition {
            error!("MLC_KERNEL FAIL cache assertion line={} {}", line!(), stringify!($condition));
            return Err(VfsError::BadState);
        }
    };
}

struct NoopWake;
impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(NoopWake));
    future.poll(&mut Context::from_waker(&waker))
}

struct TestFile {
    inode: u64,
    data: Mutex<Vec<u8>>,
    fail_write: AtomicBool,
    fail_sync: AtomicBool,
    pause_write: AtomicBool,
    pause_sync: AtomicBool,
    writes: AtomicUsize,
    syncs: AtomicUsize,
}

#[async_trait::async_trait]
impl NodeOps for TestFile {
    fn inode(&self) -> u64 { self.inode }
    async fn metadata(&self) -> VfsResult<Metadata> { Err(VfsError::Unsupported) }
    async fn update_metadata(&self, _update: MetadataUpdate) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }
    async fn len(&self) -> VfsResult<u64> { Ok(self.data.lock().len() as u64) }
    fn filesystem(&self) -> &dyn FilesystemOps {
        panic!("cache lifecycle checks do not query filesystem metadata")
    }
    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        self.syncs.fetch_add(1, Ordering::Relaxed);
        core::future::poll_fn(|cx| {
            if self.pause_sync.load(Ordering::Acquire) {
                cx.waker().wake_by_ref();
                Poll::Pending::<VfsResult<()>>
            } else if self.fail_sync.load(Ordering::Acquire) {
                Poll::Ready(Err(VfsError::Io))
            } else {
                Poll::Ready(Ok(()))
            }
        }).await
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> { self }
}

impl Pollable for TestFile {
    fn poll(&self) -> IoEvents { IoEvents::IN | IoEvents::OUT }
    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}

#[async_trait::async_trait]
impl FileNodeOps for TestFile {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let data = self.data.lock();
        let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidInput)?;
        let count = buf.len().min(data.len().saturating_sub(offset));
        if count != 0 { buf[..count].copy_from_slice(&data[offset..offset + count]); }
        Ok(count)
    }
    async fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        core::future::poll_fn(|cx| {
            if self.pause_write.load(Ordering::Acquire) {
                cx.waker().wake_by_ref();
                Poll::Pending::<VfsResult<()>>
            } else {
                Poll::Ready(Ok(()))
            }
        }).await?;
        if self.fail_write.load(Ordering::Acquire) { return Err(VfsError::Io); }
        let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidInput)?;
        let end = offset.checked_add(buf.len()).ok_or(VfsError::InvalidInput)?;
        let mut data = self.data.lock();
        if end > data.len() { data.resize(end, 0); }
        data[offset..end].copy_from_slice(buf);
        Ok(buf.len())
    }
    async fn append(&self, _buf: &[u8]) -> VfsResult<(usize, u64)> { Err(VfsError::Unsupported) }
    async fn set_len(&self, len: u64) -> VfsResult<()> {
        self.data.lock().resize(usize::try_from(len).map_err(|_| VfsError::InvalidInput)?, 0);
        Ok(())
    }
    async fn set_symlink(&self, _target: &str) -> VfsResult<()> { Err(VfsError::Unsupported) }
}

struct CacheCase {
    shared: Arc<CachedFileShared>,
    backend: Arc<TestFile>,
    file: FileNode,
}

impl CacheCase {
    fn new() -> VfsResult<Self> {
        let backend = Arc::new(TestFile {
            inode: 67,
            data: Mutex::new(alloc::vec![0; PAGE_SIZE]),
            fail_write: AtomicBool::new(false),
            fail_sync: AtomicBool::new(false),
            pause_write: AtomicBool::new(false),
            pause_sync: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
            syncs: AtomicUsize::new(0),
        });
        let file = FileNode::new(backend.clone());
        let shared = Arc::new(CachedFileShared::new(0, false, PAGE_SIZE as u64, Some(file.clone())));
        let mut page = PageCache::new(false)?;
        page.data().fill(0x67);
        let paddr = page.paddr();
        check!(axalloc::frame_table().contains(paddr));
        shared.page_cache.lock().put(0, page);
        shared.mark_page_dirty_if_paddr(0, paddr, false)?;
        Ok(Self { shared, backend, file })
    }
    fn dirty(&self) -> VfsResult<bool> {
        self.shared.page_cache.lock().peek(&0).map(|page| page.dirty).ok_or(VfsError::BadState)
    }
    fn checkpoint(&self) -> VfsResult<()> {
        axtask::future::block_on(flush_file_cache_state(self.shared.clone()))
            .ok_or(VfsError::BadState)?.1
    }
    fn sync(&self) -> VfsResult<()> {
        axtask::future::block_on(async {
            let _guard = self.shared.io_lock.write().await;
            self.shared.sync_dirty_pages_async(&self.file, false).await
        })
    }
}

struct MappingPin(PhysAddr);
impl Drop for MappingPin {
    fn drop(&mut self) {
        let remaining = axalloc::frame_table().dec_ref(self.0);
        debug_assert_ne!(remaining, 0, "cache frame must still own its reference");
    }
}

fn identity_publication() -> VfsResult<()> {
    let case = CacheCase::new()?;
    case.checkpoint()?;
    let pin = {
        let mut cache = case.shared.page_cache.lock();
        MappingPin(cache.get_mut(&0).ok_or(VfsError::BadState)?.pin_for_mapping(false)?)
    };
    let paddr = pin.0;
    let identity = case.shared.retain_shared_page_if_paddr(0, paddr)?;
    check!(identity.page_num() == 0 && identity.paddr() == paddr);
    check!(matches!(case.shared.retain_shared_page_if_paddr(0, paddr + PAGE_SIZE), Err(VfsError::BadState)));
    let generation = case.shared.writeback_generation.load(Ordering::Acquire);
    let writes = case.backend.writes.load(Ordering::Acquire);
    check!(case.shared.mark_page_dirty_if_paddr(0, paddr + PAGE_SIZE, false) == Err(VfsError::BadState));
    check!(!case.dirty()? && case.shared.writeback_generation.load(Ordering::Acquire) == generation);
    case.shared.mark_page_dirty_if_paddr(0, paddr, false)?;
    check!(case.dirty()? && case.shared.has_pending_background_writeback());
    check!(case.backend.writes.load(Ordering::Acquire) == writes && case.backend.syncs.load(Ordering::Acquire) == 0);
    case.checkpoint()?;
    drop(pin);
    {
        let mut cache = case.shared.page_cache.lock();
        check!(CachedFileShared::pop_clean_lru_pages(&mut cache, 1).is_empty());
        check!(identity.is_current()); // Atomic check with the cache mutex held.
    }
    axtask::future::block_on(async {
        let _guard = case.shared.io_lock.write().await;
        case.shared.discard_direct_write_range_without_writeback_async(&case.file, 0, PAGE_SIZE).await
    })?;
    check!(!identity.is_current() && case.shared.page_cache.lock().is_empty());
    Ok(())
}

fn write_failure_retry() -> VfsResult<()> {
    let case = CacheCase::new()?;
    case.backend.fail_write.store(true, Ordering::Release);
    check!(case.checkpoint() == Err(VfsError::Io));
    check!(case.dirty()? && case.shared.has_pending_background_writeback());
    check!(case.shared.completed_writeback_generation.load(Ordering::Acquire) == 0);
    check!(case.backend.data.lock()[0] == 0);
    case.backend.fail_write.store(false, Ordering::Release);
    case.checkpoint()?;
    check!(!case.dirty()? && !case.shared.has_pending_background_writeback());
    check!(case.backend.data.lock()[0] == 0x67 && case.backend.syncs.load(Ordering::Acquire) == 0);
    Ok(())
}

fn redirty_checkpoint() -> VfsResult<()> {
    let case = CacheCase::new()?;
    case.backend.pause_write.store(true, Ordering::Release);
    let target = case.shared.writeback_generation.load(Ordering::Acquire);
    let mut checkpoint = Box::pin(flush_file_cache_state(case.shared.clone()));
    check!(poll_once(checkpoint.as_mut()).is_pending());
    check!(case.backend.writes.load(Ordering::Acquire) == 1);
    let paddr = {
        let mut cache = case.shared.page_cache.lock();
        let page = cache.get_mut(&0).ok_or(VfsError::BadState)?;
        page.data()[0] = 0x68;
        page.paddr()
    };
    case.shared.mark_page_dirty_if_paddr(0, paddr, false)?;
    case.backend.pause_write.store(false, Ordering::Release);
    axtask::future::block_on(checkpoint).ok_or(VfsError::BadState)?.1?;
    check!(case.backend.data.lock()[0] == 0x67);
    check!(case.dirty()? && case.shared.has_pending_background_writeback());
    check!(case.shared.completed_writeback_generation.load(Ordering::Acquire) == target);
    case.checkpoint()?;
    check!(case.backend.data.lock()[0] == 0x68 && !case.dirty()? && !case.shared.has_pending_background_writeback());
    Ok(())
}

fn inject_sync_failure(case: &CacheCase) -> VfsResult<VfsError> {
    case.backend.fail_sync.store(true, Ordering::Release);
    let failure = case.sync().err().ok_or(VfsError::BadState)?;
    case.backend.fail_sync.store(false, Ordering::Release);
    check!(failure == VfsError::Io && case.dirty()? && case.shared.has_pending_background_writeback());
    check!(case.backend.data.lock()[0] == 0x67 && case.backend.syncs.load(Ordering::Acquire) == 1);
    Ok(failure)
}

pub(super) fn failed_sync() -> VfsResult<()> {
    let case = CacheCase::new()?;
    let failure = inject_sync_failure(&case)?;
    case.sync()?;
    check!(!case.dirty()?);
    Err(failure) // Actual captured storage failure for the shutdown barrier callback.
}

fn durability_recovery() -> VfsResult<()> {
    let case = CacheCase::new()?;
    check!(inject_sync_failure(&case)? == VfsError::Io);
    case.backend.pause_sync.store(true, Ordering::Release);
    let mut sync = Box::pin(async {
        let _guard = case.shared.io_lock.write().await;
        case.shared.sync_dirty_pages_async(&case.file, false).await
    });
    check!(poll_once(sync.as_mut()).is_pending() && !case.dirty()?);
    drop(sync);
    check!(case.dirty()? && case.shared.has_pending_background_writeback());
    case.backend.pause_sync.store(false, Ordering::Release);
    case.sync()?;
    check!(!case.dirty()? && case.backend.syncs.load(Ordering::Acquire) == 3);
    Ok(())
}

fn snapshot(page: &PageCache) -> WritebackPage {
    WritebackPage {
        page_num: 0, frame: page.frame.clone(), len: PAGE_SIZE,
        content_generation: page.content_generation,
        writable_mapping_generation: page.writable_mapping_generation,
        compare_contents: true,
    }
}

fn snapshot_identity_generations() -> VfsResult<()> {
    let mut page = PageCache::new(false)?;
    page.mark_dirty();
    let bytes = page.data().to_vec();
    let old_mapping = snapshot(&page);
    page.writable_mapping_generation += 1;
    old_mapping.complete(&mut page, &bytes);
    check!(page.dirty);
    let old_bytes = snapshot(&page);
    page.data()[0] = 1;
    old_bytes.complete(&mut page, &bytes);
    check!(page.dirty);
    let current = snapshot(&page);
    let bytes = page.data().to_vec();
    let mut replacement = PageCache::new(false)?;
    replacement.mark_dirty();
    replacement.writable_mapping_generation = page.writable_mapping_generation;
    replacement.data().copy_from_slice(&bytes);
    check!(replacement.content_generation == current.content_generation);
    current.complete(&mut replacement, &bytes);
    check!(replacement.dirty);
    current.complete(&mut page, &bytes);
    check!(!page.dirty);
    snapshot(&replacement).complete(&mut replacement, &bytes);
    check!(!replacement.dirty);
    Ok(())
}

pub(super) fn run() -> VfsResult<()> {
    let checks: [(&str, fn() -> VfsResult<()>); 5] = [
        ("cache_identity_publication", identity_publication),
        ("cache_write_failure_retry", write_failure_retry),
        ("cache_redirty_checkpoint", redirty_checkpoint),
        ("cache_durability_recovery", durability_recovery),
        ("cache_snapshot_identity_generations", snapshot_identity_generations),
    ];
    for (name, check) in checks {
        if let Err(err) = check() {
            error!("MLC_KERNEL FAIL {} {:?}", name, err);
            return Err(err);
        }
        info!("MLC_KERNEL PASS {}", name);
    }
    run_cache_shard_regression_checks()?;
    Ok(())
}

fn create_test_file_cache(
    fs_id: usize,
    inode: u64,
    page_count: usize,
) -> (Arc<TestFile>, FileNode, Arc<CachedFileShared>, FileCacheKey, usize) {
    let key = FileCacheKey { fs_id, inode };
    let shard_idx = file_state_registry_shard(key);
    let backend = Arc::new(TestFile {
        inode,
        data: Mutex::new(alloc::vec![0; PAGE_SIZE * page_count]),
        fail_write: AtomicBool::new(false),
        fail_sync: AtomicBool::new(false),
        pause_write: AtomicBool::new(false),
        pause_sync: AtomicBool::new(false),
        writes: AtomicUsize::new(0),
        syncs: AtomicUsize::new(0),
    });
    let file = FileNode::new(backend.clone());
    let shared = Arc::new(CachedFileShared::new(
        fs_id,
        false,
        (PAGE_SIZE * page_count) as u64,
        Some(file.clone()),
    ));
    {
        let mut shard = FILE_SHARED_STATES[shard_idx].lock();
        shard.insert_weak(key, &shared);
        shard.insert_active_disk(key, shared.clone());
    }
    (backend, file, shared, key, shard_idx)
}

fn test_dirty_retention_and_writebacks() -> VfsResult<()> {
    // 1. Background writeback check
    let (backend, _file, shared, key, shard_idx) = create_test_file_cache(1, 88881, 1);
    let mut page = PageCache::new(false)?;
    page.data().fill(0x42);
    let paddr = page.paddr();
    shared.page_cache.lock().put(0, page);
    shared.mark_page_dirty_if_paddr(0, paddr, false)?;
    drop(shared);

    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        let cached = shard.get(&key).ok_or(VfsError::BadState)?;
        check!(cached.page_cache.lock().get(&0).unwrap().dirty);
    }

    let flushed = axtask::future::block_on(flush_pending_file_caches_async())?;
    check!(flushed);
    check!(backend.writes.load(Ordering::Acquire) > 0);
    check!(backend.data.lock()[0] == 0x42);
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(!shard.active_disk_caches.contains_key(&key));
        check!(shard.get(&key).is_none());
    }

    // 2. Explicit sync writeback check
    let (backend2, _file2, shared2, key2, shard_idx2) = create_test_file_cache(1, 88889, 1);
    let mut page2 = PageCache::new(false)?;
    page2.data().fill(0x77);
    let paddr2 = page2.paddr();
    shared2.page_cache.lock().put(0, page2);
    shared2.mark_page_dirty_if_paddr(0, paddr2, false)?;
    drop(shared2);

    axtask::future::block_on(flush_all_file_caches_async())?;
    check!(backend2.writes.load(Ordering::Acquire) > 0);
    check!(backend2.data.lock()[0] == 0x77);
    {
        let shard2 = FILE_SHARED_STATES[shard_idx2].lock();
        check!(!shard2.active_disk_caches.contains_key(&key2));
        check!(shard2.get(&key2).is_none());
    }

    Ok(())
}

fn test_unlink_discard_and_restore_recovery() -> VfsResult<()> {
    let inode = 88882;
    let fs_id = 1;
    let (_backend, _file, shared, key, shard_idx) = create_test_file_cache(fs_id, inode, 1);

    let mut page = PageCache::new(false)?;
    page.data().fill(0x55);
    let paddr = page.paddr();
    shared.page_cache.lock().put(0, page);
    shared.mark_page_dirty_if_paddr(0, paddr, false)?;

    // Case 2A: Unlink deletion fails -> cache must be restored to shard with dirty page intact!
    let op_err = axtask::future::block_on(discard_unlinked_file_cache_after(
        fs_id,
        inode,
        async { Err::<(), VfsError>(VfsError::Io) },
    ));
    check!(op_err == Err(VfsError::Io));

    // Verify restored
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        let cached = shard.get(&key).ok_or(VfsError::BadState)?;
        check!(cached.page_cache.lock().get(&0).unwrap().dirty);
        check!(!cached.is_unlinked());
    }

    // Case 2B: Unlink lease dropped without commit (cancellation) -> restored!
    {
        let lease = UnlinkedFileCacheLease::new(key);
        check!(lease.state.is_some());
        drop(lease);
    }
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(shard.get(&key).is_some());
    }

    // Case 2C: Unlink deletion succeeds -> cache discarded!
    let op_ok = axtask::future::block_on(discard_unlinked_file_cache_after(
        fs_id,
        inode,
        async { Ok::<(), VfsError>(()) },
    ));
    check!(op_ok.is_ok());

    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(shard.get(&key).is_none());
        check!(!shard.active_disk_caches.contains_key(&key));
    }
    check!(shared.page_cache.lock().is_empty());
    Ok(())
}

fn test_unlink_interleaving_with_global_collections() -> VfsResult<()> {
    let inode = 88885;
    let fs_id = 1;
    let (backend, _file, shared, key, shard_idx) = create_test_file_cache(fs_id, inode, 1);

    let mut page = PageCache::new(false)?;
    page.data().fill(0x33);
    let paddr = page.paddr();
    shared.page_cache.lock().put(0, page);
    shared.mark_page_dirty_if_paddr(0, paddr, false)?;
    drop(shared);

    // 1. Start an unlink lease: cache is detached from shard and marked unlinked
    let lease = UnlinkedFileCacheLease::new(key);
    check!(lease.state.is_some());
    let state = lease.state.as_ref().unwrap();
    check!(state.is_unlinked());
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(!shard.active_disk_caches.contains_key(&key));
    }

    // 2. Global writeback runs while unlink lease is active:
    // It must NOT select or write back the unlinked state
    let _ = axtask::future::block_on(flush_pending_file_caches_async())?;
    check!(backend.writes.load(Ordering::Acquire) == 0);

    // 3. Allocator reclaim runs while unlink lease is active:
    // It must not evict or disturb the unlinked state
    let _ = page_cache_reclaim_inner(5);
    check!(state.page_cache.lock().contains(&0));

    // 4. Simulate unlink delete cancellation: lease dropped without commit
    drop(lease);

    // 5. Cache state restored to its shard
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(shard.active_disk_caches.contains_key(&key));
        let restored = shard.get(&key).ok_or(VfsError::BadState)?;
        check!(!restored.is_unlinked());
        check!(restored.page_cache.lock().get(&0).unwrap().dirty);
    }

    // 6. Global writeback now flushes the restored cache!
    let _ = axtask::future::block_on(flush_pending_file_caches_async())?;
    check!(backend.writes.load(Ordering::Acquire) > 0);
    check!(backend.data.lock()[0] == 0x33);

    // 7. Clean cache released from shard
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(!shard.active_disk_caches.contains_key(&key));
    }

    Ok(())
}

fn test_reclaim_clean_unmapped_only() -> VfsResult<()> {
    let inode = 88883;
    let fs_id = 1;
    let (_backend, _file, shared, key, _shard_idx) = create_test_file_cache(fs_id, inode, 3);

    // Page 0: clean & unmapped
    let page0 = PageCache::new(false)?;
    shared.page_cache.lock().put(0, page0);

    // Page 1: dirty
    let mut page1 = PageCache::new(false)?;
    let paddr1 = page1.paddr();
    shared.page_cache.lock().put(1, page1);
    shared.mark_page_dirty_if_paddr(1, paddr1, false)?;

    // Page 2: clean but pinned for user mapping
    let mut page2 = PageCache::new(false)?;
    let paddr2 = page2.pin_for_mapping(false)?;
    shared.page_cache.lock().put(2, page2);

    let evicted = page_cache_reclaim_inner(5);
    check!(evicted == 1);

    {
        let mut cache = shared.page_cache.lock();
        check!(!cache.contains(&0));
        check!(cache.contains(&1));
        check!(cache.get(&1).unwrap().dirty);
        check!(cache.contains(&2));
    }

    let remaining = axalloc::frame_table().dec_ref(paddr2);
    check!(remaining > 0);

    shared.page_cache.lock().clear();
    detach_file_cache_state(key);
    Ok(())
}

fn test_concurrent_open_and_release_interleaving() -> VfsResult<()> {
    let inode = 88884;
    let fs_id = 1;
    let (_backend, _file, shared, key, shard_idx) = create_test_file_cache(fs_id, inode, 1);

    // Simulate opening: external reference `shared` is held (strong count = 2).
    // During release_unreferenced_disk_file_caches, candidate + shared + active = 3.
    // So Arc::strong_count != 2, and it must NOT be released!
    release_unreferenced_disk_file_caches(10);
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(shard.active_disk_caches.contains_key(&key));
    }

    // Drop external reference: now only shard holds it.
    drop(shared);

    // Next release pass releases it cleanly
    release_unreferenced_disk_file_caches(10);
    {
        let shard = FILE_SHARED_STATES[shard_idx].lock();
        check!(!shard.active_disk_caches.contains_key(&key));
    }

    Ok(())
}

fn test_multi_shard_round_robin_fairness() -> VfsResult<()> {
    let fs_id = 99;
    let mut keys = Vec::new();
    for i in 0..64u64 {
        let (_backend, _file, shared, key, _shard_idx) = create_test_file_cache(fs_id, 10000 + i, 1);
        drop(shared);
        keys.push(key);
    }

    let snapshot = active_disk_file_cache_snapshot()?;
    check!(snapshot.len() >= 64);

    for key in keys {
        detach_file_cache_state(key);
    }

    Ok(())
}

pub(super) fn run_cache_shard_regression_checks() -> VfsResult<()> {
    let checks: [(&str, fn() -> VfsResult<()>); 6] = [
        ("dirty_retention_and_writebacks", test_dirty_retention_and_writebacks),
        ("unlink_discard_and_restore_recovery", test_unlink_discard_and_restore_recovery),
        ("unlink_interleaving_with_global_collections", test_unlink_interleaving_with_global_collections),
        ("reclaim_clean_unmapped_only", test_reclaim_clean_unmapped_only),
        ("concurrent_open_and_release_interleaving", test_concurrent_open_and_release_interleaving),
        ("multi_shard_round_robin_fairness", test_multi_shard_round_robin_fairness),
    ];
    for (name, check) in checks {
        if let Err(err) = check() {
            error!("[CACHE_SHARD_GUEST] FAIL {} {:?}", name, err);
            return Err(err);
        }
        info!("[CACHE_SHARD_GUEST] PASS {}", name);
    }
    info!("[CACHE_SHARD_GUEST] All cache shard regression checks PASSED!");
    Ok(())
}
