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

use super::{CachedFileShared, PAGE_SIZE, PageCache, WritebackPage, flush_file_cache_state};

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
    fn inode(&self) -> u64 { 67 }
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
    Ok(())
}
