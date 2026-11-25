//! Opt-in guest checks using real cache frames and asynchronous FileNode I/O.
//! The backend injects storage errors; it does not claim physical disk coverage.

use alloc::{boxed::Box, sync::{Arc, Weak}, vec, vec::Vec};
use core::{
    any::Any,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use vfs::{
    FileNode, FileNodeOps, FilesystemOps, Metadata, MetadataUpdate, Mountpoint, NodeOps,
    NodePermission, VfsError, VfsResult,
};
use hal::mem::PhysAddr;
use poll::{IoEvents, Pollable};
use spin::Mutex;

use super::{
    CachedFile, CachedFileShared, File, FileBackend, FileCacheKey, FsContext, OpenOptions,
    PAGE_SIZE, PageCache, UnlinkedFileCacheLease, WritebackPage,
    CachedFile, CachedFileShared, File, FileBackend, FileCacheKey, FileFlags, FsContext,
    OpenOptions, PAGE_SIZE, PageCache, UnlinkedFileCacheLease, WritebackPage,
    active_disk_file_cache_snapshot, cached_file_size, cached_file_size_if_present,
    detach_file_cache_state, discard_unlinked_file_cache_after, file_state_registry_shard,
    flush_all_file_caches_async, flush_file_cache_state, flush_pending_file_caches_async,
    page_cache_reclaim_inner, release_unreferenced_disk_file_caches, FILE_SHARED_STATES,
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
impl alloc::task::Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(NoopWake));
    future.poll(&mut Context::from_waker(&waker))
}

struct MockDiskFs;

#[async_trait::async_trait]
impl FilesystemOps for MockDiskFs {
    fn name(&self) -> &str { "mockdisk" }
    fn root_dir(&self) -> vfs::DirEntry { panic!("mock disk fs has no root dir") }
    fn stat(&self) -> VfsResult<vfs::StatFs> { Err(VfsError::Unsupported) }
}

static MOCK_DISK_FS: MockDiskFs = MockDiskFs;

struct TestFile {
    inode: u64,
    data: Mutex<Vec<u8>>,
    fail_read: AtomicBool,
    pause_read: AtomicBool,
    read_io: AtomicUsize,
    reads: AtomicUsize,
    fail_write: AtomicBool,
    fail_sync: AtomicBool,
    pause_write: AtomicBool,
    pause_sync: AtomicBool,
    writes: AtomicUsize,
    syncs: AtomicUsize,
    allow_metadata_update: AtomicBool,
    metadata_updates: AtomicUsize,
    set_lens: AtomicUsize,
    last_writes: Mutex<Vec<(u64, usize)>>,
}

#[async_trait::async_trait]
impl NodeOps for TestFile {
    fn inode(&self) -> u64 { self.inode }
    async fn metadata(&self) -> VfsResult<Metadata> { Err(VfsError::Unsupported) }
    async fn update_metadata(&self, _update: MetadataUpdate) -> VfsResult<()> {
        Err(VfsError::Unsupported)
        if self.allow_metadata_update.load(Ordering::Acquire) {
            self.metadata_updates.fetch_add(1, Ordering::Relaxed);
            Ok(())
        } else {
            Err(VfsError::Unsupported)
        }
    }
    async fn len(&self) -> VfsResult<u64> { Ok(self.data.lock().len() as u64) }
    fn filesystem(&self) -> &dyn FilesystemOps {
        panic!("cache lifecycle checks do not query filesystem metadata")
        if self.allow_metadata_update.load(Ordering::Acquire) {
            &MOCK_DISK_FS
        } else {
            panic!("cache lifecycle checks do not query filesystem metadata")
        }
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
        self.reads.fetch_add(1, Ordering::Relaxed);
        core::future::poll_fn(|cx| {
            if self.pause_read.load(Ordering::Acquire) {
                cx.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }).await;
        if self.fail_read.load(Ordering::Acquire) { return Err(VfsError::Io); }
        let data = self.data.lock();
        let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidInput)?;
        let count = buf.len().min(data.len().saturating_sub(offset));
        if count != 0 { buf[..count].copy_from_slice(&data[offset..offset + count]); }
        Ok(count)
    }
    async fn read_at_with_io(
        &self,
        buf: &mut [u8],
        offset: u64,
        _observed: core::ops::Range<usize>,
    ) -> VfsResult<(usize, Option<bool>)> {
        let read = self.read_at(buf, offset).await?;
        let io = match self.read_io.load(Ordering::Acquire) {
            1 => Some(false),
            2 => Some(true),
            _ => None,
        };
        Ok((read, io))
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
        self.last_writes.lock().push((offset as u64, buf.len()));
        Ok(buf.len())
    }
    async fn append(&self, _buf: &[u8]) -> VfsResult<(usize, u64)> { Err(VfsError::Unsupported) }
    async fn set_len(&self, len: u64) -> VfsResult<()> {
        self.set_lens.fetch_add(1, Ordering::Relaxed);
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
            fail_read: AtomicBool::new(false),
            pause_read: AtomicBool::new(false),
            read_io: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            fail_write: AtomicBool::new(false),
            fail_sync: AtomicBool::new(false),
            pause_write: AtomicBool::new(false),
            pause_sync: AtomicBool::new(false),
            writes: AtomicUsize::new(0),
            syncs: AtomicUsize::new(0),
            allow_metadata_update: AtomicBool::new(false),
            metadata_updates: AtomicUsize::new(0),
            set_lens: AtomicUsize::new(0),
            last_writes: Mutex::new(Vec::new()),
        });
        let file = FileNode::new(backend.clone());
        let shared = Arc::new(CachedFileShared::new(0, false, PAGE_SIZE as u64, Some(file.clone())));
        let mut page = PageCache::new(false)?;
        page.data().fill(0x67);
        let paddr = page.paddr();
        check!(kernel_alloc::frame_table().contains(paddr));
        shared.page_cache.lock().put(0, page);
        shared.mark_page_dirty_if_paddr(0, paddr, false)?;
        Ok(Self { shared, backend, file })
    }
    fn dirty(&self) -> VfsResult<bool> {
        self.shared.page_cache.lock().peek(&0).map(|page| page.dirty).ok_or(VfsError::BadState)
    }
    fn checkpoint(&self) -> VfsResult<()> {
        task::future::block_on(flush_file_cache_state(self.shared.clone()))
            .ok_or(VfsError::BadState)?.1
    }
    fn sync(&self) -> VfsResult<()> {
        task::future::block_on(async {
            let _guard = self.shared.io_lock.write().await;
            self.shared.sync_dirty_pages_async(&self.file, false).await
        })
    }
}

struct MappingPin(PhysAddr);
impl Drop for MappingPin {
    fn drop(&mut self) {
        let remaining = kernel_alloc::frame_table().dec_ref(self.0);
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
    task::future::block_on(async {
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
    task::future::block_on(checkpoint).ok_or(VfsError::BadState)?.1?;
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
    let checks: [(&str, fn() -> VfsResult<()>); 9] = [
    let checks: [(&str, fn() -> VfsResult<()>); 11] = [
        ("fault_io_owner_waiter", fault_io_owner_waiter),
        ("fault_io_hot_target_cold_neighbor", fault_io_hot_target_cold_neighbor),
        ("fault_io_cancel_error_retry", fault_io_cancel_error_retry),
        ("fault_io_unsupported_generation_retry", fault_io_unsupported_generation_retry),
        ("cache_identity_publication", identity_publication),
        ("cache_write_failure_retry", write_failure_retry),
        ("cache_redirty_checkpoint", redirty_checkpoint),
        ("cache_durability_recovery", durability_recovery),
        ("cache_snapshot_identity_generations", snapshot_identity_generations),
        (
            "fdatasync_skips_deferred_timestamps_and_redundant_set_len",
            fdatasync_skips_deferred_timestamps_and_redundant_set_len,
        ),
        (
            "fdatasync_partial_page_subrange_redirty_and_retry",
            fdatasync_partial_page_subrange_redirty_and_retry,
        ),
    ];
    for (name, check) in checks {
        if let Err(err) = check() {
            error!("MLC_KERNEL FAIL {} {:?}", name, err);
            return Err(err);
        }
        info!("MLC_KERNEL PASS {}", name);
    }
    run_cache_shard_regression_checks()?;
    run_tmpfs_cache_lifecycle_checks()?;
    #[cfg(feature = "ext4")]
    crate::fs::ext4::run_fault_io_checks()?;
    Ok(())
}

fn new_tmpfs_context() -> (vfs::Filesystem, FsContext) {
    let fs = crate::fs::new_tmpfs();
    let mount = Mountpoint::new_root(&fs);
    let cx = FsContext::new(mount.root_location());
    (fs, cx)
}

fn weak_cache_for_file(file: &File) -> VfsResult<Weak<CachedFileShared>> {
    match file.backend()? {
        FileBackend::Cached(cached) => Ok(Arc::downgrade(&cached.shared)),
        FileBackend::Direct(_) => Err(VfsError::BadState),
    }
}

fn tmpfs_write_new(cx: &FsContext, path: &str, data: &[u8]) -> VfsResult<Weak<CachedFileShared>> {
    task::future::block_on(async {
        let file = File::create(cx, path).await?;
        let weak = weak_cache_for_file(&file)?;
        let written = file.write_at_slice(data, 0).await?;
        check!(written == data.len());
        Ok(weak)
    })
}

fn tmpfs_read_all(file: &File, expected_len: usize) -> VfsResult<Vec<u8>> {
    let mut buf = vec![0u8; expected_len + 16];
    let n = task::future::block_on(file.read_at(&mut buf.as_mut_slice(), 0))?;
    buf.truncate(n);
    Ok(buf)
}

fn tmpfs_rename_after_close_preserves_data_and_size() -> VfsResult<()> {
    let (_fs, cx) = new_tmpfs_context();
    task::future::block_on(cx.create_dir("dir1", NodePermission::from_bits_truncate(0o755)))?;
    task::future::block_on(cx.create_dir("dir2", NodePermission::from_bits_truncate(0o755)))?;

    let payload = b"MANIFEST-000001\n";
    let _weak = tmpfs_write_new(&cx, "/dir1/000001.dbtmp", payload)?;

    let (src_ino, src_meta_size, src_cached_size) = task::future::block_on(async {
        let loc = cx.resolve("/dir1/000001.dbtmp").await?;
        let meta = loc.metadata().await?;
        let cached_sz = cached_file_size_if_present(&loc);
        Ok::<_, VfsError>((meta.inode, meta.size, cached_sz))
    })?;
    check!(src_meta_size == payload.len() as u64);
    check!(src_cached_size == Some(payload.len() as u64));

    // 1. Same-directory rename after last fd closed.
    task::future::block_on(cx.rename("/dir1/000001.dbtmp", "/dir1/CURRENT"))?;
    check!(matches!(
        task::future::block_on(cx.resolve("/dir1/000001.dbtmp")),
        Err(VfsError::NotFound)
    ));

    let (dst_ino, dst_meta_size, dst_cached_size, bytes) = task::future::block_on(async {
        let loc = cx.resolve("/dir1/CURRENT").await?;
        let meta = loc.metadata().await?;
        let cached_sz = cached_file_size(&loc)?;
        let bytes = cx.read("/dir1/CURRENT").await?;
        Ok::<_, VfsError>((meta.inode, meta.size, cached_sz, bytes))
    })?;
    check!(dst_ino == src_ino);
    check!(dst_meta_size == payload.len() as u64);
    check!(dst_cached_size == payload.len() as u64);
    check!(bytes == payload);

    // 2. Self-rename must be a no-op and preserve data.
    task::future::block_on(cx.rename("/dir1/CURRENT", "/dir1/CURRENT"))?;
    check!(task::future::block_on(cx.read("/dir1/CURRENT"))? == payload);

    // 3. Cross-directory rename after last fd closed.
    task::future::block_on(cx.rename("/dir1/CURRENT", "/dir2/CURRENT"))?;
    check!(matches!(
        task::future::block_on(cx.resolve("/dir1/CURRENT")),
        Err(VfsError::NotFound)
    ));
    let cross_meta = task::future::block_on(cx.metadata("/dir2/CURRENT"))?;
    check!(cross_meta.inode == src_ino && cross_meta.size == payload.len() as u64);
    check!(task::future::block_on(cx.read("/dir2/CURRENT"))? == payload);

    // 4. Parent directory rename (triggers DirNode::forget() on subtree).
    task::future::block_on(cx.rename("/dir2", "/dir2_moved"))?;
    let moved_meta = task::future::block_on(cx.metadata("/dir2_moved/CURRENT"))?;
    check!(moved_meta.inode == src_ino && moved_meta.size == payload.len() as u64);
    check!(task::future::block_on(cx.read("/dir2_moved/CURRENT"))? == payload);

    // 5. Same-directory rename while holding an open fd on the source file.
    let open_payload = b"OPEN-FD-RENAME\n";
    let open_fd = task::future::block_on(async {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        let file = opts.open(&cx, "/dir1/open_src").await?.into_file()?;
        check!(file.write_at_slice(open_payload, 0).await? == open_payload.len());
        Ok::<_, VfsError>(file)
    })?;
    let open_src_ino = task::future::block_on(cx.metadata("/dir1/open_src"))?.inode;
    task::future::block_on(cx.rename("/dir1/open_src", "/dir1/open_dst"))?;
    let open_dst_meta = task::future::block_on(cx.metadata("/dir1/open_dst"))?;
    check!(open_dst_meta.inode == open_src_ino);
    check!(open_dst_meta.size == open_payload.len() as u64);
    check!(task::future::block_on(cx.read("/dir1/open_dst"))? == open_payload);
    check!(tmpfs_read_all(&open_fd, open_payload.len())? == open_payload);
    drop(open_fd);
    check!(task::future::block_on(cx.read("/dir1/open_dst"))? == open_payload);

    Ok(())
}

fn tmpfs_hardlink_unlink_after_close_preserves_data() -> VfsResult<()> {
    let (fs, cx) = new_tmpfs_context();
    let baseline_files = fs.stat()?.file_count;

    let payload = b"HARDLINK-CONTENT\n";
    let weak = tmpfs_write_new(&cx, "/orig", payload)?;
    let orig_ino = task::future::block_on(cx.metadata("/orig"))?.inode;

    task::future::block_on(cx.link("/orig", "/alias"))?;
    task::future::block_on(cx.remove_file("/orig"))?;

    check!(matches!(
        task::future::block_on(cx.resolve("/orig")),
        Err(VfsError::NotFound)
    ));
    let alias_meta = task::future::block_on(cx.metadata("/alias"))?;
    check!(alias_meta.inode == orig_ino);
    check!(alias_meta.size == payload.len() as u64);
    check!(task::future::block_on(cx.read("/alias"))? == payload);
    check!(weak.strong_count() > 0);

    task::future::block_on(cx.remove_file("/alias"))?;
    check!(fs.stat()?.file_count == baseline_files);
    check!(weak.strong_count() == 0);
    Ok(())
}

fn tmpfs_rename_overwrite_closed_and_open_targets() -> VfsResult<()> {
    let (fs, cx) = new_tmpfs_context();
    let baseline_files = fs.stat()?.file_count;

    // Part A: overwrite a closed multi-page target.
    let old_data = vec![0xA5u8; 8 * PAGE_SIZE];
    let old_weak = tmpfs_write_new(&cx, "/dst_closed", &old_data)?;
    check!(old_weak.strong_count() > 0);
    let new_data = b"NEW-DATA\n";
    let new_weak = tmpfs_write_new(&cx, "/src_closed", new_data)?;
    let src_ino = task::future::block_on(cx.metadata("/src_closed"))?.inode;
    let before_replace_count = fs.stat()?.file_count;
    check!(before_replace_count == baseline_files + 2);

    task::future::block_on(cx.rename("/src_closed", "/dst_closed"))?;
    check!(matches!(
        task::future::block_on(cx.resolve("/src_closed")),
        Err(VfsError::NotFound)
    ));
    let dst_meta = task::future::block_on(cx.metadata("/dst_closed"))?;
    check!(dst_meta.inode == src_ino);
    check!(dst_meta.size == new_data.len() as u64);
    check!(task::future::block_on(cx.read("/dst_closed"))? == new_data);
    check!(fs.stat()?.file_count == baseline_files + 1);
    check!(old_weak.strong_count() == 0);
    check!(new_weak.strong_count() > 0);

    task::future::block_on(cx.remove_file("/dst_closed"))?;
    check!(fs.stat()?.file_count == baseline_files);
    check!(new_weak.strong_count() == 0);

    // Part B: overwrite a target that still has an open read/write fd.
    let open_old_data = vec![0x5Au8; 4 * PAGE_SIZE];
    let open_fd = task::future::block_on(async {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        let file = opts.open(&cx, "/dst_open").await?.into_file()?;
        check!(file.write_at_slice(&open_old_data, 0).await? == open_old_data.len());
        Ok::<_, VfsError>(file)
    })?;
    let open_old_weak = weak_cache_for_file(&open_fd)?;

    let replacement = b"REPLACED\n";
    let repl_weak = tmpfs_write_new(&cx, "/src_open", replacement)?;
    let repl_ino = task::future::block_on(cx.metadata("/src_open"))?.inode;

    task::future::block_on(cx.rename("/src_open", "/dst_open"))?;
    check!(fs.stat()?.file_count == baseline_files + 2);
    check!(open_old_weak.strong_count() > 0);

    // New name observes replacement; old fd still observes and writes old inode.
    let dst_open_meta = task::future::block_on(cx.metadata("/dst_open"))?;
    check!(dst_open_meta.inode == repl_ino);
    check!(dst_open_meta.size == replacement.len() as u64);
    check!(task::future::block_on(cx.read("/dst_open"))? == replacement);
    check!(tmpfs_read_all(&open_fd, open_old_data.len())? == open_old_data);
    check!(task::future::block_on(open_fd.write_at_slice(b"TAIL", 0))? == 4);
    check!(task::future::block_on(cx.read("/dst_open"))? == replacement);

    // Closing the old fd reclaims the replaced inode and its page cache.
    drop(open_fd);
    check!(fs.stat()?.file_count == baseline_files + 1);
    check!(open_old_weak.strong_count() == 0);
    check!(task::future::block_on(cx.read("/dst_open"))? == replacement);

    task::future::block_on(cx.remove_file("/dst_open"))?;
    check!(fs.stat()?.file_count == baseline_files);
    check!(repl_weak.strong_count() == 0);
    Ok(())
}

fn tmpfs_unlink_reclaims_after_final_close() -> VfsResult<()> {
    let (fs, cx) = new_tmpfs_context();
    let baseline_files = fs.stat()?.file_count;

    // Case 1: unlink after close reclaims immediately.
    let big = vec![0x3Cu8; 8 * PAGE_SIZE];
    let weak1 = tmpfs_write_new(&cx, "/unlinked_closed", &big)?;
    check!(fs.stat()?.file_count == baseline_files + 1);
    check!(weak1.strong_count() > 0);
    task::future::block_on(cx.remove_file("/unlinked_closed"))?;
    check!(fs.stat()?.file_count == baseline_files);
    check!(weak1.strong_count() == 0);

    // Case 2: unlink while open retains data until final close, then reclaims.
    let open_fd = task::future::block_on(async {
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(true);
        let file = opts.open(&cx, "/unlinked_open").await?.into_file()?;
        check!(file.write_at_slice(&big, 0).await? == big.len());
        Ok::<_, VfsError>(file)
    })?;
    let weak2 = weak_cache_for_file(&open_fd)?;
    task::future::block_on(cx.remove_file("/unlinked_open"))?;
    check!(matches!(
        task::future::block_on(cx.resolve("/unlinked_open")),
        Err(VfsError::NotFound)
    ));
    check!(fs.stat()?.file_count == baseline_files + 1);
    check!(weak2.strong_count() > 0);
    check!(tmpfs_read_all(&open_fd, big.len())? == big);

    drop(open_fd);
    check!(fs.stat()?.file_count == baseline_files);
    check!(weak2.strong_count() == 0);
    Ok(())
}

fn run_tmpfs_cache_lifecycle_checks() -> VfsResult<()> {
    let checks: [(&str, fn() -> VfsResult<()>); 4] = [
        (
            "tmpfs_rename_after_close_preserves_data_and_size",
            tmpfs_rename_after_close_preserves_data_and_size,
        ),
        (
            "tmpfs_hardlink_unlink_after_close_preserves_data",
            tmpfs_hardlink_unlink_after_close_preserves_data,
        ),
        (
            "tmpfs_rename_overwrite_closed_and_open_targets",
            tmpfs_rename_overwrite_closed_and_open_targets,
        ),
        (
            "tmpfs_unlink_reclaims_after_final_close",
            tmpfs_unlink_reclaims_after_final_close,
        ),
    ];
    for (name, check) in checks {
        if let Err(err) = check() {
            error!("[TMPFS_CACHE_GUEST] FAIL {} {:?}", name, err);
            return Err(err);
        }
        info!("[TMPFS_CACHE_GUEST] PASS {}", name);
    }
    info!("[TMPFS_CACHE_GUEST] All tmpfs cache lifecycle checks PASSED!");
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
        fail_read: AtomicBool::new(false),
        pause_read: AtomicBool::new(false),
        read_io: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        fail_write: AtomicBool::new(false),
        fail_sync: AtomicBool::new(false),
        pause_write: AtomicBool::new(false),
        pause_sync: AtomicBool::new(false),
        writes: AtomicUsize::new(0),
        syncs: AtomicUsize::new(0),
        allow_metadata_update: AtomicBool::new(false),
        metadata_updates: AtomicUsize::new(0),
        set_lens: AtomicUsize::new(0),
        last_writes: Mutex::new(Vec::new()),
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

    let flushed = task::future::block_on(flush_pending_file_caches_async())?;
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

    task::future::block_on(flush_all_file_caches_async())?;
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
    let op_err = task::future::block_on(discard_unlinked_file_cache_after(
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
    let op_ok = task::future::block_on(discard_unlinked_file_cache_after(
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
    let _ = task::future::block_on(flush_pending_file_caches_async())?;
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
    let _ = task::future::block_on(flush_pending_file_caches_async())?;
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

    let remaining = kernel_alloc::frame_table().dec_ref(paddr2);
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

/// Controlled external FileNode boundary: injected I/O tests propagation and
/// lifetime behavior; these cases do not claim physical storage coverage.
fn fault_fixture() -> VfsResult<(super::CachedFile, Arc<TestFile>)> {
    let case = CacheCase::new()?;
    case.shared.page_cache.lock().clear();
    case.backend.data.lock().resize(2 * PAGE_SIZE, 0x73);
    case.shared.size.store((2 * PAGE_SIZE) as u64, Ordering::Release);
    let fs = crate::fs::new_tmpfs();
    let mount = vfs::Mountpoint::new_root(&fs);
    let entry = vfs::DirEntry::new_file(
        case.file, vfs::NodeType::RegularFile, vfs::Reference::root(),
    );
    let file = super::CachedFile {
        inner: vfs::Location::new(mount, entry),
        shared: case.shared,
        in_memory: false,
        read_hint: Arc::new(core::sync::atomic::AtomicU64::new(u64::MAX)),
    };
    Ok((file, case.backend))
}

fn release_fault_pins(pages: super::SharedPagePaddrs) {
    for (_, frame) in pages { drop(MappingPin(frame)); }
}

fn fault_io_owner_waiter() -> VfsResult<()> {
    let (file, backend) = fault_fixture()?;
    backend.pause_read.store(true, Ordering::Release);
    backend.read_io.store(2, Ordering::Release);
    let mut owner = Box::pin(file.get_shared_page_paddrs_with_io_async(0, 1, false));
    check!(poll_once(owner.as_mut()).is_pending());
    let mut waiter = Box::pin(file.get_shared_page_paddrs_with_io_async(0, 1, false));
    check!(poll_once(waiter.as_mut()).is_pending());
    check!(backend.reads.load(Ordering::Acquire) == 1);
    backend.pause_read.store(false, Ordering::Release);
    let Poll::Ready(Ok((owner_pages, owner_io))) = poll_once(owner.as_mut()) else {
        return Err(VfsError::BadState);
    };
    release_fault_pins(owner_pages);
    check!(owner_io == mm::FilePageIo::StorageRead);
    let Poll::Ready(Ok((waiter_pages, waiter_io))) = poll_once(waiter.as_mut()) else {
        return Err(VfsError::BadState);
    };
    release_fault_pins(waiter_pages);
    check!(waiter_io == mm::FilePageIo::NoStorageRead);
    check!(backend.reads.load(Ordering::Acquire) == 1);
    Ok(())
}

fn fault_io_hot_target_cold_neighbor() -> VfsResult<()> {
    let (file, backend) = fault_fixture()?;
    backend.read_io.store(2, Ordering::Release);
    let (pages, io) = file.get_shared_page_paddrs_with_io(0, 1, false)?;
    release_fault_pins(pages);
    check!(io == mm::FilePageIo::StorageRead);
    let (pages, io) = file.get_shared_page_paddrs_with_io(0, 2, false)?;
    let count = pages.len();
    release_fault_pins(pages);
    check!(io == mm::FilePageIo::NoStorageRead && count == 1);
    check!(backend.reads.load(Ordering::Acquire) == 1);
    check!(file.shared_page_paddr(1).is_err());
    Ok(())
}

fn fault_io_cancel_error_retry() -> VfsResult<()> {
    let (file, backend) = fault_fixture()?;
    backend.pause_read.store(true, Ordering::Release);
    let mut canceled = Box::pin(file.get_shared_page_paddrs_with_io_async(0, 1, false));
    check!(poll_once(canceled.as_mut()).is_pending());
    drop(canceled);
    check!(file.shared_page_paddr(0).is_err());
    backend.pause_read.store(false, Ordering::Release);
    backend.fail_read.store(true, Ordering::Release);
    check!(matches!(file.get_shared_page_paddrs_with_io(0, 1, false), Err(VfsError::Io)));
    check!(file.shared_page_paddr(0).is_err());
    backend.fail_read.store(false, Ordering::Release);
    backend.read_io.store(2, Ordering::Release);
    let (pages, io) = file.get_shared_page_paddrs_with_io(0, 1, false)?;
    release_fault_pins(pages);
    check!(io == mm::FilePageIo::StorageRead);
    check!(backend.reads.load(Ordering::Acquire) == 3);
    Ok(())
}

fn fault_io_unsupported_generation_retry() -> VfsResult<()> {
    let (file, backend) = fault_fixture()?;
    let (pages, io) = file.get_shared_page_paddrs_with_io(0, 1, false)?;
    release_fault_pins(pages);
    check!(io == mm::FilePageIo::Unknown);
    file.shared.page_cache.lock().clear();
    backend.pause_read.store(true, Ordering::Release);
    backend.read_io.store(2, Ordering::Release);
    let mut owner = Box::pin(file.get_shared_page_paddrs_with_io_async(0, 1, false));
    check!(poll_once(owner.as_mut()).is_pending());
    file.shared.cache_generation.fetch_add(1, Ordering::AcqRel);
    backend.pause_read.store(false, Ordering::Release);
    let Poll::Ready(Ok((pages, io))) = poll_once(owner.as_mut()) else {
        return Err(VfsError::BadState);
    };
    release_fault_pins(pages);
    check!(io == mm::FilePageIo::StorageRead);
    check!(backend.reads.load(Ordering::Acquire) == 3);
    Ok(())
}

fn test_cached_file_handle(inode: u64, initial_data: Vec<u8>) -> (File, Arc<CachedFileShared>, Arc<TestFile>) {
    let initial_len = initial_data.len() as u64;
    let backend = Arc::new(TestFile {
        inode,
        data: Mutex::new(initial_data),
        fail_read: AtomicBool::new(false),
        pause_read: AtomicBool::new(false),
        read_io: AtomicUsize::new(0),
        reads: AtomicUsize::new(0),
        fail_write: AtomicBool::new(false),
        fail_sync: AtomicBool::new(false),
        pause_write: AtomicBool::new(false),
        pause_sync: AtomicBool::new(false),
        writes: AtomicUsize::new(0),
        syncs: AtomicUsize::new(0),
        allow_metadata_update: AtomicBool::new(true),
        metadata_updates: AtomicUsize::new(0),
        set_lens: AtomicUsize::new(0),
        last_writes: Mutex::new(Vec::new()),
    });
    let file_node = FileNode::new(backend.clone());
    let shared = Arc::new(CachedFileShared::new(0, false, initial_len, Some(file_node.clone())));
    let fs = crate::fs::new_tmpfs();
    let mount = Mountpoint::new_root(&fs);
    let entry = vfs::DirEntry::new_file(
        file_node,
        vfs::NodeType::RegularFile,
        vfs::Reference::root(),
    );
    let cached = super::CachedFile {
        inner: vfs::Location::new(mount, entry),
        shared: shared.clone(),
        in_memory: false,
        read_hint: Arc::new(core::sync::atomic::AtomicU64::new(u64::MAX)),
    };
    let file = File::new(FileBackend::Cached(cached), FileFlags::READ | FileFlags::WRITE, None);
    (file, shared, backend)
}

fn fdatasync_skips_deferred_timestamps_and_redundant_set_len() -> VfsResult<()> {
    let (file, _shared, backend) = test_cached_file_handle(9001, Vec::new());
    let chunk1 = vec![0x41u8; 288];
    let chunk2 = vec![0x42u8; 288];

    task::future::block_on(async {
        check!(file.write_at_slice(&chunk1, 0).await? == chunk1.len());
        file.sync(true).await?;
        check!(backend.metadata_updates.load(Ordering::Acquire) == 0);
        check!(backend.set_lens.load(Ordering::Acquire) == 0);
        check!(&*backend.last_writes.lock() == &[(0u64, 288usize)]);
        backend.last_writes.lock().clear();

        check!(file.write_at_slice(&chunk2, 288).await? == chunk2.len());
        file.sync(true).await?;
        check!(backend.metadata_updates.load(Ordering::Acquire) == 0);
        check!(backend.set_lens.load(Ordering::Acquire) == 0);
        check!(&*backend.last_writes.lock() == &[(288u64, 288usize)]);
        {
            let data = backend.data.lock();
            check!(data.len() == 576);
            check!(data[..288] == chunk1[..]);
            check!(data[288..576] == chunk2[..]);
        }

        file.sync(false).await?;
        #[cfg(feature = "times")]
        check!(backend.metadata_updates.load(Ordering::Acquire) == 1);
        Ok(())
    })
}

fn fdatasync_partial_page_subrange_redirty_and_retry() -> VfsResult<()> {
    let (file, shared, backend) = test_cached_file_handle(9002, Vec::new());
    let p1 = vec![0x11u8; 128];
    let p2 = vec![0x22u8; 128];
    let p3 = vec![0x33u8; 128];
    let p4 = vec![0x44u8; 128];

    // 1. Sync failure preserves dirty state for retry.
    task::future::block_on(async {
        check!(file.write_at_slice(&p1, 0).await? == 128);
        file.sync(true).await?;
        check!(file.write_at_slice(&p2, 128).await? == 128);
        backend.fail_sync.store(true, Ordering::Release);
        check!(file.sync(true).await.is_err());
        check!(shared.page_cache.lock().peek(&0).is_some_and(|p| p.dirty));
        backend.fail_sync.store(false, Ordering::Release);
        file.sync(true).await?;
        check!(&backend.data.lock()[..256] == [&p1[..], &p2[..]].concat().as_slice());
        Ok::<_, VfsError>(())
    })?;

    // 2. Concurrent re-dirty during paused writeback leaves page dirty and preserves new bytes.
    task::future::block_on(file.write_at_slice(&p3, 256))?;
    backend.last_writes.lock().clear();
    backend.pause_write.store(true, Ordering::Release);
    let mut sync_fut = Box::pin(shared.sync_dirty_pages_async(
        file.location().entry().as_file()?,
        true,
    ));
    check!(poll_once(sync_fut.as_mut()).is_pending());
    check!(backend.writes.load(Ordering::Acquire) == 3);
    // Simulate concurrent page write while writeback write_at is in-flight.
    {
        let mut cache = shared.page_cache.lock();
        let page = cache.get_mut(&0).ok_or(VfsError::BadState)?;
        page.data()[384..512].copy_from_slice(&p4);
        page.mark_dirty();
    }
    shared.set_size(512);
    backend.pause_write.store(false, Ordering::Release);
    let Poll::Ready(res) = poll_once(sync_fut.as_mut()) else {
        return Err(VfsError::BadState);
    };
    res?;
    check!(shared.page_cache.lock().peek(&0).is_some_and(|p| p.dirty));
    task::future::block_on(file.sync(true))?;
    check!(&backend.data.lock()[256..512] == [&p3[..], &p4[..]].concat().as_slice());

    // 3. Truncate shrink into partial page zeroes tail across re-extend.
    let FileBackend::Cached(cached) = file.backend()? else {
        return Err(VfsError::BadState);
    };
    task::future::block_on(async {
        cached.set_len_async(100).await?;
        file.sync(true).await?;
        check!(file.write_at_slice(&[0x55u8; 50], 200).await? == 50);
        file.sync(true).await?;
        {
            let data = backend.data.lock();
            check!(data.len() == 250);
            check!(data[100..200].iter().all(|&b| b == 0));
            check!(data[200..250].iter().all(|&b| b == 0x55));
        }

        // 4. Read-only mapping upgraded via mark_shared_page_writable is tracked in
        // writable_mapped_pages, flushed on fdatasync, and cleared when unmapped.
        let paddr = cached
            .try_pin_shared_page_paddr(0, false)?
            .ok_or(VfsError::BadState)?;
        let pin = MappingPin(paddr);
        cached.mark_shared_page_writable(0, paddr)?;
        {
            let mut cache = shared.page_cache.lock();
            check!(cache.writable_mapped_pages.contains(&0));
            let page = cache.get_mut(&0).ok_or(VfsError::BadState)?;
            page.data()[128..144].fill(0x77);
        }
        file.sync(true).await?;
        check!(backend.data.lock()[128..144].iter().all(|&b| b == 0x77));
        drop(pin);
        file.sync(true).await?;
        {
            let cache = shared.page_cache.lock();
            check!(!cache.writable_mapped_pages.contains(&0));
            check!(cache.peek(&0).is_some_and(|p| !p.may_write_mapping));
        }
        Ok(())
    })
}
