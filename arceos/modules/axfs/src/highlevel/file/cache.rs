use super::*;

pub fn invalidate_file_cache(fs_id: usize, inode: u64) {
    let key = FileCacheKey { fs_id, inode };
    let state = FILE_SHARED_STATES[file_state_registry_shard(key)]
        .lock()
        .remove(&key);
    if let Some(state) = state {
        let removed = {
            let mut caches = ACTIVE_DISK_FILE_CACHES.lock();
            caches
                .iter()
                .position(|cached| Arc::ptr_eq(cached, &state))
                .map(|index| caches.swap_remove(index))
        };
        drop(removed);
    }
}

static FILE_SHARED_STATES: Lazy<
    [SpinMutex<WeakStateRegistry<FileCacheKey, CachedFileShared>>; FILE_STATE_REGISTRY_SHARDS],
> = Lazy::new(|| core::array::from_fn(|_| SpinMutex::new(WeakStateRegistry::default())));

// Disk caches survive descriptor close and are released after explicit global
// writeback. Stage 2 adds bounded retention and memory-pressure reclaim.
static ACTIVE_DISK_FILE_CACHES: Lazy<SpinMutex<Vec<Arc<CachedFileShared>>>> =
    Lazy::new(|| SpinMutex::new(Vec::new()));
const PAGE_SIZE: usize = 4096;
const MAX_WRITEBACK_PAGES: usize = 256;
const READ_AHEAD_PAGES: usize = 16;
// Copy at most one readahead window while holding the cache locks. This
// removes per-page lock churn for resident sequential reads without making a
// direct-I/O invalidation wait behind an unbounded cache hit stream.
const READ_COPY_BATCH_PAGES: usize = READ_AHEAD_PAGES;
const DISK_FILE_CACHE_SOFT_LIMIT: usize = 1024;
const PAGE_CACHE_GROWTH_HEADROOM: usize = 256;
const PAGE_CACHE_EVICTION_BATCH: usize = 256;
const PAGE_CACHE_SCAN_MULTIPLIER: usize = 4;
const PAGE_CACHE_MIN_SCAN: usize = 64;
const PAGE_CACHE_RECLAIM_LOG_INTERVAL: usize = 4096;
const WRITE_STAGING_SIZE: usize = 64 * 1024;
const MAX_WRITE_ACCESS_PAGES: usize = WRITE_STAGING_SIZE / PAGE_SIZE + 1;
const WRITEBACK_CONCURRENCY: usize = 4;
// Read-ahead covers 16 pages and the largest staged write touches 17 pages.
// Thirty-two per-file stripes keep those windows collision-free without
// retaining hundreds of async locks for every disk file cache.
const PAGE_ACCESS_LOCK_STRIPES: usize = 32;

type PageAccessLockIndices = heapless::Vec<usize, PAGE_ACCESS_LOCK_STRIPES>;

struct PageAccessDomain {
    // These locks are scoped to one cached file. They serialize cache fills
    // and writes without allocating a lock or touching a BTreeMap for every
    // page-cache access. Resident reads only need the page-cache mutex.
    locks: [async_lock::Mutex<()>; PAGE_ACCESS_LOCK_STRIPES],
}

impl Default for PageAccessDomain {
    fn default() -> Self {
        Self {
            locks: core::array::from_fn(|_| async_lock::Mutex::new(())),
        }
    }
}

impl PageAccessDomain {
    #[inline]
    fn lock_for_page(&self, pn: u32) -> &async_lock::Mutex<()> {
        crate::buildstorm_stat_inc!(PAGE_ACCESS_LOCK_LOOKUPS);
        &self.locks[pn as usize % PAGE_ACCESS_LOCK_STRIPES]
    }

    #[inline]
    fn lock_by_index(&self, index: usize) -> &async_lock::Mutex<()> {
        debug_assert!(index < PAGE_ACCESS_LOCK_STRIPES);
        &self.locks[index]
    }

    async fn acquire_for_page(&self, pn: u32) -> async_lock::MutexGuard<'_, ()> {
        let lock = self.lock_for_page(pn);
        #[cfg(feature = "buildstorm-stats")]
        {
            if let Some(guard) = lock.try_lock() {
                crate::buildstorm_stat_inc!(PAGE_ACCESS_LOCK_FAST);
                return guard;
            }
            crate::buildstorm_stat_inc!(PAGE_ACCESS_LOCK_WAIT);
        }
        lock.lock().await
    }

    async fn acquire_by_index(&self, index: usize) -> async_lock::MutexGuard<'_, ()> {
        let lock = self.lock_by_index(index);
        #[cfg(feature = "buildstorm-stats")]
        {
            if let Some(guard) = lock.try_lock() {
                crate::buildstorm_stat_inc!(PAGE_ACCESS_LOCK_FAST);
                return guard;
            }
            crate::buildstorm_stat_inc!(PAGE_ACCESS_LOCK_WAIT);
        }
        lock.lock().await
    }

    fn locks_for_range(&self, pn: u32, page_count: usize) -> VfsResult<PageAccessLockIndices> {
        let page_count = page_count.max(1);
        crate::buildstorm_stat_add!(PAGE_ACCESS_LOCK_LOOKUPS, page_count);
        let last_offset = u32::try_from(page_count - 1).map_err(|_| VfsError::StorageFull)?;
        pn.checked_add(last_offset).ok_or(VfsError::StorageFull)?;

        let mut indices = PageAccessLockIndices::new();
        if page_count >= PAGE_ACCESS_LOCK_STRIPES {
            for index in 0..PAGE_ACCESS_LOCK_STRIPES {
                indices.push(index).map_err(|_| VfsError::StorageFull)?;
            }
        } else {
            for offset in 0..page_count {
                let page_num = pn
                    .checked_add(u32::try_from(offset).map_err(|_| VfsError::StorageFull)?)
                    .ok_or(VfsError::StorageFull)?;
                let index = page_num as usize % PAGE_ACCESS_LOCK_STRIPES;
                if !indices.contains(&index) {
                    indices.push(index).map_err(|_| VfsError::StorageFull)?;
                }
            }
            indices.sort_unstable();
        }
        crate::buildstorm_stat_add!(PAGE_ACCESS_STRIPES_LOCKED, indices.len());
        Ok(indices)
    }
}

fn checked_page_span(offset: u64, len: usize) -> VfsResult<(u32, usize)> {
    if len == 0 {
        return Err(VfsError::InvalidInput);
    }
    let end = offset
        .checked_add(len as u64)
        .ok_or(VfsError::InvalidInput)?;
    let start_page = u32::try_from(offset / PAGE_SIZE as u64).map_err(|_| VfsError::StorageFull)?;
    let end_page = end.div_ceil(PAGE_SIZE as u64);
    let page_count = usize::try_from(end_page.saturating_sub(start_page as u64))
        .map_err(|_| VfsError::StorageFull)?;
    let last_offset = u32::try_from(page_count - 1).map_err(|_| VfsError::StorageFull)?;
    start_page
        .checked_add(last_offset)
        .ok_or(VfsError::StorageFull)?;
    Ok((start_page, page_count))
}

fn checked_dirty_page_range(offset: u64, len: usize) -> VfsResult<(u32, u32)> {
    if len == 0 {
        return Err(VfsError::InvalidInput);
    }
    let end = offset
        .checked_add(len as u64)
        .ok_or(VfsError::InvalidInput)?;
    let first_page = u32::try_from(offset / PAGE_SIZE as u64).map_err(|_| VfsError::StorageFull)?;
    let end_page =
        u32::try_from(end.div_ceil(PAGE_SIZE as u64)).map_err(|_| VfsError::StorageFull)?;
    debug_assert!(first_page < end_page);
    Ok((first_page, end_page))
}

fn write_all_at(
    mut write: impl FnMut(&[u8], u64) -> VfsResult<usize>,
    data: &[u8],
    offset: u64,
) -> VfsResult<()> {
    let mut completed = 0;
    while completed < data.len() {
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or(VfsError::InvalidInput)?;
        let written = write(&data[completed..], current_offset)?;
        if written == 0 || written > data.len() - completed {
            return Err(VfsError::Io);
        }
        completed += written;
    }
    Ok(())
}

async fn write_all_at_async(file: &FileNode, data: &[u8], offset: u64) -> VfsResult<()> {
    let mut completed = 0;
    while completed < data.len() {
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or(VfsError::InvalidInput)?;
        let written = file.write_at(&data[completed..], current_offset).await?;
        if written == 0 || written > data.len() - completed {
            return Err(VfsError::Io);
        }
        completed += written;
    }
    Ok(())
}

pub(super) async fn write_slice_source_at_async(
    file: &FileNode,
    data: &[u8],
    offset: u64,
) -> VfsResult<usize> {
    offset
        .checked_add(data.len() as u64)
        .ok_or(VfsError::InvalidInput)?;
    if data.is_empty() {
        return Ok(0);
    }
    write_all_at_async(file, data, offset).await?;
    Ok(data.len())
}

pub(super) async fn append_slice_source_async(
    file: &FileNode,
    data: &[u8],
) -> VfsResult<(usize, u64)> {
    if data.is_empty() {
        return Ok((0, file.len().await?));
    }

    let mut written = 0usize;
    let mut end = 0;
    while written < data.len() {
        let (count, new_end) = file.append(&data[written..]).await?;
        if count == 0 || count > data.len() - written {
            return Err(VfsError::Io);
        }
        written += count;
        end = new_end;
    }
    Ok((written, end))
}

struct WritebackPage {
    page_num: u32,
    len: usize,
    content_generation: u64,
    writable_mapping_generation: u64,
    compare_contents: bool,
}

struct WritebackBatch {
    pages: Vec<WritebackPage>,
    offset: u64,
    data: WritebackData,
}

async fn submit_writeback_batch(
    file: &FileNode,
    batch: WritebackBatch,
) -> (WritebackBatch, VfsResult<()>) {
    let result = if batch.data.is_empty() {
        Ok(())
    } else {
        match batch.data.bytes() {
            Ok(data) => write_all_at_async(file, data, batch.offset).await,
            Err(err) => Err(err),
        }
    };
    (batch, result)
}

pub(super) async fn write_source_at_async<R: Read + IoBuf>(
    file: &FileNode,
    source: &mut R,
    offset: u64,
) -> VfsResult<usize> {
    let total = source.remaining();
    offset
        .checked_add(total as u64)
        .ok_or(VfsError::InvalidInput)?;
    if total == 0 {
        return Ok(0);
    }

    let mut staging = alloc::vec![0; total.min(64 * 1024)];
    let mut written = 0usize;
    while written < total {
        let wanted = (total - written).min(staging.len());
        let read = source.read(&mut staging[..wanted])?;
        if read == 0 || read > wanted {
            return Err(VfsError::Io);
        }
        let current_offset = offset
            .checked_add(written as u64)
            .ok_or(VfsError::InvalidInput)?;
        write_all_at_async(file, &staging[..read], current_offset).await?;
        written += read;
    }
    Ok(written)
}

pub(super) async fn append_source_async<R: Read + IoBuf>(
    file: &FileNode,
    source: &mut R,
) -> VfsResult<(usize, u64)> {
    let total = source.remaining();
    if total == 0 {
        return Ok((0, file.len().await?));
    }

    let mut staging = alloc::vec![0; total.min(64 * 1024)];
    let mut written = 0usize;
    let mut end = 0;
    while written < total {
        let wanted = (total - written).min(staging.len());
        let read = source.read(&mut staging[..wanted])?;
        if read == 0 || read > wanted {
            return Err(VfsError::Io);
        }

        let mut completed = 0;
        while completed < read {
            let (count, new_end) = file.append(&staging[completed..read]).await?;
            if count == 0 || count > read - completed {
                return Err(VfsError::Io);
            }
            completed += count;
            written += count;
            end = new_end;
        }
    }
    Ok((written, end))
}

#[derive(Debug)]
struct ContiguousPageGroup {
    addr: VirtAddr,
    pages: usize,
    owns_allocation: AtomicBool,
}

impl Drop for ContiguousPageGroup {
    fn drop(&mut self) {
        if self.owns_allocation.load(Ordering::Acquire) {
            global_allocator().dealloc_pages(self.addr.as_usize(), self.pages);
        }
    }
}

impl ContiguousPageGroup {
    fn new(pages: usize) -> VfsResult<Arc<Self>> {
        if pages == 0 {
            return Err(VfsError::InvalidInput);
        }
        let addr = global_allocator()
            .alloc_pages(pages, PAGE_SIZE)
            .map_err(|_| VfsError::NoMemory)?;
        Ok(Arc::new(Self {
            addr: addr.into(),
            pages,
            owns_allocation: AtomicBool::new(true),
        }))
    }

    fn len(&self) -> VfsResult<usize> {
        self.pages
            .checked_mul(PAGE_SIZE)
            .ok_or(VfsError::StorageFull)
    }

    fn page_addr(&self, index: usize) -> VfsResult<VirtAddr> {
        if index >= self.pages {
            return Err(VfsError::InvalidInput);
        }
        let offset = index.checked_mul(PAGE_SIZE).ok_or(VfsError::StorageFull)?;
        self.addr
            .as_usize()
            .checked_add(offset)
            .map(Into::into)
            .ok_or(VfsError::StorageFull)
    }

    fn split_for_page_cache(self: &Arc<Self>) -> VfsResult<()> {
        if Arc::strong_count(self) != 1 || !self.owns_allocation.load(Ordering::Acquire) {
            return Err(VfsError::BadState);
        }
        global_allocator()
            .split_allocated_pages(self.addr.as_usize(), self.pages)
            .map_err(|_| VfsError::BadState)?;
        self.owns_allocation.store(false, Ordering::Release);
        Ok(())
    }

    /// The group is private until every direct read has completed and it is
    /// published as page-cache entries. Callers must preserve that exclusivity.
    unsafe fn bytes_mut(&self, len: usize) -> VfsResult<&mut [u8]> {
        if len > self.len()? {
            return Err(VfsError::InvalidInput);
        }
        // SAFETY: upheld by the caller as documented above.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.addr.as_mut_ptr(), len) })
    }

    fn bytes(&self, len: usize) -> VfsResult<&[u8]> {
        if len > self.len()? {
            return Err(VfsError::InvalidInput);
        }
        // The writeback owner publishes this immutable view only after it has
        // finished building the snapshot and registered the DMA source.
        Ok(unsafe { core::slice::from_raw_parts(self.addr.as_ptr(), len) })
    }

    fn register_direct_read(
        self: &Arc<Self>,
        len: usize,
    ) -> VfsResult<axdriver::prelude::OwnedReadBufferRegistration> {
        if len == 0 || len > self.len()? {
            return Err(VfsError::InvalidInput);
        }
        let ptr = NonNull::new(self.addr.as_mut_ptr()).ok_or(VfsError::BadState)?;
        // SAFETY: the group is one contiguous allocation and remains private
        // until the direct read completes. The cloned owner also survives a
        // cancelled read until the block driver's lease is released.
        unsafe { axdriver::prelude::register_owned_read_buffer(ptr, len, self.clone()) }
            .map_err(|_| VfsError::BadState)
    }

    fn register_direct_write(
        self: &Arc<Self>,
        len: usize,
    ) -> VfsResult<axdriver::prelude::OwnedWriteBufferRegistration> {
        if len == 0 || len > self.len()? {
            return Err(VfsError::InvalidInput);
        }
        let ptr = NonNull::new(self.addr.as_mut_ptr()).ok_or(VfsError::BadState)?;
        // SAFETY: the group is physically contiguous, immutable after the
        // snapshot is built, and its cloned owner outlives a detached request.
        unsafe { axdriver::prelude::register_owned_write_buffer(ptr, len, self.clone()) }
            .map_err(|_| VfsError::BadState)
    }
}

/// A writeback snapshot uses contiguous pages when possible so VirtIO can
/// claim it as an owned DMA source. A normal `Vec` remains a safe fallback
/// when the page allocator cannot provide one contiguous group.
enum WritebackData {
    Direct {
        group: Arc<ContiguousPageGroup>,
        len: usize,
        _registration: Option<axdriver::prelude::OwnedWriteBufferRegistration>,
    },
    Bounce(Vec<u8>),
}

impl WritebackData {
    fn new(page_count: usize, expected_len: usize) -> Self {
        match ContiguousPageGroup::new(page_count) {
            Ok(group) => Self::Direct {
                group,
                len: 0,
                _registration: None,
            },
            Err(_) => Self::Bounce(Vec::with_capacity(expected_len)),
        }
    }

    fn push_from_slice(&mut self, bytes: &[u8]) -> VfsResult<()> {
        match self {
            Self::Direct { group, len, .. } => {
                let end = len.checked_add(bytes.len()).ok_or(VfsError::StorageFull)?;
                let data = unsafe { group.bytes_mut(end)? };
                data[*len..end].copy_from_slice(bytes);
                *len = end;
            }
            Self::Bounce(data) => data.extend_from_slice(bytes),
        }
        Ok(())
    }

    fn finish_snapshot(&mut self) {
        if let Self::Direct {
            group,
            len,
            _registration,
        } = self
            && *len != 0
        {
            // Registration failure only disables the direct path. The group is
            // still a valid immutable source for the driver's bounce fallback.
            *_registration = group.register_direct_write(*len).ok();
        }
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Direct { len, .. } => *len == 0,
            Self::Bounce(data) => data.is_empty(),
        }
    }

    fn bytes(&self) -> VfsResult<&[u8]> {
        match self {
            Self::Direct { group, len, .. } => group.bytes(*len),
            Self::Bounce(data) => Ok(data),
        }
    }
}

#[derive(Debug)]
struct PageCacheFrame {
    addr: VirtAddr,
}

impl Drop for PageCacheFrame {
    fn drop(&mut self) {
        let paddr = virt_to_phys(self.addr);
        if let Some(ref_count) = axalloc::frame_table().try_get_ref(paddr) {
            if ref_count == 0 {
                global_allocator().dealloc_pages(self.addr.as_usize(), 1);
            } else if axalloc::frame_table().dec_ref(paddr) == 0 {
                global_allocator().dealloc_pages(self.addr.as_usize(), 1);
            }
        } else {
            global_allocator().dealloc_pages(self.addr.as_usize(), 1);
        }
    }
}

#[derive(Debug)]
pub struct PageCache {
    frame: Arc<PageCacheFrame>,
    dirty: bool,
    may_write_mapping: bool,
    content_generation: u64,
    writable_mapping_generation: u64,
}

impl PageCache {
    fn new(skip_zero: bool) -> VfsResult<Self> {
        let frame = Self::new_standalone_frame(skip_zero)?;
        Ok(Self {
            frame,
            dirty: false,
            may_write_mapping: false,
            content_generation: 0,
            writable_mapping_generation: 0,
        })
    }

    fn new_standalone_frame(skip_zero: bool) -> VfsResult<Arc<PageCacheFrame>> {
        let addr = global_allocator()
            .alloc_pages(1, PAGE_SIZE)
            .inspect_err(|err| {
                warn!("Failed to allocate page cache: {:?}", err);
            })
            .map_err(|_| VfsError::NoMemory)?;
        if !skip_zero {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE) };
        }
        Ok(Arc::new(PageCacheFrame { addr: addr.into() }))
    }

    fn from_independent_frame(addr: VirtAddr) -> Self {
        Self {
            frame: Arc::new(PageCacheFrame { addr }),
            dirty: false,
            may_write_mapping: false,
            content_generation: 0,
            writable_mapping_generation: 0,
        }
    }

    pub fn paddr(&self) -> PhysAddr {
        virt_to_phys(self.frame.addr)
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
        self.content_generation = self.content_generation.wrapping_add(1);
    }

    fn mark_mapping_dirty(&mut self) {
        self.dirty = true;
    }

    fn has_user_mapping(&self) -> bool {
        axalloc::frame_table()
            .try_get_ref(self.paddr())
            .is_some_and(|ref_count| ref_count > 1)
    }

    fn pin_for_mapping(&mut self, may_write: bool) -> VfsResult<PhysAddr> {
        let paddr = self.paddr();
        let ref_count = axalloc::frame_table()
            .try_get_ref(paddr)
            .ok_or(VfsError::BadState)?;
        if ref_count <= 1 {
            self.may_write_mapping = false;
        }
        if may_write {
            self.writable_mapping_generation = self.writable_mapping_generation.wrapping_add(1);
        }
        self.may_write_mapping |= may_write;
        if ref_count == 0 {
            axalloc::frame_table().mark_used(paddr);
        }
        axalloc::frame_table().inc_ref(paddr);
        Ok(paddr)
    }

    pub fn data(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.frame.addr.as_mut_ptr(), PAGE_SIZE) }
    }

    fn register_direct_read(
        &self,
        len: usize,
    ) -> VfsResult<axdriver::prelude::OwnedReadBufferRegistration> {
        if len == 0 || len > PAGE_SIZE {
            return Err(VfsError::InvalidInput);
        }
        let ptr = NonNull::new(self.frame.addr.as_mut_ptr()).ok_or(VfsError::BadState)?;
        // SAFETY: A page-cache frame is a dedicated, physically contiguous
        // page. The page is not published while it is being filled, and the
        // cloned frame owner keeps it allocated if the read future is dropped.
        unsafe { axdriver::prelude::register_owned_read_buffer(ptr, len, self.frame.clone()) }
            .map_err(|_| VfsError::BadState)
    }
}

impl Drop for PageCache {
    fn drop(&mut self) {
        if self.dirty {
            warn!("dirty page dropped without flushing");
        }
    }
}

struct EvictListener {
    listener: Box<dyn Fn(u32, &PageCache) + Send + Sync>,
}

pub(super) struct CachedFileShared {
    // Page stripes protect fill/write coherence; inline entries keep the hot
    // cache-hit path to one cache lock without per-page Arc/Mutex overhead.
    page_cache: Mutex<LruCache<u32, PageCache>>,
    page_access: PageAccessDomain,
    cache_soft_limit: AtomicUsize,
    evict_listeners: Mutex<Vec<Arc<EvictListener>>>,
    backing: Option<FileNode>,
    pub(super) io_lock: async_lock::RwLock<()>,
    size: AtomicU64,
    cache_generation: AtomicU64,
}

#[derive(Clone, Copy)]
enum CachedWriteAccess {
    PageRange,
    ExclusiveFileHeld,
}

impl CachedFileShared {
    fn new(in_memory: bool, size: u64, backing: Option<FileNode>) -> Self {
        Self {
            // The LRU's own capacity eagerly reserves hash-table metadata.
            // Keep storage lazy and enforce the disk limit during admission.
            page_cache: Mutex::new(LruCache::unbounded()),
            page_access: PageAccessDomain::default(),
            cache_soft_limit: AtomicUsize::new(if in_memory {
                usize::MAX
            } else {
                DISK_FILE_CACHE_SOFT_LIMIT
            }),
            evict_listeners: Mutex::new(Vec::new()),
            backing,
            io_lock: async_lock::RwLock::new(()),
            size: AtomicU64::new(size),
            cache_generation: AtomicU64::new(0),
        }
    }

    #[inline]
    pub(super) fn size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    #[inline]
    pub(super) fn set_size(&self, size: u64) {
        self.size.store(size, Ordering::Release);
    }

    #[inline]
    fn extend_size(&self, size: u64) {
        self.size.fetch_max(size, Ordering::AcqRel);
    }

    fn pop_clean_lru_pages(
        cache: &mut LruCache<u32, PageCache>,
        max: usize,
    ) -> Vec<(u32, PageCache)> {
        let max = max.min(PAGE_CACHE_EVICTION_BATCH);
        let scan_limit = cache.len().min(
            max.saturating_mul(PAGE_CACHE_SCAN_MULTIPLIER)
                .max(PAGE_CACHE_MIN_SCAN),
        );
        let mut evicted = Vec::with_capacity(max.min(cache.len()));
        let mut scanned = 0;
        while evicted.len() < max && scanned < scan_limit {
            let Some((&pn, page)) = cache.peek_lru() else {
                break;
            };
            if page.dirty || page.has_user_mapping() {
                cache.promote(&pn);
                scanned += 1;
                continue;
            }
            if let Some(entry) = cache.pop_lru() {
                evicted.push(entry);
            }
            scanned += 1;
        }
        evicted
    }

    fn evict_listeners_snapshot(&self) -> Vec<Arc<EvictListener>> {
        self.evict_listeners.lock().clone()
    }

    fn try_evict_clean_pages(&self, max: usize) -> usize {
        let limit = max.min(PAGE_CACHE_EVICTION_BATCH);
        let Some(_io_guard) = self.io_lock.try_read() else {
            return 0;
        };
        let Some(listeners) = self.evict_listeners.try_lock() else {
            return 0;
        };
        if !listeners.is_empty() {
            return 0;
        }
        let Some(mut cache) = self.page_cache.try_lock() else {
            return 0;
        };
        let evicted_pages = Self::pop_clean_lru_pages(&mut cache, limit);
        let evicted = evicted_pages.len();
        drop(cache);
        drop(listeners);
        drop(evicted_pages);
        evicted
    }

    fn flush_dirty_pages_locked(
        file_len: u64,
        file: &FileNode,
        guard: &mut LruCache<u32, PageCache>,
    ) -> VfsResult<()> {
        for (_, page) in guard.iter_mut() {
            if page.may_write_mapping && page.has_user_mapping() {
                page.mark_mapping_dirty();
            }
        }
        let mut dirty_pns: Vec<u32> = guard
            .iter()
            .filter(|(_, page)| page.dirty)
            .map(|(pn, _)| *pn)
            .collect();
        dirty_pns.sort_unstable();

        if dirty_pns.is_empty() {
            return Ok(());
        }

        let mut i = 0;
        while i < dirty_pns.len() {
            let mut j = i;
            while j + 1 < dirty_pns.len()
                && dirty_pns[j + 1] == dirty_pns[j] + 1
                && (j - i) < MAX_WRITEBACK_PAGES - 1
            {
                j += 1;
            }

            let pn_start = dirty_pns[i];
            let pn_end = dirty_pns[j];
            let page_start = pn_start as u64 * PAGE_SIZE as u64;
            let last_page_start = pn_end as u64 * PAGE_SIZE as u64;
            let last_len =
                (file_len.saturating_sub(last_page_start)).min(PAGE_SIZE as u64) as usize;

            if last_len > 0 {
                let total_len = (pn_end - pn_start) as usize * PAGE_SIZE + last_len;
                let mut merged_buf = alloc::vec::Vec::with_capacity(total_len);
                let mut snapshots = Vec::with_capacity(j - i + 1);
                for k in i..=j {
                    let pn_curr = dirty_pns[k];
                    if let Some(page) = guard.get_mut(&pn_curr) {
                        let curr_page_start = pn_curr as u64 * PAGE_SIZE as u64;
                        let curr_len = (file_len.saturating_sub(curr_page_start))
                            .min(PAGE_SIZE as u64) as usize;
                        let compare_contents = page.may_write_mapping && page.has_user_mapping();
                        snapshots.push(WritebackPage {
                            page_num: pn_curr,
                            len: curr_len,
                            content_generation: page.content_generation,
                            writable_mapping_generation: page.writable_mapping_generation,
                            compare_contents,
                        });
                        merged_buf.extend_from_slice(&page.data()[..curr_len]);
                    }
                }

                write_all_at(
                    |data, offset| axtask::future::block_on(file.write_at(data, offset)),
                    &merged_buf,
                    page_start,
                )?;
                let mut data_offset = 0;
                for snapshot in snapshots {
                    let end = data_offset + snapshot.len;
                    if let Some(page) = guard.get_mut(&snapshot.page_num)
                        && page.dirty
                        && page.content_generation == snapshot.content_generation
                        && page.writable_mapping_generation == snapshot.writable_mapping_generation
                        && (!snapshot.compare_contents
                            || page.data()[..snapshot.len] == merged_buf[data_offset..end])
                    {
                        page.dirty = false;
                    }
                    data_offset = end;
                }
            } else {
                for k in i..=j {
                    if let Some(page) = guard.get_mut(&dirty_pns[k]) {
                        page.dirty = false;
                    }
                }
            }

            i = j + 1;
        }

        Ok(())
    }

    pub(super) async fn flush_dirty_pages_async(&self, file: &FileNode) -> VfsResult<()> {
        self.flush_dirty_pages_in_range_async(file, None).await
    }

    /// Flushes dirty cache pages that overlap one direct-I/O request.
    ///
    /// A direct read must observe buffered writes in its range. A direct write
    /// must first persist only the pages it can overwrite, then invalidate that
    /// same range after the device I/O completes. Unrelated dirty pages remain
    /// cache-resident and must not be discarded without writeback.
    pub(super) async fn flush_dirty_range_async(
        &self,
        file: &FileNode,
        offset: u64,
        len: usize,
    ) -> VfsResult<()> {
        if len == 0 {
            return Ok(());
        }
        self.flush_dirty_pages_in_range_async(file, Some(checked_dirty_page_range(offset, len)?))
            .await
    }

    async fn flush_dirty_pages_in_range_async(
        &self,
        file: &FileNode,
        page_range: Option<(u32, u32)>,
    ) -> VfsResult<()> {
        let file_len = self.size();
        if file.len().await? < file_len {
            file.set_len(file_len).await?;
        }

        let dirty_pns = {
            let mut cache = self.page_cache.lock();
            for (_, page) in cache.iter_mut() {
                if page.may_write_mapping && page.has_user_mapping() {
                    page.mark_mapping_dirty();
                }
            }
            let mut dirty = cache
                .iter()
                .filter(|(pn, page)| {
                    page.dirty && page_range.is_none_or(|(first, end)| **pn >= first && **pn < end)
                })
                .map(|(pn, _)| *pn)
                .collect::<Vec<_>>();
            dirty.sort_unstable();
            dirty
        };

        let mut page_batches = Vec::new();
        let mut start = 0;
        while start < dirty_pns.len() {
            let mut end = start + 1;
            while end < dirty_pns.len()
                && end - start < MAX_WRITEBACK_PAGES
                && dirty_pns[end] == dirty_pns[end - 1] + 1
            {
                end += 1;
            }
            page_batches.push(dirty_pns[start..end].to_vec());
            start = end;
        }

        let mut next_batch = 0;
        let mut first_error = None;
        let mut pending = FuturesUnordered::new();
        loop {
            while first_error.is_none()
                && next_batch < page_batches.len()
                && pending.len() < WRITEBACK_CONCURRENCY
            {
                let pages = &page_batches[next_batch];
                let page_start = pages[0] as u64 * PAGE_SIZE as u64;
                let expected_len = pages
                    .len()
                    .checked_mul(PAGE_SIZE)
                    .ok_or(VfsError::StorageFull)?;
                let (mut data, snapshots) = {
                    let mut cache = self.page_cache.lock();
                    let mut data = WritebackData::new(pages.len(), expected_len);
                    let mut snapshots = Vec::with_capacity(pages.len());
                    for &pn in pages {
                        let Some(page) = cache.get_mut(&pn) else {
                            if first_error.is_none() {
                                first_error = Some(VfsError::Io);
                            }
                            break;
                        };
                        let current_start = pn as u64 * PAGE_SIZE as u64;
                        let len =
                            file_len.saturating_sub(current_start).min(PAGE_SIZE as u64) as usize;
                        let compare_contents = page.may_write_mapping && page.has_user_mapping();
                        snapshots.push(WritebackPage {
                            page_num: pn,
                            len,
                            content_generation: page.content_generation,
                            writable_mapping_generation: page.writable_mapping_generation,
                            compare_contents,
                        });
                        data.push_from_slice(&page.data()[..len])?;
                    }
                    (data, snapshots)
                };
                if first_error.is_some() {
                    break;
                }
                data.finish_snapshot();
                pending.push(submit_writeback_batch(
                    file,
                    WritebackBatch {
                        pages: snapshots,
                        offset: page_start,
                        data,
                    },
                ));
                next_batch += 1;
            }

            let Some((batch, result)) = pending.next().await else {
                break;
            };
            if let Err(err) = result {
                if first_error.is_none() {
                    first_error = Some(err);
                }
                continue;
            }

            let mut cache = self.page_cache.lock();
            let data = batch.data.bytes()?;
            let mut data_offset = 0;
            for snapshot in batch.pages {
                let end = data_offset + snapshot.len;
                if let Some(page) = cache.get_mut(&snapshot.page_num)
                    && page.dirty
                    && page.content_generation == snapshot.content_generation
                    && page.writable_mapping_generation == snapshot.writable_mapping_generation
                    && (!snapshot.compare_contents
                        || page.data()[..snapshot.len] == data[data_offset..end])
                {
                    page.dirty = false;
                }
                data_offset = end;
            }
        }

        first_error.map_or(Ok(()), Err)
    }

    async fn discard_pages_without_writeback_async(
        &self,
        file: &FileNode,
        keys: Vec<u32>,
    ) -> VfsResult<()> {
        for pn in keys {
            let mapped_paddr = {
                let mut cache = self.page_cache.lock();
                match cache.get_mut(&pn) {
                    Some(page) if page.has_user_mapping() => Some(page.paddr()),
                    Some(_) => {
                        let mut page = cache.pop(&pn).expect("cached page disappeared");
                        page.dirty = false;
                        drop(cache);
                        let listeners = self.evict_listeners_snapshot();
                        for listener in &listeners {
                            (listener.listener)(pn, &page);
                        }
                        drop(page);
                        None
                    }
                    None => None,
                }
            };

            let Some(paddr) = mapped_paddr else {
                continue;
            };
            let mut data = alloc::vec![0; PAGE_SIZE];
            let read = file
                .read_at(&mut data, pn as u64 * PAGE_SIZE as u64)
                .await?;
            if read > PAGE_SIZE {
                return Err(VfsError::Io);
            }
            data[read..].fill(0);

            let mut cache = self.page_cache.lock();
            if let Some(page) = cache.get_mut(&pn)
                && page.paddr() == paddr
            {
                page.data().copy_from_slice(&data);
                page.dirty = false;
            }
        }
        Ok(())
    }

    /// Invalidates cached pages changed by one direct write without writing
    /// unrelated dirty pages back first.
    ///
    /// The caller holds `io_lock.write()` and has already flushed dirty pages
    /// in this range. Bumping the generation rejects fills that started before
    /// the direct write and would otherwise publish stale data afterwards.
    pub(super) async fn discard_direct_write_range_without_writeback_async(
        &self,
        file: &FileNode,
        offset: u64,
        len: usize,
    ) -> VfsResult<()> {
        if len == 0 {
            return Ok(());
        }
        let (first_page, end_page) = checked_dirty_page_range(offset, len)?;
        self.cache_generation.fetch_add(1, Ordering::AcqRel);
        let keys = self
            .page_cache
            .lock()
            .iter()
            .filter(|(pn, _)| **pn >= first_page && **pn < end_page)
            .map(|(pn, _)| *pn)
            .collect::<Vec<_>>();
        self.discard_pages_without_writeback_async(file, keys).await
    }

    pub(super) async fn discard_all_pages_without_writeback_async(
        &self,
        file: &FileNode,
    ) -> VfsResult<()> {
        self.cache_generation.fetch_add(1, Ordering::AcqRel);
        let keys = self
            .page_cache
            .lock()
            .iter()
            .map(|(pn, _)| *pn)
            .collect::<Vec<_>>();
        self.discard_pages_without_writeback_async(file, keys).await
    }
}

impl Drop for CachedFileShared {
    fn drop(&mut self) {
        let mut guard = self.page_cache.lock();
        let mut dirty_count = 0;
        while let Some((_pn, page)) = guard.pop_lru() {
            if page.dirty {
                dirty_count += 1;
            }
            drop(page);
        }
        if dirty_count > 0 {
            error!(
                "CachedFileShared drop: {} dirty page(s) discarded without flushing!",
                dirty_count
            );
        }
    }
}

async fn flush_file_cache_state(state: Arc<CachedFileShared>) -> Option<(u64, VfsResult<()>)> {
    let file = state.backing.as_ref()?;
    let inode = file.inode();
    let result = async {
        let _guard = state.io_lock.write().await;
        let cached_size = state.size();
        if file.len().await? != cached_size {
            file.set_len(cached_size).await?;
        }
        state.flush_dirty_pages_async(file).await
    }
    .await;
    Some((inode, result))
}

pub(crate) async fn flush_all_file_caches_async() -> VfsResult<()> {
    let states = ACTIVE_DISK_FILE_CACHES.lock().clone();

    let mut first_error = None;
    let mut states = states.into_iter();
    let mut pending = FuturesUnordered::new();
    loop {
        while pending.len() < WRITEBACK_CONCURRENCY {
            let Some(state) = states.next() else {
                break;
            };
            pending.push(flush_file_cache_state(state));
        }
        let Some(result) = pending.next().await else {
            break;
        };
        if let Some((inode, Err(err))) = result {
            error!("Failed to flush cached inode {}: {:?}", inode, err);
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }

    if first_error.is_none() {
        // Dropping a backing inode can invalidate this registry, so move all
        // released entries out before the global lock is dropped.
        let removed = {
            let mut caches = ACTIVE_DISK_FILE_CACHES.lock();
            let mut removed = Vec::new();
            let mut index = 0;
            while index < caches.len() {
                if Arc::strong_count(&caches[index]) == 1 {
                    removed.push(caches.swap_remove(index));
                } else {
                    index += 1;
                }
            }
            removed
        };
        drop(removed);
    }

    first_error.map_or(Ok(()), Err)
}

struct ReclaimGuard {
    slot_mask: usize,
}

impl Drop for ReclaimGuard {
    fn drop(&mut self) {
        PAGE_CACHE_RECLAIM_ACTIVE_CPUS.fetch_and(!self.slot_mask, Ordering::Release);
    }
}

static PAGE_CACHE_RECLAIM_ACTIVE_CPUS: AtomicUsize = AtomicUsize::new(0);
static PAGE_CACHE_RECLAIMED_TOTAL: AtomicUsize = AtomicUsize::new(0);
static PAGE_CACHE_RECLAIM_ZERO_STREAK: AtomicUsize = AtomicUsize::new(0);
static PAGE_CACHE_RECLAIM_CURSOR: AtomicUsize = AtomicUsize::new(0);

fn page_cache_reclaim_inner(num_pages: usize) -> usize {
    if num_pages == 0 {
        return 0;
    }

    let mut reclaimed = 0;
    let mut file_count = 0;

    let cache_count = ACTIVE_DISK_FILE_CACHES
        .try_lock()
        .map(|caches| caches.len())
        .unwrap_or(0);
    if cache_count == 0 {
        return 0;
    }
    let start = PAGE_CACHE_RECLAIM_CURSOR.fetch_add(1, Ordering::Relaxed) % cache_count;
    for offset in 0..cache_count {
        let file = {
            let Some(caches) = ACTIVE_DISK_FILE_CACHES.try_lock() else {
                break;
            };
            if caches.is_empty() {
                break;
            }
            caches[(start + offset) % caches.len()].clone()
        };
        let freed = file.try_evict_clean_pages(num_pages.saturating_sub(reclaimed));
        reclaimed += freed;
        file_count += 1;
        if reclaimed >= num_pages {
            break;
        }
    }

    if reclaimed > 0 {
        debug!(
            "page_cache_reclaim: evicted {} clean pages across {} files",
            reclaimed, file_count
        );
    }

    reclaimed
}

fn prune_inactive_disk_file_caches() {
    loop {
        let removed = {
            let Some(mut caches) = ACTIVE_DISK_FILE_CACHES.try_lock() else {
                return;
            };
            caches
                .iter()
                .position(|cached| {
                    Arc::strong_count(cached) == 1
                        && cached
                            .page_cache
                            .try_lock()
                            .map(|cache| cache.is_empty())
                            .unwrap_or(false)
                })
                .map(|index| caches.swap_remove(index))
        };
        let Some(removed) = removed else {
            return;
        };
        // Drop after releasing the registry lock: the backing inode teardown
        // may re-enter filesystem registries.
        drop(removed);
    }
}

/// Reclaim clean, unmapped page-cache pages after a physical allocation failure.
///
/// This path deliberately never writes dirty pages back. File I/O and allocator
/// pressure must not turn into synchronous filesystem writeback.
pub fn page_cache_reclaim(num_pages: usize) -> usize {
    if num_pages == 0 {
        return 0;
    }

    let cpu_id = axhal::percpu::this_cpu_id();
    let slot = cpu_id % usize::BITS as usize;
    let slot_mask = 1usize << slot;
    if PAGE_CACHE_RECLAIM_ACTIVE_CPUS.fetch_or(slot_mask, Ordering::AcqRel) & slot_mask != 0 {
        // Allocation failure can re-enter reclaim while dropping cache state.
        // Only suppress recursion on the same CPU slot; other CPUs may scan
        // independent file caches concurrently.
        return 0;
    }

    let _guard = ReclaimGuard { slot_mask };
    let reclaimed = page_cache_reclaim_inner(num_pages);
    if reclaimed > 0 {
        PAGE_CACHE_RECLAIM_ZERO_STREAK.store(0, Ordering::Relaxed);
        let previous = PAGE_CACHE_RECLAIMED_TOTAL.fetch_add(reclaimed, Ordering::Release);
        let total = previous.wrapping_add(reclaimed);
        if previous == 0
            || previous / PAGE_CACHE_RECLAIM_LOG_INTERVAL != total / PAGE_CACHE_RECLAIM_LOG_INTERVAL
        {
            info!(
                "page_cache_reclaim_progress: total_pages={} last_pages={} requested_pages={}",
                total, reclaimed, num_pages
            );
        }
    } else {
        let streak = PAGE_CACHE_RECLAIM_ZERO_STREAK.fetch_add(1, Ordering::Relaxed) + 1;
        if streak <= 4 || streak.is_power_of_two() {
            let active_caches = ACTIVE_DISK_FILE_CACHES
                .try_lock()
                .map(|caches| caches.len())
                .unwrap_or(usize::MAX);
            warn!(
                "page_cache_reclaim_stalled: streak={} requested_pages={} active_caches={} \
                 available_pages={}",
                streak,
                num_pages,
                active_caches,
                global_allocator().available_pages()
            );
        }
    }
    prune_inactive_disk_file_caches();
    reclaimed
}

pub(super) async fn shared_file_state_async(
    location: &Location,
) -> VfsResult<Arc<CachedFileShared>> {
    if !node_allows_page_cache(location.flags()) {
        return Err(VfsError::OperationNotSupported);
    }

    let key = file_cache_key(location);
    let registry_shard = file_state_registry_shard(key);
    let in_memory = location.filesystem().name() == "tmpfs";

    {
        let registry = FILE_SHARED_STATES[registry_shard].lock();
        if let Some(state) = registry.get(&key) {
            return Ok(state);
        }
    }

    let size = location.len().await.unwrap_or(0);
    let backing = if in_memory {
        None
    } else {
        location.entry().as_file().ok().cloned()
    };
    let state = Arc::new(CachedFileShared::new(in_memory, size, backing));

    let mut registry = FILE_SHARED_STATES[registry_shard].lock();
    if let Some(existing_state) = registry.get(&key) {
        drop(registry);
        drop(state);
        return Ok(existing_state);
    }
    registry.sweep_dead();
    registry.insert(key, &state);
    crate::buildstorm_stat_inc!(FILE_CACHE_STATES_CREATED);
    drop(registry);
    if !in_memory {
        ACTIVE_DISK_FILE_CACHES.lock().push(state.clone());
    }
    Ok(state)
}

pub fn cached_file_size(location: &Location) -> VfsResult<u64> {
    if let Some(size) = cached_file_size_if_present(location) {
        Ok(size)
    } else {
        axtask::future::block_on(location.len())
    }
}

pub fn cached_file_size_if_present(location: &Location) -> Option<u64> {
    let key = file_cache_key(location);
    FILE_SHARED_STATES[file_state_registry_shard(key)]
        .lock()
        .get(&key)
        .map(|state| state.size())
}

enum FileUserData {
    Strong(Arc<CachedFileShared>),
}

impl FileUserData {
    fn get(&self) -> Arc<CachedFileShared> {
        match self {
            FileUserData::Strong(strong) => strong.clone(),
        }
    }
}

#[derive(Clone)]
pub struct CachedFile {
    inner: Location,
    shared: Arc<CachedFileShared>,
    in_memory: bool,
    read_hint: Arc<AtomicU64>,
}

impl CachedFile {
    pub async fn get_or_create_async(location: Location) -> VfsResult<Self> {
        if !node_allows_page_cache(location.flags()) {
            return Err(VfsError::OperationNotSupported);
        }

        let in_memory = location.filesystem().name() == "tmpfs";
        let existing = location
            .user_data()
            .get::<FileUserData>()
            .map(|data| data.get());
        let shared = match existing {
            Some(shared) => shared,
            None => {
                let candidate = shared_file_state_async(&location).await?;
                let mut user_data = location.user_data();
                if let Some(existing) = user_data.get::<FileUserData>() {
                    existing.get()
                } else {
                    user_data.insert(FileUserData::Strong(candidate.clone()));
                    candidate
                }
            }
        };

        Ok(Self {
            inner: location,
            shared,
            in_memory,
            read_hint: Arc::new(AtomicU64::new(u64::MAX)),
        })
    }

    pub fn get_or_create(location: Location) -> VfsResult<Self> {
        axtask::future::block_on(Self::get_or_create_async(location))
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    /// Returns the logical size shared by all cached handles and mappings.
    #[inline]
    pub fn size(&self) -> u64 {
        self.shared.size()
    }

    pub fn in_memory(&self) -> bool {
        self.in_memory
    }

    pub fn add_evict_listener<F>(&self, listener: F) -> usize
    where
        F: Fn(u32, &PageCache) + Send + Sync + 'static,
    {
        let pointer = Arc::new(EvictListener {
            listener: Box::new(listener),
        });
        let handle = Arc::as_ptr(&pointer) as usize;
        self.shared.evict_listeners.lock().push(pointer);
        handle
    }

    pub unsafe fn remove_evict_listener(&self, handle: usize) {
        let mut guard = self.shared.evict_listeners.lock();
        if let Some(pos) = guard
            .iter()
            .position(|listener| Arc::as_ptr(listener) as usize == handle)
        {
            guard.remove(pos);
        }
    }

    fn evict_cache(&self, file: &FileNode, pn: u32, page: &mut PageCache) -> VfsResult<()> {
        let listeners = self.shared.evict_listeners_snapshot();
        for listener in listeners.iter() {
            (listener.listener)(pn, page);
        }
        if page.dirty {
            let cached_size = self.shared.size();
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let len = (cached_size.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
            if len > 0 {
                axtask::future::block_on(file.write_at(&page.data()[..len], page_start))?;
            }
            page.dirty = false;
        }
        Ok(())
    }

    fn page_or_insert(
        &self,
        file: &FileNode,
        cache: &mut LruCache<u32, PageCache>,
        pn: u32,
        mut skip_read: bool,
        file_len: u64,
    ) -> VfsResult<Option<(u32, PageCache)>> {
        if cache.contains(&pn) {
            return Ok(None);
        }
        let mut evicted = None;
        let cache_soft_limit = self.shared.cache_soft_limit.load(Ordering::Acquire);
        if !self.in_memory && cache.len() >= cache_soft_limit {
            let mut clean = CachedFileShared::pop_clean_lru_pages(cache, 1);
            if clean.is_empty()
                && cache
                    .iter()
                    .rev()
                    .take(PAGE_CACHE_MIN_SCAN)
                    .any(|(_, page)| page.dirty && !page.has_user_mapping())
            {
                CachedFileShared::flush_dirty_pages_locked(file_len, file, cache)?;
                clean = CachedFileShared::pop_clean_lru_pages(cache, 1);
            }
            if let Some((evict_pn, mut page)) = clean.pop() {
                if let Err(err) = self.evict_cache(file, evict_pn, &mut page) {
                    cache.put(evict_pn, page);
                    return Err(err);
                }
                evicted = Some((evict_pn, page));
            } else {
                self.shared.cache_soft_limit.fetch_max(
                    cache_soft_limit.saturating_add(PAGE_CACHE_GROWTH_HEADROOM),
                    Ordering::AcqRel,
                );
            }
        }

        // Page not in cache, read it
        if (pn as u64 * PAGE_SIZE as u64) >= file_len {
            skip_read = true;
        }
        let mut page = PageCache::new(!skip_read)?;
        if self.in_memory {
            if !skip_read {
                page.data().fill(0);
            }
        } else if !skip_read {
            let registration = page.register_direct_read(PAGE_SIZE)?;
            let read_result =
                axtask::future::block_on(file.read_at(page.data(), pn as u64 * PAGE_SIZE as u64));
            drop(registration);
            let read_len = read_result?;
            if read_len < PAGE_SIZE {
                page.data()[read_len..].fill(0);
            }
        }
        cache.put(pn, page);
        Ok(evicted)
    }

    fn pin_cached_pages(
        cache: &mut LruCache<u32, PageCache>,
        pn: u32,
        page_count: usize,
        may_write: bool,
    ) -> VfsResult<Option<SharedPagePaddrs>> {
        let page_count = checked_shared_page_count(page_count)?;
        for offset in 0..page_count {
            let offset = u32::try_from(offset).map_err(|_| VfsError::StorageFull)?;
            let page_num = pn.checked_add(offset).ok_or(VfsError::StorageFull)?;
            if !cache.contains(&page_num) {
                return Ok(None);
            }
        }

        let mut pinned = SharedPagePaddrs::new();
        for offset in 0..page_count {
            let offset = u32::try_from(offset).map_err(|_| VfsError::StorageFull)?;
            let page_num = pn.checked_add(offset).ok_or(VfsError::StorageFull)?;
            let result = cache
                .get_mut(&page_num)
                .ok_or(VfsError::BadState)
                .and_then(|page| page.pin_for_mapping(may_write));
            match result {
                Ok(paddr) => {
                    if let Err((_, paddr)) = pinned.push((page_num, paddr)) {
                        let refs = axalloc::frame_table().dec_ref(paddr);
                        debug_assert_ne!(refs, 0);
                        while let Some((_, paddr)) = pinned.pop() {
                            let refs = axalloc::frame_table().dec_ref(paddr);
                            debug_assert_ne!(refs, 0);
                        }
                        return Err(VfsError::StorageFull);
                    }
                }
                Err(err) => {
                    while let Some((_, paddr)) = pinned.pop() {
                        let refs = axalloc::frame_table().dec_ref(paddr);
                        debug_assert_ne!(refs, 0);
                    }
                    return Err(err);
                }
            }
        }
        Ok(Some(pinned))
    }

    async fn pin_resident_pages(
        &self,
        pn: u32,
        page_count: usize,
        may_write: bool,
    ) -> VfsResult<Option<SharedPagePaddrs>> {
        let _io_guard = self.shared.io_lock.read().await;
        let mut cache = self.shared.page_cache.lock();
        Self::pin_cached_pages(&mut cache, pn, page_count, may_write)
    }

    async fn load_pages_async(
        &self,
        file: &FileNode,
        pn: u32,
        page_count: usize,
        file_len: u64,
    ) -> VfsResult<Vec<(u32, PageCache)>> {
        let page_start = pn as u64 * PAGE_SIZE as u64;
        let bytes_available = file_len.saturating_sub(page_start);
        crate::buildstorm_stat_inc!(PAGE_FILL_CALLS);
        crate::buildstorm_stat_add!(PAGE_FILL_PAGES, page_count);

        if page_count == 1 {
            // A single-page fault can read directly into its final page. This
            // avoids allocating, zeroing, and copying through a temporary Vec.
            let will_read = !self.in_memory && bytes_available != 0;
            crate::buildstorm_stat_inc!(PAGE_FILL_DIRECT_PAGES);
            let mut page = PageCache::new(will_read)?;
            if will_read {
                let wanted = bytes_available.min(PAGE_SIZE as u64) as usize;
                crate::buildstorm_stat_add!(PAGE_FILL_DEVICE_BYTES, wanted);
                let registration = page.register_direct_read(wanted)?;
                let read_result = file.read_at(&mut page.data()[..wanted], page_start).await;
                drop(registration);
                let read = read_result?;
                if read > wanted {
                    return Err(VfsError::Io);
                }
                page.data()[read..].fill(0);
            }
            let mut pages = Vec::with_capacity(1);
            pages.push((pn, page));
            return Ok(pages);
        }

        let buffer_len = page_count
            .checked_mul(PAGE_SIZE)
            .ok_or(VfsError::StorageFull)?;
        crate::buildstorm_stat_add!(PAGE_FILL_CONTIGUOUS_PAGES, page_count);
        let group = ContiguousPageGroup::new(page_count)?;
        let mut initialized = 0;
        if !self.in_memory && bytes_available != 0 {
            let wanted = bytes_available.min(buffer_len as u64) as usize;
            crate::buildstorm_stat_add!(PAGE_FILL_DIRECT_PAGES, page_count);
            crate::buildstorm_stat_add!(PAGE_FILL_DEVICE_BYTES, wanted);
            let registration = group.register_direct_read(wanted)?;
            let read_result = {
                // SAFETY: `group` is not visible outside this fill operation
                // until the direct read completes and its registration is
                // dropped below.
                let data = unsafe { group.bytes_mut(wanted)? };
                file.read_at(data, page_start).await
            };
            drop(registration);
            let read = read_result?;
            if read > wanted {
                return Err(VfsError::Io);
            }
            initialized = read;
        }
        if initialized < buffer_len {
            // SAFETY: no direct read is in flight after the registration above
            // was dropped, and the group is still private to this fill.
            let data = unsafe { group.bytes_mut(buffer_len)? };
            data[initialized..].fill(0);
        }

        // Validate every derived address before changing allocator ownership.
        // Once split, each page is released independently by PageCacheFrame.
        let _ = group.page_addr(page_count - 1)?;
        let last_page_offset = u32::try_from(page_count - 1).map_err(|_| VfsError::StorageFull)?;
        let _ = pn
            .checked_add(last_page_offset)
            .ok_or(VfsError::StorageFull)?;
        group.split_for_page_cache()?;

        let mut pages = Vec::with_capacity(page_count);
        for page_offset in 0..page_count {
            let page_num = pn
                .checked_add(u32::try_from(page_offset).map_err(|_| VfsError::StorageFull)?)
                .ok_or(VfsError::StorageFull)?;
            pages.push((
                page_num,
                PageCache::from_independent_frame(group.page_addr(page_offset)?),
            ));
        }
        Ok(pages)
    }

    async fn ensure_write_page_async(
        &self,
        file: &FileNode,
        pn: u32,
        skip_read: bool,
        file_len: u64,
    ) -> VfsResult<()> {
        if self.shared.page_cache.lock().contains(&pn) {
            return Ok(());
        }

        let page_start = pn as u64 * PAGE_SIZE as u64;
        let should_read = !self.in_memory && !skip_read && page_start < file_len;
        let mut page = PageCache::new(should_read)?;
        if should_read {
            let wanted = file_len.saturating_sub(page_start).min(PAGE_SIZE as u64) as usize;
            let registration = page.register_direct_read(wanted)?;
            let read_result = file.read_at(&mut page.data()[..wanted], page_start).await;
            drop(registration);
            let read = read_result?;
            if read > wanted {
                return Err(VfsError::Io);
            }
            page.data()[read..].fill(0);
        }

        let mut evicted_pages = Vec::new();
        let mut page = Some(page);
        let mut attempted_writeback = false;
        loop {
            let should_write_back = {
                let mut cache = self.shared.page_cache.lock();
                if cache.contains(&pn) {
                    return Ok(());
                }
                let cache_soft_limit = self.shared.cache_soft_limit.load(Ordering::Acquire);
                if self.in_memory || cache.len() < cache_soft_limit {
                    cache.put(pn, page.take().expect("write page already inserted"));
                    break;
                }

                evicted_pages = CachedFileShared::pop_clean_lru_pages(&mut cache, 1);
                if !evicted_pages.is_empty() {
                    cache.put(pn, page.take().expect("write page already inserted"));
                    break;
                }

                !attempted_writeback
                    && cache
                        .iter()
                        .any(|(_, page)| page.dirty && !page.has_user_mapping())
            };

            if should_write_back {
                self.shared.flush_dirty_pages_async(file).await?;
                attempted_writeback = true;
                continue;
            }

            let mut cache = self.shared.page_cache.lock();
            let cache_soft_limit = self.shared.cache_soft_limit.load(Ordering::Acquire);
            self.shared.cache_soft_limit.fetch_max(
                cache_soft_limit.saturating_add(PAGE_CACHE_GROWTH_HEADROOM),
                Ordering::AcqRel,
            );
            cache.put(pn, page.take().expect("write page already inserted"));
            break;
        }

        if !evicted_pages.is_empty() {
            let listeners = self.shared.evict_listeners_snapshot();
            for (evicted_pn, page) in &evicted_pages {
                for listener in &listeners {
                    (listener.listener)(*evicted_pn, page);
                }
            }
        }
        Ok(())
    }

    async fn ensure_pages_loaded_async(
        &self,
        file: &FileNode,
        pn: u32,
        requested_pages: usize,
        pin: Option<bool>,
    ) -> VfsResult<(usize, Option<SharedPagePaddrs>)> {
        let requested_pages = requested_pages.max(1);
        let page_locks = self
            .shared
            .page_access
            .locks_for_range(pn, requested_pages)?;
        let mut fill_guards = heapless::Vec::<_, PAGE_ACCESS_LOCK_STRIPES>::new();
        for &index in &page_locks {
            fill_guards
                .push(self.shared.page_access.acquire_by_index(index).await)
                .map_err(|_| VfsError::StorageFull)?;
        }

        loop {
            let (generation, file_len, page_count, first_missing, resident_pins) = {
                let _io_guard = self.shared.io_lock.read().await;
                let mut cache = self.shared.page_cache.lock();
                let file_len = self.shared.size();
                let page_start = pn as u64 * PAGE_SIZE as u64;
                let bytes_available = file_len.saturating_sub(page_start);
                let pages_available = bytes_available.div_ceil(PAGE_SIZE as u64) as usize;
                let page_count = requested_pages.min(pages_available.max(1));
                let mut first_missing = None;
                for offset in 0..page_count {
                    let offset_u32 = u32::try_from(offset).map_err(|_| VfsError::StorageFull)?;
                    let page_num = pn.checked_add(offset_u32).ok_or(VfsError::StorageFull)?;
                    if !cache.contains(&page_num) {
                        first_missing = Some((offset, page_num));
                        break;
                    }
                }
                let resident_pins = if first_missing.is_none() {
                    pin.map(|may_write| {
                        Self::pin_cached_pages(&mut cache, pn, page_count, may_write)?
                            .ok_or(VfsError::BadState)
                    })
                    .transpose()?
                } else {
                    None
                };
                (
                    self.shared.cache_generation.load(Ordering::Acquire),
                    file_len,
                    page_count,
                    first_missing,
                    resident_pins,
                )
            };

            let Some((first_missing_offset, first_missing_page)) = first_missing else {
                return Ok((page_count, resident_pins));
            };
            // A mapping pin must publish the whole requested run atomically.
            // While the backing I/O is pending, reclaim may evict a prefix
            // that was resident in the snapshot above. Retaining a fill for
            // the full run lets publication replace any such prefix instead
            // of turning the user fault into `BadState`.
            let (fill_page, fill_count) = if pin.is_some() {
                (pn, page_count)
            } else {
                (first_missing_page, page_count - first_missing_offset)
            };
            let mut new_pages = self
                .load_pages_async(file, fill_page, fill_count, file_len)
                .await?;

            // Direct writes hold the exclusive side while changing the backend
            // and invalidating the cache. Validate and publish under the shared
            // side so a stale fill can never be inserted after that invalidation.
            let io_guard = self.shared.io_lock.read().await;
            if self.shared.cache_generation.load(Ordering::Acquire) != generation {
                continue;
            }

            let mut evicted_pages = Vec::new();
            let mut cache = self.shared.page_cache.lock();
            let incoming = new_pages
                .iter()
                .filter(|(page_num, _)| !cache.contains(page_num))
                .count();
            let required = cache.len().saturating_add(incoming);
            let cache_soft_limit = self.shared.cache_soft_limit.load(Ordering::Acquire);
            let pinned_pages = if let Some(may_write) = pin {
                for (page_num, page) in new_pages.drain(..) {
                    if cache.contains(&page_num) {
                        continue;
                    }
                    cache.put(page_num, page);
                }
                Self::pin_cached_pages(&mut cache, pn, page_count, may_write)?
            } else {
                None
            };
            if !self.in_memory && required > cache_soft_limit {
                let needed = required - cache_soft_limit;
                evicted_pages = CachedFileShared::pop_clean_lru_pages(&mut cache, needed);
                let remaining = needed.saturating_sub(evicted_pages.len());
                if remaining != 0 {
                    self.shared.cache_soft_limit.fetch_max(
                        cache_soft_limit.saturating_add(remaining.max(PAGE_CACHE_GROWTH_HEADROOM)),
                        Ordering::AcqRel,
                    );
                }
            }

            for (page_num, page) in new_pages {
                if cache.contains(&page_num) {
                    continue;
                }
                cache.put(page_num, page);
            }
            drop(cache);
            drop(io_guard);

            let listeners =
                (!evicted_pages.is_empty()).then(|| self.shared.evict_listeners_snapshot());
            crate::buildstorm_stat_add!(PAGE_EVICTIONS, evicted_pages.len());
            for (evicted_pn, page) in &evicted_pages {
                for listener in listeners.as_ref().unwrap().iter() {
                    (listener.listener)(*evicted_pn, page);
                }
            }
            drop(evicted_pages);
            if pin.is_some() && pinned_pages.is_none() {
                continue;
            }
            return Ok((page_count, pinned_pages));
        }
    }

    async fn pin_pages_inner_async(
        &self,
        file: &FileNode,
        pn: u32,
        requested_pages: usize,
        may_write: bool,
    ) -> VfsResult<SharedPagePaddrs> {
        let requested_pages = checked_shared_page_count(requested_pages)?;
        if let Some(pages) = self
            .pin_resident_pages(pn, requested_pages, may_write)
            .await?
        {
            return Ok(pages);
        }
        self.ensure_pages_loaded_async(file, pn, requested_pages, Some(may_write))
            .await?
            .1
            .ok_or(VfsError::BadState)
    }

    async fn ensure_pages_inner_async(
        &self,
        file: &FileNode,
        pn: u32,
        requested_pages: usize,
        pin: Option<bool>,
    ) -> VfsResult<Option<PhysAddr>> {
        if let Some(may_write) = pin {
            return self
                .pin_pages_inner_async(file, pn, 1, may_write)
                .await?
                .into_iter()
                .next()
                .map(|(_, paddr)| paddr)
                .ok_or(VfsError::BadState)
                .map(Some);
        }
        self.ensure_pages_loaded_async(file, pn, requested_pages, None)
            .await
            .map(|_| None)
    }

    async fn ensure_pages_async(
        &self,
        file: &FileNode,
        pn: u32,
        requested_pages: usize,
    ) -> VfsResult<()> {
        self.ensure_pages_inner_async(file, pn, requested_pages, None)
            .await
            .map(drop)
    }

    pub fn with_page<R>(&self, pn: u32, f: impl FnOnce(Option<&mut PageCache>) -> R) -> R {
        let _page_guard = axtask::future::block_on(self.shared.page_access.acquire_for_page(pn));
        let _guard = axtask::future::block_on(self.shared.io_lock.read());
        let mut cache = self.shared.page_cache.lock();
        f(cache.get_mut(&pn))
    }

    pub fn with_page_or_insert<R>(
        &self,
        pn: u32,
        f: impl FnOnce(&mut PageCache, Option<(u32, PageCache)>) -> VfsResult<R>,
    ) -> VfsResult<R> {
        let io_guard = axtask::future::block_on(self.shared.io_lock.write());
        let file_len = self.shared.size();
        let mut guard = self.shared.page_cache.lock();
        let evicted = self.page_or_insert(
            self.inner.entry().as_file()?,
            &mut guard,
            pn,
            false,
            file_len,
        )?;
        let page = guard.get_mut(&pn).ok_or(VfsError::BadState)?;
        let result = f(page, evicted);
        drop(guard);
        drop(io_guard);
        result
    }

    /// Tries to satisfy a read entirely from resident cache pages without
    /// waiting. A lock conflict or cache miss returns `None` so the caller can
    /// retain the normal asynchronous read path.
    pub(super) fn try_read_at_resident(
        &self,
        mut dst: impl Write + IoBufMut,
        offset: u64,
    ) -> Option<VfsResult<usize>> {
        // Match the regular read lock order. The shared side prevents a direct
        // write or truncate from invalidating pages while they are copied.
        let _io_guard = self.shared.io_lock.try_read()?;
        let len = self.shared.size();
        let remaining = dst.remaining_mut();
        if remaining == 0 || offset >= len {
            return Some(Ok(0));
        }

        // Calculate from the available range rather than `offset + remaining`
        // so an oversized caller buffer cannot wrap the file offset.
        let read_len = (len - offset).min(remaining as u64) as usize;
        let end = offset + read_len as u64;
        let start_page = (offset / PAGE_SIZE as u64) as u32;
        let end_page = end.div_ceil(PAGE_SIZE as u64) as u32;

        let mut cache = self.shared.page_cache.try_lock()?;
        if !(start_page..end_page).all(|pn| cache.contains(&pn)) {
            return None;
        }

        let mut page_offset = (offset % PAGE_SIZE as u64) as usize;
        let mut read = 0usize;
        for pn in start_page..end_page {
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let page_end = (end - page_start).min(PAGE_SIZE as u64) as usize;
            let copied = match page_end.checked_sub(page_offset) {
                Some(copied) => copied,
                None => return Some(Err(VfsError::BadState)),
            };
            let page = cache
                .get_mut(&pn)
                .expect("resident cache page disappeared while locked");
            let written = match dst.write(&page.data()[page_offset..page_end]) {
                Ok(written) => written,
                Err(err) => return Some(Err(err.into())),
            };
            if written != copied {
                return Some(Err(VfsError::Io));
            }
            read = match read.checked_add(copied) {
                Some(read) => read,
                None => return Some(Err(VfsError::Io)),
            };
            page_offset = 0;
        }

        crate::buildstorm_stat_add!(PAGE_READ_HITS, end_page - start_page);
        self.read_hint.store(end, Ordering::Release);
        Some(Ok(read))
    }

    pub(super) async fn read_at_async(
        &self,
        mut dst: impl Write + IoBufMut,
        offset: u64,
    ) -> VfsResult<usize> {
        let len = self.shared.size();
        let end = (offset + dst.remaining_mut() as u64).min(len);
        if end <= offset {
            return Ok(0);
        }
        let file = self.inner.entry().as_file()?;
        let start_page = (offset / PAGE_SIZE as u64) as u32;
        let end_page = end.div_ceil(PAGE_SIZE as u64) as u32;
        let mut page_offset = (offset % PAGE_SIZE as u64) as usize;
        let mut read = 0usize;
        let sequential = self.read_hint.load(Ordering::Acquire) == offset;
        let mut pn = start_page;
        while pn < end_page {
            let hit_pages = {
                // A resident page is stable while `page_cache` is held. Keep
                // the shared lock only for a bounded copy batch; cache fills
                // and device waits happen after both guards are dropped.
                let _io_guard = self.shared.io_lock.read().await;
                let mut cache = self.shared.page_cache.lock();
                let mut hit_pages = 0usize;
                while pn < end_page && hit_pages < READ_COPY_BATCH_PAGES {
                    let page_start = pn as u64 * PAGE_SIZE as u64;
                    let page_end = (end - page_start).min(PAGE_SIZE as u64) as usize;
                    let Some(page) = cache.get_mut(&pn) else {
                        break;
                    };
                    let copied = page_end
                        .checked_sub(page_offset)
                        .ok_or(VfsError::BadState)?;
                    let written = dst.write(&page.data()[page_offset..page_end])?;
                    if written != copied {
                        return Err(VfsError::Io);
                    }
                    read = read.checked_add(copied).ok_or(VfsError::Io)?;
                    pn = pn.checked_add(1).ok_or(VfsError::StorageFull)?;
                    page_offset = 0;
                    hit_pages += 1;
                }
                hit_pages
            };
            if hit_pages != 0 {
                crate::buildstorm_stat_add!(PAGE_READ_HITS, hit_pages);
                continue;
            }

            crate::buildstorm_stat_inc!(PAGE_READ_MISSES);
            // The page can be invalidated after a fill returns but before this
            // task reacquires the read lock, so retry this lookup on the next
            // iteration rather than carrying a page reference across await.
            self.ensure_pages_async(file, pn, if sequential { READ_AHEAD_PAGES } else { 1 })
                .await?;
        }
        self.read_hint.store(end, Ordering::Release);
        Ok(read)
    }

    pub fn read_at(&self, dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        axtask::future::block_on(self.read_at_async(dst, offset))
    }

    async fn write_slice_at_locked_async(
        &self,
        file: &FileNode,
        data: &[u8],
        offset: u64,
    ) -> VfsResult<usize> {
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(VfsError::InvalidInput)?;
        let original_len = self.shared.size();
        let mut current = offset;
        let mut copied = 0;

        while current < end {
            let pn = (current / PAGE_SIZE as u64) as u32;
            let page_offset = (current % PAGE_SIZE as u64) as usize;
            let len = (data.len() - copied).min(PAGE_SIZE - page_offset);
            let skip_read = page_offset == 0 && len == PAGE_SIZE;
            self.ensure_write_page_async(file, pn, skip_read, original_len)
                .await?;

            let mut cache = self.shared.page_cache.lock();
            let page = cache.get_mut(&pn).ok_or(VfsError::Io)?;
            page.data()[page_offset..page_offset + len]
                .copy_from_slice(&data[copied..copied + len]);
            crate::buildstorm_stat_add!(PAGE_WRITE_BYTES, len);
            if !self.in_memory {
                page.mark_dirty();
            }
            drop(cache);

            copied += len;
            current = current
                .checked_add(len as u64)
                .ok_or(VfsError::InvalidInput)?;
            self.shared.extend_size(current);
        }

        Ok(copied)
    }

    async fn write_slice_chunk_with_access_async(
        &self,
        file: &FileNode,
        data: &[u8],
        offset: u64,
        access: CachedWriteAccess,
    ) -> VfsResult<usize> {
        match access {
            CachedWriteAccess::PageRange => {
                let (start_page, page_count) = checked_page_span(offset, data.len())?;
                debug_assert!(page_count <= MAX_WRITE_ACCESS_PAGES);
                let page_locks = self
                    .shared
                    .page_access
                    .locks_for_range(start_page, page_count)?;
                let mut page_guards = heapless::Vec::<_, PAGE_ACCESS_LOCK_STRIPES>::new();
                for &index in &page_locks {
                    page_guards
                        .push(self.shared.page_access.acquire_by_index(index).await)
                        .map_err(|_| VfsError::StorageFull)?;
                }
                // Preserve the lock order: page access precedes the shared
                // side of io_lock. Each chunk releases both before the next
                // page range is acquired.
                let _io_guard = self.shared.io_lock.read().await;
                self.write_slice_at_locked_async(file, data, offset).await
            }
            // Atomic append already owns the exclusive side of io_lock, so no
            // page-access lock is needed or safe to acquire here.
            CachedWriteAccess::ExclusiveFileHeld => {
                self.write_slice_at_locked_async(file, data, offset).await
            }
        }
    }

    async fn write_slice_locked_async(
        &self,
        data: &[u8],
        offset: u64,
        access: CachedWriteAccess,
    ) -> VfsResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        checked_page_span(offset, data.len())?;
        let file = self.inner.entry().as_file()?;
        let mut written = 0usize;
        while written < data.len() {
            let chunk_len = (data.len() - written).min(WRITE_STAGING_SIZE);
            let current_offset = offset
                .checked_add(written as u64)
                .ok_or(VfsError::InvalidInput)?;
            let result = self
                .write_slice_chunk_with_access_async(
                    file,
                    &data[written..written + chunk_len],
                    current_offset,
                    access,
                )
                .await;
            match result {
                Ok(count) => written += count,
                Err(err) if written == 0 => return Err(err),
                Err(_) => break,
            }
        }
        Ok(written)
    }

    async fn write_at_locked_async(
        &self,
        mut buf: impl Read + IoBuf,
        offset: u64,
        access: CachedWriteAccess,
    ) -> VfsResult<usize> {
        let file = self.inner.entry().as_file()?;
        let total = buf.remaining();
        if total == 0 {
            return Ok(0);
        }
        checked_page_span(offset, total)?;

        let mut staging = alloc::vec![0; total.min(WRITE_STAGING_SIZE)];
        let mut written = 0usize;
        while written < total {
            let wanted = (total - written).min(staging.len());
            let read = match buf.read(&mut staging[..wanted]) {
                Ok(0) if written == 0 => return Err(VfsError::Io),
                Ok(0) => break,
                Ok(read) if read <= wanted => read,
                Ok(_) if written == 0 => return Err(VfsError::Io),
                Ok(_) => break,
                Err(err) if written == 0 => return Err(err.into()),
                Err(_) => break,
            };
            let current_offset = offset
                .checked_add(written as u64)
                .ok_or(VfsError::InvalidInput)?;
            let result = self
                .write_slice_chunk_with_access_async(file, &staging[..read], current_offset, access)
                .await;
            match result {
                Ok(count) => written += count,
                Err(err) if written == 0 => return Err(err),
                Err(_) => break,
            }
        }
        Ok(written)
    }

    pub async fn write_at_async(&self, buf: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        self.write_at_locked_async(buf, offset, CachedWriteAccess::PageRange)
            .await
    }

    pub async fn write_at_slice_async(&self, data: &[u8], offset: u64) -> VfsResult<usize> {
        self.write_slice_locked_async(data, offset, CachedWriteAccess::PageRange)
            .await
    }

    pub async fn append_async(&self, buf: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        let _guard = self.shared.io_lock.write().await;
        let len = self.shared.size();
        let written = self
            .write_at_locked_async(buf, len, CachedWriteAccess::ExclusiveFileHeld)
            .await?;
        let end = len
            .checked_add(written as u64)
            .ok_or(VfsError::InvalidInput)?;
        Ok((written, end))
    }

    pub async fn append_slice_async(&self, data: &[u8]) -> VfsResult<(usize, u64)> {
        let _guard = self.shared.io_lock.write().await;
        let len = self.shared.size();
        let written = self
            .write_slice_locked_async(data, len, CachedWriteAccess::ExclusiveFileHeld)
            .await?;
        let end = len
            .checked_add(written as u64)
            .ok_or(VfsError::InvalidInput)?;
        Ok((written, end))
    }

    pub async fn set_len_async(&self, len: u64) -> VfsResult<()> {
        let _guard = self.shared.io_lock.write().await;
        let file = self.inner.entry().as_file()?;
        let old_len = self.shared.size();
        if old_len == len {
            return Ok(());
        }

        file.set_len(len).await?;
        self.shared.cache_generation.fetch_add(1, Ordering::AcqRel);
        self.shared.set_size(len);

        let old_last_page = (old_len / PAGE_SIZE as u64) as u32;
        let new_last_page = (len / PAGE_SIZE as u64) as u32;
        if old_len < len {
            let mut cache = self.shared.page_cache.lock();
            if let Some(page) = cache.get_mut(&old_last_page) {
                let page_start = old_last_page as u64 * PAGE_SIZE as u64;
                let old_page_offset = (old_len - page_start) as usize;
                let new_page_offset = (len - page_start).min(PAGE_SIZE as u64) as usize;
                page.data()[old_page_offset..new_page_offset].fill(0);
                if !self.in_memory {
                    page.mark_dirty();
                }
            }
        } else {
            let keys = {
                let mut cache = self.shared.page_cache.lock();
                let tail = (len % PAGE_SIZE as u64) as usize;
                if tail != 0
                    && let Some(page) = cache.get_mut(&new_last_page)
                {
                    page.data()[tail..].fill(0);
                }
                let first_discarded_page = len.div_ceil(PAGE_SIZE as u64) as u32;
                cache
                    .iter()
                    .map(|(pn, _)| *pn)
                    .filter(|pn| *pn >= first_discarded_page)
                    .collect::<Vec<_>>()
            };
            self.shared
                .discard_pages_without_writeback_async(file, keys)
                .await?;
        }
        Ok(())
    }

    pub async fn sync_async(&self, data_only: bool) -> VfsResult<()> {
        if self.in_memory {
            return Ok(());
        }
        let _guard = self.shared.io_lock.write().await;
        let file = self.inner.entry().as_file()?;
        let cached_size = self.shared.size();
        if file.len().await? != cached_size {
            file.set_len(cached_size).await?;
        }
        self.shared.flush_dirty_pages_async(file).await?;
        file.sync(data_only).await
    }

    pub fn write_at(&self, buf: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        axtask::future::block_on(self.write_at_async(buf, offset))
    }

    pub fn append(&self, buf: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        axtask::future::block_on(self.append_async(buf))
    }

    pub fn set_len(&self, len: u64) -> VfsResult<()> {
        axtask::future::block_on(self.set_len_async(len))
    }

    pub fn sync(&self, data_only: bool) -> VfsResult<()> {
        axtask::future::block_on(self.sync_async(data_only))
    }

    /// Returns whether two handles refer to the same shared page cache.
    pub fn shares_page_cache_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
    }

    pub fn location(&self) -> &Location {
        &self.inner
    }

    /// Ensures that a page is resident without retaining any page-cache lock
    /// while the backing I/O future is pending.
    pub fn ensure_page_resident(&self, pn: u32) -> VfsResult<()> {
        let file = self.inner.entry().as_file()?;
        axtask::future::block_on(self.ensure_pages_async(file, pn, 1))
    }

    /// Pins a resident page for a user mapping without performing I/O.
    pub fn try_pin_shared_page_paddr(
        &self,
        pn: u32,
        may_write: bool,
    ) -> VfsResult<Option<PhysAddr>> {
        self.with_page(pn, |page| {
            let Some(page) = page else {
                return Ok(None);
            };
            page.pin_for_mapping(may_write).map(Some)
        })
    }

    /// Returns the physical address of the page at the given page index.
    ///
    /// If the page is not in the cache, it will be read from the file.
    pub fn get_shared_page_paddr(&self, pn: u32, may_write: bool) -> VfsResult<PhysAddr> {
        let file = self.inner.entry().as_file()?;
        axtask::future::block_on(self.ensure_pages_inner_async(file, pn, 1, Some(may_write)))?
            .ok_or(VfsError::BadState)
    }

    /// Faults in and pins a bounded run of pages for a user mapping.
    pub fn get_shared_page_paddrs(
        &self,
        pn: u32,
        page_count: usize,
        may_write: bool,
    ) -> VfsResult<SharedPagePaddrs> {
        let file = self.inner.entry().as_file()?;
        axtask::future::block_on(self.pin_pages_inner_async(file, pn, page_count, may_write))
    }

    /// Returns a resident page's physical address without adding a mapping pin.
    pub fn shared_page_paddr(&self, pn: u32) -> VfsResult<PhysAddr> {
        self.with_page(pn, |page| {
            page.map(|page| page.paddr()).ok_or(VfsError::BadState)
        })
    }

    pub fn mark_shared_page_writable(&self, pn: u32, paddr: PhysAddr) -> VfsResult<()> {
        self.with_page(pn, |page| {
            let page = page.ok_or(VfsError::BadState)?;
            if page.paddr() != paddr || !page.has_user_mapping() {
                return Err(VfsError::BadState);
            }
            page.writable_mapping_generation = page.writable_mapping_generation.wrapping_add(1);
            page.may_write_mapping = true;
            Ok(())
        })
    }

    /// Marks the page at the given page index as dirty.
    pub fn mark_page_dirty(&self, pn: u32) -> VfsResult<()> {
        self.with_page(pn, |page| match page {
            Some(page) => {
                if !self.in_memory {
                    page.mark_dirty();
                }
                Ok(())
            }
            None => Err(VfsError::BadState),
        })
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use axfs_ng_vfs::VfsError;

    use super::{
        super::{
            SHARED_PAGE_BATCH_CAPACITY, WEAK_STATE_SWEEP_BUDGET, WeakStateRegistry,
            checked_shared_page_count,
        },
        CachedFileShared, MAX_WRITE_ACCESS_PAGES, PAGE_ACCESS_LOCK_STRIPES, PAGE_SIZE,
        PageAccessDomain, WRITE_STAGING_SIZE, checked_dirty_page_range, checked_page_span,
    };

    #[test]
    fn shared_page_batch_count_is_bounded_before_pinning() {
        assert_eq!(checked_shared_page_count(0), Ok(1));
        assert_eq!(
            checked_shared_page_count(SHARED_PAGE_BATCH_CAPACITY),
            Ok(SHARED_PAGE_BATCH_CAPACITY)
        );
        assert_eq!(
            checked_shared_page_count(SHARED_PAGE_BATCH_CAPACITY + 1),
            Err(VfsError::StorageFull)
        );
    }

    #[test]
    fn concurrent_write_size_updates_never_shrink_the_cached_length() {
        let shared = CachedFileShared::new(true, 8192, None);
        shared.extend_size(4096);
        assert_eq!(shared.size(), 8192);
        shared.extend_size(16_384);
        assert_eq!(shared.size(), 16_384);
    }

    #[test]
    fn page_access_locks_are_file_scoped_and_striped() {
        let first_file = PageAccessDomain::default();
        let same_page = first_file.lock_for_page(7);
        let same_page_again = first_file.lock_for_page(7);
        assert!(core::ptr::eq(same_page, same_page_again));

        let same_page_guard = same_page.try_lock().unwrap();
        assert!(same_page_again.try_lock().is_none());

        let different_page = first_file.lock_for_page(8);
        assert!(!core::ptr::eq(same_page, different_page));
        let different_page_guard = different_page.try_lock().unwrap();

        let second_file = PageAccessDomain::default();
        let second_file_same_page = second_file.lock_for_page(7);
        assert!(!core::ptr::eq(same_page, second_file_same_page));
        let second_file_guard = second_file_same_page.try_lock().unwrap();

        drop((same_page_guard, different_page_guard, second_file_guard));
        assert!(same_page_again.try_lock().is_some());
    }

    #[test]
    fn write_page_lock_windows_are_bounded_and_validate_overflow() {
        assert_eq!(
            checked_page_span(0, WRITE_STAGING_SIZE),
            Ok((0, WRITE_STAGING_SIZE / PAGE_SIZE))
        );
        assert_eq!(
            checked_page_span((PAGE_SIZE - 1) as u64, WRITE_STAGING_SIZE),
            Ok((0, MAX_WRITE_ACCESS_PAGES))
        );

        let domain = PageAccessDomain::default();
        let locks = domain.locks_for_range(7, MAX_WRITE_ACCESS_PAGES).unwrap();
        assert_eq!(locks.len(), MAX_WRITE_ACCESS_PAGES);
        assert!(locks.windows(2).all(|pair| pair[0] < pair[1]));
        let all_stripes = domain
            .locks_for_range(7, PAGE_ACCESS_LOCK_STRIPES + 3)
            .unwrap();
        assert_eq!(all_stripes.len(), PAGE_ACCESS_LOCK_STRIPES);
        assert!(all_stripes.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(
            domain.locks_for_range(u32::MAX - 1, 3).map(drop),
            Err(VfsError::StorageFull)
        );
    }

    #[test]
    fn direct_read_dirty_ranges_cover_each_overlapping_page() {
        assert_eq!(checked_dirty_page_range(0, PAGE_SIZE), Ok((0, 1)));
        assert_eq!(
            checked_dirty_page_range((PAGE_SIZE - 1) as u64, 2),
            Ok((0, 2))
        );
        assert_eq!(
            checked_dirty_page_range(u64::MAX, 1),
            Err(VfsError::InvalidInput)
        );
    }

    #[test]
    fn weak_state_registry_sweep_has_a_fixed_budget() {
        let mut registry = WeakStateRegistry::<u32, usize>::default();
        for key in 0..(WEAK_STATE_SWEEP_BUDGET as u32 + 2) {
            let state = Arc::new(key as usize);
            registry.insert(key, &state);
        }

        registry.sweep_dead();
        assert_eq!(registry.states.len(), 2);
        registry.sweep_dead();
        assert!(registry.states.is_empty());
    }
}
