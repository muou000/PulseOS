use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(feature = "times")]
use core::sync::atomic::AtomicU8;
use core::{
    sync::atomic::{AtomicIsize, AtomicU64, AtomicUsize, Ordering},
    task::Context,
};

use axalloc::global_allocator;
use axerrno::LinuxError;
use axfs_ng_vfs::{
    FileNode, Location, Metadata, NodeFlags, NodePermission, NodeType, VfsError, VfsResult,
    path::Path,
};
use axhal::mem::{PhysAddr, VirtAddr, virt_to_phys};
use axio::{SeekFrom, prelude::*};
use axpoll::{IoEvents, Pollable};
use axsync::{Mutex, RwLock};
use lru::LruCache;
use spin::{Lazy, Mutex as SpinMutex};

use super::FsContext;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy)]
    pub struct FileFlags: u8 {
        const READ = 1;
        const WRITE = 2;
        const EXECUTE = 4;
        const APPEND = 8;
        const PATH = 16;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FileCacheKey {
    fs_id: usize,
    inode: u64,
}

fn filesystem_id(loc: &Location) -> usize {
    loc.filesystem() as *const dyn axfs_ng_vfs::FilesystemOps as *const () as usize
}

fn file_cache_key(loc: &Location) -> FileCacheKey {
    FileCacheKey {
        fs_id: filesystem_id(loc),
        inode: loc.inode(),
    }
}

fn node_allows_page_cache(flags: NodeFlags) -> bool {
    !flags.contains(NodeFlags::NON_CACHEABLE)
}

fn prune_file_shared_states(registry: &mut BTreeMap<FileCacheKey, Weak<CachedFileShared>>) {
    registry.retain(|_, state| state.strong_count() > 0);
}

pub fn invalidate_file_cache(fs_id: usize, inode: u64) {
    let key = FileCacheKey { fs_id, inode };
    let state = FILE_SHARED_STATES
        .lock()
        .remove(&key)
        .and_then(|state| state.upgrade());
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

static FILE_SHARED_STATES: Lazy<SpinMutex<BTreeMap<FileCacheKey, Weak<CachedFileShared>>>> =
    Lazy::new(|| SpinMutex::new(BTreeMap::new()));

// Disk caches survive descriptor close and are released after explicit global
// writeback. Stage 2 adds bounded retention and memory-pressure reclaim.
static ACTIVE_DISK_FILE_CACHES: Lazy<SpinMutex<Vec<Arc<CachedFileShared>>>> =
    Lazy::new(|| SpinMutex::new(Vec::new()));

struct InodeAccessState {
    count: AtomicIsize,
}

impl InodeAccessState {
    const fn new() -> Self {
        Self {
            count: AtomicIsize::new(0),
        }
    }

    fn acquire_write(self: &Arc<Self>) -> VfsResult<WriteAccessGuard> {
        let mut count = self.count.load(Ordering::Acquire);
        loop {
            if count < 0 {
                return Err(VfsError::from(LinuxError::ETXTBSY));
            }
            let next = count.checked_add(1).ok_or(VfsError::BadState)?;
            match self
                .count
                .compare_exchange_weak(count, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Ok(WriteAccessGuard {
                        _lease: Arc::new(WriteAccessLease {
                            state: self.clone(),
                        }),
                    });
                }
                Err(observed) => count = observed,
            }
        }
    }

    fn acquire_exec(self: &Arc<Self>) -> VfsResult<ExecAccessGuard> {
        let mut count = self.count.load(Ordering::Acquire);
        loop {
            if count > 0 {
                return Err(VfsError::from(LinuxError::ETXTBSY));
            }
            let next = count.checked_sub(1).ok_or(VfsError::BadState)?;
            match self
                .count
                .compare_exchange_weak(count, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => {
                    return Ok(ExecAccessGuard {
                        _lease: Arc::new(ExecAccessLease {
                            state: self.clone(),
                        }),
                    });
                }
                Err(observed) => count = observed,
            }
        }
    }
}

struct WriteAccessLease {
    state: Arc<InodeAccessState>,
}

impl Drop for WriteAccessLease {
    fn drop(&mut self) {
        let previous = self.state.count.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0);
    }
}

#[derive(Clone)]
pub struct WriteAccessGuard {
    _lease: Arc<WriteAccessLease>,
}

struct ExecAccessLease {
    state: Arc<InodeAccessState>,
}

impl Drop for ExecAccessLease {
    fn drop(&mut self) {
        let previous = self.state.count.fetch_add(1, Ordering::AcqRel);
        debug_assert!(previous < 0);
    }
}

#[derive(Clone)]
pub struct ExecAccessGuard {
    _lease: Arc<ExecAccessLease>,
}

static INODE_ACCESS_STATES: Lazy<SpinMutex<BTreeMap<FileCacheKey, Weak<InodeAccessState>>>> =
    Lazy::new(|| SpinMutex::new(BTreeMap::new()));

fn inode_access_state(location: &Location) -> Arc<InodeAccessState> {
    let key = file_cache_key(location);
    let mut registry = INODE_ACCESS_STATES.lock();
    if let Some(state) = registry.get(&key).and_then(Weak::upgrade) {
        return state;
    }
    registry.retain(|_, state| state.strong_count() > 0);
    let state = Arc::new(InodeAccessState::new());
    registry.insert(key, Arc::downgrade(&state));
    state
}

pub fn acquire_exec_access(location: &Location) -> VfsResult<ExecAccessGuard> {
    inode_access_state(location).acquire_exec()
}

fn acquire_write_access(location: &Location) -> VfsResult<WriteAccessGuard> {
    inode_access_state(location).acquire_write()
}

/// Results returned by [`OpenOptions::open`].
pub enum OpenResult {
    File(File),
    Dir(Location),
}

impl OpenResult {
    pub fn into_file(self) -> VfsResult<File> {
        match self {
            Self::File(file) => Ok(file),
            Self::Dir(_) => Err(VfsError::IsADirectory),
        }
    }

    pub fn into_dir(self) -> VfsResult<Location> {
        match self {
            Self::Dir(dir) => Ok(dir),
            Self::File(_) => Err(VfsError::NotADirectory),
        }
    }

    pub fn into_location(self) -> Location {
        match self {
            Self::File(file) => file.location().clone(),
            Self::Dir(dir) => dir,
        }
    }
}

/// Options and flags which can be used to configure how a file is opened.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    // generic
    read: bool,
    write: bool,
    append: bool,
    truncate: bool,
    create: bool,
    create_new: bool,
    directory: bool,
    no_follow: bool,
    direct: bool,
    user: Option<(u32, u32)>,
    path: bool,
    node_type: NodeType,
    // system-specific
    mode: u32,
}

impl OpenOptions {
    /// Creates a blank new set of options ready for configuration.
    pub fn new() -> Self {
        Self {
            // generic
            read: false,
            write: false,
            append: false,
            truncate: false,
            create: false,
            create_new: false,
            directory: false,
            no_follow: false,
            direct: false,
            user: None,
            path: false,
            node_type: NodeType::RegularFile,
            // system-specific
            mode: 0o666,
        }
    }

    /// Sets the option for read access.
    pub fn read(&mut self, read: bool) -> &mut Self {
        self.read = read;
        self
    }

    /// Sets the option for write access.
    pub fn write(&mut self, write: bool) -> &mut Self {
        self.write = write;
        self
    }

    /// Sets the option for the append mode.
    pub fn append(&mut self, append: bool) -> &mut Self {
        self.append = append;
        self
    }

    /// Sets the option for truncating a previous file.
    pub fn truncate(&mut self, truncate: bool) -> &mut Self {
        self.truncate = truncate;
        self
    }

    /// Sets the option to create a new file, or open it if it already exists.
    pub fn create(&mut self, create: bool) -> &mut Self {
        self.create = create;
        self
    }

    /// Sets the option to create a new file, failing if it already exists.
    pub fn create_new(&mut self, create_new: bool) -> &mut Self {
        self.create_new = create_new;
        self
    }

    /// Sets the option to open directory instead.
    pub fn directory(&mut self, directory: bool) -> &mut Self {
        self.directory = directory;
        self
    }

    /// Sets the option to not follow symlinks.
    pub fn no_follow(&mut self, no_follow: bool) -> &mut Self {
        self.no_follow = no_follow;
        self
    }

    /// Sets the option to open the file with direct I/O.\
    pub fn direct(&mut self, direct: bool) -> &mut Self {
        self.direct = direct;
        self
    }

    /// Sets the user and group id to open the file with.
    pub fn user(&mut self, uid: u32, gid: u32) -> &mut Self {
        self.user = Some((uid, gid));
        self
    }

    /// Sets the option for path only access.
    pub fn path(&mut self, path: bool) -> &mut Self {
        self.path = path;
        self
    }

    /// Sets the node type for the file.
    ///
    /// This will only be used if the file is created.
    pub fn node_type(&mut self, node_type: NodeType) -> &mut Self {
        self.node_type = node_type;
        self
    }

    /// Sets the mode bits that a new file will be created with.
    pub fn mode(&mut self, mode: u32) -> &mut Self {
        self.mode = mode;
        self
    }

    async fn _open(&self, loc: Location) -> VfsResult<(OpenResult, Metadata)> {
        let flags = self.to_flags()?;

        if loc.is_dir() && (self.create_new || flags.contains(FileFlags::WRITE)) {
            return Err(VfsError::IsADirectory);
        }

        if self.directory {
            if flags.contains(FileFlags::WRITE) {
                return Err(VfsError::IsADirectory);
            }
            loc.check_is_dir()?;
        }
        if (flags.intersects(FileFlags::WRITE | FileFlags::APPEND) || self.truncate)
            && loc.mountpoint().is_readonly()
            && !flags.contains(FileFlags::PATH)
        {
            return Err(VfsError::ReadOnlyFilesystem);
        }

        let metadata = loc.metadata().await?;
        let write_access = if metadata.node_type == NodeType::RegularFile
            && flags.intersects(FileFlags::WRITE | FileFlags::APPEND)
            && !flags.contains(FileFlags::PATH)
        {
            Some(acquire_write_access(&loc)?)
        } else {
            None
        };
        let opened = if loc.is_dir() {
            OpenResult::Dir(loc)
        } else {
            // TODO(mivik): is this correct?
            let non_cacheable_type = matches!(
                metadata.node_type,
                NodeType::CharacterDevice
                    | NodeType::BlockDevice
                    | NodeType::Fifo
                    | NodeType::Socket
            );

            let node_flags = loc.flags();
            let direct = non_cacheable_type
                || self.path
                || self.direct
                || !node_allows_page_cache(node_flags);

            let backend = if node_allows_page_cache(node_flags)
                && (!direct || node_flags.contains(NodeFlags::ALWAYS_CACHE))
            {
                FileBackend::new_cached(loc)?
            } else {
                FileBackend::new_direct(loc)
            };
            if self.truncate && metadata.node_type == NodeType::RegularFile {
                backend.set_len(0).await?;
            }
            OpenResult::File(File::new(backend, flags, write_access))
        };
        Ok((opened, metadata))
    }

    pub async fn open_loc(&self, loc: Location) -> VfsResult<OpenResult> {
        if !self.is_valid() {
            return Err(VfsError::InvalidInput);
        }
        self._open(loc).await.map(|(opened, _)| opened)
    }

    pub async fn open(&self, context: &FsContext, path: impl AsRef<Path>) -> VfsResult<OpenResult> {
        self.open_with_metadata(context, path)
            .await
            .map(|(opened, _)| opened)
    }

    /// Opens a path and returns the metadata snapshot used to select and
    /// configure its file backend.
    pub async fn open_with_metadata(
        &self,
        context: &FsContext,
        path: impl AsRef<Path>,
    ) -> VfsResult<(OpenResult, Metadata)> {
        if !self.is_valid() {
            return Err(VfsError::InvalidInput);
        }

        let loc = match context.resolve_parent(path.as_ref()).await {
            Ok((parent, name)) => {
                let create_options = axfs_ng_vfs::OpenOptions {
                    create: self.create,
                    create_new: self.create_new,
                    node_type: self.node_type,
                    permission: NodePermission::from_bits_truncate(self.mode as _),
                    user: self.user.or(context.credentials),
                };
                let mut loc =
                    if (self.create || self.create_new) && parent.mountpoint().is_readonly() {
                        let existing = parent
                            .open_file(&name, &axfs_ng_vfs::OpenOptions::default())
                            .await
                            .map_err(|err| {
                                if err.canonicalize() == VfsError::NotFound {
                                    VfsError::ReadOnlyFilesystem
                                } else {
                                    err
                                }
                            })?;
                        if self.create_new {
                            return Err(VfsError::AlreadyExists);
                        }
                        existing
                    } else {
                        parent.open_file(&name, &create_options).await?
                    };
                if !self.no_follow {
                    loc = context
                        .with_current_dir(parent)?
                        .try_resolve_symlink(loc, &mut 0)
                        .await?;
                }
                loc
            }
            Err(VfsError::InvalidInput) => {
                // root directory
                context.root_dir().clone()
            }
            Err(err) => return Err(err),
        };
        self._open(loc).await
    }

    pub(crate) fn to_flags(&self) -> VfsResult<FileFlags> {
        Ok(match (self.read, self.write, self.append) {
            (true, false, false) => FileFlags::READ,
            (false, true, false) => FileFlags::WRITE,
            (true, true, false) => FileFlags::READ | FileFlags::WRITE,
            (false, _, true) => FileFlags::WRITE | FileFlags::APPEND,
            (true, _, true) => FileFlags::READ | FileFlags::WRITE | FileFlags::APPEND,
            (false, false, false) => return Err(VfsError::InvalidInput),
        } | if self.path {
            FileFlags::PATH
        } else {
            FileFlags::empty()
        })
    }

    pub(crate) fn is_valid(&self) -> bool {
        if !self.read && !self.write && !self.append {
            return true;
        }
        match (self.write, self.append) {
            (true, false) => {}
            (false, false) => {
                if self.truncate {
                    return false;
                }
            }
            (_, true) => {
                if self.truncate && !self.create_new {
                    return false;
                }
            }
        }
        true
    }
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self::new()
    }
}

const PAGE_SIZE: usize = 4096;
const MAX_WRITEBACK_PAGES: usize = 256;
const READ_AHEAD_PAGES: usize = 16;
const DISK_FILE_CACHE_SOFT_LIMIT: usize = 1024;
const PAGE_CACHE_GROWTH_HEADROOM: usize = 256;
const PAGE_CACHE_EVICTION_BATCH: usize = 256;
const PAGE_CACHE_SCAN_MULTIPLIER: usize = 4;
const PAGE_CACHE_MIN_SCAN: usize = 64;
const PAGE_CACHE_RECLAIM_LOG_INTERVAL: usize = 4096;
const PAGE_FILL_LOCK_STRIPES: usize = 256;

static PAGE_FILL_LOCKS: Lazy<Vec<async_lock::Mutex<()>>> = Lazy::new(|| {
    (0..PAGE_FILL_LOCK_STRIPES)
        .map(|_| async_lock::Mutex::new(()))
        .collect()
});

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

#[derive(Debug)]
pub struct PageCache {
    addr: VirtAddr,
    dirty: bool,
    may_write_mapping: bool,
}

impl PageCache {
    fn new(skip_zero: bool) -> VfsResult<Self> {
        let addr = global_allocator()
            .alloc_pages(1, PAGE_SIZE)
            .inspect_err(|err| {
                warn!("Failed to allocate page cache: {:?}", err);
            })
            .map_err(|_| VfsError::NoMemory)?;
        if !skip_zero {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE) };
        }
        Ok(Self {
            addr: addr.into(),
            dirty: false,
            may_write_mapping: false,
        })
    }

    pub fn paddr(&self) -> PhysAddr {
        virt_to_phys(self.addr)
    }

    pub fn mark_dirty(&mut self) {
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
        self.may_write_mapping |= may_write;
        if ref_count == 0 {
            axalloc::frame_table().mark_used(paddr);
        }
        axalloc::frame_table().inc_ref(paddr);
        Ok(paddr)
    }

    pub fn data(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.addr.as_mut_ptr(), PAGE_SIZE) }
    }
}

impl Drop for PageCache {
    fn drop(&mut self) {
        if self.dirty {
            warn!("dirty page dropped without flushing");
        }
        let paddr = self.paddr();
        if let Some(ref_count) = axalloc::frame_table().try_get_ref(paddr) {
            if ref_count == 0 {
                global_allocator().dealloc_pages(self.addr.as_usize(), 1);
            } else {
                if axalloc::frame_table().dec_ref(paddr) == 0 {
                    global_allocator().dealloc_pages(self.addr.as_usize(), 1);
                }
            }
        } else {
            global_allocator().dealloc_pages(self.addr.as_usize(), 1);
        }
    }
}

struct EvictListener {
    listener: Box<dyn Fn(u32, &PageCache) + Send + Sync>,
}

struct CachedFileShared {
    page_cache: Mutex<LruCache<u32, PageCache>>,
    cache_soft_limit: AtomicUsize,
    evict_listeners: Mutex<Vec<Arc<EvictListener>>>,
    backing: Option<FileNode>,
    io_lock: RwLock<()>,
    size: SpinMutex<u64>,
    cache_generation: AtomicU64,
}

impl CachedFileShared {
    fn new(in_memory: bool, size: u64, backing: Option<FileNode>) -> Self {
        Self {
            // The LRU's own capacity eagerly reserves hash-table metadata.
            // Keep storage lazy and enforce the disk limit during admission.
            page_cache: Mutex::new(LruCache::unbounded()),
            cache_soft_limit: AtomicUsize::new(if in_memory {
                usize::MAX
            } else {
                DISK_FILE_CACHE_SOFT_LIMIT
            }),
            evict_listeners: Mutex::new(Vec::new()),
            backing,
            io_lock: RwLock::new(()),
            size: SpinMutex::new(size),
            cache_generation: AtomicU64::new(0),
        }
    }

    fn page_fill_lock_index(&self, pn: u32) -> usize {
        let file_hash = (self as *const Self as usize).rotate_right(6);
        (file_hash ^ pn as usize) % PAGE_FILL_LOCK_STRIPES
    }

    fn page_fill_lock_indices(&self, pn: u32, page_count: usize) -> VfsResult<Vec<usize>> {
        let mut indices = Vec::with_capacity(page_count);
        for offset in 0..page_count {
            let offset = u32::try_from(offset).map_err(|_| VfsError::StorageFull)?;
            let page_num = pn.checked_add(offset).ok_or(VfsError::StorageFull)?;
            indices.push(self.page_fill_lock_index(page_num));
        }
        indices.sort_unstable();
        indices.dedup();
        Ok(indices)
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
            if !page.dirty && !page.has_user_mapping() {
                if let Some(entry) = cache.pop_lru() {
                    evicted.push(entry);
                }
            } else {
                cache.promote(&pn);
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
        let Some(listeners) = self.evict_listeners.try_lock() else {
            return 0;
        };
        if !listeners.is_empty() {
            return 0;
        }
        let Some(mut cache) = self.page_cache.try_lock() else {
            return 0;
        };
        let scan_limit = cache.len().min(
            limit
                .saturating_mul(PAGE_CACHE_SCAN_MULTIPLIER)
                .max(PAGE_CACHE_MIN_SCAN),
        );
        let mut evicted = 0;
        let mut scanned = 0;
        while evicted < limit && scanned < scan_limit {
            let Some((&pn, page)) = cache.peek_lru() else {
                break;
            };
            if !page.dirty && !page.has_user_mapping() {
                let page = cache.pop_lru().unwrap().1;
                drop(page);
                evicted += 1;
            } else {
                cache.promote(&pn);
            }
            scanned += 1;
        }
        evicted
    }

    fn evict_cache(&self, file: &FileNode, pn: u32, page: &mut PageCache) -> VfsResult<()> {
        let listeners = self.evict_listeners_snapshot();
        for listener in listeners.iter() {
            (listener.listener)(pn, page);
        }
        if page.dirty {
            let cached_size = *self.size.lock();
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let len = (cached_size.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
            if len > 0 {
                write_all_at(
                    |data, offset| axtask::future::block_on(file.write_at(data, offset)),
                    &page.data()[..len],
                    page_start,
                )?;
            }
            page.dirty = false;
        }
        Ok(())
    }

    fn flush_dirty_pages_locked(
        file_len: u64,
        file: &FileNode,
        guard: &mut LruCache<u32, PageCache>,
    ) -> VfsResult<()> {
        for (_, page) in guard.iter_mut() {
            if page.may_write_mapping && page.has_user_mapping() {
                page.mark_dirty();
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
                for k in i..=j {
                    let pn_curr = dirty_pns[k];
                    if let Some(page) = guard.get_mut(&pn_curr) {
                        let curr_page_start = pn_curr as u64 * PAGE_SIZE as u64;
                        let curr_len = (file_len.saturating_sub(curr_page_start))
                            .min(PAGE_SIZE as u64) as usize;
                        merged_buf.extend_from_slice(&page.data()[..curr_len]);
                    }
                }

                write_all_at(
                    |data, offset| axtask::future::block_on(file.write_at(data, offset)),
                    &merged_buf,
                    page_start,
                )?;
                for k in i..=j {
                    if let Some(page) = guard.get_mut(&dirty_pns[k]) {
                        page.dirty = false;
                    }
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

    fn flush_dirty_pages(&self, file: &FileNode) -> VfsResult<()> {
        let file_len = *self.size.lock();
        if axtask::future::block_on(file.len())? < file_len {
            axtask::future::block_on(file.set_len(file_len))?;
        }
        {
            let mut guard = self.page_cache.lock();
            for (_, page) in guard.iter_mut() {
                if page.may_write_mapping && page.has_user_mapping() {
                    page.mark_dirty();
                }
            }
        }

        loop {
            let (dirty_pns, page_start, data) = {
                let mut guard = self.page_cache.lock();
                let mut dirty_pns = guard
                    .iter()
                    .filter(|(_, page)| page.dirty)
                    .map(|(pn, _)| *pn)
                    .collect::<Vec<_>>();
                dirty_pns.sort_unstable();
                let Some(&pn_start) = dirty_pns.first() else {
                    return Ok(());
                };
                let mut count = 1usize;
                while count < dirty_pns.len()
                    && count < MAX_WRITEBACK_PAGES
                    && dirty_pns[count] == pn_start + count as u32
                {
                    count += 1;
                }
                dirty_pns.truncate(count);

                let pn_end = *dirty_pns.last().unwrap();
                let page_start = pn_start as u64 * PAGE_SIZE as u64;
                let last_page_start = pn_end as u64 * PAGE_SIZE as u64;
                let last_len = file_len
                    .saturating_sub(last_page_start)
                    .min(PAGE_SIZE as u64) as usize;
                let mut data = Vec::new();
                if last_len != 0 {
                    let total_len = (pn_end - pn_start) as usize * PAGE_SIZE + last_len;
                    data.reserve(total_len);
                    for &pn in &dirty_pns {
                        let page = guard.get_mut(&pn).ok_or(VfsError::Io)?;
                        let curr_page_start = pn as u64 * PAGE_SIZE as u64;
                        let curr_len = file_len
                            .saturating_sub(curr_page_start)
                            .min(PAGE_SIZE as u64) as usize;
                        data.extend_from_slice(&page.data()[..curr_len]);
                        page.dirty = false;
                    }
                } else {
                    for &pn in &dirty_pns {
                        if let Some(page) = guard.get_mut(&pn) {
                            page.dirty = false;
                        }
                    }
                }
                (dirty_pns, page_start, data)
            };

            if data.is_empty() {
                continue;
            }
            let result = write_all_at(
                |data, offset| axtask::future::block_on(file.write_at(data, offset)),
                &data,
                page_start,
            );
            if let Err(err) = result {
                let mut guard = self.page_cache.lock();
                for pn in dirty_pns {
                    if let Some(page) = guard.get_mut(&pn) {
                        page.dirty = true;
                    }
                }
                return Err(err);
            }
        }
    }

    fn reload_page(file: &FileNode, pn: u32, page: &mut PageCache) -> VfsResult<()> {
        let read =
            axtask::future::block_on(file.read_at(page.data(), pn as u64 * PAGE_SIZE as u64))?;
        if read < PAGE_SIZE {
            page.data()[read..].fill(0);
        }
        page.dirty = false;
        Ok(())
    }

    #[allow(dead_code)]
    fn discard_pages(
        &self,
        file: &FileNode,
        keys: Vec<u32>,
        write_back_dirty: bool,
    ) -> VfsResult<()> {
        let mut guard = self.page_cache.lock();
        for pn in keys {
            if let Some(page) = guard.get_mut(&pn)
                && page.has_user_mapping()
            {
                if page.dirty && write_back_dirty {
                    self.evict_cache(file, pn, page)?;
                } else if !write_back_dirty {
                    Self::reload_page(file, pn, page)?;
                }
                continue;
            }
            let Some(mut page) = guard.pop(&pn) else {
                continue;
            };

            if page.dirty && write_back_dirty {
                if let Err(err) = self.evict_cache(file, pn, &mut page) {
                    guard.put(pn, page);
                    return Err(err);
                }
            } else {
                let listeners = self.evict_listeners_snapshot();
                for listener in listeners.iter() {
                    (listener.listener)(pn, &page);
                }
                page.dirty = false;
            }
        }
        Ok(())
    }

    fn discard_all_pages(&self, file: &FileNode, write_back_dirty: bool) -> VfsResult<()> {
        // Callers hold the exclusive I/O lock. In-flight cache fills use this
        // generation to reject data read before the invalidation.
        self.cache_generation.fetch_add(1, Ordering::AcqRel);
        let mut guard = self.page_cache.lock();
        let keys = guard.iter().map(|(pn, _)| *pn).collect::<Vec<_>>();
        for pn in keys {
            if let Some(page) = guard.get_mut(&pn)
                && page.has_user_mapping()
            {
                if page.dirty && write_back_dirty {
                    self.evict_cache(file, pn, page)?;
                } else if !write_back_dirty {
                    Self::reload_page(file, pn, page)?;
                }
                continue;
            }
            let Some(mut page) = guard.pop(&pn) else {
                continue;
            };
            if page.dirty && write_back_dirty {
                if let Err(err) = self.evict_cache(file, pn, &mut page) {
                    guard.put(pn, page);
                    return Err(err);
                }
            } else {
                let listeners = self.evict_listeners_snapshot();
                for listener in listeners.iter() {
                    (listener.listener)(pn, &page);
                }
                page.dirty = false;
            }
        }
        Ok(())
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

pub(crate) fn flush_all_file_caches() -> VfsResult<()> {
    let states = ACTIVE_DISK_FILE_CACHES.lock().clone();

    let mut first_error = None;
    for state in states {
        let Some(file) = state.backing.as_ref() else {
            continue;
        };
        let result = {
            let _guard = state.io_lock.write();
            let cached_size = *state.size.lock();
            (|| {
                if axtask::future::block_on(file.len())? != cached_size {
                    axtask::future::block_on(file.set_len(cached_size))?;
                }
                state.flush_dirty_pages(file)
            })()
        };
        if let Err(err) = result {
            error!("Failed to flush cached inode {}: {:?}", file.inode(), err);
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

const NO_RECLAIM_OWNER: usize = usize::MAX;

struct ReclaimGuard;
impl Drop for ReclaimGuard {
    fn drop(&mut self) {
        PAGE_CACHE_RECLAIM_OWNER.store(NO_RECLAIM_OWNER, Ordering::Release);
    }
}

static PAGE_CACHE_RECLAIM_OWNER: AtomicUsize = AtomicUsize::new(NO_RECLAIM_OWNER);
static PAGE_CACHE_RECLAIMED_TOTAL: AtomicUsize = AtomicUsize::new(0);
static PAGE_CACHE_RECLAIM_ZERO_STREAK: AtomicUsize = AtomicUsize::new(0);
static PAGE_CACHE_RECLAIM_CURSOR: AtomicUsize = AtomicUsize::new(0);

fn page_cache_reclaim_inner(num_pages: usize) -> usize {
    if num_pages == 0 {
        return 0;
    }

    let mut reclaimed = 0;
    let mut file_count = 0;

    let Some(caches) = ACTIVE_DISK_FILE_CACHES.try_lock() else {
        return 0;
    };

    let cache_count = caches.len();
    if cache_count == 0 {
        return 0;
    }
    let start = PAGE_CACHE_RECLAIM_CURSOR.fetch_add(1, Ordering::Relaxed) % cache_count;
    for offset in 0..cache_count {
        let file = &caches[(start + offset) % cache_count];
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
    let reclaimed_before = PAGE_CACHE_RECLAIMED_TOTAL.load(Ordering::Acquire);
    match PAGE_CACHE_RECLAIM_OWNER.compare_exchange(
        NO_RECLAIM_OWNER,
        cpu_id,
        Ordering::AcqRel,
        Ordering::Acquire,
    ) {
        Ok(_) => {}
        // Re-entry on the owner CPU must not spin waiting for itself.
        Err(owner) if owner == cpu_id => return 0,
        Err(_) => {
            while PAGE_CACHE_RECLAIM_OWNER.load(Ordering::Acquire) != NO_RECLAIM_OWNER {
                core::hint::spin_loop();
            }
            return PAGE_CACHE_RECLAIMED_TOTAL
                .load(Ordering::Acquire)
                .wrapping_sub(reclaimed_before);
        }
    }

    let _guard = ReclaimGuard;
    let reclaimed = page_cache_reclaim_inner(num_pages);
    if reclaimed > 0 {
        PAGE_CACHE_RECLAIM_ZERO_STREAK.store(0, Ordering::Relaxed);
        let previous = PAGE_CACHE_RECLAIMED_TOTAL.fetch_add(reclaimed, Ordering::Release);
        let total = previous.wrapping_add(reclaimed);
        if previous == 0
            || previous / PAGE_CACHE_RECLAIM_LOG_INTERVAL
                != total / PAGE_CACHE_RECLAIM_LOG_INTERVAL
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
                "page_cache_reclaim_stalled: streak={} requested_pages={} active_caches={} available_pages={}",
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

fn shared_file_state(location: &Location) -> VfsResult<Arc<CachedFileShared>> {
    if !node_allows_page_cache(location.flags()) {
        return Err(VfsError::OperationNotSupported);
    }

    let key = file_cache_key(location);
    let in_memory = location.filesystem().name() == "tmpfs";

    {
        let registry = FILE_SHARED_STATES.lock();
        if let Some(state) = registry.get(&key).and_then(Weak::upgrade) {
            return Ok(state);
        }
    }

    let size = axtask::future::block_on(location.len()).unwrap_or(0);
    let backing = if in_memory {
        None
    } else {
        location.entry().as_file().ok().cloned()
    };
    let state = Arc::new(CachedFileShared::new(in_memory, size, backing));

    let mut registry = FILE_SHARED_STATES.lock();
    if let Some(existing_state) = registry.get(&key).and_then(Weak::upgrade) {
        drop(registry);
        drop(state);
        return Ok(existing_state);
    }
    prune_file_shared_states(&mut registry);
    registry.insert(key, Arc::downgrade(&state));
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
    FILE_SHARED_STATES
        .lock()
        .get(&key)
        .and_then(Weak::upgrade)
        .map(|state| *state.size.lock())
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
    pub fn get_or_create(location: Location) -> VfsResult<Self> {
        if !node_allows_page_cache(location.flags()) {
            return Err(VfsError::OperationNotSupported);
        }

        let in_memory = location.filesystem().name() == "tmpfs";
        let mut guard = location.user_data();
        let shared = if let Some(user_data) = guard.get::<FileUserData>() {
            user_data.get()
        } else {
            let shared = shared_file_state(&location)?;
            guard.insert(FileUserData::Strong(shared.clone()));
            shared
        };
        drop(guard);

        Ok(Self {
            inner: location,
            shared,
            in_memory,
            read_hint: Arc::new(AtomicU64::new(u64::MAX)),
        })
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.shared, &other.shared)
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
            let cached_size = *self.shared.size.lock();
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let len = (cached_size.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
            if len > 0 {
                axtask::future::block_on(file.write_at(&page.data()[..len], page_start))?;
            }
            page.dirty = false;
        }
        Ok(())
    }

    fn flush_dirty_pages(&self, file: &FileNode) -> VfsResult<()> {
        self.shared.flush_dirty_pages(file)
    }

    fn discard_pages(
        &self,
        file: &FileNode,
        keys: Vec<u32>,
        write_back_dirty: bool,
    ) -> VfsResult<()> {
        let mut guard = self.shared.page_cache.lock();
        for pn in keys {
            let Some(mut page) = guard.pop(&pn) else {
                continue;
            };
            if page.dirty && write_back_dirty {
                if let Err(err) = self.evict_cache(file, pn, &mut page) {
                    guard.put(pn, page);
                    return Err(err);
                }
            } else {
                let listeners = self.shared.evict_listeners_snapshot();
                for listener in listeners.iter() {
                    (listener.listener)(pn, &page);
                }
                page.dirty = false;
            }
        }
        Ok(())
    }

    fn page_or_insert<'a>(
        &self,
        file: &FileNode,
        cache: &'a mut LruCache<u32, PageCache>,
        pn: u32,
        mut skip_read: bool,
        file_len: u64,
    ) -> VfsResult<(&'a mut PageCache, Option<(u32, PageCache)>)> {
        // TODO: Matching the result of `get_mut` confuses compiler. See
        // https://users.rust-lang.org/t/return-do-not-release-mutable-borrow/55757.
        if cache.contains(&pn) {
            return Ok((cache.get_mut(&pn).unwrap(), None));
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
            let read_len =
                axtask::future::block_on(file.read_at(page.data(), pn as u64 * PAGE_SIZE as u64))?;
            if read_len < PAGE_SIZE {
                page.data()[read_len..].fill(0);
            }
        }
        cache.put(pn, page);
        Ok((cache.get_mut(&pn).unwrap(), evicted))
    }

    fn pin_cached_pages(
        cache: &mut LruCache<u32, PageCache>,
        pn: u32,
        page_count: usize,
        may_write: bool,
    ) -> VfsResult<Option<Vec<(u32, PhysAddr)>>> {
        let mut page_numbers = Vec::with_capacity(page_count);
        for offset in 0..page_count {
            let offset = u32::try_from(offset).map_err(|_| VfsError::StorageFull)?;
            let page_num = pn.checked_add(offset).ok_or(VfsError::StorageFull)?;
            if !cache.contains(&page_num) {
                return Ok(None);
            }
            page_numbers.push(page_num);
        }

        let mut pinned = Vec::with_capacity(page_count);
        for page_num in page_numbers {
            let result = cache
                .get_mut(&page_num)
                .ok_or(VfsError::BadState)
                .and_then(|page| page.pin_for_mapping(may_write));
            match result {
                Ok(paddr) => pinned.push((page_num, paddr)),
                Err(err) => {
                    for (_, paddr) in pinned.drain(..) {
                        let refs = axalloc::frame_table().dec_ref(paddr);
                        debug_assert_ne!(refs, 0);
                    }
                    return Err(err);
                }
            }
        }
        Ok(Some(pinned))
    }

    fn pin_resident_pages(
        &self,
        pn: u32,
        page_count: usize,
        may_write: bool,
    ) -> VfsResult<Option<Vec<(u32, PhysAddr)>>> {
        let _io_guard = self.shared.io_lock.read();
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

        if page_count == 1 {
            // A single-page fault can read directly into its final page. This
            // avoids allocating, zeroing, and copying through a temporary Vec.
            let will_read = !self.in_memory && bytes_available != 0;
            let mut page = PageCache::new(will_read)?;
            if will_read {
                let wanted = bytes_available.min(PAGE_SIZE as u64) as usize;
                let read = file.read_at(&mut page.data()[..wanted], page_start).await?;
                if read > wanted {
                    return Err(VfsError::Io);
                }
                page.data()[read..].fill(0);
            }
            return Ok(alloc::vec![(pn, page)]);
        }

        let buffer_len = page_count
            .checked_mul(PAGE_SIZE)
            .ok_or(VfsError::StorageFull)?;
        let mut data = alloc::vec![0; buffer_len];
        if !self.in_memory && bytes_available != 0 {
            let wanted = bytes_available.min(buffer_len as u64) as usize;
            let read = file.read_at(&mut data[..wanted], page_start).await?;
            if read > wanted {
                return Err(VfsError::Io);
            }
        }

        let mut pages = Vec::with_capacity(page_count);
        for page_offset in 0..page_count {
            let page_num = pn
                .checked_add(u32::try_from(page_offset).map_err(|_| VfsError::StorageFull)?)
                .ok_or(VfsError::StorageFull)?;
            let mut page = PageCache::new(true)?;
            let start = page_offset * PAGE_SIZE;
            page.data().copy_from_slice(&data[start..start + PAGE_SIZE]);
            pages.push((page_num, page));
        }
        Ok(pages)
    }

    async fn ensure_pages_loaded_async(
        &self,
        file: &FileNode,
        pn: u32,
        requested_pages: usize,
        pin: Option<bool>,
    ) -> VfsResult<(usize, Option<Vec<(u32, PhysAddr)>>)> {
        let requested_pages = requested_pages.max(1);
        let lock_indices = self.shared.page_fill_lock_indices(pn, requested_pages)?;
        let mut fill_guards = Vec::with_capacity(lock_indices.len());
        for index in lock_indices {
            fill_guards.push(PAGE_FILL_LOCKS[index].lock().await);
        }

        loop {
            let (generation, file_len, page_count, first_missing, resident_pins) = {
                let _io_guard = self.shared.io_lock.read();
                let mut cache = self.shared.page_cache.lock();
                let file_len = *self.shared.size.lock();
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
            let mut new_pages = self
                .load_pages_async(
                    file,
                    first_missing_page,
                    page_count - first_missing_offset,
                    file_len,
                )
                .await?;

            // Direct writes hold the exclusive side while changing the backend
            // and invalidating the cache. Validate and publish under the shared
            // side so a stale fill can never be inserted after that invalidation.
            let io_guard = self.shared.io_lock.read();
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
                Some(
                    Self::pin_cached_pages(&mut cache, pn, page_count, may_write)?
                        .ok_or(VfsError::BadState)?,
                )
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
            for (evicted_pn, page) in &evicted_pages {
                for listener in listeners.as_ref().unwrap().iter() {
                    (listener.listener)(*evicted_pn, page);
                }
            }
            drop(evicted_pages);
            return Ok((page_count, pinned_pages));
        }
    }

    async fn pin_pages_inner_async(
        &self,
        file: &FileNode,
        pn: u32,
        requested_pages: usize,
        may_write: bool,
    ) -> VfsResult<Vec<(u32, PhysAddr)>> {
        if let Some(pages) = self.pin_resident_pages(pn, requested_pages.max(1), may_write)? {
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
        let _guard = self.shared.io_lock.read();
        f(self.shared.page_cache.lock().get_mut(&pn))
    }

    pub fn with_page_or_insert<R>(
        &self,
        pn: u32,
        f: impl FnOnce(&mut PageCache, Option<(u32, PageCache)>) -> VfsResult<R>,
    ) -> VfsResult<R> {
        let io_guard = self.shared.io_lock.write();
        let file_len = *self.shared.size.lock();
        let mut guard = self.shared.page_cache.lock();
        let (page, evicted) = self.page_or_insert(
            self.inner.entry().as_file()?,
            &mut guard,
            pn,
            false,
            file_len,
        )?;
        let result = f(page, evicted);
        drop(guard);
        drop(io_guard);
        result
    }

    async fn read_at_async(&self, mut dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        let len = *self.shared.size.lock();
        let end = (offset + dst.remaining_mut() as u64).min(len);
        if end <= offset {
            return Ok(0);
        }
        let file = self.inner.entry().as_file()?;
        let start_page = (offset / PAGE_SIZE as u64) as u32;
        let end_page = end.div_ceil(PAGE_SIZE as u64) as u32;
        let mut page_offset = (offset % PAGE_SIZE as u64) as usize;
        let mut read = 0;
        let sequential = self.read_hint.load(Ordering::Acquire) == offset;
        for pn in start_page..end_page {
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let page_end = (end - page_start).min(PAGE_SIZE as u64) as usize;
            loop {
                let hit = {
                    let _io_guard = self.shared.io_lock.read();
                    let mut cache = self.shared.page_cache.lock();
                    if let Some(page) = cache.get_mut(&pn) {
                        let copied = page_end - page_offset;
                        dst.write(&page.data()[page_offset..page_end])?;
                        read += copied;
                        true
                    } else {
                        false
                    }
                };
                if hit {
                    break;
                }

                // The page can be invalidated after a fill returns but before
                // this task reacquires the read lock, so retry the lookup.
                self.ensure_pages_async(file, pn, if sequential { READ_AHEAD_PAGES } else { 1 })
                    .await?;
            }
            page_offset = 0;
        }
        self.read_hint.store(end, Ordering::Release);
        Ok(read)
    }

    pub fn read_at(&self, dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        axtask::future::block_on(self.read_at_async(dst, offset))
    }

    fn write_at_locked(&self, mut buf: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let end = offset
            .checked_add(buf.remaining() as u64)
            .ok_or(VfsError::InvalidInput)?;
        let file = self.inner.entry().as_file()?;
        let start_page = (offset / PAGE_SIZE as u64) as u32;
        let end_page = end.div_ceil(PAGE_SIZE as u64) as u32;
        let mut page_offset = (offset % PAGE_SIZE as u64) as usize;
        let mut written = 0usize;
        let original_len = *self.shared.size.lock();
        let mut guard = self.shared.page_cache.lock();

        for pn in start_page..end_page {
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let page_end = (end - page_start).min(PAGE_SIZE as u64) as usize;
            let skip_read = page_offset == 0 && page_end == PAGE_SIZE;
            // Cache pressure may write back pages copied earlier in this call.
            // Give writeback that progress without exposing the still-unwritten
            // remainder as part of the logical file.
            let visible_len = offset
                .checked_add(written as u64)
                .ok_or(VfsError::InvalidInput)?
                .max(original_len);
            let (page, evicted) =
                match self.page_or_insert(file, &mut guard, pn, skip_read, visible_len) {
                    Ok(result) => result,
                    Err(err) if written == 0 => return Err(err),
                    Err(_) => break,
                };

            if let Err(err) = buf.read(&mut page.data()[page_offset..page_end]) {
                if written == 0 {
                    return Err(err.into());
                }
                break;
            }
            if !self.in_memory {
                page.dirty = true;
            }
            written += page_end - page_offset;
            page_offset = 0;
            drop(evicted);
        }
        drop(guard);

        if written != 0 {
            let written_end = offset
                .checked_add(written as u64)
                .ok_or(VfsError::InvalidInput)?;
            let mut size_guard = self.shared.size.lock();
            if written_end > *size_guard {
                *size_guard = written_end;
            }
        }
        Ok(written)
    }

    pub fn write_at(&self, buf: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let _guard = self.shared.io_lock.write();
        self.write_at_locked(buf, offset)
    }

    pub fn append(&self, buf: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        let _guard = self.shared.io_lock.write();
        let len = *self.shared.size.lock();
        self.write_at_locked(buf, len).and_then(|written| {
            len.checked_add(written as u64)
                .map(|end| (written, end))
                .ok_or(VfsError::InvalidInput)
        })
    }

    pub fn set_len(&self, len: u64) -> VfsResult<()> {
        let _guard = self.shared.io_lock.write();
        let file = self.inner.entry().as_file()?;
        let old_len = *self.shared.size.lock();
        if old_len == len {
            return Ok(());
        }

        axtask::future::block_on(file.set_len(len))?;
        self.shared.cache_generation.fetch_add(1, Ordering::AcqRel);
        *self.shared.size.lock() = len;

        let old_last_page = (old_len / PAGE_SIZE as u64) as u32;
        let new_last_page = (len / PAGE_SIZE as u64) as u32;
        if old_len < len {
            let mut guard = self.shared.page_cache.lock();
            if let Some(page) = guard.get_mut(&old_last_page) {
                let page_start = old_last_page as u64 * PAGE_SIZE as u64;
                let old_page_offset = (old_len - page_start) as usize;
                let new_page_offset = (len - page_start).min(PAGE_SIZE as u64) as usize;
                page.data()[old_page_offset..new_page_offset].fill(0);
                if !self.in_memory {
                    page.mark_dirty();
                }
            }
        } else {
            let mut guard = self.shared.page_cache.lock();
            let tail = (len % PAGE_SIZE as u64) as usize;
            if tail != 0
                && let Some(page) = guard.get_mut(&new_last_page)
            {
                page.data()[tail..].fill(0);
            }
            let first_discarded_page = len.div_ceil(PAGE_SIZE as u64) as u32;
            let keys = guard
                .iter()
                .map(|(k, _)| *k)
                .filter(|it| *it >= first_discarded_page)
                .collect::<Vec<_>>();
            drop(guard);
            self.discard_pages(file, keys, false)?;
        }
        Ok(())
    }

    pub fn sync(&self, data_only: bool) -> VfsResult<()> {
        if self.in_memory {
            return Ok(());
        }
        let _guard = self.shared.io_lock.write();
        let file = self.inner.entry().as_file()?;
        let cached_size = *self.shared.size.lock();
        if axtask::future::block_on(file.len())? != cached_size {
            axtask::future::block_on(file.set_len(cached_size))?;
        }
        self.flush_dirty_pages(file)?;
        axtask::future::block_on(file.sync(data_only))?;
        Ok(())
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
    ) -> VfsResult<Vec<(u32, PhysAddr)>> {
        let file = self.inner.entry().as_file()?;
        axtask::future::block_on(self.pin_pages_inner_async(file, pn, page_count.max(1), may_write))
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

/// Low-level interface for file operations.
#[derive(Clone)]
pub enum FileBackend {
    Cached(CachedFile),
    Direct(Location),
}

impl FileBackend {
    pub(crate) fn new_direct(location: Location) -> Self {
        Self::Direct(location)
    }

    pub(crate) fn new_cached(location: Location) -> VfsResult<Self> {
        CachedFile::get_or_create(location).map(Self::Cached)
    }

    pub async fn read_at(&self, mut dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.read_at_async(dst, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if node_allows_page_cache(node_flags) && !node_flags.contains(NodeFlags::STREAM) {
                    let shared = shared_file_state(loc)?;
                    let _guard = shared.io_lock.write();
                    let cached_size = *shared.size.lock();
                    if axtask::future::block_on(file.len())? != cached_size {
                        axtask::future::block_on(file.set_len(cached_size))?;
                    }
                    shared.flush_dirty_pages(file)?;

                    let mut tmp = alloc::vec![0u8; dst.remaining_mut().min(64 * 1024)];
                    let read = file.read_at(&mut tmp, offset).await?;
                    return dst.write(&tmp[..read]);
                }
                // Keep the adapter bounded for very large vectored/user buffers.
                let mut tmp = alloc::vec![0u8; dst.remaining_mut().min(64 * 1024)];
                let read = file.read_at(&mut tmp, offset).await?;
                dst.write(&tmp[..read])
            }
        }
    }

    pub async fn write_at(&self, mut src: impl Read + IoBuf, mut offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.write_at(src, offset),
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if !node_allows_page_cache(node_flags) || node_flags.contains(NodeFlags::STREAM) {
                    src.write_to(&mut axio::write_fn(|buf| {
                        axtask::future::block_on(file.write_at(buf, offset)).inspect(|written| {
                            offset += *written as u64;
                        })
                    }))
                } else {
                    let shared = shared_file_state(loc)?;
                    let _guard = shared.io_lock.write();
                    let cached_size = *shared.size.lock();
                    if axtask::future::block_on(file.len())? != cached_size {
                        axtask::future::block_on(file.set_len(cached_size))?;
                    }
                    shared.flush_dirty_pages(file)?;
                    let result = src.write_to(&mut axio::write_fn(|buf| {
                        axtask::future::block_on(file.write_at(buf, offset)).inspect(|written| {
                            offset += *written as u64;
                        })
                    }));
                    if let Ok(backend_size) = axtask::future::block_on(file.len()) {
                        *shared.size.lock() = backend_size;
                    }
                    let invalidate = shared.discard_all_pages(file, false);
                    match (result, invalidate) {
                        (Ok(written), Ok(())) => Ok(written),
                        (Err(err), Ok(())) => Err(err),
                        (Ok(_), Err(err)) => Err(err),
                        (Err(err), Err(_)) => Err(err),
                    }
                }
            }
        }
    }

    pub async fn append(&self, mut src: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        match self {
            Self::Cached(cached) => cached.append(src),
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    let mut end = 0;
                    let written = src.write_to(&mut axio::write_fn(|buf| {
                        axtask::future::block_on(file.append(buf)).map(|(n, offset)| {
                            end = offset;
                            n
                        })
                    }))?;
                    return Ok((written, end));
                }

                let shared = shared_file_state(loc)?;
                let _guard = shared.io_lock.write();
                let cached_size = *shared.size.lock();
                if axtask::future::block_on(file.len())? != cached_size {
                    axtask::future::block_on(file.set_len(cached_size))?;
                }
                shared.flush_dirty_pages(file)?;
                let mut end = 0;
                let result = src.write_to(&mut axio::write_fn(|buf| {
                    axtask::future::block_on(file.append(buf)).map(|(n, offset)| {
                        end = offset;
                        n
                    })
                }));
                if let Ok(backend_size) = axtask::future::block_on(file.len()) {
                    *shared.size.lock() = backend_size;
                }
                let invalidate = shared.discard_all_pages(file, false);
                match (result, invalidate) {
                    (Ok(n), Ok(())) => Ok((n, end)),
                    (Err(err), Ok(())) => Err(err),
                    (Ok(_), Err(err)) => Err(err),
                    (Err(err), Err(_)) => Err(err),
                }
            }
        }
    }

    pub fn location(&self) -> &Location {
        match self {
            Self::Cached(cached) => cached.location(),
            Self::Direct(loc) => loc,
        }
    }

    pub async fn sync(&self, data_only: bool) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.sync(data_only),
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.sync(data_only).await;
                }

                let shared = shared_file_state(loc)?;
                let _guard = shared.io_lock.write();
                let cached_size = *shared.size.lock();
                if axtask::future::block_on(file.len())? != cached_size {
                    axtask::future::block_on(file.set_len(cached_size))?;
                }
                shared.flush_dirty_pages(file)?;
                axtask::future::block_on(file.sync(data_only))
            }
        }
    }

    pub async fn set_len(&self, len: u64) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.set_len(len),
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.set_len(len).await;
                }

                let shared = shared_file_state(loc)?;
                let _guard = shared.io_lock.write();
                shared.flush_dirty_pages(file)?;
                axtask::future::block_on(file.set_len(len))?;
                *shared.size.lock() = len;
                shared.discard_all_pages(file, false)
            }
        }
    }
}

/// Provides `std::fs::File`-like interface.
pub struct File {
    inner: FileBackend,
    flags: FileFlags,
    position: Option<Mutex<u64>>,
    _write_access: Option<WriteAccessGuard>,
    #[cfg(feature = "times")]
    access_flags: AtomicU8,
}

impl File {
    fn new(inner: FileBackend, flags: FileFlags, write_access: Option<WriteAccessGuard>) -> Self {
        let position = if inner.location().flags().contains(NodeFlags::STREAM) {
            None
        } else {
            Some(Mutex::new(if flags.contains(FileFlags::APPEND) {
                cached_file_size(inner.location()).unwrap_or_default()
            } else {
                0
            }))
        };
        Self {
            inner,
            flags,
            position,
            _write_access: write_access,
            #[cfg(feature = "times")]
            access_flags: AtomicU8::new(0),
        }
    }

    pub fn clone_with_new_position(&self) -> Self {
        Self::new(self.inner.clone(), self.flags, self._write_access.clone())
    }

    pub fn write_access_guard(&self) -> Option<WriteAccessGuard> {
        self._write_access.clone()
    }

    pub async fn open(context: &FsContext, path: impl AsRef<Path>) -> VfsResult<Self> {
        OpenOptions::new()
            .read(true)
            .open(context, path.as_ref())
            .await
            .and_then(OpenResult::into_file)
    }

    pub async fn create(context: &FsContext, path: impl AsRef<Path>) -> VfsResult<Self> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(context, path.as_ref())
            .await
            .and_then(OpenResult::into_file)
    }

    pub fn access(&self, flags: FileFlags) -> VfsResult<&FileBackend> {
        if self.flags.contains(flags) && !self.is_path() {
            Ok(&self.inner)
        } else {
            Err(VfsError::BadFileDescriptor)
        }
    }

    pub fn is_path(&self) -> bool {
        self.flags.contains(FileFlags::PATH)
    }

    pub fn flags(&self) -> FileFlags {
        self.flags
    }

    pub fn backend(&self) -> VfsResult<&FileBackend> {
        self.access(FileFlags::empty())?;
        Ok(&self.inner)
    }

    pub fn location(&self) -> &Location {
        self.inner.location()
    }

    pub fn is_direct_regular_file(&self) -> bool {
        if matches!(self.inner, FileBackend::Direct(_)) {
            if let Ok(metadata) = axtask::future::block_on(self.inner.location().metadata()) {
                if metadata.node_type == NodeType::RegularFile {
                    let fs_name = self.inner.location().filesystem().name();
                    return fs_name != "proc" && fs_name != "devfs" && fs_name != "tmpfs";
                }
            }
        }
        false
    }

    pub fn block_size(&self) -> u64 {
        axtask::future::block_on(self.inner.location().metadata())
            .map(|m| m.block_size)
            .unwrap_or(512)
    }

    /// Reads a number of bytes starting from a given offset.
    pub async fn read_at(&self, dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        let result = self.access(FileFlags::READ)?.read_at(dst, offset).await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|read| *read != 0) {
            self.access_flags.fetch_or(1, Ordering::AcqRel);
        }
        result
    }

    /// Writes a number of bytes starting from a given offset.
    pub async fn write_at(&self, src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let result = self.access(FileFlags::WRITE)?.write_at(src, offset).await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags.fetch_or(2, Ordering::AcqRel);
        }
        result
    }

    /// Attempts to sync OS-internal file content and metadata to disk.
    ///
    /// If `data_only` is `true`, only the file data is synced, not the
    /// metadata.
    pub async fn sync(&self, data_only: bool) -> VfsResult<()> {
        self.access(FileFlags::empty())?;
        #[cfg(feature = "times")]
        let timestamp_flags = self.take_timestamp_updates().await?;

        let result = self.inner.sync(data_only).await;
        #[cfg(feature = "times")]
        if result.is_err() {
            self.access_flags
                .fetch_or(timestamp_flags, Ordering::AcqRel);
        }
        result
    }

    pub async fn read(&self, dst: impl Write + IoBufMut) -> axio::Result<usize> {
        if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock();
            self.read_at(dst, *pos).await.inspect(|n| {
                *pos += *n as u64;
            })
        } else {
            self.read_at(dst, 0).await
        }
    }

    pub async fn write(&self, src: impl Read + IoBuf) -> axio::Result<usize> {
        let result = if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock();
            if let Ok(f) = self.access(FileFlags::APPEND) {
                f.append(src).await.map(|(written, new_size)| {
                    *pos = new_size;
                    written
                })
            } else {
                self.write_at(src, *pos).await.inspect(|n| {
                    *pos += *n as u64;
                })
            }
        } else {
            self.write_at(src, 0).await
        };
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags.fetch_or(2, Ordering::AcqRel);
        }
        result
    }

    pub async fn flush(&self) -> axio::Result {
        self.sync(false).await
    }

    pub fn position(&self) -> Option<u64> {
        self.position.as_ref().map(|pos| *pos.lock())
    }

    #[cfg(feature = "times")]
    async fn take_timestamp_updates(&self) -> VfsResult<u8> {
        let flags = self.access_flags.swap(0, Ordering::AcqRel);
        if flags == 0 {
            return Ok(0);
        }

        let now = axhal::time::wall_time();
        let mut update = axfs_ng_vfs::MetadataUpdate::default();
        if flags & 1 != 0 {
            update.atime = Some(now);
        }
        if flags & 2 != 0 {
            update.mtime = Some(now);
        }

        if let Err(err) = self.inner.location().update_metadata(update).await {
            self.access_flags.fetch_or(flags, Ordering::AcqRel);
            return Err(err);
        }
        Ok(flags)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        #[cfg(feature = "times")]
        if self.access_flags.load(Ordering::Acquire) != 0 {
            // Closing a file should publish deferred timestamps, but it must not
            // turn an ordinary close into fsync and a device-wide flush.
            let _ = axtask::future::block_on(self.take_timestamp_updates());
        }
    }
}

impl Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> axio::Result<usize> {
        axtask::future::block_on((*self).read(buf))
    }
}

impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> axio::Result<usize> {
        axtask::future::block_on((*self).write(buf))
    }

    fn flush(&mut self) -> axio::Result {
        axtask::future::block_on((*self).flush())
    }
}

impl Seek for &File {
    fn seek(&mut self, pos: SeekFrom) -> axio::Result<u64> {
        self.access(FileFlags::empty())?;

        if let Some(guard) = self.position.as_ref() {
            let mut guard = guard.lock();
            let new_pos = match pos {
                SeekFrom::Start(pos) => pos,
                SeekFrom::End(off) => {
                    let size = cached_file_size(self.access(FileFlags::empty())?.location())?;
                    size.checked_add_signed(off).ok_or(VfsError::InvalidInput)?
                }
                SeekFrom::Current(off) => guard
                    .checked_add_signed(off)
                    .ok_or(VfsError::InvalidInput)?,
            };
            *guard = new_pos;
            Ok(new_pos)
        } else {
            Ok(0)
        }
    }
}

impl Pollable for File {
    fn poll(&self) -> IoEvents {
        self.inner.location().poll()
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        self.inner.location().register(context, events)
    }
}
