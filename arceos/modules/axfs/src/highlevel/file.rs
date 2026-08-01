use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(feature = "times")]
use core::sync::atomic::AtomicU8;
use core::{
    ptr::NonNull,
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
use axsync::Mutex;
use futures_util::{StreamExt, stream::FuturesUnordered};
use lru::LruCache;
use spin::{Lazy, Mutex as SpinMutex};

use super::FsContext;

pub const SHARED_PAGE_BATCH_CAPACITY: usize = 16;
pub type SharedPagePaddrs = heapless::Vec<(u32, PhysAddr), SHARED_PAGE_BATCH_CAPACITY>;

const WEAK_STATE_SWEEP_BUDGET: usize = 8;
const FILE_STATE_REGISTRY_SHARDS: usize = 32;

struct WeakStateRegistry<K: Ord + Copy, V> {
    states: BTreeMap<K, Weak<V>>,
    sweep_cursor: Option<K>,
}

impl<K: Ord + Copy, V> Default for WeakStateRegistry<K, V> {
    fn default() -> Self {
        Self {
            states: BTreeMap::new(),
            sweep_cursor: None,
        }
    }
}

impl<K: Ord + Copy, V> WeakStateRegistry<K, V> {
    fn get(&self, key: &K) -> Option<Arc<V>> {
        self.states.get(key).and_then(Weak::upgrade)
    }

    fn insert(&mut self, key: K, state: &Arc<V>) {
        self.states.insert(key, Arc::downgrade(state));
    }

    fn remove(&mut self, key: &K) -> Option<Arc<V>> {
        self.states.remove(key).and_then(|state| state.upgrade())
    }

    fn sweep_dead(&mut self) {
        if self.states.is_empty() {
            self.sweep_cursor = None;
            return;
        }

        let previous_cursor = self.sweep_cursor;
        let mut keys = [None; WEAK_STATE_SWEEP_BUDGET];
        let mut count = 0;
        if let Some(cursor) = previous_cursor {
            for key in self
                .states
                .range((
                    core::ops::Bound::Excluded(cursor),
                    core::ops::Bound::Unbounded,
                ))
                .map(|(key, _)| *key)
                .take(WEAK_STATE_SWEEP_BUDGET)
            {
                keys[count] = Some(key);
                count += 1;
            }
        } else {
            for key in self.states.keys().copied().take(WEAK_STATE_SWEEP_BUDGET) {
                keys[count] = Some(key);
                count += 1;
            }
        }

        if count < WEAK_STATE_SWEEP_BUDGET
            && let Some(cursor) = previous_cursor
        {
            for key in self
                .states
                .range(..=cursor)
                .map(|(key, _)| *key)
                .take(WEAK_STATE_SWEEP_BUDGET - count)
            {
                keys[count] = Some(key);
                count += 1;
            }
        }

        self.sweep_cursor = count.checked_sub(1).and_then(|index| keys[index]);
        for key in keys[..count].iter().flatten() {
            if self
                .states
                .get(key)
                .is_some_and(|state| state.strong_count() == 0)
            {
                self.states.remove(key);
            }
        }
        if self.states.is_empty() {
            self.sweep_cursor = None;
        }
    }
}

fn checked_shared_page_count(page_count: usize) -> VfsResult<usize> {
    let page_count = page_count.max(1);
    if page_count > SHARED_PAGE_BATCH_CAPACITY {
        return Err(VfsError::StorageFull);
    }
    Ok(page_count)
}

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

fn file_state_registry_shard(key: FileCacheKey) -> usize {
    let inode = key.inode as usize ^ (key.inode >> 32) as usize;
    (key.fs_id.rotate_left(13) ^ inode.rotate_right(7)) % FILE_STATE_REGISTRY_SHARDS
}

fn node_allows_page_cache(flags: NodeFlags) -> bool {
    !flags.contains(NodeFlags::NON_CACHEABLE)
}

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

static INODE_ACCESS_STATES: Lazy<
    [SpinMutex<WeakStateRegistry<FileCacheKey, InodeAccessState>>; FILE_STATE_REGISTRY_SHARDS],
> = Lazy::new(|| core::array::from_fn(|_| SpinMutex::new(WeakStateRegistry::default())));

fn inode_access_state(location: &Location) -> Arc<InodeAccessState> {
    let key = file_cache_key(location);
    let mut registry = INODE_ACCESS_STATES[file_state_registry_shard(key)].lock();
    if let Some(state) = registry.get(&key) {
        return state;
    }
    registry.sweep_dead();
    let state = Arc::new(InodeAccessState::new());
    registry.insert(key, &state);
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
                FileBackend::new_cached(loc).await?
            } else {
                FileBackend::new_direct(loc)
            };
            if self.truncate && metadata.node_type == NodeType::RegularFile {
                backend.set_len(0).await?;
            }
            OpenResult::File(File::new_async(backend, flags, write_access).await)
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
                    loc = context.try_resolve_symlink(loc, &mut 0).await?;
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

struct WritebackBatch {
    pages: Vec<u32>,
    offset: u64,
    data: Vec<u8>,
}

async fn submit_writeback_batch(
    file: &FileNode,
    batch: WritebackBatch,
) -> (WritebackBatch, VfsResult<()>) {
    let result = if batch.data.is_empty() {
        Ok(())
    } else {
        write_all_at_async(file, &batch.data, batch.offset).await
    };
    (batch, result)
}

async fn write_source_at_async<R: Read + IoBuf>(
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

async fn append_source_async<R: Read + IoBuf>(
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
}

impl Drop for ContiguousPageGroup {
    fn drop(&mut self) {
        global_allocator().dealloc_pages(self.addr.as_usize(), self.pages);
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

    /// The group is private until every direct read has completed and it is
    /// published as page-cache entries. Callers must preserve that exclusivity.
    unsafe fn bytes_mut(&self, len: usize) -> VfsResult<&mut [u8]> {
        if len > self.len()? {
            return Err(VfsError::InvalidInput);
        }
        // SAFETY: upheld by the caller as documented above.
        Ok(unsafe { core::slice::from_raw_parts_mut(self.addr.as_mut_ptr(), len) })
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
}

#[derive(Debug)]
enum PageCacheFrameBacking {
    Standalone,
    Group(Arc<ContiguousPageGroup>),
}

#[derive(Debug)]
struct PageCacheFrame {
    addr: VirtAddr,
    backing: PageCacheFrameBacking,
}

impl PageCacheFrame {
    fn is_group_backed(&self) -> bool {
        matches!(self.backing, PageCacheFrameBacking::Group(_))
    }
}

impl Drop for PageCacheFrame {
    fn drop(&mut self) {
        if !matches!(self.backing, PageCacheFrameBacking::Standalone) {
            return;
        }
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
}

impl PageCache {
    fn new(skip_zero: bool) -> VfsResult<Self> {
        let frame = Self::new_standalone_frame(skip_zero)?;
        Ok(Self {
            frame,
            dirty: false,
            may_write_mapping: false,
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
        Ok(Arc::new(PageCacheFrame {
            addr: addr.into(),
            backing: PageCacheFrameBacking::Standalone,
        }))
    }

    fn new_grouped(group: Arc<ContiguousPageGroup>, index: usize) -> VfsResult<Self> {
        Ok(Self {
            frame: Arc::new(PageCacheFrame {
                addr: group.page_addr(index)?,
                backing: PageCacheFrameBacking::Group(group),
            }),
            dirty: false,
            may_write_mapping: false,
        })
    }

    fn detach_group_frame(&mut self) -> VfsResult<()> {
        if !self.frame.is_group_backed() {
            return Ok(());
        }
        let source = self.frame.addr;
        let frame = Self::new_standalone_frame(true)?;
        // SAFETY: the page is protected by the page-cache mutex while this
        // transition runs. The grouped page is no longer in direct I/O, and
        // the new standalone page does not overlap it.
        unsafe {
            core::ptr::copy_nonoverlapping(source.as_ptr(), frame.addr.as_mut_ptr(), PAGE_SIZE);
        }
        self.frame = frame;
        crate::buildstorm_stat_inc!(PAGE_FILL_MAPPING_DETACHES);
        Ok(())
    }

    pub fn paddr(&self) -> PhysAddr {
        virt_to_phys(self.frame.addr)
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    fn has_user_mapping(&self) -> bool {
        if self.frame.is_group_backed() {
            return false;
        }
        axalloc::frame_table()
            .try_get_ref(self.paddr())
            .is_some_and(|ref_count| ref_count > 1)
    }

    fn pin_for_mapping(&mut self, may_write: bool) -> VfsResult<PhysAddr> {
        self.detach_group_frame()?;
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

struct CachedFileShared {
    // Page stripes protect fill/write coherence; inline entries keep the hot
    // cache-hit path to one cache lock without per-page Arc/Mutex overhead.
    page_cache: Mutex<LruCache<u32, PageCache>>,
    page_access: PageAccessDomain,
    cache_soft_limit: AtomicUsize,
    evict_listeners: Mutex<Vec<Arc<EvictListener>>>,
    backing: Option<FileNode>,
    io_lock: async_lock::RwLock<()>,
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
    fn size(&self) -> u64 {
        self.size.load(Ordering::Acquire)
    }

    #[inline]
    fn set_size(&self, size: u64) {
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

    async fn flush_dirty_pages_async(&self, file: &FileNode) -> VfsResult<()> {
        let file_len = self.size();
        if file.len().await? < file_len {
            file.set_len(file_len).await?;
        }

        let dirty_pns = {
            let mut cache = self.page_cache.lock();
            for (_, page) in cache.iter_mut() {
                if page.may_write_mapping && page.has_user_mapping() {
                    page.mark_dirty();
                }
            }
            let mut dirty = cache
                .iter()
                .filter(|(_, page)| page.dirty)
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
                let data = {
                    let mut cache = self.page_cache.lock();
                    let mut data = Vec::new();
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
                        data.extend_from_slice(&page.data()[..len]);
                    }
                    data
                };
                if first_error.is_some() {
                    break;
                }
                pending.push(submit_writeback_batch(
                    file,
                    WritebackBatch {
                        pages: pages.clone(),
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
            let mut data_offset = 0;
            for pn in batch.pages {
                let current_start = pn as u64 * PAGE_SIZE as u64;
                let len = file_len.saturating_sub(current_start).min(PAGE_SIZE as u64) as usize;
                if let Some(page) = cache.get_mut(&pn)
                    && page.data()[..len] == batch.data[data_offset..data_offset + len]
                {
                    page.dirty = false;
                }
                data_offset += len;
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

    async fn discard_all_pages_without_writeback_async(&self, file: &FileNode) -> VfsResult<()> {
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

async fn shared_file_state_async(location: &Location) -> VfsResult<Arc<CachedFileShared>> {
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
                // until the direct read has completed and its registration is
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

        let mut pages = Vec::with_capacity(page_count);
        for page_offset in 0..page_count {
            let page_num = pn
                .checked_add(u32::try_from(page_offset).map_err(|_| VfsError::StorageFull)?)
                .ok_or(VfsError::StorageFull)?;
            pages.push((
                page_num,
                PageCache::new_grouped(group.clone(), page_offset)?,
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

    async fn read_at_async(&self, mut dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        let len = self.shared.size();
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
                    // A resident page is stable while `page_cache` is held.
                    // Cache fills and writes take page-access locks, and direct
                    // I/O invalidation takes the exclusive `io_lock`.
                    let _io_guard = self.shared.io_lock.read().await;
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
                    crate::buildstorm_stat_inc!(PAGE_READ_HITS);
                    break;
                }
                crate::buildstorm_stat_inc!(PAGE_READ_MISSES);

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
                page.dirty = true;
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
            let result = match access {
                CachedWriteAccess::PageRange => {
                    let (start_page, page_count) = checked_page_span(current_offset, read)?;
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
                    // Preserve the lock order: page access precedes the
                    // shared side of `io_lock`. Each chunk releases both before
                    // acquiring the next page range.
                    let _io_guard = self.shared.io_lock.read().await;
                    self.write_slice_at_locked_async(file, &staging[..read], current_offset)
                        .await
                }
                // Atomic append already owns the exclusive side of `io_lock`,
                // so no page-access lock is needed or safe to acquire here.
                CachedWriteAccess::ExclusiveFileHeld => {
                    self.write_slice_at_locked_async(file, &staging[..read], current_offset)
                        .await
                }
            };
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

    pub(crate) async fn new_cached(location: Location) -> VfsResult<Self> {
        CachedFile::get_or_create_async(location)
            .await
            .map(Self::Cached)
    }

    pub async fn read_at(&self, mut dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.read_at_async(dst, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if node_allows_page_cache(node_flags) && !node_flags.contains(NodeFlags::STREAM) {
                    let shared = shared_file_state_async(loc).await?;
                    let _guard = shared.io_lock.write().await;
                    let cached_size = shared.size();
                    if file.len().await? != cached_size {
                        file.set_len(cached_size).await?;
                    }
                    shared.flush_dirty_pages_async(file).await?;

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

    pub async fn write_at(&self, mut src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.write_at_async(src, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if !node_allows_page_cache(node_flags) || node_flags.contains(NodeFlags::STREAM) {
                    write_source_at_async(file, &mut src, offset).await
                } else {
                    let shared = shared_file_state_async(loc).await?;
                    let _guard = shared.io_lock.write().await;
                    let cached_size = shared.size();
                    if file.len().await? != cached_size {
                        file.set_len(cached_size).await?;
                    }
                    shared.flush_dirty_pages_async(file).await?;
                    let result = write_source_at_async(file, &mut src, offset).await;
                    if let Ok(backend_size) = file.len().await {
                        shared.set_size(backend_size);
                    }
                    let invalidate = shared.discard_all_pages_without_writeback_async(file).await;
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
            Self::Cached(cached) => cached.append_async(src).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return append_source_async(file, &mut src).await;
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                let cached_size = shared.size();
                if file.len().await? != cached_size {
                    file.set_len(cached_size).await?;
                }
                shared.flush_dirty_pages_async(file).await?;
                let result = append_source_async(file, &mut src).await;
                if let Ok(backend_size) = file.len().await {
                    shared.set_size(backend_size);
                }
                let invalidate = shared.discard_all_pages_without_writeback_async(file).await;
                match (result, invalidate) {
                    (Ok(result), Ok(())) => Ok(result),
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
            Self::Cached(cached) => cached.sync_async(data_only).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.sync(data_only).await;
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                let cached_size = shared.size();
                if file.len().await? != cached_size {
                    file.set_len(cached_size).await?;
                }
                shared.flush_dirty_pages_async(file).await?;
                file.sync(data_only).await
            }
        }
    }

    pub async fn set_len(&self, len: u64) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.set_len_async(len).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.set_len(len).await;
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                shared.flush_dirty_pages_async(file).await?;
                file.set_len(len).await?;
                shared.set_size(len);
                shared.discard_all_pages_without_writeback_async(file).await
            }
        }
    }
}

/// Provides `std::fs::File`-like interface.
pub struct File {
    inner: FileBackend,
    flags: FileFlags,
    position: Option<async_lock::Mutex<u64>>,
    _write_access: Option<WriteAccessGuard>,
    #[cfg(feature = "times")]
    access_flags: AtomicU8,
}

impl File {
    fn new_with_position(
        inner: FileBackend,
        flags: FileFlags,
        write_access: Option<WriteAccessGuard>,
        append_position: u64,
    ) -> Self {
        let position = if inner.location().flags().contains(NodeFlags::STREAM) {
            None
        } else {
            Some(async_lock::Mutex::new(
                if flags.contains(FileFlags::APPEND) {
                    append_position
                } else {
                    0
                },
            ))
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

    fn new(inner: FileBackend, flags: FileFlags, write_access: Option<WriteAccessGuard>) -> Self {
        let append_position = if flags.contains(FileFlags::APPEND) {
            cached_file_size(inner.location()).unwrap_or_default()
        } else {
            0
        };
        Self::new_with_position(inner, flags, write_access, append_position)
    }

    async fn new_async(
        inner: FileBackend,
        flags: FileFlags,
        write_access: Option<WriteAccessGuard>,
    ) -> Self {
        let append_position = if flags.contains(FileFlags::APPEND) {
            match cached_file_size_if_present(inner.location()) {
                Some(size) => size,
                None => inner.location().len().await.unwrap_or_default(),
            }
        } else {
            0
        };
        Self::new_with_position(inner, flags, write_access, append_position)
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
            let mut pos = pos.lock().await;
            self.read_at(dst, *pos).await.inspect(|n| {
                *pos += *n as u64;
            })
        } else {
            self.read_at(dst, 0).await
        }
    }

    pub async fn write(&self, src: impl Read + IoBuf) -> axio::Result<usize> {
        let result = if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock().await;
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
        self.position
            .as_ref()
            .map(|pos| *axtask::future::block_on(pos.lock()))
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
            let mut guard = axtask::future::block_on(guard.lock());
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

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use axfs_ng_vfs::VfsError;

    use super::{
        CachedFileShared, MAX_WRITE_ACCESS_PAGES, PAGE_ACCESS_LOCK_STRIPES, PAGE_SIZE,
        PageAccessDomain, SHARED_PAGE_BATCH_CAPACITY, WEAK_STATE_SWEEP_BUDGET, WRITE_STAGING_SIZE,
        WeakStateRegistry, checked_page_span, checked_shared_page_count,
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
