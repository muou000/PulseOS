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
    sync::atomic::{AtomicBool, AtomicIsize, AtomicU64, AtomicUsize, Ordering},
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
use kspin::SpinNoPreempt;
use lru::LruCache;
use spin::Lazy;

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

pub(super) fn filesystem_id(filesystem: &dyn axfs_ng_vfs::FilesystemOps) -> usize {
    filesystem as *const dyn axfs_ng_vfs::FilesystemOps as *const () as usize
}

fn file_cache_key(loc: &Location) -> FileCacheKey {
    FileCacheKey {
        fs_id: filesystem_id(loc.filesystem()),
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

mod cache;
mod handle;

pub use cache::*;
pub use handle::*;

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
    [SpinNoPreempt<WeakStateRegistry<FileCacheKey, InodeAccessState>>; FILE_STATE_REGISTRY_SHARDS],
> = Lazy::new(|| core::array::from_fn(|_| SpinNoPreempt::new(WeakStateRegistry::default())));

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
