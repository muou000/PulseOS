use alloc::{
    boxed::Box,
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Weak},
    vec::Vec,
};
#[cfg(feature = "times")]
use core::sync::atomic::{AtomicU8, Ordering};
use core::{num::NonZeroUsize, ops::Range, task::Context};

use axalloc::global_allocator;
use axfs_ng_vfs::{
    FileNode, Location, NodeFlags, NodePermission, NodeType, VfsError, VfsResult, path::Path,
};
use axhal::mem::{PhysAddr, VirtAddr, virt_to_phys};
use axio::{SeekFrom, prelude::*};
use axpoll::{IoEvents, Pollable};
use axsync::Mutex;
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

fn prune_file_shared_states(registry: &mut BTreeMap<FileCacheKey, Weak<CachedFileShared>>) {
    registry.retain(|_, state| state.strong_count() > 0);
}

static FILE_SHARED_STATES: Lazy<SpinMutex<BTreeMap<FileCacheKey, Weak<CachedFileShared>>>> =
    Lazy::new(|| SpinMutex::new(BTreeMap::new()));

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

    fn _open(&self, loc: Location) -> VfsResult<OpenResult> {
        let flags = self.to_flags()?;

        if loc.is_dir() && (self.create || self.create_new || flags.contains(FileFlags::WRITE)) {
            return Err(VfsError::IsADirectory);
        }

        if self.directory {
            if flags.contains(FileFlags::WRITE) {
                return Err(VfsError::IsADirectory);
            }
            loc.check_is_dir()?;
        }
        if self.truncate && loc.metadata()?.node_type == NodeType::RegularFile {
            loc.entry().as_file()?.set_len(0)?;
        }

        Ok(if loc.is_dir() {
            OpenResult::Dir(loc)
        } else {
            // TODO(mivik): is this correct?
            let non_cacheable_type = matches!(
                loc.metadata()?.node_type,
                NodeType::CharacterDevice
                    | NodeType::BlockDevice
                    | NodeType::Fifo
                    | NodeType::Socket
            );

            let direct = non_cacheable_type
                || self.path
                || self.direct
                || loc.flags().contains(NodeFlags::NON_CACHEABLE);
            let backend = if !direct || loc.flags().contains(NodeFlags::ALWAYS_CACHE) {
                FileBackend::new_cached(loc)
            } else {
                FileBackend::new_direct(loc)
            };
            OpenResult::File(File::new(backend, flags))
        })
    }

    pub fn open_loc(&self, loc: Location) -> VfsResult<OpenResult> {
        if !self.is_valid() {
            return Err(VfsError::InvalidInput);
        }
        self._open(loc)
    }

    pub fn open(&self, context: &FsContext, path: impl AsRef<Path>) -> VfsResult<OpenResult> {
        if !self.is_valid() {
            return Err(VfsError::InvalidInput);
        }

        let loc = match context.resolve_parent(path.as_ref()) {
            Ok((parent, name)) => {
                let mut loc = parent.open_file(
                    &name,
                    &axfs_ng_vfs::OpenOptions {
                        create: self.create,
                        create_new: self.create_new,
                        node_type: self.node_type,
                        permission: NodePermission::from_bits_truncate(self.mode as _),
                        user: self.user.or(context.credentials),
                    },
                )?;
                if !self.no_follow {
                    loc = context
                        .with_current_dir(parent)?
                        .try_resolve_symlink(loc, &mut 0)?;
                }
                loc
            }
            Err(VfsError::InvalidInput) => {
                // root directory
                context.root_dir().clone()
            }
            Err(err) => return Err(err),
        };
        self._open(loc)
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

#[derive(Debug)]
pub struct PageCache {
    addr: VirtAddr,
    dirty: bool,
    pub has_user_mapping: bool,
}

impl PageCache {
    fn new(skip_zero: bool) -> VfsResult<Self> {
        let addr = global_allocator()
            .alloc_pages(1, PAGE_SIZE)
            .inspect_err(|err| {
                warn!("Failed to allocate page cache: {:?}", err);
            })
            .map_err(|_| VfsError::StorageFull)?;
        if !skip_zero {
            unsafe { core::ptr::write_bytes(addr as *mut u8, 0, PAGE_SIZE) };
        }
        Ok(Self {
            addr: addr.into(),
            dirty: false,
            has_user_mapping: false,
        })
    }

    pub fn paddr(&self) -> PhysAddr {
        virt_to_phys(self.addr)
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
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
        if self.has_user_mapping && axalloc::frame_table().contains(paddr) {
            let ref_count = axalloc::frame_table().get_ref(paddr);
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
    evict_listeners: Mutex<Vec<Arc<EvictListener>>>,
    io_lock: Mutex<()>,
    size: SpinMutex<u64>,
}

impl CachedFileShared {
    pub fn new(in_memory: bool, size: u64) -> Self {
        Self {
            page_cache: if in_memory {
                Mutex::new(LruCache::unbounded())
            } else {
                Mutex::new(LruCache::new(NonZeroUsize::new(16384).unwrap()))
            },
            evict_listeners: Mutex::new(Vec::new()),
            io_lock: Mutex::new(()),
            size: SpinMutex::new(size),
        }
    }

    fn evict_listeners_snapshot(&self) -> Vec<Arc<EvictListener>> {
        self.evict_listeners.lock().clone()
    }

    fn evict_cache(&self, file: &FileNode, pn: u32, page: &mut PageCache) -> VfsResult<()> {
        let listeners = self.evict_listeners_snapshot();
        for listener in listeners.iter() {
            (listener.listener)(pn, page);
        }
        if page.dirty {
            let cached_size = *self.size.lock();
            if file.len()? < cached_size {
                file.set_len(cached_size)?;
            }
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let len = (cached_size.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
            if len > 0 {
                file.write_at(&page.data()[..len], page_start)?;
            }
            page.dirty = false;
        }
        Ok(())
    }

    fn flush_dirty_pages(&self, file: &FileNode) -> VfsResult<()> {
        const MAX_COALESCE_PAGES: usize = 32; // Limit contiguous writes to 128KB
        let file_len = *self.size.lock();
        if file.len()? < file_len {
            file.set_len(file_len)?;
        }
        let mut guard = self.page_cache.lock();

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
            let mut j = i + 1;
            while j < dirty_pns.len()
                && dirty_pns[j] == dirty_pns[j - 1] + 1
                && (j - i) < MAX_COALESCE_PAGES
            {
                j += 1;
            }

            let span_pns = &dirty_pns[i..j];
            let start_pn = span_pns[0];

            let mut combined_data = Vec::new();
            for &pn in span_pns {
                if let Some(page) = guard.get_mut(&pn) {
                    let page_start = pn as u64 * PAGE_SIZE as u64;
                    let len = (file_len.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
                    if len > 0 {
                        combined_data.extend_from_slice(&page.data()[..len]);
                    }
                }
            }

            if !combined_data.is_empty() {
                let written = file.write_at(&combined_data, start_pn as u64 * PAGE_SIZE as u64)?;
                let mut bytes_marked = 0;
                for &pn in span_pns {
                    if let Some(page) = guard.get_mut(&pn) {
                        let page_start = pn as u64 * PAGE_SIZE as u64;
                        let len = (file_len.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
                        if bytes_marked + len <= written {
                            bytes_marked += len;
                            page.dirty = false;
                        } else {
                            break;
                        }
                    }
                }
            } else {
                for &pn in span_pns {
                    if let Some(page) = guard.get_mut(&pn) {
                        page.dirty = false;
                    }
                }
            }

            i = j;
        }

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
        let mut guard = self.page_cache.lock();
        while let Some((pn, mut page)) = guard.pop_lru() {
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

static RECENTLY_CLOSED_FILES: Lazy<SpinMutex<VecDeque<Arc<CachedFileShared>>>> =
    Lazy::new(|| SpinMutex::new(VecDeque::new()));

fn shared_file_state(location: &Location) -> Arc<CachedFileShared> {
    let key = file_cache_key(location);
    let in_memory = location.filesystem().name() == "tmpfs";

    let mut registry = FILE_SHARED_STATES.lock();
    if let Some(state) = registry.get(&key).and_then(Weak::upgrade) {
        return state;
    }
    prune_file_shared_states(&mut registry);

    let size = location.len().unwrap_or(0);
    let state = Arc::new(CachedFileShared::new(in_memory, size));
    registry.insert(key, Arc::downgrade(&state));
    state
}

pub fn cached_file_size(location: &Location) -> VfsResult<u64> {
    let key = file_cache_key(location);
    if let Some(state) = FILE_SHARED_STATES.lock().get(&key).and_then(Weak::upgrade) {
        Ok(*state.size.lock())
    } else {
        location.len()
    }
}

enum FileUserData {
    Weak(Weak<CachedFileShared>),
    Strong(Arc<CachedFileShared>),
}

impl FileUserData {
    fn get(&self) -> Option<Arc<CachedFileShared>> {
        match self {
            FileUserData::Weak(weak) => weak.upgrade(),
            FileUserData::Strong(strong) => Some(strong.clone()),
        }
    }
}

#[derive(Clone)]
pub struct CachedFile {
    inner: Location,
    shared: Arc<CachedFileShared>,
    in_memory: bool,
}

impl Drop for CachedFile {
    fn drop(&mut self) {
        if Arc::strong_count(&self.shared) == 1 {
            if let Ok(file) = self.inner.entry().as_file() {
                let cached_size = *self.shared.size.lock();
                if let Ok(current_size) = file.len() {
                    if cached_size != current_size {
                        let _ = file.set_len(cached_size);
                    }
                }
                if let Err(err) = self.flush_dirty_pages(file) {
                    error!("CachedFile drop: failed to flush dirty pages: {:?}", err);
                }
            }
            if !self.in_memory {
                let mut queue = RECENTLY_CLOSED_FILES.lock();
                if let Some(pos) = queue.iter().position(|x| Arc::ptr_eq(x, &self.shared)) {
                    queue.remove(pos);
                }
                queue.push_back(self.shared.clone());
                while queue.len() > 8 {
                    queue.pop_front();
                }
            }
        }
    }
}

impl CachedFile {
    pub fn get_or_create(location: Location) -> Self {
        let in_memory = location.filesystem().name() == "tmpfs";
        let mut guard = location.user_data();
        let shared = if let Some(shared) = guard.get::<FileUserData>().and_then(|it| it.get()) {
            shared
        } else {
            let shared = shared_file_state(&location);
            let user_data = if in_memory {
                FileUserData::Strong(shared.clone())
            } else {
                FileUserData::Weak(Arc::downgrade(&shared))
            };
            guard.insert(user_data);
            shared
        };
        drop(guard);

        Self {
            inner: location,
            shared,
            in_memory,
        }
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
            if file.len()? < cached_size {
                file.set_len(cached_size)?;
            }
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let len = (cached_size.saturating_sub(page_start)).min(PAGE_SIZE as u64) as usize;
            if len > 0 {
                file.write_at(&page.data()[..len], page_start)?;
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
    ) -> VfsResult<(&'a mut PageCache, Option<(u32, PageCache)>)> {
        // TODO: Matching the result of `get_mut` confuses compiler. See
        // https://users.rust-lang.org/t/return-do-not-release-mutable-borrow/55757.
        if cache.contains(&pn) {
            return Ok((cache.get_mut(&pn).unwrap(), None));
        }
        let mut evicted = None;
        if cache.len() == cache.cap().get() {
            // Cache is full, remove the least recently used page
            if let Some((pn, mut page)) = cache.pop_lru() {
                if let Err(err) = self.evict_cache(file, pn, &mut page) {
                    cache.put(pn, page);
                    return Err(err);
                }
                evicted = Some((pn, page));
            }
        }

        // Page not in cache, read it
        let file_len = *self.shared.size.lock();
        if (pn as u64 * PAGE_SIZE as u64) >= file_len {
            skip_read = true;
        }
        let mut page = PageCache::new(skip_read)?;
        if self.in_memory {
            if !skip_read {
                page.data().fill(0);
            }
        } else if !skip_read {
            file.read_at(page.data(), pn as u64 * PAGE_SIZE as u64)?;
        }
        cache.put(pn, page);
        Ok((cache.get_mut(&pn).unwrap(), evicted))
    }

    pub fn with_page<R>(&self, pn: u32, f: impl FnOnce(Option<&mut PageCache>) -> R) -> R {
        let _guard = self.shared.io_lock.lock();
        f(self.shared.page_cache.lock().get_mut(&pn))
    }

    pub fn with_page_or_insert<R>(
        &self,
        pn: u32,
        f: impl FnOnce(&mut PageCache, Option<(u32, PageCache)>) -> VfsResult<R>,
    ) -> VfsResult<R> {
        let _guard = self.shared.io_lock.lock();
        let mut guard = self.shared.page_cache.lock();
        let (page, evicted) = self.page_or_insert(self.inner.entry().as_file()?, &mut guard, pn, false)?;
        f(page, evicted)
    }

    fn with_pages<T>(
        &self,
        range: Range<u64>,
        is_write: bool,
        page_initial: impl FnOnce(&FileNode) -> VfsResult<T>,
        mut page_each: impl FnMut(T, &mut PageCache, Range<usize>) -> VfsResult<T>,
    ) -> VfsResult<T> {
        let file = self.inner.entry().as_file()?;
        let mut initial = page_initial(file)?;
        let start_page = (range.start / PAGE_SIZE as u64) as u32;
        let end_page = range.end.div_ceil(PAGE_SIZE as u64) as u32;
        let mut page_offset = (range.start % PAGE_SIZE as u64) as usize;
        let mut guard = self.shared.page_cache.lock();
        for pn in start_page..end_page {
            let page_start = pn as u64 * PAGE_SIZE as u64;
            let page_end = (range.end - page_start).min(PAGE_SIZE as u64) as usize;

            let skip_read = is_write && (page_offset == 0) && (page_end == PAGE_SIZE);

            let page = self.page_or_insert(file, &mut guard, pn, skip_read)?.0;

            initial = page_each(
                initial,
                page,
                page_offset..page_end,
            )?;
            page_offset = 0;
        }

        Ok(initial)
    }

    pub fn read_at(&self, mut dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        let _guard = self.shared.io_lock.lock();
        let len = *self.shared.size.lock();
        let end = (offset + dst.remaining_mut() as u64).min(len);
        if end <= offset {
            return Ok(0);
        }
        self.with_pages(
            offset..end,
            false,
            |_| Ok(0),
            |read, page, range| {
                let len = range.end - range.start;
                dst.write(&page.data()[range.start..range.end])?;
                Ok(read + len)
            },
        )
    }

    fn write_at_locked(&self, mut buf: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let end = offset + buf.remaining() as u64;
        self.with_pages(
            offset..end,
            true,
            |_file| {
                let mut size_guard = self.shared.size.lock();
                if end > *size_guard {
                    *size_guard = end;
                }
                Ok(0)
            },
            |written, page, range| {
                let len = range.end - range.start;
                buf.read(&mut page.data()[range.start..range.end])?;
                if !self.in_memory {
                    page.dirty = true;
                }
                Ok(written + len)
            },
        )
    }

    pub fn write_at(&self, buf: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let _guard = self.shared.io_lock.lock();
        self.write_at_locked(buf, offset)
    }

    pub fn append(&self, buf: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        let _guard = self.shared.io_lock.lock();
        let len = *self.shared.size.lock();
        self.write_at_locked(buf, len)
            .map(|written| (written, len + written as u64))
    }

    pub fn set_len(&self, len: u64) -> VfsResult<()> {
        let _guard = self.shared.io_lock.lock();
        let file = self.inner.entry().as_file()?;
        let old_len = *self.shared.size.lock();
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
            }
        } else if old_last_page > new_last_page {
            // For truncating, we need to remove all pages that are beyond the
            // new length
            // TODO(mivik): can this be more efficient?
            let mut guard = self.shared.page_cache.lock();
            if let Some(page) = guard.get_mut(&new_last_page) {
                let page_start = new_last_page as u64 * PAGE_SIZE as u64;
                let new_page_offset = (len - page_start) as usize;
                page.data()[new_page_offset..].fill(0);
            }
            let keys = guard
                .iter()
                .map(|(k, _)| *k)
                .filter(|it| *it > new_last_page)
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
        let _guard = self.shared.io_lock.lock();
        let file = self.inner.entry().as_file()?;
        let cached_size = *self.shared.size.lock();
        if file.len()? != cached_size {
            file.set_len(cached_size)?;
        }
        self.flush_dirty_pages(file)?;
        file.sync(data_only)?;
        Ok(())
    }

    pub fn location(&self) -> &Location {
        &self.inner
    }

    /// Returns the physical address of the page at the given page index.
    ///
    /// If the page is not in the cache, it will be read from the file.
    pub fn get_shared_page_paddr(&self, pn: u32) -> VfsResult<PhysAddr> {
        self.with_page_or_insert(pn, |page, _| {
            page.has_user_mapping = true;
            Ok(page.paddr())
        })
    }

    /// Marks the page at the given page index as dirty.
    pub fn mark_page_dirty(&self, pn: u32) -> VfsResult<()> {
        self.with_page(pn, |page| {
            if let Some(page) = page {
                if !self.in_memory {
                    page.mark_dirty();
                }
            }
        });
        Ok(())
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

    pub(crate) fn new_cached(location: Location) -> Self {
        Self::Cached(CachedFile::get_or_create(location))
    }

    pub fn read_at(&self, mut dst: impl Write + IoBufMut, mut offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => {
                cached.read_at(dst, offset)
            }
            Self::Direct(loc) => {
                if loc.flags().contains(NodeFlags::STREAM) {
                    dst.read_from(&mut axio::read_fn(|buf| {
                        loc.entry().as_file()?.read_at(buf, offset).inspect(|read| {
                            offset += *read as u64;
                        })
                    }))
                } else {
                    let shared = shared_file_state(loc);
                    let _guard = shared.io_lock.lock();
                    dst.read_from(&mut axio::read_fn(|buf| {
                        loc.entry().as_file()?.read_at(buf, offset).inspect(|read| {
                            offset += *read as u64;
                        })
                    }))
                }
            }
        }
    }

    pub fn write_at(&self, mut src: impl Read + IoBuf, mut offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => {
                cached.write_at(src, offset)
            }
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if loc.flags().contains(NodeFlags::STREAM) {
                    src.write_to(&mut axio::write_fn(|buf| {
                        file.write_at(buf, offset).inspect(|written| {
                            offset += *written as u64;
                        })
                    }))
                } else {
                    let shared = shared_file_state(loc);
                    let _guard = shared.io_lock.lock();
                    let cached_size = *shared.size.lock();
                    if file.len()? != cached_size {
                        file.set_len(cached_size)?;
                    }
                    shared.flush_dirty_pages(file)?;
                    let result = src.write_to(&mut axio::write_fn(|buf| {
                        file.write_at(buf, offset).inspect(|written| {
                            offset += *written as u64;
                        })
                    }));
                    let invalidate = shared.discard_all_pages(file, false);
                    let new_end = offset;
                    let mut size_guard = shared.size.lock();
                    if new_end > *size_guard {
                        *size_guard = new_end;
                    }
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


    pub fn append(&self, mut src: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        match self {
            Self::Cached(cached) => cached.append(src),
            Self::Direct(loc) => {
                let shared = shared_file_state(loc);
                let _guard = shared.io_lock.lock();
                let file = loc.entry().as_file()?;
                let cached_size = *shared.size.lock();
                if file.len()? != cached_size {
                    file.set_len(cached_size)?;
                }
                shared.flush_dirty_pages(file)?;
                let mut end = 0;
                let result = src.write_to(&mut axio::write_fn(|buf| {
                    file.append(buf).map(|(n, offset)| {
                        end = offset;
                        n
                    })
                }));
                let invalidate = shared.discard_all_pages(file, false);
                if result.is_ok() {
                    *shared.size.lock() = end;
                }
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

    pub fn sync(&self, data_only: bool) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.sync(data_only),
            Self::Direct(loc) => {
                let shared = shared_file_state(loc);
                let _guard = shared.io_lock.lock();
                let file = loc.entry().as_file()?;
                let cached_size = *shared.size.lock();
                if file.len()? != cached_size {
                    file.set_len(cached_size)?;
                }
                shared.flush_dirty_pages(file)?;
                file.sync(data_only)
            }
        }
    }

    pub fn set_len(&self, len: u64) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.set_len(len),
            Self::Direct(loc) => {
                let shared = shared_file_state(loc);
                let _guard = shared.io_lock.lock();
                let file = loc.entry().as_file()?;
                *shared.size.lock() = len;
                shared.flush_dirty_pages(file)?;
                let result = file.set_len(len);
                let invalidate = shared.discard_all_pages(file, false);
                match (result, invalidate) {
                    (Ok(()), Ok(())) => Ok(()),
                    (Err(err), Ok(())) => Err(err),
                    (Ok(()), Err(err)) => Err(err),
                    (Err(err), Err(_)) => Err(err),
                }
            }
        }
    }
}

/// Provides `std::fs::File`-like interface.
pub struct File {
    inner: FileBackend,
    flags: FileFlags,
    position: Option<Mutex<u64>>,
    #[cfg(feature = "times")]
    access_flags: AtomicU8,
}

impl File {
    pub fn new(inner: FileBackend, flags: FileFlags) -> Self {
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
            #[cfg(feature = "times")]
            access_flags: AtomicU8::new(0),
        }
    }

    pub fn open(context: &FsContext, path: impl AsRef<Path>) -> VfsResult<Self> {
        OpenOptions::new()
            .read(true)
            .open(context, path.as_ref())
            .and_then(OpenResult::into_file)
    }

    pub fn create(context: &FsContext, path: impl AsRef<Path>) -> VfsResult<Self> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(context, path.as_ref())
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
            if let Ok(metadata) = self.inner.location().metadata() {
                if metadata.node_type == NodeType::RegularFile {
                    let fs_name = self.inner.location().filesystem().name();
                    return fs_name != "proc" && fs_name != "devfs" && fs_name != "tmpfs";
                }
            }
        }
        false
    }

    pub fn block_size(&self) -> u64 {
        self.inner.location().metadata().map(|m| m.block_size).unwrap_or(512)
    }

    /// Reads a number of bytes starting from a given offset.
    pub fn read_at(&self, dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        self.access(FileFlags::READ)?.read_at(dst, offset)
    }

    /// Writes a number of bytes starting from a given offset.
    pub fn write_at(&self, src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        self.access(FileFlags::WRITE)?.write_at(src, offset)
    }

    /// Attempts to sync OS-internal file content and metadata to disk.
    ///
    /// If `data_only` is `true`, only the file data is synced, not the
    /// metadata.
    pub fn sync(&self, data_only: bool) -> VfsResult<()> {
        self.access(FileFlags::empty())?;
        self.inner.sync(data_only)
    }

    pub fn read(&self, dst: impl Write + IoBufMut) -> axio::Result<usize> {
        #[cfg(feature = "times")]
        {
            self.access_flags.fetch_or(1, Ordering::AcqRel);
        }
        if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock();
            self.read_at(dst, *pos).inspect(|n| {
                *pos += *n as u64;
            })
        } else {
            self.read_at(dst, 0)
        }
    }

    pub fn write(&self, src: impl Read + IoBuf) -> axio::Result<usize> {
        #[cfg(feature = "times")]
        {
            self.access_flags.fetch_or(3, Ordering::AcqRel);
        }
        if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock();
            if let Ok(f) = self.access(FileFlags::APPEND) {
                f.append(src).map(|(written, new_size)| {
                    *pos = new_size;
                    written
                })
            } else {
                self.write_at(src, *pos).inspect(|n| {
                    *pos += *n as u64;
                })
            }
        } else {
            self.write_at(src, 0)
        }
    }

    pub fn flush(&self) -> axio::Result {
        self.sync(false)
    }

    pub fn position(&self) -> Option<u64> {
        self.position.as_ref().map(|pos| *pos.lock())
    }


    #[cfg(feature = "times")]
    fn update_timestamps_on_drop(&self) {
        let flags = self.access_flags.load(Ordering::Acquire);
        if flags == 0 {
            return;
        }

        let now = axhal::time::wall_time();
        let mut update = axfs_ng_vfs::MetadataUpdate::default();
        if flags & 1 != 0 {
            update.atime = Some(now);
        }
        if flags & 2 != 0 {
            update.mtime = Some(now);
        }

        if let Err(err) = self.inner.location().update_metadata(update) {
            warn!("Failed to update file times on drop: {err:?}");
        }
    }
}

impl Drop for File {
    fn drop(&mut self) {
        #[cfg(feature = "times")]
        self.update_timestamps_on_drop();
        let _ = self.sync(false);
    }
}

impl Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> axio::Result<usize> {
        (*self).read(buf)
    }
}

impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> axio::Result<usize> {
        (*self).write(buf)
    }

    fn flush(&mut self) -> axio::Result {
        (*self).flush()
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
