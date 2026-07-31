use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{
    any::Any,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::Context,
};

use async_trait::async_trait;
use axfs_ng_vfs::{
    DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, FilesystemOps, Metadata,
    MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType, Reference, VfsError, VfsResult,
    WeakDirEntry,
};
use axpoll::{IoEvents, Pollable};
use ext4plus::{
    Ext4,
    prelude::{AsyncIterator, Ext4Error},
};
use lru::LruCache;
use spin::{Lazy, Mutex};

use super::{
    Ext4Filesystem,
    util::{into_ext4_file_type, into_vfs_err, into_vfs_type},
};

pub struct Inode {
    fs: Arc<Ext4Filesystem>,
    ino: u32,
    this: Mutex<Option<WeakDirEntry>>,
    mutation_lock: async_lock::Mutex<()>,
    metadata_cache: Arc<MetadataCacheState>,
    dir_cache: Arc<DirCacheState>,
    pub(super) is_unlinked: core::sync::atomic::AtomicBool,
}

pub(super) struct MetadataCacheState {
    generation: AtomicU64,
    cached: Mutex<Option<(u64, Metadata)>>,
    inode: Mutex<Option<(u64, ext4plus::inode::Inode)>>,
}

impl MetadataCacheState {
    fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            cached: Mutex::new(None),
            inode: Mutex::new(None),
        }
    }

    fn get(&self) -> Option<Metadata> {
        let generation = self.generation.load(Ordering::Acquire);
        let metadata = self
            .cached
            .lock()
            .as_ref()
            .filter(|(cached_generation, _)| *cached_generation == generation)
            .map(|(_, metadata)| metadata.clone());
        (self.generation.load(Ordering::Acquire) == generation)
            .then_some(metadata)
            .flatten()
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn get_inode(&self) -> Option<(u64, ext4plus::inode::Inode)> {
        let generation = self.generation.load(Ordering::Acquire);
        let inode = self
            .inode
            .lock()
            .as_ref()
            .filter(|(cached_generation, _)| *cached_generation == generation)
            .map(|(_, inode)| inode.clone());
        if self.generation.load(Ordering::Acquire) != generation {
            return None;
        }
        inode.map(|inode| (generation, inode))
    }

    fn publish(&self, generation: u64, metadata: Metadata) -> bool {
        let mut cached = self.cached.lock();
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        *cached = Some((generation, metadata));
        true
    }

    fn publish_inode(&self, generation: u64, inode: ext4plus::inode::Inode) -> bool {
        let mut cached = self.inode.lock();
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        *cached = Some((generation, inode));
        true
    }

    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        *self.cached.lock() = None;
        *self.inode.lock() = None;
    }
}

struct CachedDirEntry {
    name: String,
    inode_num: u32,
    node_type: NodeType,
}

struct DirSnapshot {
    entries: Vec<CachedDirEntry>,
    lookup_order: Vec<usize>,
}

impl DirSnapshot {
    fn new(entries: Vec<CachedDirEntry>) -> Self {
        let mut lookup_order = (0..entries.len()).collect::<Vec<_>>();
        lookup_order.sort_unstable_by(|left, right| {
            entries[*left]
                .name
                .as_str()
                .cmp(entries[*right].name.as_str())
        });
        Self {
            entries,
            lookup_order,
        }
    }

    fn lookup(&self, name: &str) -> Option<CachedLookupEntry> {
        self.lookup_order
            .binary_search_by(|index| self.entries[*index].name.as_str().cmp(name))
            .ok()
            .map(|position| {
                let entry = &self.entries[self.lookup_order[position]];
                CachedLookupEntry {
                    inode_num: entry.inode_num,
                    node_type: entry.node_type,
                }
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CachedLookupEntry {
    inode_num: u32,
    node_type: NodeType,
}

const DIR_LOOKUP_CACHE_MAX_ENTRIES: usize = 256;
const DIR_SNAPSHOT_PROMOTION_LOOKUPS: usize = 8;

struct DirCacheState {
    snapshot_generation: AtomicU64,
    lookup_generation: AtomicU64,
    uncached_lookups: AtomicUsize,
    snapshot: Mutex<Option<(u64, Arc<DirSnapshot>)>>,
    snapshot_build: async_lock::Mutex<()>,
    lookup: Mutex<LruCache<String, Option<CachedLookupEntry>>>,
}

impl DirCacheState {
    fn new() -> Self {
        Self {
            snapshot_generation: AtomicU64::new(0),
            lookup_generation: AtomicU64::new(0),
            uncached_lookups: AtomicUsize::new(0),
            snapshot: Mutex::new(None),
            snapshot_build: async_lock::Mutex::new(()),
            lookup: Mutex::new(LruCache::unbounded()),
        }
    }

    fn get(&self) -> Option<Arc<DirSnapshot>> {
        let generation = self.snapshot_generation.load(Ordering::Acquire);
        let snapshot = self
            .snapshot
            .lock()
            .as_ref()
            .filter(|(snapshot_generation, _)| *snapshot_generation == generation)
            .map(|(_, snapshot)| snapshot.clone());
        (self.snapshot_generation.load(Ordering::Acquire) == generation)
            .then_some(snapshot)
            .flatten()
    }

    fn generation(&self) -> u64 {
        self.snapshot_generation.load(Ordering::Acquire)
    }

    fn publish(&self, generation: u64, snapshot: Arc<DirSnapshot>) -> bool {
        let mut cached = self.snapshot.lock();
        if self.snapshot_generation.load(Ordering::Acquire) != generation {
            return false;
        }
        *cached = Some((generation, snapshot));
        self.uncached_lookups
            .store(DIR_SNAPSHOT_PROMOTION_LOOKUPS, Ordering::Relaxed);
        true
    }

    fn note_uncached_lookup(&self) -> bool {
        let previous = self
            .uncached_lookups
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                Some(count.saturating_add(1))
            })
            .expect("uncached lookup count update cannot fail");
        previous.saturating_add(1) >= DIR_SNAPSHOT_PROMOTION_LOOKUPS
    }

    fn get_lookup(&self, name: &str) -> Option<Option<CachedLookupEntry>> {
        let generation = self.lookup_generation.load(Ordering::Acquire);
        let entry = self.lookup.lock().get(name).copied();
        (self.lookup_generation.load(Ordering::Acquire) == generation)
            .then_some(entry)
            .flatten()
    }

    fn lookup_generation(&self) -> u64 {
        self.lookup_generation.load(Ordering::Acquire)
    }

    fn publish_lookup(
        &self,
        generation: u64,
        name: String,
        entry: Option<CachedLookupEntry>,
    ) -> bool {
        let mut lookup = self.lookup.lock();
        if self.lookup_generation.load(Ordering::Acquire) != generation {
            return false;
        }
        lookup.put(name, entry);
        while lookup.len() > DIR_LOOKUP_CACHE_MAX_ENTRIES {
            lookup.pop_lru();
        }
        true
    }

    fn update_lookup(&self, name: String, entry: Option<CachedLookupEntry>) {
        let mut lookup = self.lookup.lock();
        self.lookup_generation.fetch_add(1, Ordering::AcqRel);
        lookup.put(name, entry);
        while lookup.len() > DIR_LOOKUP_CACHE_MAX_ENTRIES {
            lookup.pop_lru();
        }
    }

    fn invalidate_snapshot(&self) {
        let mut snapshot = self.snapshot.lock();
        self.snapshot_generation.fetch_add(1, Ordering::AcqRel);
        *snapshot = None;
        self.uncached_lookups.store(0, Ordering::Relaxed);
    }

    fn invalidate(&self) {
        let mut snapshot = self.snapshot.lock();
        let mut lookup = self.lookup.lock();
        self.snapshot_generation.fetch_add(1, Ordering::AcqRel);
        self.lookup_generation.fetch_add(1, Ordering::AcqRel);
        *snapshot = None;
        self.uncached_lookups.store(0, Ordering::Relaxed);
        lookup.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct DirCacheKey {
    fs_id: usize,
    ino: u32,
}

static DIR_CACHE_REGISTRY: Lazy<Mutex<BTreeMap<DirCacheKey, Weak<DirCacheState>>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));

fn dir_cache_key(fs: &Arc<Ext4Filesystem>, ino: u32) -> DirCacheKey {
    DirCacheKey {
        fs_id: Arc::as_ptr(fs) as usize,
        ino,
    }
}

fn dir_cache_state(fs: &Arc<Ext4Filesystem>, ino: u32) -> Arc<DirCacheState> {
    let key = dir_cache_key(fs, ino);
    let mut registry = DIR_CACHE_REGISTRY.lock();
    registry.retain(|_, state| state.strong_count() > 0);
    if let Some(state) = registry.get(&key).and_then(Weak::upgrade) {
        return state;
    }

    let state = Arc::new(DirCacheState::new());
    registry.insert(key, Arc::downgrade(&state));
    state
}

pub(crate) fn cleanup_dir_cache_registry(fs_id: usize) {
    let mut registry = DIR_CACHE_REGISTRY.lock();
    registry.retain(|key, state| key.fs_id != fs_id && state.strong_count() > 0);
}

fn invalidate_dir_cache(fs: &Arc<Ext4Filesystem>, ino: u32) {
    let key = dir_cache_key(fs, ino);
    if let Some(state) = DIR_CACHE_REGISTRY.lock().get(&key).and_then(Weak::upgrade) {
        state.invalidate();
    }
}

fn invalidate_dir_snapshot(fs: &Arc<Ext4Filesystem>, ino: u32) {
    let key = dir_cache_key(fs, ino);
    if let Some(state) = DIR_CACHE_REGISTRY.lock().get(&key).and_then(Weak::upgrade) {
        state.invalidate_snapshot();
    }
}

fn invalidate_inode_metadata_cache(fs: &Arc<Ext4Filesystem>, ino: u32) {
    let mut states = Vec::new();
    {
        let mut active = fs.active_inodes.lock();
        if let Some(inodes) = active.get_mut(&ino) {
            inodes.retain(|inode| inode.strong_count() > 0);
            states.extend(
                inodes
                    .iter()
                    .filter_map(Weak::upgrade)
                    .map(|inode| inode.metadata_cache.clone()),
            );
        }
    }
    if let Some(cached) = fs.metadata_caches.lock().get(&ino).cloned()
        && !states.iter().any(|state| Arc::ptr_eq(state, &cached))
    {
        states.push(cached);
    }
    for cached in states {
        cached.invalidate();
    }
}

fn metadata_cache_state(fs: &Arc<Ext4Filesystem>, ino: u32) -> Arc<MetadataCacheState> {
    const MAX_ENTRIES: usize = 4096;

    let mut caches = fs.metadata_caches.lock();
    if let Some(cached) = caches.get(&ino) {
        return cached.clone();
    }

    let cached = Arc::new(MetadataCacheState::new());
    caches.put(ino, cached.clone());
    while caches.len() > MAX_ENTRIES {
        caches.pop_lru();
    }
    cached
}

impl Inode {
    pub(crate) fn new(fs: Arc<Ext4Filesystem>, ino: u32, this: Option<WeakDirEntry>) -> Arc<Self> {
        let mut active = fs.active_inodes.lock();
        if let Some(list) = active.get_mut(&ino) {
            list.retain(|w| w.strong_count() > 0);
            for w in list.iter() {
                if let Some(inode) = w.upgrade() {
                    if this.is_some() {
                        let mut guard = inode.this.lock();
                        let need_update = match &*guard {
                            Some(weak) => weak.upgrade().is_none(),
                            None => true,
                        };
                        if need_update {
                            *guard = this;
                        }
                    }
                    return inode;
                }
            }
        }

        log::debug!("ext4: Inode::new ino={}", ino);
        let metadata_cache = metadata_cache_state(&fs, ino);
        let dir_cache = dir_cache_state(&fs, ino);
        let inode = Arc::new(Self {
            fs: fs.clone(),
            ino,
            this: Mutex::new(this),
            mutation_lock: async_lock::Mutex::new(()),
            metadata_cache,
            dir_cache,
            is_unlinked: core::sync::atomic::AtomicBool::new(false),
        });
        active.entry(ino).or_default().push(Arc::downgrade(&inode));
        inode
    }

    fn create_entry(
        &self,
        inode_num: u32,
        node_type: NodeType,
        is_dir: bool,
        name: impl Into<String>,
    ) -> DirEntry {
        let reference = Reference::new(self.this.lock().clone(), name.into());
        if is_dir {
            DirEntry::new_dir(
                |child_this| DirNode::new(Inode::new(self.fs.clone(), inode_num, Some(child_this))),
                reference,
            )
        } else {
            DirEntry::new_file(
                FileNode::new(Inode::new(self.fs.clone(), inode_num, None)),
                node_type,
                reference,
            )
        }
    }

    async fn lock_mutation_set<'a>(inodes: &[&'a Self]) -> Vec<async_lock::MutexGuard<'a, ()>> {
        let mut ordered = inodes.to_vec();
        ordered.sort_unstable_by_key(|inode| (inode.ino, *inode as *const Self as usize));
        ordered.dedup_by(|left, right| core::ptr::eq(*left, *right));

        let mut guards = Vec::with_capacity(ordered.len());
        for inode in ordered {
            guards.push(inode.mutation_lock.lock().await);
        }
        guards
    }

    /// Marks active inode instances outside the caller's local handle as unlinked.
    ///
    /// Callers must hold exactly one strong reference in `local`: `unlink` uses `child`,
    /// while `rename` uses `dst_node`. `weak.upgrade()` creates the second reference, so
    /// a strong count greater than two is the signal for another active local handle.
    fn mark_unlinked_and_has_external_refs(local: &Arc<Self>) -> bool {
        let mut active = local.fs.active_inodes.lock();
        let mut has_external = false;
        if let Some(list) = active.get_mut(&local.ino) {
            list.retain(|weak| weak.strong_count() > 0);
            for weak in list.iter() {
                let Some(inode) = weak.upgrade() else {
                    continue;
                };
                let is_local = Arc::ptr_eq(&inode, local);
                let is_external = !is_local || Arc::strong_count(&inode) > 2;
                if is_external {
                    inode.is_unlinked.store(true, Ordering::Relaxed);
                    has_external = true;
                }
            }
        }
        if !has_external {
            active.remove(&local.ino);
        }
        has_external
    }

    fn entry_from_cached_lookup(
        &self,
        name: &str,
        cached: Option<CachedLookupEntry>,
    ) -> VfsResult<DirEntry> {
        match cached {
            Some(entry) => Ok(self.create_entry(
                entry.inode_num,
                entry.node_type,
                entry.node_type == NodeType::Directory,
                name,
            )),
            None => Err(VfsError::NotFound),
        }
    }

    fn invalidate_snapshot(&self, dir_ino: u32) {
        if dir_ino == self.ino {
            self.dir_cache.invalidate_snapshot();
        } else {
            invalidate_dir_snapshot(&self.fs, dir_ino);
        }
    }

    fn invalidate_metadata(&self) {
        self.metadata_cache.invalidate();
    }

    async fn build_dir_snapshot_uncached(
        &self,
        fs: &Ext4,
        dir_ino: u32,
    ) -> VfsResult<Arc<DirSnapshot>> {
        let mut entries = Vec::new();
        let total_inodes = fs.superblock().num_block_groups() as u64
            * fs.superblock().inodes_per_block_group().get() as u64;

        let (_, dir_inode) = self.read_inode_cached(fs, dir_ino).await?;
        let dir = ext4plus::dir::Dir::open_inode(fs, dir_inode).map_err(into_vfs_err)?;
        let read_dir = dir.read_dir().map_err(into_vfs_err)?;

        let mut read_dir = read_dir;
        while let Some(entry_res) = read_dir.next().await {
            let entry = entry_res.map_err(into_vfs_err)?;
            if entry.inode.get() == 0 || entry.inode.get() as u64 > total_inodes {
                log::error!(
                    "ext4: skip invalid dir entry ino={} in dir ino={}",
                    entry.inode,
                    dir_ino
                );
                return Err(VfsError::InvalidData);
            }
            let name = match entry.file_name().as_str() {
                Ok(name) => String::from(name),
                Err(_) => alloc::format!("{}", entry.file_name().display()),
            };

            let de_type = match entry.file_type() {
                Ok(t) => t,
                Err(_) => self
                    .read_inode_cached(fs, entry.inode.get())
                    .await?
                    .1
                    .file_type(),
            };
            let node_type = into_vfs_type(de_type);

            entries.push(CachedDirEntry {
                name,
                inode_num: entry.inode.get(),
                node_type,
            });
        }

        Ok(Arc::new(DirSnapshot::new(entries)))
    }

    async fn dir_snapshot(&self, fs: &Ext4) -> VfsResult<Arc<DirSnapshot>> {
        if let Some(snapshot) = self.dir_cache.get() {
            return Ok(snapshot);
        }

        let _build_guard = self.dir_cache.snapshot_build.lock().await;
        loop {
            if let Some(snapshot) = self.dir_cache.get() {
                return Ok(snapshot);
            }
            let generation = self.dir_cache.generation();
            let snapshot = self.build_dir_snapshot_uncached(fs, self.ino).await?;
            if self.dir_cache.publish(generation, snapshot.clone()) {
                return Ok(snapshot);
            }
        }
    }

    async fn build_dir_snapshot(&self, fs: &Ext4, dir_ino: u32) -> VfsResult<Arc<DirSnapshot>> {
        if dir_ino == self.ino {
            self.dir_snapshot(fs).await
        } else {
            self.build_dir_snapshot_uncached(fs, dir_ino).await
        }
    }

    fn validate_inode_num(&self, fs: &Ext4, inode_num: u32) -> VfsResult<()> {
        let total_inodes = fs.superblock().num_block_groups() as u64
            * fs.superblock().inodes_per_block_group().get() as u64;
        if inode_num == 0 || inode_num as u64 > total_inodes {
            log::error!(
                "ext4: invalid inode {} (total={}) on cached inode {}",
                inode_num,
                total_inodes,
                self.ino
            );
            return Err(VfsError::InvalidData);
        }
        Ok(())
    }

    async fn read_inode_cached(
        &self,
        fs: &Ext4,
        inode_num: u32,
    ) -> VfsResult<(u64, ext4plus::inode::Inode)> {
        self.validate_inode_num(fs, inode_num)?;
        let cache = if inode_num == self.ino {
            self.metadata_cache.clone()
        } else {
            metadata_cache_state(&self.fs, inode_num)
        };

        loop {
            if let Some(inode) = cache.get_inode() {
                return Ok(inode);
            }

            let generation = cache.generation();
            let index = core::num::NonZeroU32::new(inode_num).ok_or(VfsError::InvalidData)?;
            let inode = ext4plus::inode::Inode::read(fs, index)
                .await
                .map_err(into_vfs_err)?;
            if cache.publish_inode(generation, inode.clone()) {
                return Ok((generation, inode));
            }
        }
    }

    async fn dir_has_children(&self, fs: &Ext4, dir_ino: u32) -> VfsResult<bool> {
        let snapshot = self.build_dir_snapshot(fs, dir_ino).await?;
        Ok(snapshot
            .entries
            .iter()
            .any(|entry| entry.name != "." && entry.name != ".."))
    }
}

#[async_trait]
impl NodeOps for Inode {
    fn inode(&self) -> u64 {
        self.ino as u64
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        loop {
            if let Some(metadata) = self.metadata_cache.get() {
                return Ok(metadata);
            }

            let _mutation_guard = self.mutation_lock.lock().await;
            if let Some(metadata) = self.metadata_cache.get() {
                return Ok(metadata);
            }

            let fs = &self.fs.inner;
            let (generation, inode) = self.read_inode_cached(fs, self.ino).await?;
            let file_type = inode.file_type();
            let perm = inode.mode().bits() & 0x0fff;
            let metadata = Metadata {
                device: 0,
                inode: self.ino as u64,
                nlink: inode.links_count() as u64,
                mode: NodePermission::from_bits_truncate(perm),
                node_type: into_vfs_type(file_type),
                uid: inode.uid(),
                gid: inode.gid(),
                size: inode.size_in_bytes(),
                block_size: self.fs.block_size as u64,
                blocks: inode.fs_blocks(fs).unwrap_or(0),
                rdev: Default::default(),
                atime: inode.atime(),
                mtime: inode.mtime(),
                ctime: inode.ctime(),
            };
            if self.metadata_cache.publish(generation, metadata.clone()) {
                return Ok(metadata);
            }
        }
    }

    async fn len(&self) -> VfsResult<u64> {
        let fs = &self.fs.inner;
        let (_, inode) = self.read_inode_cached(fs, self.ino).await?;
        Ok(inode.size_in_bytes())
    }

    async fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut write_scope = self.fs.write_scope(&[self.ino as u64]);
        write_scope
            .run(async {
                self.invalidate_metadata();
                let mut inode = ext4plus::inode::Inode::read(&fs, idx)
                    .await
                    .map_err(into_vfs_err)?;
                if let Some(mode) = update.mode {
                    let perm = mode.bits() & 0x0fff;
                    let kind = inode.mode().bits() & 0xf000;
                    inode
                        .set_mode(ext4plus::inode::InodeMode::from_bits_truncate(kind | perm))
                        .map_err(into_vfs_err)?;
                }
                if let Some((uid, gid)) = update.owner {
                    inode.set_uid(uid);
                    inode.set_gid(gid);
                }
                if let Some(atime) = update.atime {
                    inode.set_atime(atime);
                }
                if let Some(mtime) = update.mtime {
                    inode.set_mtime(mtime);
                }
                if cfg!(feature = "times") {
                    inode.set_ctime(axhal::time::wall_time());
                }
                let result = inode.write(&fs).await.map_err(into_vfs_err);
                self.invalidate_metadata();
                result
            })
            .await
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        &*self.fs
    }

    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        self.fs.flush_inode(self.ino).await
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::BLOCKING
    }
}

#[async_trait]
impl FileNodeOps for Inode {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let fs = &self.fs.inner;
        let (_, inode) = self.read_inode_cached(fs, self.ino).await?;
        if inode.file_type().is_symlink() && inode.blocks() == 0 {
            let target_path = inode.symlink_target(&fs).await.map_err(into_vfs_err)?;
            let target_bytes = target_path.as_ref();
            let size = target_bytes.len();
            if offset >= size as u64 {
                return Ok(0);
            }
            let offset = offset as usize;
            let available = size - offset;
            let len = available.min(buf.len());
            buf[..len].copy_from_slice(&target_bytes[offset..offset + len]);
            return Ok(len);
        }
        ext4plus::file::read_at(&fs, &inode, buf, offset)
            .await
            .map_err(into_vfs_err)
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        log::debug!("ext4 inode::write_at: offset={}, len={}", offset, buf.len());
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut write_scope = self.fs.write_scope(&[self.ino as u64]);
        write_scope
            .run(async {
                self.invalidate_metadata();
                let mut inode = ext4plus::inode::Inode::read(&fs, idx)
                    .await
                    .map_err(into_vfs_err)?;
                let written = ext4plus::file::write_at(&fs, &mut inode, buf, offset)
                    .await
                    .map_err(into_vfs_err);
                self.invalidate_metadata();
                let written = written?;
                log::debug!("ext4 inode::write_at done: written={}", written);
                Ok(written)
            })
            .await
    }

    async fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut write_scope = self.fs.write_scope(&[self.ino as u64]);
        write_scope
            .run(async {
                self.invalidate_metadata();
                let mut inode = ext4plus::inode::Inode::read(&fs, idx)
                    .await
                    .map_err(into_vfs_err)?;
                let length = inode.size_in_bytes();
                let written = ext4plus::file::write_at(&fs, &mut inode, buf, length)
                    .await
                    .map_err(into_vfs_err);
                self.invalidate_metadata();
                let written = written?;
                Ok((written, length + written as u64))
            })
            .await
    }

    async fn set_len(&self, len: u64) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut write_scope = self.fs.write_scope(&[self.ino as u64]);
        write_scope
            .run(async {
                self.invalidate_metadata();
                let mut inode = ext4plus::inode::Inode::read(&fs, idx)
                    .await
                    .map_err(into_vfs_err)?;
                let old_len = inode.size_in_bytes();
                if len == old_len {
                    return Ok(());
                }
                let result = ext4plus::file::truncate(&fs, &mut inode, len)
                    .await
                    .map_err(into_vfs_err);
                self.invalidate_metadata();
                result
            })
            .await
    }

    async fn set_symlink(&self, target: &str) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut write_scope = self.fs.write_scope(&[self.ino as u64]);
        write_scope
            .run(async {
                self.invalidate_metadata();
                let mut inode = ext4plus::inode::Inode::read(&fs, idx)
                    .await
                    .map_err(into_vfs_err)?;
                let bytes = target.as_bytes();
                let written = async {
                    ext4plus::file::truncate(&fs, &mut inode, 0)
                        .await
                        .map_err(into_vfs_err)?;
                    ext4plus::file::write_at(&fs, &mut inode, bytes, 0)
                        .await
                        .map_err(into_vfs_err)
                }
                .await;
                self.invalidate_metadata();
                let written = written?;
                if written != bytes.len() {
                    return Err(VfsError::StorageFull);
                }
                Ok(())
            })
            .await
    }
}

impl Pollable for Inode {
    fn poll(&self) -> IoEvents {
        IoEvents::IN | IoEvents::OUT
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}

#[async_trait]
impl DirNodeOps for Inode {
    fn is_cacheable(&self) -> bool {
        true
    }

    async fn read_dir(
        &self,
        offset: u64,
        sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let snapshot = self.dir_snapshot(&fs).await?;
        let mut count = 0usize;
        for (index, entry) in snapshot.entries.iter().enumerate().skip(offset as usize) {
            if !sink.accept(
                &entry.name,
                entry.inode_num as u64,
                entry.node_type,
                (index + 1) as u64,
            ) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let name_ref =
            ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;

        if let Some(cached) = self.dir_cache.get_lookup(name) {
            return self.entry_from_cached_lookup(name, cached);
        }
        let generation = self.dir_cache.lookup_generation();

        if let Some(snapshot) = self.dir_cache.get() {
            let cached = snapshot.lookup(name);
            self.dir_cache
                .publish_lookup(generation, String::from(name), cached);
            return self.entry_from_cached_lookup(name, cached);
        }

        if self.dir_cache.note_uncached_lookup() {
            let snapshot = self.dir_snapshot(fs).await?;
            let cached = snapshot.lookup(name);
            self.dir_cache
                .publish_lookup(generation, String::from(name), cached);
            return self.entry_from_cached_lookup(name, cached);
        }

        let (_, dir_inode) = self.read_inode_cached(fs, self.ino).await?;
        let dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;
        match dir.get_entry(name_ref).await {
            Ok(target_inode) => {
                let target_type = target_inode.file_type();
                let cached = CachedLookupEntry {
                    inode_num: target_inode.index.get(),
                    node_type: into_vfs_type(target_type),
                };
                self.dir_cache
                    .publish_lookup(generation, String::from(name), Some(cached));
                self.entry_from_cached_lookup(name, Some(cached))
            }
            Err(Ext4Error::NotFound) => {
                self.dir_cache
                    .publish_lookup(generation, String::from(name), None);
                Err(VfsError::NotFound)
            }
            Err(e) => Err(into_vfs_err(e)),
        }
    }

    async fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let _directory_guard = self.mutation_lock.lock().await;
        let name_ref =
            ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;

        match self.dir_cache.get_lookup(name) {
            Some(Some(_)) => return Err(VfsError::AlreadyExists),
            Some(None) => {}
            None => {
                let generation = self.dir_cache.lookup_generation();
                let (_, dir_inode) = self.read_inode_cached(fs, self.ino).await?;
                let dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;
                match dir.get_entry(name_ref).await {
                    Ok(target) => {
                        let cached = CachedLookupEntry {
                            inode_num: target.index.get(),
                            node_type: into_vfs_type(target.file_type()),
                        };
                        self.dir_cache
                            .publish_lookup(generation, String::from(name), Some(cached));
                        return Err(VfsError::AlreadyExists);
                    }
                    Err(Ext4Error::NotFound) => {
                        self.dir_cache
                            .publish_lookup(generation, String::from(name), None);
                    }
                    Err(e) => return Err(into_vfs_err(e)),
                }
            }
        }

        let file_type = into_ext4_file_type(node_type)?;
        let mode = ext4plus::inode::InodeMode::from_bits_truncate(
            into_ext4_type_bits(node_type) | permission.bits(),
        );
        let options = ext4plus::inode::InodeCreationOptions {
            file_type,
            mode,
            uid: 0,
            gid: 0,
            time: axhal::time::wall_time(),
            flags: ext4plus::inode::InodeFlags::empty(),
        };

        let mut write_scope = self.fs.write_scope(&[self.ino as u64]);
        let write_scope_handle = write_scope.handle();
        write_scope
            .run(async {
                let mut new_inode = fs.create_inode(options).await.map_err(into_vfs_err)?;
                let new_inode_idx = new_inode.index;
                write_scope_handle.include_owner(new_inode_idx.get() as u64);

                let entry_res = async {
                    let dir_idx =
                        core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
                    let parent_inode = ext4plus::inode::Inode::read(&fs, dir_idx)
                        .await
                        .map_err(into_vfs_err)?;
                    let mut dir =
                        ext4plus::dir::Dir::open_inode(&fs, parent_inode).map_err(into_vfs_err)?;

                    if node_type == NodeType::Directory {
                        let new_dir = ext4plus::dir::Dir::init(fs.clone(), new_inode, dir_idx)
                            .await
                            .map_err(into_vfs_err)?;
                        new_inode = new_dir.inode().clone();
                    }

                    let name_ref = ext4plus::DirEntryName::try_from(name)
                        .map_err(|_| VfsError::InvalidInput)?;
                    self.invalidate_metadata();
                    let link_result = dir
                        .link(name_ref, &mut new_inode)
                        .await
                        .map_err(into_vfs_err);
                    self.invalidate_metadata();
                    invalidate_inode_metadata_cache(&self.fs, new_inode.index.get());
                    if link_result.is_err() {
                        self.dir_cache.invalidate();
                    }
                    link_result?;

                    self.invalidate_snapshot(self.ino);
                    self.dir_cache.update_lookup(
                        String::from(name),
                        Some(CachedLookupEntry {
                            inode_num: new_inode.index.get(),
                            node_type,
                        }),
                    );
                    Ok(self.create_entry(
                        new_inode.index.get(),
                        node_type,
                        node_type == NodeType::Directory,
                        name,
                    ))
                }
                .await;

                match entry_res {
                    Ok(entry) => Ok(entry),
                    Err(e) => {
                        if let Ok(inode) = ext4plus::inode::Inode::read(&fs, new_inode_idx).await {
                            let _ = fs.delete_file(inode).await;
                        }
                        Err(e)
                    }
                }
            })
            .await
    }

    async fn link(&self, name: &str, node: &DirEntry) -> VfsResult<DirEntry> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let child: Arc<Self> = node.downcast().map_err(|_| VfsError::InvalidInput)?;
        if !Arc::ptr_eq(&self.fs, &child.fs) {
            return Err(VfsError::CrossesDevices);
        }
        let mutation_nodes = [self, child.as_ref()];
        let _mutation_guards = Self::lock_mutation_set(&mutation_nodes).await;
        let mut write_scope = self.fs.write_scope(&[self.ino as u64, child.ino as u64]);
        write_scope
            .run(async {
                let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
                let dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx)
                    .await
                    .map_err(into_vfs_err)?;
                let mut dir =
                    ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;

                let child_idx =
                    core::num::NonZeroU32::new(node.inode() as u32).ok_or(VfsError::InvalidData)?;
                let mut child_inode = ext4plus::inode::Inode::read(&fs, child_idx)
                    .await
                    .map_err(into_vfs_err)?;

                if child_inode.file_type() == ext4plus::FileType::Directory {
                    return Err(VfsError::OperationNotSupported);
                }

                let name_ref =
                    ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
                self.invalidate_metadata();
                invalidate_inode_metadata_cache(&self.fs, child_inode.index.get());
                let link_result = dir
                    .link(name_ref, &mut child_inode)
                    .await
                    .map_err(into_vfs_err);
                self.invalidate_metadata();
                invalidate_inode_metadata_cache(&self.fs, child_inode.index.get());
                if link_result.is_err() {
                    self.dir_cache.invalidate();
                }
                link_result?;

                self.invalidate_snapshot(self.ino);
                let cached = CachedLookupEntry {
                    inode_num: child_inode.index.get(),
                    node_type: into_vfs_type(child_inode.file_type()),
                };
                self.dir_cache
                    .update_lookup(String::from(name), Some(cached));
                Ok(self.create_entry(
                    cached.inode_num,
                    cached.node_type,
                    child_inode.file_type() == ext4plus::FileType::Directory,
                    name,
                ))
            })
            .await
    }

    async fn unlink(&self, name: &str) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        loop {
            let observed_child_ino = match self.dir_cache.get_lookup(name) {
                Some(Some(cached)) => cached.inode_num,
                Some(None) => return Err(VfsError::NotFound),
                None => {
                    let observation_nodes = [self];
                    let observation_guards = Self::lock_mutation_set(&observation_nodes).await;
                    let observed_dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx)
                        .await
                        .map_err(into_vfs_err)?;
                    let observed_dir = ext4plus::dir::Dir::open_inode(&fs, observed_dir_inode)
                        .map_err(into_vfs_err)?;
                    let observed_name = ext4plus::DirEntryName::try_from(name)
                        .map_err(|_| VfsError::InvalidInput)?;
                    let observed_child = observed_dir
                        .get_entry(observed_name)
                        .await
                        .map_err(into_vfs_err)?;
                    let ino = observed_child.index.get();
                    drop(observation_guards);
                    ino
                }
            };

            let child = Inode::new(self.fs.clone(), observed_child_ino, None);
            let mutation_nodes = [self, child.as_ref()];
            let _mutation_guards = Self::lock_mutation_set(&mutation_nodes).await;

            let dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx)
                .await
                .map_err(into_vfs_err)?;
            let mut dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;
            let name_ref =
                ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
            let child_inode = dir.get_entry(name_ref).await.map_err(into_vfs_err)?;
            let child_ino = child_inode.index.get();
            if child_ino != observed_child_ino {
                self.dir_cache.update_lookup(
                    String::from(name),
                    Some(CachedLookupEntry {
                        inode_num: child_ino,
                        node_type: into_vfs_type(child_inode.file_type()),
                    }),
                );
                continue;
            }
            if child_inode.file_type() == ext4plus::FileType::Directory
                && self.dir_has_children(&fs, child_ino).await?
            {
                return Err(VfsError::DirectoryNotEmpty);
            }

            let is_dir = child_inode.file_type() == ext4plus::FileType::Directory;
            let mut write_scope = self.fs.write_scope(&[self.ino as u64, child_ino as u64]);
            return write_scope
                .run(async {
                    self.invalidate_metadata();
                    invalidate_inode_metadata_cache(&self.fs, child_ino);
                    let child_inode = dir
                        .unlink(name_ref, child_inode)
                        .await
                        .map_err(into_vfs_err);
                    self.invalidate_metadata();
                    invalidate_inode_metadata_cache(&self.fs, child_ino);
                    if child_inode.is_err() {
                        self.dir_cache.invalidate();
                    }
                    let child_inode = child_inode?;
                    self.invalidate_snapshot(self.ino);
                    self.dir_cache.update_lookup(String::from(name), None);
                    if is_dir {
                        invalidate_dir_cache(&self.fs, child_ino);
                    }
                    if child_inode.links_count() == 0 {
                        let has_other_active = Self::mark_unlinked_and_has_external_refs(&child);
                        if !has_other_active {
                            log::debug!(
                                "ext4: unlink deleting unlinked file (ino {}) immediately because \
                                 no active references",
                                child_ino
                            );
                            child.is_unlinked.store(true, Ordering::Relaxed);
                            fs.delete_file(child_inode).await.map_err(into_vfs_err)?;
                            child.is_unlinked.store(false, Ordering::Relaxed);
                            crate::invalidate_file_cache(
                                Arc::as_ptr(&self.fs) as usize,
                                child_ino as u64,
                            );
                        }
                    }
                    Ok(())
                })
                .await;
        }
    }

    async fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        let dst_dir: Arc<Self> = dst_dir.downcast().map_err(|_| VfsError::InvalidInput)?;
        if !Arc::ptr_eq(&self.fs, &dst_dir.fs) {
            return Err(VfsError::CrossesDevices);
        }
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        self.validate_inode_num(&fs, dst_dir.ino)?;
        let src_dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let dst_dir_idx = core::num::NonZeroU32::new(dst_dir.ino).ok_or(VfsError::InvalidData)?;
        loop {
            let observation_nodes = [self, dst_dir.as_ref()];
            let observation_guards = Self::lock_mutation_set(&observation_nodes).await;
            let observed_src_dir_inode = ext4plus::inode::Inode::read(&fs, src_dir_idx)
                .await
                .map_err(into_vfs_err)?;
            let observed_src_dir = ext4plus::dir::Dir::open_inode(&fs, observed_src_dir_inode)
                .map_err(into_vfs_err)?;
            let observed_src_name =
                ext4plus::DirEntryName::try_from(src_name).map_err(|_| VfsError::InvalidInput)?;
            let observed_src_inode = observed_src_dir
                .get_entry(observed_src_name)
                .await
                .map_err(into_vfs_err)?;
            let observed_src_ino = observed_src_inode.index.get();

            let observed_dst_dir_inode = ext4plus::inode::Inode::read(&fs, dst_dir_idx)
                .await
                .map_err(into_vfs_err)?;
            let observed_dst_dir = ext4plus::dir::Dir::open_inode(&fs, observed_dst_dir_inode)
                .map_err(into_vfs_err)?;
            let observed_dst_name =
                ext4plus::DirEntryName::try_from(dst_name).map_err(|_| VfsError::InvalidInput)?;
            let observed_dst_ino = match observed_dst_dir.get_entry(observed_dst_name).await {
                Ok(inode) => Some(inode.index.get()),
                Err(Ext4Error::NotFound) => None,
                Err(error) => return Err(into_vfs_err(error)),
            };
            drop(observation_guards);

            let src_node = Inode::new(self.fs.clone(), observed_src_ino, None);
            let dst_node = observed_dst_ino.map(|ino| Inode::new(self.fs.clone(), ino, None));
            let mut mutation_nodes = vec![self, dst_dir.as_ref(), src_node.as_ref()];
            if let Some(dst_node) = dst_node.as_ref() {
                mutation_nodes.push(dst_node.as_ref());
            }
            let _mutation_guards = Self::lock_mutation_set(&mutation_nodes).await;

            let src_dir_inode = ext4plus::inode::Inode::read(&fs, src_dir_idx)
                .await
                .map_err(into_vfs_err)?;
            let mut src_dir =
                ext4plus::dir::Dir::open_inode(&fs, src_dir_inode).map_err(into_vfs_err)?;
            let src_name_ref =
                ext4plus::DirEntryName::try_from(src_name).map_err(|_| VfsError::InvalidInput)?;
            let mut src_inode = src_dir
                .get_entry(src_name_ref)
                .await
                .map_err(into_vfs_err)?;

            let dst_dir_inode = ext4plus::inode::Inode::read(&fs, dst_dir_idx)
                .await
                .map_err(into_vfs_err)?;
            let mut dst_dir_obj =
                ext4plus::dir::Dir::open_inode(&fs, dst_dir_inode).map_err(into_vfs_err)?;
            let dst_name_ref =
                ext4plus::DirEntryName::try_from(dst_name).map_err(|_| VfsError::InvalidInput)?;
            let dst_inode = match dst_dir_obj.get_entry(dst_name_ref).await {
                Ok(inode) => Some(inode),
                Err(Ext4Error::NotFound) => None,
                Err(error) => return Err(into_vfs_err(error)),
            };
            if src_inode.index.get() != observed_src_ino
                || dst_inode.as_ref().map(|inode| inode.index.get()) != observed_dst_ino
            {
                continue;
            }
            if dst_inode
                .as_ref()
                .is_some_and(|dst_inode| dst_inode.index == src_inode.index)
            {
                return Ok(());
            }
            if src_inode.file_type() == ext4plus::FileType::Directory && self.ino != dst_dir.ino {
                return Err(VfsError::OperationNotSupported);
            }

            let mut write_owners = vec![
                self.ino as u64,
                dst_dir.ino as u64,
                src_inode.index.get() as u64,
            ];
            if let Some(dst_inode) = dst_inode.as_ref() {
                write_owners.push(dst_inode.index.get() as u64);
            }
            let mut write_scope = self.fs.write_scope(&write_owners);
            return write_scope
                .run(async {
                    if let (Some(dst_inode), Some(local_dst)) = (dst_inode, dst_node.as_ref()) {
                        let src_is_dir = src_inode.file_type() == ext4plus::FileType::Directory;
                        let dst_is_dir = dst_inode.file_type() == ext4plus::FileType::Directory;
                        if src_is_dir != dst_is_dir {
                            if dst_is_dir {
                                return Err(VfsError::IsADirectory);
                            } else {
                                return Err(VfsError::NotADirectory);
                            }
                        }

                        if dst_inode.file_type() == ext4plus::FileType::Directory
                            && self.dir_has_children(&fs, dst_inode.index.get()).await?
                        {
                            return Err(VfsError::DirectoryNotEmpty);
                        }

                        let dst_inode_ino = dst_inode.index.get();
                        let dst_is_dir = dst_inode.file_type() == ext4plus::FileType::Directory;
                        dst_dir.invalidate_metadata();
                        invalidate_inode_metadata_cache(&dst_dir.fs, dst_inode_ino);
                        let dst_inode = dst_dir_obj
                            .unlink(dst_name_ref, dst_inode)
                            .await
                            .map_err(into_vfs_err);
                        dst_dir.invalidate_metadata();
                        invalidate_inode_metadata_cache(&dst_dir.fs, dst_inode_ino);
                        if dst_inode.is_err() {
                            dst_dir.dir_cache.invalidate();
                        }
                        let dst_inode = dst_inode?;
                        dst_dir.invalidate_snapshot(dst_dir.ino);
                        dst_dir
                            .dir_cache
                            .update_lookup(String::from(dst_name), None);
                        if dst_is_dir {
                            invalidate_dir_cache(&dst_dir.fs, dst_inode_ino);
                        }
                        if dst_inode.links_count() == 0 {
                            let has_other_active =
                                Self::mark_unlinked_and_has_external_refs(local_dst);
                            if !has_other_active {
                                log::debug!(
                                    "ext4: rename deleting unlinked dst file (ino {}) immediately \
                                     because no active references",
                                    dst_inode_ino
                                );
                                local_dst.is_unlinked.store(true, Ordering::Relaxed);
                                fs.delete_file(dst_inode).await.map_err(into_vfs_err)?;
                                local_dst.is_unlinked.store(false, Ordering::Relaxed);
                                crate::invalidate_file_cache(
                                    Arc::as_ptr(&dst_dir.fs) as usize,
                                    dst_inode_ino as u64,
                                );
                            }
                        }
                    }

                    let src_inode_ino = src_inode.index.get();
                    self.invalidate_metadata();
                    if dst_dir.ino != self.ino {
                        dst_dir.invalidate_metadata();
                    }
                    invalidate_inode_metadata_cache(&self.fs, src_inode_ino);
                    let link_result = dst_dir_obj
                        .link(dst_name_ref, &mut src_inode)
                        .await
                        .map_err(into_vfs_err);
                    dst_dir.invalidate_metadata();
                    invalidate_inode_metadata_cache(&self.fs, src_inode_ino);
                    if link_result.is_err() {
                        dst_dir.dir_cache.invalidate();
                    }
                    link_result?;
                    dst_dir.invalidate_snapshot(dst_dir.ino);
                    dst_dir.dir_cache.update_lookup(
                        String::from(dst_name),
                        Some(CachedLookupEntry {
                            inode_num: src_inode_ino,
                            node_type: into_vfs_type(src_inode.file_type()),
                        }),
                    );
                    let rollback_inode = src_inode.clone();
                    self.invalidate_metadata();
                    let unlink_result = src_dir
                        .unlink(src_name_ref, src_inode)
                        .await
                        .map_err(into_vfs_err);
                    self.invalidate_metadata();
                    invalidate_inode_metadata_cache(&self.fs, src_inode_ino);
                    if let Err(unlink_error) = unlink_result {
                        self.dir_cache.invalidate();
                        dst_dir.invalidate_metadata();
                        invalidate_inode_metadata_cache(&self.fs, src_inode_ino);
                        let source_still_linked = match src_dir.get_entry(src_name_ref).await {
                            Ok(inode) if inode.index.get() == src_inode_ino => true,
                            Ok(inode) => {
                                log::error!(
                                    "ext4: rename source entry '{}' changed from inode {} to {} \
                                     while mutation locks were held",
                                    src_name,
                                    src_inode_ino,
                                    inode.index.get()
                                );
                                false
                            }
                            Err(Ext4Error::NotFound) => false,
                            Err(error) => {
                                log::error!(
                                    "ext4: rename could not verify source entry '{}' for inode {} \
                                     before rollback: {}",
                                    src_name,
                                    src_inode_ino,
                                    error
                                );
                                false
                            }
                        };
                        if source_still_linked {
                            if let Err(rollback_error) =
                                dst_dir_obj.unlink(dst_name_ref, rollback_inode).await
                            {
                                log::error!(
                                    "ext4: rename failed to roll back destination entry '{}' for \
                                     inode {}: {}",
                                    dst_name,
                                    src_inode_ino,
                                    rollback_error
                                );
                            }
                        } else {
                            log::error!(
                                "ext4: rename preserved destination entry '{}' for inode {} \
                                 because the failed source unlink may have removed '{}'",
                                dst_name,
                                src_inode_ino,
                                src_name
                            );
                        }
                        dst_dir.invalidate_metadata();
                        invalidate_inode_metadata_cache(&self.fs, src_inode_ino);
                        dst_dir.dir_cache.invalidate();
                        return Err(unlink_error);
                    }
                    self.invalidate_snapshot(self.ino);
                    self.dir_cache.update_lookup(String::from(src_name), None);
                    Ok(())
                })
                .await;
        }
    }
}

impl Drop for Inode {
    fn drop(&mut self) {
        let is_unlinked = self.is_unlinked.load(core::sync::atomic::Ordering::Relaxed);
        let mut active = self.fs.active_inodes.lock();
        let mut still_active = false;
        if let Some(list) = active.get_mut(&self.ino) {
            list.retain(|w| w.strong_count() > 0);
            if !list.is_empty() {
                still_active = true;
            }
        }

        if !still_active {
            active.remove(&self.ino);
            if is_unlinked {
                drop(active);
                crate::invalidate_file_cache(Arc::as_ptr(&self.fs) as usize, self.ino as u64);
                self.fs.queue_deletion(self.ino);
            }
        }
    }
}

fn into_ext4_type_bits(ty: NodeType) -> u16 {
    match ty {
        NodeType::Fifo => ext4plus::inode::InodeMode::S_IFIFO.bits(),
        NodeType::CharacterDevice => ext4plus::inode::InodeMode::S_IFCHR.bits(),
        NodeType::Directory => ext4plus::inode::InodeMode::S_IFDIR.bits(),
        NodeType::BlockDevice => ext4plus::inode::InodeMode::S_IFBLK.bits(),
        NodeType::RegularFile => ext4plus::inode::InodeMode::S_IFREG.bits(),
        NodeType::Symlink => ext4plus::inode::InodeMode::S_IFLNK.bits(),
        NodeType::Socket => ext4plus::inode::InodeMode::S_IFSOCK.bits(),
        NodeType::Unknown => 0,
    }
}

#[cfg(test)]
mod tests {
    use alloc::{
        string::String,
        sync::Arc,
        vec::{self, Vec},
    };
    use core::time::Duration;

    use axfs_ng_vfs::{DeviceId, Metadata, NodePermission, NodeType};

    use super::{
        CachedDirEntry, CachedLookupEntry, DIR_SNAPSHOT_PROMOTION_LOOKUPS, DirCacheState,
        DirSnapshot, MetadataCacheState,
    };

    fn metadata_with_size(size: u64) -> Metadata {
        Metadata {
            device: 0,
            inode: 7,
            nlink: 1,
            mode: NodePermission::from_bits_truncate(0o644),
            node_type: NodeType::RegularFile,
            uid: 0,
            gid: 0,
            size,
            block_size: 4096,
            blocks: 8,
            rdev: DeviceId::default(),
            atime: Duration::ZERO,
            mtime: Duration::ZERO,
            ctime: Duration::ZERO,
        }
    }

    #[test]
    fn metadata_cache_rejects_stale_publish_after_invalidation() {
        let state = MetadataCacheState::new();
        let generation = state.generation();
        assert!(state.publish(generation, metadata_with_size(16)));
        assert_eq!(state.get().unwrap().size, 16);

        state.invalidate();
        assert!(state.get().is_none());
        assert!(!state.publish(generation, metadata_with_size(32)));

        let current_generation = state.generation();
        assert!(state.publish(current_generation, metadata_with_size(64)));
        assert_eq!(state.get().unwrap().size, 64);
    }

    #[test]
    fn invalidated_directory_snapshot_cannot_be_published() {
        let state = DirCacheState::new();
        let stale_generation = state.generation();
        let stale = Arc::new(DirSnapshot::new(Vec::new()));

        state.invalidate();
        assert!(!state.publish(stale_generation, stale));
        assert!(state.get().is_none());

        let current = Arc::new(DirSnapshot::new(Vec::new()));
        assert!(state.publish(state.generation(), current.clone()));
        assert!(Arc::ptr_eq(&state.get().unwrap(), &current));
    }

    #[test]
    fn directory_snapshot_preserves_iteration_order_and_indexes_names() {
        let entries = vec![
            CachedDirEntry {
                name: String::from("zeta"),
                inode_num: 31,
                node_type: NodeType::RegularFile,
            },
            CachedDirEntry {
                name: String::from("alpha"),
                inode_num: 17,
                node_type: NodeType::Directory,
            },
        ];
        let snapshot = DirSnapshot::new(entries);

        assert_eq!(snapshot.entries[0].name, "zeta");
        assert_eq!(snapshot.entries[1].name, "alpha");
        assert_eq!(
            snapshot.lookup("alpha"),
            Some(CachedLookupEntry {
                inode_num: 17,
                node_type: NodeType::Directory,
            })
        );
        assert_eq!(snapshot.lookup("missing"), None);
    }

    #[test]
    fn directory_snapshot_promotion_resets_on_invalidation() {
        let state = DirCacheState::new();
        for _ in 1..DIR_SNAPSHOT_PROMOTION_LOOKUPS {
            assert!(!state.note_uncached_lookup());
        }
        assert!(state.note_uncached_lookup());

        state.invalidate_snapshot();
        assert!(!state.note_uncached_lookup());
    }

    #[test]
    fn directory_lookup_cache_handles_negative_entries_and_invalidation() {
        let state = DirCacheState::new();
        let generation = state.lookup_generation();
        let found = CachedLookupEntry {
            inode_num: 23,
            node_type: NodeType::RegularFile,
        };

        assert!(state.publish_lookup(generation, String::from("found"), Some(found)));
        assert_eq!(state.get_lookup("found"), Some(Some(found)));

        assert!(state.publish_lookup(generation, String::from("missing"), None));
        assert_eq!(state.get_lookup("missing"), Some(None));

        state.invalidate_snapshot();
        assert_eq!(state.get_lookup("found"), Some(Some(found)));
        assert_eq!(state.get_lookup("missing"), Some(None));

        state.update_lookup(
            String::from("changed"),
            Some(CachedLookupEntry {
                inode_num: 24,
                node_type: NodeType::Directory,
            }),
        );
        assert_eq!(state.get_lookup("found"), Some(Some(found)));
        assert_eq!(state.get_lookup("missing"), Some(None));
        assert!(!state.publish_lookup(generation, String::from("stale"), None));

        state.invalidate();
        assert_eq!(state.get_lookup("found"), None);
        assert_eq!(state.get_lookup("missing"), None);
    }
}
