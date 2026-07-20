use alloc::{
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
    boxed::Box,
};
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
    task::Context,
};

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
use spin::{Lazy, Mutex};
use async_trait::async_trait;

use super::{
    Ext4Filesystem,
    util::{into_ext4_file_type, into_vfs_err, into_vfs_type},
};

pub struct Inode {
    fs: Arc<Ext4Filesystem>,
    ino: u32,
    this: Mutex<Option<WeakDirEntry>>,
    mutation_lock: async_lock::Mutex<()>,
    dir_cache: Arc<DirCacheState>,
    pub(super) is_unlinked: core::sync::atomic::AtomicBool,
}

struct CachedDirEntry {
    name: String,
    inode_num: u32,
    node_type: NodeType,
}

struct DirSnapshot {
    entries: Vec<CachedDirEntry>,
}

struct DirCacheState {
    generation: AtomicU64,
    snapshot: Mutex<Option<(u64, Arc<DirSnapshot>)>>,
}

impl DirCacheState {
    fn new() -> Self {
        Self {
            generation: AtomicU64::new(0),
            snapshot: Mutex::new(None),
        }
    }

    fn get(&self) -> Option<Arc<DirSnapshot>> {
        let generation = self.generation.load(Ordering::Acquire);
        let snapshot = self
            .snapshot
            .lock()
            .as_ref()
            .filter(|(snapshot_generation, _)| *snapshot_generation == generation)
            .map(|(_, snapshot)| snapshot.clone());
        (self.generation.load(Ordering::Acquire) == generation)
            .then_some(snapshot)
            .flatten()
    }

    fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    fn publish(&self, generation: u64, snapshot: Arc<DirSnapshot>) -> bool {
        let mut cached = self.snapshot.lock();
        if self.generation.load(Ordering::Acquire) != generation {
            return false;
        }
        *cached = Some((generation, snapshot));
        true
    }

    fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        *self.snapshot.lock() = None;
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
        let dir_cache = dir_cache_state(&fs, ino);
        let inode = Arc::new(Self {
            fs: fs.clone(),
            ino,
            this: Mutex::new(this),
            mutation_lock: async_lock::Mutex::new(()),
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
        let reference = Reference::new(
            self.this.lock().clone(),
            name.into(),
        );
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

    fn invalidate_snapshot(&self, dir_ino: u32) {
        if dir_ino == self.ino {
            self.dir_cache.invalidate();
        } else {
            invalidate_dir_cache(&self.fs, dir_ino);
        }
    }

    async fn build_dir_snapshot_uncached(&self, fs: &Ext4, dir_ino: u32) -> VfsResult<Arc<DirSnapshot>> {
        let mut entries = Vec::new();
        let total_inodes = fs.superblock().num_block_groups() as u64 * fs.superblock().inodes_per_block_group().get() as u64;

        let dir_idx = core::num::NonZeroU32::new(dir_ino).ok_or(VfsError::InvalidData)?;
        let dir_inode = ext4plus::inode::Inode::read(fs, dir_idx).await.map_err(into_vfs_err)?;
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
                Err(_) => {
                    let idx = core::num::NonZeroU32::new(entry.inode.get()).ok_or(VfsError::InvalidData)?;
                    ext4plus::inode::Inode::read(fs, idx).await.map_err(into_vfs_err)?.file_type()
                }
            };
            let node_type = into_vfs_type(de_type);

            entries.push(CachedDirEntry {
                name,
                inode_num: entry.inode.get(),
                node_type,
            });
        }

        Ok(Arc::new(DirSnapshot { entries }))
    }

    async fn dir_snapshot(&self, fs: &Ext4) -> VfsResult<Arc<DirSnapshot>> {
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
        let total_inodes = fs.superblock().num_block_groups() as u64 * fs.superblock().inodes_per_block_group().get() as u64;
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
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        let file_type = inode.file_type();
        let perm = inode.mode().bits() & 0x0fff; // Permission bits only
        Ok(Metadata {
            device: 0,
            inode: self.ino as u64,
            nlink: inode.links_count() as u64,
            mode: NodePermission::from_bits_truncate(perm),
            node_type: into_vfs_type(file_type),
            uid: inode.uid(),
            gid: inode.gid(),
            size: inode.size_in_bytes(),
            block_size: self.fs.block_size as u64,
            blocks: inode.fs_blocks(&fs).unwrap_or(0),
            rdev: Default::default(),
            atime: inode.atime(),
            mtime: inode.mtime(),
            ctime: inode.ctime(),
        })
    }

    async fn len(&self) -> VfsResult<u64> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        Ok(inode.size_in_bytes())
    }

    async fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        if let Some(mode) = update.mode {
            let perm = mode.bits() & 0x0fff;
            let kind = inode.mode().bits() & 0xf000;
            inode.set_mode(ext4plus::inode::InodeMode::from_bits_truncate(kind | perm)).map_err(into_vfs_err)?;
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
        inode.write(&fs).await.map_err(into_vfs_err)?;
        Ok(())
    }


    fn filesystem(&self) -> &dyn FilesystemOps {
        &*self.fs
    }

    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        self.fs.flush_storage()
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
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
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
        ext4plus::file::read_at(&fs, &inode, buf, offset).await.map_err(into_vfs_err)
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        log::debug!("ext4 inode::write_at: offset={}, len={}", offset, buf.len());
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        let written = ext4plus::file::write_at(&fs, &mut inode, buf, offset).await.map_err(into_vfs_err)?;
        log::debug!("ext4 inode::write_at done: written={}", written);
        Ok(written)
    }

    async fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        let length = inode.size_in_bytes();
        let written = ext4plus::file::write_at(&fs, &mut inode, buf, length)
            .await
            .map_err(into_vfs_err)?;
        Ok((written, length + written as u64))
    }

    async fn set_len(&self, len: u64) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        let old_len = inode.size_in_bytes();
        if len == old_len {
            return Ok(());
        }
        ext4plus::file::truncate(&fs, &mut inode, len).await.map_err(into_vfs_err)?;
        Ok(())
    }

    async fn set_symlink(&self, target: &str) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let _mutation_guard = self.mutation_lock.lock().await;
        let mut inode = ext4plus::inode::Inode::read(&fs, idx).await.map_err(into_vfs_err)?;
        let bytes = target.as_bytes();
        ext4plus::file::truncate(&fs, &mut inode, 0).await.map_err(into_vfs_err)?;
        let written = ext4plus::file::write_at(&fs, &mut inode, bytes, 0).await.map_err(into_vfs_err)?;
        if written != bytes.len() {
            return Err(VfsError::StorageFull);
        }
        Ok(())
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

    async fn read_dir(&self, offset: u64, sink: &mut (dyn DirEntrySink + Send)) -> VfsResult<usize> {
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

        let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx).await.map_err(into_vfs_err)?;
        let dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;
        let name_ref = ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
        match dir.get_entry(name_ref).await {
            Ok(target_inode) => {
                let target_type = target_inode.file_type();
                Ok(self.create_entry(
                    target_inode.index.get(),
                    into_vfs_type(target_type),
                    target_type == ext4plus::FileType::Directory,
                    name,
                ))
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
        let _directory_guard = self.fs.directory_mutation.lock().await;

        let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx).await.map_err(into_vfs_err)?;
        let dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;
        let name_ref = ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
        let exists = match dir.get_entry(name_ref).await {
            Ok(_) => true,
            Err(Ext4Error::NotFound) => false,
            Err(e) => return Err(into_vfs_err(e)),
        };

        if exists {
            return Err(VfsError::AlreadyExists);
        }

        let file_type = into_ext4_file_type(node_type)?;
        let mode = ext4plus::inode::InodeMode::from_bits_truncate(
            into_ext4_type_bits(node_type) | permission.bits()
        );
        let options = ext4plus::inode::InodeCreationOptions {
            file_type,
            mode,
            uid: 0,
            gid: 0,
            time: axhal::time::wall_time(),
            flags: ext4plus::inode::InodeFlags::empty(),
        };

        let mut new_inode = fs.create_inode(options).await.map_err(into_vfs_err)?;
        let new_inode_idx = new_inode.index;

        let entry_res = async {
            let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
            let parent_inode = ext4plus::inode::Inode::read(&fs, dir_idx).await.map_err(into_vfs_err)?;
            let mut dir = ext4plus::dir::Dir::open_inode(&fs, parent_inode).map_err(into_vfs_err)?;

            if node_type == NodeType::Directory {
                let new_dir = ext4plus::dir::Dir::init(fs.clone(), new_inode, dir_idx).await.map_err(into_vfs_err)?;
                new_inode = new_dir.inode().clone();
            }

            let name_ref = ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
            dir.link(name_ref, &mut new_inode).await.map_err(into_vfs_err)?;

            self.invalidate_snapshot(self.ino);
            Ok(self.create_entry(
                new_inode.index.get(),
                node_type,
                node_type == NodeType::Directory,
                name,
            ))
        }.await;

        match entry_res {
            Ok(entry) => Ok(entry),
            Err(e) => {
                if let Ok(inode) = ext4plus::inode::Inode::read(&fs, new_inode_idx).await {
                    let _ = fs.delete_file(inode).await;
                }
                Err(e)
            }
        }
    }

    async fn link(&self, name: &str, node: &DirEntry) -> VfsResult<DirEntry> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let _directory_guard = self.fs.directory_mutation.lock().await;
        let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx).await.map_err(into_vfs_err)?;
        let mut dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;

        let child_idx = core::num::NonZeroU32::new(node.inode() as u32).ok_or(VfsError::InvalidData)?;
        let mut child_inode = ext4plus::inode::Inode::read(&fs, child_idx).await.map_err(into_vfs_err)?;

        if child_inode.file_type() == ext4plus::FileType::Directory {
            return Err(VfsError::OperationNotSupported);
        }

        let name_ref = ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
        dir.link(name_ref, &mut child_inode).await.map_err(into_vfs_err)?;

        self.invalidate_snapshot(self.ino);
        Ok(self.create_entry(
            child_inode.index.get(),
            into_vfs_type(child_inode.file_type()),
            child_inode.file_type() == ext4plus::FileType::Directory,
            name,
        ))
    }

    async fn unlink(&self, name: &str) -> VfsResult<()> {
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        let _directory_guard = self.fs.directory_mutation.lock().await;

        let dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let dir_inode = ext4plus::inode::Inode::read(&fs, dir_idx).await.map_err(into_vfs_err)?;
        let mut dir = ext4plus::dir::Dir::open_inode(&fs, dir_inode).map_err(into_vfs_err)?;

        let name_ref = ext4plus::DirEntryName::try_from(name).map_err(|_| VfsError::InvalidInput)?;
        let child_inode = dir.get_entry(name_ref).await.map_err(into_vfs_err)?;

        if child_inode.file_type() == ext4plus::FileType::Directory
            && self.dir_has_children(&fs, child_inode.index.get()).await?
        {
            return Err(VfsError::DirectoryNotEmpty);
        }

        let child_ino = child_inode.index.get();
        let is_dir = child_inode.file_type() == ext4plus::FileType::Directory;
        let child_inode = dir.unlink(name_ref, child_inode).await.map_err(into_vfs_err)?;
        if child_inode.links_count() == 0 {
            let has_other_active = {
                let mut active = self.fs.active_inodes.lock();
                let mut still_active = false;
                if let Some(list) = active.get_mut(&child_ino) {
                    list.retain(|w| w.strong_count() > 0);
                    for w in list.iter() {
                        if let Some(inode) = w.upgrade() {
                            inode.is_unlinked.store(true, core::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    if !list.is_empty() {
                        still_active = true;
                    }
                }
                if !still_active {
                    active.remove(&child_ino);
                }
                still_active
            };
            if !has_other_active {
                log::debug!("ext4: unlink deleting unlinked file (ino {}) immediately because no active references", child_ino);
                fs.delete_file(child_inode).await.map_err(into_vfs_err)?;
                crate::invalidate_file_cache(Arc::as_ptr(&self.fs) as usize, child_ino as u64);
            }
        }
        self.invalidate_snapshot(self.ino);
        if is_dir {
            self.invalidate_snapshot(child_ino);
        }
        Ok(())
    }

    async fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        let dst_dir: Arc<Self> = dst_dir.downcast().map_err(|_| VfsError::InvalidInput)?;
        let fs = &self.fs.inner;
        self.validate_inode_num(&fs, self.ino)?;
        self.validate_inode_num(&fs, dst_dir.ino)?;
        let _directory_guard = self.fs.directory_mutation.lock().await;

        let src_dir_idx = core::num::NonZeroU32::new(self.ino).ok_or(VfsError::InvalidData)?;
        let src_dir_inode = ext4plus::inode::Inode::read(&fs, src_dir_idx).await.map_err(into_vfs_err)?;
        let mut src_dir = ext4plus::dir::Dir::open_inode(&fs, src_dir_inode).map_err(into_vfs_err)?;

        let src_name_ref = ext4plus::DirEntryName::try_from(src_name).map_err(|_| VfsError::InvalidInput)?;
        let mut src_inode = src_dir.get_entry(src_name_ref).await.map_err(into_vfs_err)?;

        if src_inode.file_type() == ext4plus::FileType::Directory && self.ino != dst_dir.ino {
            return Err(VfsError::OperationNotSupported);
        }

        let dst_dir_idx = core::num::NonZeroU32::new(dst_dir.ino).ok_or(VfsError::InvalidData)?;
        let dst_dir_inode = ext4plus::inode::Inode::read(&fs, dst_dir_idx).await.map_err(into_vfs_err)?;
        let mut dst_dir_obj = ext4plus::dir::Dir::open_inode(&fs, dst_dir_inode).map_err(into_vfs_err)?;
        let dst_name_ref = ext4plus::DirEntryName::try_from(dst_name).map_err(|_| VfsError::InvalidInput)?;

        let dst_inode = match dst_dir_obj.get_entry(dst_name_ref).await {
            Ok(inode) => Some(inode),
            Err(Ext4Error::NotFound) => None,
            Err(e) => return Err(into_vfs_err(e)),
        };
        if let Some(dst_inode) = dst_inode {
            if dst_inode.index == src_inode.index {
                return Ok(());
            }

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
            let dst_inode = dst_dir_obj.unlink(dst_name_ref, dst_inode).await.map_err(into_vfs_err)?;
            if dst_inode.links_count() == 0 {
                let has_other_active = {
                    let mut active = dst_dir.fs.active_inodes.lock();
                    let mut still_active = false;
                    if let Some(list) = active.get_mut(&dst_inode_ino) {
                        list.retain(|w| w.strong_count() > 0);
                        for w in list.iter() {
                            if let Some(inode) = w.upgrade() {
                                inode.is_unlinked.store(true, core::sync::atomic::Ordering::Relaxed);
                            }
                        }
                        if !list.is_empty() {
                            still_active = true;
                        }
                    }
                    if !still_active {
                        active.remove(&dst_inode_ino);
                    }
                    still_active
                };
                if !has_other_active {
                    log::debug!("ext4: rename deleting unlinked dst file (ino {}) immediately because no active references", dst_inode_ino);
                    fs.delete_file(dst_inode).await.map_err(into_vfs_err)?;
                    crate::invalidate_file_cache(Arc::as_ptr(&dst_dir.fs) as usize, dst_inode_ino as u64);
                }
            }
            dst_dir.invalidate_snapshot(dst_dir.ino);
            if dst_is_dir {
                dst_dir.invalidate_snapshot(dst_inode_ino);
            }
        }

        dst_dir_obj.link(dst_name_ref, &mut src_inode).await.map_err(into_vfs_err)?;
        src_dir.unlink(src_name_ref, src_inode).await.map_err(into_vfs_err)?;

        self.invalidate_snapshot(self.ino);
        if dst_dir.ino != self.ino {
            dst_dir.invalidate_snapshot(dst_dir.ino);
        }
        Ok(())
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
    use super::{DirCacheState, DirSnapshot};
    use alloc::sync::Arc;
    use alloc::vec::Vec;

    #[test]
    fn invalidated_directory_snapshot_cannot_be_published() {
        let state = DirCacheState::new();
        let stale_generation = state.generation();
        let stale = Arc::new(DirSnapshot { entries: Vec::new() });

        state.invalidate();
        assert!(!state.publish(stale_generation, stale));
        assert!(state.get().is_none());

        let current = Arc::new(DirSnapshot { entries: Vec::new() });
        assert!(state.publish(state.generation(), current.clone()));
        assert!(Arc::ptr_eq(&state.get().unwrap(), &current));
    }
}
