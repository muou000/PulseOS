use alloc::{
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{any::Any, task::Context, time::Duration};

use axfs_ng_vfs::{
    DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, FilesystemOps, Metadata,
    MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType, Reference, VfsError, VfsResult,
    WeakDirEntry,
};
use axpoll::{IoEvents, Pollable};
use ext4_rs::Ext4;
use spin::{Lazy, Mutex};

use super::{
    Ext4Filesystem,
    util::{duration_to_ext4_time, into_ext4_type, into_vfs_err, into_vfs_type, now_as_ext4_time},
};
pub struct Inode {
    fs: Arc<Ext4Filesystem>,
    ino: u32,
    this: Option<WeakDirEntry>,
    dir_cache: Arc<DirCacheState>,
}

#[derive(Clone)]
struct CachedDirEntry {
    name: String,
    inode_num: u32,
    node_type: NodeType,
    is_dir: bool,
}

struct DirSnapshot {
    entries: Vec<CachedDirEntry>,
}

struct DirCacheState {
    snapshot: Mutex<Option<Arc<DirSnapshot>>>,
}

impl DirCacheState {
    fn new() -> Self {
        Self {
            snapshot: Mutex::new(None),
        }
    }

    fn get(&self) -> Option<Arc<DirSnapshot>> {
        self.snapshot.lock().clone()
    }

    fn set(&self, snapshot: Arc<DirSnapshot>) {
        *self.snapshot.lock() = Some(snapshot);
    }

    fn invalidate(&self) {
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

pub(crate) fn ext4_fs_id(fs: &Arc<Ext4Filesystem>) -> usize {
    Arc::as_ptr(fs) as usize
}

fn dir_cache_key(fs: &Arc<Ext4Filesystem>, ino: u32) -> DirCacheKey {
    DirCacheKey {
        fs_id: ext4_fs_id(fs),
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
        let dir_cache = dir_cache_state(&fs, ino);
        Arc::new(Self {
            fs,
            ino,
            this,
            dir_cache,
        })
    }

    fn create_entry(
        &self,
        inode_num: u32,
        node_type: NodeType,
        is_dir: bool,
        name: impl Into<String>,
    ) -> DirEntry {
        let reference = Reference::new(
            self.this.as_ref().and_then(WeakDirEntry::upgrade),
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

    fn build_dir_snapshot_uncached(&self, fs: &Ext4, dir_ino: u32) -> Arc<DirSnapshot> {
        let mut entries = Vec::new();
        let total_inodes = fs.super_block.total_inodes();

        for entry in fs.dir_get_entries(dir_ino) {
            if entry.inode == 0 || entry.inode > total_inodes {
                log::warn!(
                    "ext4: skip invalid dir entry ino={} in dir ino={}",
                    entry.inode,
                    dir_ino
                );
                continue;
            }
            let name = entry.get_name();
            
            let de_type = entry.get_de_type();
            let (mut node_type, mut is_dir) = match de_type {
                1 => (NodeType::RegularFile, false),
                2 => (NodeType::Directory, true),
                3 => (NodeType::CharacterDevice, false),
                4 => (NodeType::BlockDevice, false),
                5 => (NodeType::Fifo, false),
                6 => (NodeType::Socket, false),
                7 => (NodeType::Symlink, false),
                _ => (NodeType::Unknown, false),
            };

            // If the type is unknown (e.g. older ext4 without file_type feature),
            // fall back to reading the inode directly from the block device.
            if node_type == NodeType::Unknown {
                let inode_ref = fs.get_inode_ref(entry.inode);
                // Validate that the inode is actually allocated and valid.
                // Unallocated inodes have mode==0, deleted inodes have dtime!=0.
                if inode_ref.inode.mode() == 0 || inode_ref.inode.dtime() != 0 {
                    log::warn!(
                        "ext4: skip unallocated/deleted inode {} (mode={}, dtime={}) in dir ino={}",
                        entry.inode,
                        inode_ref.inode.mode(),
                        inode_ref.inode.dtime(),
                        dir_ino,
                    );
                    continue;
                }
                node_type = into_vfs_type(inode_ref.inode.file_type());
                // Skip entries with Unknown node type (likely corruption).
                if node_type == NodeType::Unknown {
                    log::warn!(
                        "ext4: skip unknown node type for inode {} in dir ino={}",
                        entry.inode,
                        dir_ino,
                    );
                    continue;
                }
                is_dir = inode_ref.inode.is_dir();
            }

            entries.push(CachedDirEntry {
                name,
                inode_num: entry.inode,
                node_type,
                is_dir,
            });
        }

        Arc::new(DirSnapshot { entries })
    }

    fn dir_snapshot(&self, fs: &Ext4) -> Arc<DirSnapshot> {
        if let Some(snapshot) = self.dir_cache.get() {
            return snapshot.clone();
        }
        let snapshot = self.build_dir_snapshot_uncached(fs, self.ino);
        self.dir_cache.set(snapshot.clone());
        snapshot
    }

    fn build_dir_snapshot(&self, fs: &Ext4, dir_ino: u32) -> Arc<DirSnapshot> {
        if dir_ino == self.ino {
            self.dir_snapshot(fs)
        } else {
            self.build_dir_snapshot_uncached(fs, dir_ino)
        }
    }

    fn validate_inode_num(&self, fs: &Ext4, inode_num: u32) -> VfsResult<()> {
        let total_inodes = fs.super_block.total_inodes();
        if inode_num == 0 || inode_num > total_inodes {
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

    fn cached_entry<'a>(
        &self,
        snapshot: &'a DirSnapshot,
        name: &str,
    ) -> Option<&'a CachedDirEntry> {
        snapshot.entries.iter().find(|entry| entry.name == name)
    }

    fn dir_has_children(&self, fs: &Ext4, dir_ino: u32) -> bool {
        let snapshot = self.build_dir_snapshot(fs, dir_ino);
        snapshot
            .entries
            .iter()
            .any(|entry| entry.name != "." && entry.name != "..")
    }
}

impl NodeOps for Inode {
    fn inode(&self) -> u64 {
        self.ino as u64
    }

    fn metadata(&self) -> VfsResult<Metadata> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let inode_ref = fs.get_inode_ref(self.ino);
        Ok(Metadata {
            device: 0,
            inode: inode_ref.inode_num as u64,
            nlink: inode_ref.inode.links_count() as u64,
            mode: NodePermission::from_bits_truncate(inode_ref.inode.file_perm().bits()),
            node_type: into_vfs_type(inode_ref.inode.file_type()),
            uid: inode_ref.inode.uid() as u32,
            gid: inode_ref.inode.gid() as u32,
            size: inode_ref.inode.size(),
            block_size: ext4_rs::BLOCK_SIZE as u64,
            blocks: inode_ref.inode.blocks_count(),
            rdev: Default::default(),
            atime: Duration::from_secs(inode_ref.inode.atime() as u64),
            mtime: Duration::from_secs(inode_ref.inode.mtime() as u64),
            ctime: Duration::from_secs(inode_ref.inode.ctime() as u64),
        })
    }

    fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let mut inode_ref = fs.get_inode_ref(self.ino);
        if let Some(mode) = update.mode {
            let kind = inode_ref.inode.mode() & 0xf000;
            inode_ref.inode.set_mode(kind | mode.bits());
        }
        if let Some((uid, gid)) = update.owner {
            inode_ref.inode.set_uid(uid as u16);
            inode_ref.inode.set_gid(gid as u16);
        }
        if let Some(atime) = update.atime {
            inode_ref.inode.set_atime(duration_to_ext4_time(atime));
        }
        if let Some(mtime) = update.mtime {
            inode_ref.inode.set_mtime(duration_to_ext4_time(mtime));
        }
        if let Some(now) = now_as_ext4_time() {
            inode_ref.inode.set_ctime(now);
        }
        fs.write_back_inode(&mut inode_ref);
        Ok(())
    }

    fn len(&self) -> VfsResult<u64> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        Ok(fs.get_inode_ref(self.ino).inode.size())
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        &*self.fs
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::BLOCKING
    }
}

impl FileNodeOps for Inode {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let inode_ref = fs.get_inode_ref(self.ino);
        if inode_ref.inode.is_link() && inode_ref.inode.blocks_count() == 0 {
            let size = inode_ref.inode.size() as usize;
            let offset = offset as usize;
            if offset >= size {
                return Ok(0);
            }

            let available = size - offset;
            let len = available.min(buf.len());
            let mut raw = [0u8; 15 * core::mem::size_of::<u32>()];
            let len = len.min(raw.len().saturating_sub(offset));
            if len == 0 {
                return Ok(0);
            }
            for (chunk, word) in raw.chunks_exact_mut(4).zip(inode_ref.inode.block().iter()) {
                chunk.copy_from_slice(&word.to_le_bytes());
            }
            buf[..len].copy_from_slice(&raw[offset..offset + len]);
            return Ok(len);
        }
        fs.read_at(self.ino, offset as usize, buf)
            .map_err(into_vfs_err)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        fs.write_at(self.ino, offset as usize, buf)
            .map_err(into_vfs_err)
    }

    fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)> {
        let length = self.len()?;
        let written = self.write_at(buf, length)?;
        Ok((written, length + written as u64))
    }

    fn set_len(&self, len: u64) -> VfsResult<()> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let mut inode_ref = fs.get_inode_ref(self.ino);
        let old_len = inode_ref.inode.size();
        if len == old_len {
            return Ok(());
        }
        if len < old_len {
            fs.truncate_inode(&mut inode_ref, len)
                .map_err(into_vfs_err)?;
            return Ok(());
        }

        inode_ref.inode.set_size(len);
        fs.write_back_inode(&mut inode_ref);
        Ok(())
    }

    fn set_symlink(&self, target: &str) -> VfsResult<()> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let mut inode_ref = fs.get_inode_ref(self.ino);
        let bytes = target.as_bytes();
        if bytes.len() <= 15 * core::mem::size_of::<u32>() {
            let mut words = [0u32; 15];
            for (word, chunk) in words.iter_mut().zip(bytes.chunks(4)) {
                let mut raw = [0u8; 4];
                raw[..chunk.len()].copy_from_slice(chunk);
                *word = u32::from_le_bytes(raw);
            }

            inode_ref.inode.set_block(words);
            inode_ref.inode.set_size(bytes.len() as u64);
            inode_ref.inode.set_blocks_count(0);
            fs.write_back_inode(&mut inode_ref);
            return Ok(());
        }

        drop(inode_ref);
        drop(fs);
        self.set_len(0)?;
        self.fs
            .lock()
            .write_at(self.ino, 0, target.as_bytes())
            .map(|_| ())
            .map_err(into_vfs_err)
    }
}

impl Pollable for Inode {
    fn poll(&self) -> IoEvents {
        IoEvents::IN | IoEvents::OUT
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}

impl DirNodeOps for Inode {
    fn is_cacheable(&self) -> bool {
        true
    }

    fn read_dir(&self, offset: u64, sink: &mut dyn DirEntrySink) -> VfsResult<usize> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let snapshot = self.dir_snapshot(&fs);
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

    fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        
        // Try cached snapshot first
        if let Some(snapshot) = self.dir_cache.get() {
            let Some(entry) = self.cached_entry(&snapshot, name) else {
                return Err(VfsError::NotFound);
            };
            return Ok(self.create_entry(entry.inode_num, entry.node_type, entry.is_dir, &entry.name));
        }

        // Direct search on disk to avoid O(N) snapshot build if not needed
        let mut result = ext4_rs::ext4_defs::Ext4DirSearchResult::new(ext4_rs::ext4_defs::Ext4DirEntry::default());
        match fs.dir_find_entry(self.ino, name, &mut result) {
            Ok(_) => {
                let linked = fs.get_inode_ref(result.dentry.inode);
                Ok(self.create_entry(
                    linked.inode_num,
                    into_vfs_type(linked.inode.file_type()),
                    linked.inode.is_dir(),
                    name,
                ))
            }
            Err(_) => Err(VfsError::NotFound),
        }
    }

    fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        let inode_type = into_ext4_type(node_type)?;
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        
        let exists = if let Some(snapshot) = self.dir_cache.get() {
            self.cached_entry(&snapshot, name).is_some()
        } else {
            let mut result = ext4_rs::ext4_defs::Ext4DirSearchResult::new(ext4_rs::ext4_defs::Ext4DirEntry::default());
            fs.dir_find_entry(self.ino, name, &mut result).is_ok()
        };

        if exists {
            return Err(VfsError::AlreadyExists);
        }
        let inode_ref = fs
            .create(self.ino, name, inode_type.bits() | permission.bits())
            .map_err(into_vfs_err)?;
        self.invalidate_snapshot(self.ino);
        Ok(self.create_entry(
            inode_ref.inode_num,
            node_type,
            node_type == NodeType::Directory,
            name,
        ))
    }

    fn link(&self, name: &str, node: &DirEntry) -> VfsResult<DirEntry> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        let mut parent = fs.get_inode_ref(self.ino);
        let mut child = fs.get_inode_ref(node.inode() as u32);
        fs.link(&mut parent, &mut child, name)
            .map_err(into_vfs_err)?;
        fs.write_back_inode(&mut parent);
        fs.write_back_inode(&mut child);
        self.invalidate_snapshot(self.ino);
        let linked = fs.get_inode_ref(child.inode_num);
        Ok(self.create_entry(
            linked.inode_num,
            into_vfs_type(linked.inode.file_type()),
            linked.inode.is_dir(),
            name,
        ))
    }

    fn unlink(&self, name: &str) -> VfsResult<()> {
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        
        let inode_num = if let Some(snapshot) = self.dir_cache.get() {
            self.cached_entry(&snapshot, name)
                .map(|entry| entry.inode_num)
                .ok_or(VfsError::NotFound)?
        } else {
            let mut result = ext4_rs::ext4_defs::Ext4DirSearchResult::new(ext4_rs::ext4_defs::Ext4DirEntry::default());
            fs.dir_find_entry(self.ino, name, &mut result)
                .map_err(|_| VfsError::NotFound)?;
            result.dentry.inode
        };

        let mut parent = fs.get_inode_ref(self.ino);
        let mut child = fs.get_inode_ref(inode_num);
        if child.inode.is_dir() && self.dir_has_children(&fs, child.inode_num) {
            return Err(VfsError::DirectoryNotEmpty);
        }
        if child.inode.links_count() == 1 && child.inode.size() > 0 {
            fs.truncate_inode(&mut child, 0).map_err(into_vfs_err)?;
        }
        fs.unlink(&mut parent, &mut child, name)
            .map_err(into_vfs_err)?;
        self.invalidate_snapshot(self.ino);
        if child.inode.is_dir() {
            self.invalidate_snapshot(child.inode_num);
        }
        Ok(())
    }

    fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        let dst_dir: Arc<Self> = dst_dir.downcast().map_err(|_| VfsError::InvalidInput)?;
        let fs = self.fs.lock();
        self.validate_inode_num(&fs, self.ino)?;
        self.validate_inode_num(&fs, dst_dir.ino)?;
        let src_snapshot = self.build_dir_snapshot(&fs, self.ino);

        let src_inode_num = self
            .cached_entry(&src_snapshot, src_name)
            .map(|entry| entry.inode_num)
            .ok_or(VfsError::NotFound)?;
        let src_inode = fs.get_inode_ref(src_inode_num);

        if src_inode.inode.is_dir() && self.ino != dst_dir.ino {
            return Err(VfsError::OperationNotSupported);
        }

        let dst_snapshot = if dst_dir.ino == self.ino {
            src_snapshot.clone()
        } else {
            dst_dir.dir_snapshot(&fs)
        };

        if let Some(dst_inode_num) = dst_dir
            .cached_entry(&dst_snapshot, dst_name)
            .map(|entry| entry.inode_num)
        {
            if dst_inode_num == src_inode.inode_num {
                return Ok(());
            }

            let mut dst_parent = fs.get_inode_ref(dst_dir.ino);
            let mut dst_inode = fs.get_inode_ref(dst_inode_num);
            if dst_inode.inode.is_dir() && self.dir_has_children(&fs, dst_inode.inode_num) {
                return Err(VfsError::DirectoryNotEmpty);
            }
            if dst_inode.inode.links_count() == 1 && dst_inode.inode.size() > 0 {
                fs.truncate_inode(&mut dst_inode, 0).map_err(into_vfs_err)?;
            }
            fs.unlink(&mut dst_parent, &mut dst_inode, dst_name)
                .map_err(into_vfs_err)?;
            dst_dir.invalidate_snapshot(dst_dir.ino);
            if dst_inode.inode.is_dir() {
                dst_dir.invalidate_snapshot(dst_inode.inode_num);
            }
        }

        let mut dst_parent = fs.get_inode_ref(dst_dir.ino);
        fs.dir_add_entry(&mut dst_parent, &src_inode, dst_name)
            .map_err(into_vfs_err)?;

        fs.write_back_inode(&mut dst_parent);

        let mut src_parent = fs.get_inode_ref(self.ino);
        fs.dir_remove_entry(&mut src_parent, src_name)
            .map_err(into_vfs_err)?;
        self.invalidate_snapshot(self.ino);
        if dst_dir.ino != self.ino {
            dst_dir.invalidate_snapshot(dst_dir.ino);
        }
        Ok(())
    }
}
