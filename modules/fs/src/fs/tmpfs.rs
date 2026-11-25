use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
};
use core::{
    any::Any,
    cell::OnceCell,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::Context,
    time::Duration,
};

use async_trait::async_trait;
use vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, FileName, FileNode, FileNodeOps,
    Filesystem, FilesystemOps, InMemDir, InMemInode, Metadata, MetadataUpdate, NodeFlags, NodeOps,
    NodePermission, NodeType, Reference, StatFs, VfsError, VfsResult, WeakDirEntry,
    path::MAX_NAME_LEN, read_dir_impl, update_metadata_impl,
};
use poll::{IoEvents, Pollable};
use kspin::SpinNoPreempt;

use crate::highlevel::CachedFileShared;

const TMPFS_MAGIC: u64 = 0x0102_1994;
const TMPFS_INODE_SHARDS: usize = 32;

fn inode_shard(ino: u64) -> usize {
    ino as usize % TMPFS_INODE_SHARDS
}

pub struct TmpFilesystem {
    inodes: [SpinNoPreempt<BTreeMap<u64, Arc<Inode>>>; TMPFS_INODE_SHARDS],
    next_ino: AtomicU64,
    inode_count: AtomicUsize,
    root: OnceCell<DirEntry>,
}

impl TmpFilesystem {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            inodes: core::array::from_fn(|_| SpinNoPreempt::new(BTreeMap::new())),
            next_ino: AtomicU64::new(1),
            inode_count: AtomicUsize::new(0),
            root: OnceCell::new(),
        });
        let root_ino = new_inode(
            &fs,
            None,
            NodeType::Directory,
            NodePermission::from_bits_truncate(0o755),
        );
        let root_dir = DirEntry::new_dir(
            |this| DirNode::new(TmpNode::new(fs.clone(), root_ino, Some(this))),
            Reference::root(),
        );
        let _ = fs.root.set(root_dir.clone());
        Filesystem::new(fs)
    }

    fn get(&self, ino: u64) -> Arc<Inode> {
        self.inodes[inode_shard(ino)]
            .lock()
            .get(&ino)
            .cloned()
            .expect("tmpfs inode reference outlived its inode table entry")
    }
}

unsafe impl Send for TmpFilesystem {}
unsafe impl Sync for TmpFilesystem {}

#[async_trait]
impl FilesystemOps for TmpFilesystem {
    fn name(&self) -> &str {
        "tmpfs"
    }

    fn root_dir(&self) -> DirEntry {
        self.root
            .get()
            .cloned()
            .expect("tmpfs root directory should be alive while filesystem is mounted")
    }

    fn stat(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            fs_type: TMPFS_MAGIC as _,
            block_size: 4096,
            blocks: 0,
            blocks_free: 0,
            blocks_available: 0,
            file_count: self.inode_count.load(Ordering::Acquire) as u64,
            free_file_count: 0,
            name_length: MAX_NAME_LEN as u32,
            fragment_size: 4096,
            mount_flags: 0,
        })
    }
}

fn release_inode(fs: &TmpFilesystem, inode: Arc<Inode>, nlink: u64) {
    let ino = inode.ino;
    let removed = {
        let mut inodes = fs.inodes[inode_shard(ino)].lock();
        let unlinked = {
            let mut metadata = inode.metadata.lock();
            metadata.nlink -= nlink;
            metadata.nlink == 0
        };
        if inodes.contains_key(&ino) {
            // Drop the caller's Arc while the inode table entry keeps strong_count >= 1
            // so Inode::drop (and any cached page deallocation) never runs under spinlocks.
            drop(inode);
            if unlinked
                && inodes
                    .get(&ino)
                    .is_some_and(|entry| Arc::strong_count(entry) == 1)
            {
                let entry = inodes.remove(&ino);
                if entry.is_some() {
                    fs.inode_count.fetch_sub(1, Ordering::AcqRel);
                }
                entry
            } else {
                None
            }
        } else {
            Some(inode)
        }
    };
    drop(removed);
}

#[derive(Default)]
struct FileContent {
    length: SpinNoPreempt<u64>,
    symlink: SpinNoPreempt<Option<String>>,
    cache: SpinNoPreempt<Option<Arc<CachedFileShared>>>,
}

impl FileContent {
    fn len(&self) -> u64 {
        let cache = self.cache.lock();
        if let Some(state) = cache.as_ref() {
            state.size()
        } else {
            *self.length.lock()
        }
    }
}

type DirContent = InMemDir<InodeRef>;

enum NodeContent {
    File(FileContent),
    Dir(DirContent),
}

type Inode = InMemInode<NodeContent>;

fn new_inode(
    fs: &Arc<TmpFilesystem>,
    parent: Option<u64>,
    node_type: NodeType,
    permission: NodePermission,
) -> Arc<Inode> {
    let ino = fs
        .next_ino
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |ino| {
            ino.checked_add(1)
        })
        .expect("tmpfs inode number exhausted");
    let metadata = Metadata {
        device: 0,
        inode: ino,
        nlink: 0,
        mode: permission,
        node_type,
        uid: 0,
        gid: 0,
        size: 0,
        block_size: 4096,
        blocks: 0,
        rdev: DeviceId::default(),
        atime: Duration::default(),
        mtime: Duration::default(),
        ctime: Duration::default(),
    };
    let content = match node_type {
        NodeType::Directory => NodeContent::Dir(DirContent::new()),
        _ => NodeContent::File(FileContent::default()),
    };
    let result = Arc::new(InMemInode::new(ino, metadata, content));
    let previous = fs.inodes[inode_shard(ino)]
        .lock()
        .insert(ino, result.clone());
    debug_assert!(previous.is_none());
    fs.inode_count.fetch_add(1, Ordering::Release);

    if let NodeContent::Dir(dir) = &result.content {
        let mut entries = dir.entries.write();
        entries.insert(".".into(), InodeRef::new(fs.clone(), ino));
        entries.insert(
            "..".into(),
            InodeRef::new(fs.clone(), parent.unwrap_or(ino)),
        );
    }

    result
}

fn inode_as_file(inode: &Inode) -> VfsResult<&FileContent> {
    match inode.content {
        NodeContent::File(ref content) => Ok(content),
        _ => Err(VfsError::IsADirectory),
    }
}

fn inode_as_dir(inode: &Inode) -> VfsResult<&DirContent> {
    match inode.content {
        NodeContent::Dir(ref content) => Ok(content),
        _ => Err(VfsError::NotADirectory),
    }
}

struct InodeRef {
    fs: Weak<TmpFilesystem>,
    ino: u64,
}

impl InodeRef {
    pub fn new(fs: Arc<TmpFilesystem>, ino: u64) -> Self {
        fs.get(ino).metadata.lock().nlink += 1;
        Self {
            fs: Arc::downgrade(&fs),
            ino,
        }
    }

    fn get(&self) -> Arc<Inode> {
        self.fs
            .upgrade()
            .expect("tmpfs filesystem was dropped while inodes are still referenced")
            .get(self.ino)
    }
}

impl Drop for InodeRef {
    fn drop(&mut self) {
        if let Some(fs) = self.fs.upgrade() {
            let inode = fs.get(self.ino);
            release_inode(&fs, inode, 1);
        }
    }
}

pub(crate) struct TmpNode {
    fs: Arc<TmpFilesystem>,
    inode: Option<Arc<Inode>>,
    this: Option<WeakDirEntry>,
}

impl TmpNode {
    pub fn new(fs: Arc<TmpFilesystem>, inode: Arc<Inode>, this: Option<WeakDirEntry>) -> Arc<Self> {
        Arc::new(Self {
            fs,
            inode: Some(inode),
            this,
        })
    }

    fn inode_arc(&self) -> &Arc<Inode> {
        self.inode
            .as_ref()
            .expect("tmpfs node accessed after drop")
    }

    pub(crate) fn cached_file_state(&self) -> Option<Arc<CachedFileShared>> {
        let file = inode_as_file(self.inode_arc()).ok()?;
        file.cache.lock().clone()
    }

    pub(crate) fn cached_file_size(&self) -> Option<u64> {
        let file = inode_as_file(self.inode_arc()).ok()?;
        file.cache.lock().as_ref().map(|state| state.size())
    }

    pub(crate) fn attach_cached_file_state(
        &self,
        candidate: Arc<CachedFileShared>,
    ) -> VfsResult<Arc<CachedFileShared>> {
        let file = inode_as_file(self.inode_arc())?;
        let (state, unused) = {
            let mut cache = file.cache.lock();
            if let Some(existing) = cache.as_ref() {
                (existing.clone(), Some(candidate))
            } else {
                candidate.set_size(*file.length.lock());
                *cache = Some(candidate.clone());
                (candidate, None)
            }
        };
        drop(unused);
        Ok(state)
    }

    fn new_entry(&self, name: &str, node_type: NodeType, inode: Arc<Inode>) -> VfsResult<DirEntry> {
        let fs = self.fs.clone();
        let reference = Reference::new(self.this.clone(), name.to_owned());
        Ok(if node_type == NodeType::Directory {
            DirEntry::new_dir(
                |this| DirNode::new(TmpNode::new(fs, inode, Some(this))),
                reference,
            )
        } else {
            DirEntry::new_file(
                FileNode::new(TmpNode::new(fs, inode, None)),
                node_type,
                reference,
            )
        })
    }
}

#[async_trait]
impl NodeOps for TmpNode {
    fn inode(&self) -> u64 {
        self.inode_arc().ino
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        let inode = self.inode_arc();
        let mut metadata = inode.metadata.lock().clone();
        match &inode.content {
            NodeContent::File(content) => {
                metadata.size = content.len();
            }
            NodeContent::Dir(dir) => {
                metadata.size = dir.entries.read().len() as u64;
            }
        }
        Ok(metadata)
    }

    async fn len(&self) -> VfsResult<u64> {
        match &self.inode_arc().content {
            NodeContent::File(content) => Ok(content.len()),
            NodeContent::Dir(dir) => Ok(dir.entries.read().len() as u64),
        }
    }

    async fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        update_metadata_impl(&mut self.inode_arc().metadata.lock(), update);
        Ok(())
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        self.fs.as_ref()
    }

    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        if self.inode_arc().metadata.lock().node_type == NodeType::RegularFile {
            NodeFlags::ALWAYS_CACHE
        } else {
            NodeFlags::NON_CACHEABLE
        }
    }
}

#[async_trait]
impl FileNodeOps for TmpNode {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let file = inode_as_file(self.inode_arc())?;
        if let Some(symlink) = file.symlink.lock().as_ref() {
            assert_eq!(offset, 0);
            let len = buf.len().min(symlink.len());
            buf[..len].copy_from_slice(&symlink.as_bytes()[..len]);
            return Ok(len);
        }
        unreachable!("page cache should handle reading");
    }

    async fn write_at(&self, _buf: &[u8], _offset: u64) -> VfsResult<usize> {
        unreachable!("page cache should handle writing");
    }

    async fn append(&self, _buf: &[u8]) -> VfsResult<(usize, u64)> {
        unreachable!("page cache should handle writing");
    }

    async fn set_len(&self, len: u64) -> VfsResult<()> {
        let file = inode_as_file(self.inode_arc())?;
        // Hold `file.cache` to serialize length updates with `attach_cached_file_state`.
        let cache = file.cache.lock();
        if let Some(state) = cache.as_ref() {
            state.set_size(len);
        }
        *file.length.lock() = len;
        Ok(())
    }

    async fn set_symlink(&self, target: &str) -> VfsResult<()> {
        let file = inode_as_file(self.inode_arc())?;
        *file.length.lock() = target.len() as u64;
        *file.symlink.lock() = Some(target.to_owned());
        Ok(())
    }
}

impl Pollable for TmpNode {
    fn poll(&self) -> IoEvents {
        IoEvents::IN | IoEvents::OUT
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}

fn take_empty_dir_entries(inode: &Inode) -> VfsResult<Option<BTreeMap<FileName, InodeRef>>> {
    let NodeContent::Dir(dir_content) = &inode.content else {
        return Ok(None);
    };
    let mut sub_entries = dir_content.entries.write();
    if sub_entries.len() > 2 {
        return Err(VfsError::DirectoryNotEmpty);
    }
    Ok(Some(core::mem::take(&mut *sub_entries)))
}

fn prepare_replace_target(
    src_ref: &InodeRef,
    old_entry: &InodeRef,
) -> VfsResult<Option<BTreeMap<FileName, InodeRef>>> {
    let is_src_dir = matches!(&src_ref.get().content, NodeContent::Dir(_));
    let old_inode = old_entry.get();
    let is_dst_dir = matches!(&old_inode.content, NodeContent::Dir(_));
    match (is_src_dir, is_dst_dir) {
        (true, false) => Err(VfsError::NotADirectory),
        (false, true) => Err(VfsError::IsADirectory),
        (true, true) => take_empty_dir_entries(&old_inode),
        (false, false) => Ok(None),
    }
}

enum RenameDirEntries<'a> {
    Same(kspin::SpinNoPreemptGuard<'a, BTreeMap<FileName, InodeRef>>),
    Different(
        kspin::SpinNoPreemptGuard<'a, BTreeMap<FileName, InodeRef>>,
        kspin::SpinNoPreemptGuard<'a, BTreeMap<FileName, InodeRef>>,
    ),
}

impl RenameDirEntries<'_> {
    fn src(&self) -> &BTreeMap<FileName, InodeRef> {
        match self {
            Self::Same(entries) => entries,
            Self::Different(src, _) => src,
        }
    }

    fn dst(&self) -> &BTreeMap<FileName, InodeRef> {
        match self {
            Self::Same(entries) => entries,
            Self::Different(_, dst) => dst,
        }
    }

    fn remove_src(&mut self, name: &str) -> Option<InodeRef> {
        match self {
            Self::Same(entries) => entries.remove(name),
            Self::Different(src, _) => src.remove(name),
        }
    }

    fn insert_dst(&mut self, name: FileName, entry: InodeRef) -> Option<InodeRef> {
        match self {
            Self::Same(entries) => entries.insert(name, entry),
            Self::Different(_, dst) => dst.insert(name, entry),
        }
    }
}

#[async_trait]
impl DirNodeOps for TmpNode {
    async fn read_dir(
        &self,
        offset: u64,
        sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        let dir = inode_as_dir(self.inode_arc())?;
        read_dir_impl(&dir.entries, offset, sink, |entry| {
            (entry.ino, entry.get().metadata.lock().node_type)
        })
    }

    async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let dir = inode_as_dir(self.inode_arc())?;
        let entries = dir.entries.read();

        let entry = entries.get(name).ok_or(VfsError::NotFound)?;
        let inode = entry.get();
        let node_type = inode.metadata.lock().node_type;
        self.new_entry(name, node_type, inode)
    }

    async fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        let dir = inode_as_dir(self.inode_arc())?;
        let mut entries = dir.entries.write();

        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let inode = new_inode(
            &self.fs,
            Some(self.inode_arc().ino),
            node_type,
            permission,
        );
        entries.insert(name.into(), InodeRef::new(self.fs.clone(), inode.ino));
        self.new_entry(name, node_type, inode)
    }

    async fn link(&self, name: &str, target: &DirEntry) -> VfsResult<DirEntry> {
        let target = target.downcast::<Self>()?;
        if !Arc::ptr_eq(&self.fs, &target.fs) {
            return Err(VfsError::CrossesDevices);
        }
        let inode = target.inode_arc().clone();
        let node_type = target.metadata().await?.node_type;

        let dir = inode_as_dir(self.inode_arc())?;
        let mut entries = dir.entries.write();

        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        entries.insert(name.into(), InodeRef::new(self.fs.clone(), inode.ino));
        self.new_entry(name, node_type, inode)
    }

    async fn unlink(&self, name: &str) -> VfsResult<()> {
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }
        let dir = inode_as_dir(self.inode_arc())?;
        let (removed_entry, removed_sub_entries) = {
            let mut entries = dir.entries.write();
            let Some(entry) = entries.get(name) else {
                return Err(VfsError::NotFound);
            };
            let removed_sub_entries = take_empty_dir_entries(&entry.get())?;
            (entries.remove(name), removed_sub_entries)
        };
        drop(removed_sub_entries);
        drop(removed_entry);
        Ok(())
    }

    async fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        if src_name == "." || src_name == ".." || dst_name == "." || dst_name == ".." {
            return Err(VfsError::InvalidInput);
        }
        let dst_node = dst_dir.downcast::<Self>()?;
        if !Arc::ptr_eq(&self.fs, &dst_node.fs) {
            return Err(VfsError::CrossesDevices);
        }
        if let Ok(entry) = dst_dir.lookup(dst_name).await {
            let src_entry = self.lookup(src_name).await?;
            if entry.inode() == src_entry.inode() {
                return Ok(());
            }
        }

        let src_ino = self.inode_arc().ino;
        let dst_ino = dst_node.inode_arc().ino;
        let src_entry_ino = {
            let entries = inode_as_dir(self.inode_arc())?.entries.read();
            let Some(entry) = entries.get(src_name) else {
                return Err(VfsError::NotFound);
            };
            entry.ino
        };

        let src_node = self.fs.get(src_entry_ino);
        if let NodeContent::Dir(_) = &src_node.content {
            let mut curr_ino = dst_ino;
            loop {
                if curr_ino == src_entry_ino {
                    return Err(VfsError::InvalidInput);
                }
                let curr_node = self.fs.get(curr_ino);
                let NodeContent::Dir(dir_content) = &curr_node.content else {
                    break;
                };
                let entries = dir_content.entries.read();
                let Some(parent_ref) = entries.get("..") else {
                    break;
                };
                let parent_ino = parent_ref.ino;
                if parent_ino == curr_ino {
                    break;
                }
                curr_ino = parent_ino;
            }
        }

        let (replaced_entry, replaced_sub_entries, replaced_dotdot) = {
            let src_dir_content = inode_as_dir(self.inode_arc())?;
            let dst_dir_content = inode_as_dir(dst_node.inode_arc())?;
            let mut dirs = if src_ino == dst_ino {
                RenameDirEntries::Same(src_dir_content.entries.write())
            } else if src_ino < dst_ino {
                let s = src_dir_content.entries.write();
                let d = dst_dir_content.entries.write();
                RenameDirEntries::Different(s, d)
            } else {
                let d = dst_dir_content.entries.write();
                let s = src_dir_content.entries.write();
                RenameDirEntries::Different(s, d)
            };

            let Some(src_ref) = dirs.src().get(src_name) else {
                return Err(VfsError::NotFound);
            };
            let replaced_sub_entries = if let Some(old_entry) = dirs.dst().get(dst_name) {
                if old_entry.ino == src_ref.ino {
                    return Ok(());
                }
                prepare_replace_target(src_ref, old_entry)?
            } else {
                None
            };
            let src_entry = dirs.remove_src(src_name).unwrap();
            let replaced_dotdot = if src_ino != dst_ino
                && let NodeContent::Dir(dir_content) = &src_entry.get().content
            {
                let mut sub_entries = dir_content.entries.write();
                sub_entries.insert("..".into(), InodeRef::new(self.fs.clone(), dst_ino))
            } else {
                None
            };
            let replaced_entry = dirs.insert_dst(dst_name.into(), src_entry);
            (replaced_entry, replaced_sub_entries, replaced_dotdot)
        };
        drop((replaced_sub_entries, replaced_dotdot, replaced_entry));
        Ok(())
    }
}

impl Drop for TmpNode {
    fn drop(&mut self) {
        if let Some(inode) = self.inode.take() {
            release_inode(&self.fs, inode, 0);
        }
    }
}
