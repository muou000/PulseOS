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
use axfs_ng_vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, Filesystem,
    FilesystemOps, InMemDir, InMemInode, Metadata, MetadataUpdate, NodeFlags, NodeOps,
    NodePermission, NodeType, Reference, StatFs, VfsError, VfsResult, WeakDirEntry,
    path::MAX_NAME_LEN, read_dir_impl, update_metadata_impl,
};
use axpoll::{IoEvents, Pollable};
use spin::Mutex;

const TMPFS_MAGIC: u64 = 0x0102_1994;
const TMPFS_INODE_SHARDS: usize = 32;

fn inode_shard(ino: u64) -> usize {
    ino as usize % TMPFS_INODE_SHARDS
}

pub struct TmpFilesystem {
    inodes: [Mutex<BTreeMap<u64, Arc<Inode>>>; TMPFS_INODE_SHARDS],
    next_ino: AtomicU64,
    inode_count: AtomicUsize,
    root: OnceCell<DirEntry>,
}

impl TmpFilesystem {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            inodes: core::array::from_fn(|_| Mutex::new(BTreeMap::new())),
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

fn release_inode(fs: &TmpFilesystem, inode: &Arc<Inode>, nlink: u64) {
    let mut inodes = fs.inodes[inode_shard(inode.ino)].lock();
    let mut metadata = inode.metadata.lock();
    metadata.nlink -= nlink;
    if metadata.nlink == 0 && Arc::strong_count(inode) == 2 {
        let ino = metadata.inode;
        drop(metadata);
        if inodes.remove(&ino).is_some() {
            fs.inode_count.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

#[derive(Default)]
struct FileContent {
    length: Mutex<u64>,
    symlink: Mutex<Option<String>>,
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
            release_inode(&fs, &fs.get(self.ino), 1);
        }
    }
}

struct TmpNode {
    fs: Arc<TmpFilesystem>,
    inode: Arc<Inode>,
    this: Option<WeakDirEntry>,
}

impl TmpNode {
    pub fn new(fs: Arc<TmpFilesystem>, inode: Arc<Inode>, this: Option<WeakDirEntry>) -> Arc<Self> {
        Arc::new(Self { fs, inode, this })
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
        self.inode.ino
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        let mut metadata = self.inode.metadata.lock().clone();
        match &self.inode.content {
            NodeContent::File(content) => {
                metadata.size = *content.length.lock();
            }
            NodeContent::Dir(dir) => {
                metadata.size = dir.entries.read().len() as u64;
            }
        }
        Ok(metadata)
    }

    async fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        update_metadata_impl(&mut self.inode.metadata.lock(), update);
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
        NodeFlags::ALWAYS_CACHE
    }
}

#[async_trait]
impl FileNodeOps for TmpNode {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let file = inode_as_file(&self.inode)?;
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
        *inode_as_file(&self.inode)?.length.lock() = len;
        Ok(())
    }

    async fn set_symlink(&self, target: &str) -> VfsResult<()> {
        let file = inode_as_file(&self.inode)?;
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

#[async_trait]
impl DirNodeOps for TmpNode {
    async fn read_dir(
        &self,
        offset: u64,
        sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        let dir = inode_as_dir(&self.inode)?;
        read_dir_impl(&dir.entries, offset, sink, |entry| {
            (entry.ino, entry.get().metadata.lock().node_type)
        })
    }

    async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let dir = inode_as_dir(&self.inode)?;
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
        let dir = inode_as_dir(&self.inode)?;
        let mut entries = dir.entries.write();

        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let inode = new_inode(&self.fs, Some(self.inode.ino), node_type, permission);
        entries.insert(name.into(), InodeRef::new(self.fs.clone(), inode.ino));
        self.new_entry(name, node_type, inode)
    }

    async fn link(&self, name: &str, target: &DirEntry) -> VfsResult<DirEntry> {
        let target = target.downcast::<Self>()?;
        let inode = target.inode.clone();
        let node_type = target.metadata().await?.node_type;

        let dir = inode_as_dir(&self.inode)?;
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
        let dir = inode_as_dir(&self.inode)?;
        let mut entries = dir.entries.write();

        let Some(entry) = entries.get(name) else {
            return Err(VfsError::NotFound);
        };
        if let NodeContent::Dir(dir_content) = &entry.get().content {
            let mut sub_entries = dir_content.entries.write();
            if sub_entries.len() > 2 {
                return Err(VfsError::DirectoryNotEmpty);
            }
            sub_entries.clear();
        }
        entries.remove(name);
        Ok(())
    }

    async fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        if src_name == "." || src_name == ".." || dst_name == "." || dst_name == ".." {
            return Err(VfsError::InvalidInput);
        }
        let dst_node = dst_dir.downcast::<Self>()?;
        if let Ok(entry) = dst_dir.lookup(dst_name).await {
            let src_entry = self.lookup(src_name).await?;
            if entry.inode() == src_entry.inode() {
                return Ok(());
            }
        }

        let src_entry_ino = {
            let entries = inode_as_dir(&self.inode)?.entries.read();
            let Some(entry) = entries.get(src_name) else {
                return Err(VfsError::NotFound);
            };
            entry.ino
        };

        let src_node = self.fs.get(src_entry_ino);
        if let NodeContent::Dir(_) = &src_node.content {
            let mut curr_ino = dst_node.inode.ino;
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

        if self.inode.ino == dst_node.inode.ino {
            let mut entries = inode_as_dir(&self.inode)?.entries.write();
            if !entries.contains_key(src_name) {
                return Err(VfsError::NotFound);
            }
            if let Some(old_entry) = entries.get(dst_name) {
                let src_ref = entries.get(src_name).unwrap();
                let is_src_dir = match &src_ref.get().content {
                    NodeContent::Dir(_) => true,
                    _ => false,
                };
                let is_dst_dir = match &old_entry.get().content {
                    NodeContent::Dir(_) => true,
                    _ => false,
                };
                match (is_src_dir, is_dst_dir) {
                    (true, false) => return Err(VfsError::NotADirectory),
                    (false, true) => return Err(VfsError::IsADirectory),
                    (true, true) => {
                        if let NodeContent::Dir(dir_content) = &old_entry.get().content {
                            let mut sub_entries = dir_content.entries.write();
                            if sub_entries.len() > 2 {
                                return Err(VfsError::DirectoryNotEmpty);
                            }
                            sub_entries.clear();
                        }
                    }
                    (false, false) => {}
                }
            }
            let src_entry = entries.remove(src_name).unwrap();
            entries.insert(dst_name.into(), src_entry);
        } else if self.inode.ino < dst_node.inode.ino {
            let mut src_entries = inode_as_dir(&self.inode)?.entries.write();
            if !src_entries.contains_key(src_name) {
                return Err(VfsError::NotFound);
            }
            let mut dst_entries = inode_as_dir(&dst_node.inode)?.entries.write();
            if let Some(old_entry) = dst_entries.get(dst_name) {
                let src_ref = src_entries.get(src_name).unwrap();
                let is_src_dir = match &src_ref.get().content {
                    NodeContent::Dir(_) => true,
                    _ => false,
                };
                let is_dst_dir = match &old_entry.get().content {
                    NodeContent::Dir(_) => true,
                    _ => false,
                };
                match (is_src_dir, is_dst_dir) {
                    (true, false) => return Err(VfsError::NotADirectory),
                    (false, true) => return Err(VfsError::IsADirectory),
                    (true, true) => {
                        if let NodeContent::Dir(dir_content) = &old_entry.get().content {
                            let mut sub_entries = dir_content.entries.write();
                            if sub_entries.len() > 2 {
                                return Err(VfsError::DirectoryNotEmpty);
                            }
                            sub_entries.clear();
                        }
                    }
                    (false, false) => {}
                }
            }
            let src_entry = src_entries.remove(src_name).unwrap();
            if let NodeContent::Dir(dir_content) = &src_entry.get().content {
                let mut sub_entries = dir_content.entries.write();
                sub_entries.insert(
                    "..".into(),
                    InodeRef::new(self.fs.clone(), dst_node.inode.ino),
                );
            }
            dst_entries.insert(dst_name.into(), src_entry);
        } else {
            let mut dst_entries = inode_as_dir(&dst_node.inode)?.entries.write();
            let mut src_entries = inode_as_dir(&self.inode)?.entries.write();
            if !src_entries.contains_key(src_name) {
                return Err(VfsError::NotFound);
            }
            if let Some(old_entry) = dst_entries.get(dst_name) {
                let src_ref = src_entries.get(src_name).unwrap();
                let is_src_dir = match &src_ref.get().content {
                    NodeContent::Dir(_) => true,
                    _ => false,
                };
                let is_dst_dir = match &old_entry.get().content {
                    NodeContent::Dir(_) => true,
                    _ => false,
                };
                match (is_src_dir, is_dst_dir) {
                    (true, false) => return Err(VfsError::NotADirectory),
                    (false, true) => return Err(VfsError::IsADirectory),
                    (true, true) => {
                        if let NodeContent::Dir(dir_content) = &old_entry.get().content {
                            let mut sub_entries = dir_content.entries.write();
                            if sub_entries.len() > 2 {
                                return Err(VfsError::DirectoryNotEmpty);
                            }
                            sub_entries.clear();
                        }
                    }
                    (false, false) => {}
                }
            }
            let src_entry = src_entries.remove(src_name).unwrap();
            if let NodeContent::Dir(dir_content) = &src_entry.get().content {
                let mut sub_entries = dir_content.entries.write();
                sub_entries.insert(
                    "..".into(),
                    InodeRef::new(self.fs.clone(), dst_node.inode.ino),
                );
            }
            dst_entries.insert(dst_name.into(), src_entry);
        }
        Ok(())
    }
}

impl Drop for TmpNode {
    fn drop(&mut self) {
        release_inode(&self.fs, &self.inode, 0);
    }
}
