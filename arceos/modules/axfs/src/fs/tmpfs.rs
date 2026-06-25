use alloc::{borrow::ToOwned, string::String, sync::Arc};
use core::{any::Any, task::Context, time::Duration};

use axpoll::{IoEvents, Pollable};
use slab::Slab;
use kspin::SpinNoIrq as Mutex;

use axfs_ng_vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, Filesystem,
    FilesystemOps, Metadata, MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType,
    Reference, StatFs, VfsError, VfsResult, WeakDirEntry, path::MAX_NAME_LEN,
    InMemDir, InMemInode, update_metadata_impl, read_dir_impl,
};

const TMPFS_MAGIC: u64 = 0x0102_1994;

pub struct TmpFilesystem {
    inodes: Mutex<Slab<Arc<Inode>>>,
    root: Mutex<Option<DirEntry>>,
}

impl TmpFilesystem {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            inodes: Mutex::new(Slab::new()),
            root: Mutex::default(),
        });
        let root_ino = new_inode(
            &fs,
            None,
            NodeType::Directory,
            NodePermission::from_bits_truncate(0o755),
        );
        *fs.root.lock() = Some(DirEntry::new_dir(
            |this| DirNode::new(TmpNode::new(fs.clone(), root_ino, Some(this))),
            Reference::root(),
        ));
        Filesystem::new(fs)
    }

    fn get(&self, ino: u64) -> Arc<Inode> {
        self.inodes.lock()[ino as usize - 1].clone()
    }
}

impl FilesystemOps for TmpFilesystem {
    fn name(&self) -> &str {
        "tmpfs"
    }

    fn root_dir(&self) -> DirEntry {
        self.root.lock().clone().unwrap()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            fs_type: TMPFS_MAGIC as _,
            block_size: 4096,
            blocks: 0,
            blocks_free: 0,
            blocks_available: 0,
            file_count: self.inodes.lock().len() as u64,
            free_file_count: 0,
            name_length: MAX_NAME_LEN as u32,
            fragment_size: 4096,
            mount_flags: 0,
        })
    }
}

fn release_inode(fs: &TmpFilesystem, inode: &Arc<Inode>, nlink: u64) {
    let mut inodes = fs.inodes.lock();
    let mut metadata = inode.metadata.lock();
    metadata.nlink -= nlink;
    if metadata.nlink == 0 && Arc::strong_count(inode) == 2 {
        inodes.remove(metadata.inode as usize - 1);
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
    let mut inodes = fs.inodes.lock();
    let entry = inodes.vacant_entry();
    let ino = entry.key() as u64 + 1;
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
    let result = Arc::new(InMemInode::new(
        ino,
        metadata,
        content,
    ));
    entry.insert(result.clone());
    drop(inodes);

    if let NodeContent::Dir(dir) = &result.content {
        let mut entries = dir.entries.lock();
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
    fs: Arc<TmpFilesystem>,
    ino: u64,
}

impl InodeRef {
    pub fn new(fs: Arc<TmpFilesystem>, ino: u64) -> Self {
        fs.get(ino).metadata.lock().nlink += 1;
        Self { fs, ino }
    }

    fn get(&self) -> Arc<Inode> {
        self.fs.get(self.ino)
    }
}

impl Drop for InodeRef {
    fn drop(&mut self) {
        release_inode(&self.fs, &self.get(), 1);
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
        let reference = Reference::new(
            self.this.clone(),
            name.to_owned(),
        );
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

impl NodeOps for TmpNode {
    fn inode(&self) -> u64 {
        self.inode.ino
    }

    fn metadata(&self) -> VfsResult<Metadata> {
        let mut metadata = self.inode.metadata.lock().clone();
        match &self.inode.content {
            NodeContent::File(content) => {
                metadata.size = *content.length.lock();
            }
            NodeContent::Dir(dir) => {
                metadata.size = dir.entries.lock().len() as u64;
            }
        }
        Ok(metadata)
    }

    fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        update_metadata_impl(&mut self.inode.metadata.lock(), update);
        Ok(())
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        self.fs.as_ref()
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::ALWAYS_CACHE
    }
}

impl FileNodeOps for TmpNode {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let file = inode_as_file(&self.inode)?;
        if let Some(symlink) = file.symlink.lock().as_ref() {
            assert_eq!(offset, 0);
            let len = buf.len().min(symlink.len());
            buf[..len].copy_from_slice(&symlink.as_bytes()[..len]);
            return Ok(len);
        }
        unreachable!("page cache should handle reading");
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> VfsResult<usize> {
        unreachable!("page cache should handle writing");
    }

    fn append(&self, _buf: &[u8]) -> VfsResult<(usize, u64)> {
        unreachable!("page cache should handle writing");
    }

    fn set_len(&self, len: u64) -> VfsResult<()> {
        *inode_as_file(&self.inode)?.length.lock() = len;
        Ok(())
    }

    fn set_symlink(&self, target: &str) -> VfsResult<()> {
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

impl DirNodeOps for TmpNode {
    fn read_dir(&self, offset: u64, sink: &mut dyn DirEntrySink) -> VfsResult<usize> {
        let dir = inode_as_dir(&self.inode)?;
        read_dir_impl(&dir.entries, offset, sink, |entry| {
            (entry.ino, entry.get().metadata.lock().node_type)
        })
    }

    fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let dir = inode_as_dir(&self.inode)?;
        let entries = dir.entries.lock();

        let entry = entries.get(name).ok_or(VfsError::NotFound)?;
        let inode = entry.get();
        let node_type = inode.metadata.lock().node_type;
        self.new_entry(name, node_type, inode)
    }

    fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        let dir = inode_as_dir(&self.inode)?;
        let mut entries = dir.entries.lock();

        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let inode = new_inode(&self.fs, Some(self.inode.ino), node_type, permission);
        entries.insert(name.into(), InodeRef::new(self.fs.clone(), inode.ino));
        self.new_entry(name, node_type, inode)
    }

    fn link(&self, name: &str, target: &DirEntry) -> VfsResult<DirEntry> {
        let dir = inode_as_dir(&self.inode)?;
        let mut entries = dir.entries.lock();

        let target = target.downcast::<Self>()?;

        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let inode = target.inode.clone();
        let node_type = target.metadata()?.node_type;
        entries.insert(name.into(), InodeRef::new(self.fs.clone(), inode.ino));
        self.new_entry(name, node_type, inode)
    }

    fn unlink(&self, name: &str) -> VfsResult<()> {
        let dir = inode_as_dir(&self.inode)?;
        let mut entries = dir.entries.lock();

        let Some(entry) = entries.get(name) else {
            return Err(VfsError::NotFound);
        };
        if let NodeContent::Dir(dir_content) = &entry.get().content {
            if dir_content.entries.lock().len() > 2 {
                return Err(VfsError::DirectoryNotEmpty);
            }
            dir_content.entries.lock().clear();
        }
        entries.remove(name);
        Ok(())
    }

    fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        let dst_node = dst_dir.downcast::<Self>()?;
        if let Ok(entry) = dst_dir.lookup(dst_name) {
            let src_entry = self.lookup(src_name)?;
            if entry.inode() == src_entry.inode() {
                return Ok(());
            }
        }

        let src_entry = inode_as_dir(&self.inode)?
            .entries
            .lock()
            .remove(src_name)
            .ok_or(VfsError::NotFound)?;
        let old_dst = inode_as_dir(&dst_node.inode)?
            .entries
            .lock()
            .insert(dst_name.into(), src_entry);
        if let Some(old_dst) = old_dst {
            if let NodeContent::Dir(dir_content) = &old_dst.get().content {
                dir_content.entries.lock().clear();
            }
        }
        Ok(())
    }
}

impl Drop for TmpNode {
    fn drop(&mut self) {
        release_inode(&self.fs, &self.inode, 0);
    }
}
