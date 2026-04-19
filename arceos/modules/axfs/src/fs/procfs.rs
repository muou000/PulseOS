use alloc::{borrow::ToOwned, collections::BTreeMap, format, string::String, sync::Arc, vec::Vec};
use core::{
    any::Any,
    borrow::Borrow,
    cmp::{Ordering, min},
    ops::Deref,
    task::Context,
    time::Duration,
};

use axalloc::global_allocator;
use axfs_ng_vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, Filesystem,
    FilesystemOps, Metadata, MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType,
    Reference, StatFs, VfsError, VfsResult, WeakDirEntry, path::MAX_NAME_LEN,
};
use axpoll::{IoEvents, Pollable};
use spin::Mutex;

const ROOT_INO: u64 = 1;
const MEMINFO_INO: u64 = 2;
const MOUNTS_INO: u64 = 3;
const NEXT_DYNAMIC_INO: u64 = MOUNTS_INO + 1;

#[derive(Clone, Copy)]
enum ProcLiveFileKind {
    Meminfo,
    Mounts,
}

#[derive(PartialEq, Eq, Hash, Clone)]
struct FileName(String);

impl PartialOrd for FileName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileName {
    fn cmp(&self, other: &Self) -> Ordering {
        fn index(s: &str) -> u8 {
            match s {
                "." => 0,
                ".." => 1,
                _ => 2,
            }
        }
        (index(&self.0), &self.0).cmp(&(index(&other.0), &other.0))
    }
}

impl<T> From<T> for FileName
where
    T: Into<String>,
{
    fn from(name: T) -> Self {
        Self(name.into())
    }
}

impl Borrow<str> for FileName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[derive(Default)]
struct DirContent {
    entries: Mutex<BTreeMap<FileName, InodeRef>>,
}

#[derive(Default)]
struct FileContent {
    data: Mutex<Vec<u8>>,
}

enum NodeContent {
    Directory(DirContent),
    Live(ProcLiveFileKind),
    File(FileContent),
}

struct Inode {
    ino: u64,
    metadata: Mutex<Metadata>,
    content: NodeContent,
}

impl Inode {
    fn new_directory(ino: u64, parent_ino: u64, permission: NodePermission) -> Arc<Self> {
        let inode = Arc::new(Self {
            ino,
            metadata: Mutex::new(Metadata {
                device: 0,
                inode: ino,
                nlink: 0,
                mode: permission,
                node_type: NodeType::Directory,
                uid: 0,
                gid: 0,
                size: 0,
                block_size: 4096,
                blocks: 0,
                rdev: DeviceId::default(),
                atime: now(),
                mtime: now(),
                ctime: now(),
            }),
            content: NodeContent::Directory(DirContent::default()),
        });

        {
            let mut entries = inode.as_dir().expect("directory inode").entries.lock();
            entries.insert(".".into(), InodeRef::new(ino));
            entries.insert("..".into(), InodeRef::new(parent_ino));
        }
        inode
    }

    fn new_live_file(ino: u64, kind: ProcLiveFileKind, permission: NodePermission) -> Arc<Self> {
        Arc::new(Self {
            ino,
            metadata: Mutex::new(Metadata {
                device: 0,
                inode: ino,
                nlink: 0,
                mode: permission,
                node_type: NodeType::RegularFile,
                uid: 0,
                gid: 0,
                size: 0,
                block_size: 4096,
                blocks: 0,
                rdev: DeviceId::default(),
                atime: now(),
                mtime: now(),
                ctime: now(),
            }),
            content: NodeContent::Live(kind),
        })
    }

    fn new_file(ino: u64, node_type: NodeType, permission: NodePermission) -> Arc<Self> {
        Arc::new(Self {
            ino,
            metadata: Mutex::new(Metadata {
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
                atime: now(),
                mtime: now(),
                ctime: now(),
            }),
            content: NodeContent::File(FileContent::default()),
        })
    }

    fn as_dir(&self) -> VfsResult<&DirContent> {
        match self.content {
            NodeContent::Directory(ref content) => Ok(content),
            _ => Err(VfsError::NotADirectory),
        }
    }

    fn as_file(&self) -> VfsResult<&FileContent> {
        match self.content {
            NodeContent::File(ref content) => Ok(content),
            NodeContent::Live(_) => Err(VfsError::ReadOnlyFilesystem),
            NodeContent::Directory(_) => Err(VfsError::IsADirectory),
        }
    }

    fn live_kind(&self) -> Option<ProcLiveFileKind> {
        match self.content {
            NodeContent::Live(kind) => Some(kind),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct InodeRef {
    ino: u64,
}

impl InodeRef {
    fn new(ino: u64) -> Self {
        Self { ino }
    }
}

pub struct ProcFilesystem {
    root_dir: Mutex<Option<DirEntry>>,
    inodes: Mutex<BTreeMap<u64, Arc<Inode>>>,
    next_ino: Mutex<u64>,
}

impl ProcFilesystem {
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            root_dir: Mutex::new(None),
            inodes: Mutex::new(BTreeMap::new()),
            next_ino: Mutex::new(NEXT_DYNAMIC_INO),
        });

        fs.bootstrap();

        let root_dir = DirEntry::new_dir(
            |this| ProcNode::new_dir(fs.clone(), ROOT_INO, Some(this)),
            Reference::root(),
        );
        *fs.root_dir.lock() = Some(root_dir);

        Filesystem::new(fs)
    }

    fn bootstrap(self: &Arc<Self>) {
        let root = Inode::new_directory(
            ROOT_INO,
            ROOT_INO,
            NodePermission::from_bits_truncate(0o755),
        );
        let meminfo = Inode::new_live_file(
            MEMINFO_INO,
            ProcLiveFileKind::Meminfo,
            NodePermission::from_bits_truncate(0o444),
        );
        let mounts = Inode::new_live_file(
            MOUNTS_INO,
            ProcLiveFileKind::Mounts,
            NodePermission::from_bits_truncate(0o444),
        );

        root.metadata.lock().nlink = 2;

        {
            let mut inodes = self.inodes.lock();
            inodes.insert(ROOT_INO, root.clone());
            inodes.insert(MEMINFO_INO, meminfo);
            inodes.insert(MOUNTS_INO, mounts);
        }

        let mut entries = root.as_dir().expect("proc root is dir").entries.lock();
        entries.insert("meminfo".into(), InodeRef::new(MEMINFO_INO));
        entries.insert("mounts".into(), InodeRef::new(MOUNTS_INO));
    }

    fn allocate_ino(&self) -> u64 {
        let mut next = self.next_ino.lock();
        let ino = *next;
        *next += 1;
        ino
    }

    fn get_inode(&self, ino: u64) -> VfsResult<Arc<Inode>> {
        self.inodes
            .lock()
            .get(&ino)
            .cloned()
            .ok_or(VfsError::NotFound)
    }

    fn create_inode(
        &self,
        parent_ino: u64,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<Arc<Inode>> {
        let ino = self.allocate_ino();
        let inode = match node_type {
            NodeType::Directory => Inode::new_directory(ino, parent_ino, permission),
            NodeType::CharacterDevice | NodeType::BlockDevice => {
                return Err(VfsError::OperationNotPermitted);
            }
            _ => Inode::new_file(ino, node_type, permission),
        };

        self.inodes.lock().insert(ino, inode.clone());
        Ok(inode)
    }

    fn bump_nlink(&self, ino: u64, delta: i64) -> VfsResult<()> {
        let inode = self.get_inode(ino)?;
        let mut meta = inode.metadata.lock();
        if delta < 0 {
            meta.nlink = meta.nlink.saturating_sub((-delta) as u64);
        } else {
            meta.nlink = meta.nlink.saturating_add(delta as u64);
        }
        if meta.nlink == 0 && ino >= NEXT_DYNAMIC_INO {
            drop(meta);
            self.inodes.lock().remove(&ino);
        }
        Ok(())
    }

    fn node_type_of(&self, ino: u64) -> VfsResult<NodeType> {
        Ok(self.get_inode(ino)?.metadata.lock().node_type)
    }
}

impl FilesystemOps for ProcFilesystem {
    fn name(&self) -> &str {
        "proc"
    }

    fn root_dir(&self) -> DirEntry {
        self.root_dir.lock().clone().unwrap()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            fs_type: 0x9fa0,
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

fn now() -> Duration {
    axhal::time::wall_time()
}

fn to_kib(bytes: u64) -> u64 {
    bytes / 1024
}

fn render_meminfo() -> String {
    let total_bytes = axhal::mem::total_ram_size() as u64;
    let allocator = global_allocator();
    let free_bytes = allocator.available_bytes() as u64
        + allocator.available_pages() as u64 * axhal::mem::PAGE_SIZE_4K as u64;
    let mem_free = free_bytes.min(total_bytes);
    let mem_available = mem_free;

    format!(
        "MemTotal: {:>8} kB\nMemFree: {:>9} kB\nMemAvailable: {:>4} kB\n",
        to_kib(total_bytes),
        to_kib(mem_free),
        to_kib(mem_available)
    )
}

fn render_mounts() -> String {
    let mounts = crate::list_mounts();
    let mut out = String::new();
    for mount in mounts {
        out.push_str(&mount.source);
        out.push(' ');
        out.push_str(&mount.target);
        out.push(' ');
        out.push_str(&mount.fs_type);
        out.push(' ');
        out.push_str(&mount.options);
        out.push_str(" 0 0\n");
    }
    out
}

fn render_proc_file(kind: ProcLiveFileKind) -> String {
    match kind {
        ProcLiveFileKind::Meminfo => render_meminfo(),
        ProcLiveFileKind::Mounts => render_mounts(),
    }
}

struct ProcNode {
    fs: Arc<ProcFilesystem>,
    ino: u64,
    this: Option<WeakDirEntry>,
}

impl ProcNode {
    fn new_dir(fs: Arc<ProcFilesystem>, ino: u64, this: Option<WeakDirEntry>) -> DirNode {
        DirNode::new(Arc::new(Self { fs, ino, this }))
    }

    fn new_file(fs: Arc<ProcFilesystem>, ino: u64) -> FileNode {
        FileNode::new(Arc::new(Self {
            fs,
            ino,
            this: None,
        }))
    }

    fn inode_ref(&self) -> VfsResult<Arc<Inode>> {
        self.fs.get_inode(self.ino)
    }

    fn build_entry(&self, name: &str, target_ino: u64) -> VfsResult<DirEntry> {
        let node_type = self.fs.node_type_of(target_ino)?;
        let reference = Reference::new(
            self.this.as_ref().and_then(WeakDirEntry::upgrade),
            name.to_owned(),
        );

        Ok(if node_type == NodeType::Directory {
            DirEntry::new_dir(
                |this| ProcNode::new_dir(self.fs.clone(), target_ino, Some(this)),
                reference,
            )
        } else {
            DirEntry::new_file(
                ProcNode::new_file(self.fs.clone(), target_ino),
                node_type,
                reference,
            )
        })
    }

    fn can_remove_entry(&self, name: &str) -> VfsResult<InodeRef> {
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let dir = self.inode_ref()?;
        let dir_content = dir.as_dir()?;
        let entries = dir_content.entries.lock();
        let Some(entry) = entries.get(name).cloned() else {
            return Err(VfsError::NotFound);
        };
        drop(entries);

        let target = self.fs.get_inode(entry.ino)?;
        if target.metadata.lock().node_type == NodeType::Directory {
            let child_entries = target.as_dir()?.entries.lock();
            if child_entries.len() > 2 {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }

        Ok(entry)
    }

    fn remove_entry(&self, name: &str) -> VfsResult<()> {
        let entry = self.can_remove_entry(name)?;

        let dir = self.inode_ref()?;
        let dir_content = dir.as_dir()?;
        dir_content.entries.lock().remove(name);

        let target = self.fs.get_inode(entry.ino)?;
        if target.metadata.lock().node_type == NodeType::Directory {
            self.fs.bump_nlink(dir.ino, -1)?;
        }
        self.fs.bump_nlink(entry.ino, -1)
    }
}

impl NodeOps for ProcNode {
    fn inode(&self) -> u64 {
        self.ino
    }

    fn metadata(&self) -> VfsResult<Metadata> {
        let inode = self.inode_ref()?;
        let mut metadata = inode.metadata.lock().clone();

        match &inode.content {
            NodeContent::Directory(dir) => {
                metadata.size = dir.entries.lock().len() as u64;
            }
            NodeContent::Live(kind) => {
                metadata.size = render_proc_file(*kind).len() as u64;
                metadata.blocks = metadata.size.div_ceil(512);
            }
            NodeContent::File(file) => {
                metadata.size = file.data.lock().len() as u64;
                metadata.blocks = metadata.size.div_ceil(512);
            }
        }

        Ok(metadata)
    }

    fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        let inode = self.inode_ref()?;
        if inode.live_kind().is_some() {
            return Err(VfsError::ReadOnlyFilesystem);
        }

        let mut metadata = inode.metadata.lock();
        if let Some(mode) = update.mode {
            metadata.mode = mode;
        }
        if let Some((uid, gid)) = update.owner {
            metadata.uid = uid;
            metadata.gid = gid;
        }
        if let Some(atime) = update.atime {
            metadata.atime = atime;
        }
        if let Some(mtime) = update.mtime {
            metadata.mtime = mtime;
        }
        Ok(())
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        self.fs.deref()
    }

    fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        if self
            .inode_ref()
            .ok()
            .and_then(|inode| inode.live_kind())
            .is_some()
        {
            NodeFlags::NON_CACHEABLE
        } else {
            NodeFlags::ALWAYS_CACHE
        }
    }
}

impl DirNodeOps for ProcNode {
    fn read_dir(&self, offset: u64, sink: &mut dyn DirEntrySink) -> VfsResult<usize> {
        let inode = self.inode_ref()?;
        let entries = inode.as_dir()?.entries.lock();
        let mut count = 0;
        for (idx, (name, entry)) in entries.iter().enumerate().skip(offset as usize) {
            let node_type = self.fs.node_type_of(entry.ino)?;
            if !sink.accept(&name.0, entry.ino, node_type, (idx + 1) as u64) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let inode = self.inode_ref()?;
        let entries = inode.as_dir()?.entries.lock();
        let entry = entries.get(name).ok_or(VfsError::NotFound)?;
        self.build_entry(name, entry.ino)
    }

    fn is_cacheable(&self) -> bool {
        true
    }

    fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let parent = self.inode_ref()?;
        let parent_dir = parent.as_dir()?;
        let mut entries = parent_dir.entries.lock();
        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }

        let inode = self.fs.create_inode(self.ino, node_type, permission)?;
        if node_type == NodeType::Directory {
            self.fs.bump_nlink(self.ino, 1)?;
        }

        entries.insert(name.into(), InodeRef::new(inode.ino));
        drop(entries);
        self.fs.bump_nlink(inode.ino, 1)?;

        self.build_entry(name, inode.ino)
    }

    fn link(&self, name: &str, target: &DirEntry) -> VfsResult<DirEntry> {
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let target = target.downcast::<Self>()?;
        let target_inode = target.inode_ref()?;
        if target_inode.metadata.lock().node_type == NodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        let parent = self.inode_ref()?;
        let parent_dir = parent.as_dir()?;
        let mut entries = parent_dir.entries.lock();
        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }

        entries.insert(name.into(), InodeRef::new(target.ino));
        drop(entries);
        self.fs.bump_nlink(target.ino, 1)?;
        self.build_entry(name, target.ino)
    }

    fn unlink(&self, name: &str) -> VfsResult<()> {
        self.remove_entry(name)
    }

    fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        if src_name == "." || src_name == ".." || dst_name == "." || dst_name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let dst_node = dst_dir.downcast::<Self>()?;
        if self.ino == dst_node.ino && src_name == dst_name {
            return Ok(());
        }

        let src_inode = self.inode_ref()?;
        let src_dir = src_inode.as_dir()?;

        let moved_ref = {
            let src_entries = src_dir.entries.lock();
            src_entries
                .get(src_name)
                .cloned()
                .ok_or(VfsError::NotFound)?
        };

        if let Ok(existing) = dst_node.lookup(dst_name) {
            let existing = existing.downcast::<Self>()?;
            if existing.ino == moved_ref.ino {
                return Ok(());
            }
            dst_node.can_remove_entry(dst_name)?;
        }

        let moved_ref = {
            let mut src_entries = src_dir.entries.lock();
            src_entries.remove(src_name).ok_or(VfsError::NotFound)?
        };

        if dst_node.lookup(dst_name).is_ok() {
            dst_node.remove_entry(dst_name)?;
        }

        let moved_inode = self.fs.get_inode(moved_ref.ino)?;
        let moved_type = moved_inode.metadata.lock().node_type;

        if moved_type == NodeType::Directory && self.ino != dst_node.ino {
            self.fs.bump_nlink(self.ino, -1)?;
            self.fs.bump_nlink(dst_node.ino, 1)?;
            moved_inode
                .as_dir()?
                .entries
                .lock()
                .insert("..".into(), InodeRef::new(dst_node.ino));
        }

        let dst_inode = dst_node.inode_ref()?;
        let dst_content = dst_inode.as_dir()?;
        dst_content
            .entries
            .lock()
            .insert(dst_name.into(), moved_ref);
        Ok(())
    }
}

impl FileNodeOps for ProcNode {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let inode = self.inode_ref()?;

        if let Some(kind) = inode.live_kind() {
            let content = render_proc_file(kind);
            let bytes = content.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let read_len = min(buf.len(), bytes.len() - start);
            buf[..read_len].copy_from_slice(&bytes[start..start + read_len]);
            return Ok(read_len);
        }

        let file = inode.as_file()?;
        let data = file.data.lock();
        let start = offset as usize;
        if start >= data.len() {
            return Ok(0);
        }
        let read_len = min(buf.len(), data.len() - start);
        buf[..read_len].copy_from_slice(&data[start..start + read_len]);
        Ok(read_len)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        let inode = self.inode_ref()?;
        if inode.live_kind().is_some() {
            return Err(VfsError::ReadOnlyFilesystem);
        }

        let file = inode.as_file()?;
        let mut data = file.data.lock();
        let start = offset as usize;
        let end = start.saturating_add(buf.len());
        if end > data.len() {
            data.resize(end, 0);
        }
        data[start..end].copy_from_slice(buf);
        Ok(buf.len())
    }

    fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)> {
        let inode = self.inode_ref()?;
        if inode.live_kind().is_some() {
            return Err(VfsError::ReadOnlyFilesystem);
        }

        let file = inode.as_file()?;
        let mut data = file.data.lock();
        let offset = data.len() as u64;
        data.extend_from_slice(buf);
        Ok((buf.len(), offset))
    }

    fn set_len(&self, len: u64) -> VfsResult<()> {
        let inode = self.inode_ref()?;
        if inode.live_kind().is_some() {
            return Err(VfsError::ReadOnlyFilesystem);
        }

        let file = inode.as_file()?;
        file.data.lock().resize(len as usize, 0);
        Ok(())
    }

    fn set_symlink(&self, _target: &str) -> VfsResult<()> {
        Err(VfsError::PermissionDenied)
    }
}

impl Pollable for ProcNode {
    fn poll(&self) -> IoEvents {
        if self
            .inode_ref()
            .ok()
            .and_then(|inode| inode.live_kind())
            .is_some()
        {
            IoEvents::IN
        } else {
            IoEvents::IN | IoEvents::OUT
        }
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}
