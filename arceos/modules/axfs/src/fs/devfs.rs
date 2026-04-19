use alloc::{borrow::ToOwned, collections::BTreeMap, string::String, sync::Arc};
use core::{
    any::Any,
    borrow::Borrow,
    cmp::{Ordering, min},
    ops::Deref,
    task::Context,
    time::Duration,
};

use axfs_ng_vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, Filesystem,
    FilesystemOps, Metadata, MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType,
    Reference, StatFs, VfsError, VfsResult, WeakDirEntry, path::MAX_NAME_LEN,
};
use axpoll::{IoEvents, Pollable};
use spin::Mutex;

const ROOT_INO: u64 = 1;
const MISC_INO: u64 = 2;
const NULL_INO: u64 = 3;
const RTC_INO: u64 = 4;
const CPU_DMA_LATENCY_INO: u64 = 5;
const SHM_INO: u64 = 6;

const NEXT_DYNAMIC_INO: u64 = SHM_INO + 1;

#[derive(Clone, Copy)]
enum DevDeviceKind {
    Null,
    Rtc,
    CpuDmaLatency,
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
    length: Mutex<u64>,
}

enum NodeContent {
    Directory(DirContent),
    Device(DevDeviceKind),
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

    fn new_device(ino: u64, kind: DevDeviceKind, mode: u16, major: u32, minor: u32) -> Arc<Self> {
        Arc::new(Self {
            ino,
            metadata: Mutex::new(Metadata {
                device: 0,
                inode: ino,
                nlink: 0,
                mode: NodePermission::from_bits_truncate(mode),
                node_type: NodeType::CharacterDevice,
                uid: 0,
                gid: 0,
                size: 0,
                block_size: 4096,
                blocks: 0,
                rdev: DeviceId::new(major, minor),
                atime: now(),
                mtime: now(),
                ctime: now(),
            }),
            content: NodeContent::Device(kind),
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
            NodeContent::Device(_) => Err(VfsError::OperationNotPermitted),
            NodeContent::Directory(_) => Err(VfsError::IsADirectory),
        }
    }

    fn device_kind(&self) -> Option<DevDeviceKind> {
        match self.content {
            NodeContent::Device(kind) => Some(kind),
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

pub struct DevFilesystem {
    root_dir: Mutex<Option<DirEntry>>,
    inodes: Mutex<BTreeMap<u64, Arc<Inode>>>,
    next_ino: Mutex<u64>,
}

impl DevFilesystem {
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            root_dir: Mutex::new(None),
            inodes: Mutex::new(BTreeMap::new()),
            next_ino: Mutex::new(NEXT_DYNAMIC_INO),
        });

        fs.bootstrap();

        let root_dir = DirEntry::new_dir(
            |this| DevNode::new_dir(fs.clone(), ROOT_INO, Some(this)),
            Reference::root(),
        );
        *fs.root_dir.lock() = Some(root_dir);

        Filesystem::new(fs)
    }

    fn bootstrap(self: &Arc<Self>) {
        let mut inodes = self.inodes.lock();

        let root = Inode::new_directory(
            ROOT_INO,
            ROOT_INO,
            NodePermission::from_bits_truncate(0o755),
        );
        let misc = Inode::new_directory(
            MISC_INO,
            ROOT_INO,
            NodePermission::from_bits_truncate(0o755),
        );
        let shm =
            Inode::new_directory(SHM_INO, ROOT_INO, NodePermission::from_bits_truncate(0o777));

        let null = Inode::new_device(NULL_INO, DevDeviceKind::Null, 0o666, 1, 3);
        let rtc = Inode::new_device(RTC_INO, DevDeviceKind::Rtc, 0o666, 254, 0);
        let cpu_dma = Inode::new_device(
            CPU_DMA_LATENCY_INO,
            DevDeviceKind::CpuDmaLatency,
            0o666,
            10,
            63,
        );

        root.metadata.lock().nlink = 2;
        misc.metadata.lock().nlink = 2;
        shm.metadata.lock().nlink = 2;

        self.insert_entry_locked(&root, "misc", MISC_INO, &inodes);
        self.insert_entry_locked(&root, "shm", SHM_INO, &inodes);
        self.insert_entry_locked(&root, "null", NULL_INO, &inodes);
        self.insert_entry_locked(&root, "rtc", RTC_INO, &inodes);
        self.insert_entry_locked(&root, "cpu_dma_latency", CPU_DMA_LATENCY_INO, &inodes);
        self.insert_entry_locked(&misc, "rtc", RTC_INO, &inodes);

        inodes.insert(ROOT_INO, root);
        inodes.insert(MISC_INO, misc);
        inodes.insert(SHM_INO, shm);
        inodes.insert(NULL_INO, null);
        inodes.insert(RTC_INO, rtc);
        inodes.insert(CPU_DMA_LATENCY_INO, cpu_dma);
    }

    fn insert_entry_locked(
        &self,
        dir: &Arc<Inode>,
        name: &str,
        target_ino: u64,
        inodes: &BTreeMap<u64, Arc<Inode>>,
    ) {
        if let Ok(content) = dir.as_dir() {
            content
                .entries
                .lock()
                .insert(name.into(), InodeRef::new(target_ino));
            if let Some(target) = inodes.get(&target_ino) {
                target.metadata.lock().nlink += 1;
            }
        }
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

impl FilesystemOps for DevFilesystem {
    fn name(&self) -> &str {
        "devtmpfs"
    }

    fn root_dir(&self) -> DirEntry {
        self.root_dir.lock().clone().unwrap()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            fs_type: 0x1373,
            block_size: 4096,
            blocks: 1,
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

struct DevNode {
    fs: Arc<DevFilesystem>,
    ino: u64,
    this: Option<WeakDirEntry>,
}

impl DevNode {
    fn new_dir(fs: Arc<DevFilesystem>, ino: u64, this: Option<WeakDirEntry>) -> DirNode {
        DirNode::new(Arc::new(Self { fs, ino, this }))
    }

    fn new_file(fs: Arc<DevFilesystem>, ino: u64, _node_type: NodeType) -> FileNode {
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
                |this| DevNode::new_dir(self.fs.clone(), target_ino, Some(this)),
                reference,
            )
        } else {
            DirEntry::new_file(
                DevNode::new_file(self.fs.clone(), target_ino, node_type),
                node_type,
                reference,
            )
        })
    }

    fn remove_entry(&self, name: &str) -> VfsResult<()> {
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }
        let dir = self.inode_ref()?;
        let dir_content = dir.as_dir()?;
        let mut entries = dir_content.entries.lock();
        let Some(entry) = entries.get(name).cloned() else {
            return Err(VfsError::NotFound);
        };

        let target = self.fs.get_inode(entry.ino)?;
        if target.metadata.lock().node_type == NodeType::Directory {
            let child_entries = target.as_dir()?.entries.lock();
            if child_entries.len() > 2 {
                return Err(VfsError::DirectoryNotEmpty);
            }
            drop(child_entries);
            self.fs.bump_nlink(dir.ino, -1)?;
        }

        entries.remove(name);
        drop(entries);
        self.fs.bump_nlink(entry.ino, -1)
    }
}

impl NodeOps for DevNode {
    fn inode(&self) -> u64 {
        self.ino
    }

    fn metadata(&self) -> VfsResult<Metadata> {
        let inode = self.inode_ref()?;
        let mut metadata = inode.metadata.lock().clone();
        if let NodeContent::Directory(dir) = &inode.content {
            metadata.size = dir.entries.lock().len() as u64;
        } else if let NodeContent::File(file) = &inode.content {
            metadata.size = *file.length.lock();
            metadata.blocks = metadata.size.div_ceil(512);
        }
        Ok(metadata)
    }

    fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        let inode = self.inode_ref()?;
        if inode.device_kind().is_some() {
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
        match self.inode_ref().ok().and_then(|i| i.device_kind()) {
            Some(_) => NodeFlags::STREAM | NodeFlags::NON_CACHEABLE,
            None => NodeFlags::ALWAYS_CACHE,
        }
    }
}

impl DirNodeOps for DevNode {
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
            let existing_inode = existing.inode_ref()?;
            if existing_inode.metadata.lock().node_type == NodeType::Directory {
                let existing_entries = existing_inode.as_dir()?.entries.lock();
                if existing_entries.len() > 2 {
                    return Err(VfsError::DirectoryNotEmpty);
                }
            }
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

impl FileNodeOps for DevNode {
    fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let inode = self.inode_ref()?;
        match inode.device_kind() {
            Some(DevDeviceKind::Null) => Ok(0),
            Some(DevDeviceKind::Rtc) => Ok(0),
            Some(DevDeviceKind::CpuDmaLatency) => {
                let bytes = i32::MAX.to_ne_bytes();
                let start = offset as usize;
                if start >= bytes.len() {
                    return Ok(0);
                }
                let n = min(buf.len(), bytes.len() - start);
                buf[..n].copy_from_slice(&bytes[start..start + n]);
                Ok(n)
            }
            None => {
                let file = inode.as_file()?;
                let len = *file.length.lock();
                let start = offset;
                if start >= len {
                    return Ok(0);
                }
                let n = min(buf.len() as u64, len - start) as usize;
                buf[..n].fill(0);
                Ok(n)
            }
        }
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        let inode = self.inode_ref()?;
        match inode.device_kind() {
            Some(DevDeviceKind::Null) => Ok(buf.len()),
            Some(DevDeviceKind::Rtc) => Err(VfsError::OperationNotPermitted),
            Some(DevDeviceKind::CpuDmaLatency) => match buf.len() {
                4 | 10 => Ok(buf.len()),
                _ => Err(VfsError::InvalidInput),
            },
            None => {
                let file = inode.as_file()?;
                let end = offset.saturating_add(buf.len() as u64);
                let mut length = file.length.lock();
                if end > *length {
                    *length = end;
                }
                Ok(buf.len())
            }
        }
    }

    fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)> {
        let inode = self.inode_ref()?;
        match inode.device_kind() {
            Some(DevDeviceKind::Null) => Ok((buf.len(), 0)),
            Some(DevDeviceKind::Rtc) => Err(VfsError::OperationNotPermitted),
            Some(DevDeviceKind::CpuDmaLatency) => self.write_at(buf, 0).map(|n| (n, 0)),
            None => {
                let file = inode.as_file()?;
                let mut length = file.length.lock();
                let off = *length;
                *length = length.saturating_add(buf.len() as u64);
                Ok((buf.len(), off))
            }
        }
    }

    fn set_len(&self, len: u64) -> VfsResult<()> {
        let inode = self.inode_ref()?;
        if inode.device_kind().is_some() {
            return Err(VfsError::InvalidInput);
        }
        *inode.as_file()?.length.lock() = len;
        Ok(())
    }

    fn set_symlink(&self, _target: &str) -> VfsResult<()> {
        Err(VfsError::PermissionDenied)
    }
}

impl Pollable for DevNode {
    fn poll(&self) -> IoEvents {
        let kind = self.inode_ref().ok().and_then(|i| i.device_kind());
        match kind {
            Some(DevDeviceKind::Rtc) => IoEvents::IN | IoEvents::OUT,
            Some(DevDeviceKind::Null) | Some(DevDeviceKind::CpuDmaLatency) => {
                IoEvents::IN | IoEvents::OUT
            }
            None => IoEvents::IN | IoEvents::OUT,
        }
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}
