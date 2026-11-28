use alloc::{
    borrow::ToOwned,
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    any::Any,
    cmp::min,
    ops::Deref,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::Context,
};

use async_trait::async_trait;
use kspin::SpinNoPreempt;
use poll::{IoEvents, Pollable};
use vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, Filesystem, FilesystemOps, InMemDir,
    InMemInode, Metadata, MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType, Reference,
    StatFs, VfsError, VfsResult, WeakDirEntry, cmp_file_name, path::MAX_NAME_LEN,
};

const ROOT_INO: u64 = 1;
const NEXT_INO: u64 = 2;

type DirContent = InMemDir<u64>;
type Inode = InMemInode<NodeContent>;

#[derive(Clone, Copy)]
enum SysFileKind {
    CpuOnline,
    CpuPossible,
    CpuPresent,
    NodeOnline,
    NodePossible,
    Node0Cpumap,
    Node0Cpulist,
    Node0Online,
    Node0Possible,
    Node0HasCpu,
    Node0HasMemory,
}

enum NodeContent {
    Directory(DirContent),
    Live(SysFileKind),
}

fn now() -> core::time::Duration {
    hal::time::wall_time()
}

fn new_directory(ino: u64, parent_ino: u64) -> Arc<Inode> {
    let inode = Arc::new(InMemInode::new(
        ino,
        Metadata {
            device: 0,
            inode: ino,
            nlink: 2,
            mode: NodePermission::from_bits_truncate(0o555),
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
        },
        NodeContent::Directory(DirContent::new()),
    ));
    let mut entries = match &inode.content {
        NodeContent::Directory(content) => content.entries.write(),
        NodeContent::Live(_) => unreachable!(),
    };
    entries.insert(".".into(), ino);
    entries.insert("..".into(), parent_ino);
    drop(entries);
    inode
}

fn new_live_file(ino: u64, kind: SysFileKind) -> Arc<Inode> {
    Arc::new(InMemInode::new(
        ino,
        Metadata {
            device: 0,
            inode: ino,
            nlink: 1,
            mode: NodePermission::from_bits_truncate(0o444),
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
        },
        NodeContent::Live(kind),
    ))
}

fn inode_as_dir(inode: &Inode) -> VfsResult<&DirContent> {
    match &inode.content {
        NodeContent::Directory(content) => Ok(content),
        NodeContent::Live(_) => Err(VfsError::NotADirectory),
    }
}

fn inode_live_kind(inode: &Inode) -> Option<SysFileKind> {
    match &inode.content {
        NodeContent::Live(kind) => Some(*kind),
        NodeContent::Directory(_) => None,
    }
}

fn possible_cpu_mask() -> usize {
    let count = hal::cpu_num().min(usize::BITS as usize);
    if count == 0 {
        0
    } else if count == usize::BITS as usize {
        usize::MAX
    } else {
        (1usize << count) - 1
    }
}

fn online_cpu_mask() -> usize {
    hal::online_cpu_mask() & possible_cpu_mask()
}

fn render_cpu_list(mask: usize) -> String {
    let max_cpu = hal::cpu_num().min(usize::BITS as usize);
    let mut output = String::new();
    let mut range_start = None;
    let mut previous = 0;

    for cpu in 0..=max_cpu {
        let online = cpu < max_cpu && mask & (1usize << cpu) != 0;
        if online {
            if range_start.is_none() {
                range_start = Some(cpu);
            }
            previous = cpu;
            continue;
        }

        if let Some(start) = range_start.take() {
            if !output.is_empty() {
                output.push(',');
            }
            if start == previous {
                output.push_str(&start.to_string());
            } else {
                output.push_str(&format!("{start}-{previous}"));
            }
        }
    }

    output.push('\n');
    output
}

fn render_cpu_map(mask: usize) -> String {
    let group_count = (usize::BITS as usize / 32).max(1);
    let mut output = String::new();
    let mut first = true;
    for group in (0..group_count).rev() {
        let shift = group * 32;
        let value = if shift >= usize::BITS as usize {
            0
        } else {
            (mask >> shift) as u32
        };
        if first && value == 0 {
            continue;
        }
        if !first {
            output.push(',');
        }
        if first {
            output.push_str(&format!("{value:x}"));
            first = false;
        } else {
            output.push_str(&format!("{value:08x}"));
        }
    }
    if first {
        output.push('0');
    }
    output.push('\n');
    output
}

fn render_sys_file(kind: SysFileKind) -> String {
    match kind {
        SysFileKind::CpuOnline | SysFileKind::CpuPresent => render_cpu_list(online_cpu_mask()),
        SysFileKind::CpuPossible => render_cpu_list(possible_cpu_mask()),
        SysFileKind::NodeOnline | SysFileKind::NodePossible => "0\n".to_owned(),
        SysFileKind::Node0Cpumap => render_cpu_map(online_cpu_mask()),
        SysFileKind::Node0Cpulist => render_cpu_list(online_cpu_mask()),
        SysFileKind::Node0Online
        | SysFileKind::Node0Possible
        | SysFileKind::Node0HasCpu
        | SysFileKind::Node0HasMemory => "1\n".to_owned(),
    }
}

pub struct SysFilesystem {
    root_dir: SpinNoPreempt<Option<DirEntry>>,
    inodes: SpinNoPreempt<BTreeMap<u64, Arc<Inode>>>,
    next_ino: AtomicU64,
    inode_count: AtomicUsize,
}

impl SysFilesystem {
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            root_dir: SpinNoPreempt::new(None),
            inodes: SpinNoPreempt::new(BTreeMap::new()),
            next_ino: AtomicU64::new(NEXT_INO),
            inode_count: AtomicUsize::new(0),
        });
        fs.bootstrap();
        let root_dir = DirEntry::new_dir(
            |this| SysNode::new_dir(fs.clone(), ROOT_INO, Some(this)),
            Reference::root(),
        );
        *fs.root_dir.lock() = Some(root_dir);
        Filesystem::new(fs)
    }

    fn insert_inode(&self, inode: Arc<Inode>) {
        self.inodes.lock().insert(inode.ino, inode);
        self.inode_count.fetch_add(1, Ordering::Relaxed);
    }

    fn get_inode(&self, ino: u64) -> VfsResult<Arc<Inode>> {
        self.inodes
            .lock()
            .get(&ino)
            .cloned()
            .ok_or(VfsError::NotFound)
    }

    fn allocate_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::AcqRel)
    }

    fn add_dir(self: &Arc<Self>, parent: u64, name: &str) -> u64 {
        let ino = self.allocate_ino();
        self.insert_inode(new_directory(ino, parent));
        self.add_child(parent, name, ino);
        ino
    }

    fn add_file(self: &Arc<Self>, parent: u64, name: &str, kind: SysFileKind) -> u64 {
        let ino = self.allocate_ino();
        self.insert_inode(new_live_file(ino, kind));
        self.add_child(parent, name, ino);
        ino
    }

    fn add_child(&self, parent: u64, name: &str, child: u64) {
        let inode = self.get_inode(parent).expect("sysfs parent inode");
        let dir = inode_as_dir(&inode).expect("sysfs parent directory");
        dir.entries.write().insert(name.into(), child);
        if self
            .get_inode(child)
            .expect("sysfs child inode")
            .metadata
            .lock()
            .node_type
            == NodeType::Directory
        {
            inode.metadata.lock().nlink += 1;
        }
    }

    fn bootstrap(self: &Arc<Self>) {
        self.insert_inode(new_directory(ROOT_INO, ROOT_INO));
        let devices = self.add_dir(ROOT_INO, "devices");
        let system = self.add_dir(devices, "system");
        let cpu = self.add_dir(system, "cpu");
        let node = self.add_dir(system, "node");

        self.add_file(cpu, "online", SysFileKind::CpuOnline);
        self.add_file(cpu, "possible", SysFileKind::CpuPossible);
        self.add_file(cpu, "present", SysFileKind::CpuPresent);

        self.add_file(node, "online", SysFileKind::NodeOnline);
        self.add_file(node, "possible", SysFileKind::NodePossible);
        let node0 = self.add_dir(node, "node0");
        self.add_file(node0, "cpumap", SysFileKind::Node0Cpumap);
        self.add_file(node0, "cpulist", SysFileKind::Node0Cpulist);
        self.add_file(node0, "online", SysFileKind::Node0Online);
        self.add_file(node0, "possible", SysFileKind::Node0Possible);
        self.add_file(node0, "has_cpu", SysFileKind::Node0HasCpu);
        self.add_file(node0, "has_memory", SysFileKind::Node0HasMemory);
    }
}

#[async_trait]
impl FilesystemOps for SysFilesystem {
    fn name(&self) -> &str {
        "sysfs"
    }

    fn root_dir(&self) -> DirEntry {
        self.root_dir.lock().clone().unwrap()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        Ok(StatFs {
            fs_type: 0x6265_6572,
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

struct SysNode {
    fs: Arc<SysFilesystem>,
    ino: u64,
    this: Option<WeakDirEntry>,
}

impl SysNode {
    fn new_dir(fs: Arc<SysFilesystem>, ino: u64, this: Option<WeakDirEntry>) -> DirNode {
        DirNode::new(Arc::new(Self { fs, ino, this }))
    }

    fn new_file(fs: Arc<SysFilesystem>, ino: u64) -> vfs::FileNode {
        vfs::FileNode::new(Arc::new(Self {
            fs,
            ino,
            this: None,
        }))
    }

    fn inode_ref(&self) -> VfsResult<Arc<Inode>> {
        self.fs.get_inode(self.ino)
    }

    fn build_entry(&self, name: &str, ino: u64) -> VfsResult<DirEntry> {
        let node_type = self.fs.get_inode(ino)?.metadata.lock().node_type;
        let reference = Reference::new(self.this.clone(), name.to_owned());
        Ok(if node_type == NodeType::Directory {
            DirEntry::new_dir(
                |this| SysNode::new_dir(self.fs.clone(), ino, Some(this)),
                reference,
            )
        } else {
            DirEntry::new_file(
                SysNode::new_file(self.fs.clone(), ino),
                node_type,
                reference,
            )
        })
    }
}

#[async_trait]
impl NodeOps for SysNode {
    fn inode(&self) -> u64 {
        self.ino
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        let inode = self.inode_ref()?;
        let mut metadata = inode.metadata.lock().clone();
        match &inode.content {
            NodeContent::Directory(dir) => metadata.size = dir.entries.read().len() as u64,
            NodeContent::Live(kind) => {
                metadata.size = render_sys_file(*kind).len() as u64;
                metadata.blocks = metadata.size.div_ceil(512);
            }
        }
        Ok(metadata)
    }

    async fn update_metadata(&self, _update: MetadataUpdate) -> VfsResult<()> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        self.fs.deref()
    }

    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::NON_CACHEABLE
    }
}

#[async_trait]
impl DirNodeOps for SysNode {
    async fn read_dir(
        &self,
        offset: u64,
        sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        let inode = self.inode_ref()?;
        let dir = inode_as_dir(&inode)?;
        let mut entries: Vec<(String, u64)> = dir
            .entries
            .read()
            .iter()
            .map(|(name, &ino)| (name.0.clone(), ino))
            .collect();
        entries.sort_by(|a, b| cmp_file_name(&a.0, &b.0));
        let mut count = 0;
        for (idx, (name, ino)) in entries.iter().enumerate().skip(offset as usize) {
            let node_type = self.fs.get_inode(*ino)?.metadata.lock().node_type;
            if !sink.accept(name, *ino, node_type, (idx + 1) as u64) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let inode = self.inode_ref()?;
        let dir = inode_as_dir(&inode)?;
        let ino = dir
            .entries
            .read()
            .get(name)
            .copied()
            .ok_or(VfsError::NotFound)?;
        self.build_entry(name, ino)
    }

    fn is_cacheable(&self) -> bool {
        false
    }

    async fn create(
        &self,
        _name: &str,
        _node_type: NodeType,
        _permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn link(&self, _name: &str, _target: &DirEntry) -> VfsResult<DirEntry> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn unlink(&self, _name: &str) -> VfsResult<()> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn rename(&self, _src_name: &str, _dst_dir: &DirNode, _dst_name: &str) -> VfsResult<()> {
        Err(VfsError::ReadOnlyFilesystem)
    }
}

#[async_trait]
impl vfs::FileNodeOps for SysNode {
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        let inode = self.inode_ref()?;
        let kind = inode_live_kind(&inode).ok_or(VfsError::IsADirectory)?;
        let content = render_sys_file(kind);
        let bytes = content.as_bytes();
        let start = offset as usize;
        if start >= bytes.len() {
            return Ok(0);
        }
        let read_len = min(buf.len(), bytes.len() - start);
        buf[..read_len].copy_from_slice(&bytes[start..start + read_len]);
        Ok(read_len)
    }

    async fn write_at(&self, _buf: &[u8], _offset: u64) -> VfsResult<usize> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn append(&self, _buf: &[u8]) -> VfsResult<(usize, u64)> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn set_len(&self, _len: u64) -> VfsResult<()> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn set_symlink(&self, _target: &str) -> VfsResult<()> {
        Err(VfsError::ReadOnlyFilesystem)
    }

    async fn ioctl(&self, _cmd: u32, _arg: usize) -> VfsResult<usize> {
        Err(VfsError::NotATty)
    }
}

impl Pollable for SysNode {
    fn poll(&self) -> IoEvents {
        IoEvents::IN
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}
