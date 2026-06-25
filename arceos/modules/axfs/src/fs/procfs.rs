use alloc::{borrow::ToOwned, collections::BTreeMap, format, string::{String, ToString}, sync::Arc, vec::Vec};
use core::{
    any::Any,
    cmp::min,
    ops::Deref,
    task::Context,
    time::Duration,
};

use axalloc::global_allocator;
use axfs_ng_vfs::{
    DeviceId, DirEntry, DirEntrySink, DirNode, DirNodeOps, FileNode, FileNodeOps, Filesystem,
    FilesystemOps, Metadata, MetadataUpdate, NodeFlags, NodeOps, NodePermission, NodeType,
    Reference, StatFs, VfsError, VfsResult, WeakDirEntry, path::MAX_NAME_LEN,
    InMemDir, InMemInode, update_metadata_impl, cmp_file_name,
};
use axpoll::{IoEvents, Pollable};
use kspin::SpinNoIrq as Mutex;

static PID_MAX: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(32768);

const ROOT_INO: u64 = 1;
const MEMINFO_INO: u64 = 2;
const MOUNTS_INO: u64 = 3;
const FILESYSTEMS_INO: u64 = 4;
const SELF_INO: u64 = 5;
const SYS_INO: u64 = 6;
const KERNEL_INO: u64 = 7;
const PID_MAX_INO: u64 = 8;
const TAINTED_INO: u64 = 9;
const CORE_PATTERN_INO: u64 = 10;
const INIT_SYM_INO: u64 = 11;
const CPUINFO_INO: u64 = 12;
const NEXT_DYNAMIC_INO: u64 = CPUINFO_INO + 1;

pub const PID_INODE_START: u64 = 0x10_0000_0000;
pub const PID_INODE_SHIFT: u32 = 24;

const SUB_INO_DIR: u64 = 0;
const SUB_INO_CMDLINE: u64 = 1;
const SUB_INO_STATUS: u64 = 2;
const SUB_INO_EXE: u64 = 3;
const SUB_INO_COMM: u64 = 4;
const SUB_INO_STAT: u64 = 5;
const SUB_INO_FD_DIR: u64 = 6;
const SUB_INO_MAPS: u64 = 7;
const SUB_INO_PAGEMAP: u64 = 8;
const SUB_INO_SETGROUPS: u64 = 9;
const SUB_INO_UID_MAP: u64 = 10;
const SUB_INO_GID_MAP: u64 = 11;
pub const SUB_INO_NS_DIR: u64 = 12;
pub const SUB_INO_NS_UTS: u64 = 13;
pub const SUB_INO_NS_IPC: u64 = 14;
pub const SUB_INO_NS_NET: u64 = 15;
pub const SUB_INO_NS_MNT: u64 = 16;
pub const SUB_INO_NS_PID: u64 = 17;
pub const SUB_INO_NS_USER: u64 = 18;
pub const SUB_INO_NS_CGROUP: u64 = 19;
pub const SUB_INO_CHILDREN: u64 = 20;
pub const SUB_INO_TASK_DIR: u64 = 21;

const SUB_INO_FD_BASE: u64 = 0x40;

const SUB_INO_TASK_BASE: u64 = 0x80_0000;
const SUB_TASK_DIR: u64 = 0;
const SUB_TASK_STATUS: u64 = 1;
const SUB_TASK_COMM: u64 = 2;
const SUB_TASK_STAT: u64 = 3;

pub trait ProcfsProcessProvider: Send + Sync {
    fn current_pid(&self) -> Option<u64>;
    fn process_exists(&self, pid: u64) -> bool;
    fn process_pids(&self) -> Vec<u64>;
    fn cmdline(&self, pid: u64) -> Option<String>;
    fn comm(&self, pid: u64) -> Option<String>;
    fn status(&self, pid: u64) -> Option<String>;
    fn exe(&self, pid: u64) -> Option<String>;
    fn stat(&self, pid: u64) -> Option<String>;
    fn thread_tids(&self, _pid: u64) -> Option<Vec<u64>> {
        None
    }
    fn thread_stat(&self, _pid: u64, _tid: u64) -> Option<String> {
        None
    }
    fn process_fds(&self, pid: u64) -> Option<Vec<u32>>;
    fn fd_path(&self, pid: u64, fd: u32) -> Option<String>;
    fn maps(&self, pid: u64) -> Option<String>;
    fn pagemap(&self, _pid: u64, _offset: u64, _buf: &mut [u8]) -> Option<usize> {
        None
    }
    fn children(&self, _pid: u64) -> Option<Vec<u64>> {
        None
    }
    fn thread_status(&self, _pid: u64, _tid: u64) -> Option<String> {
        None
    }
    fn thread_comm(&self, _pid: u64, _tid: u64) -> Option<String> {
        None
    }
}

static PROCESS_PROVIDER: spin::Once<Arc<dyn ProcfsProcessProvider>> = spin::Once::new();

pub fn register_process_provider(provider: Arc<dyn ProcfsProcessProvider>) {
    PROCESS_PROVIDER.call_once(|| provider);
}

fn decode_pid_inode(ino: u64) -> Option<(u64, u64)> {
    if ino >= PID_INODE_START {
        let offset = ino - PID_INODE_START;
        let pid = offset >> PID_INODE_SHIFT;
        let sub = offset & ((1 << PID_INODE_SHIFT) - 1);
        Some((pid, sub))
    } else {
        None
    }
}

#[derive(Clone, Copy)]
enum ProcLiveFileKind {
    Meminfo,
    Mounts,
    SelfSymlink,
    InitSymlink,
    PidCmdline(u64),
    PidStatus(u64),
    PidExe(u64),
    PidComm(u64),
    PidStat(u64),
    PidFdSymlink(u64, u32),
    PidMaps(u64),
    PidPagemap(u64),
    PidSetgroups(u64),
    PidUidMap(u64),
    PidGidMap(u64),
    PidNsSymlink(u64, u64 /* sub_ino */),
    PidMax,
    Filesystems,
    Tainted,
    CorePattern,
    Cpuinfo,
    PidChildren(u64),
    ThreadStatus(u64, u64),
    ThreadComm(u64, u64),
    ThreadStat(u64, u64),
}

type DirContent = InMemDir<InodeRef>;

#[derive(Default)]
struct FileContent {
    data: Mutex<Vec<u8>>,
}

enum NodeContent {
    Directory(DirContent),
    Live(ProcLiveFileKind),
    File(FileContent),
}

type Inode = InMemInode<NodeContent>;
type InodeRef = u64;

fn new_directory(ino: u64, parent_ino: u64, permission: NodePermission) -> Arc<Inode> {
    let inode = Arc::new(InMemInode::new(
        ino,
        Metadata {
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
        },
        NodeContent::Directory(DirContent::new()),
    ));

    {
        let mut entries = inode_as_dir(&inode).expect("directory inode").entries.lock();
        entries.insert(".".into(), ino);
        entries.insert("..".into(), parent_ino);
    }
    inode
}

fn new_live_file(ino: u64, kind: ProcLiveFileKind, permission: NodePermission) -> Arc<Inode> {
    let node_type = match kind {
        ProcLiveFileKind::SelfSymlink
        | ProcLiveFileKind::InitSymlink
        | ProcLiveFileKind::PidExe(_)
        | ProcLiveFileKind::PidFdSymlink(_, _) => NodeType::Symlink,
        _ => NodeType::RegularFile,
    };
    Arc::new(InMemInode::new(
        ino,
        Metadata {
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
        },
        NodeContent::Live(kind),
    ))
}

fn new_file(ino: u64, node_type: NodeType, permission: NodePermission) -> Arc<Inode> {
    Arc::new(InMemInode::new(
        ino,
        Metadata {
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
        },
        NodeContent::File(FileContent::default()),
    ))
}

fn inode_as_dir(inode: &Inode) -> VfsResult<&DirContent> {
    match &inode.content {
        NodeContent::Directory(content) => Ok(content),
        _ => Err(VfsError::NotADirectory),
    }
}

fn inode_as_file(inode: &Inode) -> VfsResult<&FileContent> {
    match &inode.content {
        NodeContent::File(content) => Ok(content),
        NodeContent::Live(_) => Err(VfsError::ReadOnlyFilesystem),
        NodeContent::Directory(_) => Err(VfsError::IsADirectory),
    }
}

fn inode_live_kind(inode: &Inode) -> Option<ProcLiveFileKind> {
    match &inode.content {
        NodeContent::Live(kind) => Some(*kind),
        _ => None,
    }
}

pub struct ProcFilesystem {
    root_dir: Mutex<Option<DirEntry>>,
    inodes: Mutex<BTreeMap<u64, Arc<Inode>>>,
    next_ino: Mutex<u64>,
    setgroups_map: Mutex<BTreeMap<u64, String>>,
    uid_map_map: Mutex<BTreeMap<u64, String>>,
    gid_map_map: Mutex<BTreeMap<u64, String>>,
}

impl ProcFilesystem {
    pub fn new() -> Filesystem {
        let fs = Arc::new(Self {
            root_dir: Mutex::new(None),
            inodes: Mutex::new(BTreeMap::new()),
            next_ino: Mutex::new(NEXT_DYNAMIC_INO),
            setgroups_map: Mutex::new(BTreeMap::new()),
            uid_map_map: Mutex::new(BTreeMap::new()),
            gid_map_map: Mutex::new(BTreeMap::new()),
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
        let root = new_directory(
            ROOT_INO,
            ROOT_INO,
            NodePermission::from_bits_truncate(0o755),
        );
        let meminfo = new_live_file(
            MEMINFO_INO,
            ProcLiveFileKind::Meminfo,
            NodePermission::from_bits_truncate(0o444),
        );
        let mounts = new_live_file(
            MOUNTS_INO,
            ProcLiveFileKind::Mounts,
            NodePermission::from_bits_truncate(0o444),
        );
        let filesystems = new_live_file(
            FILESYSTEMS_INO,
            ProcLiveFileKind::Filesystems,
            NodePermission::from_bits_truncate(0o444),
        );
        let self_sym = new_live_file(
            SELF_INO,
            ProcLiveFileKind::SelfSymlink,
            NodePermission::from_bits_truncate(0o777),
        );
        let init_sym = new_live_file(
            INIT_SYM_INO,
            ProcLiveFileKind::InitSymlink,
            NodePermission::from_bits_truncate(0o777),
        );
        let sys_dir = new_directory(
            SYS_INO,
            ROOT_INO,
            NodePermission::from_bits_truncate(0o555),
        );
        let kernel_dir = new_directory(
            KERNEL_INO,
            SYS_INO,
            NodePermission::from_bits_truncate(0o555),
        );
        let pid_max = new_live_file(
            PID_MAX_INO,
            ProcLiveFileKind::PidMax,
            NodePermission::from_bits_truncate(0o644),
        );
        let tainted = new_live_file(
            TAINTED_INO,
            ProcLiveFileKind::Tainted,
            NodePermission::from_bits_truncate(0o444),
        );
        let core_pattern = new_live_file(
            CORE_PATTERN_INO,
            ProcLiveFileKind::CorePattern,
            NodePermission::from_bits_truncate(0o444),
        );
        let cpuinfo = new_live_file(
            CPUINFO_INO,
            ProcLiveFileKind::Cpuinfo,
            NodePermission::from_bits_truncate(0o444),
        );

        root.metadata.lock().nlink = 3;
        sys_dir.metadata.lock().nlink = 3;
        kernel_dir.metadata.lock().nlink = 2;

        {
            let mut inodes = self.inodes.lock();
            inodes.insert(ROOT_INO, root.clone());
            inodes.insert(MEMINFO_INO, meminfo);
            inodes.insert(MOUNTS_INO, mounts);
            inodes.insert(FILESYSTEMS_INO, filesystems);
            inodes.insert(SELF_INO, self_sym);
            inodes.insert(INIT_SYM_INO, init_sym);
            inodes.insert(SYS_INO, sys_dir.clone());
            inodes.insert(KERNEL_INO, kernel_dir.clone());
            inodes.insert(PID_MAX_INO, pid_max);
            inodes.insert(TAINTED_INO, tainted);
            inodes.insert(CORE_PATTERN_INO, core_pattern);
            inodes.insert(CPUINFO_INO, cpuinfo);
        }

        {
            let mut entries = inode_as_dir(&root).expect("proc root is dir").entries.lock();
            entries.insert("meminfo".into(), MEMINFO_INO);
            entries.insert("cpuinfo".into(), CPUINFO_INO);
            entries.insert("mounts".into(), MOUNTS_INO);
            entries.insert("filesystems".into(), FILESYSTEMS_INO);
            entries.insert("self".into(), SELF_INO);
            entries.insert("1".into(), INIT_SYM_INO);
            entries.insert("sys".into(), SYS_INO);
        }

        {
            let mut entries = inode_as_dir(&sys_dir).expect("proc sys is dir").entries.lock();
            entries.insert("kernel".into(), KERNEL_INO);
        }

        {
            let mut entries = inode_as_dir(&kernel_dir).expect("proc sys kernel is dir").entries.lock();
            entries.insert("pid_max".into(), PID_MAX_INO);
            entries.insert("tainted".into(), TAINTED_INO);
            entries.insert("core_pattern".into(), CORE_PATTERN_INO);
        }
    }

    fn allocate_ino(&self) -> u64 {
        let mut next = self.next_ino.lock();
        let ino = *next;
        *next += 1;
        ino
    }

    fn get_inode(&self, ino: u64) -> VfsResult<Arc<Inode>> {
        if let Some(inode) = self.inodes.lock().get(&ino).cloned() {
            return Ok(inode);
        }

        if ino == SELF_INO {
            let inode = new_live_file(
                SELF_INO,
                ProcLiveFileKind::SelfSymlink,
                NodePermission::from_bits_truncate(0o777),
            );
            return Ok(inode);
        }

        if ino == INIT_SYM_INO {
            let inode = new_live_file(
                INIT_SYM_INO,
                ProcLiveFileKind::InitSymlink,
                NodePermission::from_bits_truncate(0o777),
            );
            return Ok(inode);
        }

        if let Some((pid, sub)) = decode_pid_inode(ino) {
            let provider = PROCESS_PROVIDER.get().ok_or(VfsError::NotFound)?;

            if sub == SUB_INO_DIR {
                let dir = new_directory(ino, ROOT_INO, NodePermission::from_bits_truncate(0o555));
                {
                    let mut entries = inode_as_dir(&dir)?.entries.lock();
                    entries.insert(".".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR);
                    entries.insert("..".into(), ROOT_INO);
                    entries.insert("cmdline".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_CMDLINE);
                    entries.insert("status".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_STATUS);
                    entries.insert("exe".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_EXE);
                    entries.insert("comm".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_COMM);
                    entries.insert("stat".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_STAT);
                    entries.insert("fd".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_FD_DIR);
                    entries.insert("maps".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_MAPS);
                    entries.insert("pagemap".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_PAGEMAP);
                    entries.insert("ns".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_DIR);
                    entries.insert("setgroups".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_SETGROUPS);
                    entries.insert("uid_map".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_UID_MAP);
                    entries.insert("gid_map".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_GID_MAP);
                    entries.insert("children".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_CHILDREN);
                    entries.insert("task".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_DIR);
                }
                return Ok(dir);
            }

            if sub == SUB_INO_NS_DIR {
                let dir = new_directory(
                    ino,
                    PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR,
                    NodePermission::from_bits_truncate(0o555),
                );
                {
                    let mut entries = inode_as_dir(&dir)?.entries.lock();
                    entries.insert(".".into(), ino);
                    entries.insert(
                        "..".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR,
                    );
                    entries.insert(
                        "uts".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_UTS,
                    );
                    entries.insert(
                        "ipc".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_IPC,
                    );
                    entries.insert(
                        "net".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_NET,
                    );
                    entries.insert(
                        "mnt".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_MNT,
                    );
                    entries.insert(
                        "pid".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_PID,
                    );
                    entries.insert(
                        "user".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_USER,
                    );
                    entries.insert(
                        "cgroup".into(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_CGROUP,
                    );
                }
                return Ok(dir);
            }

            if sub == SUB_INO_FD_DIR {
                let dir = new_directory(ino, PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR, NodePermission::from_bits_truncate(0o555));
                {
                    let mut entries = inode_as_dir(&dir)?.entries.lock();
                    entries.insert(".".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_FD_DIR);
                    entries.insert("..".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR);

                    if let Some(fds) = provider.process_fds(pid) {
                        for fd in fds {
                            let name = fd.to_string(); // Bolt: Use to_string() instead of format! for single integer conversion to avoid allocation overhead
                            let child_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_FD_BASE + fd as u64;
                            entries.insert(name.into(), child_ino);
                        }
                    }
                }
                return Ok(dir);
            }

            if sub == SUB_INO_TASK_DIR {
                let dir = new_directory(ino, PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR, NodePermission::from_bits_truncate(0o555));
                {
                    let mut entries = inode_as_dir(&dir)?.entries.lock();
                    entries.insert(".".into(), ino);
                    entries.insert("..".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR);

                    if let Some(tids) = provider.thread_tids(pid) {
                        for tid in tids {
                            let name = tid.to_string();
                            let child_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_DIR;
                            entries.insert(name.into(), child_ino);
                        }
                    }
                }
                return Ok(dir);
            }

            if sub >= SUB_INO_FD_BASE && sub < SUB_INO_TASK_BASE {
                let fd = (sub - SUB_INO_FD_BASE) as u32;
                let file = new_live_file(
                    ino,
                    ProcLiveFileKind::PidFdSymlink(pid, fd),
                    NodePermission::from_bits_truncate(0o777),
                );
                return Ok(file);
            }

            if sub >= SUB_INO_TASK_BASE {
                let task_offset = sub - SUB_INO_TASK_BASE;
                let tid = task_offset >> 4;
                let task_sub = task_offset & 0xf;

                if task_sub == SUB_TASK_DIR {
                    let dir = new_directory(ino, PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_DIR, NodePermission::from_bits_truncate(0o555));
                    {
                        let mut entries = inode_as_dir(&dir)?.entries.lock();
                        entries.insert(".".into(), ino);
                        entries.insert("..".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_DIR);
                        entries.insert("status".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_STATUS);
                        entries.insert("comm".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_COMM);
                        entries.insert("stat".into(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_STAT);
                    }
                    return Ok(dir);
                }

                let kind = match task_sub {
                    SUB_TASK_STATUS => ProcLiveFileKind::ThreadStatus(pid, tid),
                    SUB_TASK_COMM => ProcLiveFileKind::ThreadComm(pid, tid),
                    SUB_TASK_STAT => ProcLiveFileKind::ThreadStat(pid, tid),
                    _ => return Err(VfsError::NotFound),
                };
                let file = new_live_file(
                    ino,
                    kind,
                    NodePermission::from_bits_truncate(0o444),
                );
                return Ok(file);
            }

            let kind = match sub {
                SUB_INO_CMDLINE => ProcLiveFileKind::PidCmdline(pid),
                SUB_INO_STATUS => ProcLiveFileKind::PidStatus(pid),
                SUB_INO_EXE => ProcLiveFileKind::PidExe(pid),
                SUB_INO_COMM => ProcLiveFileKind::PidComm(pid),
                SUB_INO_STAT => ProcLiveFileKind::PidStat(pid),
                SUB_INO_MAPS => ProcLiveFileKind::PidMaps(pid),
                SUB_INO_PAGEMAP => ProcLiveFileKind::PidPagemap(pid),
                SUB_INO_SETGROUPS => ProcLiveFileKind::PidSetgroups(pid),
                SUB_INO_UID_MAP => ProcLiveFileKind::PidUidMap(pid),
                SUB_INO_GID_MAP => ProcLiveFileKind::PidGidMap(pid),
                SUB_INO_CHILDREN => ProcLiveFileKind::PidChildren(pid),
                SUB_INO_NS_UTS | SUB_INO_NS_IPC | SUB_INO_NS_NET | SUB_INO_NS_MNT | SUB_INO_NS_PID | SUB_INO_NS_USER | SUB_INO_NS_CGROUP => {
                    ProcLiveFileKind::PidNsSymlink(pid, sub)
                }
                _ => return Err(VfsError::NotFound),
            };

            let perm = if sub == SUB_INO_EXE {
                0o777
            } else if sub == SUB_INO_SETGROUPS || sub == SUB_INO_UID_MAP || sub == SUB_INO_GID_MAP {
                0o644
            } else {
                0o444
            };
            let file = new_live_file(
                ino,
                kind,
                NodePermission::from_bits_truncate(perm),
            );
            return Ok(file);
        }

        Err(VfsError::NotFound)
    }

    fn create_inode(
        &self,
        parent_ino: u64,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<Arc<Inode>> {
        let ino = self.allocate_ino();
        let inode = match node_type {
            NodeType::Directory => new_directory(ino, parent_ino, permission),
            NodeType::CharacterDevice | NodeType::BlockDevice => {
                return Err(VfsError::OperationNotPermitted);
            }
            _ => new_file(ino, node_type, permission),
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

fn render_filesystems() -> String {
    let mut out = String::new();
    out.push_str("nodev\tproc\n");
    out.push_str("nodev\tdevtmpfs\n");
    out.push_str("nodev\ttmpfs\n");
    #[cfg(feature = "ext4")]
    out.push_str("\text2\n\text3\n\text4\n");
    out
}

fn render_proc_file(fs: &ProcFilesystem, kind: ProcLiveFileKind) -> String {
    match kind {
        ProcLiveFileKind::Meminfo => render_meminfo(),
        ProcLiveFileKind::Mounts => render_mounts(),
        ProcLiveFileKind::SelfSymlink => {
            if let Some(provider) = PROCESS_PROVIDER.get() {
                if let Some(pid) = provider.current_pid() {
                    return pid.to_string(); // Bolt: Use to_string() instead of format! for single integer conversion
                }
            }
            "1".to_owned()
        }
        ProcLiveFileKind::InitSymlink => {
            if let Some(provider) = PROCESS_PROVIDER.get() {
                let pids = provider.process_pids();
                if let Some(&min_pid) = pids.iter().min() {
                    return min_pid.to_string(); // Bolt: Use to_string() instead of format! for single integer conversion
                }
            }
            "1".to_owned()
        }
        ProcLiveFileKind::PidCmdline(pid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.cmdline(pid)).unwrap_or_default()
        }
        ProcLiveFileKind::PidStatus(pid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.status(pid)).unwrap_or_default()
        }
        ProcLiveFileKind::PidExe(pid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.exe(pid)).unwrap_or_default()
        }
        ProcLiveFileKind::PidComm(pid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.comm(pid)).unwrap_or_default()
        }
        ProcLiveFileKind::PidStat(pid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.stat(pid)).unwrap_or_default()
        }
        ProcLiveFileKind::PidFdSymlink(pid, fd) => {
            PROCESS_PROVIDER.get().and_then(|p| p.fd_path(pid, fd)).unwrap_or_default()
        }
        ProcLiveFileKind::PidMaps(pid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.maps(pid)).unwrap_or_default()
        }
        ProcLiveFileKind::PidPagemap(_pid) => {
            String::new()
        }
        ProcLiveFileKind::PidSetgroups(pid) => {
            fs.setgroups_map.lock().get(&pid).cloned().unwrap_or_else(|| "allow\n".to_owned())
        }
        ProcLiveFileKind::PidUidMap(pid) => {
            fs.uid_map_map.lock().get(&pid).cloned().unwrap_or_default()
        }
        ProcLiveFileKind::PidGidMap(pid) => {
            fs.gid_map_map.lock().get(&pid).cloned().unwrap_or_default()
        }
        ProcLiveFileKind::PidNsSymlink(_pid, sub) => {
            let ns_name = match sub {
                SUB_INO_NS_UTS => "uts",
                SUB_INO_NS_IPC => "ipc",
                SUB_INO_NS_NET => "net",
                SUB_INO_NS_MNT => "mnt",
                SUB_INO_NS_PID => "pid",
                SUB_INO_NS_USER => "user",
                SUB_INO_NS_CGROUP => "cgroup",
                _ => "unknown",
            };
            // Format: <ns_name>:[<inode>]
            // Use the inode of the ns file itself as the namespace identifier.
            let ino = PID_INODE_START + (_pid << PID_INODE_SHIFT) + sub;
            format!("{}:[{}]", ns_name, ino)
        }
        ProcLiveFileKind::PidMax => {
            format!("{}\n", PID_MAX.load(core::sync::atomic::Ordering::Acquire))
        }
        ProcLiveFileKind::Filesystems => render_filesystems(),
        ProcLiveFileKind::Tainted => {
            "0\n".to_owned()
        }
        ProcLiveFileKind::CorePattern => {
            "core\n".to_owned()
        }
        ProcLiveFileKind::Cpuinfo => {
            "processor\t: 0\nmodel name\t: QEMU Virtual CPU version 2.5+\n".to_owned()
        }
        ProcLiveFileKind::PidChildren(pid) => {
            if let Some(provider) = PROCESS_PROVIDER.get() {
                if let Some(children) = provider.children(pid) {
                    let mut out = String::new();
                    for (i, child_pid) in children.iter().enumerate() {
                        if i > 0 {
                            out.push(' ');
                        }
                        out.push_str(&child_pid.to_string());
                    }
                    out.push('\n');
                    return out;
                }
            }
            String::new()
        }
        ProcLiveFileKind::ThreadStatus(pid, tid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.thread_status(pid, tid)).unwrap_or_default()
        }
        ProcLiveFileKind::ThreadComm(pid, tid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.thread_comm(pid, tid)).unwrap_or_default()
        }
        ProcLiveFileKind::ThreadStat(pid, tid) => {
            PROCESS_PROVIDER.get().and_then(|p| p.thread_stat(pid, tid)).unwrap_or_default()
        }
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
            self.this.clone(),
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
        let dir_content = inode_as_dir(&dir)?;
        let entries = dir_content.entries.lock();
        let Some(entry) = entries.get(name).cloned() else {
            return Err(VfsError::NotFound);
        };
        drop(entries);

        let target = self.fs.get_inode(entry)?;
        if target.metadata.lock().node_type == NodeType::Directory {
            let child_entries = inode_as_dir(&target)?.entries.lock();
            if child_entries.len() > 2 {
                return Err(VfsError::DirectoryNotEmpty);
            }
        }

        Ok(entry)
    }

    fn remove_entry(&self, name: &str) -> VfsResult<()> {
        let entry = self.can_remove_entry(name)?;

        let dir = self.inode_ref()?;
        let dir_content = inode_as_dir(&dir)?;
        dir_content.entries.lock().remove(name);

        let target = self.fs.get_inode(entry)?;
        if target.metadata.lock().node_type == NodeType::Directory {
            self.fs.bump_nlink(dir.ino, -1)?;
        }
        self.fs.bump_nlink(entry, -1)
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
                if let ProcLiveFileKind::PidPagemap(_) = kind {
                    metadata.size = 0x8000_0000_0000;
                    metadata.blocks = metadata.size.div_ceil(512);
                } else {
                    metadata.size = render_proc_file(&self.fs, *kind).len() as u64;
                    metadata.blocks = metadata.size.div_ceil(512);
                }
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
        if (update.mode.is_some() || update.owner.is_some())
            && (inode_live_kind(&inode).is_some() || self.ino >= PID_INODE_START)
        {
            return Err(VfsError::ReadOnlyFilesystem);
        }
        update_metadata_impl(&mut inode.metadata.lock(), update);
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
        if self.ino >= PID_INODE_START {
            NodeFlags::NON_CACHEABLE
        } else if self
            .inode_ref()
            .ok()
            .and_then(|inode| inode_live_kind(&inode))
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
        let mut all_entries = Vec::new();

        if self.ino >= PID_INODE_START {
            if let Some((pid, sub)) = decode_pid_inode(self.ino) {
                let provider = PROCESS_PROVIDER.get().ok_or(VfsError::NotFound)?;
                if !provider.process_exists(pid) {
                    return Err(VfsError::NotFound);
                }

                if sub == SUB_INO_DIR {
                    all_entries.push((".".to_owned(), self.ino));
                    all_entries.push(("..".to_owned(), ROOT_INO));
                    all_entries.push(("cmdline".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_CMDLINE));
                    all_entries.push(("status".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_STATUS));
                    all_entries.push(("exe".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_EXE));
                    all_entries.push(("comm".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_COMM));
                    all_entries.push(("stat".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_STAT));
                    all_entries.push(("fd".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_FD_DIR));
                    all_entries.push(("ns".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_DIR));
                    all_entries.push(("maps".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_MAPS));
                    all_entries.push(("pagemap".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_PAGEMAP));
                    all_entries.push(("setgroups".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_SETGROUPS));
                    all_entries.push(("uid_map".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_UID_MAP));
                    all_entries.push(("gid_map".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_GID_MAP));
                    all_entries.push(("children".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_CHILDREN));
                    all_entries.push(("task".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_DIR));
                } else if sub == SUB_INO_TASK_DIR {
                    all_entries.push((".".to_owned(), self.ino));
                    all_entries.push(("..".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR));
                    if let Some(tids) = provider.thread_tids(pid) {
                        for tid in tids {
                            let name = tid.to_string();
                            let child_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_DIR;
                            all_entries.push((name, child_ino));
                        }
                    }
                } else if sub >= SUB_INO_TASK_BASE {
                    let task_offset = sub - SUB_INO_TASK_BASE;
                    let tid = task_offset >> 4;
                    let task_sub = task_offset & 0xf;
                    if task_sub == SUB_TASK_DIR {
                        all_entries.push((".".to_owned(), self.ino));
                        all_entries.push(("..".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_DIR));
                        all_entries.push(("status".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_STATUS));
                        all_entries.push(("comm".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_COMM));
                        all_entries.push(("stat".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_STAT));
                    }
                } else if sub == SUB_INO_NS_DIR {
                    all_entries.push((".".to_owned(), self.ino));
                    all_entries.push((
                        "..".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR,
                    ));
                    all_entries.push((
                        "uts".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_UTS,
                    ));
                    all_entries.push((
                        "ipc".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_IPC,
                    ));
                    all_entries.push((
                        "net".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_NET,
                    ));
                    all_entries.push((
                        "mnt".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_MNT,
                    ));
                    all_entries.push((
                        "pid".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_PID,
                    ));
                    all_entries.push((
                        "user".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_USER,
                    ));
                    all_entries.push((
                        "cgroup".to_owned(),
                        PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_NS_CGROUP,
                    ));
                } else if sub == SUB_INO_FD_DIR {
                    all_entries.push((".".to_owned(), self.ino));
                    all_entries.push(("..".to_owned(), PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR));

                    if let Some(fds) = provider.process_fds(pid) {
                        for fd in fds {
                            let name = fd.to_string(); // Bolt: Use to_string() instead of format! for single integer conversion to avoid allocation overhead
                            let child_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_FD_BASE + fd as u64;
                            all_entries.push((name, child_ino));
                        }
                    }
                }
            }
        } else {
            let entries = inode_as_dir(&inode)?.entries.lock();
            for (name, &entry) in entries.iter() {
                all_entries.push((name.0.clone(), entry));
            }

            if self.ino == ROOT_INO {
                if let Some(provider) = PROCESS_PROVIDER.get() {
                    for pid in provider.process_pids() {
                        let name = pid.to_string(); // Bolt: Use to_string() instead of format! for single integer conversion to avoid allocation overhead
                        let child_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR;
                        all_entries.push((name, child_ino));
                    }
                }
            }
        }

        all_entries.sort_by(|a, b| cmp_file_name(&a.0, &b.0));

        let mut count = 0;
        for (idx, (name, ino)) in all_entries.iter().enumerate().skip(offset as usize) {
            let node_type = self.fs.node_type_of(*ino)?;
            if !sink.accept(name, *ino, node_type, (idx + 1) as u64) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let inode = self.inode_ref()?;

        if self.ino >= PID_INODE_START {
            if let Some((pid, sub)) = decode_pid_inode(self.ino) {
                let provider = PROCESS_PROVIDER.get().ok_or(VfsError::NotFound)?;
                if !provider.process_exists(pid) {
                    return Err(VfsError::NotFound);
                }

                if sub == SUB_INO_DIR {
                    let target_sub = match name {
                        "." => Some(SUB_INO_DIR),
                        ".." => return self.build_entry(name, ROOT_INO),
                        "cmdline" => Some(SUB_INO_CMDLINE),
                        "status" => Some(SUB_INO_STATUS),
                        "exe" => Some(SUB_INO_EXE),
                        "comm" => Some(SUB_INO_COMM),
                        "stat" => Some(SUB_INO_STAT),
                        "fd" => Some(SUB_INO_FD_DIR),
                        "ns" => Some(SUB_INO_NS_DIR),
                        "maps" => Some(SUB_INO_MAPS),
                        "pagemap" => Some(SUB_INO_PAGEMAP),
                        "setgroups" => Some(SUB_INO_SETGROUPS),
                        "uid_map" => Some(SUB_INO_UID_MAP),
                        "gid_map" => Some(SUB_INO_GID_MAP),
                        "children" => Some(SUB_INO_CHILDREN),
                        "task" => Some(SUB_INO_TASK_DIR),
                        _ => None,
                    };
                    if let Some(ts) = target_sub {
                        let ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + ts;
                        return self.build_entry(name, ino);
                    }
                } else if sub == SUB_INO_TASK_DIR {
                    if name == "." {
                        return self.build_entry(name, self.ino);
                    } else if name == ".." {
                        let parent_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR;
                        return self.build_entry(name, parent_ino);
                    }
                    if let Ok(tid) = name.parse::<u64>() {
                        if let Some(tids) = provider.thread_tids(pid) {
                            if tids.contains(&tid) {
                                let ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + SUB_TASK_DIR;
                                return self.build_entry(name, ino);
                            }
                        }
                    }
                } else if sub >= SUB_INO_TASK_BASE {
                    let task_offset = sub - SUB_INO_TASK_BASE;
                    let tid = task_offset >> 4;
                    let task_sub = task_offset & 0xf;
                    if task_sub == SUB_TASK_DIR {
                        let target_sub = match name {
                            "." => Some(SUB_TASK_DIR),
                            ".." => return self.build_entry(name, PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_DIR),
                            "status" => Some(SUB_TASK_STATUS),
                            "comm" => Some(SUB_TASK_COMM),
                            "stat" => Some(SUB_TASK_STAT),
                            _ => None,
                        };
                        if let Some(ts) = target_sub {
                            let ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_TASK_BASE + (tid << 4) + ts;
                            return self.build_entry(name, ino);
                        }
                    }
                } else if sub == SUB_INO_NS_DIR {
                    let target_sub = match name {
                        "." => Some(SUB_INO_NS_DIR),
                        ".." => Some(SUB_INO_DIR),
                        "uts" => Some(SUB_INO_NS_UTS),
                        "ipc" => Some(SUB_INO_NS_IPC),
                        "net" => Some(SUB_INO_NS_NET),
                        "mnt" => Some(SUB_INO_NS_MNT),
                        "pid" => Some(SUB_INO_NS_PID),
                        "user" => Some(SUB_INO_NS_USER),
                        "cgroup" => Some(SUB_INO_NS_CGROUP),
                        _ => None,
                    };
                    if let Some(ts) = target_sub {
                        let ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + ts;
                        return self.build_entry(name, ino);
                    }
                } else if sub == SUB_INO_FD_DIR {
                    if name == "." {
                        return self.build_entry(name, self.ino);
                    } else if name == ".." {
                        let parent_ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR;
                        return self.build_entry(name, parent_ino);
                    }
                    if let Ok(fd) = name.parse::<u32>() {
                        if let Some(fds) = provider.process_fds(pid) {
                            if fds.contains(&fd) {
                                let ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_FD_BASE + fd as u64;
                                return self.build_entry(name, ino);
                            }
                        }
                    }
                }
            }
        } else {
            let entries = inode_as_dir(&inode)?.entries.lock();
            if let Some(entry) = entries.get(name) {
                return self.build_entry(name, *entry);
            }

            if self.ino == ROOT_INO {
                if let Ok(pid) = name.parse::<u64>() {
                    if let Some(provider) = PROCESS_PROVIDER.get() {
                        if provider.process_exists(pid) {
                            let ino = PID_INODE_START + (pid << PID_INODE_SHIFT) + SUB_INO_DIR;
                            return self.build_entry(name, ino);
                        }
                    }
                }
            }
        }

        Err(VfsError::NotFound)
    }

    fn is_cacheable(&self) -> bool {
        false
    }

    fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        if self.ino >= PID_INODE_START {
            return Err(VfsError::ReadOnlyFilesystem);
        }
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let parent = self.inode_ref()?;
        let parent_dir = inode_as_dir(&parent)?;
        let mut entries = parent_dir.entries.lock();
        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }

        let inode = self.fs.create_inode(self.ino, node_type, permission)?;
        if node_type == NodeType::Directory {
            self.fs.bump_nlink(self.ino, 1)?;
        }

        entries.insert(name.into(), inode.ino);
        drop(entries);
        self.fs.bump_nlink(inode.ino, 1)?;

        self.build_entry(name, inode.ino)
    }

    fn link(&self, name: &str, target: &DirEntry) -> VfsResult<DirEntry> {
        if self.ino >= PID_INODE_START {
            return Err(VfsError::ReadOnlyFilesystem);
        }
        if name == "." || name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let target = target.downcast::<Self>()?;
        let target_inode = target.inode_ref()?;
        if target_inode.metadata.lock().node_type == NodeType::Directory {
            return Err(VfsError::IsADirectory);
        }

        let parent = self.inode_ref()?;
        let parent_dir = inode_as_dir(&parent)?;
        let mut entries = parent_dir.entries.lock();
        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }

        entries.insert(name.into(), target.ino);
        drop(entries);
        self.fs.bump_nlink(target.ino, 1)?;
        self.build_entry(name, target.ino)
    }

    fn unlink(&self, name: &str) -> VfsResult<()> {
        if self.ino >= PID_INODE_START {
            return Err(VfsError::ReadOnlyFilesystem);
        }
        self.remove_entry(name)
    }

    fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        if self.ino >= PID_INODE_START {
            return Err(VfsError::ReadOnlyFilesystem);
        }
        if src_name == "." || src_name == ".." || dst_name == "." || dst_name == ".." {
            return Err(VfsError::InvalidInput);
        }

        let dst_node = dst_dir.downcast::<Self>()?;
        if dst_node.ino >= PID_INODE_START {
            return Err(VfsError::ReadOnlyFilesystem);
        }
        if self.ino == dst_node.ino && src_name == dst_name {
            return Ok(());
        }

        let src_inode = self.inode_ref()?;
        let src_dir = inode_as_dir(&src_inode)?;

        let moved_ref = {
            let src_entries = src_dir.entries.lock();
            src_entries
                .get(src_name)
                .cloned()
                .ok_or(VfsError::NotFound)?
        };

        if let Ok(existing) = dst_node.lookup(dst_name) {
            let existing = existing.downcast::<Self>()?;
            if existing.ino == moved_ref {
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

        let moved_inode = self.fs.get_inode(moved_ref)?;
        let moved_type = moved_inode.metadata.lock().node_type;

        if moved_type == NodeType::Directory && self.ino != dst_node.ino {
            self.fs.bump_nlink(self.ino, -1)?;
            self.fs.bump_nlink(dst_node.ino, 1)?;
            inode_as_dir(&moved_inode)?
                .entries
                .lock()
                .insert("..".into(), dst_node.ino);
        }

        let dst_inode = dst_node.inode_ref()?;
        let dst_content = inode_as_dir(&dst_inode)?;
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

        if let Some(kind) = inode_live_kind(&inode) {
            if let ProcLiveFileKind::PidPagemap(pid) = kind {
                if let Some(provider) = PROCESS_PROVIDER.get() {
                    if let Some(bytes_read) = provider.pagemap(pid, offset, buf) {
                        return Ok(bytes_read);
                    }
                }
                return Err(VfsError::NotFound);
            }

            let content = render_proc_file(&self.fs, kind);
            let bytes = content.as_bytes();
            let start = offset as usize;
            if start >= bytes.len() {
                return Ok(0);
            }
            let read_len = min(buf.len(), bytes.len() - start);
            buf[..read_len].copy_from_slice(&bytes[start..start + read_len]);
            return Ok(read_len);
        }

        let file = inode_as_file(&inode)?;
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
        if let Some(kind) = inode_live_kind(&inode) {
            match kind {
                ProcLiveFileKind::PidMax => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        if let Ok(val) = s.trim().parse::<u32>() {
                            PID_MAX.store(val, core::sync::atomic::Ordering::Release);
                            return Ok(buf.len());
                        }
                    }
                    return Err(VfsError::InvalidInput);
                }
                ProcLiveFileKind::PidSetgroups(pid) => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        self.fs.setgroups_map.lock().insert(pid, s.to_owned());
                        return Ok(buf.len());
                    }
                    return Err(VfsError::InvalidInput);
                }
                ProcLiveFileKind::PidUidMap(pid) => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        self.fs.uid_map_map.lock().insert(pid, s.to_owned());
                        return Ok(buf.len());
                    }
                    return Err(VfsError::InvalidInput);
                }
                ProcLiveFileKind::PidGidMap(pid) => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        self.fs.gid_map_map.lock().insert(pid, s.to_owned());
                        return Ok(buf.len());
                    }
                    return Err(VfsError::InvalidInput);
                }
                _ => return Err(VfsError::ReadOnlyFilesystem),
            }
        }

        let file = inode_as_file(&inode)?;
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
        if let Some(kind) = inode_live_kind(&inode) {
            match kind {
                ProcLiveFileKind::PidSetgroups(pid) => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        self.fs.setgroups_map.lock().insert(pid, s.to_owned());
                        return Ok((buf.len(), 0));
                    }
                    return Err(VfsError::InvalidInput);
                }
                ProcLiveFileKind::PidUidMap(pid) => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        self.fs.uid_map_map.lock().insert(pid, s.to_owned());
                        return Ok((buf.len(), 0));
                    }
                    return Err(VfsError::InvalidInput);
                }
                ProcLiveFileKind::PidGidMap(pid) => {
                    if let Ok(s) = core::str::from_utf8(buf) {
                        self.fs.gid_map_map.lock().insert(pid, s.to_owned());
                        return Ok((buf.len(), 0));
                    }
                    return Err(VfsError::InvalidInput);
                }
                _ => return Err(VfsError::ReadOnlyFilesystem),
            }
        }

        let file = inode_as_file(&inode)?;
        let mut data = file.data.lock();
        let offset = data.len() as u64;
        data.extend_from_slice(buf);
        Ok((buf.len(), offset))
    }

    fn set_len(&self, len: u64) -> VfsResult<()> {
        let inode = self.inode_ref()?;
        if let Some(kind) = inode_live_kind(&inode) {
            match kind {
                ProcLiveFileKind::PidMax
                | ProcLiveFileKind::PidSetgroups(_)
                | ProcLiveFileKind::PidUidMap(_)
                | ProcLiveFileKind::PidGidMap(_) => return Ok(()),
                _ => return Err(VfsError::ReadOnlyFilesystem),
            }
        }

        let file = inode_as_file(&inode)?;
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
            .and_then(|inode| inode_live_kind(&inode))
            .is_some()
        {
            IoEvents::IN
        } else {
            IoEvents::IN | IoEvents::OUT
        }
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}
