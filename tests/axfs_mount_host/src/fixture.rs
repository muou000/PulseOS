use std::{
    any::Any,
    collections::BTreeMap,
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
};

use async_trait::async_trait;
use vfs::{
    DirEntry, DirEntrySink, DirNode, DirNodeOps, Filesystem, FilesystemOps, Location, Metadata,
    MetadataUpdate, NodeOps, NodePermission, NodeType, Reference, StatFs, VfsError, VfsResult,
    WeakDirEntry,
};
use kspin::SpinNoPreempt;

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

pub fn block_on<F: Future>(future: F) -> F::Output {
    let waker = Waker::from(Arc::new(NoopWake));
    let mut cx = Context::from_waker(&waker);
    let mut future = core::pin::pin!(future);
    loop {
        if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
            return output;
        }
        core::hint::spin_loop();
    }
}

pub struct MemFs {
    name: &'static str,
    next_ino: AtomicU64,
    root: SpinNoPreempt<Option<WeakDirEntry>>,
}

struct MemDir {
    ino: u64,
    fs: Arc<MemFs>,
    this: WeakDirEntry,
    entries: SpinNoPreempt<BTreeMap<String, DirEntry>>,
}

impl MemFs {
    pub fn create(name: &'static str) -> Filesystem {
        let fs = Arc::new(Self {
            name,
            next_ino: AtomicU64::new(2),
            root: SpinNoPreempt::new(None),
        });
        let fs_for_root = fs.clone();
        let root = DirEntry::new_dir(
            move |this| {
                DirNode::new(Arc::new(MemDir {
                    ino: 1,
                    fs: fs_for_root,
                    this,
                    entries: SpinNoPreempt::new(BTreeMap::new()),
                }))
            },
            Reference::root(),
        );
        *fs.root.lock() = Some(root.downgrade());
        let filesystem = Filesystem::new(fs);
        drop(root);
        filesystem
    }
}

#[async_trait]
impl FilesystemOps for MemFs {
    fn name(&self) -> &str {
        self.name
    }

    fn root_dir(&self) -> DirEntry {
        self.root.lock().as_ref().unwrap().upgrade().unwrap()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        Err(VfsError::Unsupported)
    }
}

#[async_trait]
impl NodeOps for MemDir {
    fn inode(&self) -> u64 {
        self.ino
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        Err(VfsError::Unsupported)
    }

    async fn update_metadata(&self, _update: MetadataUpdate) -> VfsResult<()> {
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
}

#[async_trait]
impl DirNodeOps for MemDir {
    async fn read_dir(
        &self,
        _offset: u64,
        _sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        Err(VfsError::Unsupported)
    }

    async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        self.entries
            .lock()
            .get(name)
            .cloned()
            .ok_or(VfsError::NotFound)
    }

    async fn create(
        &self,
        name: &str,
        node_type: NodeType,
        _permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        if node_type != NodeType::Directory {
            return Err(VfsError::Unsupported);
        }
        let mut entries = self.entries.lock();
        if entries.contains_key(name) {
            return Err(VfsError::AlreadyExists);
        }
        let ino = self.fs.next_ino.fetch_add(1, Ordering::Relaxed);
        let fs = self.fs.clone();
        let entry = DirEntry::new_dir(
            move |this| {
                DirNode::new(Arc::new(MemDir {
                    ino,
                    fs,
                    this,
                    entries: SpinNoPreempt::new(BTreeMap::new()),
                }))
            },
            Reference::new(Some(self.this.clone()), name.to_owned()),
        );
        entries.insert(name.to_owned(), entry.clone());
        Ok(entry)
    }

    async fn link(&self, _name: &str, _node: &DirEntry) -> VfsResult<DirEntry> {
        Err(VfsError::Unsupported)
    }

    async fn unlink(&self, name: &str) -> VfsResult<()> {
        self.entries
            .lock()
            .remove(name)
            .map(|_| ())
            .ok_or(VfsError::NotFound)
    }

    async fn rename(&self, _src_name: &str, _dst_dir: &DirNode, _dst_name: &str) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }
}

pub fn mkdir(parent: &Location, name: &str) -> Location {
    block_on(parent.create(name, NodeType::Directory, NodePermission::default())).unwrap()
}
