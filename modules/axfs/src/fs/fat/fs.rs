use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::mem;

use async_lock::{Mutex, MutexGuard};
use async_trait::async_trait;
use axdriver::prelude::AsyncBlockDriverOps;
use axfs_ng_vfs::{
    DirEntry, Filesystem, FilesystemOps, NodeType, Reference, StatFs, VfsError, VfsResult,
    WeakDirEntry, path::MAX_NAME_LEN,
};
use hadris_fat::async_::FatFs;
use hadris_fs::{MountOptions, NodeId};
use kspin::SpinNoPreempt;

use super::{
    disk::FatDisk,
    node::{FatNode, NodePin},
};

pub(super) struct Volume<D> {
    pub driver: FatFs<FatDisk<D>>,
    // FAT long names and 8.3 aliases identify the same node. Share the live
    // dentry (including its page-cache data) by volume-local node identity.
    pub entries: BTreeMap<NodeId, WeakDirEntry>,
}

pub(crate) struct FatFilesystem<D> {
    // Keep names bound to the same nodes while unlink/replace drops the
    // volume lock to acquire the victim's page-cache I/O lock.
    pub(super) namespace: Mutex<()>,
    volume: Mutex<Volume<D>>,
    open_files: SpinNoPreempt<BTreeMap<NodeId, Weak<()>>>,
    root_id: NodeId,
    block_size: u32,
    this: Weak<Self>,
    root: SpinNoPreempt<Option<WeakDirEntry>>,
    // Drop cannot await the volume mutex. Drain these pins at the start of
    // the next operation; dropping the volume also drops its node table.
    forgotten: SpinNoPreempt<Vec<NodeId>>,
}

pub(super) fn vfs_error<E>(e: hadris_fs::Error<E>) -> VfsError {
    axerrno::LinuxError::try_from(e.kind().errno().linux())
        .map(VfsError::from)
        .unwrap_or(VfsError::Io)
        .canonicalize()
}

impl<D: AsyncBlockDriverOps + Clone + 'static> FatFilesystem<D> {
    pub(crate) async fn new(dev: D) -> VfsResult<Filesystem> {
        let options = MountOptions::new().with_clock(&super::node::WallClock);
        let driver = FatFs::mount(FatDisk::new(dev)?, options)
            .await
            .map_err(|e| vfs_error(e.into_error()))?;
        let root_id = driver.root();
        let block_size = driver.info().cluster_size();
        let fs = Arc::new_cyclic(|this| Self {
            namespace: Mutex::new(()),
            open_files: SpinNoPreempt::default(),
            volume: Mutex::new(Volume {
                driver,
                entries: BTreeMap::new(),
            }),
            root_id,
            block_size,
            this: this.clone(),
            root: SpinNoPreempt::new(None),
            forgotten: SpinNoPreempt::new(Vec::new()),
        });
        Ok(Filesystem::new(fs))
    }

    pub(super) async fn lock(&self) -> MutexGuard<'_, Volume<D>> {
        let mut volume = self.volume.lock().await;
        let forgotten = mem::take(&mut *self.forgotten.lock());
        for id in forgotten {
            volume.driver.forget(id, 1);
            if volume
                .entries
                .get(&id)
                .is_some_and(|entry| entry.upgrade().is_none())
            {
                volume.entries.remove(&id);
            }
        }
        volume
    }

    pub(super) async fn open_file(&self, id: NodeId) -> VfsResult<Arc<()>> {
        let _namespace = self.namespace.lock().await;
        // A lookup may have completed before an unlink acquired the namespace.
        // Only publish a lease for a node that is still live.
        self.lock().await.driver.stat(id).await.map_err(vfs_error)?;
        let mut open = self.open_files.lock();
        if let Some(lease) = open.get(&id).and_then(Weak::upgrade) {
            return Ok(lease);
        }
        let lease = Arc::new(());
        open.insert(id, Arc::downgrade(&lease));
        Ok(lease)
    }

    /// Call with the namespace locked, before detaching a victim's dirty pages.
    pub(super) fn has_open_handles(&self, id: NodeId) -> bool {
        self.open_files
            .lock()
            .get(&id)
            .is_some_and(|lease| lease.strong_count() != 0)
    }

    pub(super) fn block_size(&self) -> u64 {
        self.block_size.into()
    }
}

impl<D> FatFilesystem<D> {
    pub(super) fn forget(&self, id: NodeId) {
        if id != self.root_id {
            let mut open = self.open_files.lock();
            if open.get(&id).is_some_and(|lease| lease.strong_count() == 0) {
                open.remove(&id);
            }
            drop(open);
            self.forgotten.lock().push(id);
        }
    }
}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> FilesystemOps for FatFilesystem<D> {
    fn name(&self) -> &str {
        "vfat"
    }

    fn root_dir(&self) -> DirEntry {
        let mut root = self.root.lock();
        if let Some(entry) = root.as_ref().and_then(WeakDirEntry::upgrade) {
            return entry;
        }
        let fs = self.this.upgrade().expect("live FAT filesystem");
        let pin = NodePin::new(fs, self.root_id);
        let entry = FatNode::entry(pin, NodeType::Directory, Reference::root());
        *root = Some(entry.downgrade());
        entry
    }

    fn stat(&self) -> VfsResult<StatFs> {
        // The VFS statfs entry point is synchronous. The underlying block
        // requests can sleep while counting FAT clusters.
        let stats = axtask::future::block_on(async {
            self.lock().await.driver.statfs().await.map_err(vfs_error)
        })?;
        Ok(StatFs {
            fs_type: 0x4d44, // MSDOS_SUPER_MAGIC
            block_size: stats.block_size(),
            blocks: stats.total_blocks(),
            blocks_free: stats.free_blocks(),
            blocks_available: stats.free_blocks(),
            file_count: 0,
            free_file_count: 0,
            name_length: MAX_NAME_LEN as u32,
            fragment_size: stats.block_size(),
            mount_flags: 0,
        })
    }

    async fn flush(&self) -> VfsResult<()> {
        self.lock().await.driver.sync().await.map_err(vfs_error)
    }
}
