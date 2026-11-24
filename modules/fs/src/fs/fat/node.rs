use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, time::Duration};

use async_trait::async_trait;
use driver::prelude::AsyncBlockDriverOps;
use vfs::{
    DeviceId, DirEntry, DirNode, FileNode, FilesystemOps, Metadata, MetadataUpdate, NodeFlags,
    NodeOps, NodePermission, NodeType, Reference, VfsError, VfsResult, WeakDirEntry,
};
use hadris_fs::{Clock, DateTime, NoClock, NodeId, SetAttr};

use super::fs::{FatFilesystem, vfs_error};

pub(super) struct WallClock;

impl Clock for WallClock {
    fn now(&self) -> DateTime {
        to_fat_time(hal::time::wall_time()).unwrap_or(NoClock::TIME)
    }
}

fn to_fat_time(duration: Duration) -> VfsResult<DateTime> {
    let seconds = i64::try_from(duration.as_secs()).map_err(|_| VfsError::InvalidInput)?;
    DateTime::new(seconds, duration.subsec_nanos()).map_err(|_| VfsError::InvalidInput)
}

fn from_fat_time(time: Option<DateTime>) -> Duration {
    time.and_then(|t| {
        u64::try_from(t.unix_seconds())
            .ok()
            .map(|sec| Duration::new(sec, t.nanoseconds()))
    })
    .unwrap_or_default()
}

/// Owns one successful lookup/create pin, even if a later await is cancelled.
pub(super) struct NodePin<D> {
    pub fs: Arc<FatFilesystem<D>>,
    pub id: NodeId,
}

impl<D> NodePin<D> {
    pub fn new(fs: Arc<FatFilesystem<D>>, id: NodeId) -> Self {
        Self { fs, id }
    }
}

impl<D> Drop for NodePin<D> {
    fn drop(&mut self) {
        self.fs.forget(self.id);
    }
}

pub(super) struct FatNode<D> {
    pub pin: NodePin<D>,
    pub this: Option<WeakDirEntry>,
}

impl<D: AsyncBlockDriverOps + Clone + 'static> FatNode<D> {
    pub fn entry(pin: NodePin<D>, kind: NodeType, reference: Reference) -> DirEntry {
        if kind == NodeType::Directory {
            DirEntry::new_dir(
                |this| {
                    DirNode::new(Arc::new(Self {
                        pin,
                        this: Some(this),
                    }))
                },
                reference,
            )
        } else {
            DirEntry::new_file(
                FileNode::new(Arc::new(Self { pin, this: None })),
                kind,
                reference,
            )
        }
    }
}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> NodeOps for FatNode<D> {
    fn inode(&self) -> u64 {
        self.pin.id.get()
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        let m = self
            .pin
            .fs
            .lock()
            .await
            .driver
            .stat(self.pin.id)
            .await
            .map_err(vfs_error)?;
        let cluster = self.pin.fs.block_size();
        Ok(Metadata {
            device: 0,
            inode: self.inode(),
            nlink: 1,
            mode: NodePermission::from_bits_truncate(m.permissions().bits() as u16),
            node_type: if m.file_type().is_dir() {
                NodeType::Directory
            } else {
                NodeType::RegularFile
            },
            uid: 0,
            gid: 0,
            size: m.len(),
            block_size: cluster,
            blocks: m.len().div_ceil(cluster) * (cluster / 512),
            rdev: DeviceId::default(),
            atime: from_fat_time(m.accessed()),
            mtime: from_fat_time(m.modified()),
            ctime: from_fat_time(m.created()),
        })
    }

    async fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        // FAT has no POSIX ownership and mode bits. Keep the existing synthetic
        // ownership/permission policy, including on VFS create with an owner.
        let mut changes = SetAttr::new();
        if let Some(time) = update.atime {
            changes = changes.with_accessed(to_fat_time(time)?);
        }
        if let Some(time) = update.mtime {
            changes = changes.with_modified(to_fat_time(time)?);
        }
        if changes.is_empty() {
            return Ok(());
        }
        self.pin
            .fs
            .lock()
            .await
            .driver
            .setattr(self.pin.id, &changes)
            .await
            .map_err(vfs_error)
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        self.pin.fs.as_ref()
    }

    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        self.pin
            .fs
            .lock()
            .await
            .driver
            .fsync(self.pin.id)
            .await
            .map_err(vfs_error)
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }

    fn flags(&self) -> NodeFlags {
        NodeFlags::BLOCKING
    }
}
