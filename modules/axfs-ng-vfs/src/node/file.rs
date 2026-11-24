use alloc::sync::Arc;
use alloc::boxed::Box;
use core::ops::Deref;

use axpoll::Pollable;
use async_trait::async_trait;

use super::NodeOps;
use crate::{VfsError, VfsResult};

/// An optional handle lease retained by open descriptions and file mappings.
pub type OpenLeaseFuture<'a> =
    core::pin::Pin<Box<dyn core::future::Future<Output = VfsResult<Arc<()>>> + Send + 'a>>;

#[async_trait]
pub trait FileNodeOps: NodeOps + Pollable {
    /// Filesystems that cannot unlink an open node may track this lease until
    /// the last file description or mapping using it has been dropped.
    fn open_lease(&self) -> Option<OpenLeaseFuture<'_>> {
        None
    }

    /// Reads a number of bytes starting from a given offset.
    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize>;

    /// Reads data with storage provenance for `observed`, relative to `buf`.
    /// Only successful data reads overlapping that window count; metadata and
    /// other batch pages are excluded. `None` is explicitly unsupported.
    async fn read_at_with_io(
        &self,
        buf: &mut [u8],
        offset: u64,
        _observed: core::ops::Range<usize>,
    ) -> VfsResult<(usize, Option<bool>)> {
        self.read_at(buf, offset).await.map(|read| (read, None))
    }

    /// Writes a number of bytes starting from a given offset.
    async fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize>;

    /// Appends data to the file.
    ///
    /// Returns `(written, offset)` where `written` is the number of bytes
    /// written and `offset` is the new file size.
    async fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)>;

    /// Sets the size of the file.
    async fn set_len(&self, len: u64) -> VfsResult<()>;

    /// Sets the file's symlink target.
    async fn set_symlink(&self, target: &str) -> VfsResult<()>;

    /// Manipulates the underlying device parameters of special files.
    async fn ioctl(&self, _cmd: u32, _arg: usize) -> VfsResult<usize> {
        Err(VfsError::NotATty)
    }
}

#[derive(Clone)]
#[repr(transparent)]
pub struct FileNode(Arc<dyn FileNodeOps>);

impl Deref for FileNode {
    type Target = dyn FileNodeOps;

    fn deref(&self) -> &Self::Target {
        &*self.0
    }
}

impl From<FileNode> for Arc<dyn NodeOps> {
    fn from(node: FileNode) -> Self {
        node.0.clone()
    }
}

impl FileNode {
    pub fn new(ops: Arc<dyn FileNodeOps>) -> Self {
        Self(ops)
    }

    pub fn inner(&self) -> &Arc<dyn FileNodeOps> {
        &self.0
    }

    pub fn downcast<T: FileNodeOps>(self: &Arc<Self>) -> VfsResult<Arc<T>> {
        self.0
            .clone()
            .into_any()
            .downcast()
            .map_err(|_| VfsError::InvalidInput)
    }
}
