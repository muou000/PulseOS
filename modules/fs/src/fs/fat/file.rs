use alloc::boxed::Box;
use core::task::Context;

use async_trait::async_trait;
use axdriver::prelude::AsyncBlockDriverOps;
use vfs::{FileNodeOps, VfsError, VfsResult};
use poll::{IoEvents, Pollable};

use super::{fs::vfs_error, node::FatNode};

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> FileNodeOps for FatNode<D> {
    fn open_lease(&self) -> Option<vfs::OpenLeaseFuture<'_>> {
        Some(Box::pin(self.pin.fs.open_file(self.pin.id)))
    }

    async fn read_at(&self, buf: &mut [u8], offset: u64) -> VfsResult<usize> {
        self.pin
            .fs
            .lock()
            .await
            .driver
            .read(self.pin.id, offset, buf)
            .await
            .map_err(vfs_error)
    }

    async fn write_at(&self, buf: &[u8], offset: u64) -> VfsResult<usize> {
        self.pin
            .fs
            .lock()
            .await
            .driver
            .write(self.pin.id, offset, buf)
            .await
            .map_err(vfs_error)
    }

    async fn append(&self, buf: &[u8]) -> VfsResult<(usize, u64)> {
        let mut vol = self.pin.fs.lock().await;
        let end = vol.driver.stat(self.pin.id).await.map_err(vfs_error)?.len();
        let written = vol
            .driver
            .write(self.pin.id, end, buf)
            .await
            .map_err(vfs_error)?;
        Ok((written, end + written as u64))
    }

    async fn set_len(&self, len: u64) -> VfsResult<()> {
        self.pin
            .fs
            .lock()
            .await
            .driver
            .truncate(self.pin.id, len)
            .await
            .map_err(vfs_error)
    }

    async fn set_symlink(&self, _target: &str) -> VfsResult<()> {
        Err(VfsError::PermissionDenied)
    }
}

impl<D: AsyncBlockDriverOps + Clone + 'static> Pollable for FatNode<D> {
    fn poll(&self) -> IoEvents {
        IoEvents::IN | IoEvents::OUT
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}
