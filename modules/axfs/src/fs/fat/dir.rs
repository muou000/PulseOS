use alloc::{boxed::Box, sync::Arc};

use async_trait::async_trait;
use axdriver::prelude::AsyncBlockDriverOps;
use axfs_ng_vfs::{
    DirEntry, DirEntrySink, DirNode, DirNodeOps, NodeOps, NodePermission, NodeType, Reference,
    VfsError, VfsResult, WeakDirEntry,
};
use hadris_fs::{DirCursor, ErrorKind, Name, RenameMode, SetAttr};

use super::{
    fs::{Volume, vfs_error},
    node::{FatNode, NodePin},
};

impl<D: AsyncBlockDriverOps + Clone + 'static> FatNode<D> {
    fn child(
        &self,
        volume: &mut Volume<D>,
        pin: NodePin<D>,
        name: &str,
        kind: NodeType,
    ) -> VfsResult<DirEntry> {
        if let Some(entry) = volume.entries.get(&pin.id).and_then(WeakDirEntry::upgrade) {
            return Ok(entry);
        }
        let parent = self
            .this
            .as_ref()
            .and_then(WeakDirEntry::upgrade)
            .ok_or(VfsError::NotFound)?;
        let reference = Reference::new(Some(parent.downgrade()), name.into());
        let id = pin.id;
        let entry = Self::entry(pin, kind, reference, Some(parent));
        volume.entries.insert(id, entry.downgrade());
        Ok(entry)
    }
}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> DirNodeOps for FatNode<D> {
    fn is_cacheable(&self) -> bool {
        // Revalidate long names and short aliases together against FAT. The
        // generic VFS cache is keyed by the caller's exact byte spelling.
        false
    }

    async fn read_dir(
        &self,
        offset: u64,
        sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        let mut count = 0;
        if offset == 0 {
            if !sink.accept(".", self.inode(), NodeType::Directory, 1) {
                return Ok(0);
            }
            count += 1;
        }
        if offset < 2 {
            let parent_id = self.parent.as_ref().map_or(self.inode(), DirEntry::inode);
            if !sink.accept("..", parent_id, NodeType::Directory, 2) {
                return Ok(count);
            }
            count += 1;
        }
        let mut volume = self.pin.fs.lock().await;
        let mut cursor = DirCursor::from_raw(offset.saturating_sub(2));
        while let Some(entry) = volume
            .driver
            .readdir(self.pin.id, cursor)
            .await
            .map_err(vfs_error)?
        {
            cursor = entry.next_cursor();
            let name = entry.name().to_str().map_err(|_| VfsError::InvalidData)?;
            let kind = if entry.file_type().is_dir() {
                NodeType::Directory
            } else {
                NodeType::RegularFile
            };
            if !sink.accept(name, entry.node().get(), kind, cursor.into_raw() + 2) {
                break;
            }
            count += 1;
        }
        Ok(count)
    }

    async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        let mut volume = self.pin.fs.lock().await;
        let id = volume
            .driver
            .lookup(self.pin.id, Name::new(name))
            .await
            .map_err(vfs_error)?;
        let pin = NodePin::new(self.pin.fs.clone(), id);
        let metadata = volume.driver.stat(id).await.map_err(vfs_error)?;
        let kind = if metadata.file_type().is_dir() {
            NodeType::Directory
        } else {
            NodeType::RegularFile
        };
        self.child(&mut volume, pin, name, kind)
    }

    async fn create(
        &self,
        name: &str,
        kind: NodeType,
        _permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        let _namespace = self.pin.fs.namespace.lock().await;
        let mut volume = self.pin.fs.lock().await;
        let attrs = SetAttr::new();
        let name_bytes = Name::new(name);
        let id = match kind {
            NodeType::RegularFile => volume.driver.create(self.pin.id, name_bytes, &attrs).await,
            NodeType::Directory => volume.driver.mkdir(self.pin.id, name_bytes, &attrs).await,
            _ => return Err(VfsError::InvalidInput),
        }
        .map_err(vfs_error)?;
        self.child(
            &mut volume,
            NodePin::new(self.pin.fs.clone(), id),
            name,
            kind,
        )
    }

    async fn link(&self, _name: &str, _node: &DirEntry) -> VfsResult<DirEntry> {
        Err(VfsError::PermissionDenied)
    }

    async fn unlink(&self, name: &str) -> VfsResult<()> {
        let fs = &self.pin.fs;
        let _namespace = fs.namespace.lock().await;
        let name = Name::new(name);
        let victim = {
            let mut volume = fs.lock().await;
            let id = volume
                .driver
                .lookup(self.pin.id, name)
                .await
                .map_err(vfs_error)?;
            NodePin::new(fs.clone(), id)
        };
        // Writeback takes the cache I/O lock before entering the FAT driver.
        // Acquire those locks in the same order when retiring the backing id.
        crate::discard_unlinked_file_cache_after(Arc::as_ptr(fs) as usize, victim.id.get(), async {
            let mut volume = fs.lock().await;
            match volume.driver.unlink(self.pin.id, name).await {
                Err(e) if e.kind() == ErrorKind::IsADirectory => volume
                    .driver
                    .rmdir(self.pin.id, name)
                    .await
                    .map_err(vfs_error),
                result => result.map_err(vfs_error),
            }
        })
        .await
    }

    async fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()> {
        let dst = dst_dir
            .downcast::<Self>()
            .map_err(|_| VfsError::CrossesDevices)?;
        if !Arc::ptr_eq(&self.pin.fs, &dst.pin.fs) {
            return Err(VfsError::CrossesDevices);
        }
        let fs = &self.pin.fs;
        let _namespace = fs.namespace.lock().await;
        let src_name = Name::new(src_name);
        let dst_name = Name::new(dst_name);
        let (source, target) = {
            let mut volume = fs.lock().await;
            let id = volume
                .driver
                .lookup(self.pin.id, src_name)
                .await
                .map_err(vfs_error)?;
            let source = NodePin::new(fs.clone(), id);
            let target = match volume.driver.lookup(dst.pin.id, dst_name).await {
                Ok(id) => Some(NodePin::new(fs.clone(), id)),
                Err(e) if e.kind() == ErrorKind::NotFound => None,
                Err(e) => return Err(vfs_error(e)),
            };
            (source, target)
        };
        let rename = async {
            let mut volume = fs.lock().await;
            // On success (or a cancelled rename completed by hadris recovery)
            // a new lookup supplies the source node's current parent and name.
            volume.entries.remove(&source.id);
            volume
                .driver
                .rename(
                    self.pin.id,
                    src_name,
                    dst.pin.id,
                    dst_name,
                    RenameMode::Replace,
                )
                .await
                .map_err(vfs_error)
        };
        match target {
            Some(victim) if victim.id != source.id => {
                crate::discard_unlinked_file_cache_after(
                    Arc::as_ptr(fs) as usize,
                    victim.id.get(),
                    rename,
                )
                .await
            }
            _ => rename.await,
        }
    }
}
