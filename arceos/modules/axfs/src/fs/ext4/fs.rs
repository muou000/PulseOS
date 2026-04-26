use alloc::sync::Arc;
use core::cell::OnceCell;

use axdriver::prelude::BlockDriverOps;
use axfs_ng_vfs::{
    DirEntry, DirNode, Filesystem, FilesystemOps, Reference, StatFs, VfsResult, path::MAX_NAME_LEN,
};
use ext4_rs::Ext4;
use kspin::{SpinNoPreempt as Mutex, SpinNoPreemptGuard as MutexGuard};

use super::{Ext4Disk, Inode, cleanup_dir_cache_registry};

const ROOT_INODE: u32 = 2;

pub struct Ext4Filesystem {
    inner: Mutex<Ext4>,
    root_dir: OnceCell<DirEntry>,
}

impl Ext4Filesystem {
    pub fn new<D: BlockDriverOps + 'static>(dev: D) -> VfsResult<Filesystem> {
        let disk = Ext4Disk::new(dev);
        let ext4 = Ext4::open(disk);
        let fs = Arc::new(Self {
            inner: Mutex::new(ext4),
            root_dir: OnceCell::new(),
        });
        let _ = fs.root_dir.set(DirEntry::new_dir(
            |this| DirNode::new(Inode::new(fs.clone(), ROOT_INODE, Some(this))),
            Reference::root(),
        ));
        Ok(Filesystem::new(fs))
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, Ext4> {
        self.inner.lock()
    }
}

unsafe impl Send for Ext4Filesystem {}

unsafe impl Sync for Ext4Filesystem {}

impl Drop for Ext4Filesystem {
    fn drop(&mut self) {
        // Use the same pointer-based id as ext4_fs_id so the registry cleanup
        // targets exactly this filesystem's cached directory states.
        cleanup_dir_cache_registry(self as *const Self as usize);
    }
}

impl FilesystemOps for Ext4Filesystem {
    fn name(&self) -> &str {
        "ext4"
    }

    fn root_dir(&self) -> DirEntry {
        self.root_dir.get().unwrap().clone()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        let fs = self.lock();
        let sb = &fs.super_block;
        Ok(StatFs {
            fs_type: 0xef53,
            block_size: sb.block_size(),
            blocks: sb.blocks_count() as u64,
            blocks_free: sb.free_blocks_count(),
            blocks_available: sb.free_blocks_count(),
            file_count: sb.total_inodes() as u64,
            free_file_count: sb.free_inodes_count() as u64,
            name_length: MAX_NAME_LEN as u32,
            fragment_size: 0,
            mount_flags: 0,
        })
    }

    fn flush(&self) -> VfsResult<()> {
        Ok(())
    }
}
