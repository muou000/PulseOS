use alloc::sync::Arc;
use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Weak;
use alloc::vec::Vec;
use core::cell::OnceCell;

use axdriver::prelude::BlockDriverOps;
use axfs_ng_vfs::{
    DirEntry, DirNode, Filesystem, FilesystemOps, Reference, StatFs, VfsResult, WeakDirEntry,
    path::MAX_NAME_LEN,
};
use ext4plus::Ext4;
use axsync::{Mutex, MutexGuard};
use super::{Ext4Disk, Ext4DiskWrapper, Inode, cleanup_dir_cache_registry};

const ROOT_INODE: u32 = 2;

pub struct Ext4Filesystem {
    inner: Mutex<Ext4>,
    root_dir: OnceCell<WeakDirEntry>,
    pub(super) active_inodes: Mutex<BTreeMap<u32, Vec<Weak<Inode>>>>,
    pub(crate) block_size: usize,
}

impl Ext4Filesystem {
    pub fn new<D: BlockDriverOps + 'static>(dev: D) -> VfsResult<Filesystem> {
        log::info!("Ext4Filesystem::new: opening block device");
        let disk = Ext4Disk::new(dev);
        let ext4 = Ext4::load_with_writer(
            Box::new(Ext4DiskWrapper(disk.clone())),
            Some(Box::new(Ext4DiskWrapper(disk.clone()))),
        ).map_err(|e| {
            log::error!("Failed to load ext4 filesystem: {:?}", e);
            axfs_ng_vfs::VfsError::Io
        })?;
        let mut log_block_size_buf = [0u8; 4];
        disk.read_offset(1048, &mut log_block_size_buf);
        let log_block_size = u32::from_le_bytes(log_block_size_buf);
        let block_size = 1024usize << log_block_size;
        disk.set_block_size(block_size);
        log::info!("Ext4Filesystem::new: block device opened successfully");
        let fs = Arc::new(Self {
            inner: Mutex::new(ext4),
            root_dir: OnceCell::new(),
            active_inodes: Mutex::new(BTreeMap::new()),
            block_size,
        });
        let root_dir = DirEntry::new_dir(
            |this| DirNode::new(Inode::new(fs.clone(), ROOT_INODE, Some(this))),
            Reference::root(),
        );
        let _ = fs.root_dir.set(root_dir.downgrade());
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
        self.root_dir
            .get()
            .and_then(WeakDirEntry::upgrade)
            .expect("ext4 root directory should be alive while filesystem is mounted")
    }

    fn stat(&self) -> VfsResult<StatFs> {
        let fs = self.lock();
        let sb = fs.superblock();
        let total_inodes = sb.num_block_groups() as u64 * sb.inodes_per_block_group().get() as u64;
        Ok(StatFs {
            fs_type: 0xef53,
            block_size: self.block_size as u32,
            blocks: sb.blocks_count(),
            blocks_free: sb.free_blocks_count(),
            blocks_available: sb.free_blocks_count(),
            file_count: total_inodes,
            free_file_count: sb.free_inodes_count() as u64,
            name_length: MAX_NAME_LEN as u32,
            fragment_size: 0,
            mount_flags: 0,
        })
    }

    fn flush(&self) -> VfsResult<()> {
        crate::disk::flush_all_disks().map_err(|_| axfs_ng_vfs::VfsError::Io)?;
        Ok(())
    }
}
