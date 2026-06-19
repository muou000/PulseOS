use alloc::sync::Arc;

use crate::{DirEntry, VfsResult};

pub struct StatFs {
    pub fs_type: u32,
    pub block_size: u32,
    pub blocks: u64,
    pub blocks_free: u64,
    pub blocks_available: u64,

    pub file_count: u64,
    pub free_file_count: u64,

    pub name_length: u32,
    pub fragment_size: u32,
    pub mount_flags: u32,
}

/// Trait for filesystem operations
pub trait FilesystemOps: Send + Sync {
    /// Gets the name of the filesystem
    fn name(&self) -> &str;

    /// Gets the root directory entry of the filesystem
    fn root_dir(&self) -> DirEntry;

    /// Returns statistics about the filesystem
    fn stat(&self) -> VfsResult<StatFs>;

    /// Flushes the filesystem, ensuring all data is written to disk
    fn flush(&self) -> VfsResult<()> {
        Ok(())
    }
}

#[derive(Clone)]
pub struct Filesystem {
    ops: Arc<dyn FilesystemOps>,
    root_dir: DirEntry,
}

impl Filesystem {
    pub fn name(&self) -> &str {
        self.ops.name()
    }

    pub fn root_dir(&self) -> DirEntry {
        self.root_dir.clone()
    }

    pub fn stat(&self) -> VfsResult<StatFs> {
        self.ops.stat()
    }

    pub fn flush(&self) -> VfsResult<()> {
        self.ops.flush()
    }
}

impl Filesystem {
    pub fn new(ops: Arc<dyn FilesystemOps>) -> Self {
        let root_dir = ops.root_dir();
        Self { ops, root_dir }
    }
}
