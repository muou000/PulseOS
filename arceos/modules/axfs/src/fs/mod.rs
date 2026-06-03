use alloc::vec::Vec;

#[cfg(feature = "fat")]
mod fat;

#[cfg(feature = "ext4")]
pub mod ext4;

pub(crate) mod devfs;
mod procfs;
mod tmpfs;
pub mod loop_dev;

use axdriver::prelude::BlockDriverOps;
use axfs_ng_vfs::{Filesystem, VfsResult};
use cfg_if::cfg_if;
pub(crate) use devfs::BlockDeviceSpec;
pub use devfs::{TtyCallbacks, register_tty_callbacks};

pub fn new_default<D: BlockDriverOps + 'static>(dev: D) -> VfsResult<Filesystem> {
    cfg_if! {
        if #[cfg(feature = "ext4")] {
            ext4::Ext4Filesystem::new(dev)
        } else if #[cfg(feature = "fat")] {
            Ok(fat::FatFilesystem::new(dev))
        } else {
            panic!("No filesystem feature enabled");
        }
    }
}

pub fn new_devfs(block_devices: Vec<BlockDeviceSpec>) -> Filesystem {
    devfs::DevFilesystem::new(block_devices)
}

pub fn new_procfs() -> Filesystem {
    procfs::ProcFilesystem::new()
}

pub use procfs::{ProcfsProcessProvider, register_process_provider};

pub fn new_tmpfs() -> Filesystem {
    tmpfs::TmpFilesystem::new()
}
