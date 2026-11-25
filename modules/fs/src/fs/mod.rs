use alloc::vec::Vec;

#[cfg(feature = "fat")]
pub(crate) mod fat;

#[cfg(feature = "ext4")]
pub mod ext4;

pub(crate) mod devfs;
pub mod loop_dev;
pub mod procfs;
pub(crate) mod tmpfs;

use driver::prelude::AsyncBlockDriverOps;
use vfs::{Filesystem, VfsResult};
use cfg_if::cfg_if;
pub(crate) use devfs::BlockDeviceSpec;
pub use devfs::{TtyCallbacks, register_tty_callbacks};

pub async fn new_default<D: AsyncBlockDriverOps + Clone + 'static>(
    dev: D,
) -> VfsResult<Filesystem> {
    cfg_if! {
        if #[cfg(feature = "ext4")] {
            ext4::Ext4Filesystem::new(dev).await
        } else if #[cfg(feature = "fat")] {
            fat::FatFilesystem::new(dev).await
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
