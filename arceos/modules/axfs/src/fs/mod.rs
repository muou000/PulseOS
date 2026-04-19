#[cfg(feature = "fat")]
mod fat;

#[cfg(feature = "ext4")]
mod ext4;

mod devfs;
mod procfs;
mod tmpfs;

use axdriver::AxBlockDevice;
use axfs_ng_vfs::{Filesystem, VfsResult};
use cfg_if::cfg_if;

pub fn new_default(dev: AxBlockDevice) -> VfsResult<Filesystem> {
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

pub fn new_devfs() -> Filesystem {
    devfs::DevFilesystem::new()
}

pub fn new_procfs() -> Filesystem {
    procfs::ProcFilesystem::new()
}

pub fn new_tmpfs() -> Filesystem {
    tmpfs::TmpFilesystem::new()
}
