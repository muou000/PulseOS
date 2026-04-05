use core::time::Duration;

use axerrno::LinuxError;
use axfs_ng_vfs::{NodeType, VfsError};
use ext4_rs::{Ext4Error, InodeFileType};

pub fn into_vfs_err(err: Ext4Error) -> VfsError {
    let linux_error = LinuxError::try_from(err.error() as i32).unwrap_or(LinuxError::EIO);
    VfsError::from(linux_error).canonicalize()
}

pub fn into_vfs_type(ty: InodeFileType) -> NodeType {
    match ty {
        InodeFileType::S_IFREG => NodeType::RegularFile,
        InodeFileType::S_IFDIR => NodeType::Directory,
        InodeFileType::S_IFCHR => NodeType::CharacterDevice,
        InodeFileType::S_IFBLK => NodeType::BlockDevice,
        InodeFileType::S_IFIFO => NodeType::Fifo,
        InodeFileType::S_IFSOCK => NodeType::Socket,
        InodeFileType::S_IFLNK => NodeType::Symlink,
        _ => NodeType::Unknown,
    }
}

pub fn into_ext4_type(ty: NodeType) -> Result<InodeFileType, VfsError> {
    Ok(match ty {
        NodeType::Fifo => InodeFileType::S_IFIFO,
        NodeType::CharacterDevice => InodeFileType::S_IFCHR,
        NodeType::Directory => InodeFileType::S_IFDIR,
        NodeType::BlockDevice => InodeFileType::S_IFBLK,
        NodeType::RegularFile => InodeFileType::S_IFREG,
        NodeType::Symlink => InodeFileType::S_IFLNK,
        NodeType::Socket => InodeFileType::S_IFSOCK,
        NodeType::Unknown => return Err(VfsError::InvalidData),
    })
}

pub fn duration_to_ext4_time(value: Duration) -> u32 {
    value.as_secs().min(u32::MAX as u64) as u32
}

pub fn now_as_ext4_time() -> Option<u32> {
    if cfg!(feature = "times") {
        Some(duration_to_ext4_time(axhal::time::wall_time()))
    } else {
        None
    }
}
