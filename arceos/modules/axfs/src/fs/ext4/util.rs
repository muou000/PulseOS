use axfs_ng_vfs::{NodeType, VfsError};
use ext4plus::error::Ext4Error;
use ext4plus::FileType;

pub fn into_vfs_err(err: Ext4Error) -> VfsError {
    let vfs_err = match &err {
        Ext4Error::NotFound => VfsError::NotFound,
        Ext4Error::NotADirectory => VfsError::NotADirectory,
        Ext4Error::IsADirectory => VfsError::IsADirectory,
        Ext4Error::Io(error) => {
            log::error!("ext4plus I/O error: {error}");
            error
                .as_ref()
                .downcast_ref::<super::Ext4DevError>()
                .map(super::Ext4DevError::to_vfs_error)
                .unwrap_or(VfsError::Io)
        }
        Ext4Error::Incompatible(_) => VfsError::Unsupported,
        Ext4Error::UnsupportedOperation(_) => VfsError::Unsupported,
        Ext4Error::Readonly => VfsError::ReadOnlyFilesystem,
        Ext4Error::NoSpace => VfsError::StorageFull,
        Ext4Error::AlreadyExists => VfsError::AlreadyExists,
        _ => VfsError::InvalidData,
    };
    if let VfsError::InvalidData = vfs_err {
        log::error!("ext4plus error mapped to InvalidData: {:?}", err);
    }
    vfs_err
}

pub fn into_vfs_type(ty: FileType) -> NodeType {
    match ty {
        FileType::Regular => NodeType::RegularFile,
        FileType::Directory => NodeType::Directory,
        FileType::CharacterDevice => NodeType::CharacterDevice,
        FileType::BlockDevice => NodeType::BlockDevice,
        FileType::Fifo => NodeType::Fifo,
        FileType::Socket => NodeType::Socket,
        FileType::Symlink => NodeType::Symlink,
    }
}

pub fn into_ext4_file_type(ty: NodeType) -> Result<FileType, VfsError> {
    Ok(match ty {
        NodeType::Fifo => FileType::Fifo,
        NodeType::CharacterDevice => FileType::CharacterDevice,
        NodeType::Directory => FileType::Directory,
        NodeType::BlockDevice => FileType::BlockDevice,
        NodeType::RegularFile => FileType::Regular,
        NodeType::Symlink => FileType::Symlink,
        NodeType::Socket => FileType::Socket,
        NodeType::Unknown => return Err(VfsError::InvalidData),
    })
}

#[cfg(test)]
mod tests {
    use alloc::boxed::Box;

    use axdriver::prelude::DevError;
    use axfs_ng_vfs::VfsError;
    use ext4plus::error::Ext4Error;

    use super::into_vfs_err;

    fn device_error(error: DevError) -> Ext4Error {
        Ext4Error::Io(Box::new(super::super::Ext4DevError(error)))
    }

    #[test]
    fn ext4_device_errors_preserve_actionable_kinds() {
        assert_eq!(
            into_vfs_err(device_error(DevError::NoMemory)),
            VfsError::NoMemory
        );
        assert_eq!(
            into_vfs_err(device_error(DevError::BadState)),
            VfsError::BadState
        );
        assert_eq!(
            into_vfs_err(device_error(DevError::Again)),
            VfsError::WouldBlock
        );
        assert_eq!(into_vfs_err(device_error(DevError::Io)), VfsError::Io);
    }
}
