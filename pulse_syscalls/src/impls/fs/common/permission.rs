use axerrno::LinuxError;
use axfs_ng_vfs::{Location, NodePermission, NodeType};
use linux_raw_sys::general::*;

pub(crate) fn permission_mask_from_bits(
    mode: NodePermission,
    read: NodePermission,
    write: NodePermission,
    exec: NodePermission,
) -> usize {
    let mut mask = 0usize;
    if mode.contains(read) {
        mask |= R_OK as usize;
    }
    if mode.contains(write) {
        mask |= W_OK as usize;
    }
    if mode.contains(exec) {
        mask |= X_OK as usize;
    }
    mask
}

pub(crate) fn allowed_access_mask(
    mode: NodePermission,
    uid: u32,
    gid: u32,
    owner_uid: u32,
    owner_gid: u32,
) -> usize {
    if uid == owner_uid {
        permission_mask_from_bits(
            mode,
            NodePermission::OWNER_READ,
            NodePermission::OWNER_WRITE,
            NodePermission::OWNER_EXEC,
        )
    } else if gid == owner_gid {
        permission_mask_from_bits(
            mode,
            NodePermission::GROUP_READ,
            NodePermission::GROUP_WRITE,
            NodePermission::GROUP_EXEC,
        )
    } else {
        permission_mask_from_bits(
            mode,
            NodePermission::OTHER_READ,
            NodePermission::OTHER_WRITE,
            NodePermission::OTHER_EXEC,
        )
    }
}

pub(crate) fn check_faccess_permission(
    location: &Location,
    mode: usize,
    uid: u32,
    gid: u32,
) -> Result<(), LinuxError> {
    if mode == 0 {
        return Ok(());
    }

    let meta = location
        .metadata()
        .map_err(|e| LinuxError::from(e.canonicalize()))?;

    axlog::debug!(
        "check_faccess_permission: location={:?}, mode={:#o}, uid={}, gid={}, meta.mode={:#o}, meta.uid={}, meta.gid={}",
        location,
        mode,
        uid,
        gid,
        meta.mode.bits(),
        meta.uid,
        meta.gid
    );

    if uid == 0 {
        if (mode & X_OK as usize) == 0 {
            return Ok(());
        }
        if meta.node_type != NodeType::RegularFile {
            return Ok(());
        }
        let any_exec = meta.mode.intersects(
            NodePermission::OWNER_EXEC | NodePermission::GROUP_EXEC | NodePermission::OTHER_EXEC,
        );
        return if any_exec {
            Ok(())
        } else {
            Err(LinuxError::EACCES)
        };
    }

    let allowed = allowed_access_mask(meta.mode, uid, gid, meta.uid, meta.gid);
    if (mode & !allowed) == 0 {
        Ok(())
    } else {
        Err(LinuxError::EACCES)
    }
}
