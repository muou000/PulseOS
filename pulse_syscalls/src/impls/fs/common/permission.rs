use axerrno::LinuxError;
use axfs::MountRecord;
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

pub(crate) fn is_location_readonly(location: &Location) -> bool {
    let abs_path = match location.absolute_path() {
        Ok(path) => path,
        Err(_) => return false,
    };
    let path_str = abs_path.as_str();

    // Get all mount records
    let mounts = axfs::list_mounts();

    // Find the longest target matching the path_str prefix.
    let mut best_match: Option<MountRecord> = None;
    for m in mounts {
        if path_str.starts_with(&m.target) {
            let target_len = m.target.len();
            if m.target == "/"
                || path_str.len() == target_len
                || path_str.as_bytes().get(target_len) == Some(&b'/')
            {
                if let Some(ref best) = best_match {
                    if m.target.len() > best.target.len() {
                        best_match = Some(m);
                    }
                } else {
                    best_match = Some(m);
                }
            }
        }
    }

    if let Some(best) = best_match {
        best.options.split(',').any(|opt| opt == "ro")
    } else {
        false
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

    if (mode & W_OK as usize) != 0 && is_location_readonly(location) {
        return Err(LinuxError::EROFS);
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
