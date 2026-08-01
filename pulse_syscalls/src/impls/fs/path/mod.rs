use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::LinuxError;
use axfs::OpenOptions;
use axfs_ng_vfs::{MetadataUpdate, NodePermission, NodeType, VfsError, path::Path};
use linux_raw_sys::general::*;
use pulse_core::fd_table::open_result_to_entry;

use crate::impls::{
    fs::common::{context_for_dirfd, insert_fd_entry, open_fd_flags, resolve_location_at_ptr},
    utils::USER_PATH_MAX,
};

static MOUNT_FLAGS_WARNED: AtomicBool = AtomicBool::new(false);
static UMOUNT_FLAGS_WARNED: AtomicBool = AtomicBool::new(false);

mod links;
mod mount;
mod open;

pub(crate) use links::*;
pub(crate) use mount::*;
pub(crate) use open::*;

fn read_user_nonempty_path(pathname: usize) -> Result<String, LinuxError> {
    crate::impls::utils::with_user_path_str(pathname, |path| {
        if path.is_empty() {
            Err(LinuxError::EINVAL)
        } else {
            Ok(path.to_string())
        }
    })
}

fn read_user_optional_path(pathname: usize) -> Result<Option<String>, LinuxError> {
    if pathname == 0 {
        return Ok(None);
    }
    crate::impls::utils::with_user_path_str(pathname, |path| {
        if path.is_empty() {
            Ok(None)
        } else {
            Ok(Some(path.to_string()))
        }
    })
}
