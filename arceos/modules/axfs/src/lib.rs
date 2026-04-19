#![cfg_attr(all(not(test), not(doc)), no_std)]
#![allow(clippy::new_ret_no_self)]

extern crate alloc;

#[macro_use]
extern crate log;

use alloc::{
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

#[allow(unused_imports)]
use axdriver::prelude::{BaseDriverOps, BlockDriverOps};
use axdriver::{AxBlockDevice, AxDeviceContainer};
use axfs_ng_vfs::NodePermission;
pub use axfs_ng_vfs::NodeType;
use spin::{Lazy, Mutex};

#[cfg(feature = "fat")]
mod disk;
mod fs;

mod highlevel;
pub use highlevel::*;

#[derive(Clone, Debug)]
pub struct MountRecord {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub options: String,
}

static MOUNT_RECORDS: Lazy<Mutex<Vec<MountRecord>>> = Lazy::new(|| Mutex::new(Vec::new()));
static MOUNTABLE_FILESYSTEMS: Lazy<Mutex<BTreeMap<String, axfs_ng_vfs::Filesystem>>> =
    Lazy::new(|| Mutex::new(BTreeMap::new()));
static PINNED_MOUNTPOINTS: Lazy<Mutex<Vec<Arc<axfs_ng_vfs::Mountpoint>>>> =
    Lazy::new(|| Mutex::new(Vec::new()));

fn normalize_target(target: &str) -> String {
    if target.is_empty() || target == "/" {
        "/".to_string()
    } else if target.starts_with('/') {
        target.to_string()
    } else {
        format!("/{}", target)
    }
}

fn reset_mount_records() {
    MOUNT_RECORDS.lock().clear();
}

fn reset_mountable_filesystems() {
    MOUNTABLE_FILESYSTEMS.lock().clear();
}

fn reset_pinned_mountpoints() {
    PINNED_MOUNTPOINTS.lock().clear();
}

fn pin_mountpoint(mountpoint: Arc<axfs_ng_vfs::Mountpoint>) {
    PINNED_MOUNTPOINTS.lock().push(mountpoint);
}

pub fn register_mount(source: &str, target: &str, fs_type: &str, options: &str) {
    let target = normalize_target(target);
    let mut mounts = MOUNT_RECORDS.lock();
    if let Some(existing) = mounts.iter_mut().find(|m| m.target == target) {
        existing.source = source.to_string();
        existing.fs_type = fs_type.to_string();
        existing.options = options.to_string();
        return;
    }
    mounts.push(MountRecord {
        source: source.to_string(),
        target,
        fs_type: fs_type.to_string(),
        options: options.to_string(),
    });
    mounts.sort_unstable_by(|a, b| a.target.cmp(&b.target));
}

pub fn unregister_mount(target: &str) -> bool {
    let target = normalize_target(target);
    if target == "/" {
        return false;
    }
    let mut mounts = MOUNT_RECORDS.lock();
    if let Some(index) = mounts.iter().position(|m| m.target == target) {
        mounts.remove(index);
        true
    } else {
        false
    }
}

pub fn is_mount_registered(target: &str) -> bool {
    let target = normalize_target(target);
    MOUNT_RECORDS.lock().iter().any(|m| m.target == target)
}

pub fn list_mounts() -> Vec<MountRecord> {
    MOUNT_RECORDS.lock().clone()
}

pub fn register_mountable_filesystem(source: &str, fs: &axfs_ng_vfs::Filesystem) {
    MOUNTABLE_FILESYSTEMS
        .lock()
        .insert(source.to_string(), fs.clone());
}

pub fn lookup_mountable_filesystem(source: &str) -> Option<axfs_ng_vfs::Filesystem> {
    MOUNTABLE_FILESYSTEMS.lock().get(source).cloned()
}

fn ensure_mount_dir(cx: &FsContext, path: &str) -> axfs_ng_vfs::VfsResult<axfs_ng_vfs::Location> {
    match cx.resolve(path) {
        Ok(loc) => {
            loc.check_is_dir()?;
            Ok(loc)
        }
        Err(_) => cx.create_dir(path, NodePermission::default()),
    }
}

fn mount_builtin_fs(
    cx: &FsContext,
    path: &str,
    fs: &axfs_ng_vfs::Filesystem,
    source: &str,
    options: &str,
) -> Option<Arc<axfs_ng_vfs::Mountpoint>> {
    let mount_dir = match ensure_mount_dir(cx, path) {
        Ok(loc) => loc,
        Err(e) => {
            warn!("  skip {} mountpoint {}: {:?}", fs.name(), path, e);
            return None;
        }
    };

    match mount_dir.mount(fs) {
        Ok(mountpoint) => {
            pin_mountpoint(mountpoint.clone());
            register_mount(source, path, fs.name(), options);
            info!("  mounted {} at {}", fs.name(), path);
            Some(mountpoint)
        }
        Err(e) => {
            warn!("  skip {} mount at {}: {:?}", fs.name(), path, e);
            None
        }
    }
}

pub fn init_filesystems(mut block_devs: AxDeviceContainer<AxBlockDevice>) {
    info!("Initialize filesystem subsystem...");
    reset_mount_records();
    reset_mountable_filesystems();
    reset_pinned_mountpoints();

    struct FsCandidate {
        disk_idx: usize,
        disk_size: u64,
        dev_name: String,
        fs: axfs_ng_vfs::Filesystem,
    }

    let mut candidates: Vec<FsCandidate> = Vec::new();
    let mut disk_idx = 0usize;

    while let Some(dev) = block_devs.take_one() {
        let disk_size = dev.num_blocks().saturating_mul(dev.block_size() as u64);
        let dev_name = dev.device_name().to_string();
        info!("  probing block device {}: {}", disk_idx, dev_name);

        let fs = match fs::new_default(dev) {
            Ok(fs) => fs,
            Err(e) => {
                warn!(
                    "  skip block device {} ({}): failed to initialize filesystem: {:?}",
                    disk_idx, dev_name, e
                );
                disk_idx += 1;
                continue;
            }
        };

        info!(
            "  filesystem on device {}: {} (size={} KiB)",
            disk_idx,
            fs.name(),
            disk_size / 1024,
        );

        candidates.push(FsCandidate {
            disk_idx,
            disk_size,
            dev_name,
            fs,
        });
        disk_idx += 1;
    }

    assert!(!candidates.is_empty(), "No usable filesystem found!");

    // Use block device 1 as the root filesystem. The remaining devices are
    // registered for user-initiated mount.
    let root_pos = if candidates.len() > 1 { 1 } else { 0 };
    let root = candidates.swap_remove(root_pos);
    info!(
        "  select block device {} ({}, {} KiB) as root filesystem (fixed device1)",
        root.disk_idx,
        root.dev_name,
        root.disk_size / 1024
    );

    let root_mp = axfs_ng_vfs::Mountpoint::new_root(&root.fs);
    let cx = FsContext::new(root_mp.root_location());
    register_mount(
        &format!("device{}", root.disk_idx),
        "/",
        root.fs.name(),
        "rw,relatime",
    );
    register_mountable_filesystem(&format!("device{}", root.disk_idx), &root.fs);

    for cand in candidates {
        let source = format!("device{}", cand.disk_idx);
        register_mountable_filesystem(&source, &cand.fs);
        info!(
            "  registered block device {} ({}) as {} for user-initiated mount",
            cand.disk_idx, cand.dev_name, source
        );
    }

    let proc_fs = fs::new_procfs();
    mount_builtin_fs(
        &cx,
        "/proc",
        &proc_fs,
        "proc",
        "rw,nosuid,nodev,noexec,relatime",
    );
    let dev_fs = fs::new_devfs();
    mount_builtin_fs(&cx, "/dev", &dev_fs, "devtmpfs", "rw,nosuid,relatime");

    let shm_fs = fs::new_tmpfs();
    mount_builtin_fs(
        &cx,
        "/dev/shm",
        &shm_fs,
        "tmpfs",
        "rw,nosuid,nodev,noexec,relatime",
    );

    ROOT_FS_CONTEXT.call_once(|| cx.clone());
    *FS_CONTEXT.lock() = cx;
}
