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

mod disk;
pub mod fs;

pub use fs::{new_tmpfs, new_procfs, new_default, devfs::DevNode, TtyCallbacks, register_tty_callbacks};
#[cfg(feature = "ext4")]
pub use fs::ext4;

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
static MOUNTED_MOUNTPOINTS: Lazy<Mutex<Vec<(String, Arc<axfs_ng_vfs::Mountpoint>)>>> =
    Lazy::new(|| Mutex::new(Vec::new()));
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

fn reset_mounted_mountpoints() {
    MOUNTED_MOUNTPOINTS.lock().clear();
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
    mounts.push(MountRecord {
        source: source.to_string(),
        target,
        fs_type: fs_type.to_string(),
        options: options.to_string(),
    });
}

pub fn unregister_mount(target: &str) -> bool {
    let target = normalize_target(target);
    if target == "/" {
        return false;
    }
    let mut mounts = MOUNT_RECORDS.lock();
    if let Some(index) = mounts.iter().rposition(|m| m.target == target) {
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
    MOUNTABLE_FILESYSTEMS.lock().insert(source.to_string(), fs.clone());
}

pub fn lookup_mountable_filesystem(source: &str) -> Option<axfs_ng_vfs::Filesystem> {
    MOUNTABLE_FILESYSTEMS.lock().get(source).cloned()
}

pub fn register_mounted_mountpoint(target: &str, mountpoint: Arc<axfs_ng_vfs::Mountpoint>) {
    MOUNTED_MOUNTPOINTS.lock().push((normalize_target(target), mountpoint));
}

pub fn lookup_mounted_mountpoint(target: &str) -> Option<Arc<axfs_ng_vfs::Mountpoint>> {
    let target = normalize_target(target);
    MOUNTED_MOUNTPOINTS.lock().iter().rfind(|(t, _)| t == &target).map(|(_, m)| m.clone())
}

pub fn find_free_loop_device() -> Option<usize> {
    for i in 0..8 {
        if fs::loop_dev::LOOP_DEVICES[i].backing.lock().is_none() {
            return Some(i);
        }
    }
    None
}

pub fn is_loop_bound(id: usize) -> bool {
    if id >= 8 {
        return false;
    }
    fs::loop_dev::LOOP_DEVICES[id].backing.lock().is_some()
}

pub fn get_loop_size(id: usize) -> Option<u64> {
    if id >= 8 {
        return None;
    }
    let dev = &fs::loop_dev::LOOP_DEVICES[id];
    if dev.backing.lock().is_some() {
        Some(dev.size.load(core::sync::atomic::Ordering::Acquire))
    } else {
        None
    }
}

pub fn clear_loop_backing(id: usize) -> axfs_ng_vfs::VfsResult<()> {
    if id >= 8 {
        return Err(axfs_ng_vfs::VfsError::InvalidInput);
    }
    *fs::loop_dev::LOOP_DEVICES[id].backing.lock() = None;
    fs::loop_dev::LOOP_DEVICES[id]
        .size
        .store(0, core::sync::atomic::Ordering::Release);
    fs::loop_dev::LOOP_DEVICES[id]
        .flags
        .store(0, core::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn set_loop_backing(id: usize, file: File) -> axfs_ng_vfs::VfsResult<()> {
    if id >= 8 {
        return Err(axfs_ng_vfs::VfsError::InvalidInput);
    }
    let metadata = file.location().metadata()?;
    *fs::loop_dev::LOOP_DEVICES[id].backing.lock() = Some(Arc::new(file));
    fs::loop_dev::LOOP_DEVICES[id]
        .size
        .store(metadata.size, core::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn get_loop_flags(id: usize) -> Option<u32> {
    if id >= 8 {
        return None;
    }
    Some(fs::loop_dev::LOOP_DEVICES[id].flags.load(core::sync::atomic::Ordering::Acquire))
}

pub fn set_loop_flags(id: usize, flags: u32) -> axfs_ng_vfs::VfsResult<()> {
    if id >= 8 {
        return Err(axfs_ng_vfs::VfsError::InvalidInput);
    }
    fs::loop_dev::LOOP_DEVICES[id].flags.store(flags, core::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn lookup_location(path: &str) -> axfs_ng_vfs::VfsResult<axfs_ng_vfs::Location> {
    FS_CONTEXT.lock().resolve(path)
}

pub fn probe_block_device(
    path: &str,
    loc: &axfs_ng_vfs::Location,
) -> axfs_ng_vfs::VfsResult<axfs_ng_vfs::Filesystem> {
    let entry = loc.entry();
    let node = entry
        .downcast::<fs::devfs::DevNode>()
        .map_err(|_| axfs_ng_vfs::VfsError::InvalidInput)?;
    let disk = node.get_block_device()?;

    let fs = fs::new_default(disk.clone())?;
    register_mountable_device(path, path, &fs);
    Ok(fs)
}

pub fn unregister_mounted_mountpoint(target: &str) -> bool {
    let target = normalize_target(target);
    let mut mps = MOUNTED_MOUNTPOINTS.lock();
    if let Some(index) = mps.iter().rposition(|(t, _)| t == &target) {
        mps.remove(index);
        true
    } else {
        false
    }
}

pub fn rename_mount_registry(old_prefix: &str, new_prefix: &str) {
    let old_prefix = normalize_target(old_prefix);
    let new_prefix = normalize_target(new_prefix);

    // 1. Update MOUNT_RECORDS
    {
        let mut records = MOUNT_RECORDS.lock();
        for record in records.iter_mut() {
            if record.target == old_prefix {
                record.target = new_prefix.clone();
            } else if record.target.starts_with(&format!("{}/", old_prefix)) {
                let suffix = &record.target[old_prefix.len()..];
                record.target = format!("{}{}", new_prefix, suffix);
            }
        }
    }

    // 2. Update MOUNTED_MOUNTPOINTS
    {
        let mut mps = MOUNTED_MOUNTPOINTS.lock();
        for (target, _mp) in mps.iter_mut() {
            if target == &old_prefix {
                *target = new_prefix.clone();
            } else if target.starts_with(&format!("{}/", old_prefix)) {
                let suffix = &target[old_prefix.len()..];
                *target = format!("{}{}", new_prefix, suffix);
            }
        }
    }
}

fn disk_node_name(index: usize) -> String {
    let mut n = index;
    let mut suffix = String::new();
    loop {
        suffix.insert(0, (b'a' + (n % 26) as u8) as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    format!("vd{}", suffix)
}

fn register_mountable_device(source: &str, disk_name: &str, fs: &axfs_ng_vfs::Filesystem) {
    register_mountable_filesystem(source, fs);
    register_mountable_filesystem(&format!("/dev/{}", disk_name), fs);
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
            register_mounted_mountpoint(path, mountpoint.clone());
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
    reset_mounted_mountpoints();
    reset_pinned_mountpoints();

    struct FsCandidate {
        disk_idx: usize,
        disk_size: u64,
        dev_name: String,
        shared_dev: disk::SharedBlockDevice,
        fs: axfs_ng_vfs::Filesystem,
    }

    let mut candidates: Vec<FsCandidate> = Vec::new();
    let mut disk_idx = 0usize;

    while let Some(dev) = block_devs.take_one() {
        let shared_dev = disk::SharedBlockDevice::new(dev);
        let disk_size = shared_dev.size();
        let dev_name = shared_dev.device_name().to_string();
        info!("  probing block device {}: {}", disk_idx, dev_name);

        let fs = match fs::new_default(shared_dev.clone()) {
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

        info!("  filesystem on device {}: {} (size={} KiB)", disk_idx, fs.name(), disk_size / 1024,);

        candidates.push(FsCandidate { disk_idx, disk_size, dev_name, shared_dev, fs });
        disk_idx += 1;
    }

    assert!(!candidates.is_empty(), "No usable filesystem found!");

    // Use block device 1 as the root filesystem. The remaining devices are
    // registered for user-initiated mount.
    let root_pos = candidates
        .iter()
        .position(|cand| cand.disk_idx == 1)
        .expect("block device1 is required for the root filesystem");
    let root = candidates.swap_remove(root_pos);
    info!(
        "  select block device {} ({}, {} KiB) as root filesystem",
        root.disk_idx,
        root.dev_name,
        root.disk_size / 1024
    );

    let root_mp = axfs_ng_vfs::Mountpoint::new_root(&root.fs);
    let cx = FsContext::new(root_mp.root_location());
    register_mount(&format!("device{}", root.disk_idx), "/", root.fs.name(), "rw,relatime");
    register_mountable_device(
        &format!("device{}", root.disk_idx),
        &disk_node_name(root.disk_idx),
        &root.fs,
    );

    let mut dev_nodes = Vec::with_capacity(candidates.len() + 9);
    dev_nodes.push(fs::BlockDeviceSpec {
        name: disk_node_name(root.disk_idx),
        device: root.shared_dev.clone(),
        major: 254,
        minor: root.disk_idx as u32,
    });

    for cand in candidates {
        let source = format!("device{}", cand.disk_idx);
        register_mountable_device(&source, &disk_node_name(cand.disk_idx), &cand.fs);
        info!(
            "  registered block device {} ({}) as {} for user-initiated mount",
            cand.disk_idx, cand.dev_name, source
        );
        dev_nodes.push(fs::BlockDeviceSpec {
            name: disk_node_name(cand.disk_idx),
            device: cand.shared_dev,
            major: 254,
            minor: cand.disk_idx as u32,
        });
    }

    for i in 0..8 {
        let loop_dev = fs::loop_dev::LoopBlockDevice::new(i);
        dev_nodes.push(fs::BlockDeviceSpec {
            name: format!("loop{}", i),
            device: disk::SharedBlockDevice::new(alloc::boxed::Box::new(loop_dev)),
            major: 7,
            minor: i as u32,
        });
    }

    let proc_fs = fs::new_procfs();
    mount_builtin_fs(&cx, "/proc", &proc_fs, "proc", "rw,nosuid,nodev,noexec,relatime");
    let dev_fs = fs::new_devfs(dev_nodes);
    mount_builtin_fs(&cx, "/dev", &dev_fs, "devtmpfs", "rw,nosuid,relatime");

    let shm_fs = fs::new_tmpfs();
    mount_builtin_fs(&cx, "/dev/shm", &shm_fs, "tmpfs", "rw,nosuid,nodev,noexec,relatime");
    let tmp_fs = fs::new_tmpfs();
    mount_builtin_fs(&cx, "/tmp", &tmp_fs, "tmpfs", "rw,nosuid,nodev,relatime");

    ROOT_FS_CONTEXT.call_once(|| cx.clone());
    *FS_CONTEXT.lock() = cx;
}

pub use fs::{ProcfsProcessProvider, register_process_provider};
