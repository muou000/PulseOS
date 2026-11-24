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
use core::{
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use axdriver::{AxBlockDevice, AxDeviceContainer, prelude::BaseDriverOps};
use axfs_ng_vfs::NodePermission;
pub use axfs_ng_vfs::NodeType;
use futures_util::{StreamExt, stream::FuturesUnordered};
use kspin::SpinNoPreempt;
use spin::Lazy;

mod disk;
pub mod fs;
mod mounts;

pub use mounts::*;
use mounts::{reset_mount_records, reset_mounted_mountpoints};

pub use disk::{flush_all_disks, flush_all_disks_async};
pub use fs::{
    TtyCallbacks, devfs::DevNode, new_default, new_procfs, new_tmpfs, register_tty_callbacks,
};

/// Fills `buf` with bytes from the kernel random stream.
pub fn fill_random_bytes(buf: &mut [u8]) {
    fs::devfs::fill_random_bytes(buf);
}

// Dirty data is flushed by a kernel task instead of relying on descriptor
// close (which is intentionally only a cache-lifetime operation). A short
// polling interval gives ordinary writes bounded writeback latency. File
// caches keep their own dirty generations, so the task only takes their I/O
// locks when they actually changed; this flag is reserved for direct/raw disk
// writes that have no file-cache state to inspect.
const WRITEBACK_INTERVAL: Duration = Duration::from_secs(1);
static WRITEBACK_DAEMON_STARTED: AtomicBool = AtomicBool::new(false);
static WRITEBACK_REQUESTED: AtomicBool = AtomicBool::new(false);

// A global checkpoint holds mount roots and driver references across async
// I/O. Finish the checkpoint before retiring a FAT volume or loop binding.
#[cfg(feature = "fat")]
static CHECKPOINT: async_lock::Mutex<()> = async_lock::Mutex::new(());

/// Marks direct filesystem or raw-block state for background writeback.
///
/// Cached-file writes use their own per-file generations instead. Keep this
/// store rather than a lossy load/CAS fast path: a writer racing the daemon's
/// `swap(false)` must always leave a later checkpoint pending.
pub(crate) fn request_writeback() {
    WRITEBACK_REQUESTED.store(true, Ordering::Release);
}

fn take_writeback_request() -> bool {
    WRITEBACK_REQUESTED.swap(false, Ordering::AcqRel)
}

fn start_writeback_daemon() {
    if WRITEBACK_DAEMON_STARTED
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }

    task::spawn_async(async {
        loop {
            task::future::sleep(WRITEBACK_INTERVAL).await;
            if let Err(error) = flush_background_writeback_async().await {
                // Keep the request armed so a transient SD/MMC error gets a
                // later retry. Shutdown still performs its own bounded,
                // non-interruptible flush and reports failure to the caller.
                request_writeback();
                error!("background filesystem writeback failed: {:?}", error);
            }
        }
    });
}

pub fn flush_all_filesystems() -> axfs_ng_vfs::VfsResult<()> {
    task::future::block_on(flush_all_filesystems_async())
}

/// Drains writeback owned by a mount before detaching it from the VFS tree.
///
/// A loop device can be detached immediately after `umount(2)` returns. Its
/// file-cache and filesystem metadata must therefore be checkpointed before
/// the mount is detached; otherwise a later global sync can write to a loop
/// device whose backing file has already been cleared.
pub async fn flush_mountpoint_before_unmount(
    mountpoint: &Arc<axfs_ng_vfs::Mountpoint>,
) -> axfs_ng_vfs::VfsResult<()> {
    let root = mountpoint.root_location();
    let filesystem = root.filesystem();
    highlevel::flush_file_caches_for_filesystem_async(filesystem).await?;
    filesystem.flush().await
}

/// Drain a real mount before detaching it. Bind mounts share their source's
/// cache and need no separate checkpoint.
pub async fn flush_and_unmount(
    target: &axfs_ng_vfs::Location,
    subtree: bool,
) -> axfs_ng_vfs::VfsResult<()> {
    #[cfg(feature = "fat")]
    let _checkpoint = CHECKPOINT.lock().await;
    let mountpoint = target.mountpoint();
    if !mounts::mountpoint_is_bind(mountpoint) {
        flush_mountpoint_before_unmount(mountpoint).await?;
    }
    if subtree {
        mounts::unmount_subtree(target)
    } else {
        mounts::unmount_filesystem(target)
    }
}

async fn flush_filesystem_root(
    root: axfs_ng_vfs::Location,
) -> (String, axfs_ng_vfs::VfsResult<()>) {
    let name = root.filesystem().name().to_string();
    let result = root.filesystem().flush().await;
    (name, result)
}

async fn flush_registered_filesystems_and_disks(
    mut first_error: Option<axfs_ng_vfs::VfsError>,
) -> axfs_ng_vfs::VfsResult<()> {
    let mut roots = BTreeMap::new();
    if let Some(cx) = ROOT_FS_CONTEXT.get() {
        let root = cx.root_dir().clone();
        roots.insert(filesystem_id(root.filesystem()), root);
    }
    let mps = mounts::mounted_mountpoints();
    for mp in mps {
        let root = mp.root_location();
        roots
            .entry(filesystem_id(root.filesystem()))
            .or_insert(root);
    }
    const FILESYSTEM_FLUSH_CONCURRENCY: usize = 4;
    let mut roots = roots.into_values();
    let mut pending = FuturesUnordered::new();
    loop {
        while pending.len() < FILESYSTEM_FLUSH_CONCURRENCY {
            let Some(root) = roots.next() else {
                break;
            };
            pending.push(flush_filesystem_root(root));
        }
        let Some((name, result)) = pending.next().await else {
            break;
        };
        if let Err(err) = result {
            error!("Failed to flush {} filesystem: {:?}", name, err);
            if first_error.is_none() {
                first_error = Some(err);
            }
        }
    }
    // Filesystem flushes cover mounted data. The disk registry additionally
    // owns seekable raw-block write buffers; generation checks make the ext4
    // entries reached here a cheap no-op after their filesystem checkpoint.
    if let Err(err) = disk::flush_all_disks_async().await {
        error!("Failed to flush registered disks: {:?}", err);
        if first_error.is_none() {
            first_error = Some(axfs_ng_vfs::VfsError::Io);
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// Performs one background checkpoint without acquiring every cached file's
/// I/O lock. Explicit `sync`, unmount, and shutdown still use the complete
/// cache walk below as their stronger semantic boundary.
async fn flush_background_writeback_async() -> axfs_ng_vfs::VfsResult<()> {
    #[cfg(feature = "fat")]
    let _checkpoint = CHECKPOINT.lock().await;
    let (first_error, dirty_file_caches) = match highlevel::flush_pending_file_caches_async().await
    {
        Ok(dirty_file_caches) => (None, dirty_file_caches),
        Err(err) => (Some(err), true),
    };
    let direct_writeback = take_writeback_request();

    if dirty_file_caches || direct_writeback {
        return flush_registered_filesystems_and_disks(first_error).await;
    }

    first_error.map_or(Ok(()), Err)
}

pub async fn flush_all_filesystems_async() -> axfs_ng_vfs::VfsResult<()> {
    #[cfg(feature = "fat")]
    let _checkpoint = CHECKPOINT.lock().await;
    let first_error = highlevel::flush_all_file_caches_async().await.err();
    flush_registered_filesystems_and_disks(first_error).await
}

fn filesystem_id(fs: &dyn axfs_ng_vfs::FilesystemOps) -> usize {
    fs as *const dyn axfs_ng_vfs::FilesystemOps as *const () as usize
}
#[cfg(feature = "ext4")]
pub use fs::ext4;

mod highlevel;
pub use highlevel::*;

// These registries are inspected from syscall/task context.  A preemptible
// raw spin lock can strand its owner on a single CPU while a cleanup task
// spins, so keep the short bookkeeping sections preemption-safe.
static MOUNTABLE_FILESYSTEMS: Lazy<SpinNoPreempt<BTreeMap<String, axfs_ng_vfs::Filesystem>>> =
    Lazy::new(|| SpinNoPreempt::new(BTreeMap::new()));
static PINNED_MOUNTPOINTS: Lazy<SpinNoPreempt<Vec<Arc<axfs_ng_vfs::Mountpoint>>>> =
    Lazy::new(|| SpinNoPreempt::new(Vec::new()));

fn reset_mountable_filesystems() {
    let cleared = {
        let mut guard = MOUNTABLE_FILESYSTEMS.lock();
        core::mem::take(&mut *guard)
    };
    drop(cleared);
}

fn reset_pinned_mountpoints() {
    let cleared = {
        let mut guard = PINNED_MOUNTPOINTS.lock();
        core::mem::take(&mut *guard)
    };
    drop(cleared);
}

fn pin_mountpoint(mountpoint: Arc<axfs_ng_vfs::Mountpoint>) {
    PINNED_MOUNTPOINTS.lock().push(mountpoint);
}

pub fn register_mountable_filesystem(source: &str, fs: &axfs_ng_vfs::Filesystem) {
    MOUNTABLE_FILESYSTEMS
        .lock()
        .insert(source.to_string(), fs.clone());
}

pub fn lookup_mountable_filesystem(source: &str) -> Option<axfs_ng_vfs::Filesystem> {
    MOUNTABLE_FILESYSTEMS.lock().get(source).cloned()
}

/// Resolve the kernel's legacy deviceN mount-source spelling.
pub fn mount_device_alias(source: &str) -> Option<String> {
    let index: u32 = source.strip_prefix("device")?.parse().ok()?;
    Some(format!("/dev/{}", disk_node_name(index as usize)))
}

#[cfg(feature = "fat")]
pub fn filesystem_is_mounted(fs: &axfs_ng_vfs::Filesystem) -> bool {
    let id = filesystem_id(fs.root_dir().filesystem());
    ROOT_FS_CONTEXT.get().is_some_and(|ctx| filesystem_id(ctx.root_dir().filesystem()) == id)
        || mounts::mounted_mountpoints().iter().any(|mp| filesystem_id(mp.root_location().filesystem()) == id)
}

#[cfg(feature = "fat")]
pub fn forget_mountable_filesystem(fs: &axfs_ng_vfs::Filesystem) {
    // Both deviceN and /dev/vdX can refer to this boot probe. The caller
    // retains the filesystem across removal from the registry.
    let root = fs.root_dir();
    MOUNTABLE_FILESYSTEMS.lock().retain(|_, cached| cached.root_dir() != root);
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
    let dev = &fs::loop_dev::LOOP_DEVICES[id];
    let mut backing = dev.backing.lock();
    let file = backing.as_ref().ok_or(axfs_ng_vfs::VfsError::NoSuchDevice)?;
    if Arc::strong_count(file) != 1 {
        return Err(axfs_ng_vfs::VfsError::ResourceBusy);
    }
    let removed = backing.take();
    dev.size.store(0, core::sync::atomic::Ordering::Release);
    dev.flags.store(0, core::sync::atomic::Ordering::Release);
    drop(backing);
    drop(removed);
    Ok(())
}

pub fn set_loop_backing(id: usize, file: File) -> axfs_ng_vfs::VfsResult<()> {
    if id >= 8 {
        return Err(axfs_ng_vfs::VfsError::InvalidInput);
    }
    let metadata = task::future::block_on(file.location().metadata())?;
    let size = cached_file_size(file.location()).unwrap_or(metadata.size);
    let dev = &fs::loop_dev::LOOP_DEVICES[id];
    let file = Arc::new(file);
    let mut backing = dev.backing.lock();
    if backing.is_some() {
        return Err(axfs_ng_vfs::VfsError::ResourceBusy);
    }
    *backing = Some(file);
    dev.size.store(size, core::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn get_loop_flags(id: usize) -> Option<u32> {
    if id >= 8 {
        return None;
    }
    Some(
        fs::loop_dev::LOOP_DEVICES[id]
            .flags
            .load(core::sync::atomic::Ordering::Acquire),
    )
}

pub fn set_loop_flags(id: usize, flags: u32) -> axfs_ng_vfs::VfsResult<()> {
    if id >= 8 {
        return Err(axfs_ng_vfs::VfsError::InvalidInput);
    }
    fs::loop_dev::LOOP_DEVICES[id]
        .flags
        .store(flags, core::sync::atomic::Ordering::Release);
    Ok(())
}

pub fn lookup_location(path: &str) -> axfs_ng_vfs::VfsResult<axfs_ng_vfs::Location> {
    let context = FS_CONTEXT.lock().clone();
    task::future::block_on(context.resolve(path))
}

pub fn probe_block_device(
    path: &str,
    loc: &axfs_ng_vfs::Location,
) -> axfs_ng_vfs::VfsResult<axfs_ng_vfs::Filesystem> {
    let entry = loc.entry();
    let node = entry
        .downcast::<fs::devfs::DevNode>()
        .map_err(|_| axfs_ng_vfs::VfsError::InvalidInput)?;
    #[cfg(all(feature = "fat", not(feature = "ext4")))]
    {
        let _ = path;
        task::future::block_on(node.mount_fat())
    }
    #[cfg(not(all(feature = "fat", not(feature = "ext4"))))]
    {
        let disk = node.get_block_device()?;
        let fs = task::future::block_on(fs::new_default(disk))?;
        // /dev/loopN is a name for a changeable binding. The boot aliases
        // represent fixed devices and may retain their filesystem.
        let rdev = task::future::block_on(entry.metadata())?.rdev;
        if rdev.major() != 7 {
            register_mountable_filesystem(path, &fs);
        }
        Ok(fs)
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
    match task::future::block_on(cx.resolve(path)) {
        Ok(loc) => {
            loc.check_is_dir()?;
            Ok(loc)
        }
        Err(_) => task::future::block_on(cx.create_dir(path, NodePermission::default())),
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
            register_mount_for_mountpoint(source, path, fs.name(), options, mountpoint.clone());
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

    // The first disk supplies the root filesystem. Every additional disk
    // must also be reachable by device name, even when its on-disk format
    // differs from the boot filesystem or it has yet to be formatted.
    let root_device = disk::SharedBlockDevice::new(
        block_devs.take_one().expect("root block device is required"),
    );
    let root = task::future::block_on(fs::new_default(root_device.clone()))
        .expect("failed to mount root filesystem on device0");
    info!(
        "  select block device 0 ({}, {} KiB) as root filesystem",
        root_device.device_name(),
        root_device.size() / 1024,
    );

    let root_mp = axfs_ng_vfs::Mountpoint::new_root(&root);
    let cx = FsContext::new(root_mp.root_location());
    register_mount("device0", "/", root.name(), "rw,relatime");
    register_mountable_device("device0", "vda", &root);

    let mut dev_nodes = alloc::vec![fs::BlockDeviceSpec {
        name: disk_node_name(0),
        device: root_device,
        major: 254,
        minor: 0,
    }];

    while let Some(dev) = block_devs.take_one() {
        let index = dev_nodes.len();
        let name = disk_node_name(index);
        let device = disk::SharedBlockDevice::new(dev);
        match task::future::block_on(fs::new_default(device.clone())) {
            Ok(fs) if fs.name() != "vfat" => {
                register_mountable_device(&format!("device{index}"), &name, &fs);
            }
            Ok(_) => {}  // FAT is probed per device when the volume is mounted.
            Err(error) => info!("  /dev/{name} available for explicit mount ({error:?})"),
        }
        dev_nodes.push(fs::BlockDeviceSpec {
            name,
            device,
            major: 254,
            minor: index as u32,
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
    mount_builtin_fs(
        &cx,
        "/proc",
        &proc_fs,
        "proc",
        "rw,nosuid,nodev,noexec,relatime",
    );
    let dev_fs = fs::new_devfs(dev_nodes);
    mount_builtin_fs(&cx, "/dev", &dev_fs, "devtmpfs", "rw,nosuid,relatime");

    let shm_fs = fs::new_tmpfs();
    mount_builtin_fs(
        &cx,
        "/dev/shm",
        &shm_fs,
        "tmpfs",
        "rw,nosuid,nodev,noexec,relatime",
    );
    let tmp_fs = fs::new_tmpfs();
    mount_builtin_fs(&cx, "/tmp", &tmp_fs, "tmpfs", "rw,nosuid,nodev,relatime");

    ROOT_FS_CONTEXT.call_once(|| cx.clone());
    *FS_CONTEXT.lock() = cx;
    start_writeback_daemon();
}

pub use fs::{ProcfsProcessProvider, register_process_provider};
