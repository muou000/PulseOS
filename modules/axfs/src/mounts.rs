//! Mount records and mount/unmount coordination.
//!
//! Callers use `mount_filesystem`, `mount_bind`, and `unmount_filesystem` (or
//! `unmount_subtree` for lazy detach). Each primary and propagated shadow uses
//! the same publication workflow. The individual registry helpers remain for
//! boot, move bookkeeping, and remount.
//! Coordination takes the mountpoint index, then the listing lock, then the VFS
//! topology writer lock. Readers of either registry cannot observe an unfinished
//! update. The VFS rolls back a rejected update before releasing its topology
//! lock, so path resolution never observes a rejected topology transition.
//! Probing, path calculation, and capacity reservation precede the topology
//! transition; its commit callback only edits already-locked, reserved vectors.

use alloc::{
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use axfs_ng_vfs::{Filesystem, Location, Mountpoint, PropagationMode, VfsError, VfsResult};
use kspin::SpinNoPreempt;
use spin::Lazy;

#[derive(Clone, Debug)]
pub struct MountRecord {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub options: String,
    mountpoint: Option<Arc<axfs_ng_vfs::Mountpoint>>,
}

static MOUNT_RECORDS: Lazy<SpinNoPreempt<Vec<MountRecord>>> =
    Lazy::new(|| SpinNoPreempt::new(Vec::new()));

static MOUNTED_MOUNTPOINTS: Lazy<SpinNoPreempt<Vec<(String, Arc<axfs_ng_vfs::Mountpoint>)>>> =
    Lazy::new(|| SpinNoPreempt::new(Vec::new()));

#[cfg(test)]
pub(crate) static FAIL_NEXT_RECORD_UPDATE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// A deterministic registry failure at the second step of the workflow. The
// host harness includes this production module and tests real VFS rollback.
#[cfg(test)]
fn check_record_update() -> VfsResult<()> {
    if FAIL_NEXT_RECORD_UPDATE.swap(false, core::sync::atomic::Ordering::Relaxed) {
        Err(VfsError::NoMemory)
    } else {
        Ok(())
    }
}

/// Probe and mount an ordinary filesystem, publishing its index and listing
/// record together with its VFS attachment.
///
/// `flags` are Linux mount flags (bit 0 is MS_RDONLY). The probe runs before any
/// registry/topology lock is held and may perform I/O. A failed probe changes
/// nothing. A duplicate target or rejected record update leaves the prior
/// topology and records intact. After publishing the primary, propagate to
/// peers and slaves using the same per-mount transaction.
pub fn mount_filesystem(
    target: &Location,
    source: &str,
    fs_type: &str,
    flags: usize,
    probe: impl FnOnce() -> VfsResult<Filesystem>,
) -> VfsResult<Arc<Mountpoint>> {
    target.check_is_dir()?;
    let initial_path = target.absolute_path()?;
    if initial_path.as_str() == "/" || lookup_mounted_mountpoint(initial_path.as_str()).is_some() {
        return Err(VfsError::ResourceBusy);
    }
    let filesystem = probe()?;
    let mountpoint = publish_mount(
        target,
        MountSource::Filesystem(&filesystem),
        source,
        fs_type,
        flags & 1 != 0,
        flags,
        false,
    )?;
    propagate_mount(&mountpoint);
    Ok(mountpoint)
}

enum MountSource<'a> {
    Filesystem(&'a Filesystem),
    Bind(Location),
    Shadow(Location, PropagationMode),
}

// Prepare all bookkeeping before entering VFS, then publish both registries
// inside the attachment's rollback boundary. Bind stacks may share a pathname;
// an ordinary filesystem mount continues to reject a pathname conflict.
fn publish_mount(
    target: &Location,
    mount_source: MountSource<'_>,
    source: &str,
    fs_type: &str,
    readonly: bool,
    flags: usize,
    bind: bool,
) -> VfsResult<Arc<Mountpoint>> {
    // Probing or propagation traversal may overlap an ancestor move. Validate
    // this fresh snapshot under the topology writer at attachment time.
    let expected_path = target.absolute_path()?;
    let mut target_path = expected_path.to_string();
    let ordinary = matches!(mount_source, MountSource::Filesystem(_));
    if ordinary && target_path == "/" {
        return Err(VfsError::ResourceBusy);
    }
    let mut record = Some(MountRecord {
        source: source.to_string(),
        target: target_path.clone(),
        fs_type: fs_type.to_string(),
        options: match (readonly, bind) {
            (true, true) => "ro,bind,relatime",
            (false, true) => "rw,bind,relatime",
            (true, false) => "ro,relatime",
            (false, false) => "rw,relatime",
        }
        .to_string(),
        mountpoint: None,
    });

    let mut mountpoints = MOUNTED_MOUNTPOINTS.lock();
    let mut records = MOUNT_RECORDS.lock();
    mountpoints.try_reserve(1).map_err(|_| VfsError::NoMemory)?;
    records.try_reserve(1).map_err(|_| VfsError::NoMemory)?;
    let commit = |mountpoint: &Arc<Mountpoint>| {
        // Recheck after probing: another mount may have won the target while
        // the probe was doing I/O. A pathname conflict also rejects stacking
        // through an already-resolved mount root in the ordinary workflow.
        if ordinary
            && (mountpoints.iter().any(|(path, _)| path == &target_path)
                || records.iter().any(|entry| entry.target == target_path))
        {
            return Err(VfsError::ResourceBusy);
        }
        #[cfg(test)]
        check_record_update()?;
        mountpoint.set_readonly(readonly);
        mountpoint.set_flags(flags);
        // Borrow the prepared storage until commit succeeds so a rejection
        // does not free its strings inside the topology critical section.
        let mut record = record.take().unwrap();
        record.mountpoint = Some(mountpoint.clone());
        records.push(record);
        mountpoints.push((core::mem::take(&mut target_path), mountpoint.clone()));
        Ok(())
    };
    let expected_path = Some(expected_path.as_str());
    match mount_source {
        MountSource::Filesystem(fs) => target.mount_with(fs, expected_path, commit),
        MountSource::Bind(source) => target.mount_bind_with(source, expected_path, commit),
        MountSource::Shadow(source, propagation) => {
            target.mount_shadow_with(source, propagation, expected_path, commit)
        }
    }
}

/// Bind a source and clone its reachable mount subtree, then propagate to the
/// destination's peers and slaves. Read-only inheritance and request flags are
/// installed before publication; each child shadow inherits its own template.
/// Stacked binds keep distinct records even when they share a pathname.
pub fn mount_bind(
    target: &Location,
    source: Location,
    source_name: &str,
    flags: usize,
) -> VfsResult<Arc<Mountpoint>> {
    let readonly = flags & 1 != 0 || source.mountpoint().is_readonly();
    let mountpoint = publish_mount(
        target,
        MountSource::Bind(source.clone()),
        source_name,
        "none",
        readonly,
        flags,
        true,
    )?;
    let mut shadows = Vec::new();
    axfs_ng_vfs::propagate_subtree_with(
        source.mountpoint(),
        &mountpoint,
        &mut shadows,
        &mut publish_shadow,
    );
    propagate_mount(&mountpoint);
    Ok(mountpoint)
}

fn publish_shadow(
    target: &Location,
    source: Location,
    template: &Arc<Mountpoint>,
    propagation: PropagationMode,
) -> VfsResult<Arc<Mountpoint>> {
    let record = MOUNT_RECORDS
        .lock()
        .iter()
        .rfind(|record| {
            record
                .mountpoint
                .as_ref()
                .is_some_and(|mp| Arc::ptr_eq(mp, template))
        })
        .cloned()
        .ok_or(VfsError::InvalidInput)?;
    publish_mount(
        target,
        MountSource::Shadow(source, propagation),
        &record.source,
        &record.fs_type,
        template.is_readonly(),
        template.get_flags(),
        record.options.split(',').any(|option| option == "bind"),
    )
}

/// Propagate an already registered mount (including an MS_MOVE destination).
/// Selection retains VFS's best-effort semantics: an unavailable destination
/// or rejected shadow update is skipped. Every successful shadow has both
/// topology and records; a rejected one has neither. The whole fan-out is not
/// an atomic transaction, and a failed shadow does not undo the primary.
pub fn propagate_mount(mountpoint: &Arc<Mountpoint>) {
    if let Some(location) = mountpoint.location() {
        axfs_ng_vfs::propagate_new_mount_with(
            location.mountpoint(),
            Location::pub_entry_key(location.entry()),
            None,
            mountpoint,
            &mut publish_shadow,
        );
    }
}

/// Detach one mount and remove every index/listing entry owned by that exact
/// mountpoint. A busy mount or rejected record update preserves both registries
/// and the original VFS attachment, including its mount identity.
///
/// The caller must drain filesystem writeback before this synchronous topology
/// operation when unmounting a real filesystem. No I/O runs under these locks.
/// Propagation selection remains a separate workflow; each selected peer or
/// slave detach uses this same entry point.
pub fn unmount_filesystem(target: &Location) -> VfsResult<()> {
    unmount(target, false)
}

/// Lazily detach a mount and its complete subtree. The topology callback
/// supplies the actual detached identities, so concurrently attached children
/// cannot leave shadow records behind. Rejection restores the entire subtree.
pub fn unmount_subtree(target: &Location) -> VfsResult<()> {
    unmount(target, true)
}

fn unmount(target: &Location, subtree: bool) -> VfsResult<()> {
    if !target.is_root_of_mount() {
        return Err(VfsError::InvalidInput);
    }
    let mountpoint = target.mountpoint();
    if mountpoint.is_root() {
        return Err(VfsError::ResourceBusy);
    }
    let mut mountpoints = MOUNTED_MOUNTPOINTS.lock();
    let mut records = MOUNT_RECORDS.lock();
    let mut removed_mountpoints = Vec::new();
    let mut removed_records = Vec::new();
    // The actual lazy subtree is selected under the topology writer. Reserve
    // enough for all registry entries so the callback never needs to allocate.
    removed_mountpoints
        .try_reserve(mountpoints.len())
        .map_err(|_| VfsError::NoMemory)?;
    removed_records
        .try_reserve(records.len())
        .map_err(|_| VfsError::NoMemory)?;
    let commit = |detached: &[Arc<Mountpoint>]| {
        if !mountpoints
            .iter()
            .any(|(_, mp)| Arc::ptr_eq(mp, mountpoint))
            || !records.iter().any(|record| {
                record
                    .mountpoint
                    .as_ref()
                    .is_some_and(|mp| Arc::ptr_eq(mp, mountpoint))
            })
        {
            return Err(VfsError::InvalidInput);
        }
        #[cfg(test)]
        check_record_update()?;
        let is_detached =
            |mp: &Arc<Mountpoint>| detached.iter().any(|other| Arc::ptr_eq(mp, other));
        // Retain removed objects until after the topology and registry locks
        // are released: final Arc/string drops can enter other locks.
        for index in (0..mountpoints.len()).rev() {
            if is_detached(&mountpoints[index].1) {
                removed_mountpoints.push(mountpoints.remove(index));
            }
        }
        for index in (0..records.len()).rev() {
            if records[index].mountpoint.as_ref().is_some_and(is_detached) {
                removed_records.push(records.remove(index));
            }
        }
        Ok(())
    };
    let result = if subtree {
        target.unmount_all_with(commit)
    } else {
        let mut commit = commit;
        target.unmount_with(|| commit(core::slice::from_ref(mountpoint)))
    };
    drop(records);
    drop(mountpoints);
    drop((removed_records, removed_mountpoints));
    result
}

pub(crate) fn mounted_mountpoints() -> Vec<Arc<Mountpoint>> {
    MOUNTED_MOUNTPOINTS
        .lock()
        .iter()
        .map(|(_, mp)| mp.clone())
        .collect()
}

fn normalize_target(target: &str) -> String {
    if target.is_empty() || target == "/" {
        "/".to_string()
    } else if target.starts_with('/') {
        target.to_string()
    } else {
        format!("/{}", target)
    }
}

pub(crate) fn reset_mount_records() {
    MOUNT_RECORDS.lock().clear();
}

pub(crate) fn reset_mounted_mountpoints() {
    let cleared = {
        let mut guard = MOUNTED_MOUNTPOINTS.lock();
        core::mem::take(&mut *guard)
    };
    drop(cleared);
}

pub fn register_mount(source: &str, target: &str, fs_type: &str, options: &str) {
    register_mount_record(source, target, fs_type, options, None);
}

fn register_mount_record(
    source: &str,
    target: &str,
    fs_type: &str,
    options: &str,
    mountpoint: Option<Arc<axfs_ng_vfs::Mountpoint>>,
) {
    let target = normalize_target(target);
    let mut mounts = MOUNT_RECORDS.lock();
    mounts.push(MountRecord {
        source: source.to_string(),
        target,
        fs_type: fs_type.to_string(),
        options: options.to_string(),
        mountpoint,
    });
}

/// Register a mount record owned by a concrete VFS mountpoint.
///
/// Remounts update the existing record for that mountpoint. This keeps the
/// mount-record stack aligned with the VFS mount stack while still allowing
/// legitimate stacked mounts at the same pathname.
pub fn register_mount_for_mountpoint(
    source: &str,
    target: &str,
    fs_type: &str,
    options: &str,
    mountpoint: Arc<axfs_ng_vfs::Mountpoint>,
) {
    let target = normalize_target(target);
    let mut mounts = MOUNT_RECORDS.lock();
    if let Some(record) = mounts.iter_mut().rfind(|record| {
        record.target == target
            && record
                .mountpoint
                .as_ref()
                .is_some_and(|existing| Arc::ptr_eq(existing, &mountpoint))
    }) {
        record.source = source.to_string();
        record.fs_type = fs_type.to_string();
        record.options = options.to_string();
        return;
    }
    mounts.push(MountRecord {
        source: source.to_string(),
        target,
        fs_type: fs_type.to_string(),
        options: options.to_string(),
        mountpoint: Some(mountpoint),
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

/// Returns whether this mountpoint was created as a bind mount.
pub fn mountpoint_is_bind(mountpoint: &Arc<axfs_ng_vfs::Mountpoint>) -> bool {
    MOUNT_RECORDS.lock().iter().any(|record| {
        record
            .mountpoint
            .as_ref()
            .is_some_and(|existing| Arc::ptr_eq(existing, mountpoint))
            && record.options.split(',').any(|option| option == "bind")
    })
}

pub fn register_mounted_mountpoint(target: &str, mountpoint: Arc<axfs_ng_vfs::Mountpoint>) {
    let target = normalize_target(target);
    let mut mps = MOUNTED_MOUNTPOINTS.lock();
    if mps.iter().any(|(existing_target, existing)| {
        existing_target == &target && Arc::ptr_eq(existing, &mountpoint)
    }) {
        return;
    }
    mps.push((target, mountpoint));
}

pub fn lookup_mounted_mountpoint(target: &str) -> Option<Arc<axfs_ng_vfs::Mountpoint>> {
    let target = normalize_target(target);
    MOUNTED_MOUNTPOINTS
        .lock()
        .iter()
        .rfind(|(t, _)| t == &target)
        .map(|(_, m)| m.clone())
}

pub fn unregister_mounted_mountpoint(target: &str) -> bool {
    let target = normalize_target(target);
    let mut mps = MOUNTED_MOUNTPOINTS.lock();
    if let Some(index) = mps.iter().rposition(|(t, _)| t == &target) {
        let removed = mps.remove(index);
        drop(mps);
        drop(removed);
        true
    } else {
        false
    }
}

/// Remove the registry entry for the exact VFS mountpoint that was unmounted.
///
/// A propagated bind mount can share its pathname with another stacked mount.
/// Removing by pathname alone can therefore pop the wrong registry entry and
/// leave `/proc/mounts` pointing at a mount that no longer exists.
pub fn unregister_mounted_mountpoint_exact(
    target: &str,
    mountpoint: &Arc<axfs_ng_vfs::Mountpoint>,
) -> bool {
    let target = normalize_target(target);
    let mut mps = MOUNTED_MOUNTPOINTS.lock();
    let removed_mountpoint = if let Some(index) = mps
        .iter()
        .rposition(|(t, mp)| t == &target && Arc::ptr_eq(mp, mountpoint))
    {
        mps.remove(index);
        true
    } else {
        false
    };
    drop(mps);

    let mut mounts = MOUNT_RECORDS.lock();
    let removed_record = if let Some(index) = mounts.iter().rposition(|record| {
        record.target == target
            && record
                .mountpoint
                .as_ref()
                .is_some_and(|existing| Arc::ptr_eq(existing, mountpoint))
    }) {
        mounts.remove(index);
        true
    } else {
        false
    };

    removed_mountpoint || removed_record
}

/// Remove every bookkeeping entry owned by a VFS mountpoint.
///
/// A propagated bind mount can be registered under more than one visible
/// path, and a lazy unmount removes a whole subtree at once.  Cleaning by one
/// `(path, Arc)` pair leaves stale `/proc/mounts` rows in either case; the LTP
/// cleanup loop then keeps retrying those rows forever.  The vectors are
/// detached before filtering so dropping mount records never happens while a
/// registry spin lock is held.
pub fn unregister_mountpoint_records(mountpoint: &Arc<axfs_ng_vfs::Mountpoint>) -> usize {
    let mut removed_mps = Vec::new();
    {
        let mut guard = MOUNTED_MOUNTPOINTS.lock();
        let entries = core::mem::take(&mut *guard);
        let mut kept = Vec::with_capacity(entries.len());
        for entry in entries {
            if Arc::ptr_eq(&entry.1, mountpoint) {
                removed_mps.push(entry);
            } else {
                kept.push(entry);
            }
        }
        *guard = kept;
    }

    let mut removed_records = Vec::new();
    {
        let mut guard = MOUNT_RECORDS.lock();
        let records = core::mem::take(&mut *guard);
        let mut kept = Vec::with_capacity(records.len());
        for record in records {
            let owned = record
                .mountpoint
                .as_ref()
                .is_some_and(|existing| Arc::ptr_eq(existing, mountpoint));
            if owned {
                removed_records.push(record);
            } else {
                kept.push(record);
            }
        }
        *guard = kept;
    }

    let removed = removed_mps.len() + removed_records.len();
    drop(removed_mps);
    drop(removed_records);
    removed
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
            } else if record.target.starts_with(&old_prefix)
                && record.target[old_prefix.len()..].starts_with('/')
            {
                record.target.replace_range(..old_prefix.len(), &new_prefix);
            }
        }
    }

    // 2. Update MOUNTED_MOUNTPOINTS
    {
        let mut mps = MOUNTED_MOUNTPOINTS.lock();
        for (target, _mp) in mps.iter_mut() {
            if target == &old_prefix {
                *target = new_prefix.clone();
            } else if target.starts_with(&old_prefix) && target[old_prefix.len()..].starts_with('/')
            {
                target.replace_range(..old_prefix.len(), &new_prefix);
            }
        }
    }
}
