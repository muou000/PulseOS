//! Mount records and mount/unmount coordination.
//!
//! Callers use `mount_filesystem`, `mount_bind`, `move_filesystem`, and
//! `unmount_filesystem` (or `unmount_subtree` for lazy detach). Each primary and
//! propagated shadow uses the same publication workflow. Individual registry
//! helpers remain only for boot and remount.
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

use vfs::{Filesystem, Location, Mountpoint, PropagationMode, VfsError, VfsResult};
use kspin::SpinNoPreempt;
use spin::Lazy;

#[derive(Clone, Debug)]
pub struct MountRecord {
    pub source: String,
    pub target: String,
    pub fs_type: String,
    pub options: String,
    mountpoint: Option<Arc<vfs::Mountpoint>>,
}

static MOUNT_RECORDS: Lazy<SpinNoPreempt<Vec<MountRecord>>> =
    Lazy::new(|| SpinNoPreempt::new(Vec::new()));

static MOUNTED_MOUNTPOINTS: Lazy<SpinNoPreempt<Vec<(String, Arc<vfs::Mountpoint>)>>> =
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
    vfs::propagate_subtree_with(
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
        // A shadow aliases its template's filesystem even when that template
        // is an ordinary mount. Preserve bind identity for remount/unmount.
        true,
    )
}

/// Propagate an already registered mount (including an MS_MOVE destination).
/// Selection retains VFS's best-effort semantics: an unavailable destination
/// or rejected shadow update is skipped. Every successful shadow has both
/// topology and records; a rejected one has neither. The whole fan-out is not
/// an atomic transaction, and a failed shadow does not undo the primary.
pub(crate) fn propagate_mount(mountpoint: &Arc<Mountpoint>) {
    if let Some(location) = mountpoint.location() {
        vfs::propagate_new_mount_with(
            location.mountpoint(),
            Location::pub_entry_key(location.entry()),
            None,
            mountpoint,
            &mut publish_shadow,
        );
    }
}

/// Move a mount and its subtree, updating only records owned by the moved
/// identities. Covered mounts at the old pathname retain their records.
/// Rejection preserves both paths and mount identity; propagation begins only
/// after the primary topology and both registries have committed.
pub fn move_filesystem(source: &Location, target: &Location) -> VfsResult<Arc<Mountpoint>> {
    if !source.is_root_of_mount() {
        return Err(VfsError::InvalidInput);
    }
    target.check_is_dir()?;
    let mut mountpoints = MOUNTED_MOUNTPOINTS.lock();
    let mut records = MOUNT_RECORDS.lock();
    let old_path = source.absolute_path()?;
    let new_path = target.absolute_path()?;
    let moving = source.mountpoint().collect_subtree();
    let owns = |mp: &Arc<Mountpoint>| moving.iter().any(|other| Arc::ptr_eq(mp, other));
    if !mountpoints
        .iter()
        .any(|(_, mp)| Arc::ptr_eq(mp, source.mountpoint()))
        || !records.iter().any(|row| {
            row.mountpoint
                .as_ref()
                .is_some_and(|mp| Arc::ptr_eq(mp, source.mountpoint()))
        })
    {
        return Err(VfsError::InvalidInput);
    }
    // Prepare strings before the topology transition, selecting by identity
    // first: pathname prefixes alone also match covered mounts in a stack.
    let rewrite = |path: &str| -> VfsResult<String> {
        let suffix = path
            .strip_prefix(old_path.as_str())
            .ok_or(VfsError::InvalidInput)?;
        if !suffix.is_empty() && !suffix.starts_with('/') {
            return Err(VfsError::InvalidInput);
        }
        Ok(format!("{}{suffix}", new_path.as_str()))
    };
    let mut index_paths = Vec::new();
    let mut record_paths = Vec::new();
    index_paths
        .try_reserve(mountpoints.len())
        .map_err(|_| VfsError::NoMemory)?;
    record_paths
        .try_reserve(records.len())
        .map_err(|_| VfsError::NoMemory)?;
    for (index, (path, mp)) in mountpoints.iter().enumerate() {
        if owns(mp) {
            index_paths.push((index, rewrite(path)?));
        }
    }
    for (index, row) in records.iter().enumerate() {
        if row.mountpoint.as_ref().is_some_and(owns) {
            record_paths.push((index, rewrite(&row.target)?));
        }
    }
    let result = source.move_mount_with(
        target,
        Some((old_path.as_str(), new_path.as_str())),
        |moved| {
            // A raw VFS mutation between preparation and publication must not
            // commit an incomplete set of registry updates.
            if moved.len() != moving.len() || !moved.iter().all(owns) {
                return Err(VfsError::ResourceBusy);
            }
            #[cfg(test)]
            check_record_update()?;
            for (index, path) in &mut index_paths {
                core::mem::swap(&mut mountpoints[*index].0, path);
            }
            for (index, path) in &mut record_paths {
                core::mem::swap(&mut records[*index].target, path);
            }
            Ok(())
        },
    );
    drop(records);
    drop(mountpoints);
    drop((index_paths, record_paths));
    let mountpoint = result?;
    propagate_mount(&mountpoint);
    Ok(mountpoint)
}

/// Detach one mount and remove every index/listing entry owned by that exact
/// mountpoint. A busy mount or rejected record update preserves both registries
/// and the original VFS attachment, including its mount identity.
///
/// The caller must drain filesystem writeback before this synchronous topology
/// operation when unmounting a real filesystem. No I/O runs under these locks.
/// Peer and slave selection happens before detachment; after the primary
/// succeeds, each selected shadow is detached through the same transaction.
/// Propagation is best effort: a busy shadow retains both topology and records.
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
    let peers = vfs::collect_propagate_unmount(target.mountpoint());
    // A rejected primary must not remove its propagated peers. Keep the
    // selection alive across primary detachment, which removes peer links.
    unmount_one(target, subtree)?;
    for peer in peers {
        if let Err(error) = unmount_one(&peer.root_location(), subtree) {
            log::warn!("failed to unmount propagated mount: {:?}", error);
        }
    }
    Ok(())
}

fn unmount_one(target: &Location, subtree: bool) -> VfsResult<()> {
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

pub(crate) fn register_mount(source: &str, target: &str, fs_type: &str, options: &str) {
    register_mount_record(source, target, fs_type, options, None);
}

fn register_mount_record(
    source: &str,
    target: &str,
    fs_type: &str,
    options: &str,
    mountpoint: Option<Arc<vfs::Mountpoint>>,
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
    mountpoint: Arc<vfs::Mountpoint>,
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

pub fn list_mounts() -> Vec<MountRecord> {
    MOUNT_RECORDS.lock().clone()
}

/// Returns whether this mountpoint was created as a bind mount.
pub fn mountpoint_is_bind(mountpoint: &Arc<vfs::Mountpoint>) -> bool {
    MOUNT_RECORDS.lock().iter().any(|record| {
        record
            .mountpoint
            .as_ref()
            .is_some_and(|existing| Arc::ptr_eq(existing, mountpoint))
            && record.options.split(',').any(|option| option == "bind")
    })
}

pub(crate) fn register_mounted_mountpoint(target: &str, mountpoint: Arc<vfs::Mountpoint>) {
    let target = normalize_target(target);
    let mut mps = MOUNTED_MOUNTPOINTS.lock();
    if mps.iter().any(|(existing_target, existing)| {
        existing_target == &target && Arc::ptr_eq(existing, &mountpoint)
    }) {
        return;
    }
    mps.push((target, mountpoint));
}

pub fn lookup_mounted_mountpoint(target: &str) -> Option<Arc<vfs::Mountpoint>> {
    let target = normalize_target(target);
    MOUNTED_MOUNTPOINTS
        .lock()
        .iter()
        .rfind(|(t, _)| t == &target)
        .map(|(_, m)| m.clone())
}
