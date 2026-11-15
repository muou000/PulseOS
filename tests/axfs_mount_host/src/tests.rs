use std::sync::{Arc, Mutex};

use axfs_ng_vfs::Mountpoint;

use crate::{
    fixture::{MemFs, block_on, mkdir},
    mounts::*,
};

// The production registry is global; each test owns it for its whole workflow.
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn mount_and_unmount_keep_listing_and_resolution_in_agreement() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "success");
    let mounted =
        mount_filesystem(&target, "none", "tmpfs", 1, || Ok(MemFs::create("tmpfs"))).unwrap();

    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].target, "/success");
    assert_eq!(rows[0].source, "none");
    assert_eq!(rows[0].fs_type, "tmpfs");
    assert_eq!(rows[0].options, "ro,relatime");
    let resolved = block_on(root.lookup_no_follow("success")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &mounted));
    assert_eq!(resolved.filesystem().name(), "tmpfs");
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/success").unwrap(),
        &mounted
    ));

    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
    assert!(lookup_mounted_mountpoint("/success").is_none());
    let resolved = block_on(root.lookup_no_follow("success")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), root.mountpoint()));
    assert_eq!(resolved.filesystem().name(), "root");
}

#[test]
fn duplicate_target_preserves_the_existing_mount() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "duplicate");
    let mounted =
        mount_filesystem(&target, "first", "tmpfs", 0, || Ok(MemFs::create("first"))).unwrap();
    for location in [&target, &mounted.root_location()] {
        assert_eq!(
            mount_filesystem(location, "second", "tmpfs", 0, || {
                panic!("an already registered duplicate must fail before probing")
            })
            .unwrap_err(),
            axfs_ng_vfs::VfsError::ResourceBusy,
        );
    }
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source, "first");
    assert_eq!(rows[0].options, "rw,relatime");
    let resolved = block_on(root.lookup_no_follow("duplicate")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &mounted));
    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn failed_probe_publishes_no_mount_or_record() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "probe_failure");
    assert_eq!(
        mount_filesystem(&target, "/dev/bad", "ext4", 0, || {
            // Probing may query registries: the coordinator must not hold them.
            assert!(list_mounts().is_empty());
            Err(axfs_ng_vfs::VfsError::Io)
        })
        .unwrap_err(),
        axfs_ng_vfs::VfsError::Io,
    );
    assert!(list_mounts().is_empty());
    assert!(lookup_mounted_mountpoint("/probe_failure").is_none());
    let resolved = block_on(root.lookup_no_follow("probe_failure")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), root.mountpoint()));
}

#[test]
fn rejected_mount_record_update_restores_the_underlying_directory() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "mount_rollback");
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        mount_filesystem(&target, "none", "tmpfs", 0, || {
            Ok(MemFs::create("rejected"))
        })
        .unwrap_err(),
        axfs_ng_vfs::VfsError::NoMemory,
    );
    assert!(list_mounts().is_empty());
    assert!(lookup_mounted_mountpoint("/mount_rollback").is_none());
    let resolved = block_on(root.lookup_no_follow("mount_rollback")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), root.mountpoint()));
    assert!(!target.is_mountpoint());

    let retry =
        mount_filesystem(&target, "retry", "tmpfs", 0, || Ok(MemFs::create("retry"))).unwrap();
    assert_eq!(list_mounts().len(), 1);
    unmount_filesystem(&retry.root_location()).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn rejected_unmount_record_update_restores_the_same_mount_identity() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "unmount_rollback");
    let mounted = mount_filesystem(&target, "original", "tmpfs", 0, || {
        Ok(MemFs::create("original"))
    })
    .unwrap();
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        unmount_filesystem(&mounted.root_location()),
        Err(axfs_ng_vfs::VfsError::NoMemory),
    );
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source, "original");
    let resolved = block_on(root.lookup_no_follow("unmount_rollback")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &mounted));
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/unmount_rollback").unwrap(),
        &mounted
    ));

    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
    assert!(lookup_mounted_mountpoint("/unmount_rollback").is_none());
    let resolved = block_on(root.lookup_no_follow("unmount_rollback")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), root.mountpoint()));
}

#[test]
fn busy_parent_unmount_preserves_parent_and_child_records() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "busy");
    let parent = mount_filesystem(&target, "parent", "tmpfs", 0, || {
        Ok(MemFs::create("parent"))
    })
    .unwrap();
    let child_target = mkdir(&parent.root_location(), "child");
    let child = mount_filesystem(&child_target, "child", "tmpfs", 0, || {
        Ok(MemFs::create("child"))
    })
    .unwrap();
    assert_eq!(
        unmount_filesystem(&parent.root_location()),
        Err(axfs_ng_vfs::VfsError::ResourceBusy),
    );
    let rows = list_mounts();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().any(|row| row.target == "/busy"));
    assert!(rows.iter().any(|row| row.target == "/busy/child"));
    let resolved = block_on(root.lookup_no_follow("busy")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &parent));
    let resolved_child = block_on(resolved.lookup_no_follow("child")).unwrap();
    assert!(Arc::ptr_eq(resolved_child.mountpoint(), &child));
    unmount_filesystem(&resolved_child).unwrap();
    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn record_conflict_created_during_probe_rolls_back_the_new_attachment() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "late_conflict");
    assert_eq!(
        mount_filesystem(&target, "candidate", "tmpfs", 0, || {
            // Simulate a legacy bookkeeping writer winning during device I/O.
            register_mount("existing", "/late_conflict", "tmpfs", "rw,relatime");
            Ok(MemFs::create("candidate"))
        })
        .unwrap_err(),
        axfs_ng_vfs::VfsError::ResourceBusy,
    );
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source, "existing");
    assert!(lookup_mounted_mountpoint("/late_conflict").is_none());
    let resolved = block_on(root.lookup_no_follow("late_conflict")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), root.mountpoint()));
    assert!(!target.is_mountpoint());
    assert!(unregister_mount("/late_conflict"));
    assert!(list_mounts().is_empty());
}

#[test]
fn stale_unmount_cannot_remove_a_replacement_at_the_same_path() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "replacement");
    let old = mount_filesystem(&target, "old", "tmpfs", 0, || Ok(MemFs::create("old"))).unwrap();
    unmount_filesystem(&old.root_location()).unwrap();
    let replacement =
        mount_filesystem(&target, "new", "tmpfs", 0, || Ok(MemFs::create("new"))).unwrap();
    assert_eq!(
        unmount_filesystem(&old.root_location()),
        Err(axfs_ng_vfs::VfsError::InvalidInput),
    );
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source, "new");
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/replacement").unwrap(),
        &replacement
    ));
    let resolved = block_on(root.lookup_no_follow("replacement")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &replacement));
    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn competing_probes_publish_exactly_one_mount_and_record() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "race");
    let probes_ready = Arc::new(std::sync::Barrier::new(2));
    let workers: Vec<_> = ["first", "second"]
        .into_iter()
        .map(|name| {
            let target = target.clone();
            let probes_ready = probes_ready.clone();
            std::thread::spawn(move || {
                mount_filesystem(&target, name, "tmpfs", 0, || {
                    // Both callers passed preflight before either may commit.
                    probes_ready.wait();
                    Ok(MemFs::create(name))
                })
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(axfs_ng_vfs::VfsError::ResourceBusy)))
            .count(),
        1
    );
    let winner = results.into_iter().find_map(Result::ok).unwrap();
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    let resolved = block_on(root.lookup_no_follow("race")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &winner));
    assert_eq!(rows[0].source, resolved.filesystem().name());
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/race").unwrap(),
        &winner
    ));
    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn unmounting_a_legacy_stacked_mount_preserves_the_lower_record() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "stack");
    let lower =
        mount_filesystem(&target, "lower", "tmpfs", 0, || Ok(MemFs::create("lower"))).unwrap();
    // Existing bind/move workflows retain their lower-level registration API.
    let source = Mountpoint::new_root(&MemFs::create("upper"));
    let upper = lower
        .root_location()
        .mount_bind(source.root_location())
        .unwrap();
    register_mounted_mountpoint("/stack", upper.clone());
    register_mount_for_mountpoint("upper", "/stack", "tmpfs", "rw,bind", upper.clone());
    assert_eq!(list_mounts().len(), 2);
    let resolved = block_on(root.lookup_no_follow("stack")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &upper));
    unmount_filesystem(&resolved).unwrap();
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source, "lower");
    let resolved = block_on(root.lookup_no_follow("stack")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &lower));
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/stack").unwrap(),
        &lower
    ));
    unmount_filesystem(&resolved).unwrap();
    assert!(list_mounts().is_empty());
}
