use std::sync::{Arc, Mutex};

use vfs::Mountpoint;

use crate::{
    fixture::{MemFs, block_on, mkdir},
    mounts::*,
};

// The production registry is global; each test owns it for its whole workflow.
static TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn rejected_move_preserves_subtree_records_and_retry_moves_each_once() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let old_target = mkdir(&root, "old");
    let destination = mkdir(&root, "new");
    let parent = mount_filesystem(&old_target, "parent", "tmpfs", 0, || {
        Ok(MemFs::create("parent"))
    })
    .unwrap();
    let child = mount_filesystem(
        &mkdir(&parent.root_location(), "child"),
        "child",
        "tmpfs",
        1,
        || Ok(MemFs::create("child")),
    )
    .unwrap();
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        move_filesystem(&parent.root_location(), &destination).unwrap_err(),
        vfs::VfsError::NoMemory
    );
    assert_eq!(list_mounts().len(), 2);
    for (path, mp) in [("/old", &parent), ("/old/child", &child)] {
        assert_eq!(
            list_mounts()
                .iter()
                .filter(|row| row.target == path)
                .count(),
            1
        );
        assert!(Arc::ptr_eq(&lookup_mounted_mountpoint(path).unwrap(), mp));
        assert_eq!(mp.root_location().absolute_path().unwrap().as_str(), path);
    }
    assert!(lookup_mounted_mountpoint("/new").is_none());
    assert!(!destination.is_mountpoint());
    move_filesystem(&parent.root_location(), &destination).unwrap();
    assert_eq!(list_mounts().len(), 2);
    for (path, mp) in [("/new", &parent), ("/new/child", &child)] {
        assert_eq!(
            list_mounts()
                .iter()
                .filter(|row| row.target == path)
                .count(),
            1
        );
        assert!(Arc::ptr_eq(&lookup_mounted_mountpoint(path).unwrap(), mp));
        assert_eq!(mp.root_location().absolute_path().unwrap().as_str(), path);
    }
    assert!(lookup_mounted_mountpoint("/old").is_none());
    assert!(lookup_mounted_mountpoint("/old/child").is_none());
    assert!(!old_target.is_mountpoint());
    assert!(child.is_readonly());
    assert_eq!(child.get_flags(), 1);
    unmount_subtree(&parent.root_location()).unwrap();
    let replacement = mount_filesystem(&destination, "replacement", "tmpfs", 0, || {
        Ok(MemFs::create("replacement"))
    })
    .unwrap();
    assert_eq!(
        unmount_subtree(&parent.root_location()),
        Err(vfs::VfsError::InvalidInput)
    );
    assert_eq!(
        unmount_subtree(&child.root_location()),
        Err(vfs::VfsError::InvalidInput)
    );
    assert_eq!(
        move_filesystem(&parent.root_location(), &old_target).unwrap_err(),
        vfs::VfsError::InvalidInput
    );
    assert_eq!(list_mounts().len(), 1);
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/new").unwrap(),
        &replacement
    ));
    unmount_filesystem(&replacement.root_location()).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn rejected_move_shadow_update_leaves_no_ghost_and_retry_can_publish() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let primary = mount_filesystem(&mkdir(&root, "primary"), "base", "tmpfs", 0, || {
        Ok(MemFs::create("base"))
    })
    .unwrap();
    primary.make_shared();
    let peer = mount_bind(
        &mkdir(&root, "peer"),
        primary.root_location(),
        "/primary",
        4096,
    )
    .unwrap();
    let moving = mount_filesystem(&mkdir(&root, "moving"), "moving", "tmpfs", 1, || {
        Ok(MemFs::create("moving"))
    })
    .unwrap();
    let destination = mkdir(&primary.root_location(), "child");
    // First publish under a private destination, then exercise a rejected
    // propagated shadow and retry using the coordinator's own propagation.
    primary.make_private();
    move_filesystem(&moving.root_location(), &destination).unwrap();
    primary.change_propagation(peer.propagation());
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    propagate_mount(&moving);
    assert!(lookup_mounted_mountpoint("/peer/child").is_none());
    assert_eq!(list_mounts().len(), 3);
    let unchanged = block_on(peer.root_location().lookup_no_follow("child")).unwrap();
    assert!(Arc::ptr_eq(unchanged.mountpoint(), &peer));
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/primary/child").unwrap(),
        &moving
    ));
    propagate_mount(&moving);
    let shadow = block_on(peer.root_location().lookup_no_follow("child")).unwrap();
    assert_eq!(shadow.filesystem().name(), "moving");
    assert!(shadow.mountpoint().is_readonly());
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/peer/child").unwrap(),
        shadow.mountpoint()
    ));
    assert_eq!(list_mounts().len(), 4);
    unmount_filesystem(&moving.root_location()).unwrap();
    unmount_filesystem(&peer.root_location()).unwrap();
    unmount_filesystem(&primary.root_location()).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn rejected_bind_update_leaves_no_mount_and_retry_inherits_readonly() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let source = mount_filesystem(&mkdir(&root, "source"), "source", "tmpfs", 1, || {
        Ok(MemFs::create("source"))
    })
    .unwrap();
    let target = mkdir(&root, "bind");
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        mount_bind(&target, source.root_location(), "/source", 4096).unwrap_err(),
        vfs::VfsError::NoMemory
    );
    assert!(!target.is_mountpoint());
    assert!(lookup_mounted_mountpoint("/bind").is_none());
    assert_eq!(list_mounts().len(), 1);
    let bound = mount_bind(&target, source.root_location(), "/source", 4096).unwrap();
    assert!(bound.is_readonly());
    assert_eq!(bound.get_flags(), 4096);
    assert!(mountpoint_is_bind(&bound));
    assert_eq!(
        list_mounts()
            .iter()
            .find(|row| row.target == "/bind")
            .unwrap()
            .options,
        "ro,bind,relatime"
    );
    let resolved = block_on(root.lookup_no_follow("bind")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &bound));
    unmount_filesystem(&resolved).unwrap();
    unmount_filesystem(&source.root_location()).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn lazy_bind_subtree_rejection_restores_shadows_and_retry_cleans_records() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let source = mount_filesystem(&mkdir(&root, "source"), "source", "tmpfs", 0, || {
        Ok(MemFs::create("source"))
    })
    .unwrap();
    let child = mount_filesystem(
        &mkdir(&source.root_location(), "nested"),
        "nested",
        "tmpfs",
        1,
        || Ok(MemFs::create("nested")),
    )
    .unwrap();
    let bound = mount_bind(
        &mkdir(&root, "bind"),
        source.root_location(),
        "/source",
        4096,
    )
    .unwrap();
    let shadow = block_on(bound.root_location().lookup_no_follow("nested")).unwrap();
    assert!(!Arc::ptr_eq(shadow.mountpoint(), &child));
    assert!(mountpoint_is_bind(shadow.mountpoint()));
    assert!(shadow.mountpoint().is_readonly());
    assert_eq!(shadow.mountpoint().get_flags(), 1);
    assert_eq!(list_mounts().len(), 4);
    assert_eq!(
        list_mounts()
            .iter()
            .find(|row| row.target == "/bind/nested")
            .unwrap()
            .options,
        "ro,bind,relatime"
    );
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        unmount_subtree(&bound.root_location()),
        Err(vfs::VfsError::NoMemory)
    );
    assert_eq!(list_mounts().len(), 4);
    let resolved = block_on(root.lookup_no_follow("bind")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), &bound));
    let restored = block_on(resolved.lookup_no_follow("nested")).unwrap();
    assert!(Arc::ptr_eq(restored.mountpoint(), shadow.mountpoint()));
    unmount_subtree(&resolved).unwrap();
    assert_eq!(list_mounts().len(), 2);
    assert!(lookup_mounted_mountpoint("/bind").is_none());
    assert!(lookup_mounted_mountpoint("/bind/nested").is_none());
    assert!(bound.location().is_none());
    assert!(shadow.mountpoint().location().is_none());
    unmount_subtree(&source.root_location()).unwrap();
    assert!(list_mounts().is_empty());
}

#[test]
fn ordinary_mount_publishes_peer_and_slave_shadow_records() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let primary = mount_filesystem(&mkdir(&root, "primary"), "base", "tmpfs", 0, || {
        Ok(MemFs::create("base"))
    })
    .unwrap();
    primary.make_shared();
    let peer = mount_bind(
        &mkdir(&root, "peer"),
        primary.root_location(),
        "/primary",
        4096,
    )
    .unwrap();
    let slave = mount_bind(
        &mkdir(&root, "slave"),
        primary.root_location(),
        "/primary",
        4096,
    )
    .unwrap();
    slave.make_slave();
    let child = mount_filesystem(
        &mkdir(&primary.root_location(), "child"),
        "child",
        "tmpfs",
        1,
        || Ok(MemFs::create("child")),
    )
    .unwrap();

    for (parent, path) in [(&peer, "/peer/child"), (&slave, "/slave/child")] {
        let resolved = block_on(parent.root_location().lookup_no_follow("child")).unwrap();
        assert_eq!(
            resolved.filesystem().name(),
            "child",
            "missing shadow at {path}"
        );
        assert!(resolved.mountpoint().is_readonly());
        assert_eq!(resolved.mountpoint().get_flags(), 1);
        assert!(Arc::ptr_eq(
            &lookup_mounted_mountpoint(path).unwrap(),
            resolved.mountpoint()
        ));
        let rows = list_mounts();
        let row = rows.iter().find(|row| row.target == path).unwrap();
        assert_eq!(row.source, "child");
        assert_eq!(row.fs_type, "tmpfs");
        assert_eq!(row.options, "ro,bind,relatime");
    }
    let peer_child = block_on(peer.root_location().lookup_no_follow("child")).unwrap();
    let slave_child = block_on(slave.root_location().lookup_no_follow("child")).unwrap();
    assert_eq!(
        peer_child.mountpoint().propagation().peer_group(),
        child.propagation().peer_group()
    );
    assert_eq!(
        slave_child.mountpoint().propagation().master_group(),
        child.propagation().peer_group()
    );
    FAIL_NEXT_RECORD_UPDATE.store(true, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        unmount_filesystem(&child.root_location()),
        Err(vfs::VfsError::NoMemory)
    );
    assert_eq!(list_mounts().len(), 6);
    for (path, mp) in [
        ("/primary/child", &child),
        ("/peer/child", peer_child.mountpoint()),
        ("/slave/child", slave_child.mountpoint()),
    ] {
        assert!(Arc::ptr_eq(&lookup_mounted_mountpoint(path).unwrap(), mp));
        assert_eq!(mp.root_location().absolute_path().unwrap().as_str(), path);
    }
    unmount_filesystem(&child.root_location()).unwrap();
    assert!(
        !list_mounts()
            .iter()
            .any(|row| row.target.ends_with("/child"))
    );
    for removed in [&child, peer_child.mountpoint(), slave_child.mountpoint()] {
        assert_eq!(
            unmount_filesystem(&removed.root_location()),
            Err(vfs::VfsError::InvalidInput)
        );
        assert_eq!(
            unmount_subtree(&removed.root_location()),
            Err(vfs::VfsError::InvalidInput)
        );
    }
    for mount in [slave, peer, primary] {
        unmount_filesystem(&mount.root_location()).unwrap();
    }
    assert!(list_mounts().is_empty());
}

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
            vfs::VfsError::ResourceBusy,
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
            Err(vfs::VfsError::Io)
        })
        .unwrap_err(),
        vfs::VfsError::Io,
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
        vfs::VfsError::NoMemory,
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
        Err(vfs::VfsError::NoMemory),
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
        Err(vfs::VfsError::ResourceBusy),
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
        vfs::VfsError::ResourceBusy,
    );
    let rows = list_mounts();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].source, "existing");
    assert!(lookup_mounted_mountpoint("/late_conflict").is_none());
    let resolved = block_on(root.lookup_no_follow("late_conflict")).unwrap();
    assert!(Arc::ptr_eq(resolved.mountpoint(), root.mountpoint()));
    assert!(!target.is_mountpoint());
    reset_mount_records();
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
        Err(vfs::VfsError::InvalidInput),
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
            .filter(|result| matches!(result, Err(vfs::VfsError::ResourceBusy)))
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
fn unmounting_a_stacked_bind_preserves_the_lower_record() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let target = mkdir(&root, "stack");
    let lower =
        mount_filesystem(&target, "lower", "tmpfs", 0, || Ok(MemFs::create("lower"))).unwrap();
    let source = Mountpoint::new_root(&MemFs::create("upper"));
    let upper = mount_bind(
        &lower.root_location(),
        source.root_location(),
        "upper",
        4096,
    )
    .unwrap();
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

#[test]
fn parent_moved_during_probe_records_the_current_mount_path() {
    let _serial = TEST_LOCK.lock().unwrap();
    let root = Mountpoint::new_root(&MemFs::create("root")).root_location();
    let old_target = mkdir(&root, "old");
    let new_target = mkdir(&root, "new");
    let parent = mount_filesystem(&old_target, "parent", "tmpfs", 0, || {
        Ok(MemFs::create("parent"))
    })
    .unwrap();
    let child_target = mkdir(&parent.root_location(), "child");
    let child = mount_filesystem(&child_target, "child", "tmpfs", 0, || {
        // Model another task's complete MS_MOVE while the probe waits for I/O.
        move_filesystem(&parent.root_location(), &new_target)?;
        Ok(MemFs::create("child"))
    })
    .unwrap();

    let rows = list_mounts();
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.iter()
            .find(|row| row.source == "child")
            .unwrap()
            .target,
        "/new/child"
    );
    assert!(lookup_mounted_mountpoint("/old/child").is_none());
    assert!(Arc::ptr_eq(
        &lookup_mounted_mountpoint("/new/child").unwrap(),
        &child
    ));
    let resolved_parent = block_on(root.lookup_no_follow("new")).unwrap();
    assert!(Arc::ptr_eq(resolved_parent.mountpoint(), &parent));
    let resolved_child = block_on(resolved_parent.lookup_no_follow("child")).unwrap();
    assert!(Arc::ptr_eq(resolved_child.mountpoint(), &child));
    assert_eq!(
        resolved_child.absolute_path().unwrap().as_str(),
        "/new/child"
    );
    unmount_filesystem(&resolved_child).unwrap();
    unmount_filesystem(&resolved_parent).unwrap();
    assert!(list_mounts().is_empty());
}
