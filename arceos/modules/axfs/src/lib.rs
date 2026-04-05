#![cfg_attr(all(not(test), not(doc)), no_std)]
#![feature(doc_cfg)]
#![allow(clippy::new_ret_no_self)]

extern crate alloc;

#[macro_use]
extern crate log;

use alloc::{format, string::String, vec::Vec};

use axdriver::{AxBlockDevice, AxDeviceContainer};
use axfs_ng_vfs::NodePermission;
pub use axfs_ng_vfs::NodeType;

#[cfg(feature = "fat")]
mod disk;
mod fs;

mod highlevel;
pub use highlevel::*;

pub fn init_filesystems(mut block_devs: AxDeviceContainer<AxBlockDevice>) {
    info!("Initialize filesystem subsystem...");

    struct FsCandidate {
        disk_idx: usize,
        dev_name: String,
        fs: axfs_ng_vfs::Filesystem,
        has_shell: bool,
    }

    let mut candidates: Vec<FsCandidate> = Vec::new();
    let mut disk_idx = 0usize;

    while let Some(dev) = block_devs.take_one() {
        let dev_name = format!("{:?}", dev.device_name());
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

        let probe_mp = axfs_ng_vfs::Mountpoint::new_root(&fs);
        let probe_cx = FsContext::new(probe_mp.root_location());
        let has_shell = probe_cx.metadata("/bin/sh").is_ok();

        info!(
            "  filesystem on device {}: {} (sh={})",
            disk_idx,
            fs.name(),
            has_shell,
        );

        candidates.push(FsCandidate {
            disk_idx,
            dev_name,
            fs,
            has_shell,
        });
        disk_idx += 1;
    }

    assert!(!candidates.is_empty(), "No usable filesystem found!");

    // Pick the most likely user rootfs first to avoid booting from test images.
    let root_pos = candidates
        .iter()
        .position(|c| c.has_shell)
        .unwrap_or(0);
    let root = candidates.swap_remove(root_pos);
    info!(
        "  select block device {} ({}) as root filesystem",
        root.disk_idx, root.dev_name
    );

    let root_mp = axfs_ng_vfs::Mountpoint::new_root(&root.fs);
    let cx = FsContext::new(root_mp.root_location());

    let mut fs_mount_idx = 1usize;
    for cand in candidates {
        let mount_path = if fs_mount_idx == 1 {
            format!("/fs")
        } else {
            format!("/fs{}", fs_mount_idx)
        };

        let mount_dir = match cx.resolve(&mount_path) {
            Ok(loc) => loc,
            Err(_) => match cx.create_dir(&mount_path, NodePermission::default()) {
                Ok(loc) => loc,
                Err(e) => {
                    warn!(
                        "  skip block device {} ({}): failed to create mountpoint {}: {:?}",
                        cand.disk_idx, cand.dev_name, mount_path, e
                    );
                    fs_mount_idx += 1;
                    continue;
                }
            },
        };

        match mount_dir.mount(&cand.fs) {
            Ok(_) => info!(
                "  mounted block device {} ({}) at {} ({})",
                cand.disk_idx,
                cand.dev_name,
                mount_path,
                cand.fs.name()
            ),
            Err(e) => warn!(
                "  skip block device {} ({}): mount {} failed: {:?}",
                cand.disk_idx, cand.dev_name, mount_path, e
            ),
        }

        fs_mount_idx += 1;
    }

    ROOT_FS_CONTEXT.call_once(|| cx);
}
