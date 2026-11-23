//! Boot-time user CPU placement policy, loaded before creating PID 1.

use axerrno::AxError;
use axtask::future::block_on;

const CONFIG: &str = "/etc/pulse-kernel-cpus";

fn parse_cpu_list(list: &str) -> Result<usize, &'static str> {
    let list = list.trim();
    let mut mask = 0;
    if list.is_empty() {
        return Ok(mask);
    }
    let cpu_id = |value: &str| {
        value
            .parse::<u32>()
            .ok()
            .filter(|id| *id < usize::BITS)
            .ok_or("expected a decimal CPU ID within the scheduler mask")
    };
    for item in list.split(',') {
        let item = item.trim();
        let (first, last) = item.split_once('-').unwrap_or((item, item));
        let first = cpu_id(first)?;
        let last = cpu_id(last)?;
        if first > last {
            return Err("reversed CPU range");
        }
        for cpu in first..=last {
            mask |= 1usize << cpu;
        }
    }
    Ok(mask)
}

pub(super) fn init() {
    let fs = axfs::ROOT_FS_CONTEXT
        .get()
        .expect("root filesystem not mounted");
    // The rootfs is mounted and userspace has not started, so the configuration
    // is stable between the metadata check and the read.
    let mask = match block_on(fs.metadata(CONFIG)) {
        Err(AxError::NotFound) => 0,
        Err(error) => panic!("{CONFIG}: {error:?}"),
        Ok(meta) => {
            assert!(
                meta.node_type == axfs::NodeType::RegularFile && meta.size <= 4096,
                "{CONFIG}: expected a regular file of at most 4096 bytes"
            );
            let list = block_on(fs.read_to_string(CONFIG))
                .unwrap_or_else(|error| panic!("{CONFIG}: {error:?}"));
            parse_cpu_list(&list).unwrap_or_else(|error| panic!("{CONFIG}: {error}"))
        }
    };
    axtask::init_user_cpu_mask(mask).unwrap_or_else(|error| {
        panic!(
            "{CONFIG}: {error} (requested={mask:#x}, online={:#x})",
            axhal::online_cpu_mask()
        )
    });
}
