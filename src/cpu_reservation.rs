//! Boot-time CPU reservation policy, loaded before creating PID 1.

use axerrno::AxError;
use task::future::block_on;

const RESERVED_CPUS: &str = "/etc/pulse-kernel-cpus";
const SQPOLL_CPUS: &str = "/etc/pulse-sqpoll-cpus";

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

fn read_cpu_list(path: &str) -> usize {
    let fs = fs::ROOT_FS_CONTEXT
        .get()
        .expect("root filesystem not mounted");
    // The rootfs is mounted and userspace has not started, so the configuration
    // is stable between the metadata check and the read.
    match block_on(fs.metadata(path)) {
        Err(AxError::NotFound) => 0,
        Err(error) => panic!("{path}: {error:?}"),
        Ok(meta) => {
            assert!(
                meta.node_type == fs::NodeType::RegularFile && meta.size <= 4096,
                "{path}: expected a regular file of at most 4096 bytes"
            );
            let list = block_on(fs.read_to_string(path))
                .unwrap_or_else(|error| panic!("{path}: {error:?}"));
            parse_cpu_list(&list).unwrap_or_else(|error| panic!("{path}: {error}"))
        }
    }
}

pub(super) fn init() {
    let reserved = read_cpu_list(RESERVED_CPUS);
    let sqpoll = read_cpu_list(SQPOLL_CPUS);
    task::init_cpu_reservation(reserved, sqpoll).unwrap_or_else(|error| {
        panic!(
            "CPU reservation: {error} ({RESERVED_CPUS}={reserved:#x}, {SQPOLL_CPUS}={sqpoll:#x}, \
             online={:#x})",
            hal::online_cpu_mask()
        )
    });
}
