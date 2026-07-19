use axerrno::LinuxError;
use linux_raw_sys::general::{EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE};
use pulse_core::fd_table::{FdFlags, eventfd_entry};

use crate::impls::fs::common::insert_fd_entry;

pub fn sys_eventfd2(initval: u32, flags: u32) -> isize {
    axlog::debug!("sys_eventfd2: initval={}, flags={:#x}", initval, flags);

    let allowed = EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE;
    if flags & !allowed != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let mut fd_flags = FdFlags::empty();
    if flags & EFD_CLOEXEC != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    if flags & EFD_NONBLOCK != 0 {
        fd_flags.insert(FdFlags::NONBLOCK);
    }

    let entry = eventfd_entry(initval, flags & EFD_SEMAPHORE != 0, fd_flags);
    match insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}
