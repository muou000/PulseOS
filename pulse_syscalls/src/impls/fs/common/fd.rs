use axerrno::LinuxError;
use linux_raw_sys::general::*;
use pulse_core::{
    fd_table::{FdEntry, FdFlags},
    task::with_current_process,
};

pub(crate) fn get_fd_entry(fd: usize) -> Result<FdEntry, LinuxError> {
    with_current_process(|process| process.get_fd_entry(fd))?
}

pub(crate) fn insert_fd_entry(entry: FdEntry) -> Result<usize, LinuxError> {
    with_current_process(|process| process.insert_fd_entry(entry))?
}

pub(crate) fn insert_fd_entry_from(min_fd: usize, entry: FdEntry) -> Result<usize, LinuxError> {
    with_current_process(|process| process.insert_fd_entry_from(min_fd, entry))?
}

pub(crate) fn set_fd_entry(fd: usize, entry: FdEntry) -> Result<(), LinuxError> {
    with_current_process(|process| process.set_fd_entry(fd, entry))?
}

pub(crate) fn remove_fd_entry(fd: usize) -> Result<FdEntry, LinuxError> {
    with_current_process(|process| process.remove_fd_entry(fd))?
}

pub(crate) fn open_fd_flags(flags: usize) -> FdFlags {
    let mut fd_flags = FdFlags::empty();
    if (flags & O_CLOEXEC as usize) != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    if (flags & O_NONBLOCK as usize) != 0 {
        fd_flags.insert(FdFlags::NONBLOCK);
    }
    if (flags & O_PATH as usize) != 0 {
        fd_flags.insert(FdFlags::PATH);
    }
    fd_flags
}
