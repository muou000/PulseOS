use axerrno::LinuxError;
use linux_raw_sys::general::*;
use pulse_core::{
    fd_table::{FdEntry, FdFlags},
    task::with_current_process,
};

pub(crate) fn get_fd_entry(fd: usize) -> Result<FdEntry, LinuxError> {
    with_current_process(|process| process.fd_table.lock().get_entry_cloned(fd))?
}

pub(crate) fn insert_fd_entry(entry: FdEntry) -> Result<usize, LinuxError> {
    with_current_process(|process| process.fd_table.lock().insert_next(entry))?
}

pub(crate) fn insert_fd_entry_from(min_fd: usize, entry: FdEntry) -> Result<usize, LinuxError> {
    with_current_process(|process| process.fd_table.lock().insert_from(min_fd, entry))?
}

pub(crate) fn set_fd_entry(fd: usize, entry: FdEntry) -> Result<(), LinuxError> {
    with_current_process(|process| process.fd_table.lock().insert_at(fd, entry))?
}

pub(crate) fn remove_fd_entry(fd: usize) -> Result<FdEntry, LinuxError> {
    with_current_process(|process| process.fd_table.lock().remove_or_err(fd))?
}

pub(crate) fn open_fd_flags(flags: usize) -> FdFlags {
    let mut fd_flags = FdFlags::empty();
    if (flags & O_CLOEXEC as usize) != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    if (flags & O_NONBLOCK as usize) != 0 {
        fd_flags.insert(FdFlags::NONBLOCK);
    }
    fd_flags
}
