use axerrno::LinuxError;
use linux_raw_sys::general::{
    F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_SETFD, F_SETFL, FD_CLOEXEC, O_CLOEXEC, O_NONBLOCK,
};
use pulse_core::fd_table::{FdEntry, FdFlags};

use crate::impls::{
    fs::common::{
        get_fd_entry, insert_fd_entry, insert_fd_entry_from, remove_fd_entry, set_fd_entry,
    },
    utils::with_process,
};

pub fn sys_close(fd: usize) -> isize {
    axlog::debug!("sys_close: fd={}", fd);
    match remove_fd_entry(fd) {
        Ok(_) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_dup(fd: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let mut flags = entry.flags;
    flags.remove(FdFlags::CLOEXEC);
    match insert_fd_entry(FdEntry::new(entry.object, flags)) {
        Ok(new_fd) => new_fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    axlog::debug!("sys_dup3: oldfd={}, newfd={}, flags={:#x}", oldfd, newfd, flags);
    if oldfd == newfd {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & !(O_CLOEXEC as usize)) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let entry = match get_fd_entry(oldfd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let mut fd_flags = entry.flags;
    fd_flags.remove(FdFlags::CLOEXEC);
    if (flags & O_CLOEXEC as usize) != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    match set_fd_entry(newfd, FdEntry::new(entry.object, fd_flags)) {
        Ok(()) => newfd as isize,
        Err(e) => -e.code() as isize,
    }
}
pub fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_fcntl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    match cmd as u32 {
        F_GETFD => match get_fd_entry(fd) {
            Ok(entry) => {
                if entry.flags.contains(FdFlags::CLOEXEC) {
                    FD_CLOEXEC as isize
                } else {
                    0
                }
            }
            Err(e) => -e.code() as isize,
        },
        F_GETFL => match get_fd_entry(fd) {
            Ok(entry) => {
                let mut status = 0usize;
                if entry.flags.contains(FdFlags::NONBLOCK) {
                    status |= O_NONBLOCK as usize;
                }
                status as isize
            }
            Err(e) => -e.code() as isize,
        },
        F_SETFD => {
            let result: Result<Result<isize, LinuxError>, LinuxError> =
                with_process(|process| -> Result<isize, LinuxError> {
                    let mut table = process.fd_table.lock();
                    let Some(entry) = table.get_mut(fd) else {
                        return Err(LinuxError::EBADF);
                    };
                    entry.flags.set(FdFlags::CLOEXEC, (arg & (FD_CLOEXEC as usize)) != 0);
                    Ok(0)
                });
            match result {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => -e.code() as isize,
                Err(e) => -e.code() as isize,
            }
        }
        F_SETFL => {
            let result: Result<Result<isize, LinuxError>, LinuxError> =
                with_process(|process| -> Result<isize, LinuxError> {
                    let mut table = process.fd_table.lock();
                    let Some(entry) = table.get_mut(fd) else {
                        return Err(LinuxError::EBADF);
                    };
                    let nonblocking = (arg & O_NONBLOCK as usize) != 0;
                    entry.flags.set(FdFlags::NONBLOCK, nonblocking);
                    entry.object.set_nonblocking(nonblocking)?;
                    Ok(0)
                });
            match result {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => -e.code() as isize,
                Err(e) => -e.code() as isize,
            }
        }
        F_DUPFD | F_DUPFD_CLOEXEC => {
            let entry = match get_fd_entry(fd) {
                Ok(entry) => entry,
                Err(e) => return -e.code() as isize,
            };
            let mut flags = entry.flags;
            flags.remove(FdFlags::CLOEXEC);
            if cmd as u32 == F_DUPFD_CLOEXEC {
                flags.insert(FdFlags::CLOEXEC);
            }
            match insert_fd_entry_from(arg, FdEntry::new(entry.object, flags)) {
                Ok(new_fd) => new_fd as isize,
                Err(e) => -e.code() as isize,
            }
        }
        _ => {
            axlog::warn!("unsupported fcntl parameters: cmd {}", cmd);
            0
        }
    }
}

pub fn sys_ftruncate(fd: usize, length: usize) -> isize {
    axlog::debug!("sys_ftruncate: fd={}, length={:#x}", fd, length);
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let length = length as isize as i64;
    if length < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    match object.truncate(length as u64) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}
