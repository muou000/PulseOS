use axerrno::LinuxError;
use axio::SeekFrom;
use linux_raw_sys::general::{
    AT_FDCWD, F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD, F_GETFL, F_GETLK, F_GETPIPE_SZ, F_OFD_GETLK,
    F_OFD_SETLK, F_OFD_SETLKW, F_RDLCK, F_SETFD, F_SETFL, F_SETLK, F_SETLKW, F_SETPIPE_SZ, F_UNLCK,
    F_WRLCK, FD_CLOEXEC, O_CLOEXEC, O_NONBLOCK, O_RDONLY, O_RDWR, O_WRONLY, POSIX_FADV_NOREUSE,
    RLIMIT_FSIZE, S_IFMT, S_IFREG, SEEK_CUR, SEEK_END, SEEK_SET, flock,
};
use pulse_core::{
    fd_table::{DirObject, FdFlags, FileObject, PidfdObject},
    record_lock::{RecordLockOwner, RecordLockType},
    task::uaccess,
};

use crate::impls::{
    fs::common::{
        get_fd_entry, insert_fd_entry, insert_fd_entry_from, remove_fd_entry, set_fd_entry,
    },
    utils::with_process,
};

pub fn sys_close(fd: usize) -> isize {
    axlog::debug!("sys_close: fd={}", fd);
    match remove_fd_entry(fd) {
        Ok(_entry) => {
            axlog::debug!("sys_close: fd={} done", fd);
            0
        }
        Err(e) => {
            axlog::debug!("sys_close: fd={} err: {:?}", fd, e);
            -e.code() as isize
        }
    }
}

const CLOSE_RANGE_UNSHARE: u32 = 1 << 1;
const CLOSE_RANGE_CLOEXEC: u32 = 1 << 2;

pub fn sys_close_range(first: usize, last: usize, flags: usize) -> isize {
    let first = first as u32 as usize;
    let last = last as u32 as usize;
    let flags = flags as u32;
    let allowed = CLOSE_RANGE_UNSHARE | CLOSE_RANGE_CLOEXEC;
    if first > last || flags & !allowed != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    if flags & CLOSE_RANGE_UNSHARE != 0 {
        if let Err(e) = process.unshare_files() {
            return -e.code() as isize;
        }
    }

    if flags & CLOSE_RANGE_CLOEXEC != 0 {
        process.set_fd_cloexec_range(first, last);
    } else {
        drop(process.close_fd_range(first, last));
    }
    0
}

pub fn sys_dup(fd: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let mut flags = entry.flags;
    flags.remove(FdFlags::CLOEXEC);
    match insert_fd_entry(entry.duplicate(flags)) {
        Ok(new_fd) => new_fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_dup3: oldfd={}, newfd={}, flags={:#x}",
        oldfd,
        newfd,
        flags
    );
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
    match set_fd_entry(newfd, entry.duplicate(fd_flags)) {
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
                if entry
                    .object
                    .nonblocking_state()
                    .unwrap_or_else(|| entry.flags.contains(FdFlags::NONBLOCK))
                {
                    status |= O_NONBLOCK as usize;
                }
                if entry.object.is_read_open() && entry.object.is_write_open() {
                    status |= O_RDWR as usize;
                } else if entry.object.is_write_open() {
                    status |= O_WRONLY as usize;
                } else if entry.object.is_read_open() {
                    status |= O_RDONLY as usize;
                }
                status as isize
            }
            Err(e) => -e.code() as isize,
        },
        F_SETFD => match with_process(|process| {
            process.set_fd_cloexec(fd, (arg & (FD_CLOEXEC as usize)) != 0)
        }) {
            Ok(Ok(())) => 0,
            Ok(Err(e)) => -e.code() as isize,
            Err(e) => -e.code() as isize,
        },
        F_SETFL => match with_process(|process| {
            process.set_fd_nonblocking(fd, (arg & O_NONBLOCK as usize) != 0)
        }) {
            Ok(Ok(())) => 0,
            Ok(Err(e)) => -e.code() as isize,
            Err(e) => -e.code() as isize,
        },
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
            match insert_fd_entry_from(arg, entry.duplicate(flags)) {
                Ok(new_fd) => new_fd as isize,
                Err(e) => -e.code() as isize,
            }
        }
        F_GETLK | F_OFD_GETLK | F_SETLK | F_SETLKW | F_OFD_SETLK | F_OFD_SETLKW => {
            match sys_fcntl_record_lock(fd, cmd as u32, arg) {
                Ok(ret) => ret,
                Err(e) => -e.code() as isize,
            }
        }
        F_SETPIPE_SZ => match get_fd_entry(fd) {
            Ok(entry) => match entry.object.set_pipe_size(arg) {
                Ok(new_size) => new_size as isize,
                Err(e) => -e.code() as isize,
            },
            Err(e) => -e.code() as isize,
        },
        F_GETPIPE_SZ => match get_fd_entry(fd) {
            Ok(entry) => match entry.object.get_pipe_size() {
                Ok(size) => size as isize,
                Err(e) => -e.code() as isize,
            },
            Err(e) => -e.code() as isize,
        },
        _ => {
            axlog::warn!("unsupported fcntl parameters: cmd {}", cmd);
            -LinuxError::EINVAL.code() as isize
        }
    }
}

fn sys_fcntl_record_lock(fd: usize, cmd: u32, arg: usize) -> Result<isize, LinuxError> {
    let entry = get_fd_entry(fd)?;
    if entry.flags.contains(FdFlags::PATH) {
        return Err(LinuxError::EBADF);
    }

    let mut lock: flock = with_process(|process| uaccess::read_user_plain(process, arg))?
        .map_err(|e| LinuxError::from(e.canonicalize()))?;
    let base = match lock.l_whence as u32 {
        SEEK_SET => 0,
        SEEK_CUR => i64::try_from(entry.object.seek(SeekFrom::Current(0))?)
            .map_err(|_| LinuxError::EINVAL)?,
        SEEK_END => {
            let size = entry.object.stat()?.st_size;
            if size < 0 {
                return Err(LinuxError::EINVAL);
            }
            size as i64
        }
        _ => return Err(LinuxError::EINVAL),
    };
    let (start, end) = pulse_core::record_lock::resolve_range(base, lock.l_start, lock.l_len)?;
    let is_ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    if is_ofd && lock.l_pid != 0 {
        return Err(LinuxError::EINVAL);
    }
    let owner = if is_ofd {
        RecordLockOwner::Ofd(entry.ofd_owner())
    } else {
        RecordLockOwner::Posix(with_process(|process| process.pid())?)
    };
    let target = pulse_core::flock::get_lock_target(&entry.object);
    let lock_type = match lock.l_type as u32 {
        F_RDLCK => RecordLockType::Read,
        F_WRLCK => RecordLockType::Write,
        F_UNLCK if !matches!(cmd, F_GETLK | F_OFD_GETLK) => {
            return pulse_core::record_lock::unlock_lock(owner, target, start, end);
        }
        _ => return Err(LinuxError::EINVAL),
    };

    if matches!(cmd, F_GETLK | F_OFD_GETLK) {
        if let Some(conflict) =
            pulse_core::record_lock::get_lock(owner, target, start, end, lock_type)?
        {
            lock.l_type = match conflict.lock_type {
                RecordLockType::Read => F_RDLCK as i16,
                RecordLockType::Write => F_WRLCK as i16,
            };
            lock.l_whence = SEEK_SET as i16;
            lock.l_start = conflict.start;
            lock.l_len = if conflict.end == i64::MAX {
                0
            } else {
                conflict.end - conflict.start
            };
            lock.l_pid = match conflict.owner {
                RecordLockOwner::Posix(pid) => i32::try_from(pid).unwrap_or(-1),
                RecordLockOwner::Ofd(_) => -1,
            };
        } else {
            lock.l_type = F_UNLCK as i16;
        }
        with_process(|process| uaccess::write_user_plain(process, arg, &lock))?
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        return Ok(0);
    }

    match lock_type {
        RecordLockType::Read => {
            if !entry.object.is_read_open() {
                return Err(LinuxError::EBADF);
            }
        }
        RecordLockType::Write => {
            if !entry.object.is_write_open() {
                return Err(LinuxError::EBADF);
            }
        }
    }

    pulse_core::record_lock::set_lock(
        owner,
        target,
        start,
        end,
        lock_type,
        matches!(cmd, F_SETLKW | F_OFD_SETLKW),
    )
}

pub fn sys_fadvise64(fd: usize, offset: usize, len: usize, advice: usize) -> isize {
    axlog::debug!(
        "sys_fadvise64: fd={}, offset={}, len={}, advice={}",
        fd,
        offset as isize,
        len as isize,
        advice
    );

    // Linux resolves the descriptor before validating advice arguments.
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }

    if entry.object.as_any().is::<FileObject>() {
        if let Err(e) = entry.object.seek(SeekFrom::Current(0)) {
            return -e.code() as isize;
        }
    } else if !entry.object.as_any().is::<DirObject>() {
        return -LinuxError::ESPIPE.code() as isize;
    }

    if (len as isize) < 0 || advice > POSIX_FADV_NOREUSE as usize {
        return -LinuxError::EINVAL.code() as isize;
    }

    // The VFS has no cache-policy hook yet, so valid advice remains a no-op.
    0
}

pub fn sys_readahead(fd: usize, offset: usize, count: usize) -> isize {
    let offset = offset as isize;
    if offset < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    // pidfds have no file data to prefetch; Linux accepts this descriptor
    // class and treats the request as a successful no-op.
    if entry.object.as_any().is::<PidfdObject>() {
        return 0;
    }
    let stat = match entry.object.stat() {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    if stat.st_mode & S_IFMT != S_IFREG {
        return -LinuxError::EINVAL.code() as isize;
    }
    let Some(file) = entry.object.as_any().downcast_ref::<FileObject>() else {
        return -LinuxError::EINVAL.code() as isize;
    };
    if !file.is_read_open() {
        return -LinuxError::EBADF.code() as isize;
    }

    match file.readahead(offset as u64, count) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_ftruncate(fd: usize, length: usize) -> isize {
    axlog::debug!("sys_ftruncate: fd={}, length={:#x}", fd, length);
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let length = length as isize as i64;
    if length < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Ok(process) = pulse_core::task::current_process()
        && let Some(limit) = process.get_rlimit(RLIMIT_FSIZE)
        && (length as u64) > limit.rlim_cur
    {
        return -LinuxError::EFBIG.code() as isize;
    }
    match object.truncate(length as u64) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_truncate(pathname: usize, length: usize) -> isize {
    if (length as isize) < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if let Err(e) = crate::impls::utils::with_user_path_str(pathname, |path| {
        if path.is_empty() {
            Err(LinuxError::ENOENT)
        } else {
            Ok(())
        }
    }) {
        return -e.code() as isize;
    }

    let fd = crate::impls::sys_openat(AT_FDCWD as i32, pathname, O_WRONLY as usize, 0);
    if fd < 0 {
        return fd;
    }

    let result = match get_fd_entry(fd as usize) {
        Ok(entry) if entry.object.as_any().is::<DirObject>() => -LinuxError::EISDIR.code() as isize,
        Ok(_) => sys_ftruncate(fd as usize, length),
        Err(e) => -e.code() as isize,
    };
    let close_result = sys_close(fd as usize);
    if result == 0 { close_result } else { result }
}

pub fn sys_fallocate(fd: usize, mode: usize, offset: usize, len: usize) -> isize {
    let mode = mode as u32;
    let offset = offset as isize as i64;
    let len = len as isize as i64;

    axlog::debug!(
        "sys_fallocate: fd={}, mode={:#x}, offset={}, len={}",
        fd,
        mode,
        offset,
        len
    );

    if offset < 0 || len <= 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;

    match object.allocate(mode, offset as u64, len as u64) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_flock(fd: usize, operation: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let owner = alloc::sync::Arc::as_ptr(&entry.object) as *const () as usize;
    let target = pulse_core::flock::get_lock_target(&entry.object);
    match pulse_core::flock::do_flock(owner, target, operation as i32) {
        Ok(_) => 0,
        Err(e) => -e.code() as isize,
    }
}
