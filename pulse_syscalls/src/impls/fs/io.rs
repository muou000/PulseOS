use alloc::vec;

use crate::impls::fs::common::{
    get_fd_entry, insert_fd_entry, insert_fd_entry_from, open_fd_flags, remove_fd_entry,
    set_fd_entry,
};
use crate::impls::utils::{
    read_user_bytes, read_user_i64, read_user_iovec_array, with_process, write_user_bytes,
    write_user_i64,
};
use linux_raw_sys::general::*;

use axerrno::LinuxError;
use axio::SeekFrom;
use pulse_core::fd_table::{FdEntry, FdFlags, pipe_entries};

fn iov_len_to_usize(iov_len: u64) -> Result<usize, LinuxError> {
    usize::try_from(iov_len).map_err(|_| LinuxError::EINVAL)
}

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    axlog::debug!("sys_read: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let mut tmp = vec![0u8; count];
    let ret = match object.read(&mut tmp) {
        Ok(ret) => ret as isize,
        Err(e) => return -e.code() as isize,
    };
    if ret <= 0 {
        return ret;
    }
    match write_user_bytes(buf, &tmp[..ret as usize]) {
        Ok(()) => ret,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    axlog::debug!("sys_write: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let mut tmp = vec![0u8; count];
    if let Err(e) = read_user_bytes(buf, &mut tmp) {
        return -e.code() as isize;
    }
    match object.write(&tmp) {
        Ok(ret) => ret as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getdents64(fd: usize, dirp: usize, count: usize) -> isize {
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };

    if count == 0 {
        return 0;
    }
    // Allow larger user-provided buffers to reduce syscall count during
    // directory-heavy workloads (e.g. `du`).
    let mut tmp = vec![0u8; count.min(64 * 1024)];
    let ret = match object.read_dirents64(&mut tmp) {
        Ok(ret) => ret as isize,
        Err(e) => return -e.code() as isize,
    };
    if ret <= 0 {
        return ret;
    }
    match write_user_bytes(dirp, &tmp[..ret as usize]) {
        Ok(()) => ret,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_close(fd: usize) -> isize {
    axlog::debug!("sys_close: fd={}", fd);
    match remove_fd_entry(fd) {
        Ok(_) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_writev(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    let mut total = 0isize;
    for io_vec in iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        if len == 0 {
            continue;
        }
        let mut buf = vec![0u8; len];
        if let Err(e) = read_user_bytes(io_vec.iov_base as usize, &mut buf) {
            return -e.code() as isize;
        }
        let ret = match object.write(&buf) {
            Ok(ret) => ret as isize,
            Err(e) => return if total > 0 { total } else { -e.code() as isize },
        };
        if ret < 0 {
            return if total > 0 { total } else { ret };
        }
        total += ret;
        if ret as usize != buf.len() {
            break;
        }
    }
    total
}

pub fn sys_readv(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    let mut total = 0isize;
    for io_vec in iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        if len == 0 {
            continue;
        }
        let mut buf = vec![0u8; len];
        let ret = match object.read(&mut buf) {
            Ok(ret) => ret as isize,
            Err(e) => return if total > 0 { total } else { -e.code() as isize },
        };
        if ret <= 0 {
            return total + ret;
        }
        if let Err(e) = write_user_bytes(io_vec.iov_base as usize, &buf[..ret as usize]) {
            return if total > 0 { total } else { -e.code() as isize };
        }
        total += ret;
        if ret as usize != len {
            break;
        }
    }
    total
}

pub fn sys_sendfile(out_fd: usize, in_fd: usize, offset: usize, count: usize) -> isize {
    axlog::debug!(
        "sys_sendfile: out_fd={}, in_fd={}, offset={:#x}, count={}",
        out_fd,
        in_fd,
        offset,
        count
    );
    if count == 0 {
        return 0;
    }

    let out = match get_fd_entry(out_fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let input = match get_fd_entry(in_fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };

    let use_explicit_offset = offset != 0;
    let mut file_offset = if use_explicit_offset {
        let off = match read_user_i64(offset) {
            Ok(off) => off,
            Err(e) => return -e.code() as isize,
        };
        if off < 0 {
            return -LinuxError::EINVAL.code() as isize;
        }
        off as u64
    } else {
        0
    };

    let mut total = 0usize;
    let mut buf = vec![0u8; count.clamp(1, 64 * 1024)];
    while total < count {
        let chunk_len = core::cmp::min(buf.len(), count - total);
        let read_len = if use_explicit_offset {
            match input.read_at(&mut buf[..chunk_len], file_offset) {
                Ok(len) => len,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            }
        } else {
            match input.read(&mut buf[..chunk_len]) {
                Ok(len) => len,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            }
        };
        if read_len == 0 {
            break;
        }
        if use_explicit_offset {
            file_offset = file_offset.saturating_add(read_len as u64);
        }

        let mut written = 0usize;
        while written < read_len {
            match out.write(&buf[written..read_len]) {
                Ok(0) => break,
                Ok(len) => written += len,
                Err(e) => {
                    let transferred = total + written;
                    return if transferred > 0 {
                        transferred as isize
                    } else {
                        -e.code() as isize
                    };
                }
            }
        }
        total += written;
        if written < read_len {
            break;
        }
    }

    if use_explicit_offset && let Err(e) = write_user_i64(offset, file_offset as i64) {
        return if total > 0 {
            total as isize
        } else {
            -e.code() as isize
        };
    }

    total as isize
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
        F_SETFD => match with_process(|process| -> Result<isize, LinuxError> {
            let mut table = process.fd_table.lock();
            let Some(entry) = table.get_mut(fd) else {
                return Err(LinuxError::EBADF);
            };
            entry
                .flags
                .set(FdFlags::CLOEXEC, (arg & (FD_CLOEXEC as usize)) != 0);
            Ok(0)
        }) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) | Err(e) => -e.code() as isize,
        },
        F_SETFL => match with_process(|process| -> Result<isize, LinuxError> {
            let mut table = process.fd_table.lock();
            let Some(entry) = table.get_mut(fd) else {
                return Err(LinuxError::EBADF);
            };
            let nonblocking = (arg & O_NONBLOCK as usize) != 0;
            entry.flags.set(FdFlags::NONBLOCK, nonblocking);
            entry.object.set_nonblocking(nonblocking)?;
            Ok(0)
        }) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) | Err(e) => -e.code() as isize,
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
    match set_fd_entry(newfd, FdEntry::new(entry.object, fd_flags)) {
        Ok(()) => newfd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_pipe2(fds: usize, flags: usize) -> isize {
    axlog::debug!("sys_pipe2: fds={:#x}, flags={:#x}", fds, flags);
    if fds == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let allowed = O_NONBLOCK as usize | O_CLOEXEC as usize;
    if (flags & !allowed) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let (read_entry, write_entry) = pipe_entries(open_fd_flags(flags));
    let new_fds = match with_process(|process| -> Result<[i32; 2], LinuxError> {
        let mut table = process.fd_table.lock();
        let read_fd = table.insert_next(read_entry)?;
        let write_fd = match table.insert_next(write_entry) {
            Ok(fd) => fd,
            Err(e) => {
                if table.remove(read_fd).is_none() {
                    axlog::warn!(
                        "sys_pipe2: rollback failed to remove read fd {} after write insert error",
                        read_fd
                    );
                }
                return Err(e);
            }
        };
        Ok([read_fd as i32, write_fd as i32])
    }) {
        Ok(Ok(new_fds)) => new_fds,
        Ok(Err(e)) | Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            new_fds.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&new_fds),
        )
    };
    if let Err(e) = write_user_bytes(fds, bytes) {
        if let Err(remove_e) = remove_fd_entry(new_fds[0] as usize) {
            axlog::warn!(
                "sys_pipe2: rollback failed to remove read fd {}: {:?}",
                new_fds[0],
                remove_e
            );
        }
        if let Err(remove_e) = remove_fd_entry(new_fds[1] as usize) {
            axlog::warn!(
                "sys_pipe2: rollback failed to remove write fd {}: {:?}",
                new_fds[1],
                remove_e
            );
        }
        return -e.code() as isize;
    }
    0
}

pub fn sys_lseek(fd: usize, offset: usize, whence: usize) -> isize {
    axlog::debug!(
        "sys_lseek: fd={}, offset={:#x}, whence={}",
        fd,
        offset,
        whence
    );
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let offset = offset as isize as i64;
    let pos = match whence {
        0 => {
            if offset < 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            SeekFrom::Start(offset as u64)
        }
        1 => SeekFrom::Current(offset),
        2 => SeekFrom::End(offset),
        _ => return -LinuxError::EINVAL.code() as isize,
    };
    match object.seek(pos) {
        Ok(pos) => pos as isize,
        Err(e) => -e.code() as isize,
    }
}
