use super::*;

const SYNC_TIMEOUT: Duration = Duration::from_secs(30);

pub fn sys_getdents64(fd: usize, dirp: usize, count: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;

    if count == 0 {
        return 0;
    }
    // Allow larger user-provided buffers to reduce syscall count during
    // directory-heavy workloads (e.g. `du`).
    let mut tmp = match alloc_uninit_bytes(count.min(64 * 1024), "sys_getdents64.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
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

pub fn sys_fdatasync(fd: usize) -> isize {
    axlog::debug!("sys_fdatasync: fd={}", fd);
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    match object.sync_data() {
        Ok(()) => 0,
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
        let read_fd = process.insert_fd_entry(read_entry)?;
        let write_fd = match process.insert_fd_entry(write_entry) {
            Ok(fd) => fd,
            Err(e) => {
                if let Err(remove_e) = process.remove_fd_entry(read_fd) {
                    axlog::warn!(
                        "sys_pipe2: rollback failed to remove read fd {} after write insert \
                         error: {:?}",
                        read_fd,
                        remove_e
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
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
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

pub fn sys_fsync(fd: usize) -> isize {
    axlog::debug!("sys_fsync: fd={}", fd);
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    match object.flush() {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_sync() -> isize {
    axlog::debug!("sys_sync: global flush");
    // The filesystem registry already owns every dirty file cache and flushes
    // each mounted filesystem exactly once. Walking every process descriptor
    // first caused repeated inode-wide and disk-wide flushes, while the final
    // disk registry pass repeated the same ext4 checkpoint again.
    // Keep the syscall interruptible: a lost SD/MMC completion must not make
    // Ctrl-C unable to return the terminal to its shell. The timeout is a
    // second line of defense for signals or timer delivery that arrive late.
    match axtask::future::block_on(axtask::future::interruptible(
        axtask::future::timeout(
            Some(SYNC_TIMEOUT),
            axfs::flush_all_filesystems_async(),
        ),
    )) {
        Ok(Ok(Ok(()))) => 0,
        Err(_) => {
            axlog::warn!("sys_sync: interrupted while flushing filesystems");
            -LinuxError::EINTR.code() as isize
        }
        Ok(Err(_)) => {
            axlog::error!("sys_sync: filesystem flush timed out after {:?}", SYNC_TIMEOUT);
            -LinuxError::ETIMEDOUT.code() as isize
        }
        Ok(Ok(Err(error))) => {
            axlog::error!("sys_sync: filesystem flush failed: {:?}", error);
            -LinuxError::EIO.code() as isize
        }
    }
}
