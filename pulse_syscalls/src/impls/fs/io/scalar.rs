use super::*;

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    axlog::trace!("sys_read: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if count == 0 {
        if get_fd_entry(fd).is_ok_and(|entry| {
            entry.object.as_any().is::<EventFdObject>()
                || entry.object.as_any().is::<SignalFdObject>()
        }) {
            return -LinuxError::EINVAL.code() as isize;
        }
        return 0;
    }
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    if let Some(pipe) = object
        .as_any()
        .downcast_ref::<pulse_core::fd_table::PipeObject>()
    {
        if buf % 4096 == 0
            && count >= 65536
            && count % 4096 == 0
            && fault_in_user_io_range(buf, count, true)
        {
            match pipe.read_zerocopy(buf, count) {
                Ok(ret) => return ret as isize,
                Err(e) => return -e.code() as isize,
            }
        }
    }
    let file_obj = object.as_any().downcast_ref::<FileObject>();
    if let Some(file_obj) = file_obj {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            let offset = match file_obj.seek(SeekFrom::Current(0)) {
                Ok(off) => off as usize,
                Err(e) => return -e.code() as isize,
            };
            if buf % block_size != 0 || offset % block_size != 0 || count % block_size != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
        }
    }
    let mut total = 0usize;
    let mut fallback_buf = None;

    while total < count {
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        let requested = (count - total).min(MAX_IO_CHUNK);
        let (ret, submitted) =
            match read_into_user(user_buf, requested, &mut fallback_buf, |slice| {
                object
                    .try_read_resident(slice)
                    .unwrap_or_else(|| object.read(slice))
            }) {
                Ok(result) => result,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            };
        if ret == 0 {
            break;
        }
        total += ret;
        if ret < submitted {
            break;
        }
    }
    total as isize
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    axlog::trace!("sys_write: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if count == 0 {
        if get_fd_entry(fd).is_ok_and(|entry| entry.object.as_any().is::<EventFdObject>()) {
            return -LinuxError::EINVAL.code() as isize;
        }
        return 0;
    }
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    if let Some(pipe) = object
        .as_any()
        .downcast_ref::<pulse_core::fd_table::PipeObject>()
    {
        if buf % 4096 == 0
            && count >= 65536
            && count % 4096 == 0
            && fault_in_user_io_range(buf, count, false)
        {
            match pipe.write_zerocopy(buf, count) {
                Ok(ret) => return ret as isize,
                Err(e) => return -e.code() as isize,
            }
        }
    }
    let file_obj = object.as_any().downcast_ref::<FileObject>();
    if let Some(file_obj) = file_obj {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            let offset = match file_obj.seek(SeekFrom::Current(0)) {
                Ok(off) => off as usize,
                Err(e) => return -e.code() as isize,
            };
            if buf % block_size != 0 || offset % block_size != 0 || count % block_size != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
        }
    }
    let _tty_write_transaction = object
        .is_tty_output()
        .then(pulse_core::fd_table::lock_tty_write_transaction);
    let mut total = 0usize;
    let mut fallback_buf = None;
    #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
    let mut marker_scanner = OutputMarkerScanner::new(fd);

    while total < count {
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        let requested = (count - total).min(MAX_IO_CHUNK);
        let (ret, submitted, _) =
            match write_from_user(user_buf, requested, &mut fallback_buf, |slice| {
                let written = match file_obj {
                    Some(file_obj) => file_obj.write_slice(slice),
                    None => object.write(slice),
                }?;
                if written > slice.len() {
                    return Err(LinuxError::EIO);
                }
                #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
                if written > 0 {
                    marker_scanner.push(&slice[..written]);
                }
                Ok(written)
            }) {
                Ok(result) => result,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            };
        if ret == 0 {
            break;
        }
        total += ret;
        if ret < submitted {
            break;
        }
    }
    total as isize
}
pub fn sys_pread64(fd: usize, buf: usize, count: usize, offset: usize) -> isize {
    axlog::trace!(
        "sys_pread64: fd={}, buf={:#x}, count={}, offset={}",
        fd,
        buf,
        count,
        offset
    );
    let offset = offset as isize;
    if offset < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if count == 0 {
        return 0;
    }
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let file_obj = object.as_any().downcast_ref::<FileObject>();
    if let Some(file_obj) = file_obj {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            if buf % block_size != 0
                || (offset as usize) % block_size != 0
                || count % block_size != 0
            {
                return -LinuxError::EINVAL.code() as isize;
            }
        }
    }
    let mut total = 0usize;
    let mut fallback_buf = None;
    while total < count {
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        let requested = (count - total).min(MAX_IO_CHUNK);
        let current_offset = match (offset as u64).checked_add(total as u64) {
            Some(off) => off,
            None => return -LinuxError::EINVAL.code() as isize,
        };

        let (ret, submitted) =
            match read_into_user(user_buf, requested, &mut fallback_buf, |slice| {
                object
                    .try_read_at_resident(slice, current_offset)
                    .unwrap_or_else(|| object.read_at(slice, current_offset))
            }) {
                Ok(result) => result,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            };
        if ret == 0 {
            break;
        }
        total += ret;
        if ret < submitted {
            break;
        }
    }
    total as isize
}

pub fn sys_pwrite64(fd: usize, buf: usize, count: usize, offset: usize) -> isize {
    axlog::trace!(
        "sys_pwrite64: fd={}, buf={:#x}, count={}, offset={}",
        fd,
        buf,
        count,
        offset
    );
    let offset = offset as isize;
    if offset < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if count == 0 {
        return 0;
    }
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let file_obj = object.as_any().downcast_ref::<FileObject>();
    if let Some(file_obj) = file_obj {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            if buf % block_size != 0
                || (offset as usize) % block_size != 0
                || count % block_size != 0
            {
                return -LinuxError::EINVAL.code() as isize;
            }
        }
    }
    let mut total = 0usize;
    let mut fallback_buf = None;

    while total < count {
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        let requested = (count - total).min(MAX_IO_CHUNK);
        let current_offset = match (offset as u64).checked_add(total as u64) {
            Some(off) => off,
            None => return -LinuxError::EINVAL.code() as isize,
        };

        let (ret, submitted, _) = match write_from_user(
            user_buf,
            requested,
            &mut fallback_buf,
            |slice| match file_obj {
                Some(file_obj) => file_obj.write_at_slice(slice, current_offset),
                None => object.write_at(slice, current_offset),
            },
        ) {
            Ok(result) => result,
            Err(e) => {
                return if total > 0 {
                    total as isize
                } else {
                    -e.code() as isize
                };
            }
        };
        if ret == 0 {
            break;
        }
        total += ret;
        if ret < submitted {
            break;
        }
    }
    total as isize
}
