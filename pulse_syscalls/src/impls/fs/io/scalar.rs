use super::*;

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    axlog::trace!("sys_read: fd={}, buf={:#x}, count={}", fd, buf, count);
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
            && fault_in_user_io_range(buf, count, true)
        {
            match pipe.read_zerocopy(buf, count) {
                Ok(ret) => return ret as isize,
                Err(e) => return -e.code() as isize,
            }
        }
    }
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
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

    while total < count {
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        let remaining = count - total;

        if let Some(slice_ptr) = query_user_page_slice(user_buf, remaining, true) {
            let slice = unsafe { &mut *slice_ptr };
            let ret = match object.read(slice) {
                Ok(ret) => ret,
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
            if ret < slice.len() {
                break;
            }
        } else {
            return if total > 0 {
                total as isize
            } else {
                -LinuxError::EFAULT.code() as isize
            };
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
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
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
    #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
    let mut marker_scanner = OutputMarkerScanner::new(fd);

    while total < count {
        let user_buf = buf + total;
        let remaining = count - total;

        if let Some(slice_ptr) = query_user_page_slice(user_buf, remaining, false) {
            let slice = unsafe { &*slice_ptr };
            let ret = match object.write(slice) {
                Ok(ret) => ret,
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
            #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
            marker_scanner.push(&slice[..ret]);
            total += ret;
            if ret < slice.len() {
                break;
            }
        } else {
            let mut tmp = [0u8; 4096];
            let chunk = core::cmp::min(tmp.len(), remaining);
            let copied = match read_user_bytes_partial(user_buf, &mut tmp[..chunk]) {
                Ok(0) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -LinuxError::EFAULT.code() as isize
                    };
                }
                Ok(copied) => copied,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            };
            let ret = match object.write(&tmp[..copied]) {
                Ok(ret) => ret,
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
            #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
            marker_scanner.push(&tmp[..ret]);
            total += ret;
            if ret < copied || copied < chunk {
                break;
            }
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
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
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
    while total < count {
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        let remaining = count - total;
        let current_offset = match (offset as u64).checked_add(total as u64) {
            Some(off) => off,
            None => return -LinuxError::EINVAL.code() as isize,
        };

        if let Some(slice_ptr) = query_user_page_slice(user_buf, remaining, true) {
            let slice = unsafe { &mut *slice_ptr };
            let ret = match object.read_at(slice, current_offset) {
                Ok(ret) => ret,
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
            if ret < slice.len() {
                break;
            }
        } else {
            return if total > 0 {
                total as isize
            } else {
                -LinuxError::EFAULT.code() as isize
            };
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
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
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
    let mut fallback_tmp = None;

    while total < count {
        let user_buf = buf + total;
        let remaining = count - total;
        let current_offset = match (offset as u64).checked_add(total as u64) {
            Some(off) => off,
            None => return -LinuxError::EINVAL.code() as isize,
        };

        if let Some(slice_ptr) = query_user_page_slice(user_buf, remaining, false) {
            let slice = unsafe { &*slice_ptr };
            let ret = match object.write_at(slice, current_offset) {
                Ok(ret) => ret,
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
            if ret < slice.len() {
                break;
            }
        } else {
            let tmp = match fallback_tmp.as_mut() {
                Some(t) => t,
                None => {
                    let t =
                        match alloc_uninit_bytes(remaining.min(MAX_IO_CHUNK), "sys_pwrite64.tmp") {
                            Ok(b) => b,
                            Err(e) => {
                                return if total > 0 {
                                    total as isize
                                } else {
                                    -e.code() as isize
                                };
                            }
                        };
                    fallback_tmp = Some(t);
                    fallback_tmp.as_mut().unwrap()
                }
            };
            let chunk = core::cmp::min(tmp.len(), remaining);
            let copied = match read_user_bytes_partial(user_buf, &mut tmp[..chunk]) {
                Ok(0) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -LinuxError::EFAULT.code() as isize
                    };
                }
                Ok(copied) => copied,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            };
            let ret = match object.write_at(&tmp[..copied], current_offset) {
                Ok(ret) => ret,
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
            if ret < copied || copied < chunk {
                break;
            }
        }
    }
    total as isize
}
