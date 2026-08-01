use super::*;

pub fn sys_writev(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            let offset = match file_obj.seek(SeekFrom::Current(0)) {
                Ok(off) => off as usize,
                Err(e) => return -e.code() as isize,
            };
            if offset % block_size != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            for io_vec in &iovecs {
                let addr = io_vec.iov_base as usize;
                let len = match iov_len_to_usize(io_vec.iov_len) {
                    Ok(l) => l,
                    Err(e) => return -e.code() as isize,
                };
                if addr % block_size != 0 || len % block_size != 0 {
                    return -LinuxError::EINVAL.code() as isize;
                }
            }
        }
    }
    let mut actual_len = 0usize;
    for io_vec in &iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        actual_len = actual_len.saturating_add(len);
    }
    let mut total = 0isize;
    #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
    let mut marker_scanner = OutputMarkerScanner::new(fd);
    // Most regular-file iovecs can be written from their already mapped user
    // pages. Allocate the scratch buffer only for the cross-page fallback.
    let mut fallback_buf = None;
    for io_vec in iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        if len == 0 {
            continue;
        }
        let mut offset = 0usize;
        while offset < len {
            let chunk = core::cmp::min(MAX_IO_CHUNK, len - offset);
            let user_buf = io_vec.iov_base as usize + offset;

            let (ret, submitted) = if let Some(slice_ptr) =
                query_user_page_slice(user_buf, chunk, false)
            {
                let slice = unsafe { &*slice_ptr };
                let ret = match object.write(slice) {
                    Ok(ret) => ret as isize,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
                if ret > 0 {
                    axfs::buildstorm_stat_add!(SYSCALL_IOV_DIRECT_WRITE_BYTES, ret as usize);
                }
                #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
                if ret > 0 {
                    marker_scanner.push(&slice[..ret as usize]);
                }
                (ret, slice.len())
            } else {
                if fallback_buf.is_none() {
                    let buf =
                        match alloc_uninit_bytes(actual_len.min(MAX_IO_CHUNK), "sys_writev.tmp") {
                            Ok(buf) => buf,
                            Err(e) => {
                                return if total > 0 { total } else { -e.code() as isize };
                            }
                        };
                    fallback_buf = Some(buf);
                    axfs::buildstorm_stat_inc!(SYSCALL_IOV_SCRATCH_ALLOCS);
                }
                let buf = fallback_buf.as_mut().unwrap();
                let copied = match read_user_bytes_partial(user_buf, &mut buf[..chunk]) {
                    Ok(0) => {
                        return if total > 0 {
                            total
                        } else {
                            -LinuxError::EFAULT.code() as isize
                        };
                    }
                    Ok(copied) => copied,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
                axfs::buildstorm_stat_add!(SYSCALL_IOV_SCRATCH_COPY_BYTES, copied);
                let ret = match object.write(&buf[..copied]) {
                    Ok(ret) => ret as isize,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
                #[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
                if ret > 0 {
                    marker_scanner.push(&buf[..ret as usize]);
                }
                (ret, copied)
            };

            if ret <= 0 {
                return total + ret;
            }
            total += ret;
            offset += ret as usize;
            if ret as usize != submitted {
                return total;
            }
        }
    }
    total
}

pub fn sys_readv(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            let offset = match file_obj.seek(SeekFrom::Current(0)) {
                Ok(off) => off as usize,
                Err(e) => return -e.code() as isize,
            };
            if offset % block_size != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            for io_vec in &iovecs {
                let addr = io_vec.iov_base as usize;
                let len = match iov_len_to_usize(io_vec.iov_len) {
                    Ok(l) => l,
                    Err(e) => return -e.code() as isize,
                };
                if addr % block_size != 0 || len % block_size != 0 {
                    return -LinuxError::EINVAL.code() as isize;
                }
            }
        }
    }
    let mut total = 0isize;
    for io_vec in iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        if len == 0 {
            continue;
        }
        let mut offset = 0usize;
        while offset < len {
            let chunk = core::cmp::min(MAX_IO_CHUNK, len - offset);
            let user_buf = io_vec.iov_base as usize + offset;

            let (ret, submitted) =
                if let Some(slice_ptr) = query_user_page_slice(user_buf, chunk, true) {
                    let slice = unsafe { &mut *slice_ptr };
                    let ret = match object.read(slice) {
                        Ok(ret) => ret as isize,
                        Err(e) => return if total > 0 { total } else { -e.code() as isize },
                    };
                    (ret, slice.len())
                } else {
                    return if total > 0 {
                        total
                    } else {
                        -LinuxError::EFAULT.code() as isize
                    };
                };

            if ret <= 0 {
                return total + ret;
            }
            total += ret;
            offset += ret as usize;
            if ret as usize != submitted {
                return total;
            }
        }
    }
    total
}

pub fn sys_preadv(fd: usize, iov: usize, iovcnt: usize, pos_l: usize, pos_h: usize) -> isize {
    axlog::trace!(
        "sys_preadv: fd={}, iov={:#x}, iovcnt={}, pos_l={}, pos_h={}",
        fd,
        iov,
        iovcnt,
        pos_l,
        pos_h
    );

    let offset = pos_l as isize;
    if offset < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            if (offset as usize) % block_size != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            for io_vec in &iovecs {
                let addr = io_vec.iov_base as usize;
                let len = match iov_len_to_usize(io_vec.iov_len) {
                    Ok(l) => l,
                    Err(e) => return -e.code() as isize,
                };
                if addr % block_size != 0 || len % block_size != 0 {
                    return -LinuxError::EINVAL.code() as isize;
                }
            }
        }
    }

    let mut total_len = 0usize;
    for io_vec in &iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        total_len = match total_len.checked_add(len) {
            Some(sum) => sum,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        if total_len > isize::MAX as usize {
            return -LinuxError::EINVAL.code() as isize;
        }
    }

    let mut total = 0isize;
    for io_vec in iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        if len == 0 {
            continue;
        }
        let mut offset_in_vec = 0usize;
        while offset_in_vec < len {
            let chunk = core::cmp::min(MAX_IO_CHUNK, len - offset_in_vec);
            let user_buf = io_vec.iov_base as usize + offset_in_vec;
            let file_offset = match (offset as u64).checked_add(total as u64) {
                Some(off) => off,
                None => {
                    return if total > 0 {
                        total
                    } else {
                        -LinuxError::EINVAL.code() as isize
                    };
                }
            };

            let (ret, submitted) =
                if let Some(slice_ptr) = query_user_page_slice(user_buf, chunk, true) {
                    let slice = unsafe { &mut *slice_ptr };
                    let ret = match object.read_at(slice, file_offset) {
                        Ok(ret) => ret as isize,
                        Err(e) => return if total > 0 { total } else { -e.code() as isize },
                    };
                    (ret, slice.len())
                } else {
                    return if total > 0 {
                        total
                    } else {
                        -LinuxError::EFAULT.code() as isize
                    };
                };

            if ret <= 0 {
                return total + ret;
            }
            total += ret;
            offset_in_vec += ret as usize;
            if ret as usize != submitted {
                return total;
            }
        }
    }
    total
}

pub fn sys_preadv2(
    fd: usize,
    iov: usize,
    iovcnt: usize,
    pos_l: usize,
    pos_h: usize,
    flags: usize,
) -> isize {
    axlog::trace!(
        "sys_preadv2: fd={}, iov={:#x}, iovcnt={}, pos_l={}, pos_h={}, flags={:#x}",
        fd,
        iov,
        iovcnt,
        pos_l,
        pos_h,
        flags
    );

    if flags != 0 {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    let offset = pos_l as isize;
    if offset == -1 {
        sys_readv(fd, iov, iovcnt)
    } else {
        sys_preadv(fd, iov, iovcnt, pos_l, pos_h)
    }
}

pub fn sys_pwritev(fd: usize, iov: usize, iovcnt: usize, pos_l: usize, pos_h: usize) -> isize {
    axlog::trace!(
        "sys_pwritev: fd={}, iov={:#x}, iovcnt={}, pos_l={}, pos_h={}",
        fd,
        iov,
        iovcnt,
        pos_l,
        pos_h
    );

    let offset = pos_l as isize;
    if offset < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let object = entry.object;
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    if let Some(file_obj) = object.as_any().downcast_ref::<FileObject>() {
        if file_obj.inner().is_direct_regular_file() {
            let block_size = file_obj.inner().block_size() as usize;
            if (offset as usize) % block_size != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            for io_vec in &iovecs {
                let addr = io_vec.iov_base as usize;
                let len = match iov_len_to_usize(io_vec.iov_len) {
                    Ok(l) => l,
                    Err(e) => return -e.code() as isize,
                };
                if addr % block_size != 0 || len % block_size != 0 {
                    return -LinuxError::EINVAL.code() as isize;
                }
            }
        }
    }

    let mut total_len = 0usize;
    for io_vec in &iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        total_len = match total_len.checked_add(len) {
            Some(sum) => sum,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        if total_len > isize::MAX as usize {
            return -LinuxError::EINVAL.code() as isize;
        }
    }

    let mut total = 0isize;
    // See sys_writev: keep the direct user-page path allocation-free.
    let mut fallback_buf = None;

    for io_vec in iovecs {
        let len = match iov_len_to_usize(io_vec.iov_len) {
            Ok(len) => len,
            Err(e) => return -e.code() as isize,
        };
        if len == 0 {
            continue;
        }
        let mut offset_in_vec = 0usize;
        while offset_in_vec < len {
            let chunk = core::cmp::min(MAX_IO_CHUNK, len - offset_in_vec);
            let user_buf = io_vec.iov_base as usize + offset_in_vec;

            let file_offset = match (offset as u64).checked_add(total as u64) {
                Some(off) => off,
                None => {
                    return if total > 0 {
                        total
                    } else {
                        -LinuxError::EINVAL.code() as isize
                    };
                }
            };

            let (ret, submitted) = if let Some(slice_ptr) =
                query_user_page_slice(user_buf, chunk, false)
            {
                let slice = unsafe { &*slice_ptr };
                let ret = match object.write_at(slice, file_offset) {
                    Ok(ret) => ret as isize,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
                if ret > 0 {
                    axfs::buildstorm_stat_add!(SYSCALL_IOV_DIRECT_WRITE_BYTES, ret as usize);
                }
                (ret, slice.len())
            } else {
                if fallback_buf.is_none() {
                    let buf =
                        match alloc_uninit_bytes(total_len.min(MAX_IO_CHUNK), "sys_pwritev.tmp") {
                            Ok(buf) => buf,
                            Err(e) => {
                                return if total > 0 { total } else { -e.code() as isize };
                            }
                        };
                    fallback_buf = Some(buf);
                    axfs::buildstorm_stat_inc!(SYSCALL_IOV_SCRATCH_ALLOCS);
                }
                let buf = fallback_buf.as_mut().unwrap();
                let copied = match read_user_bytes_partial(user_buf, &mut buf[..chunk]) {
                    Ok(0) => {
                        return if total > 0 {
                            total
                        } else {
                            -LinuxError::EFAULT.code() as isize
                        };
                    }
                    Ok(copied) => copied,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
                axfs::buildstorm_stat_add!(SYSCALL_IOV_SCRATCH_COPY_BYTES, copied);
                let ret = match object.write_at(&buf[..copied], file_offset) {
                    Ok(ret) => ret as isize,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
                (ret, copied)
            };

            if ret <= 0 {
                return total + ret;
            }
            total += ret;
            offset_in_vec += ret as usize;
            if ret as usize != submitted {
                return total;
            }
        }
    }
    total
}

pub fn sys_pwritev2(
    fd: usize,
    iov: usize,
    iovcnt: usize,
    pos_l: usize,
    pos_h: usize,
    flags: usize,
) -> isize {
    axlog::trace!(
        "sys_pwritev2: fd={}, iov={:#x}, iovcnt={}, pos_l={}, pos_h={}, flags={:#x}",
        fd,
        iov,
        iovcnt,
        pos_l,
        pos_h,
        flags
    );

    if flags != 0 {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    let offset = pos_l as isize;
    if offset == -1 {
        sys_writev(fd, iov, iovcnt)
    } else {
        sys_pwritev(fd, iov, iovcnt, pos_l, pos_h)
    }
}
