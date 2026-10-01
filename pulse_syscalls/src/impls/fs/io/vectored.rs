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
    let file_obj = object.as_any().downcast_ref::<FileObject>();
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    let segments = match normalize_iovecs(&iovecs) {
        Ok(segments) => segments,
        Err(e) => return -e.code() as isize,
    };
    if let Err(e) = prepare_write(file_obj, &segments, WriteOffset::Shared) {
        return -e.code() as isize;
    }
    let _tty_write_transaction = (segments.iter().any(|segment| segment.len != 0)
        && object.is_tty_output())
    .then(pulse_core::fd_table::lock_tty_write_transaction);
    let mut fallback_buf = None;
    #[cfg(feature = "qperf-trace")]
    let mut marker_scanner = OutputMarkerScanner::new(fd);

    execute_user_write(
        object.as_ref(),
        file_obj,
        &segments,
        WriteOffset::Shared,
        &mut fallback_buf,
        |bytes| {
            #[cfg(feature = "qperf-trace")]
            marker_scanner.push(bytes);
        },
        |transfer| {
            if transfer.source == UserWriteSource::Pinned {
                if transfer.written > 0 {
                    axfs::buildstorm_stat_add!(SYSCALL_IOV_DIRECT_WRITE_BYTES, transfer.written);
                }
            } else {
                if !transfer.scratch_was_present {
                    axfs::buildstorm_stat_inc!(SYSCALL_IOV_SCRATCH_ALLOCS);
                }
                axfs::buildstorm_stat_add!(SYSCALL_IOV_SCRATCH_COPY_BYTES, transfer.submitted);
            }
        },
    )
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

            let (ret, submitted) =
                match read_into_user(user_buf, chunk, &mut fallback_buf, |slice| {
                    object
                        .try_read_resident(slice)
                        .unwrap_or_else(|| object.read(slice))
                }) {
                    Ok((ret, submitted)) => (ret as isize, submitted),
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
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

            let (ret, submitted) =
                match read_into_user(user_buf, chunk, &mut fallback_buf, |slice| {
                    object
                        .try_read_at_resident(slice, file_offset)
                        .unwrap_or_else(|| object.read_at(slice, file_offset))
                }) {
                    Ok((ret, submitted)) => (ret as isize, submitted),
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
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
    let file_obj = object.as_any().downcast_ref::<FileObject>();
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    let segments = match normalize_iovecs(&iovecs) {
        Ok(segments) => segments,
        Err(e) => return -e.code() as isize,
    };
    let offset = offset as u64;
    if let Err(e) = prepare_write(file_obj, &segments, WriteOffset::Positional(offset)) {
        return -e.code() as isize;
    }

    let mut fallback_buf = None;
    execute_user_write(
        object.as_ref(),
        file_obj,
        &segments,
        WriteOffset::Positional(offset),
        &mut fallback_buf,
        |_| {},
        |transfer| {
            if transfer.source == UserWriteSource::Pinned {
                if transfer.written > 0 {
                    axfs::buildstorm_stat_add!(SYSCALL_IOV_DIRECT_WRITE_BYTES, transfer.written);
                }
            } else {
                if !transfer.scratch_was_present {
                    axfs::buildstorm_stat_inc!(SYSCALL_IOV_SCRATCH_ALLOCS);
                }
                axfs::buildstorm_stat_add!(SYSCALL_IOV_SCRATCH_COPY_BYTES, transfer.submitted);
            }
        },
    )
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
