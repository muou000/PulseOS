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
    let sigpipe_writer = is_sigpipe_writer(object.as_ref());
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    if let Some(file_obj) = file_obj {
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
    let _tty_write_transaction = (iovecs.iter().any(|io_vec| io_vec.iov_len != 0)
        && object.is_tty_output())
    .then(pulse_core::fd_table::lock_tty_write_transaction);
    let mut total = 0isize;
    #[cfg(feature = "qperf-trace")]
    let mut marker_scanner = OutputMarkerScanner::new(fd);
    // Most iovecs use pinned user pages. A fragmented run reuses this one
    // 64 KiB buffer for the rest of the syscall.
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

            let scratch_was_present = fallback_buf.is_some();
            let (ret, submitted, source) =
                match write_from_user(user_buf, chunk, &mut fallback_buf, |slice| {
                    let written = match file_obj {
                        Some(file_obj) => file_obj.write_slice(slice),
                        None => object.write(slice),
                    }?;
                    if written > slice.len() {
                        return Err(LinuxError::EIO);
                    }
                    #[cfg(feature = "qperf-trace")]
                    if written > 0 {
                        marker_scanner.push(&slice[..written]);
                    }
                    Ok(written)
                }) {
                    Ok(result) => result,
                    Err(e) => {
                        if total > 0 {
                            return total;
                        }
                        let errno = e.code();
                        queue_sigpipe_on_epipe(sigpipe_writer, errno);
                        return -errno as isize;
                    }
                };
            let ret = ret as isize;
            if source == UserWriteSource::Pinned {
                if ret > 0 {
                    axfs::buildstorm_stat_add!(SYSCALL_IOV_DIRECT_WRITE_BYTES, ret as usize);
                }
            } else {
                if !scratch_was_present {
                    axfs::buildstorm_stat_inc!(SYSCALL_IOV_SCRATCH_ALLOCS);
                }
                axfs::buildstorm_stat_add!(SYSCALL_IOV_SCRATCH_COPY_BYTES, submitted);
            }

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
    if let Some(file_obj) = file_obj {
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
    // See sys_writev: pin contiguous user pages and reuse one fallback buffer.
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

            let scratch_was_present = fallback_buf.is_some();
            let (ret, submitted, source) =
                match write_from_user(user_buf, chunk, &mut fallback_buf, |slice| match file_obj {
                    Some(file_obj) => file_obj.write_at_slice(slice, file_offset),
                    None => object.write_at(slice, file_offset),
                }) {
                    Ok(result) => result,
                    Err(e) => return if total > 0 { total } else { -e.code() as isize },
                };
            let ret = ret as isize;
            if source == UserWriteSource::Pinned {
                if ret > 0 {
                    axfs::buildstorm_stat_add!(SYSCALL_IOV_DIRECT_WRITE_BYTES, ret as usize);
                }
            } else {
                if !scratch_was_present {
                    axfs::buildstorm_stat_inc!(SYSCALL_IOV_SCRATCH_ALLOCS);
                }
                axfs::buildstorm_stat_add!(SYSCALL_IOV_SCRATCH_COPY_BYTES, submitted);
            }

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
