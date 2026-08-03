use super::*;

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

    let out_entry = match get_fd_entry(out_fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if out_entry
        .flags
        .contains(pulse_core::fd_table::FdFlags::PATH)
    {
        return -LinuxError::EBADF.code() as isize;
    }
    let out = out_entry.object;

    let in_entry = match get_fd_entry(in_fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if in_entry.flags.contains(pulse_core::fd_table::FdFlags::PATH) {
        return -LinuxError::EBADF.code() as isize;
    }
    let input = in_entry.object;

    if !out.is_write_open() {
        return -LinuxError::EBADF.code() as isize;
    }
    if !input.is_read_open() {
        return -LinuxError::EBADF.code() as isize;
    }

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
    let mut buf = match alloc_uninit_bytes(count.clamp(1, 64 * 1024), "sys_sendfile.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
    while total < count {
        let chunk_len = core::cmp::min(buf.len(), count - total);
        let read_len = if use_explicit_offset {
            match input
                .try_read_at_resident(&mut buf[..chunk_len], file_offset)
                .unwrap_or_else(|| input.read_at(&mut buf[..chunk_len], file_offset))
            {
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
            match input
                .try_read_resident(&mut buf[..chunk_len])
                .unwrap_or_else(|| input.read(&mut buf[..chunk_len]))
            {
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

pub fn sys_copy_file_range(
    fd_in: usize,
    off_in: usize,
    fd_out: usize,
    off_out: usize,
    len: usize,
    flags: usize,
) -> isize {
    axlog::debug!(
        "sys_copy_file_range: fd_in={}, off_in={:#x}, fd_out={}, off_out={:#x}, len={}, \
         flags={:#x}",
        fd_in,
        off_in,
        fd_out,
        off_out,
        len,
        flags
    );

    if flags != 0 || len > isize::MAX as usize {
        return -LinuxError::EINVAL.code() as isize;
    }

    let in_entry = match get_fd_entry(fd_in) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let out_entry = match get_fd_entry(fd_out) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    if in_entry.flags.contains(pulse_core::fd_table::FdFlags::PATH)
        || out_entry
            .flags
            .contains(pulse_core::fd_table::FdFlags::PATH)
    {
        return -LinuxError::EBADF.code() as isize;
    }

    let input = in_entry.object;
    let output = out_entry.object;
    let in_stat = match input.stat() {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let out_stat = match output.stat() {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let in_type = in_stat.st_mode & S_IFMT;
    let out_type = out_stat.st_mode & S_IFMT;
    if in_type == S_IFDIR || out_type == S_IFDIR {
        return -LinuxError::EISDIR.code() as isize;
    }
    if in_type != S_IFREG || out_type != S_IFREG {
        return -LinuxError::EINVAL.code() as isize;
    }
    if !input.is_read_open() || !output.is_write_open() {
        return -LinuxError::EBADF.code() as isize;
    }

    let Some(out_file) = output.as_any().downcast_ref::<FileObject>() else {
        return -LinuxError::EINVAL.code() as isize;
    };
    if out_file.inner().flags().contains(axfs::FileFlags::APPEND) {
        return -LinuxError::EBADF.code() as isize;
    }

    let explicit_in = off_in != 0;
    let explicit_out = off_out != 0;
    let mut input_pos = if explicit_in {
        match read_user_i64(off_in) {
            Ok(pos) if pos >= 0 => pos as u64,
            Ok(_) => return -LinuxError::EINVAL.code() as isize,
            Err(e) => return -e.code() as isize,
        }
    } else {
        match input.seek(SeekFrom::Current(0)) {
            Ok(pos) => pos,
            Err(e) => return -e.code() as isize,
        }
    };
    let mut output_pos = if explicit_out {
        match read_user_i64(off_out) {
            Ok(pos) if pos >= 0 => pos as u64,
            Ok(_) => return -LinuxError::EINVAL.code() as isize,
            Err(e) => return -e.code() as isize,
        }
    } else {
        match output.seek(SeekFrom::Current(0)) {
            Ok(pos) => pos,
            Err(e) => return -e.code() as isize,
        }
    };

    let range_len = len as u64;
    let input_end = match input_pos.checked_add(range_len) {
        Some(end) => end,
        None => return -LinuxError::EINVAL.code() as isize,
    };
    let output_end = match output_pos.checked_add(range_len) {
        Some(end) => end,
        None => return -LinuxError::EINVAL.code() as isize,
    };
    if len != 0
        && in_stat.st_dev == out_stat.st_dev
        && in_stat.st_ino == out_stat.st_ino
        && input_pos < output_end
        && output_pos < input_end
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    let mut total = 0usize;
    let mut error = None;
    if len != 0 {
        let mut buf = match alloc_uninit_bytes(len.min(MAX_IO_CHUNK), "sys_copy_file_range.tmp") {
            Ok(buf) => buf,
            Err(e) => return -e.code() as isize,
        };

        while total < len {
            let chunk_len = core::cmp::min(buf.len(), len - total);
            let read_len = if explicit_in {
                input
                    .try_read_at_resident(&mut buf[..chunk_len], input_pos)
                    .unwrap_or_else(|| input.read_at(&mut buf[..chunk_len], input_pos))
            } else {
                input
                    .try_read_resident(&mut buf[..chunk_len])
                    .unwrap_or_else(|| input.read(&mut buf[..chunk_len]))
            };
            let read_len = match read_len {
                Ok(0) => break,
                Ok(read_len) => read_len,
                Err(e) => {
                    error = Some(e);
                    break;
                }
            };

            let mut written = 0usize;
            while written < read_len {
                let result = if explicit_out {
                    output.write_at(&buf[written..read_len], output_pos + written as u64)
                } else {
                    output.write(&buf[written..read_len])
                };
                match result {
                    Ok(0) => break,
                    Ok(n) => written += n,
                    Err(e) => {
                        error = Some(e);
                        break;
                    }
                }
            }

            if !explicit_in && written < read_len {
                let unread = read_len - written;
                if let Err(e) = input.seek(SeekFrom::Current(-(unread as i64))) {
                    error = Some(e);
                }
            }
            if explicit_in {
                input_pos += written as u64;
            }
            if explicit_out {
                output_pos += written as u64;
            }
            total += written;

            if written < read_len {
                break;
            }
        }
    }

    if explicit_in && let Err(e) = write_user_i64(off_in, input_pos as i64) {
        return if total > 0 {
            total as isize
        } else {
            -e.code() as isize
        };
    }
    if explicit_out && let Err(e) = write_user_i64(off_out, output_pos as i64) {
        return if total > 0 {
            total as isize
        } else {
            -e.code() as isize
        };
    }

    if total > 0 {
        total as isize
    } else if let Some(e) = error {
        -e.code() as isize
    } else {
        0
    }
}
