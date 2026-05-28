use core::time::Duration;

use axerrno::{AxError, LinuxError};
use axio::SeekFrom;
use linux_raw_sys::general::{
    O_CLOEXEC, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, pollfd,
};
use pulse_core::{
    fd_table::{FD_LIMIT, pipe_entries},
    task::uaccess,
};

use crate::impls::{
    fs::common::{get_fd_entry, open_fd_flags, remove_fd_entry},
    utils::{
        alloc_zeroed_bytes, read_user_bytes, read_user_i64, read_user_iovec_array,
        read_user_timespec, with_process, write_user_bytes, write_user_i64,
    },
};

fn iov_len_to_usize(iov_len: u64) -> Result<usize, LinuxError> {
    usize::try_from(iov_len).map_err(|_| LinuxError::EINVAL)
}

const MAX_IO_CHUNK: usize = 64 * 1024;

#[inline]
fn requested_poll_revents(events: i16, state: axio::PollState) -> i16 {
    let mut revents: i16 = 0;
    if state.readable && (events & (POLLIN as i16)) != 0 {
        revents |= POLLIN as i16;
    }
    if state.writable && (events & (POLLOUT as i16)) != 0 {
        revents |= POLLOUT as i16;
    }
    revents
}

fn read_ppoll_timeout(timeout: usize) -> Result<Option<Duration>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts = read_user_timespec(timeout).map_err(|_| LinuxError::EFAULT)?;
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(LinuxError::EINVAL);
    }
    Ok(Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)))
}

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    axlog::trace!("sys_read: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if count == 0 {
        return 0;
    }
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let mut tmp = match alloc_zeroed_bytes(count.min(MAX_IO_CHUNK), "sys_read.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
    let mut total = 0usize;
    while total < count {
        let chunk = core::cmp::min(tmp.len(), count - total);
        let ret = match object.read(&mut tmp[..chunk]) {
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
        let user_buf = match buf.checked_add(total) {
            Some(addr) => addr,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        if let Err(e) = write_user_bytes(user_buf, &tmp[..ret]) {
            return if total > 0 {
                total as isize
            } else {
                -e.code() as isize
            };
        }
        total += ret;
        if ret < chunk {
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
        return 0;
    }
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    let mut total = 0usize;
    let mut tmp = match alloc_zeroed_bytes(count.min(MAX_IO_CHUNK), "sys_write.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
    while total < count {
        let chunk = core::cmp::min(tmp.len(), count - total);
        if let Err(e) = read_user_bytes(buf + total, &mut tmp[..chunk]) {
            return if total > 0 {
                total as isize
            } else {
                -e.code() as isize
            };
        }
        let ret = match object.write(&tmp[..chunk]) {
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
        if ret < chunk {
            break;
        }
    }
    total as isize
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
    let mut tmp = match alloc_zeroed_bytes(count.min(64 * 1024), "sys_getdents64.tmp") {
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
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    match object.sync_data() {
        Ok(()) => 0,
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
    let mut buf = match alloc_zeroed_bytes(MAX_IO_CHUNK, "sys_writev.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
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
            let chunk = core::cmp::min(buf.len(), len - offset);
            if let Err(e) = read_user_bytes(io_vec.iov_base as usize + offset, &mut buf[..chunk]) {
                return if total > 0 { total } else { -e.code() as isize };
            }
            let ret = match object.write(&buf[..chunk]) {
                Ok(ret) => ret as isize,
                Err(e) => return if total > 0 { total } else { -e.code() as isize },
            };
            if ret <= 0 {
                return total + ret;
            }
            total += ret;
            offset += ret as usize;
            if ret as usize != chunk {
                return total;
            }
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
    let mut buf = match alloc_zeroed_bytes(MAX_IO_CHUNK, "sys_readv.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
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
            let chunk = core::cmp::min(buf.len(), len - offset);
            let ret = match object.read(&mut buf[..chunk]) {
                Ok(ret) => ret as isize,
                Err(e) => return if total > 0 { total } else { -e.code() as isize },
            };
            if ret <= 0 {
                return total + ret;
            }
            if let Err(e) =
                write_user_bytes(io_vec.iov_base as usize + offset, &buf[..ret as usize])
            {
                return if total > 0 { total } else { -e.code() as isize };
            }
            total += ret;
            offset += ret as usize;
            if ret as usize != chunk {
                return total;
            }
        }
    }
    total
}

pub fn sys_ppoll(
    fds: usize,
    nfds: usize,
    timeout: usize,
    _sigmask: usize,
    _sigsetsize: usize,
) -> isize {
    let timeout_dur = match read_ppoll_timeout(timeout) {
        Ok(timeout_dur) => timeout_dur,
        Err(e) => return -e.code() as isize,
    };

    if nfds == 0 {
        if let Some(timeout_dur) = timeout_dur {
            if timeout_dur > Duration::ZERO {
                axtask::sleep(timeout_dur);
            }
        }
        return 0;
    }
    if fds == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if nfds > FD_LIMIT {
        return -LinuxError::EINVAL.code() as isize;
    }

    let mut pollfds = match with_process(|process| {
        uaccess::read_user_plain_array::<pollfd>(process, fds, nfds)
    }) {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => match e {
            AxError::NoMemory => return -LinuxError::ENOMEM.code() as isize,
            _ => return -LinuxError::EFAULT.code() as isize,
        },
        Err(e) => return -e.code() as isize,
    };

    let deadline = timeout_dur.map(|timeout_dur| axhal::time::monotonic_time() + timeout_dur);

    let write_back = |pollfds: &[pollfd], ready: isize| -> isize {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                pollfds.as_ptr().cast::<u8>(),
                pollfds.len() * core::mem::size_of::<pollfd>(),
            )
        };
        write_user_bytes(fds, bytes)
            .map(|_| ready)
            .unwrap_or_else(|_| -LinuxError::EFAULT.code() as isize)
    };

    if nfds == 1 {
        pollfds[0].revents = 0;
        if pollfds[0].fd < 0 {
            return write_back(&pollfds, 0);
        }

        let fd = pollfds[0].fd as usize;
        let entry = match get_fd_entry(fd) {
            Ok(entry) => entry,
            Err(_) => {
                pollfds[0].revents = POLLNVAL as i16;
                return write_back(&pollfds, 1);
            }
        };

        match entry.object.poll() {
            Ok(state) => {
                pollfds[0].revents = requested_poll_revents(pollfds[0].events, state);
                if pollfds[0].revents != 0 {
                    return write_back(&pollfds, 1);
                }
            }
            Err(_) => {
                pollfds[0].revents = POLLERR as i16;
                return write_back(&pollfds, 1);
            }
        }

        if pollfds[0].events != 0 {
            loop {
                match entry.object.wait_ready(pollfds[0].events, deadline) {
                    Ok(false) => return write_back(&pollfds, 0),
                    Ok(true) => {
                        pollfds[0].revents = 0;
                        match entry.object.poll() {
                            Ok(state) => {
                                pollfds[0].revents =
                                    requested_poll_revents(pollfds[0].events, state);
                                if pollfds[0].revents != 0 {
                                    return write_back(&pollfds, 1);
                                }
                            }
                            Err(_) => {
                                pollfds[0].revents = POLLERR as i16;
                                return write_back(&pollfds, 1);
                            }
                        }
                        if deadline.is_some_and(|ddl| axhal::time::monotonic_time() >= ddl) {
                            return write_back(&pollfds, 0);
                        }
                    }
                    Err(LinuxError::EOPNOTSUPP) => break,
                    Err(_) => {
                        pollfds[0].revents = POLLERR as i16;
                        return write_back(&pollfds, 1);
                    }
                }
            }
        }
    }

    // Hybrid wait strategy:
    // - keep a short active-yield phase for high-frequency IPC readiness;
    // - then fall back to short sleeps to avoid permanent hot spinning.
    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let mut ready = 0usize;
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            let entry = match get_fd_entry(fd) {
                Ok(entry) => entry,
                Err(_) => {
                    return -LinuxError::EBADF.code() as isize;
                }
            };
            match entry.object.poll() {
                Ok(state) => {
                    pfd.revents = requested_poll_revents(pfd.events, state);
                    if pfd.revents != 0 {
                        ready += 1;
                    }
                }
                Err(_) => {
                    pfd.revents = POLLERR as i16;
                    ready += 1;
                }
            }
        }

        if ready > 0 {
            return write_back(&pollfds, ready as isize);
        }

        if let Ok(thread) = pulse_core::task::current_thread() {
            if thread.has_pending_signal() {
                return -LinuxError::EINTR.code() as isize;
            }
        }

        if let Some(deadline) = deadline {
            let now = axhal::time::monotonic_time();
            if now >= deadline {
                return write_back(&pollfds, 0);
            }
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                let sleep_dur = core::cmp::min(deadline - now, POLL_SLEEP_QUANTUM);
                if sleep_dur > Duration::ZERO {
                    axtask::sleep(sleep_dur);
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                axtask::sleep(POLL_SLEEP_QUANTUM);
            }
        }
    }
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
    let mut buf = match alloc_zeroed_bytes(count.clamp(1, 64 * 1024), "sys_sendfile.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
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
                        "sys_pipe2: rollback failed to remove read fd {} after write insert error: {:?}",
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

pub fn sys_fsync(fd: usize) -> isize {
    axlog::debug!("sys_fsync: fd={}", fd);
    let object = match get_fd_entry(fd) {
        Ok(entry) => entry.object,
        Err(e) => return -e.code() as isize,
    };
    match object.flush() {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_sync() -> isize {
    axlog::debug!("sys_sync: global flush");
    let procs = pulse_core::task::processes_snapshot();

    let mut unique_objects = alloc::collections::BTreeMap::new();

    for proc in procs {
        let entries = proc.clone_all_fd_entries();

        for entry in entries {
            let ptr = alloc::sync::Arc::as_ptr(&entry.object) as *const () as usize;
            unique_objects.insert(ptr, entry.object.clone());
        }
    }

    for object in unique_objects.into_values() {
        let _ = object.flush();
    }
    0
}

// Complete pselect6 implementation.
#[repr(C)]
#[derive(Clone, Copy)]
struct FdSet {
    fds_bits: [u64; 16],
}

impl FdSet {
    fn is_set(&self, fd: usize) -> bool {
        if fd >= 1024 {
            return false;
        }
        let idx = fd / 64;
        let bit = fd % 64;
        (self.fds_bits[idx] & (1 << bit)) != 0
    }

    fn set(&mut self, fd: usize) {
        if fd >= 1024 {
            return;
        }
        let idx = fd / 64;
        let bit = fd % 64;
        self.fds_bits[idx] |= 1 << bit;
    }

    fn zero() -> Self {
        Self { fds_bits: [0; 16] }
    }
}

pub fn sys_pselect6(
    nfds: usize,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: usize,
    _sigmask: usize,
) -> isize {
    axlog::debug!(
        "sys_pselect6 <= nfds: {nfds}, readfds: {readfds:#x}, writefds: {writefds:#x}, exceptfds: \
         {exceptfds:#x}, timeout: {timeout:#x}"
    );

    if nfds > 1024 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let mut in_read = FdSet::zero();
    let mut in_write = FdSet::zero();
    let mut in_except = FdSet::zero();

    let has_read = readfds != 0;
    let has_write = writefds != 0;
    let has_except = exceptfds != 0;

    if has_read {
        match uaccess::read_user_plain::<FdSet>(process.as_ref(), readfds) {
            Ok(fds) => in_read = fds,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    }
    if has_write {
        match uaccess::read_user_plain::<FdSet>(process.as_ref(), writefds) {
            Ok(fds) => in_write = fds,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    }
    if has_except {
        match uaccess::read_user_plain::<FdSet>(process.as_ref(), exceptfds) {
            Ok(fds) => in_except = fds,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    }

    let mut read_fds = alloc::vec::Vec::new();
    let mut write_fds = alloc::vec::Vec::new();
    let mut except_fds = alloc::vec::Vec::new();
    for fd in 0..nfds.min(1024) {
        if has_read && in_read.is_set(fd) {
            read_fds.push(fd);
        }
        if has_write && in_write.is_set(fd) {
            write_fds.push(fd);
        }
        if has_except && in_except.is_set(fd) {
            except_fds.push(fd);
        }
    }
    axlog::debug!(
        "sys_pselect6 => read_fds: {:?}, write_fds: {:?}, except_fds: {:?}",
        read_fds,
        write_fds,
        except_fds
    );

    let timeout_dur = if timeout != 0 {
        let ts = match read_user_timespec(timeout) {
            Ok(ts) => ts,
            Err(e) => return -e.code() as isize,
        };
        if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
            return -LinuxError::EINVAL.code() as isize;
        }
        Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
    } else {
        None
    };

    let mut pollfds = alloc::vec::Vec::new();
    for fd in 0..nfds.min(1024) {
        let mut events = 0i16;
        if has_read && in_read.is_set(fd) {
            events |= POLLIN as i16;
        }
        if has_write && in_write.is_set(fd) {
            events |= POLLOUT as i16;
        }
        if has_except && in_except.is_set(fd) {
            events |= linux_raw_sys::general::POLLPRI as i16;
        }
        if events != 0 {
            pollfds.push(pollfd {
                fd: fd as i32,
                events,
                revents: 0,
            });
        }
    }

    axlog::debug!(
        "sys_pselect6 => pollfds collected: {:?}",
        pollfds
            .iter()
            .map(|p| (p.fd, p.events))
            .collect::<alloc::vec::Vec<_>>()
    );

    if pollfds.is_empty() {
        if let Some(timeout_dur) = timeout_dur {
            if timeout_dur > Duration::ZERO {
                axtask::sleep(timeout_dur);
            }
        }
        axlog::debug!("sys_pselect6 => empty pollfds, returning 0");
        return 0;
    }

    let deadline = timeout_dur.map(|timeout_dur| axhal::time::monotonic_time() + timeout_dur);

    const POLL_ACTIVE_YIELD_ROUNDS: usize = 64;
    const POLL_SLEEP_QUANTUM: Duration = Duration::from_micros(100);
    let mut idle_rounds: usize = 0;

    loop {
        let mut ready = 0usize;
        for pfd in pollfds.iter_mut() {
            pfd.revents = 0;
            if pfd.fd < 0 {
                continue;
            }
            let fd = pfd.fd as usize;
            let entry = match get_fd_entry(fd) {
                Ok(entry) => entry,
                Err(_) => {
                    return -LinuxError::EBADF.code() as isize;
                }
            };
            match entry.object.poll() {
                Ok(state) => {
                    pfd.revents = requested_poll_revents(pfd.events, state);
                    if pfd.revents != 0 {
                        ready += 1;
                    }
                }
                Err(_) => {
                    pfd.revents = POLLERR as i16;
                    ready += 1;
                }
            }
        }

        if ready > 0 {
            axlog::debug!(
                "sys_pselect6 => ready fds detected: {:?}",
                pollfds
                    .iter()
                    .filter(|p| p.revents != 0)
                    .map(|p| (p.fd, p.revents))
                    .collect::<alloc::vec::Vec<_>>()
            );
            break;
        }

        if let Ok(thread) = pulse_core::task::current_thread() {
            if thread.has_pending_signal() {
                axlog::debug!("sys_pselect6 => interrupted by signal");
                return -LinuxError::EINTR.code() as isize;
            }
        }

        if let Some(deadline) = deadline {
            let now = axhal::time::monotonic_time();
            if now >= deadline {
                axlog::debug!("sys_pselect6 => deadline reached");
                break;
            }
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                let sleep_dur = core::cmp::min(deadline - now, POLL_SLEEP_QUANTUM);
                if sleep_dur > Duration::ZERO {
                    axtask::sleep(sleep_dur);
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= POLL_ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                axtask::sleep(POLL_SLEEP_QUANTUM);
            }
        }
    }

    let mut ready_count = 0isize;
    let mut out_read = FdSet::zero();
    let mut out_write = FdSet::zero();
    let mut out_except = FdSet::zero();

    for pfd in &pollfds {
        let fd = pfd.fd as usize;
        let revents = pfd.revents;
        if (revents & (POLLIN as i16 | POLLERR as i16 | POLLHUP as i16 | POLLNVAL as i16) != 0)
            && in_read.is_set(fd)
        {
            out_read.set(fd);
            ready_count += 1;
        }
        if (revents & (POLLOUT as i16 | POLLERR as i16 | POLLHUP as i16 | POLLNVAL as i16) != 0)
            && in_write.is_set(fd)
        {
            out_write.set(fd);
            ready_count += 1;
        }
        if (revents
            & (linux_raw_sys::general::POLLPRI as i16
                | POLLERR as i16
                | POLLHUP as i16
                | POLLNVAL as i16)
            != 0)
            && in_except.is_set(fd)
        {
            out_except.set(fd);
            ready_count += 1;
        }
    }

    if has_read {
        if let Err(_) = uaccess::write_user_plain(process.as_ref(), readfds, &out_read) {
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    if has_write {
        if let Err(_) = uaccess::write_user_plain(process.as_ref(), writefds, &out_write) {
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    if has_except {
        if let Err(_) = uaccess::write_user_plain(process.as_ref(), exceptfds, &out_except) {
            return -LinuxError::EFAULT.code() as isize;
        }
    }

    axlog::debug!("sys_pselect6 => returning ready: {ready_count}");
    ready_count
}
