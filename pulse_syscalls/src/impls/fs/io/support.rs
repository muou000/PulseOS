use super::*;

pub(super) fn iov_len_to_usize(iov_len: u64) -> Result<usize, LinuxError> {
    let len = usize::try_from(iov_len).map_err(|_| LinuxError::EINVAL)?;
    if len > isize::MAX as usize {
        return Err(LinuxError::EINVAL);
    }
    Ok(len)
}

pub(super) const MAX_IO_CHUNK: usize = 64 * 1024;
pub(super) fn fault_in_user_io_range(user_addr: usize, len: usize, write: bool) -> bool {
    let access = if write {
        axhal::paging::MappingFlags::WRITE
    } else {
        axhal::paging::MappingFlags::READ
    };
    with_process(|process| process.try_fault_in_user_range(user_addr, len, access))
        .is_ok_and(|result| result.is_ok())
}

#[inline]
pub(super) fn requested_poll_revents(events: i16, state: axio::PollState) -> i16 {
    let mut revents: i16 = 0;
    if state.readable && (events & (POLLIN as i16)) != 0 {
        revents |= POLLIN as i16;
    }
    if state.writable && (events & (POLLOUT as i16)) != 0 {
        revents |= POLLOUT as i16;
    }
    revents
}

pub(super) fn read_ppoll_timeout(timeout: usize) -> Result<Option<Duration>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts = read_user_timespec(timeout).map_err(|_| LinuxError::EFAULT)?;
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(LinuxError::EINVAL);
    }
    Ok(Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)))
}
