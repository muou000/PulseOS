use super::*;
pub(super) use crate::validation::io::iov_len_to_usize;

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
    crate::validation::io::requested_poll_revents(events, state.readable, state.writable)
}

pub(super) fn read_ppoll_timeout(timeout: usize) -> Result<Option<Duration>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts = read_user_timespec(timeout).map_err(|_| LinuxError::EFAULT)?;
    crate::validation::io::ppoll_timeout(ts).map(Some)
}
