use core::time::Duration;

use axerrno::{AxError, LinuxError};
use axio::SeekFrom;
use linux_raw_sys::general::{
    O_CLOEXEC, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, S_IFDIR, S_IFMT, S_IFREG,
    pollfd,
};
use pulse_core::{
    fd_table::{EventFdObject, FD_LIMIT, FdObject, FileObject, SignalFdObject, pipe_entries},
    task::uaccess,
};

use crate::impls::{
    fs::common::{get_fd_entry, get_fd_objects, open_fd_flags, remove_fd_entry},
    utils::{
        ScratchBuffer, alloc_uninit_bytes, pin_user_read_slice, pin_user_write_slice,
        read_user_bytes_partial, read_user_i64, read_user_iovec_array, read_user_timespec,
        with_process, write_user_bytes, write_user_bytes_partial, write_user_i64,
    },
};

mod descriptor;
mod markers;
mod readiness;
mod scalar;
mod support;
mod transfer;
mod vectored;

pub use descriptor::sys_sync;
pub(crate) use descriptor::{sys_fdatasync, sys_fsync, sys_getdents64, sys_lseek, sys_pipe2};
#[cfg(feature = "qperf-trace")]
use markers::OutputMarkerScanner;
pub(crate) use readiness::*;
pub(crate) use scalar::*;
use support::{
    MAX_IO_CHUNK, fault_in_user_io_range, iov_len_to_usize, read_ppoll_timeout,
    requested_poll_revents,
};
pub(crate) use transfer::*;
pub(crate) use vectored::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum UserWriteSource {
    Pinned,
    Scratch,
}

/// Invokes a potentially sleepable reader with a stable user destination.
///
/// The fast path pins a physically contiguous run. If that cannot be done,
/// read into a reusable kernel buffer before copying to the user range. This
/// avoids retaining an unpinned user pointer across `block_on`.
fn read_into_user(
    user_addr: usize,
    requested: usize,
    fallback: &mut Option<ScratchBuffer>,
    mut reader: impl FnMut(&mut [u8]) -> Result<usize, LinuxError>,
) -> Result<(usize, usize), LinuxError> {
    debug_assert!(requested > 0);
    debug_assert!(requested <= MAX_IO_CHUNK);

    if let Some(mut pinned) = pin_user_write_slice(user_addr, requested) {
        let submitted = pinned.as_slice().len();
        let read = reader(pinned.as_mut_slice())?;
        if read > submitted {
            return Err(LinuxError::EIO);
        }
        return Ok((read, submitted));
    }

    if !fault_in_user_io_range(user_addr, requested, true) {
        return Err(LinuxError::EFAULT);
    }

    let buffer = match fallback {
        Some(buffer) => buffer,
        None => {
            // A vectored call can encounter a short fragmented element before
            // a later 64 KiB one, so keep the reusable buffer at the chunk
            // ceiling instead of sizing it to the first fallback.
            *fallback = Some(alloc_uninit_bytes(MAX_IO_CHUNK, "sys_read.tmp")?);
            fallback.as_mut().unwrap()
        }
    };
    let read = reader(&mut buffer[..requested])?;
    if read > requested {
        return Err(LinuxError::EIO);
    }
    let copied = write_user_bytes_partial(user_addr, &buffer[..read])?;
    if read != 0 && copied == 0 {
        return Err(LinuxError::EFAULT);
    }
    Ok((copied, requested))
}

/// Invokes a potentially sleepable writer with a stable user source.
///
/// A pinned, physically contiguous user run takes the no-copy path. Other
/// mappings are copied into a reusable kernel buffer before a writer can wait,
/// so pipes and regular files have the same lifetime guarantee.
fn write_from_user(
    user_addr: usize,
    requested: usize,
    fallback: &mut Option<ScratchBuffer>,
    mut writer: impl FnMut(&[u8]) -> Result<usize, LinuxError>,
) -> Result<(usize, usize, UserWriteSource), LinuxError> {
    debug_assert!(requested > 0);
    debug_assert!(requested <= MAX_IO_CHUNK);

    if let Some(pinned) = pin_user_read_slice(user_addr, requested) {
        let submitted = pinned.as_slice().len();
        let written = writer(pinned.as_slice())?;
        if written > submitted {
            return Err(LinuxError::EIO);
        }
        return Ok((written, submitted, UserWriteSource::Pinned));
    }

    if !fault_in_user_io_range(user_addr, requested, false) {
        return Err(LinuxError::EFAULT);
    }

    let buffer = match fallback {
        Some(buffer) => buffer,
        None => {
            *fallback = Some(alloc_uninit_bytes(MAX_IO_CHUNK, "sys_write.tmp")?);
            fallback.as_mut().unwrap()
        }
    };
    let copied = read_user_bytes_partial(user_addr, &mut buffer[..requested])?;
    if copied == 0 {
        return Err(LinuxError::EFAULT);
    }
    let written = writer(&buffer[..copied])?;
    if written > copied {
        return Err(LinuxError::EIO);
    }
    Ok((written, copied, UserWriteSource::Scratch))
}
