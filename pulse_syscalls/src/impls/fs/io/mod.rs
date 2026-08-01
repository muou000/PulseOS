use core::time::Duration;

use axerrno::{AxError, LinuxError};
use axio::SeekFrom;
use linux_raw_sys::general::{
    O_CLOEXEC, O_NONBLOCK, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, S_IFDIR, S_IFMT, S_IFREG,
    pollfd,
};
use pulse_core::{
    fd_table::{EventFdObject, FD_LIMIT, FdObject, FileObject, pipe_entries},
    task::uaccess,
};

use crate::impls::{
    fs::common::{get_fd_entry, open_fd_flags, remove_fd_entry},
    utils::{
        alloc_uninit_bytes, query_user_page_slice, read_user_bytes_partial, read_user_i64,
        read_user_iovec_array, read_user_timespec, with_process, write_user_bytes, write_user_i64,
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
#[cfg(any(feature = "qperf-trace", feature = "buildstorm-stats"))]
use markers::OutputMarkerScanner;
pub(crate) use readiness::*;
pub(crate) use scalar::*;
use support::{
    MAX_IO_CHUNK, fault_in_user_io_range, iov_len_to_usize, read_ppoll_timeout,
    requested_poll_revents,
};
pub(crate) use transfer::*;
pub(crate) use vectored::*;
