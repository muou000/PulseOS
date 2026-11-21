//! Immutable execution context snapshot captured at `io_uring_enter` submission time.

use alloc::sync::Arc;
use alloc::vec::Vec;

use axerrno::{LinuxError, LinuxResult};
use axfs::FsContext;
use pulse_user_abi::{FromUserAbi, IntoUserAbi};

use crate::fd_table::{FdEntry, FdObject};
use crate::task::{Credentials, Process, current_process, uaccess};

/// Process, credential, and filesystem snapshot owned by an async `io_uring` request.
///
/// Futures polled by `KernelExecutor` or jobs executed on the Path 3 worker pool must
/// resolve FDs, access user memory, and evaluate path roots strictly through this snapshot
/// rather than falling back to `current_process()`.
#[derive(Clone)]
pub struct AsyncExecContext {
    pub process: Arc<Process>,
    pub credentials: Arc<Credentials>,
    pub fs_context: FsContext,
}

impl AsyncExecContext {
    /// Captures an immutable execution context from the submitting thread's process.
    pub fn capture_current() -> LinuxResult<Self> {
        let process = current_process()?;
        let credentials = process.credentials.read().clone();
        let fs_context = process.fs_context_handle().lock().clone();
        Ok(Self {
            process,
            credentials,
            fs_context,
        })
    }

    #[inline]
    pub fn is_user_range(&self, user_addr: usize, len: usize) -> bool {
        self.process.is_user_range(user_addr, len)
    }

    #[inline]
    pub fn read_value<T: FromUserAbi>(&self, user_addr: usize) -> LinuxResult<T> {
        uaccess::read_user_value(&self.process, user_addr).map_err(LinuxError::from)
    }

    #[inline]
    pub fn write_value<T: IntoUserAbi>(&self, user_addr: usize, value: &T) -> LinuxResult<()> {
        uaccess::write_user_value(&self.process, user_addr, value).map_err(LinuxError::from)
    }

    #[inline]
    pub fn read_array<T: FromUserAbi>(&self, user_addr: usize, count: usize) -> LinuxResult<Vec<T>> {
        uaccess::read_user_value_array(&self.process, user_addr, count).map_err(LinuxError::from)
    }

    #[inline]
    pub fn read_bytes(&self, user_addr: usize, dst: &mut [u8]) -> LinuxResult<()> {
        self.process
            .read_user_bytes(user_addr, dst)
            .map_err(LinuxError::from)
    }

    #[inline]
    pub fn write_bytes(&self, user_addr: usize, src: &[u8]) -> LinuxResult<()> {
        self.process
            .write_user_bytes(user_addr, src)
            .map_err(LinuxError::from)
    }

    #[inline]
    pub fn get_fd_entry(&self, fd: i32) -> LinuxResult<FdEntry> {
        let fd_usize = usize::try_from(fd).map_err(|_| LinuxError::EBADF)?;
        self.process.get_fd_entry(fd_usize)
    }

    #[inline]
    pub fn insert_fd_entry(&self, entry: FdEntry) -> LinuxResult<usize> {
        self.process.insert_fd_entry(entry)
    }

    #[inline]
    pub fn get_fd_object(&self, fd: i32) -> LinuxResult<Arc<dyn FdObject>> {
        Ok(self.get_fd_entry(fd)?.object)
    }
}
