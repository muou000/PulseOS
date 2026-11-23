//! Execution context captured by the submitting task, or by the owner at SQPOLL setup.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use axerrno::{LinuxError, LinuxResult};
use axfs::FsContext;
use pulse_user_abi::{FromUserAbi, IntoUserAbi};

use crate::fd_table::{FdEntry, FdObject, FdTable, SharedFdTable};
use crate::task::{
    AddressSpaceLock, Credentials, Process, Thread, current_process, current_thread, uaccess,
};

/// Process, credential, and filesystem snapshot owned by an async `io_uring` request.
///
/// Futures polled by `KernelExecutor` or jobs executed on the Path 3 worker pool must
/// resolve FDs, access user memory, and evaluate path roots strictly through this snapshot
/// rather than falling back to `current_process()`.
#[derive(Clone)]
pub struct AsyncExecContext {
    pub process: Arc<Process>,
    /// The poller owns the setup-time table. Pending requests borrow its identity
    /// so they cannot retain a table containing their own ring after teardown.
    sqpoll_files: Option<Weak<spin::RwLock<FdTable>>>,
    /// Retain the submitting image even if an already-running job races exec cancellation.
    pub(super) aspace: Arc<AddressSpaceLock>,
    pub thread: Option<Arc<Thread>>,
    pub credentials: Arc<Credentials>,
    pub fs_context: FsContext,
}

impl AsyncExecContext {
    /// Captures an immutable execution context from the submitting thread's process.
    pub fn capture_current() -> LinuxResult<Self> {
        let process = current_process()?;
        let thread = current_thread().ok();
        let credentials = process.credentials.read().clone();
        let aspace = process.aspace_handle();
        let mut fs_context = process.fs_context_handle().lock().clone();
        fs_context.credentials = Some((credentials.fsuid, credentials.fsgid));
        Ok(Self {
            process,
            aspace,
            sqpoll_files: None,
            thread,
            credentials,
            fs_context,
        })
    }

    pub(super) fn share_sqpoll_files(&mut self) -> SharedFdTable {
        let files = self.process.fd_table();
        self.sqpoll_files = Some(Arc::downgrade(&files));
        files
    }

    pub(super) fn files(&self) -> LinuxResult<SharedFdTable> {
        match &self.sqpoll_files {
            Some(files) => files.upgrade().ok_or(LinuxError::EBADF),
            None => Ok(self.process.fd_table()),
        }
    }

    #[inline]
    pub fn is_user_range(&self, user_addr: usize, len: usize) -> bool {
        self.process.is_user_range(user_addr, len)
    }

    #[inline]
    pub fn read_value<T: FromUserAbi>(&self, user_addr: usize) -> LinuxResult<T> {
        Ok(uaccess::read_user_value_with(user_addr, |addr, dst| {
            self.aspace.read_user_bytes_partial(addr, dst)
        })?)
    }

    #[inline]
    pub fn write_value<T: IntoUserAbi>(&self, user_addr: usize, value: &T) -> LinuxResult<()> {
        Ok(uaccess::write_user_value_with(user_addr, value, |addr, src| {
            self.aspace.write_user_bytes_partial(addr, src)
        })?)
    }

    #[inline]
    pub fn read_array<T: FromUserAbi>(&self, user_addr: usize, count: usize) -> LinuxResult<Vec<T>> {
        let len = uaccess::checked_abi_array_size::<T>(count)?;
        uaccess::validate_user_range(user_addr, len)?;
        Ok(uaccess::read_user_array_with(user_addr, count, |addr, dst| {
            self.aspace.read_user_bytes_partial(addr, dst)
        })?)
    }

    #[inline]
    pub fn read_bytes(&self, user_addr: usize, dst: &mut [u8]) -> LinuxResult<()> {
        self.aspace
            .read_user_bytes_partial(user_addr, dst)
            .map(|_| ())
            .map_err(LinuxError::from)
    }

    #[inline]
    pub fn write_bytes(&self, user_addr: usize, src: &[u8]) -> LinuxResult<()> {
        self.aspace
            .write_user_bytes_partial(user_addr, src)
            .map(|_| ())
            .map_err(LinuxError::from)
    }

    #[inline]
    pub fn get_fd_entry(&self, fd: i32) -> LinuxResult<FdEntry> {
        let fd_usize = usize::try_from(fd).map_err(|_| LinuxError::EBADF)?;
        self.files()?.read().get_entry_cloned(fd_usize)
    }

    #[inline]
    pub fn insert_fd_entry(&self, entry: FdEntry) -> LinuxResult<usize> {
        self.process.insert_fd_entry_into(&self.files()?, entry)
    }

    #[inline]
    pub fn get_fd_object(&self, fd: i32) -> LinuxResult<Arc<dyn FdObject>> {
        Ok(self.get_fd_entry(fd)?.object)
    }
}
