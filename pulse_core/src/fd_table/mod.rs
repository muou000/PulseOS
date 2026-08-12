use alloc::{
    boxed::Box,
    collections::BTreeMap,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    time::Duration,
};

use axerrno::{LinuxError, LinuxResult};
use axfs::{File, FileFlags as AxFileFlags, OpenResult};
use axfs_ng_vfs::{Location, Metadata, NodeType};
use axhal::paging::MappingFlags;
use axio::{PollState, Seek, SeekFrom, Write};
use kspin::{SpinNoIrq, SpinNoPreempt};
use linux_raw_sys::{
    general::*,
    ioctl::{FIONBIO, FIONREAD},
};
use memory_addr::{PhysAddr, VirtAddr};
use spin::{Lazy, Mutex, RwLock};

use crate::cpu_dma_latency::{CpuDmaLatencyRequest, effective_latency_us};

pub const FD_RESERVED: usize = 3;
pub const FD_LIMIT: usize = 1048576;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FdFlags: u32 {
        const CLOEXEC = 1 << 0;
        const NONBLOCK = 1 << 1;
        const PATH = 1 << 2;
    }
}

/// Owns one waker registration made while polling an fd.
pub struct PollRegistration {
    cancel: Option<Box<dyn FnOnce() + Send + 'static>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PollEventSequence {
    pub readable: u64,
    pub writable: u64,
}

impl PollRegistration {
    pub fn new(cancel: impl FnOnce() + Send + 'static) -> Self {
        Self {
            cancel: Some(Box::new(cancel)),
        }
    }
}

impl Drop for PollRegistration {
    fn drop(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel();
        }
    }
}

pub trait FdObject: Send + Sync {
    fn as_any(&self) -> &dyn Any;

    fn ioctl(&self, _cmd: u32, _arg: usize) -> LinuxResult<isize> {
        Err(LinuxError::ENOTTY)
    }

    fn set_pipe_size(&self, _size: usize) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn get_pipe_size(&self) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    /// Tries to satisfy a read without suspending.
    ///
    /// `None` means the caller must use [`Self::read`] for the regular path;
    /// `Some` contains the exact read result, including errors.
    fn try_read_resident(&self, _buf: &mut [u8]) -> Option<LinuxResult<usize>> {
        None
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    /// Whether writes to this object must participate in TTY output ordering.
    fn is_tty_output(&self) -> bool {
        false
    }

    fn stat(&self) -> LinuxResult<stat>;

    fn poll(&self) -> LinuxResult<PollState>;

    /// Waits until this object is likely ready for `events`.
    ///
    /// Returns:
    /// - `Ok(true)`: awakened for readiness (or equivalent wake event).
    /// - `Ok(false)`: timed out before readiness.
    /// - `Err(EOPNOTSUPP)`: object does not support blocking-ready wait.
    fn wait_ready(&self, _events: i16, _deadline: Option<Duration>) -> LinuxResult<bool> {
        Err(LinuxError::EOPNOTSUPP)
    }

    /// Gets the wait queues associated with the requested events for this object.
    /// Returns Ok(true) if wait queues are supported by this object, or Ok(false) otherwise.
    fn get_wait_queues<'a>(
        &'a self,
        _events: i16,
        _wqs: &mut alloc::vec::Vec<&'a axtask::WaitQueue>,
    ) -> LinuxResult<bool> {
        Ok(false)
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    /// Registers a waker for the requested events.
    ///
    /// The default implementation returns [`LinuxError::EOPNOTSUPP`]. This
    /// ensures that any `FdObject` which does not explicitly support
    /// waker-based wait (and therefore cannot wake a blocked epoll/poll
    /// caller) cannot silently break waker-based waiters. Concrete
    /// implementations that *do* support such waiting (e.g. `PipeObject`,
    /// `EventFdObject`, `StdinObject`, `EpollObject`, `Socket`, `PidfdObject`)
    /// must override this method and register the waker on their underlying
    /// wait queue.
    fn register_poll(
        self: Arc<Self>,
        _cx: &mut core::task::Context<'_>,
        _events: axpoll::IoEvents,
        _registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        Err(LinuxError::EOPNOTSUPP)
    }

    fn location(&self) -> Option<Location> {
        None
    }

    fn fifo_device_inode(&self) -> Option<(u64, u64)> {
        None
    }

    fn seek(&self, _pos: SeekFrom) -> LinuxResult<u64> {
        Err(LinuxError::ESPIPE)
    }

    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> LinuxResult<usize> {
        Err(LinuxError::ESPIPE)
    }

    /// Positional counterpart of [`Self::try_read_resident`].
    fn try_read_at_resident(&self, _buf: &mut [u8], _offset: u64) -> Option<LinuxResult<usize>> {
        None
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> LinuxResult<usize> {
        Err(LinuxError::ESPIPE)
    }

    fn mmap_file_flags(&self) -> Option<AxFileFlags> {
        None
    }

    fn mmap_write_access(&self) -> Option<axfs::WriteAccessGuard> {
        None
    }

    fn as_ns_fd(&self) -> Option<(u64, u32)> {
        None
    }

    fn read_dirents64(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::ENOTDIR)
    }

    fn truncate(&self, _len: u64) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }

    fn flush(&self) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }

    fn sync_data(&self) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }

    fn allocate(&self, _mode: u32, _offset: u64, _len: u64) -> LinuxResult {
        Err(LinuxError::ENODEV)
    }

    fn is_write_open(&self) -> bool {
        false
    }

    fn is_read_open(&self) -> bool {
        false
    }

    fn is_rdhup(&self) -> bool {
        false
    }

    fn poll_set(&self) -> Option<&axpoll::PollSet> {
        None
    }

    fn nonblocking_state(&self) -> Option<bool> {
        None
    }

    fn poll_event_sequence(&self) -> Option<PollEventSequence> {
        None
    }
}

#[derive(Clone)]
pub struct FdEntry {
    pub object: Arc<dyn FdObject>,
    pub flags: FdFlags,
    open_file_description: Arc<OpenFileDescription>,
}

struct OpenFileDescription;

impl Drop for OpenFileDescription {
    fn drop(&mut self) {
        let owner = self as *const OpenFileDescription as usize;
        crate::record_lock::release_ofd_owner(owner);
    }
}

impl FdEntry {
    pub fn new(object: Arc<dyn FdObject>, flags: FdFlags) -> Self {
        Self {
            object,
            flags,
            open_file_description: Arc::new(OpenFileDescription),
        }
    }

    pub fn duplicate(&self, flags: FdFlags) -> Self {
        Self {
            object: self.object.clone(),
            flags,
            open_file_description: self.open_file_description.clone(),
        }
    }

    pub fn ofd_owner(&self) -> usize {
        Arc::as_ptr(&self.open_file_description) as usize
    }
}

fn empty_stat() -> stat {
    unsafe { core::mem::zeroed() }
}

fn metadata_to_stat(metadata: &Metadata) -> stat {
    let ty = metadata.node_type as u8;
    let perm = metadata.mode.bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    stat {
        st_dev: metadata.device as _,
        st_ino: metadata.inode as _,
        st_nlink: metadata.nlink as _,
        st_mode,
        st_uid: metadata.uid as _,
        st_gid: metadata.gid as _,
        st_size: metadata.size as _,
        st_blocks: metadata.blocks as _,
        st_blksize: metadata.block_size as _,
        st_atime: metadata.atime.as_secs() as _,
        st_atime_nsec: metadata.atime.subsec_nanos() as _,
        st_mtime: metadata.mtime.as_secs() as _,
        st_mtime_nsec: metadata.mtime.subsec_nanos() as _,
        st_ctime: metadata.ctime.as_secs() as _,
        st_ctime_nsec: metadata.ctime.subsec_nanos() as _,
        st_rdev: metadata.rdev.0 as _,
        ..empty_stat()
    }
}

pub fn location_to_stat(location: &Location) -> LinuxResult<stat> {
    let mut st = metadata_to_stat(&axtask::future::block_on(location.metadata())?);
    if let Some(size) = axfs::cached_file_size_if_present(location) {
        st.st_size = size as _;
    }
    Ok(st)
}

mod epoll;
mod objects;
mod pipe;
mod signalfd;
mod table;
mod tty;

pub use epoll::*;
pub use objects::*;
pub use pipe::*;
pub use signalfd::*;
pub use table::*;
pub use tty::*;
