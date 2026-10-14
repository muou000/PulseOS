use alloc::sync::Arc;
use core::any::Any;

use axerrno::{LinuxError, LinuxResult};
use axio::PollState;
use linux_raw_sys::general::stat;

use super::BpfMap;
use crate::fd_table::FdObject;

/// A BPF Map object FD.
///
/// Like Linux `bpf-map` anon-inode files, the descriptor is not readable or
/// writable. `poll`, `ioctl` and `mmap` are explicitly unsupported in this
/// slice: `poll` reports an error (surfaced as `POLLERR`), `ioctl` returns
/// `ENOTTY`, and `mmap` fails because the object has no file location.
pub struct BpfMapObject {
    map: Arc<BpfMap>,
}

impl BpfMapObject {
    pub fn new(map: Arc<BpfMap>) -> Self {
        Self { map }
    }

    pub fn map(&self) -> &Arc<BpfMap> {
        &self.map
    }

    pub fn info(&self) -> super::BpfMapInfo {
        self.map.info()
    }
}

impl FdObject for BpfMapObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> LinuxResult<isize> {
        Err(LinuxError::ENOTTY)
    }

    fn stat(&self) -> LinuxResult<stat> {
        // Anonymous inode: owner read/write, regular file mode matching Linux anon_inode.
        let mut st: stat = unsafe { core::mem::zeroed() };
        st.st_ino = 1;
        st.st_mode = linux_raw_sys::general::S_IFREG | 0o600;
        st.st_nlink = 1;
        st.st_blksize = 4096;
        Ok(st)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Err(LinuxError::EOPNOTSUPP)
    }

    /// Memory mapping is explicitly unsupported for BPF Maps in this slice.
    fn mmap_file_flags(&self) -> Option<axfs::FileFlags> {
        None
    }
}

/// A BPF Program object FD.
///
/// Follows the same object lifecycle and permissions as BpfMapObject.
pub struct BpfProgramObject {
    program: Arc<super::BpfProgram>,
}

impl BpfProgramObject {
    pub fn new(program: Arc<super::BpfProgram>) -> Self {
        Self { program }
    }

    pub fn program(&self) -> &Arc<super::BpfProgram> {
        &self.program
    }

    pub fn info(&self) -> super::BpfProgInfo {
        self.program.info()
    }
}

impl FdObject for BpfProgramObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn ioctl(&self, _cmd: u32, _arg: usize) -> LinuxResult<isize> {
        Err(LinuxError::ENOTTY)
    }

    fn stat(&self) -> LinuxResult<stat> {
        let mut st: stat = unsafe { core::mem::zeroed() };
        st.st_ino = 1;
        st.st_mode = linux_raw_sys::general::S_IFREG | 0o600;
        st.st_nlink = 1;
        st.st_blksize = 4096;
        Ok(st)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Err(LinuxError::EOPNOTSUPP)
    }

    fn mmap_file_flags(&self) -> Option<axfs::FileFlags> {
        None
    }
}

