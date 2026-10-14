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

/// A Perf Event object FD (#97).
///
/// Implements Linux-compatible `read` (returning 64-bit elapsed counter value)
/// and `ioctl` (ENABLE, DISABLE, RESET, PERIOD, etc.).
pub struct PerfEventObject {
    event: Arc<super::PerfEvent>,
}

impl PerfEventObject {
    pub fn new(event: Arc<super::PerfEvent>) -> Self {
        Self { event }
    }

    pub fn event(&self) -> &Arc<super::PerfEvent> {
        &self.event
    }

    pub fn current_time_ns_for_spec(spec: &super::PerfEventSpec) -> u64 {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        match (spec.clock, spec.scope) {
            (super::PerfEventClock::CpuClock, super::PerfEventScope::PerCpu { .. }) => now_ns,
            (super::PerfEventClock::TaskClock, super::PerfEventScope::Task { pid }) => {
                if let Some(proc) = crate::task::process_by_pid(pid) {
                    let (u, s) = proc.snapshot_cpu_time_ns(now_ns);
                    u.saturating_add(s)
                } else {
                    now_ns
                }
            }
            _ => now_ns,
        }
    }

    pub fn current_time_ns(&self) -> u64 {
        Self::current_time_ns_for_spec(self.event.spec())
    }
}

impl FdObject for PerfEventObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let now_ns = self.current_time_ns();
        self.event.read_into_at(buf, now_ns)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        let now_ns = self.current_time_ns();
        self.event.ioctl_at(cmd, arg, now_ns)
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
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn mmap_file_flags(&self) -> Option<axfs::FileFlags> {
        None
    }
}


