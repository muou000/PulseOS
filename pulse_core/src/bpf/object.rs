use alloc::sync::Arc;
use core::any::Any;

use axerrno::{LinuxError, LinuxResult};
use axio::PollState;
use linux_raw_sys::general::stat;

use super::BpfMap;
use crate::fd_table::{FdObject, PollEventSequence, PollRegistration};

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
        if cmd == super::PERF_EVENT_IOC_SET_BPF {
            let process = crate::task::current_process()?;
            let obj = process.get_fd_object(arg)?;
            let Some(prog_obj) = obj.as_any().downcast_ref::<BpfProgramObject>() else {
                return Err(LinuxError::EINVAL);
            };
            self.event.attach_program(prog_obj.program().clone())?;
            return Ok(0);
        }
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
            readable: self.event.is_readable(),
            writable: false,
        })
    }

    fn poll_event_sequence(&self) -> Option<PollEventSequence> {
        Some(PollEventSequence {
            readable: self.event.poll_event_sequence(),
            writable: 0,
        })
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: axpoll::IoEvents,
        registrations: &mut alloc::vec::Vec<PollRegistration>,
    ) -> LinuxResult {
        #[cfg(target_os = "none")]
        {
            if events.contains(axpoll::IoEvents::IN) {
                let owner = self.clone();
                let registration = owner.event.read_wait_queue().register_owned_waker(cx.waker());
                registrations.push(PollRegistration::new(move || {
                    owner.event.read_wait_queue().unregister_waker(registration);
                }));
            }
            Ok(())
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (cx, events, registrations);
            Ok(())
        }
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut alloc::vec::Vec<&'a axtask::WaitQueue>,
    ) -> LinuxResult<bool> {
        #[cfg(target_os = "none")]
        {
            if (events & (linux_raw_sys::general::POLLIN as i16)) != 0 {
                wqs.push(self.event.read_wait_queue());
                return Ok(true);
            }
            Ok(events == 0)
        }
        #[cfg(not(target_os = "none"))]
        {
            let _ = (events, wqs);
            Ok(false)
        }
    }

    fn mmap_file_flags(&self) -> Option<axfs::FileFlags> {
        Some(axfs::FileFlags::READ | axfs::FileFlags::WRITE)
    }

    fn mmap_prepared(
        &self,
        size: usize,
        flags: axhal::paging::MappingFlags,
        offset: usize,
        is_shared: bool,
    ) -> Option<LinuxResult<axmm::PreparedMapping>> {
        if !is_shared || offset != 0 {
            return Some(Err(LinuxError::EINVAL));
        }
        if size <= 4096 || size % 4096 != 0 {
            return Some(Err(LinuxError::EINVAL));
        }
        let nr_data_pages = (size / 4096) - 1;
        if !nr_data_pages.is_power_of_two() {
            return Some(Err(LinuxError::EINVAL));
        }

        let buf = if let Some(existing) = self.event.buffer() {
            if existing.total_size() != size {
                return Some(Err(LinuxError::EINVAL));
            }
            existing
        } else {
            match super::perf_event::PerfBuffer::new(nr_data_pages) {
                Ok(new_buf) => {
                    self.event.set_buffer(new_buf.clone());
                    new_buf
                }
                Err(e) => return Some(Err(e)),
            }
        };

        #[cfg(target_os = "none")]
        {
            let Some(shared_frame) = buf.shared_frame() else {
                return Some(Err(LinuxError::ENOMEM));
            };
            Some(axmm::PreparedMapping::shared_frame(size, flags, shared_frame).map_err(LinuxError::from))
        }

        #[cfg(not(target_os = "none"))]
        {
            let _ = buf;
            Some(Err(LinuxError::EOPNOTSUPP))
        }
    }
}

/// A BPF Link object FD (#98).
pub struct BpfLinkObject {
    link: Arc<super::BpfLink>,
}

impl BpfLinkObject {
    pub fn new(link: Arc<super::BpfLink>) -> Self {
        Self { link }
    }

    pub fn link(&self) -> &Arc<super::BpfLink> {
        &self.link
    }

    pub fn info(&self) -> super::BpfLinkInfo {
        self.link.info()
    }
}

impl FdObject for BpfLinkObject {
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


