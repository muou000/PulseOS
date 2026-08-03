use alloc::sync::Arc;
use core::{
    any::Any,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use axerrno::{LinuxError, LinuxResult};
use axio::PollState;
use linux_raw_sys::general::{
    POLLIN, SI_SIGIO, SI_TIMER, SI_USER, SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGSEGV, SIGSYS,
    SIGTRAP, S_IFREG, siginfo,
};

use super::{FdObject, PollRegistration, empty_stat};

const SIGNALFD_SIGINFO_SIZE: usize = 128;
const _: [(); SIGNALFD_SIGINFO_SIZE] = [(); core::mem::size_of::<siginfo>()];

/// The fixed-size userspace record returned by signalfd reads.
///
/// This intentionally is not `siginfo_t`: Linux exposes a stable 128-byte
/// layout so a caller's ABI does not change with `siginfo_t` internals.
#[repr(C)]
#[derive(Clone, Copy)]
struct SignalFdSigInfo {
    ssi_signo: u32,
    ssi_errno: i32,
    ssi_code: i32,
    ssi_pid: u32,
    ssi_uid: u32,
    ssi_fd: i32,
    ssi_tid: u32,
    ssi_band: u32,
    ssi_overrun: u32,
    ssi_trapno: u32,
    ssi_status: i32,
    ssi_int: i32,
    ssi_ptr: u64,
    ssi_utime: u64,
    ssi_stime: u64,
    ssi_addr: u64,
    ssi_addr_lsb: u16,
    __pad2: u16,
    ssi_syscall: i32,
    ssi_call_addr: u64,
    ssi_arch: u32,
    __pad: [u8; 28],
}

const _: [(); SIGNALFD_SIGINFO_SIZE] = [(); core::mem::size_of::<SignalFdSigInfo>()];

fn is_fault_signal(sig: i32) -> bool {
    matches!(
        sig as u32,
        SIGSEGV | SIGBUS | SIGILL | SIGTRAP | SIGFPE | SIGSYS
    )
}

fn signalfd_info_bytes(raw: [u8; SIGNALFD_SIGINFO_SIZE]) -> [u8; SIGNALFD_SIGINFO_SIZE] {
    let info: siginfo = unsafe { core::mem::transmute(raw) };
    let mut out: SignalFdSigInfo = unsafe { core::mem::zeroed() };

    unsafe {
        let header = info.__bindgen_anon_1.__bindgen_anon_1;
        out.ssi_signo = header.si_signo as u32;
        out.ssi_errno = header.si_errno;
        out.ssi_code = header.si_code;

        match header.si_code {
            SI_TIMER => {
                let timer = header._sifields._timer;
                out.ssi_tid = timer._tid as u32;
                out.ssi_overrun = timer._overrun as u32;
                out.ssi_ptr = timer._sigval.sival_ptr as usize as u64;
                out.ssi_int = timer._sigval.sival_int;
            }
            SI_SIGIO => {
                let poll = header._sifields._sigpoll;
                out.ssi_band = poll._band as u32;
                out.ssi_fd = poll._fd;
            }
            code if code == SI_USER as i32 => {
                let kill = header._sifields._kill;
                out.ssi_pid = kill._pid as u32;
                out.ssi_uid = kill._uid;
            }
            code if code > 0 && header.si_signo == SIGCHLD as i32 => {
                let child = header._sifields._sigchld;
                out.ssi_pid = child._pid as u32;
                out.ssi_uid = child._uid;
                out.ssi_status = child._status;
                out.ssi_utime = child._utime as u64;
                out.ssi_stime = child._stime as u64;
            }
            code if code > 0 && header.si_signo == SIGSYS as i32 => {
                let sys = header._sifields._sigsys;
                out.ssi_call_addr = sys._call_addr as usize as u64;
                out.ssi_syscall = sys._syscall;
                out.ssi_arch = sys._arch;
            }
            code if code > 0 && is_fault_signal(header.si_signo) => {
                let fault = header._sifields._sigfault;
                out.ssi_addr = fault._addr as usize as u64;
            }
            _ => {
                // SI_QUEUE and the other negative user-generated codes use
                // the real-time payload layout, which is also how Linux
                // represents SI_TKILL in signalfd_siginfo.
                let rt = header._sifields._rt;
                out.ssi_pid = rt._pid as u32;
                out.ssi_uid = rt._uid;
                out.ssi_ptr = rt._sigval.sival_ptr as usize as u64;
                out.ssi_int = rt._sigval.sival_int;
            }
        }
    }

    unsafe { core::mem::transmute(out) }
}

fn minimal_siginfo(sig: usize) -> [u8; SIGNALFD_SIGINFO_SIZE] {
    let mut raw = [0u8; SIGNALFD_SIGINFO_SIZE];
    raw[..core::mem::size_of::<i32>()].copy_from_slice(&(sig as i32).to_ne_bytes());
    raw
}

/// A signalfd consumes pending signals from the thread that performs the
/// operation.  The descriptor's mask is shared by duplicated descriptors,
/// while the pending queues remain owned by `ThreadSignal`, matching Linux's
/// current-thread read and poll behavior.
pub struct SignalFdObject {
    mask: AtomicU64,
    nonblocking: AtomicBool,
    mask_wait_queue: axtask::WaitQueue,
}

impl SignalFdObject {
    pub fn new(mask: u64, nonblocking: bool) -> Self {
        Self {
            mask: AtomicU64::new(mask),
            nonblocking: AtomicBool::new(nonblocking),
            mask_wait_queue: axtask::WaitQueue::new(),
        }
    }

    pub fn mask(&self) -> u64 {
        self.mask.load(Ordering::Acquire)
    }

    pub fn set_mask(&self, mask: u64) {
        self.mask.store(mask, Ordering::Release);
        self.mask_wait_queue.notify_all(true);
    }

    fn is_readable(&self, thread: &crate::task::Thread) -> bool {
        thread.has_waitset_signal(self.mask())
    }

    fn wait_for_signal(&self, thread: &Arc<crate::task::Thread>) {
        let wait_queues = [thread.signal_wait_queue(), &self.mask_wait_queue];
        let _ = axtask::WaitQueue::wait_multiple_timeout_until(&wait_queues, None, || {
            self.is_readable(thread.as_ref()) || thread.has_pending_signal()
        });
    }

    fn wait_for_ready(
        &self,
        thread: &Arc<crate::task::Thread>,
        deadline: Option<Duration>,
    ) -> LinuxResult<bool> {
        if self.is_readable(thread.as_ref()) {
            return Ok(true);
        }

        let remaining = match deadline {
            Some(deadline) => {
                let now = axhal::time::monotonic_time();
                if now >= deadline {
                    return Ok(false);
                }
                Some(deadline - now)
            }
            None => None,
        };
        let wait_queues = [thread.signal_wait_queue(), &self.mask_wait_queue];
        let _ = axtask::WaitQueue::wait_multiple_timeout_until(
            &wait_queues,
            remaining,
            || self.is_readable(thread.as_ref()) || thread.has_pending_signal(),
        );

        if self.is_readable(thread.as_ref()) {
            return Ok(true);
        }
        if thread.has_pending_signal() {
            return Err(LinuxError::EINTR);
        }
        Ok(false)
    }
}

impl FdObject for SignalFdObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if buf.len() < SIGNALFD_SIGINFO_SIZE {
            return Err(LinuxError::EINVAL);
        }

        let thread = crate::task::current_thread()?;
        let max_records = buf.len() / SIGNALFD_SIGINFO_SIZE;
        let mut written = 0usize;

        while written / SIGNALFD_SIGINFO_SIZE < max_records {
            if let Some((sig, info)) = thread.dequeue_waitset_signal(self.mask()) {
                let raw = info.unwrap_or_else(|| minimal_siginfo(sig));
                let end = written + SIGNALFD_SIGINFO_SIZE;
                buf[written..end].copy_from_slice(&signalfd_info_bytes(raw));
                written = end;
                continue;
            }

            if written != 0 {
                return Ok(written);
            }
            if self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }

            self.wait_for_signal(&thread);
            if !self.is_readable(thread.as_ref()) && thread.has_pending_signal() {
                return Err(LinuxError::EINTR);
            }
        }

        Ok(written)
    }

    // Linux creates signalfd anonymous inodes with O_RDWR, but provides no
    // write operation. The access mode therefore permits write(2) to reach
    // this object, which rejects it with EINVAL rather than EBADF.
    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> LinuxResult<linux_raw_sys::general::stat> {
        Ok(linux_raw_sys::general::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: S_IFREG | 0o600,
            st_blksize: 4096,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let thread = crate::task::current_thread()?;
        Ok(PollState {
            readable: self.is_readable(thread.as_ref()),
            writable: false,
        })
    }

    fn wait_ready(&self, events: i16, deadline: Option<Duration>) -> LinuxResult<bool> {
        if (events & POLLIN as i16) == 0 {
            return Err(LinuxError::EOPNOTSUPP);
        }
        let thread = crate::task::current_thread()?;
        self.wait_for_ready(&thread, deadline)
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut alloc::vec::Vec<&'a axtask::WaitQueue>,
    ) -> LinuxResult<bool> {
        if (events & POLLIN as i16) != 0 {
            // The caller's signal queue is registered separately by the
            // generic poll/epoll paths; this queue handles signalfd mask
            // updates that can make a pending signal readable.
            wqs.push(&self.mask_wait_queue);
            return Ok(true);
        }
        Ok(events == 0)
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: axpoll::IoEvents,
        registrations: &mut alloc::vec::Vec<PollRegistration>,
    ) -> LinuxResult {
        if !events.contains(axpoll::IoEvents::IN) {
            return Ok(());
        }

        let thread = crate::task::current_thread()?;
        let signal_registration = thread.signal_wait_queue().register_owned_waker(cx.waker());
        let signal_owner = thread.clone();
        registrations.push(PollRegistration::new(move || {
            signal_owner
                .signal_wait_queue()
                .unregister_waker(signal_registration);
        }));

        let mask_registration = self.mask_wait_queue.register_owned_waker(cx.waker());
        let mask_owner = self.clone();
        registrations.push(PollRegistration::new(move || {
            mask_owner.mask_wait_queue.unregister_waker(mask_registration);
        }));

        if self.is_readable(thread.as_ref()) {
            cx.waker().wake_by_ref();
        }
        Ok(())
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn nonblocking_state(&self) -> Option<bool> {
        Some(self.nonblocking.load(Ordering::Acquire))
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_raw_sys::general::SI_QUEUE;

    #[test]
    fn signalfd_siginfo_has_the_linux_abi_size() {
        assert_eq!(core::mem::size_of::<SignalFdSigInfo>(), SIGNALFD_SIGINFO_SIZE);
    }

    #[test]
    fn queued_signal_payload_uses_the_rt_fields() {
        let mut info: siginfo = unsafe { core::mem::zeroed() };
        unsafe {
            let header = &mut info.__bindgen_anon_1.__bindgen_anon_1;
            header.si_signo = 42;
            header.si_code = SI_QUEUE;
            header._sifields._rt._pid = 123;
            header._sifields._rt._uid = 456;
            header._sifields._rt._sigval.sival_int = 789;
        }

        let converted: SignalFdSigInfo = unsafe {
            core::mem::transmute(signalfd_info_bytes(core::mem::transmute(info)))
        };
        assert_eq!(converted.ssi_signo, 42);
        assert_eq!(converted.ssi_code, SI_QUEUE);
        assert_eq!(converted.ssi_pid, 123);
        assert_eq!(converted.ssi_uid, 456);
        assert_eq!(converted.ssi_int, 789);
    }

    #[test]
    fn write_reaches_signalfd_and_is_rejected_as_einval() {
        let signalfd = SignalFdObject::new(0, false);

        assert!(signalfd.is_write_open());
        assert!(matches!(signalfd.write(&[]), Err(LinuxError::EINVAL)));
    }
}
