use alloc::{
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{
    any::Any,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use axerrno::{LinuxError, LinuxResult};
use io::PollState;
use task::future::{CancelHandle, global_executor, sleep_until, yield_now};
use linux_raw_sys::{
    general::{
        CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_REALTIME, O_CLOEXEC, O_NONBLOCK, POLLIN, S_IFREG,
        stat,
    },
    ioctl::{FIONBIO, FIONREAD},
};
use spin::Mutex;

use super::{FdEntry, FdFlags, FdObject, PollEventSequence, PollRegistration, empty_stat};

pub const TFD_CLOEXEC: u32 = O_CLOEXEC;
pub const TFD_NONBLOCK: u32 = O_NONBLOCK;
pub const TFD_TIMER_ABSTIME: u32 = 1;
pub const TFD_TIMER_CANCEL_ON_SET: u32 = 2;

#[inline]
fn monotonic_now_ns() -> u64 {
    u64::try_from(hal::time::monotonic_time().as_nanos()).unwrap_or(u64::MAX)
}

struct TimerFdInner {
    armed: bool,
    next_deadline_ns: u64,
    interval_ns: u64,
    expirations: u64,
    generation: u64,
    cancel_handle: Option<CancelHandle>,
    readable_sequence: u64,
}

/// Linux-compatible timerfd object backed by `task::future` timers.
pub struct TimerFdObject {
    self_weak: Weak<Self>,
    clock_id: u32,
    nonblocking: AtomicBool,
    read_wait_queue: task::WaitQueue,
    inner: Mutex<TimerFdInner>,
}

impl TimerFdObject {
    fn new(clock_id: u32, nonblocking: bool) -> Arc<Self> {
        Arc::new_cyclic(|self_weak| Self {
            self_weak: self_weak.clone(),
            clock_id,
            nonblocking: AtomicBool::new(nonblocking),
            read_wait_queue: task::WaitQueue::new(),
            inner: Mutex::new(TimerFdInner {
                armed: false,
                next_deadline_ns: 0,
                interval_ns: 0,
                expirations: 0,
                generation: 0,
                cancel_handle: None,
                readable_sequence: 0,
            }),
        })
    }

    #[inline]
    fn current_has_pending_signal() -> bool {
        crate::current_have_signals()
    }

    fn refresh_expirations_locked(inner: &mut TimerFdInner, now_ns: u64) -> bool {
        if !inner.armed || now_ns < inner.next_deadline_ns {
            return false;
        }
        if inner.interval_ns == 0 {
            inner.expirations = inner.expirations.saturating_add(1);
            inner.armed = false;
            inner.next_deadline_ns = 0;
        } else {
            let elapsed = now_ns - inner.next_deadline_ns;
            let ticks = 1u64.saturating_add(elapsed / inner.interval_ns);
            inner.expirations = inner.expirations.saturating_add(ticks);
            inner.next_deadline_ns = inner
                .next_deadline_ns
                .saturating_add(ticks.saturating_mul(inner.interval_ns));
        }
        inner.readable_sequence = inner.readable_sequence.wrapping_add(1);
        true
    }

    fn has_expirations(&self) -> bool {
        let mut inner = self.inner.lock();
        let _ = Self::refresh_expirations_locked(&mut inner, monotonic_now_ns());
        inner.expirations > 0
    }

    fn spawn_timer_future(&self, generation: u64, initial_deadline_ns: u64) {
        let weak = self.self_weak.clone();
        let handle = global_executor().spawn_and_poll_once(async move {
            let mut deadline_ns = initial_deadline_ns;
            loop {
                sleep_until(Duration::from_nanos(deadline_ns)).await;
                let Some(obj) = weak.upgrade() else {
                    return;
                };
                let (notify, next_deadline) = {
                    let mut inner = obj.inner.lock();
                    if inner.generation != generation || !inner.armed {
                        return;
                    }
                    let now_ns = monotonic_now_ns();
                    let fired = Self::refresh_expirations_locked(&mut inner, now_ns);
                    let next = if inner.armed && inner.generation == generation {
                        Some(inner.next_deadline_ns)
                    } else {
                        None
                    };
                    if next.is_none() {
                        inner.cancel_handle = None;
                    }
                    (fired || inner.expirations > 0, next)
                };
                if notify && !obj.read_wait_queue.is_empty() {
                    obj.read_wait_queue.notify_all(true);
                }
                let Some(next_ns) = next_deadline else {
                    return;
                };
                if monotonic_now_ns() >= next_ns {
                    yield_now().await;
                }
                deadline_ns = next_ns;
            }
        });
        if !handle.is_done() {
            let stale = {
                let mut inner = self.inner.lock();
                if inner.generation == generation && inner.armed {
                    inner.cancel_handle.replace(handle)
                } else {
                    Some(handle)
                }
            };
            if let Some(stale) = stale {
                stale.cancel();
            }
        }
    }

    /// Arms, modifies, or disarms this timerfd and returns the previous `(remaining_ns, interval_ns)`.
    pub fn settime(
        &self,
        flags: u32,
        value_ns: u64,
        interval_ns: u64,
    ) -> LinuxResult<(u64, u64)> {
        if flags & !(TFD_TIMER_ABSTIME | TFD_TIMER_CANCEL_ON_SET) != 0 {
            return Err(LinuxError::EINVAL);
        }

        let (old_remaining_ns, old_interval_ns, old_handle, notify_now, spawn_args) = {
            let mut inner = self.inner.lock();
            let now_ns = monotonic_now_ns();
            let _ = Self::refresh_expirations_locked(&mut inner, now_ns);
            let old_remaining = if !inner.armed || now_ns >= inner.next_deadline_ns {
                0
            } else {
                inner.next_deadline_ns - now_ns
            };
            let old_interval = inner.interval_ns;
            let old_handle = inner.cancel_handle.take();

            inner.expirations = 0;
            inner.generation = inner.generation.wrapping_add(1);

            if value_ns == 0 {
                inner.armed = false;
                inner.next_deadline_ns = 0;
                inner.interval_ns = 0;
                (old_remaining, old_interval, old_handle, false, None)
            } else {
                let deadline_ns = if (flags & TFD_TIMER_ABSTIME) != 0 {
                    if self.clock_id == CLOCK_REALTIME {
                        let offset = hal::time::current_epochoffset_nanos();
                        value_ns.saturating_sub(offset)
                    } else {
                        value_ns
                    }
                } else {
                    now_ns.saturating_add(value_ns)
                };

                inner.armed = true;
                inner.next_deadline_ns = deadline_ns;
                inner.interval_ns = interval_ns;

                let fired = Self::refresh_expirations_locked(&mut inner, now_ns);
                let spawn = if inner.armed {
                    Some((inner.generation, inner.next_deadline_ns))
                } else {
                    None
                };
                (old_remaining, old_interval, old_handle, fired, spawn)
            }
        };

        if let Some(handle) = old_handle {
            handle.cancel();
        }
        if notify_now && !self.read_wait_queue.is_empty() {
            self.read_wait_queue.notify_all(true);
        }
        if let Some((generation, deadline_ns)) = spawn_args {
            self.spawn_timer_future(generation, deadline_ns);
        }
        Ok((old_remaining_ns, old_interval_ns))
    }

    /// Returns the current `(remaining_ns, interval_ns)` pair without clearing expirations.
    pub fn gettime(&self) -> (u64, u64) {
        let mut inner = self.inner.lock();
        let now_ns = monotonic_now_ns();
        let _ = Self::refresh_expirations_locked(&mut inner, now_ns);
        let remaining = if !inner.armed || now_ns >= inner.next_deadline_ns {
            0
        } else {
            inner.next_deadline_ns - now_ns
        };
        (remaining, inner.interval_ns)
    }

    fn read_inner(&self, buf: &mut [u8], force_nonblocking: bool) -> LinuxResult<usize> {
        const COUNT_SIZE: usize = core::mem::size_of::<u64>();
        if buf.len() < COUNT_SIZE {
            return Err(LinuxError::EINVAL);
        }

        loop {
            let taken = {
                let mut inner = self.inner.lock();
                let _ = Self::refresh_expirations_locked(&mut inner, monotonic_now_ns());
                if inner.expirations > 0 {
                    let count = inner.expirations;
                    inner.expirations = 0;
                    Some(count)
                } else {
                    None
                }
            };
            if let Some(count) = taken {
                buf[..COUNT_SIZE].copy_from_slice(&count.to_ne_bytes());
                return Ok(COUNT_SIZE);
            }
            if force_nonblocking || self.nonblocking.load(Ordering::Acquire) {
                return Err(LinuxError::EAGAIN);
            }
            self.read_wait_queue
                .wait_until(|| self.has_expirations() || Self::current_has_pending_signal());
            if Self::current_has_pending_signal() {
                return Err(LinuxError::EINTR);
            }
        }
    }

    /// Reads expired timer ticks without blocking, ignoring `O_NONBLOCK` state.
    pub fn try_read_nonblocking(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        self.read_inner(buf, true)
    }
}

impl Drop for TimerFdObject {
    fn drop(&mut self) {
        let handle = self.inner.lock().cancel_handle.take();
        if let Some(handle) = handle {
            handle.cancel();
        }
    }
}

impl FdObject for TimerFdObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        false
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        self.read_inner(buf, false)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: S_IFREG | 0o600,
            st_blksize: 4096,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let (readable, fired) = {
            let mut inner = self.inner.lock();
            let fired = Self::refresh_expirations_locked(&mut inner, monotonic_now_ns());
            (inner.expirations > 0, fired)
        };
        if fired && !self.read_wait_queue.is_empty() {
            self.read_wait_queue.notify_all(true);
        }
        Ok(PollState {
            readable,
            writable: false,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn nonblocking_state(&self) -> Option<bool> {
        Some(self.nonblocking.load(Ordering::Acquire))
    }

    fn poll_event_sequence(&self) -> Option<PollEventSequence> {
        let mut inner = self.inner.lock();
        let _ = Self::refresh_expirations_locked(&mut inner, monotonic_now_ns());
        Some(PollEventSequence {
            readable: inner.readable_sequence,
            writable: 0,
        })
    }

    fn wait_ready(&self, events: i16, deadline: Option<Duration>) -> LinuxResult<bool> {
        if (events & POLLIN as i16) == 0 {
            return Err(LinuxError::EOPNOTSUPP);
        }
        if self.has_expirations() {
            return Ok(true);
        }
        let condition = || self.has_expirations() || Self::current_has_pending_signal();
        match deadline {
            Some(deadline) => {
                let now = hal::time::monotonic_time();
                if now >= deadline {
                    return Ok(self.has_expirations());
                }
                self.read_wait_queue
                    .wait_timeout_until(deadline - now, condition);
            }
            None => self.read_wait_queue.wait_until(condition),
        }
        if Self::current_has_pending_signal() {
            return Err(LinuxError::EINTR);
        }
        Ok(self.has_expirations())
    }

    fn get_wait_queues<'a>(
        &'a self,
        events: i16,
        wqs: &mut Vec<&'a task::WaitQueue>,
    ) -> LinuxResult<bool> {
        if (events & POLLIN as i16) != 0 {
            wqs.push(&self.read_wait_queue);
            return Ok(true);
        }
        Ok(events == 0)
    }

    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        events: poll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        if events.contains(poll::IoEvents::IN) {
            let owner = self.clone();
            let registration = owner.read_wait_queue.register_owned_waker(cx.waker());
            registrations.push(PollRegistration::new(move || {
                owner.read_wait_queue.unregister_waker(registration);
            }));
        }
        Ok(())
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        match cmd {
            FIONREAD => {
                let bytes = if self.has_expirations() {
                    core::mem::size_of::<u64>() as i32
                } else {
                    0i32
                };
                let process = crate::current_process()?;
                crate::uaccess::write_user_value(&process, arg, &bytes)?;
                Ok(0)
            }
            FIONBIO => {
                let process = crate::current_process()?;
                let enabled = process.read_user_u32(arg)? != 0;
                self.nonblocking.store(enabled, Ordering::Release);
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }
}

/// Creates a new `FdEntry` wrapping a Linux-compatible `timerfd`.
pub fn timerfd_entry(clock_id: i32, flags: u32) -> LinuxResult<FdEntry> {
    let Ok(clock_u32) = u32::try_from(clock_id) else {
        return Err(LinuxError::EINVAL);
    };
    if !matches!(clock_u32, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
        return Err(LinuxError::EINVAL);
    }
    if flags & !(TFD_CLOEXEC | TFD_NONBLOCK) != 0 {
        return Err(LinuxError::EINVAL);
    }

    let mut fd_flags = FdFlags::empty();
    if flags & TFD_CLOEXEC != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    if flags & TFD_NONBLOCK != 0 {
        fd_flags.insert(FdFlags::NONBLOCK);
    }

    let object: Arc<dyn FdObject> =
        TimerFdObject::new(clock_u32, flags & TFD_NONBLOCK != 0);
    Ok(FdEntry::new(object, fd_flags))
}
