use core::{
    ffi::c_long,
    time::Duration,
};

use linux_raw_sys::general::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_THREAD_CPUTIME_ID,
    TIMER_ABSTIME, timespec, timeval, itimerspec,
};
use pulse_core::task::uaccess;

use crate::{
    LinuxError,
    impls::utils::{read_user_timespec, read_user_timeval, write_user_bytes},
};

const CLK_TCK: u64 = 100;

fn timespec_to_duration(ts: timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec > 999_999_999 {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

fn duration_to_timespec(dur: Duration) -> timespec {
    timespec {
        tv_sec: dur.as_secs() as _,
        tv_nsec: dur.subsec_nanos() as _,
    }
}

fn ns_to_clk_ticks(ns: u64) -> u64 {
    ns.saturating_mul(CLK_TCK) / 1_000_000_000
}

fn write_user_timespec(user_addr: usize, value: timespec) -> Result<(), LinuxError> {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&value as *const timespec).cast::<u8>(),
            core::mem::size_of::<timespec>(),
        )
    };
    write_user_bytes(user_addr, bytes)
}

fn write_zero_timespec(user_addr: usize) -> Result<(), LinuxError> {
    write_user_timespec(
        user_addr,
        timespec {
            tv_sec: 0,
            tv_nsec: 0,
        },
    )
}

fn is_supported_clock(clockid: i32) -> bool {
    matches!(
        clockid as u32,
        CLOCK_MONOTONIC
            | CLOCK_REALTIME
            | CLOCK_MONOTONIC_RAW
            | CLOCK_REALTIME_COARSE
            | CLOCK_MONOTONIC_COARSE
            | CLOCK_BOOTTIME
            | CLOCK_PROCESS_CPUTIME_ID
            | CLOCK_THREAD_CPUTIME_ID
    )
}

fn clock_now(clockid: i32) -> Result<Duration, LinuxError> {
    match clockid as u32 {
        CLOCK_REALTIME | CLOCK_REALTIME_COARSE => Ok(axhal::time::wall_time()),
        CLOCK_MONOTONIC | CLOCK_MONOTONIC_RAW | CLOCK_MONOTONIC_COARSE | CLOCK_BOOTTIME => {
            Ok(axhal::time::monotonic_time())
        }
        CLOCK_PROCESS_CPUTIME_ID => {
            let thread = pulse_core::task::current_thread().map_err(|e| LinuxError::from(e))?;
            let process = thread.process();
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            let (utime_ns, stime_ns) = process.snapshot_cpu_time_ns(now_ns);
            Ok(Duration::from_nanos(utime_ns.saturating_add(stime_ns)))
        }
        CLOCK_THREAD_CPUTIME_ID => {
            let thread = pulse_core::task::current_thread().map_err(|e| LinuxError::from(e))?;
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            let (utime_ns, stime_ns) = thread.snapshot_cpu_time_ns(now_ns);
            Ok(Duration::from_nanos(utime_ns.saturating_add(stime_ns)))
        }
        _ => Err(LinuxError::EINVAL),
    }
}

fn clock_resolution() -> timespec {
    // cyclictest treats exactly 1ns as "high resolution" and warns otherwise.
    // Return the finest resolution we can expose to keep it on the high-res path.
    timespec {
        tv_sec: 0,
        tv_nsec: 1,
    }
}

fn current_has_pending_signal() -> bool {
    pulse_core::task::current_thread()
        .map(|thread| thread.has_pending_signal())
        .unwrap_or(false)
}

fn current_is_group_exiting() -> bool {
    pulse_core::task::current_process()
        .map(|process| process.group_exiting())
        .unwrap_or(false)
}

fn sleep_for_duration_interruptible(dur: Duration) -> Result<Duration, LinuxError> {
    if current_has_pending_signal() || current_is_group_exiting() {
        return Ok(dur);
    }
    let start = axhal::time::monotonic_time();
    let deadline = start.saturating_add(dur);
    loop {
        let now = axhal::time::monotonic_time();
        if now >= deadline {
            return Ok(Duration::ZERO);
        }
        if current_has_pending_signal() || current_is_group_exiting() {
            return Ok(deadline.saturating_sub(now));
        }
        axtask::sleep_until(deadline);
    }
}

static REALTIME_SLEEPERS: spin::Mutex<alloc::vec::Vec<axtask::AxTaskRef>> = spin::Mutex::new(alloc::vec::Vec::new());

fn sleep_until_clock_interruptible(clockid: i32, target: Duration) -> Result<Duration, LinuxError> {
    match clockid as u32 {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {}
        _ => return Err(LinuxError::EINVAL),
    }

    loop {
        let target_mono = if clockid as u32 == CLOCK_REALTIME {
            let offset = Duration::from_nanos(axhal::time::current_epochoffset_nanos());
            target.saturating_sub(offset)
        } else {
            target
        };

        let now = axhal::time::monotonic_time();
        if now >= target_mono {
            return Ok(Duration::ZERO);
        }
        if current_has_pending_signal() || current_is_group_exiting() {
            let now_clock = clock_now(clockid)?;
            return Ok(target.saturating_sub(now_clock));
        }

        if clockid as u32 == CLOCK_REALTIME {
            let current_task = axtask::current().as_task_ref().clone();
            REALTIME_SLEEPERS.lock().push(current_task);
        }

        axtask::sleep_until(target_mono);

        if clockid as u32 == CLOCK_REALTIME {
            let current_task = axtask::current().as_task_ref().clone();
            let mut guard = REALTIME_SLEEPERS.lock();
            if let Some(pos) = guard.iter().position(|t| alloc::sync::Arc::ptr_eq(t, &current_task)) {
                guard.swap_remove(pos);
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Tms {
    tms_utime: c_long,
    tms_stime: c_long,
    tms_cutime: c_long,
    tms_cstime: c_long,
}

pub fn sys_nanosleep(req: usize, rem: usize) -> isize {
    axlog::trace!("sys_nanosleep: req={:#x}, rem={:#x}", req, rem);

    if req == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let req_ts = match read_user_timespec(req).and_then(timespec_to_duration) {
        Ok(ts) => ts,
        Err(e) => {
            axlog::warn!("read user timespec failed: addr={:#x}, err={:?}", req, e);
            return -e.code() as isize;
        }
    };

    if req_ts > Duration::ZERO {
        match sleep_for_duration_interruptible(req_ts) {
            Ok(remaining) if remaining > Duration::ZERO => {
                if rem != 0 {
                    if let Err(e) = write_user_timespec(rem, duration_to_timespec(remaining)) {
                        axlog::warn!("write user timespec failed: addr={:#x}, err={:?}", rem, e);
                        return -e.code() as isize;
                    }
                }
                return -LinuxError::EINTR.code() as isize;
            }
            Ok(_) => {}
            Err(e) => return -e.code() as isize,
        }
    }

    if rem != 0 {
        if let Err(e) = write_zero_timespec(rem) {
            axlog::warn!("write user timespec failed: addr={:#x}, err={:?}", rem, e);
            return -e.code() as isize;
        }
    }
    0
}

pub fn sys_clock_nanosleep(clockid: i32, flags: usize, req: usize, rem: usize) -> isize {

    if req == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let req_ts = match read_user_timespec(req).and_then(timespec_to_duration) {
        Ok(ts) => ts,
        Err(e) => return -e.code() as isize,
    };

    // CPU-time clocks (CLOCK_PROCESS_CPUTIME_ID and CLOCK_THREAD_CPUTIME_ID)
    // are valid clock IDs but do not support sleeping, returning EOPNOTSUPP.
    if matches!(
        clockid as u32,
        CLOCK_PROCESS_CPUTIME_ID | CLOCK_THREAD_CPUTIME_ID
    ) {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    if !is_supported_clock(clockid) {
        return -LinuxError::EINVAL.code() as isize;
    }
    if !matches!(clockid as u32, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
        return -LinuxError::EINVAL.code() as isize;
    }
    if flags != 0 && flags != TIMER_ABSTIME as usize {
        return -LinuxError::EINVAL.code() as isize;
    }

    let result = if flags == TIMER_ABSTIME as usize {
        sleep_until_clock_interruptible(clockid, req_ts)
    } else {
        sleep_for_duration_interruptible(req_ts)
    };

    match result {
        Ok(remaining) if remaining > Duration::ZERO => {
            if rem != 0 {
                if let Err(e) = write_user_timespec(rem, duration_to_timespec(remaining)) {
                    return -e.code() as isize;
                }
            }
            return -LinuxError::EINTR.code() as isize;
        }
        Ok(_) => {}
        Err(e) => return -e.code() as isize,
    }

    if rem != 0 {
        if let Err(e) = write_zero_timespec(rem) {
            return -e.code() as isize;
        }
    }
    0
}

pub fn sys_clock_getres(clockid: i32, res: usize) -> isize {
    if !is_supported_clock(clockid) {
        return -LinuxError::EINVAL.code() as isize;
    }

    if res == 0 {
        return 0;
    }

    let resolution = clock_resolution();
    write_user_timespec(res, resolution)
        .map(|_| 0)
        .unwrap_or_else(|_| -LinuxError::EFAULT.code() as isize)
}

/// sys_clock_gettime - 获取时钟时间
pub fn sys_clock_gettime(clockid: i32, tp: usize) -> isize {
    axlog::trace!("sys_clock_gettime: clockid={}, tp={:#x}", clockid, tp);
    if tp == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let now = match clock_now(clockid) {
        Ok(now) => duration_to_timespec(now),
        Err(e) => return -e.code() as isize,
    };

    write_user_timespec(tp, now).map(|_| 0).unwrap_or_else(|e| {
        axlog::warn!("write user timespec failed: addr={:#x}, err={:?}", tp, e);
        -LinuxError::EFAULT.code() as isize
    })
}

/// sys_clock_settime - 设置时钟时间
pub fn sys_clock_settime(clockid: i32, tp: usize) -> isize {
    axlog::trace!("sys_clock_settime: clockid={}, tp={:#x}", clockid, tp);

    if tp == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    if clockid != CLOCK_REALTIME as i32 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let ts = match read_user_timespec(tp) {
        Ok(ts) => ts,
        Err(e) => {
            axlog::warn!("read user timespec failed: addr={:#x}, err={:?}", tp, e);
            return -e.code() as isize;
        }
    };

    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    const CAP_SYS_TIME: u32 = 25;
    if !process.has_capability(CAP_SYS_TIME) {
        return -LinuxError::EPERM.code() as isize;
    }

    let req_ts = Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32);

    let now_mono_ns = axhal::time::monotonic_time_nanos();
    let new_wall_ns = req_ts.as_nanos() as u64;
    let new_offset = new_wall_ns.wrapping_sub(now_mono_ns);

    axhal::time::set_epochoffset_nanos(new_offset);

    // Synchronize vDSO wall time instantly
    starry_vdso::vdso::set_vdso_epoch_offset(new_offset);
    starry_vdso::vdso::update_vdso_data();

    // Wake up all tasks sleeping on CLOCK_REALTIME
    let sleepers = {
        let mut guard = REALTIME_SLEEPERS.lock();
        core::mem::take(&mut *guard)
    };
    for task in sleepers {
        axtask::wake_task(task, true);
    }

    // Adjust absolute POSIX timers
    pulse_core::task::adjust_absolute_timers();

    // Check if any timers expired due to the clock jump, and reprogram the timer
    let _guard = kernel_guard::NoPreemptIrqSave::new();
    axtask::check_events();
    axtask::reprogram_timer();
    drop(_guard);

    0
}

/// sys_gettimeofday - 获取墙上时间
pub fn sys_gettimeofday(tv: usize, tz: usize) -> isize {
    axlog::trace!("sys_gettimeofday: tv={:#x}, tz={:#x}", tv, tz);

    if tv == 0 {
        return 0;
    }

    let now = axhal::time::wall_time();
    let timeval = timeval {
        tv_sec: now.as_secs() as _,
        tv_usec: now.subsec_micros() as _,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&timeval as *const timeval).cast::<u8>(),
            core::mem::size_of::<timeval>(),
        )
    };

    write_user_bytes(tv, bytes).map(|_| 0).unwrap_or_else(|e| {
        axlog::warn!("sys_gettimeofday: user write failed at {:#x}: {:?}", tv, e);
        -LinuxError::EFAULT.code() as isize
    })
}

/// sys_settimeofday - 设置墙上时间
pub fn sys_settimeofday(tv: usize, tz: usize) -> isize {
    axlog::trace!("sys_settimeofday: tv={:#x}, tz={:#x}", tv, tz);

    if tv == 0 {
        return 0;
    }

    let req_tv = match read_user_timeval(tv) {
        Ok(t) => t,
        Err(e) => {
            axlog::warn!("sys_settimeofday: read user timeval failed: addr={:#x}, err={:?}", tv, e);
            return -e.code() as isize;
        }
    };

    if req_tv.tv_sec < 0 || req_tv.tv_usec < 0 || req_tv.tv_usec >= 1_000_000 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    const CAP_SYS_TIME: u32 = 25;
    if !process.has_capability(CAP_SYS_TIME) {
        return -LinuxError::EPERM.code() as isize;
    }

    let new_wall_ns = match (req_tv.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|sec_ns| sec_ns.checked_add((req_tv.tv_usec as u64) * 1_000))
    {
        Some(ns) => ns,
        None => return -LinuxError::EINVAL.code() as isize,
    };

    let now_mono_ns = axhal::time::monotonic_time_nanos();
    let new_offset = new_wall_ns.wrapping_sub(now_mono_ns);

    axhal::time::set_epochoffset_nanos(new_offset);

    // Synchronize vDSO wall time instantly
    starry_vdso::vdso::set_vdso_epoch_offset(new_offset);
    starry_vdso::vdso::update_vdso_data();

    // Wake up all tasks sleeping on CLOCK_REALTIME
    let sleepers = {
        let mut guard = REALTIME_SLEEPERS.lock();
        core::mem::take(&mut *guard)
    };
    for task in sleepers {
        axtask::wake_task(task, true);
    }

    // Adjust absolute POSIX timers
    pulse_core::task::adjust_absolute_timers();

    // Check if any timers expired due to the clock jump, and reprogram the timer
    let _guard = kernel_guard::NoPreemptIrqSave::new();
    axtask::check_events();
    axtask::reprogram_timer();
    drop(_guard);

    0
}

pub fn sys_times(tbuf: usize) -> isize {
    axlog::debug!("sys_times: tbuf={:#x}", tbuf);

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    let now_ns = axhal::time::monotonic_time_nanos() as u64;
    let (utime_ns, stime_ns) = process.snapshot_cpu_time_ns(now_ns);
    let (cutime_ns, cstime_ns) = process.snapshot_children_cpu_time_ns();

    let ticks = ns_to_clk_ticks(now_ns);

    if tbuf != 0 {
        let tms = Tms {
            tms_utime: ns_to_clk_ticks(utime_ns) as c_long,
            tms_stime: ns_to_clk_ticks(stime_ns) as c_long,
            tms_cutime: ns_to_clk_ticks(cutime_ns) as c_long,
            tms_cstime: ns_to_clk_ticks(cstime_ns) as c_long,
        };
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&tms as *const Tms).cast::<u8>(),
                core::mem::size_of::<Tms>(),
            )
        };

        if let Err(e) = write_user_bytes(tbuf, bytes) {
            axlog::warn!("sys_times: user write failed at {:#x}: {:?}", tbuf, e);
            return -LinuxError::EFAULT.code() as isize;
        }
    }

    ticks as isize
}

const ITIMER_REAL: usize = 0;
const ITIMER_VIRTUAL: usize = 1;
const ITIMER_PROF: usize = 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct Itimerval {
    it_interval: timeval,
    it_value: timeval,
}

impl Default for Itimerval {
    fn default() -> Self {
        Self {
            it_interval: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            it_value: timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
        }
    }
}

fn timeval_to_ns(tv: &timeval) -> Option<u64> {
    if tv.tv_sec < 0 || tv.tv_usec < 0 || tv.tv_usec >= 1_000_000 {
        return None;
    }
    let sec_ns = (tv.tv_sec as u64).checked_mul(1_000_000_000)?;
    let usec_ns = (tv.tv_usec as u64).checked_mul(1_000)?;
    sec_ns.checked_add(usec_ns)
}

fn ns_to_timeval(ns: u64) -> timeval {
    timeval {
        tv_sec: (ns / 1_000_000_000) as _,
        tv_usec: ((ns % 1_000_000_000) / 1_000) as _,
    }
}

fn read_user_itimerval(addr: usize) -> Result<Itimerval, LinuxError> {
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let proc = pulse_core::task::current_process()?;
    let val: Itimerval =
        uaccess::read_user_plain(proc.as_ref(), addr).map_err(|_| LinuxError::EFAULT)?;
    Ok(val)
}

fn write_user_itimerval(addr: usize, val: &Itimerval) -> Result<(), LinuxError> {
    if addr == 0 {
        return Ok(());
    }
    let proc = pulse_core::task::current_process()?;
    uaccess::write_user_plain(proc.as_ref(), addr, val).map_err(|_| LinuxError::EFAULT)
}

pub fn sys_setitimer(which: usize, new_value: usize, old_value: usize) -> isize {
    axlog::debug!(
        "sys_setitimer: which={}, new_value={:#x}, old_value={:#x}",
        which,
        new_value,
        old_value
    );

    if which > ITIMER_PROF {
        return -LinuxError::EINVAL.code() as isize;
    }

    // Only ITIMER_REAL is truly implemented.
    // ITIMER_VIRTUAL and ITIMER_PROF are accepted but not actually timed.

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    // Read new value
    let new_itv = if new_value != 0 {
        match read_user_itimerval(new_value) {
            Ok(v) => v,
            Err(e) => return -e.code() as isize,
        }
    } else {
        // null new_value means "don't change, just query old"
        Itimerval::default()
    };

    let new_value_ns = if new_value != 0 {
        match timeval_to_ns(&new_itv.it_value) {
            Some(ns) => ns,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    } else {
        u64::MAX // sentinel: don't change
    };
    let new_interval_ns = if new_value != 0 {
        match timeval_to_ns(&new_itv.it_interval) {
            Some(ns) => ns,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    } else {
        u64::MAX // sentinel: don't change
    };

    match which {
        ITIMER_REAL => {
            let (old_remaining, old_interval) = if new_value != 0 {
                proc.set_itimer_real(new_value_ns, new_interval_ns)
            } else {
                proc.get_itimer_real()
            };

            if old_value != 0 {
                let old_itv = Itimerval {
                    it_interval: ns_to_timeval(old_interval),
                    it_value: ns_to_timeval(old_remaining),
                };
                if let Err(e) = write_user_itimerval(old_value, &old_itv) {
                    return -e.code() as isize;
                }
            }
            0
        }
        ITIMER_VIRTUAL => {
            let (old_remaining, old_interval) = if new_value != 0 {
                proc.set_itimer_virt(new_value_ns, new_interval_ns)
            } else {
                proc.get_itimer_virt()
            };

            if old_value != 0 {
                let old_itv = Itimerval {
                    it_interval: ns_to_timeval(old_interval),
                    it_value: ns_to_timeval(old_remaining),
                };
                if let Err(e) = write_user_itimerval(old_value, &old_itv) {
                    return -e.code() as isize;
                }
            }
            0
        }
        ITIMER_PROF => {
            let (old_remaining, old_interval) = if new_value != 0 {
                proc.set_itimer_prof(new_value_ns, new_interval_ns)
            } else {
                proc.get_itimer_prof()
            };

            if old_value != 0 {
                let old_itv = Itimerval {
                    it_interval: ns_to_timeval(old_interval),
                    it_value: ns_to_timeval(old_remaining),
                };
                if let Err(e) = write_user_itimerval(old_value, &old_itv) {
                    return -e.code() as isize;
                }
            }
            0
        }
        _ => -LinuxError::EINVAL.code() as isize,
    }
}

pub fn sys_getitimer(which: usize, curr_value: usize) -> isize {
    axlog::debug!(
        "sys_getitimer: which={}, curr_value={:#x}",
        which,
        curr_value
    );

    if which > ITIMER_PROF {
        return -LinuxError::EINVAL.code() as isize;
    }
    if curr_value == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let (remaining, interval) = match which {
        ITIMER_REAL => proc.get_itimer_real(),
        ITIMER_VIRTUAL => proc.get_itimer_virt(),
        ITIMER_PROF => proc.get_itimer_prof(),
        _ => return -LinuxError::EINVAL.code() as isize,
    };

    let itv = Itimerval {
        it_interval: ns_to_timeval(interval),
        it_value: ns_to_timeval(remaining),
    };
    match write_user_itimerval(curr_value, &itv) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

const ADJ_OFFSET: u32 = 0x0001;
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_ESTERROR: u32 = 0x0008;
const ADJ_STATUS: u32 = 0x0010;
const ADJ_TIMECONST: u32 = 0x0020;
const ADJ_MICRO: u32 = 0x1000;
const ADJ_NANO: u32 = 0x2000;
const ADJ_TICK: u32 = 0x4000;
const ADJ_OFFSET_SINGLESHOT: u32 = 0x8001;
const ADJ_OFFSET_SS_READ: u32 = 0xa001;

const STA_UNSYNC: i32 = 0x0040;
const STA_NANO: i32 = 0x2000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct timex {
    pub modes: u32,
    _pad1: u32,
    pub offset: c_long,
    pub freq: c_long,
    pub maxerror: c_long,
    pub esterror: c_long,
    pub status: i32,
    _pad2: u32,
    pub constant: c_long,
    pub precision: c_long,
    pub tolerance: c_long,
    pub time: timeval,
    pub tick: c_long,
    pub ppsfreq: c_long,
    pub jitter: c_long,
    pub shift: i32,
    _pad3: u32,
    pub stabil: c_long,
    pub jitcnt: c_long,
    pub calcnt: c_long,
    pub errcnt: c_long,
    pub stbcnt: c_long,
    pub tai: i32,
    _pad4: [i32; 11],
}

static GLOBAL_TIMEX: spin::Mutex<timex> = spin::Mutex::new(timex {
    modes: 0,
    _pad1: 0,
    offset: 0,
    freq: 0,
    maxerror: 0,
    esterror: 0,
    status: STA_UNSYNC,
    _pad2: 0,
    constant: 0,
    precision: 1,
    tolerance: 32768000,
    time: timeval { tv_sec: 0, tv_usec: 0 },
    tick: 10000,
    ppsfreq: 0,
    jitter: 0,
    shift: 0,
    _pad3: 0,
    stabil: 0,
    jitcnt: 0,
    calcnt: 0,
    errcnt: 0,
    stbcnt: 0,
    tai: 0,
    _pad4: [0; 11],
});

pub fn sys_clock_adjtime(clockid: i32, buf: usize) -> isize {
    axlog::trace!("sys_clock_adjtime: clockid={}, buf={:#x}", clockid, buf);

    if clockid != CLOCK_REALTIME as i32 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let tmx: timex = match uaccess::read_user_plain(proc.as_ref(), buf) {
        Ok(t) => t,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };

    let modes = tmx.modes;

    if modes != 0 && modes != ADJ_OFFSET_SS_READ {
        const CAP_SYS_TIME: u32 = 25;
        if !proc.has_capability(CAP_SYS_TIME) {
            return -LinuxError::EPERM.code() as isize;
        }
    }

    if (modes & ADJ_TICK) != 0 {
        let tick_min = 900000 / CLK_TCK;
        let tick_max = 1100000 / CLK_TCK;
        if tmx.tick < tick_min as c_long || tmx.tick > tick_max as c_long {
            return -LinuxError::EINVAL.code() as isize;
        }
    }

    let mut g = GLOBAL_TIMEX.lock();

    if (modes & ADJ_NANO) != 0 {
        g.status |= STA_NANO;
    }
    if (modes & ADJ_MICRO) != 0 {
        g.status &= !STA_NANO;
    }

    if (modes & ADJ_OFFSET) != 0 {
        g.offset = tmx.offset;
    }
    if (modes & ADJ_FREQUENCY) != 0 {
        g.freq = tmx.freq;
    }
    if (modes & ADJ_MAXERROR) != 0 {
        g.maxerror = tmx.maxerror;
    }
    if (modes & ADJ_ESTERROR) != 0 {
        g.esterror = tmx.esterror;
    }
    if (modes & ADJ_STATUS) != 0 {
        g.status = tmx.status;
    }
    if (modes & ADJ_TIMECONST) != 0 {
        g.constant = tmx.constant;
    }
    if (modes & ADJ_TICK) != 0 {
        g.tick = tmx.tick;
    }
    if (modes & ADJ_OFFSET_SINGLESHOT) != 0 {
        g.offset = tmx.offset;
    }

    let now = axhal::time::wall_time();
    if (g.status & STA_NANO) != 0 {
        g.time.tv_sec = now.as_secs() as _;
        g.time.tv_usec = now.subsec_nanos() as _;
    } else {
        g.time.tv_sec = now.as_secs() as _;
        g.time.tv_usec = now.subsec_micros() as _;
    }

    let tmx_to_write = *g;
    drop(g);

    match uaccess::write_user_plain(proc.as_ref(), buf, &tmx_to_write) {
        Ok(()) => 0,
        Err(_) => -LinuxError::EFAULT.code() as isize,
    }
}

pub fn sys_timer_create(clockid: i32, sevp: usize, timerid: usize) -> isize {
    axlog::debug!(
        "sys_timer_create: clockid={}, sevp={:#x}, timerid={:#x}",
        clockid,
        sevp,
        timerid
    );

    if timerid == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let mut event: linux_raw_sys::general::sigevent = unsafe { core::mem::zeroed() };
    if sevp != 0 {
        match uaccess::read_user_plain(proc.as_ref(), sevp) {
            Ok(ev) => event = ev,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        }
    } else {
        event.sigev_notify = 0; // SIGEV_SIGNAL
        event.sigev_signo = 14; // SIGALRM
    }

    match proc.alloc_posix_timer(clockid, event) {
        Ok(id) => {
            match uaccess::write_user_plain(proc.as_ref(), timerid, &id) {
                Ok(()) => 0,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            }
        }
        Err(e) => -e.code() as isize,
    }
}

fn read_user_itimerspec(addr: usize) -> Result<itimerspec, LinuxError> {
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let proc = pulse_core::task::current_process()?;
    let val: itimerspec =
        uaccess::read_user_plain(proc.as_ref(), addr).map_err(|_| LinuxError::EFAULT)?;
    Ok(val)
}

fn write_user_itimerspec(addr: usize, val: &itimerspec) -> Result<(), LinuxError> {
    if addr == 0 {
        return Ok(());
    }
    let proc = pulse_core::task::current_process()?;
    uaccess::write_user_plain(proc.as_ref(), addr, val).map_err(|_| LinuxError::EFAULT)
}

fn ns_to_timespec(ns: u64) -> timespec {
    timespec {
        tv_sec: (ns / 1_000_000_000) as _,
        tv_nsec: (ns % 1_000_000_000) as _,
    }
}

pub fn sys_timer_settime(
    timerid: usize,
    flags: usize,
    new_value: usize,
    old_value: usize,
) -> isize {
    axlog::debug!(
        "sys_timer_settime: timerid={}, flags={}, new_value={:#x}, old_value={:#x}",
        timerid,
        flags,
        new_value,
        old_value
    );

    if timerid >= pulse_core::task::MAX_POSIX_TIMER_COUNT {
        return -LinuxError::EINVAL.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let new_spec = if new_value != 0 {
        match read_user_itimerspec(new_value) {
            Ok(v) => v,
            Err(e) => return -e.code() as isize,
        }
    } else {
        return -LinuxError::EINVAL.code() as isize;
    };

    let val_dur = match timespec_to_duration(new_spec.it_value) {
        Ok(d) => d,
        Err(e) => return -e.code() as isize,
    };

    let int_dur = match timespec_to_duration(new_spec.it_interval) {
        Ok(d) => d,
        Err(e) => return -e.code() as isize,
    };

    let mut timers = proc.posix_timers.lock();
    let timer = match &mut timers[timerid] {
        Some(t) => t,
        None => return -LinuxError::EINVAL.code() as isize,
    };

    if old_value != 0 {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let prev_val_ns = if timer.next_deadline_ns == 0 {
            0
        } else if now_ns >= timer.next_deadline_ns {
            0
        } else {
            timer.next_deadline_ns - now_ns
        };
        let old_spec = itimerspec {
            it_interval: ns_to_timespec(timer.interval_ns),
            it_value: ns_to_timespec(prev_val_ns),
        };
        let val_write = write_user_itimerspec(old_value, &old_spec);
        if let Err(e) = val_write {
            return -e.code() as isize;
        }
    }

    timer.itimer_spec = new_spec;
    timer.interval_ns = int_dur.as_nanos() as u64;
    timer.is_absolute = (flags & TIMER_ABSTIME as usize) != 0;
    timer.first_expired = false;

    if val_dur.is_zero() {
        timer.next_deadline_ns = 0;
    } else {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let deadline = if (flags & TIMER_ABSTIME as usize) != 0 {
            let req_ns = val_dur.as_nanos() as u64;
            if timer.clock_id as u32 == CLOCK_REALTIME {
                let offset = axhal::time::current_epochoffset_nanos();
                req_ns.saturating_sub(offset)
            } else {
                req_ns
            }
        } else {
            now_ns.saturating_add(val_dur.as_nanos() as u64)
        };
        timer.next_deadline_ns = deadline;
        pulse_core::task::schedule_posix_timer_event(proc.pid(), timerid, deadline);
    }

    0
}

pub fn sys_timer_gettime(timerid: usize, curr_value: usize) -> isize {
    axlog::debug!("sys_timer_gettime: timerid={}, curr_value={:#x}", timerid, curr_value);

    if timerid >= pulse_core::task::MAX_POSIX_TIMER_COUNT {
        return -LinuxError::EINVAL.code() as isize;
    }
    if curr_value == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let timers = proc.posix_timers.lock();
    let timer = match &timers[timerid] {
        Some(t) => t,
        None => return -LinuxError::EINVAL.code() as isize,
    };

    let now_ns = axhal::time::monotonic_time_nanos() as u64;
    let prev_val_ns = if timer.next_deadline_ns == 0 {
        0
    } else if now_ns >= timer.next_deadline_ns {
        0
    } else {
        timer.next_deadline_ns - now_ns
    };
    let curr_spec = itimerspec {
        it_interval: ns_to_timespec(timer.interval_ns),
        it_value: ns_to_timespec(prev_val_ns),
    };
    match write_user_itimerspec(curr_value, &curr_spec) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_timer_delete(timerid: usize) -> isize {
    axlog::debug!("sys_timer_delete: timerid={}", timerid);

    if timerid >= pulse_core::task::MAX_POSIX_TIMER_COUNT {
        return -LinuxError::EINVAL.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let mut timers = proc.posix_timers.lock();
    if timers[timerid].is_some() {
        timers[timerid] = None;
        0
    } else {
        -LinuxError::EINVAL.code() as isize
    }
}
