use core::{
    ffi::c_long,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use linux_raw_sys::general::{
    CLOCK_BOOTTIME, CLOCK_MONOTONIC, CLOCK_MONOTONIC_COARSE, CLOCK_MONOTONIC_RAW,
    CLOCK_PROCESS_CPUTIME_ID, CLOCK_REALTIME, CLOCK_REALTIME_COARSE, CLOCK_THREAD_CPUTIME_ID,
    TIMER_ABSTIME, timespec, timeval,
};
use pulse_core::task::uaccess;

use crate::{
    LinuxError,
    impls::utils::{read_user_timespec, read_user_timeval, write_user_bytes},
};

const CLK_TCK: u64 = 100;
static CLOCK_NANOSLEEP_COMPAT_WARNED: AtomicBool = AtomicBool::new(false);
static CLOCK_GETRES_FIXED_WARNED: AtomicBool = AtomicBool::new(false);
static GETTIMEOFDAY_TZ_WARNED: AtomicBool = AtomicBool::new(false);

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

fn sleep_for_duration_interruptible(dur: Duration) -> Result<Duration, LinuxError> {
    if current_has_pending_signal() {
        return Ok(dur);
    }
    let start = axhal::time::monotonic_time();
    let deadline = start.saturating_add(dur);
    loop {
        let now = axhal::time::monotonic_time();
        if now >= deadline {
            return Ok(Duration::ZERO);
        }
        if current_has_pending_signal() {
            return Ok(deadline.saturating_sub(now));
        }
        axtask::sleep(deadline.saturating_sub(now));
    }
}

fn sleep_until_clock_interruptible(clockid: i32, target: Duration) -> Result<Duration, LinuxError> {
    match clockid as u32 {
        CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME => {}
        _ => return Err(LinuxError::EINVAL),
    }
    loop {
        let now = clock_now(clockid)?;
        if now >= target {
            return Ok(Duration::ZERO);
        }
        if current_has_pending_signal() {
            return Ok(target.saturating_sub(now));
        }
        let sleep_dur = target.saturating_sub(now);
        if sleep_dur > Duration::ZERO {
            axtask::sleep(sleep_dur);
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
    if !CLOCK_NANOSLEEP_COMPAT_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!("sys_clock_nanosleep: using task sleep with simplified EINTR/rem semantics");
    }

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

    if !CLOCK_GETRES_FIXED_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!("sys_clock_getres: reporting fixed nanosecond timer resolution");
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

    if tz != 0 {
        if !GETTIMEOFDAY_TZ_WARNED.swap(true, Ordering::AcqRel) {
            axlog::warn!("sys_gettimeofday: timezone argument is ignored");
        }
    }

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

    if tz != 0 {
        if !GETTIMEOFDAY_TZ_WARNED.swap(true, Ordering::AcqRel) {
            axlog::warn!("sys_settimeofday: timezone argument is ignored");
        }
    }

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
