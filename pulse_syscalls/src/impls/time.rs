use core::{
    ffi::c_long,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use linux_raw_sys::general::{CLOCK_MONOTONIC, CLOCK_REALTIME, TIMER_ABSTIME, timespec, timeval};

use crate::{
    LinuxError,
    impls::utils::{read_user_timespec, write_user_bytes},
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
    matches!(clockid as u32, CLOCK_MONOTONIC | CLOCK_REALTIME)
}

fn clock_now(clockid: i32) -> Result<Duration, LinuxError> {
    match clockid as u32 {
        CLOCK_REALTIME => Ok(axhal::time::wall_time()),
        CLOCK_MONOTONIC => Ok(axhal::time::monotonic_time()),
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
        CLOCK_REALTIME | CLOCK_MONOTONIC => {}
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
    axlog::debug!("sys_nanosleep: req={:#x}, rem={:#x}", req, rem);

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

    if !is_supported_clock(clockid) {
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
    axlog::debug!("sys_clock_gettime: clockid={}, tp={:#x}", clockid, tp);
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

/// sys_gettimeofday - 获取墙上时间
pub fn sys_gettimeofday(tv: usize, tz: usize) -> isize {
    axlog::debug!("sys_gettimeofday: tv={:#x}, tz={:#x}", tv, tz);

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
