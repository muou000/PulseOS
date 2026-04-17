use crate::LinuxError;
use crate::impls::utils::{read_user_timespec, write_user_bytes};
use core::ffi::c_long;
use core::time::Duration;
use linux_raw_sys::general::{CLOCK_MONOTONIC, CLOCK_REALTIME, timespec, timeval};

const CLK_TCK: u64 = 100;

fn timespec_to_duration(ts: timespec) -> Duration {
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
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

    let req_ts = match read_user_timespec(req) {
        Ok(ts) => ts,
        Err(e) => {
            axlog::warn!("read user timespec failed: addr={:#x}, err={:?}", req, e);
            return -LinuxError::EFAULT.code() as isize;
        }
    };

    if req_ts.tv_nsec < 0 || req_ts.tv_nsec > 999_999_999 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let dur = timespec_to_duration(req_ts);
    let now = axhal::time::monotonic_time();

    axhal::time::busy_wait(dur);

    let after = axhal::time::monotonic_time();
    let actual = after - now;

    if let Some(diff) = dur.checked_sub(actual) {
        if rem != 0 {
            let remain = duration_to_timespec(diff);
            let bytes = unsafe {
                core::slice::from_raw_parts(
                    (&remain as *const timespec).cast::<u8>(),
                    core::mem::size_of::<timespec>(),
                )
            };
            if let Err(e) = write_user_bytes(rem, bytes) {
                axlog::warn!("write user timespec failed: addr={:#x}, err={:?}", rem, e);
                return -LinuxError::EFAULT.code() as isize;
            }
        }
        return -LinuxError::EINTR.code() as isize;
    }

    0
}

/// sys_clock_gettime - 获取时钟时间
pub fn sys_clock_gettime(clockid: i32, tp: usize) -> isize {
    axlog::debug!("sys_clock_gettime: clockid={}, tp={:#x}", clockid, tp);
    if tp == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let now = match clockid as u32 {
        CLOCK_REALTIME => duration_to_timespec(axhal::time::wall_time()),
        CLOCK_MONOTONIC => duration_to_timespec(axhal::time::monotonic_time()),
        _ => return -LinuxError::EINVAL.code() as isize,
    };

    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&now as *const timespec).cast::<u8>(),
            core::mem::size_of::<timespec>(),
        )
    };
    match write_user_bytes(tp, bytes) {
        Ok(()) => 0,
        Err(e) => {
            axlog::warn!("write user timespec failed: addr={:#x}, err={:?}", tp, e);
            -LinuxError::EFAULT.code() as isize
        }
    }
}

/// sys_gettimeofday - 获取墙上时间
pub fn sys_gettimeofday(tv: usize, tz: usize) -> isize {
    axlog::debug!("sys_gettimeofday: tv={:#x}, tz={:#x}", tv, tz);

    if tz != 0 {
        axlog::debug!("sys_gettimeofday: timezone argument is ignored");
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
