use crate::LinuxError;
use arceos_posix_api::ctypes;
use core::mem::{MaybeUninit, size_of};
use core::time::Duration;
use memory_addr::VirtAddr;

fn read_user_timespec(
    process: &pulse_core::task::Process,
    user_addr: usize,
) -> Result<ctypes::timespec, isize> {
    let mut ts = MaybeUninit::<ctypes::timespec>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(ts.as_mut_ptr().cast::<u8>(), size_of::<ctypes::timespec>())
    };
    process
        .aspace
        .lock()
        .read(VirtAddr::from(user_addr), bytes)
        .map_err(|e| {
            axlog::warn!(
                "read user timespec failed: addr={:#x}, err={:?}",
                user_addr,
                e
            );
            -LinuxError::EFAULT.code() as isize
        })?;
    Ok(unsafe { ts.assume_init() })
}

fn write_user_timespec(
    process: &pulse_core::task::Process,
    user_addr: usize,
    ts: &ctypes::timespec,
) -> isize {
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (ts as *const ctypes::timespec).cast::<u8>(),
            size_of::<ctypes::timespec>(),
        )
    };
    process
        .aspace
        .lock()
        .write(VirtAddr::from(user_addr), bytes)
        .map(|_| 0)
        .unwrap_or_else(|e| {
            axlog::warn!(
                "write user timespec failed: addr={:#x}, err={:?}",
                user_addr,
                e
            );
            -LinuxError::EFAULT.code() as isize
        })
}

pub fn sys_nanosleep(req: usize, rem: usize) -> isize {
    axlog::debug!("sys_nanosleep: req={:#x}, rem={:#x}", req, rem);

    if req == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    use axtask::TaskExtRef;
    let curr = axtask::current();
    let process: &pulse_core::task::Process = curr.task_ext();

    let req_ts = match read_user_timespec(process, req) {
        Ok(ts) => ts,
        Err(e) => return e,
    };

    if req_ts.tv_nsec < 0 || req_ts.tv_nsec > 999_999_999 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let dur = Duration::from(req_ts);
    let now = axhal::time::monotonic_time();

    axhal::time::busy_wait(dur);

    let after = axhal::time::monotonic_time();
    let actual = after - now;

    if let Some(diff) = dur.checked_sub(actual) {
        if rem != 0 {
            let remain: ctypes::timespec = diff.into();
            let ret = write_user_timespec(process, rem, &remain);
            if ret != 0 {
                return ret;
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

    let now: ctypes::timespec = match clockid as u32 {
        ctypes::CLOCK_REALTIME => axhal::time::wall_time().into(),
        ctypes::CLOCK_MONOTONIC => axhal::time::monotonic_time().into(),
        _ => return -LinuxError::EINVAL.code() as isize,
    };

    use axtask::TaskExtRef;
    let curr = axtask::current();
    let process: &pulse_core::task::Process = curr.task_ext();
    write_user_timespec(process, tp, &now)
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
    let timeval = ctypes::timeval {
        tv_sec: now.as_secs() as _,
        tv_usec: now.subsec_micros() as _,
    };

    use axtask::TaskExtRef;
    let curr = axtask::current();
    let process: &pulse_core::task::Process = curr.task_ext();
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&timeval as *const ctypes::timeval).cast::<u8>(),
            core::mem::size_of::<ctypes::timeval>(),
        )
    };

    process
        .aspace
        .lock()
        .write(VirtAddr::from(tv), bytes)
        .map(|_| 0)
        .unwrap_or_else(|e| {
            axlog::warn!("sys_gettimeofday: user write failed at {:#x}: {:?}", tv, e);
            -LinuxError::EFAULT.code() as isize
        })
}
