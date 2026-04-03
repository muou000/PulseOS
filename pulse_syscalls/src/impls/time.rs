use arceos_posix_api::ctypes;
use arceos_posix_api::sys_clock_gettime as ax_sys_clock_gettime;
use arceos_posix_api::sys_nanosleep as ax_sys_nanosleep;

pub fn sys_nanosleep(req: usize, rem: usize) -> isize {
    axlog::debug!("sys_nanosleep: req={:#x}, rem={:#x}", req, rem);
    unsafe { ax_sys_nanosleep(req as *const ctypes::timespec, rem as *mut ctypes::timespec) as isize }
}

/// sys_clock_gettime - 获取时钟时间
pub fn sys_clock_gettime(clockid: i32, tp: usize) -> isize {
    axlog::debug!("sys_clock_gettime: clockid={}, tp={:#x}", clockid, tp);
    unsafe { ax_sys_clock_gettime(clockid, tp as *mut ctypes::timespec) as isize }
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

    unsafe {
        *(tv as *mut ctypes::timeval) = timeval;
    }

    0
}
