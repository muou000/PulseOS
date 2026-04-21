use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::LinuxError;
use chrono::{Datelike, Timelike, Utc};

use crate::impls::utils::write_user_bytes;

const TCGETS: u32 = 0x5401;
const TIOCGPGRP: u32 = 0x540f;
const TIOCSPGRP: u32 = 0x5410;
const TIOCGWINSZ: u32 = 0x5413;
const RTC_RD_TIME: u32 = 0x8024_7009;

static TTY_IOCTL_STUB_WARNED: AtomicBool = AtomicBool::new(false);

fn warn_tty_ioctl_stub_once(fd: usize, cmd: u32) {
    if !TTY_IOCTL_STUB_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!(
            "sys_ioctl: tty compatibility stub is active (fd={}, cmd={:#x}); semantics are \
             simplified",
            fd,
            cmd
        );
    }
}

#[repr(C)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

#[repr(C)]
struct RtcTime {
    tm_sec: i32,
    tm_min: i32,
    tm_hour: i32,
    tm_mday: i32,
    tm_mon: i32,
    tm_year: i32,
    tm_wday: i32,
    tm_yday: i32,
    tm_isdst: i32,
}

fn write_rtc_time(arg: usize) -> Result<(), LinuxError> {
    if arg == 0 {
        return Err(LinuxError::EFAULT);
    }
    if axhal::time::epochoffset_nanos() == 0 {
        return Err(LinuxError::ENODEV);
    }

    let wall_time = axhal::time::wall_time();
    let datetime = chrono::DateTime::<Utc>::from_timestamp(
        wall_time.as_secs() as i64,
        wall_time.subsec_nanos(),
    )
    .ok_or(LinuxError::EINVAL)?;

    let rtc_time = RtcTime {
        tm_sec: datetime.second() as i32,
        tm_min: datetime.minute() as i32,
        tm_hour: datetime.hour() as i32,
        tm_mday: datetime.day() as i32,
        tm_mon: datetime.month0() as i32,
        tm_year: datetime.year() - 1900,
        tm_wday: datetime.weekday().num_days_from_sunday() as i32,
        tm_yday: datetime.ordinal0() as i32,
        tm_isdst: 0,
    };

    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&rtc_time as *const RtcTime).cast::<u8>(),
            core::mem::size_of::<RtcTime>(),
        )
    };
    write_user_bytes(arg, bytes)?;
    Ok(())
}

pub fn sys_ioctl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_ioctl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    let cmd32 = cmd as u32;

    if cmd32 == RTC_RD_TIME {
        return match write_rtc_time(arg) {
            Ok(()) => 0,
            Err(e) => -e.code() as isize,
        };
    }

    match cmd32 {
        TCGETS => {
            // It's a stub to tell musl it is a terminal
            warn_tty_ioctl_stub_once(fd, cmd32);
            0
        }
        TIOCGPGRP => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                let value = 1i32.to_ne_bytes();
                if let Err(e) = write_user_bytes(arg, &value) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TIOCSPGRP => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            0
        }
        TIOCGWINSZ => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                let ws = WinSize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        (&ws as *const WinSize).cast::<u8>(),
                        core::mem::size_of::<WinSize>(),
                    )
                };
                if let Err(e) = write_user_bytes(arg, bytes) {
                    return -e.code() as isize;
                }
            }
            0
        }
        _ => {
            // ENOTTY
            -LinuxError::ENOTTY.code() as isize
        }
    }
}
