use core::sync::atomic::{AtomicBool, Ordering};
extern crate alloc;
use alloc::format;

use axerrno::LinuxError;
use chrono::{Datelike, Timelike, Utc};

use crate::impls::utils::write_user_bytes;

use linux_raw_sys::ioctl::{
    BLKGETSIZE64, BLKSSZGET, RTC_RD_TIME, SIOCGIFFLAGS, SIOCGIFINDEX, SIOCSIFFLAGS, TCGETS, TIOCGPGRP,
    TIOCGWINSZ, TIOCSPGRP,
};
use linux_raw_sys::loop_device::{
    LOOP_CLR_FD, LOOP_CTL_GET_FREE, LOOP_GET_STATUS, LOOP_GET_STATUS64, LOOP_SET_FD,
    LOOP_SET_STATUS, LOOP_SET_STATUS64,
};

static TTY_IOCTL_STUB_WARNED: AtomicBool = AtomicBool::new(false);

fn do_handle_loop_ioctl(fd: usize, cmd: u32, arg: usize) -> Result<isize, LinuxError> {
    let process = pulse_core::task::current_process()?;
    let fd_table = process.fd_table();
    let entry = fd_table.read().get_entry_cloned(fd)?;

    let metadata = entry.object.stat()?;

    let major =
        ((metadata.st_rdev >> 8) & 0xfff) as u32 | ((metadata.st_rdev >> 32) & !0xfff) as u32;
    let minor = (metadata.st_rdev & 0xff) as u32 | ((metadata.st_rdev >> 12) & !0xff) as u32;

    if major == 10 && minor == 237 {
        // /dev/loop-control
        if cmd == LOOP_CTL_GET_FREE {
            if let Some(id) = axfs::find_free_loop_device() {
                return Ok(id as isize);
            } else {
                return Err(LinuxError::ENOSPC);
            }
        }
    } else if major == 7 {
        // /dev/loopN
        let loop_id = minor as usize;
        match cmd {
            LOOP_SET_FD => {
                let backing_fd = arg;
                let backing_entry = fd_table.read().get_entry_cloned(backing_fd)?;
                if let Some(file_obj) = backing_entry
                    .object
                    .as_any()
                    .downcast_ref::<pulse_core::fd_table::FileObject>()
                {
                    let file = file_obj.inner();
                    let backend = file.backend().map_err(LinuxError::from)?.clone();
                    axfs::set_loop_backing(loop_id, axfs::File::new(backend, file.flags()))
                        .map_err(LinuxError::from)?;
                    return Ok(0);
                } else {
                    return Err(LinuxError::EBADF);
                }
            }
            LOOP_CLR_FD => {
                if !axfs::is_loop_bound(loop_id) {
                    return Err(LinuxError::ENXIO);
                }
                axfs::clear_loop_backing(loop_id).map_err(LinuxError::from)?;
                return Ok(0);
            }
            LOOP_SET_STATUS | LOOP_SET_STATUS64 | LOOP_GET_STATUS | LOOP_GET_STATUS64 => {
                if axfs::is_loop_bound(loop_id) {
                    return Ok(0);
                } else {
                    return Err(LinuxError::ENXIO);
                }
            }
            BLKGETSIZE64 => {
                let size = match axfs::lookup_location(&format!("/dev/loop{}", loop_id)) {
                    Ok(loc) => match loc.metadata() {
                        Ok(m) => m.size,
                        Err(_) => 0,
                    },
                    Err(_) => 0,
                };
                write_user_bytes(arg, &size.to_ne_bytes())?;
                return Ok(0);
            }
            BLKSSZGET => {
                let ssz = 512i32;
                write_user_bytes(arg, &ssz.to_ne_bytes())?;
                return Ok(0);
            }
            _ => {}
        }
    }

    Err(LinuxError::ENOTTY)
}

fn handle_loop_ioctl(fd: usize, cmd: u32, arg: usize) -> isize {
    match do_handle_loop_ioctl(fd, cmd, arg) {
        Ok(res) => res,
        Err(e) => -e.code() as isize,
    }
}

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

    let res = handle_loop_ioctl(fd, cmd32, arg);
    if res != -axerrno::LinuxError::ENOTTY.code() as isize {
        return res;
    }

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
                let ws = WinSize {
                    ws_row: 24,
                    ws_col: 80,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
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
        SIOCGIFINDEX => {
            if arg != 0 {
                let mut name_buf = [0u8; 16];
                if let Ok(()) = crate::impls::utils::read_user_bytes(arg, &mut name_buf) {
                    let name_str = core::str::from_utf8(&name_buf)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    let ifindex = if name_str == "lo" { 1i32 } else { 2i32 };
                    let bytes = ifindex.to_ne_bytes();
                    if let Err(e) = crate::impls::utils::write_user_bytes(arg + 16, &bytes) {
                        return -e.code() as isize;
                    }
                }
            }
            0
        }
        SIOCGIFFLAGS => {
            if arg != 0 {
                let mut name_buf = [0u8; 16];
                if let Ok(()) = crate::impls::utils::read_user_bytes(arg, &mut name_buf) {
                    let name_str = core::str::from_utf8(&name_buf)
                        .unwrap_or("")
                        .trim_end_matches('\0');
                    let flags: u16 = if name_str == "lo" {
                        0x1 | 0x8 | 0x40 // IFF_UP | IFF_LOOPBACK | IFF_RUNNING
                    } else {
                        0x1 | 0x40 // IFF_UP | IFF_RUNNING
                    };
                    let bytes = flags.to_ne_bytes();
                    if let Err(e) = crate::impls::utils::write_user_bytes(arg + 16, &bytes) {
                        return -e.code() as isize;
                    }
                }
            }
            0
        }
        SIOCSIFFLAGS => 0,
        _ => {
            // ENOTTY
            -LinuxError::ENOTTY.code() as isize
        }
    }
}
