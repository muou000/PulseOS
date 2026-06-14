use core::sync::atomic::{AtomicBool, Ordering};
extern crate alloc;

use axerrno::LinuxError;
use chrono::{Datelike, Timelike, Utc};
use linux_raw_sys::{
    ioctl::{
        BLKGETSIZE64, BLKSSZGET, RTC_RD_TIME, SIOCGIFFLAGS, SIOCGIFINDEX, SIOCSIFFLAGS, TCGETS,
        TCSETS, TCSETSW, TCSETSF, TCGETS2, TCSETS2, TCSETSW2, TCSETSF2, TIOCGPGRP, TIOCGWINSZ, TIOCSPGRP,
    },
    loop_device::{
        LOOP_CLR_FD, LOOP_CTL_GET_FREE, LOOP_GET_STATUS, LOOP_GET_STATUS64, LOOP_SET_FD,
        LOOP_SET_STATUS, LOOP_SET_STATUS64,
    },
};

use crate::impls::utils::{read_user_bytes, write_user_bytes};

static TTY_IOCTL_STUB_WARNED: AtomicBool = AtomicBool::new(false);

fn do_handle_loop_ioctl(fd: usize, cmd: u32, arg: usize) -> Result<isize, LinuxError> {
    let process = pulse_core::task::current_process()?;
    let fd_table = process.fd_table();
    let entry = fd_table.read().get_entry_cloned(fd)?;

    let metadata = entry.object.stat()?;

    let major =
        ((metadata.st_rdev >> 8) & 0xfff) as u32 | ((metadata.st_rdev >> 32) & !0xfff) as u32;
    let minor = (metadata.st_rdev & 0xff) as u32 | ((metadata.st_rdev >> 12) & !0xff) as u32;

    axlog::debug!(
        "do_handle_loop_ioctl: fd={}, cmd={:#x}, major={}, minor={}",
        fd,
        cmd,
        major,
        minor
    );

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
                let size = axfs::get_loop_size(loop_id).unwrap_or(0);
                write_user_bytes(arg, &size.to_ne_bytes())?;
                return Ok(0);
            }
            0x127a => {
                // BLKGETSIZE (unsigned long)
                let size = axfs::get_loop_size(loop_id).unwrap_or(0);
                let sectors = (size / 512) as usize;
                write_user_bytes(arg, &sectors.to_ne_bytes())?;
                return Ok(0);
            }
            0x1277 => {
                // BLKPBSZGET (unsigned int)
                let val = 512u32;
                write_user_bytes(arg, &val.to_ne_bytes())?;
                return Ok(0);
            }
            0x1278 => {
                // BLKDISCARDZEROES (unsigned int)
                let val = 0u32;
                write_user_bytes(arg, &val.to_ne_bytes())?;
                return Ok(0);
            }
            0x1279 => {
                // BLKSECTGET (unsigned short)
                let val = 255u16;
                write_user_bytes(arg, &val.to_ne_bytes())?;
                return Ok(0);
            }
            0x127b => {
                // BLKROTATIONAL (unsigned short)
                let val = 0u16;
                write_user_bytes(arg, &val.to_ne_bytes())?;
                return Ok(0);
            }
            0x125e => {
                // BLKFLUSH
                return Ok(0);
            }
            BLKSSZGET => {
                let ssz = 512i32;
                write_user_bytes(arg, &ssz.to_ne_bytes())?;
                return Ok(0);
            }
            0x301 => {
                axlog::debug!(
                    "do_handle_loop_ioctl: handling HDIO_GETGEO for loop{}",
                    loop_id
                );
                let size = axfs::get_loop_size(loop_id).unwrap_or(0);
                let heads = 255u8;
                let sectors = 63u8;
                let cylinders = (size / (heads as u64 * sectors as u64 * 512)) as u16;

                #[repr(C)]
                struct HdGeometry {
                    heads: u8,
                    sectors: u8,
                    cylinders: u16,
                    start: u64,
                }
                let geo = HdGeometry {
                    heads,
                    sectors,
                    cylinders,
                    start: 0,
                };
                write_user_bytes(arg, unsafe {
                    core::slice::from_raw_parts(
                        (&geo as *const HdGeometry).cast::<u8>(),
                        core::mem::size_of::<HdGeometry>(),
                    )
                })?;
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

    if let Ok(process) = pulse_core::task::current_process() {
        if let Ok(entry) = process.fd_table().read().get_entry_cloned(fd) {
            match entry.object.ioctl(cmd32, arg) {
                Ok(res) => return res,
                Err(LinuxError::ENOTTY) => {}
                Err(e) => return -e.code() as isize,
            }
        }
    }

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
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                if let Err(e) = pulse_core::fd_table::read_tty_termios(arg) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                if let Err(e) = pulse_core::fd_table::write_tty_termios(arg) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TCGETS2 => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                if let Err(e) = pulse_core::fd_table::read_tty_termios2(arg) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TCSETS2 | TCSETSW2 | TCSETSF2 => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                if let Err(e) = pulse_core::fd_table::write_tty_termios2(arg) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TIOCGPGRP => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                let mut pgid = pulse_core::fd_table::get_foreground_pgid();
                if pgid == 0 {
                    if let Ok(process) = pulse_core::task::current_process() {
                        pgid = process.pgid();
                    } else {
                        pgid = 1;
                    }
                }
                let value = (pgid as i32).to_ne_bytes();
                if let Err(e) = write_user_bytes(arg, &value) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TIOCSPGRP => {
            warn_tty_ioctl_stub_once(fd, cmd32);
            if arg != 0 {
                let mut bytes = [0u8; 4];
                if let Err(e) = read_user_bytes(arg, &mut bytes) {
                    return -e.code() as isize;
                }
                let pgid = i32::from_ne_bytes(bytes) as u64;
                pulse_core::fd_table::set_foreground_pgid(pgid);
            }
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
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let mut name_buf = [0u8; 16];
            if let Err(e) = crate::impls::utils::read_user_bytes(arg, &mut name_buf) {
                return -e.code() as isize;
            }
            let name_str = core::str::from_utf8(&name_buf)
                .unwrap_or("")
                .trim_end_matches('\0');
            let ifindex = if name_str == "lo" { 1i32 } else { 2i32 };
            let bytes = ifindex.to_ne_bytes();
            if let Err(e) = crate::impls::utils::write_user_bytes(arg + 16, &bytes) {
                return -e.code() as isize;
            }
            0
        }
        SIOCGIFFLAGS => {
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let mut name_buf = [0u8; 16];
            if let Err(e) = crate::impls::utils::read_user_bytes(arg, &mut name_buf) {
                return -e.code() as isize;
            }
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
            0
        }
        SIOCSIFFLAGS => {
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let mut name_buf = [0u8; 16];
            if let Err(e) = crate::impls::utils::read_user_bytes(arg, &mut name_buf) {
                return -e.code() as isize;
            }
            0
        }
        _ => {
            // ENOTTY
            -LinuxError::ENOTTY.code() as isize
        }
    }
}
