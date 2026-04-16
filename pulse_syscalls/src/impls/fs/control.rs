use crate::impls::utils::write_user_bytes;

use axerrno::LinuxError;

const TCGETS: usize = 0x5401;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;
const TIOCGWINSZ: usize = 0x5413;

#[repr(C)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

pub fn sys_ioctl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_ioctl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    match cmd {
        TCGETS => {
            // It's a stub to tell musl it is a terminal
            0
        }
        TIOCGPGRP => {
            if arg != 0 {
                let value = 1i32.to_ne_bytes();
                if let Err(e) = write_user_bytes(arg, &value) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TIOCSPGRP => 0,
        TIOCGWINSZ => {
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
        _ => {
            // ENOTTY
            -LinuxError::ENOTTY.code() as isize
        }
    }
}
