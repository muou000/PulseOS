use alloc::ffi::CString;
use alloc::vec::Vec;
use arceos_posix_api::ctypes;
use axerrno::LinuxError;
use core::time::Duration;

use pulse_core::task::uaccess;

pub(crate) fn with_process<R>(
    f: impl FnOnce(&pulse_core::task::Process) -> R,
) -> Result<R, LinuxError> {
    let process = pulse_core::task::current_process()?;
    Ok(f(process.as_ref()))
}

pub(crate) fn read_user_bytes(user_addr: usize, bytes: &mut [u8]) -> Result<(), LinuxError> {
    with_process(|process| process.read_user_bytes(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn write_user_bytes(user_addr: usize, bytes: &[u8]) -> Result<(), LinuxError> {
    with_process(|process| process.write_user_bytes(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn read_user_cstring(user_addr: usize) -> Result<CString, LinuxError> {
    let (bytes, terminated) = with_process(|process| {
        uaccess::read_user_cstring_bytes(process, user_addr, uaccess::DEFAULT_USER_CSTRING_MAX)
    })?
    .map_err(|e| LinuxError::from(e.canonicalize()))?;
    if !terminated {
        return Err(LinuxError::ENAMETOOLONG);
    }
    CString::new(bytes).map_err(|_| LinuxError::EINVAL)
}

pub(crate) fn read_user_iovec_array(
    user_addr: usize,
    iovcnt: usize,
) -> Result<Vec<ctypes::iovec>, LinuxError> {
    with_process(|process| {
        uaccess::read_user_plain_array::<ctypes::iovec>(process, user_addr, iovcnt)
    })?
    .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn read_user_timespec(user_addr: usize) -> Result<ctypes::timespec, LinuxError> {
    with_process(|process| uaccess::read_user_plain(process, user_addr))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn read_user_i64(user_addr: usize) -> Result<i64, LinuxError> {
    with_process(|process| uaccess::read_user_plain(process, user_addr))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn write_user_i64(user_addr: usize, value: i64) -> Result<(), LinuxError> {
    with_process(|process| uaccess::write_user_plain(process, user_addr, &value))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn timespec_to_update_time(
    ts: ctypes::timespec,
    now: Duration,
) -> Result<Option<Duration>, LinuxError> {
    const UTIME_NOW: i64 = 0x3fff_ffff;
    const UTIME_OMIT: i64 = 0x3fff_fffe;

    match ts.tv_nsec {
        UTIME_OMIT => Ok(None),
        UTIME_NOW => Ok(Some(now)),
        nsec if !(0..1_000_000_000).contains(&nsec) => Err(LinuxError::EINVAL),
        _ if ts.tv_sec < 0 => Err(LinuxError::EINVAL),
        _ => Ok(Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))),
    }
}