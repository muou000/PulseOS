use alloc::{ffi::CString, vec::Vec};
use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::general::{UTIME_NOW, UTIME_OMIT, iovec, timespec, timeval};
use pulse_core::task::uaccess;

const MAX_USER_IOVCNT: usize = 1024;

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
) -> Result<Vec<iovec>, LinuxError> {
    if iovcnt > MAX_USER_IOVCNT {
        return Err(LinuxError::EINVAL);
    }
    with_process(|process| uaccess::read_user_plain_array::<iovec>(process, user_addr, iovcnt))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) enum ScratchBuffer {
    Stack {
        buf: [u8; 4096],
        len: usize,
    },
    Heap(Vec<u8>),
}

impl core::ops::Deref for ScratchBuffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Stack { buf, len } => &buf[..*len],
            Self::Heap(vec) => vec.as_slice(),
        }
    }
}

impl core::ops::DerefMut for ScratchBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Stack { buf, len } => &mut buf[..*len],
            Self::Heap(vec) => vec.as_mut_slice(),
        }
    }
}

pub(crate) fn alloc_zeroed_bytes(len: usize, _site: &'static str) -> Result<ScratchBuffer, LinuxError> {
    if len <= 4096 {
        Ok(ScratchBuffer::Stack {
            buf: [0; 4096],
            len,
        })
    } else {
        let mut out = Vec::new();
        if out.try_reserve_exact(len).is_err() {
            return Err(LinuxError::ENOMEM);
        }
        out.resize(len, 0);
        Ok(ScratchBuffer::Heap(out))
    }
}

pub(crate) fn alloc_uninit_bytes(len: usize, _site: &'static str) -> Result<ScratchBuffer, LinuxError> {
    if len <= 4096 {
        Ok(ScratchBuffer::Stack {
            buf: [0; 4096],
            len,
        })
    } else {
        let mut out = Vec::new();
        if out.try_reserve_exact(len).is_err() {
            return Err(LinuxError::ENOMEM);
        }
        unsafe {
            out.set_len(len);
        }
        Ok(ScratchBuffer::Heap(out))
    }
}

pub(crate) fn read_user_timespec(user_addr: usize) -> Result<timespec, LinuxError> {
    with_process(|process| uaccess::read_user_plain(process, user_addr))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn read_user_timeval(user_addr: usize) -> Result<timeval, LinuxError> {
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
    ts: timespec,
    now: Duration,
) -> Result<Option<Duration>, LinuxError> {
    let nsec = ts.tv_nsec as i64;
    let utime_now = UTIME_NOW as i64;
    let utime_omit = UTIME_OMIT as i64;

    if nsec == utime_omit {
        return Ok(None);
    }
    if nsec == utime_now {
        return Ok(Some(now));
    }
    if !(0..1_000_000_000).contains(&nsec) || ts.tv_sec < 0 {
        return Err(LinuxError::EINVAL);
    }

    Ok(Some(Duration::new(ts.tv_sec as u64, nsec as u32)))
}
