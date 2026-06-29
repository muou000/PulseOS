use alloc::{ffi::CString, vec::Vec, sync::Arc};
use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::general::{UTIME_NOW, UTIME_OMIT, iovec, timespec, timeval};
use memory_addr::MemoryAddr;
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
    ThreadLocal {
        thread: Arc<pulse_core::task::Thread>,
        buffer: Option<Vec<u8>>,
        len: usize,
    },
}

impl core::ops::Deref for ScratchBuffer {
    type Target = [u8];
    #[inline]
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Stack { buf, len } => &buf[..*len],
            Self::Heap(vec) => vec.as_slice(),
            Self::ThreadLocal { buffer, len, .. } => &buffer.as_ref().unwrap()[..*len],
        }
    }
}

impl core::ops::DerefMut for ScratchBuffer {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Stack { buf, len } => &mut buf[..*len],
            Self::Heap(vec) => vec.as_mut_slice(),
            Self::ThreadLocal { buffer, len, .. } => &mut buffer.as_mut().unwrap()[..*len],
        }
    }
}

impl Drop for ScratchBuffer {
    fn drop(&mut self) {
        if let Self::ThreadLocal { thread, buffer, .. } = self {
            if let Some(buf) = buffer.take() {
                thread.put_io_buffer(buf);
            }
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
        if let Ok(thread) = pulse_core::task::current_thread() {
            let mut buf = thread.take_io_buffer();
            if buf.len() < len {
                if buf.try_reserve_exact(len - buf.len()).is_err() {
                    thread.put_io_buffer(buf);
                    return Err(LinuxError::ENOMEM);
                }
                buf.resize(len, 0);
            } else {
                buf[..len].fill(0);
            }
            Ok(ScratchBuffer::ThreadLocal {
                thread,
                buffer: Some(buf),
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
}

pub(crate) fn alloc_uninit_bytes(len: usize, _site: &'static str) -> Result<ScratchBuffer, LinuxError> {
    if len <= 4096 {
        Ok(ScratchBuffer::Stack {
            buf: [0; 4096],
            len,
        })
    } else {
        if let Ok(thread) = pulse_core::task::current_thread() {
            let mut buf = thread.take_io_buffer();
            if buf.len() < len {
                if buf.try_reserve_exact(len - buf.len()).is_err() {
                    thread.put_io_buffer(buf);
                    return Err(LinuxError::ENOMEM);
                }
                buf.resize(len, 0);
            }
            Ok(ScratchBuffer::ThreadLocal {
                thread,
                buffer: Some(buf),
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

    Ok(Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)))
}

pub(crate) fn query_user_page_slice(
    user_addr: usize,
    max_len: usize,
    write: bool,
) -> Option<*mut [u8]> {
    let process = pulse_core::task::current_process().ok()?;
    let aspace_handle = process.aspace_handle();
    let aspace = aspace_handle.read();
    
    let vaddr = memory_addr::VirtAddr::from(user_addr);
    let start_page = vaddr.align_down_4k();
    let offset = vaddr.align_offset_4k();
    
    let required_flags = if write {
        axhal::paging::MappingFlags::WRITE | axhal::paging::MappingFlags::USER
    } else {
        axhal::paging::MappingFlags::READ | axhal::paging::MappingFlags::USER
    };
    
    let all_accessible = aspace.can_access_range(vaddr, max_len, required_flags);
    let first_chunk_len = core::cmp::min(max_len, 4096 - offset);
    if !all_accessible && !aspace.can_access_range(vaddr, first_chunk_len, required_flags) {
        return None;
    }
    
    let (start_paddr, flags, _) = aspace.query_vaddr(start_page).ok()?;
    if start_paddr.as_usize() == 0 || !flags.contains(required_flags) {
        return None;
    }
    
    let mut total_len = first_chunk_len;
    let mut current_page = start_page;
    let mut expected_paddr = start_paddr;
    
    while total_len < max_len {
        let next_page = match current_page.checked_add(4096) {
            Some(addr) => addr,
            None => break,
        };
        let next_expected_paddr = match expected_paddr.checked_add(4096) {
            Some(addr) => addr,
            None => break,
        };
        
        let remaining = max_len - total_len;
        let chunk = core::cmp::min(remaining, 4096);
        
        if !all_accessible && !aspace.can_access_range(next_page, chunk, required_flags) {
            break;
        }
        
        if let Ok((paddr, flags, _)) = aspace.query_vaddr(next_page) {
            if paddr == next_expected_paddr && flags.contains(required_flags) {
                total_len += chunk;
                current_page = next_page;
                expected_paddr = next_expected_paddr;
            } else {
                break;
            }
        } else {
            break;
        }
    }
    
    let kvaddr = axhal::mem::phys_to_virt(start_paddr) + offset;
    let ptr = kvaddr.as_mut_ptr();
    axlog::debug!(
        "query_user_page_slice: user_addr={:#x}, max_len={}, total_len={}",
        user_addr, max_len, total_len
    );
    Some(core::ptr::slice_from_raw_parts_mut(ptr, total_len))
}
