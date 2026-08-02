use alloc::{sync::Arc, vec::Vec};
use core::{ptr::NonNull, time::Duration};

use axalloc::{frame_table, global_allocator};
use axerrno::LinuxError;
use axhal::mem::phys_to_virt;
use linux_raw_sys::general::{UTIME_NOW, UTIME_OMIT, iovec, timespec, timeval};
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr};
use pulse_core::task::uaccess;

const MAX_USER_IOVCNT: usize = 1024;
// Syscall I/O submits at most 64 KiB at once. An unaligned 64 KiB run spans
// no more than 17 base pages, so frame ownership stays on the kernel stack.
const PINNED_USER_IO_MAX_PAGES: usize = 17;

/// A physically contiguous user-memory slice whose backing frames remain
/// alive until the guard is dropped.
///
/// A syscall may suspend after handing either a source or destination slice to
/// an `FdObject`. Returning a raw pointer from `query_user_page_slice` is not
/// sufficient in that case because another thread can unmap the user range.
pub(crate) struct PinnedUserSlice {
    ptr: NonNull<u8>,
    len: usize,
    frames: heapless::Vec<PhysAddr, PINNED_USER_IO_MAX_PAGES>,
}

impl PinnedUserSlice {
    #[inline]
    pub(crate) fn as_slice(&self) -> &[u8] {
        // SAFETY: frames owns one reference for every covered page until this
        // guard is dropped. The constructor only exposes a contiguous range.
        unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) }
    }

    #[inline]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: see as_slice. The write pin constructor additionally checked
        // that every page has a writable user mapping.
        unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len) }
    }
}

impl Drop for PinnedUserSlice {
    fn drop(&mut self) {
        while let Some(frame) = self.frames.pop() {
            release_pinned_user_frame(frame);
        }
    }
}

fn release_pinned_user_frame(frame: PhysAddr) {
    let table = frame_table();
    if table.contains(frame) && table.dec_ref(frame) == 0 {
        global_allocator().dealloc_pages(phys_to_virt(frame).as_usize(), 1);
    }
}

/// Linux PATH_MAX, including the trailing NUL in a user C string.
pub(crate) const USER_PATH_MAX: usize = uaccess::DEFAULT_USER_CSTRING_MAX;

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

pub(crate) fn read_user_bytes_partial(
    user_addr: usize,
    bytes: &mut [u8],
) -> Result<usize, LinuxError> {
    with_process(|process| process.read_user_bytes_partial(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn write_user_bytes(user_addr: usize, bytes: &[u8]) -> Result<(), LinuxError> {
    with_process(|process| process.write_user_bytes(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn write_user_bytes_partial(
    user_addr: usize,
    bytes: &[u8],
) -> Result<usize, LinuxError> {
    with_process(|process| process.write_user_bytes_partial(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

pub(crate) fn read_user_cstring_to_slice(
    user_addr: usize,
    dst: &mut [u8],
) -> Result<usize, LinuxError> {
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let max_len = dst.len();
    let mut len = 0;
    while len < max_len {
        let chunk_addr = user_addr.checked_add(len).ok_or(LinuxError::EFAULT)?;
        let page_remaining = 4096 - (chunk_addr & 4095);
        let chunk_len = core::cmp::min(128, core::cmp::min(max_len - len, page_remaining));

        let read_len = match read_user_bytes_partial(chunk_addr, &mut dst[len..len + chunk_len]) {
            Ok(n) if n > 0 => n,
            _ => {
                let mut byte = [0u8; 1];
                read_user_bytes(chunk_addr, &mut byte)?;
                if byte[0] == 0 {
                    return Ok(len);
                }
                dst[len] = byte[0];
                1
            }
        };

        if let Some(nul_pos) = dst[len..len + read_len].iter().position(|&b| b == 0) {
            return Ok(len + nul_pos);
        }
        len += read_len;
    }
    Err(LinuxError::ENAMETOOLONG)
}

pub(crate) fn with_user_path_str<R>(
    user_addr: usize,
    f: impl FnOnce(&str) -> Result<R, LinuxError>,
) -> Result<R, LinuxError> {
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    let mut stack_buf = [0u8; USER_PATH_MAX];
    let len = read_user_cstring_to_slice(user_addr, &mut stack_buf)?;
    let path_str = core::str::from_utf8(&stack_buf[..len]).map_err(|_| LinuxError::EINVAL)?;
    f(path_str)
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

pub(crate) fn alloc_zeroed_bytes(
    len: usize,
    _site: &'static str,
) -> Result<ScratchBuffer, LinuxError> {
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

pub(crate) fn alloc_uninit_bytes(
    len: usize,
    _site: &'static str,
) -> Result<ScratchBuffer, LinuxError> {
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

fn pin_user_slice(
    user_addr: usize,
    max_len: usize,
    required_flags: axhal::paging::MappingFlags,
) -> Option<PinnedUserSlice> {
    let process = pulse_core::task::current_process().ok()?;
    if max_len == 0 {
        return None;
    }

    let first_chunk_len = core::cmp::min(max_len, 4096 - (user_addr & 4095));
    process
        .validate_user_range(user_addr, first_chunk_len)
        .ok()?;
    process
        .try_fault_in_user_range(user_addr, first_chunk_len, required_flags)
        .ok()?;

    let aspace_handle = process.aspace_handle();
    let aspace = aspace_handle.read();
    let mut current_page = VirtAddr::from(user_addr).align_down_4k();
    let mut page_offset = user_addr & 4095;
    let mut expected_paddr = None;
    let mut total_len = 0usize;
    let mut frames = heapless::Vec::new();

    while total_len < max_len {
        let paddr = match aspace.pin_user_frame(current_page, required_flags) {
            Ok(paddr) => paddr,
            Err(_) if frames.is_empty() => return None,
            Err(_) => break,
        };
        if expected_paddr.is_some_and(|expected| expected != paddr) {
            release_pinned_user_frame(paddr);
            break;
        }

        let chunk = core::cmp::min(max_len - total_len, 4096 - page_offset);
        if let Err(paddr) = frames.push(paddr) {
            release_pinned_user_frame(paddr);
            break;
        }
        total_len += chunk;
        if total_len == max_len {
            break;
        }

        let Some(next_page) = current_page.checked_add(4096) else {
            break;
        };
        let Some(next_paddr) = paddr.checked_add(4096) else {
            break;
        };
        current_page = next_page;
        expected_paddr = Some(next_paddr);
        page_offset = 0;
    }
    drop(aspace);

    let first = *frames.first()?;
    let ptr = match NonNull::new((phys_to_virt(first) + (user_addr & 4095)).as_mut_ptr()) {
        Some(ptr) => ptr,
        None => {
            while let Some(frame) = frames.pop() {
                release_pinned_user_frame(frame);
            }
            return None;
        }
    };
    Some(PinnedUserSlice {
        ptr,
        len: total_len,
        frames,
    })
}

/// Pins a physically contiguous user-readable run for an operation that can
/// suspend. The returned slice is bounded by the caller and may be shorter
/// when the next virtual page is not resident or physically adjacent.
pub(crate) fn pin_user_read_slice(user_addr: usize, max_len: usize) -> Option<PinnedUserSlice> {
    pin_user_slice(user_addr, max_len, axhal::paging::MappingFlags::READ)
}

/// Pins a physically contiguous user-writable run for an operation that can
/// suspend while producing bytes into user memory.
pub(crate) fn pin_user_write_slice(user_addr: usize, max_len: usize) -> Option<PinnedUserSlice> {
    pin_user_slice(user_addr, max_len, axhal::paging::MappingFlags::WRITE)
}
