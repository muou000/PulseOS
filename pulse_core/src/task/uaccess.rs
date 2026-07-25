use alloc::vec::Vec;

use axerrno::{AxError, AxResult};
use memory_addr::PAGE_SIZE_4K;

use super::Process;
use crate::config::{USER_SPACE_BASE, USER_SPACE_SIZE};

pub const DEFAULT_USER_CSTRING_MAX: usize = 4096;
const USER_CSTRING_READ_CHUNK: usize = 256;
const USER_SPACE_END: usize = USER_SPACE_BASE + USER_SPACE_SIZE;

const fn user_range_is_valid(user_addr: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = user_addr.checked_add(len) else {
        return false;
    };
    user_addr >= USER_SPACE_BASE && end <= USER_SPACE_END
}

const _: () = {
    assert!(!user_range_is_valid(0, 1));
    assert!(!user_range_is_valid(USER_SPACE_BASE - 1, 1));
    assert!(user_range_is_valid(USER_SPACE_BASE, 1));
    assert!(user_range_is_valid(USER_SPACE_END - 1, 1));
    assert!(!user_range_is_valid(USER_SPACE_END, 1));
    assert!(!user_range_is_valid(usize::MAX, 2));
};

pub fn validate_user_range(user_addr: usize, len: usize) -> AxResult<()> {
    if user_range_is_valid(user_addr, len) {
        Ok(())
    } else {
        Err(AxError::BadAddress)
    }
}

#[cfg(target_arch = "riscv64")]
struct UserAccessGuard {
    restore_disabled: bool,
}

#[cfg(target_arch = "riscv64")]
impl UserAccessGuard {
    #[inline]
    fn new() -> Self {
        let restore_disabled = !axcpu::asm::user_access_enabled();
        if restore_disabled {
            axcpu::asm::enable_user_access();
        }
        Self { restore_disabled }
    }
}

#[cfg(target_arch = "riscv64")]
impl Drop for UserAccessGuard {
    #[inline]
    fn drop(&mut self) {
        if self.restore_disabled {
            axcpu::asm::disable_user_access();
        }
    }
}

/// Copies as many bytes as possible and returns the number copied.
pub fn copy_from_user_partial(dst: &mut [u8], src_user_addr: usize) -> AxResult<usize> {
    if dst.is_empty() {
        return Ok(0);
    }
    validate_user_range(src_user_addr, dst.len())?;
    #[cfg(target_arch = "riscv64")]
    let _guard = UserAccessGuard::new();
    let uncopied =
        unsafe { axcpu::user_copy(dst.as_mut_ptr(), src_user_addr as *const u8, dst.len()) };
    Ok(dst.len().saturating_sub(uncopied.min(dst.len())))
}

/// Copies as many bytes as possible and returns the number copied.
pub fn copy_to_user_partial(dst_user_addr: usize, src: &[u8]) -> AxResult<usize> {
    if src.is_empty() {
        return Ok(0);
    }
    validate_user_range(dst_user_addr, src.len())?;
    #[cfg(target_arch = "riscv64")]
    let _guard = UserAccessGuard::new();
    let uncopied = unsafe { axcpu::user_copy(dst_user_addr as *mut u8, src.as_ptr(), src.len()) };
    Ok(src.len().saturating_sub(uncopied.min(src.len())))
}

pub fn copy_from_user(dst: &mut [u8], src_user_addr: usize) -> AxResult<()> {
    if copy_from_user_partial(dst, src_user_addr)? == dst.len() {
        Ok(())
    } else {
        Err(AxError::BadAddress)
    }
}

pub fn copy_to_user(dst_user_addr: usize, src: &[u8]) -> AxResult<()> {
    if copy_to_user_partial(dst_user_addr, src)? == src.len() {
        Ok(())
    } else {
        Err(AxError::BadAddress)
    }
}

fn read_user_cstring_bytes_with(
    user_addr: usize,
    max_len: usize,
    mut read_user_bytes: impl FnMut(usize, &mut [u8]) -> AxResult<()>,
) -> AxResult<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(max_len).is_err() {
        return Err(AxError::NoMemory);
    }

    while bytes.len() < max_len {
        let chunk_start = bytes.len();
        let chunk_addr = user_addr
            .checked_add(chunk_start)
            .ok_or(AxError::BadAddress)?;
        let page_remaining = PAGE_SIZE_4K - (chunk_addr & (PAGE_SIZE_4K - 1));
        let chunk_len = core::cmp::min(
            USER_CSTRING_READ_CHUNK,
            core::cmp::min(max_len - chunk_start, page_remaining),
        );

        bytes.resize(chunk_start + chunk_len, 0);
        if read_user_bytes(chunk_addr, &mut bytes[chunk_start..]).is_err() {
            bytes.truncate(chunk_start);

            // A bulk read may extend past the first NUL into an invalid range.
            // Retry byte-wise so bytes after the terminator cannot cause EFAULT.
            for offset in 0..chunk_len {
                let byte_addr = chunk_addr.checked_add(offset).ok_or(AxError::BadAddress)?;
                let mut byte = [0u8; 1];
                read_user_bytes(byte_addr, &mut byte)?;
                if byte[0] == 0 {
                    return Ok((bytes, true));
                }
                bytes.push(byte[0]);
            }
            continue;
        }

        if let Some(nul_offset) = bytes[chunk_start..].iter().position(|byte| *byte == 0) {
            bytes.truncate(chunk_start + nul_offset);
            return Ok((bytes, true));
        }
    }

    Ok((bytes, false))
}

pub fn read_user_cstring_bytes(
    process: &Process,
    user_addr: usize,
    max_len: usize,
) -> AxResult<(Vec<u8>, bool)> {
    read_user_cstring_bytes_with(user_addr, max_len, |addr, bytes| {
        process.read_user_bytes(addr, bytes)
    })
}

pub fn read_user_plain<T: Copy>(process: &Process, user_addr: usize) -> AxResult<T> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), core::mem::size_of::<T>())
    };
    process.read_user_bytes(user_addr, bytes)?;
    Ok(unsafe { value.assume_init() })
}

pub fn write_user_plain<T: Copy>(process: &Process, user_addr: usize, value: &T) -> AxResult<()> {
    let bytes = unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    process.write_user_bytes(user_addr, bytes)
}

pub fn write_user_bytes(process: &Process, user_addr: usize, bytes: &[u8]) -> AxResult<()> {
    process.write_user_bytes(user_addr, bytes)
}

pub fn read_user_plain_array<T: Copy>(
    process: &Process,
    user_addr: usize,
    count: usize,
) -> AxResult<Vec<T>> {
    let mut out = Vec::new();
    if out.try_reserve_exact(count).is_err() {
        return Err(AxError::NoMemory);
    }
    let elem_size = core::mem::size_of::<T>();
    for i in 0..count {
        let byte_off = i.checked_mul(elem_size).ok_or(AxError::InvalidInput)?;
        let addr = user_addr
            .checked_add(byte_off)
            .ok_or(AxError::InvalidInput)?;
        out.push(read_user_plain(process, addr)?);
    }
    Ok(out)
}

pub fn write_user_plain_array<T: Copy>(
    process: &Process,
    user_addr: usize,
    values: &[T],
) -> AxResult<()> {
    let elem_size = core::mem::size_of::<T>();
    for (i, val) in values.iter().enumerate() {
        let byte_off = i.checked_mul(elem_size).ok_or(AxError::InvalidInput)?;
        let addr = user_addr
            .checked_add(byte_off)
            .ok_or(AxError::InvalidInput)?;
        write_user_plain(process, addr, val)?;
    }
    Ok(())
}
