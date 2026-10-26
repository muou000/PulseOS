use alloc::vec::Vec;

use axerrno::{AxError, AxResult};
use memory_addr::PAGE_SIZE_4K;
pub use pulse_user_abi::{
    AbiByteBuffer, AbiDecodeError, AbiReader, AbiWriter, FromUserAbi, IntoUserAbi, UserAbiType,
    UserMemoryRange, abi_size_of, checked_abi_array_size, decode_from_bytes, encode_into_slice,
    encode_to_buffer, impl_user_abi_enum, impl_user_abi_fixed_array, impl_user_abi_struct,
    read_user_array_with, read_user_slice_with, read_user_value_with, write_user_slice_with,
    write_user_value_partial_with, write_user_value_with,
};

use super::Process;
use crate::config::{USER_SPACE_BASE, USER_SPACE_SIZE};

pub const DEFAULT_USER_CSTRING_MAX: usize = 4096;
const USER_CSTRING_READ_CHUNK: usize = 256;
const USER_SPACE_END: usize = USER_SPACE_BASE + USER_SPACE_SIZE;
pub const USER_MEMORY_RANGE: UserMemoryRange =
    match UserMemoryRange::new(USER_SPACE_BASE, USER_SPACE_SIZE) {
        Some(range) => range,
        None => panic!("USER_SPACE_BASE + USER_SPACE_SIZE overflowed"),
    };

const fn user_range_is_valid(user_addr: usize, len: usize) -> bool {
    USER_MEMORY_RANGE.contains(user_addr, len)
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
    USER_MEMORY_RANGE.validate(user_addr, len)
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

pub fn copy_from_user_value<T: FromUserAbi>(src_user_addr: usize) -> AxResult<T> {
    read_user_value_with(src_user_addr, |addr, dst| copy_from_user_partial(dst, addr))
}

pub fn copy_to_user_value_partial<T: IntoUserAbi>(
    dst_user_addr: usize,
    value: &T,
) -> AxResult<usize> {
    write_user_value_partial_with(dst_user_addr, value, copy_to_user_partial)
}

pub fn copy_to_user_value<T: IntoUserAbi>(dst_user_addr: usize, value: &T) -> AxResult<()> {
    write_user_value_with(dst_user_addr, value, copy_to_user_partial)
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

pub fn read_user_value<T: FromUserAbi>(process: &Process, user_addr: usize) -> AxResult<T> {
    read_user_value_with(user_addr, |addr, dst| {
        process.read_user_bytes_partial(addr, dst)
    })
}

pub fn write_user_value_partial<T: IntoUserAbi>(
    process: &Process,
    user_addr: usize,
    value: &T,
) -> AxResult<usize> {
    write_user_value_partial_with(user_addr, value, |addr, src| {
        process.write_user_bytes_partial(addr, src)
    })
}

pub fn write_user_value<T: IntoUserAbi>(
    process: &Process,
    user_addr: usize,
    value: &T,
) -> AxResult<()> {
    write_user_value_with(user_addr, value, |addr, src| {
        process.write_user_bytes_partial(addr, src)
    })
}

fn validate_abi_array_range<T: UserAbiType>(
    process: &Process,
    user_addr: usize,
    count: usize,
) -> AxResult<()> {
    let total_bytes = checked_abi_array_size::<T>(count)?;
    if total_bytes > 0 {
        process.validate_user_range(user_addr, total_bytes)?;
    }
    Ok(())
}

pub fn read_user_value_slice<T: FromUserAbi>(
    process: &Process,
    user_addr: usize,
    dst: &mut [T],
) -> AxResult<()> {
    validate_abi_array_range::<T>(process, user_addr, dst.len())?;
    read_user_slice_with(user_addr, dst, |addr, bytes| {
        process.read_user_bytes_partial(addr, bytes)
    })
}

pub fn read_user_value_array<T: FromUserAbi>(
    process: &Process,
    user_addr: usize,
    count: usize,
) -> AxResult<Vec<T>> {
    validate_abi_array_range::<T>(process, user_addr, count)?;
    read_user_array_with(user_addr, count, |addr, bytes| {
        process.read_user_bytes_partial(addr, bytes)
    })
}

pub fn write_user_value_array<T: IntoUserAbi>(
    process: &Process,
    user_addr: usize,
    values: &[T],
) -> AxResult<()> {
    write_user_slice_with(user_addr, values, |addr, bytes| {
        process.write_user_bytes_partial(addr, bytes)
    })
}

/// Legacy unvalidated `Copy` reader retained while per-family syscalls migrate
/// to [`read_user_value`] (`#157` / `#159`).
pub fn read_user_plain<T: Copy>(process: &Process, user_addr: usize) -> AxResult<T> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(value.as_mut_ptr().cast::<u8>(), core::mem::size_of::<T>())
    };
    process.read_user_bytes(user_addr, bytes)?;
    Ok(unsafe { value.assume_init() })
}

/// Legacy unvalidated `Copy` writer retained while per-family syscalls migrate
/// to [`write_user_value`] (`#158` / `#159`).
pub fn write_user_plain<T: Copy>(process: &Process, user_addr: usize, value: &T) -> AxResult<()> {
    let bytes = unsafe {
        core::slice::from_raw_parts((value as *const T).cast::<u8>(), core::mem::size_of::<T>())
    };
    process.write_user_bytes(user_addr, bytes)
}

pub fn write_user_bytes(process: &Process, user_addr: usize, bytes: &[u8]) -> AxResult<()> {
    process.write_user_bytes(user_addr, bytes)
}

/// Legacy unvalidated `Copy` array reader retained while per-family syscalls
/// migrate to [`read_user_value_array`] (`#157` / `#159`).
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

/// Legacy unvalidated `Copy` array writer retained while per-family syscalls
/// migrate to [`write_user_value_array`] (`#158` / `#159`).
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
