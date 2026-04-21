use alloc::vec::Vec;

use axerrno::AxResult;

use super::Process;

pub const DEFAULT_USER_CSTRING_MAX: usize = 4096;

pub fn read_user_cstring_bytes(
    process: &Process,
    user_addr: usize,
    max_len: usize,
) -> AxResult<(Vec<u8>, bool)> {
    let mut bytes = Vec::new();
    for i in 0..max_len {
        let mut byte = [0u8; 1];
        process.read_user_bytes(user_addr + i, &mut byte)?;
        if byte[0] == 0 {
            return Ok((bytes, true));
        }
        bytes.push(byte[0]);
    }
    Ok((bytes, false))
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
    let mut out = Vec::with_capacity(count);
    let elem_size = core::mem::size_of::<T>();
    for i in 0..count {
        let addr = user_addr + i * elem_size;
        out.push(read_user_plain(process, addr)?);
    }
    Ok(out)
}
