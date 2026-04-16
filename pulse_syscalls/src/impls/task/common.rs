use alloc::string::String;
use alloc::vec::Vec;
use axerrno::LinuxError;

use pulse_core::task::Process;

pub(super) fn read_user_bytes(
    process: &Process,
    user_addr: usize,
    bytes: &mut [u8],
) -> Result<(), isize> {
    process
        .read_user_bytes(user_addr, bytes)
        .map_err(|_| -LinuxError::EFAULT.code() as isize)
}

pub(super) fn read_user_usize(process: &Process, user_addr: usize) -> Result<usize, isize> {
    let mut bytes = [0u8; core::mem::size_of::<usize>()];
    read_user_bytes(process, user_addr, &mut bytes)?;
    Ok(usize::from_ne_bytes(bytes))
}

pub(super) fn read_user_cstring(process: &Process, user_addr: usize) -> Result<String, isize> {
    if user_addr == 0 {
        return Err(-LinuxError::EFAULT.code() as isize);
    }
    const STR_MAX: usize = 4096;
    let mut bytes = Vec::new();
    for i in 0..STR_MAX {
        let mut byte = [0u8; 1];
        read_user_bytes(process, user_addr + i, &mut byte)?;
        if byte[0] == 0 {
            return String::from_utf8(bytes).map_err(|_| -LinuxError::EINVAL.code() as isize);
        }
        bytes.push(byte[0]);
    }
    Err(-LinuxError::ENAMETOOLONG.code() as isize)
}

pub(super) fn read_user_string_array(
    process: &Process,
    array_addr: usize,
) -> Result<Vec<String>, isize> {
    const ARG_MAX_COUNT: usize = 256;
    let mut out = Vec::new();
    if array_addr == 0 {
        return Ok(out);
    }
    for i in 0..ARG_MAX_COUNT {
        let ptr = read_user_usize(process, array_addr + i * core::mem::size_of::<usize>())?;
        if ptr == 0 {
            return Ok(out);
        }
        out.push(read_user_cstring(process, ptr)?);
    }
    Err(-LinuxError::E2BIG.code() as isize)
}

pub(super) fn write_user_i32(process: &Process, user_addr: usize, value: i32) -> isize {
    process
        .write_user_i32(user_addr, value)
        .map(|_| 0)
        .unwrap_or_else(|e| {
            axlog::warn!(
                "user write failed: addr={:#x}, value={}, err={:?}",
                user_addr,
                value,
                e
            );
            -LinuxError::EFAULT.code() as isize
        })
}
