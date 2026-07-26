use alloc::{string::String, vec::Vec};

use axerrno::LinuxError;
use pulse_core::task::{Process, uaccess};

pub(super) fn read_user_usize(process: &Process, user_addr: usize) -> Result<usize, isize> {
    process.read_user_usize(user_addr).map_err(|e| {
        axlog::warn!("read_user_usize failed: addr={:#x}, err={:?}", user_addr, e);
        -LinuxError::EFAULT.code() as isize
    })
}

pub(super) fn read_user_cstring(process: &Process, user_addr: usize) -> Result<String, isize> {
    let (bytes, terminated) =
        uaccess::read_user_cstring_bytes(process, user_addr, uaccess::DEFAULT_USER_CSTRING_MAX)
            .map_err(|e| {
                axlog::warn!(
                    "read_user_cstring failed: addr={:#x}, err={:?}",
                    user_addr,
                    e
                );
                -LinuxError::EFAULT.code() as isize
            })?;
    if !terminated {
        axlog::warn!("read_user_cstring ENAMETOOLONG: addr={:#x}", user_addr);
        return Err(-LinuxError::ENAMETOOLONG.code() as isize);
    }
    String::from_utf8(bytes).map_err(|e| {
        axlog::warn!(
            "read_user_cstring UTF8 err: addr={:#x}, err={:?}",
            user_addr,
            e
        );
        -LinuxError::EINVAL.code() as isize
    })
}

pub(super) fn read_user_string_array(
    process: &Process,
    array_addr: usize,
) -> Result<Vec<String>, isize> {
    const ARG_MAX_COUNT: usize = 4096;
    let mut out = Vec::new();
    if array_addr == 0 {
        return Ok(out);
    }
    for i in 0..ARG_MAX_COUNT {
        let element_addr = array_addr + i * core::mem::size_of::<usize>();
        let ptr = match read_user_usize(process, element_addr) {
            Ok(ptr) => ptr,
            Err(e) => {
                axlog::warn!(
                    "read_user_string_array: failed to read ptr at idx={} (element_addr={:#x}), \
                     err={}",
                    i,
                    element_addr,
                    e
                );
                return Err(e);
            }
        };
        if ptr == 0 {
            return Ok(out);
        }
        let s = match read_user_cstring(process, ptr) {
            Ok(s) => s,
            Err(e) => {
                axlog::warn!(
                    "read_user_string_array: failed to read cstring at idx={} (ptr={:#x}), err={}",
                    i,
                    ptr,
                    e
                );
                return Err(e);
            }
        };
        out.push(s);
    }
    axlog::warn!(
        "read_user_string_array: ARG_MAX_COUNT ({}) reached for array at {:#x}",
        ARG_MAX_COUNT,
        array_addr
    );
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
