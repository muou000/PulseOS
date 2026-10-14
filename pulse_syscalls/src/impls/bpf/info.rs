use axerrno::LinuxError;

use super::abi::{BPF_MAX_ATTR_SIZE, check_trailing_zero};

/// Copies a kernel `bpf_*_info` record to the user buffer described by
/// `BPF_OBJ_GET_INFO_BY_FD`, following Linux semantics:
///
/// - `info_len` larger than a page is `E2BIG`;
/// - bytes the kernel does not know about (`kernel.len()..info_len`) must be
///   zero, otherwise `E2BIG`;
/// - at most `min(info_len, kernel.len())` bytes are copied.
///
/// Returns the copied length, which the caller writes back to `info.info_len`.
pub fn copy_obj_info_to_user<R, W>(
    info_ptr: usize,
    info_len: u32,
    kernel: &[u8],
    mut read_user: R,
    mut write_user: W,
) -> Result<u32, LinuxError>
where
    R: FnMut(usize, &mut [u8]) -> Result<(), LinuxError>,
    W: FnMut(usize, &[u8]) -> Result<(), LinuxError>,
{
    let user_len = info_len as usize;
    if user_len > BPF_MAX_ATTR_SIZE {
        return Err(LinuxError::E2BIG);
    }
    if user_len > kernel.len() {
        if info_ptr == 0 {
            return Err(LinuxError::EFAULT);
        }
        let mut offset = kernel.len();
        let mut tail = [0u8; 128];
        while offset < user_len {
            let chunk = core::cmp::min(tail.len(), user_len - offset);
            let addr = info_ptr.checked_add(offset).ok_or(LinuxError::EFAULT)?;
            read_user(addr, &mut tail[..chunk])?;
            check_trailing_zero(&tail[..chunk])?;
            offset += chunk;
        }
    }

    let copy_len = core::cmp::min(user_len, kernel.len());
    if copy_len > 0 {
        if info_ptr == 0 {
            return Err(LinuxError::EFAULT);
        }
        write_user(info_ptr, &kernel[..copy_len])?;
    }
    Ok(copy_len as u32)
}
