use alloc::vec::Vec;

use axerrno::{AxError, AxResult, LinuxError};
use linux_raw_sys::general::iovec;
use pulse_user_abi::{
    FromUserAbi, IntoUserAbi, UserMemoryRange, checked_abi_array_size, read_user_array_with,
    read_user_value_with, write_user_slice_with, write_user_value_with,
};

pub(crate) const MAX_USER_IOVCNT: usize = 1024;

#[inline]
pub(crate) fn map_uaccess_error(err: AxError) -> LinuxError {
    LinuxError::from(err.canonicalize())
}

pub(crate) fn read_user_value_from<T: FromUserAbi>(
    user_addr: usize,
    read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> Result<T, LinuxError> {
    read_user_value_with(user_addr, read_partial).map_err(map_uaccess_error)
}

pub(crate) fn write_user_value_to<T: IntoUserAbi>(
    user_addr: usize,
    value: &T,
    write_partial: impl FnMut(usize, &[u8]) -> AxResult<usize>,
) -> Result<(), LinuxError> {
    write_user_value_with(user_addr, value, write_partial).map_err(map_uaccess_error)
}

pub(crate) fn read_user_array_from<T: FromUserAbi>(
    range: UserMemoryRange,
    user_addr: usize,
    count: usize,
    read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> Result<Vec<T>, LinuxError> {
    let total_bytes = checked_abi_array_size::<T>(count).map_err(map_uaccess_error)?;
    if total_bytes > 0 {
        range
            .validate(user_addr, total_bytes)
            .map_err(map_uaccess_error)?;
    }
    read_user_array_with(user_addr, count, read_partial).map_err(map_uaccess_error)
}

pub(crate) fn write_user_slice_to<T: IntoUserAbi>(
    user_addr: usize,
    values: &[T],
    write_partial: impl FnMut(usize, &[u8]) -> AxResult<usize>,
) -> Result<(), LinuxError> {
    write_user_slice_with(user_addr, values, write_partial).map_err(map_uaccess_error)
}

pub(crate) fn read_user_iovec_array_from(
    range: UserMemoryRange,
    user_addr: usize,
    iovcnt: usize,
    read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> Result<Vec<iovec>, LinuxError> {
    if iovcnt > MAX_USER_IOVCNT {
        return Err(LinuxError::EINVAL);
    }
    read_user_array_from::<iovec>(range, user_addr, iovcnt, read_partial)
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::general::{flock, timespec};

    use super::*;

    struct TestUserSpace {
        range: UserMemoryRange,
        mapped_base: usize,
        bytes: Vec<u8>,
    }

    impl TestUserSpace {
        fn new(mapped_len: usize) -> Self {
            Self {
                range: UserMemoryRange::new(0x1000, 0x3f_ffff_f000).unwrap(),
                mapped_base: 0x4000,
                bytes: alloc::vec![0xABu8; mapped_len],
            }
        }

        fn mapped_end(&self) -> usize {
            self.mapped_base + self.bytes.len()
        }

        fn read_partial(&self, addr: usize, dst: &mut [u8]) -> AxResult<usize> {
            self.range.validate(addr, dst.len())?;
            let Some(off) = addr.checked_sub(self.mapped_base) else {
                return Ok(0);
            };
            let avail = self.bytes.len().saturating_sub(off).min(dst.len());
            dst[..avail].copy_from_slice(&self.bytes[off..off + avail]);
            Ok(avail)
        }

        fn write_partial(&mut self, addr: usize, src: &[u8]) -> AxResult<usize> {
            self.range.validate(addr, src.len())?;
            let Some(off) = addr.checked_sub(self.mapped_base) else {
                return Ok(0);
            };
            let avail = self.bytes.len().saturating_sub(off).min(src.len());
            self.bytes[off..off + avail].copy_from_slice(&src[..avail]);
            Ok(avail)
        }
    }

    #[test]
    fn syscall_user_abi_maps_efault_einval_and_enomem_accurately() {
        assert_eq!(map_uaccess_error(AxError::BadAddress), LinuxError::EFAULT);
        assert_eq!(map_uaccess_error(AxError::InvalidInput), LinuxError::EINVAL);
        assert_eq!(map_uaccess_error(AxError::NoMemory), LinuxError::ENOMEM);

        let mut space = TestUserSpace::new(64);

        // Invalid representation (0xAB for bool) -> EINVAL.
        assert_eq!(
            read_user_value_from::<bool>(0x4000, |a, b| space.read_partial(a, b)),
            Err(LinuxError::EINVAL),
        );

        // Null pointer -> EFAULT.
        assert_eq!(
            read_user_value_from::<timespec>(0, |a, b| space.read_partial(a, b)).err(),
            Some(LinuxError::EFAULT),
        );

        // Short read across page boundary -> EFAULT.
        let boundary = space.mapped_end() - 8;
        assert_eq!(
            read_user_value_from::<timespec>(boundary, |a, b| space.read_partial(a, b)).err(),
            Some(LinuxError::EFAULT),
        );

        // Padded struct write zeroes padding and round-trips cleanly.
        let lock = flock {
            l_type: 2,
            l_whence: 0,
            l_start: 128,
            l_len: 256,
            l_pid: 77,
        };
        assert_eq!(
            write_user_value_to(0x4000, &lock, |a, b| space.write_partial(a, b)),
            Ok(())
        );
        assert_eq!(&space.bytes[4..8], &[0, 0, 0, 0]);
        assert_eq!(&space.bytes[28..32], &[0, 0, 0, 0]);
        let decoded =
            read_user_value_from::<flock>(0x4000, |a, b| space.read_partial(a, b)).unwrap();
        assert_eq!(decoded.l_type, 2);
        assert_eq!(decoded.l_start, 128);
        assert_eq!(decoded.l_len, 256);
        assert_eq!(decoded.l_pid, 77);
    }

    #[test]
    fn syscall_iovec_and_array_helpers_preserve_bounds_and_overflow_semantics() {
        let mut space = TestUserSpace::new(64);
        let range = space.range;

        // Exceeding MAX_USER_IOVCNT returns EINVAL before touching memory.
        assert_eq!(
            read_user_iovec_array_from(range, 0, MAX_USER_IOVCNT + 1, |a, b| {
                space.read_partial(a, b)
            })
            .err(),
            Some(LinuxError::EINVAL),
        );

        // Zero iovcnt succeeds even with NULL pointer.
        let empty =
            read_user_iovec_array_from(range, 0, 0, |a, b| space.read_partial(a, b)).unwrap();
        assert!(empty.is_empty());

        // Checked size overflow on generic array helper returns EINVAL.
        assert_eq!(
            read_user_array_from::<u64>(range, 0x4000, usize::MAX, |a, b| {
                space.read_partial(a, b)
            }),
            Err(LinuxError::EINVAL),
        );

        // Array straddling USER_SPACE_END or unmapped page with invalid first
        // element returns EFAULT before EINVAL.
        assert_eq!(
            read_user_array_from::<bool>(range, range.end - 1, 2, |a, b| {
                space.read_partial(a, b)
            }),
            Err(LinuxError::EFAULT),
        );
        assert_eq!(
            read_user_array_from::<bool>(range, space.mapped_end() - 1, 2, |a, b| {
                space.read_partial(a, b)
            }),
            Err(LinuxError::EFAULT),
        );

        // Valid iovec array round-trips pointer addresses and lengths.
        let iovecs = [
            iovec {
                iov_base: core::ptr::without_provenance_mut(0x8000),
                iov_len: 64,
            },
            iovec {
                iov_base: core::ptr::without_provenance_mut(0x9000),
                iov_len: 128,
            },
        ];
        assert_eq!(
            write_user_slice_to(0x4000, &iovecs, |a, b| space.write_partial(a, b)),
            Ok(())
        );
        let read_back =
            read_user_iovec_array_from(range, 0x4000, 2, |a, b| space.read_partial(a, b)).unwrap();
        assert_eq!(read_back.len(), 2);
        assert_eq!(read_back[0].iov_base as usize, 0x8000);
        assert_eq!(read_back[0].iov_len, 64);
        assert_eq!(read_back[1].iov_base as usize, 0x9000);
        assert_eq!(read_back[1].iov_len, 128);
    }
}
