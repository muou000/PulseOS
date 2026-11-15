use alloc::vec::Vec;

use axerrno::{AxError, AxResult};

use crate::{FromUserAbi, abi_size_of, read_user_value_with};

/// Reads an array one ABI value at a time, reserving its result before touching
/// user memory. This preserves the legacy syscall allocation/fault order and
/// copy granularity; callers needing a whole-array snapshot use
/// [`crate::read_user_array_with`] instead.
pub fn read_user_array_sequential_with<T: FromUserAbi>(
    user_addr: usize,
    count: usize,
    mut read_partial: impl FnMut(usize, &mut [u8]) -> AxResult<usize>,
) -> AxResult<Vec<T>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(count)
        .map_err(|_| AxError::NoMemory)?;
    for index in 0..count {
        let offset = index
            .checked_mul(abi_size_of::<T>())
            .ok_or(AxError::InvalidInput)?;
        let addr = user_addr.checked_add(offset).ok_or(AxError::InvalidInput)?;
        values.push(read_user_value_with(addr, &mut read_partial)?);
    }
    Ok(values)
}

#[cfg(test)]
mod tests {
    use axerrno::AxError;

    use super::read_user_array_sequential_with;

    #[test]
    fn sequential_array_keeps_allocation_and_element_fault_order() {
        assert_eq!(
            read_user_array_sequential_with::<u64>(0, usize::MAX, |_, _| panic!("no read")),
            Err(AxError::NoMemory)
        );
        assert_eq!(
            read_user_array_sequential_with::<u64>(0, 0, |_, _| panic!("no read")),
            Ok(alloc::vec![])
        );
        let mut reads = 0;
        assert_eq!(
            read_user_array_sequential_with::<u32>(0x4000, 2, |addr, bytes| {
                assert_eq!(addr, 0x4000 + reads * 4);
                assert_eq!(bytes.len(), 4);
                reads += 1;
                if reads == 1 {
                    bytes.copy_from_slice(&17u32.to_ne_bytes());
                    Ok(4)
                } else {
                    Ok(3)
                }
            }),
            Err(AxError::BadAddress)
        );
        assert_eq!(reads, 2);
    }

    #[test]
    fn sequential_array_validates_each_value_before_reading_the_next() {
        let mut reads = 0;
        assert_eq!(
            read_user_array_sequential_with::<bool>(0x4000, 2, |_, bytes| {
                reads += 1;
                bytes[0] = 2;
                Ok(1)
            }),
            Err(AxError::InvalidInput)
        );
        assert_eq!(reads, 1);
    }
}
