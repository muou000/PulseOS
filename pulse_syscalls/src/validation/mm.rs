use axerrno::LinuxError;
use linux_raw_sys::general::{
    MAP_ANONYMOUS, MAP_DENYWRITE, MAP_EXECUTABLE, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_GROWSDOWN,
    MAP_HUGETLB, MAP_LOCKED, MAP_NONBLOCK, MAP_NORESERVE, MAP_POPULATE, MAP_PRIVATE, MAP_SHARED,
    MAP_SHARED_VALIDATE, MAP_STACK, MAP_SYNC, PROT_EXEC, PROT_READ, PROT_WRITE,
};

pub(crate) const PAGE_SIZE: usize = 0x1000;

pub(crate) fn page_align_up(addr: usize) -> Option<usize> {
    addr.checked_add(PAGE_SIZE - 1)
        .map(|value| value & !(PAGE_SIZE - 1))
}

pub(crate) fn is_page_aligned(addr: usize) -> bool {
    addr & (PAGE_SIZE - 1) == 0
}

pub(crate) fn mmap_offset_is_valid(file_backed: bool, offset: usize) -> bool {
    !file_backed || is_page_aligned(offset)
}

pub(crate) fn parse_mmap_flags(flags: usize) -> Result<bool, LinuxError> {
    let map_type = flags & 0x0f;
    if map_type != MAP_SHARED as usize
        && map_type != MAP_PRIVATE as usize
        && map_type != MAP_SHARED_VALIDATE as usize
    {
        return Err(LinuxError::EINVAL);
    }
    let supported = (MAP_SHARED
        | MAP_PRIVATE
        | MAP_SHARED_VALIDATE
        | MAP_FIXED
        | MAP_ANONYMOUS
        | MAP_DENYWRITE
        | MAP_EXECUTABLE
        | MAP_LOCKED
        | MAP_NORESERVE
        | MAP_POPULATE
        | MAP_NONBLOCK
        | MAP_STACK
        | MAP_HUGETLB
        | MAP_SYNC
        | MAP_FIXED_NOREPLACE
        | MAP_GROWSDOWN) as usize;
    if map_type == MAP_SHARED_VALIDATE as usize && flags & !supported != 0 {
        return Err(LinuxError::EOPNOTSUPP);
    }
    Ok(map_type == MAP_SHARED as usize || map_type == MAP_SHARED_VALIDATE as usize)
}

pub(crate) fn validate_mmap_fd_offset(
    file_backed: bool,
    fd: i32,
    offset: usize,
) -> Result<(), LinuxError> {
    if file_backed && fd < 0 {
        return Err(LinuxError::EBADF);
    }
    if !mmap_offset_is_valid(file_backed, offset) {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub(crate) fn validate_mmap_length(length: usize) -> Result<(), LinuxError> {
    if length == 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub(crate) fn mprotect_aligned_length(
    addr: usize,
    length: usize,
    prot: usize,
) -> Result<usize, LinuxError> {
    if length == 0 {
        return Ok(0);
    }
    if !is_page_aligned(addr) || prot & !((PROT_READ | PROT_WRITE | PROT_EXEC) as usize) != 0 {
        return Err(LinuxError::EINVAL);
    }
    page_align_up(length).ok_or(LinuxError::ENOMEM)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_alignment_helpers_reject_overflow_and_unaligned_file_offsets() {
        assert!(is_page_aligned(0));
        assert!(is_page_aligned(PAGE_SIZE));
        assert!(!is_page_aligned(PAGE_SIZE - 1));
        assert!(mmap_offset_is_valid(false, PAGE_SIZE - 1));
        assert!(mmap_offset_is_valid(true, PAGE_SIZE));
        assert!(!mmap_offset_is_valid(true, PAGE_SIZE - 1));
        assert_eq!(page_align_up(PAGE_SIZE + 1), Some(2 * PAGE_SIZE));
        assert_eq!(page_align_up(usize::MAX), None);
    }

    #[test]
    fn mmap_file_offsets_must_be_page_aligned() {
        assert_eq!(validate_mmap_fd_offset(true, 3, 1), Err(LinuxError::EINVAL));
        assert_eq!(validate_mmap_fd_offset(true, 3, PAGE_SIZE), Ok(()));
        assert_eq!(validate_mmap_fd_offset(false, -1, 1), Ok(()));
    }

    #[test]
    fn mmap_bad_fd_precedes_bad_file_offset() {
        assert_eq!(validate_mmap_fd_offset(true, -1, 1), Err(LinuxError::EBADF));
    }

    #[test]
    fn ltp_mmap06_requires_a_mapping_type() {
        assert_eq!(parse_mmap_flags(0), Err(LinuxError::EINVAL));
        assert_eq!(
            parse_mmap_flags(MAP_ANONYMOUS as usize),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(parse_mmap_flags(MAP_PRIVATE as usize), Ok(false));
        assert_eq!(parse_mmap_flags(MAP_SHARED as usize), Ok(true));
    }

    #[test]
    fn ltp_mmap06_rejects_zero_length() {
        assert_eq!(validate_mmap_length(0), Err(LinuxError::EINVAL));
        assert_eq!(validate_mmap_length(1024), Ok(()));
    }

    #[test]
    fn ltp_mmap20_shared_validate_rejects_unknown_flags() {
        let unknown = 1usize << 10;
        assert_eq!(
            parse_mmap_flags(MAP_SHARED_VALIDATE as usize | unknown),
            Err(LinuxError::EOPNOTSUPP),
        );
        assert_eq!(parse_mmap_flags(MAP_SHARED as usize | unknown), Ok(true));
    }

    #[test]
    fn ltp_mprotect01_rejects_unaligned_address() {
        assert_eq!(
            mprotect_aligned_length(PAGE_SIZE + 1, 1024, PROT_READ as usize),
            Err(LinuxError::EINVAL),
        );
    }

    #[test]
    fn mprotect_rejects_unknown_protection_and_length_overflow() {
        assert_eq!(
            mprotect_aligned_length(PAGE_SIZE, 1, 8),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            mprotect_aligned_length(PAGE_SIZE, usize::MAX, PROT_READ as usize),
            Err(LinuxError::ENOMEM),
        );
        assert_eq!(
            mprotect_aligned_length(PAGE_SIZE, PAGE_SIZE + 1, 0),
            Ok(2 * PAGE_SIZE)
        );
    }

    #[test]
    fn mprotect_zero_length_keeps_existing_short_circuit() {
        assert_eq!(mprotect_aligned_length(1, 0, usize::MAX), Ok(0));
    }
}
