//! Read-only physical-layout observation for the file I/O guest fixture.
//! The probe faults its own pages before calling this test-build-only hook.

use axerrno::LinuxError;
use axhal::paging::MappingFlags;
use memory_addr::{PAGE_SIZE_4K, VirtAddr};

pub(super) fn query_layout(address: usize, size: usize) -> Result<usize, LinuxError> {
    if !address.is_multiple_of(PAGE_SIZE_4K)
        || !size.is_multiple_of(PAGE_SIZE_4K)
        || size == 0
        || size > 16 * 1024 * 1024
    {
        return Err(LinuxError::EINVAL);
    }
    let end = address.checked_add(size).ok_or(LinuxError::EINVAL)?;
    let process = pulse_core::task::current_process()?;
    process
        .validate_user_range(address, size)
        .map_err(|_| LinuxError::EFAULT)?;
    let handle = process.aspace_handle();
    let aspace = handle.read();
    let mut previous = None;
    let mut discontinuities = 0;
    for address in (address..end).step_by(PAGE_SIZE_4K) {
        let (physical, flags, _) = aspace
            .query_vaddr(VirtAddr::from(address))
            .map_err(|_| LinuxError::EFAULT)?;
        if physical.as_usize() == 0 || !flags.contains(MappingFlags::USER) {
            return Err(LinuxError::EFAULT);
        }
        if previous.is_some_and(|prior: usize| {
            prior.checked_add(PAGE_SIZE_4K) != Some(physical.as_usize())
        }) {
            discontinuities += 1;
        }
        previous = Some(physical.as_usize());
    }
    Ok(discontinuities)
}
