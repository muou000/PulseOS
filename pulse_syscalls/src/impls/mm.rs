use alloc::sync::Arc;

use axfs::{CachedFile, FileFlags};
use axhal::paging::MappingFlags;
use linux_raw_sys::general::{MCL_CURRENT, MCL_FUTURE, MCL_ONFAULT};
use memory_addr::VirtAddr;
use pulse_core::fd_table::FdObject;

use crate::LinuxError;

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_EXEC: usize = 0x4;
const MAP_ANONYMOUS: usize = 0x20;
const PAGE_SIZE: usize = 0x1000;
const MS_ASYNC: usize = 1;
const MS_SYNC: usize = 2;
const MS_INVALIDATE: usize = 4;

fn get_fd_object(fd: usize) -> Result<Arc<dyn FdObject>, LinuxError> {
    let proc = pulse_core::task::current_process()?;
    proc.get_fd_entry(fd)
        .map(|entry| entry.object.clone())
        .map_err(|_| LinuxError::EBADF)
}

fn file_flags_for_mapping(map_flags: MappingFlags) -> FileFlags {
    let mut flags = FileFlags::empty();
    if map_flags.contains(MappingFlags::READ) {
        flags |= FileFlags::READ;
    }
    if map_flags.contains(MappingFlags::WRITE) {
        flags |= FileFlags::WRITE;
    }
    if map_flags.contains(MappingFlags::EXECUTE) {
        flags |= FileFlags::EXECUTE;
    }
    flags
}

pub fn sys_brk(addr: usize) -> isize {
    axlog::debug!("sys_brk: addr={:#x}", addr);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let _brk_lock = proc.brk_lock.lock();
    let old_heap_top = proc.get_heap_top();

    if addr == 0 {
        return old_heap_top as isize;
    }

    if !(pulse_core::config::USER_HEAP_BASE
        ..=pulse_core::config::USER_HEAP_BASE + pulse_core::config::USER_HEAP_SIZE_MAX)
        .contains(&addr)
    {
        axlog::warn!("sys_brk: invalid addr {:#x}", addr);
        return old_heap_top as isize;
    }

    let new_heap_top = addr;

    if new_heap_top > old_heap_top {
        let start = (old_heap_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = (new_heap_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        if end > start {
            let aspace_handle = proc.aspace_handle();
            let mut aspace = aspace_handle.lock();
            let flags = MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER;
            if let Err(e) = aspace.map_alloc(VirtAddr::from(start), end - start, flags, false) {
                axlog::error!("sys_brk: failed to expand heap: {:?}", e);
                return old_heap_top as isize;
            }
            drop(aspace);
            if let Err(e) = proc.maybe_lock_future_range(start, end - start) {
                let aspace_handle = proc.aspace_handle();
                let mut aspace = aspace_handle.lock();
                if let Err(unmap_e) = aspace.unmap(VirtAddr::from(start), end - start) {
                    axlog::warn!(
                        "sys_brk: rollback unmap failed at {:#x}, len={:#x}, err={:?}",
                        start,
                        end - start,
                        unmap_e
                    );
                }
                return -e.code() as isize;
            }
        }
    } else if new_heap_top < old_heap_top {
        let start = (new_heap_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
        let end = (old_heap_top + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

        if end > start {
            let aspace_handle = proc.aspace_handle();
            let mut aspace = aspace_handle.lock();
            if let Err(e) = aspace.unmap(VirtAddr::from(start), end - start) {
                axlog::error!("sys_brk: failed to shrink heap: {:?}", e);
                return old_heap_top as isize;
            }
            let _ = proc.memlock_unlock_range(start, end - start);
        }
    }

    proc.set_heap_top(new_heap_top);
    axlog::debug!("sys_brk: updated heap_top to {:#x}", new_heap_top);
    new_heap_top as isize
}

pub fn sys_mmap(
    addr: usize,
    length: usize,
    prot: usize,
    flags: usize,
    fd: i32,
    offset: usize,
) -> isize {
    axlog::debug!(
        "sys_mmap: addr={:#x}, length={:#x}, prot={:#x}, flags={:#x}, fd={}, offset={:#x}",
        addr,
        length,
        prot,
        flags,
        fd,
        offset
    );

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let file_backed = (flags & MAP_ANONYMOUS) == 0;

    let map_type = flags & 0x0f;
    const MAP_SHARED: usize = 0x01;
    const MAP_PRIVATE: usize = 0x02;
    const MAP_SHARED_VALIDATE: usize = 0x03;

    if map_type != MAP_SHARED && map_type != MAP_PRIVATE && map_type != MAP_SHARED_VALIDATE {
        return -LinuxError::EINVAL.code() as isize;
    }

    const MAP_FIXED: usize = 0x10;
    const MAP_GROWSDOWN: usize = 0x0100;
    const MAP_DENYWRITE: usize = 0x0800;
    const MAP_EXECUTABLE: usize = 0x1000;
    const MAP_LOCKED: usize = 0x2000;
    const MAP_NORESERVE: usize = 0x4000;
    const MAP_POPULATE: usize = 0x8000;
    const MAP_NONBLOCK: usize = 0x10000;
    const MAP_STACK: usize = 0x20000;
    const MAP_HUGETLB: usize = 0x40000;
    const MAP_SYNC: usize = 0x80000;
    const MAP_FIXED_NOREPLACE: usize = 0x100000;

    let supported_mask = MAP_SHARED | MAP_PRIVATE | MAP_SHARED_VALIDATE | MAP_FIXED | MAP_ANONYMOUS |
                         MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED | MAP_NORESERVE | MAP_POPULATE |
                         MAP_NONBLOCK | MAP_STACK | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE | MAP_GROWSDOWN;

    if map_type == MAP_SHARED_VALIDATE && (flags & !supported_mask) != 0 {
        return -LinuxError::EOPNOTSUPP.code() as isize;
    }

    let is_shared = map_type == MAP_SHARED || map_type == MAP_SHARED_VALIDATE;

    if file_backed && fd < 0 {
        return -LinuxError::EBADF.code() as isize;
    }
    let file = if file_backed {
        match get_fd_object(fd as usize) {
            Ok(file) => Some(file),
            Err(e) => return -e.code() as isize,
        }
    } else {
        None
    };

    let mut map_flags = MappingFlags::USER;
    if (prot & PROT_READ) != 0 {
        map_flags |= MappingFlags::READ;
    }
    if (prot & PROT_WRITE) != 0 {
        map_flags |= MappingFlags::WRITE;
    }
    if (prot & PROT_EXEC) != 0 {
        map_flags |= MappingFlags::EXECUTE;
    }

    if let Some(file) = file.as_ref() {
        if let Some(file_flags) = file.mmap_file_flags() {
            if map_flags.contains(MappingFlags::READ) && !file_flags.contains(FileFlags::READ) {
                return -LinuxError::EACCES.code() as isize;
            }
            if map_flags.contains(MappingFlags::WRITE) {
                if is_shared {
                    if !file_flags.contains(FileFlags::WRITE) {
                        return -LinuxError::EACCES.code() as isize;
                    }
                } else {
                    if !file_flags.contains(FileFlags::READ) {
                        return -LinuxError::EACCES.code() as isize;
                    }
                }
            }
            if map_flags.contains(MappingFlags::EXECUTE) && !file_flags.contains(FileFlags::READ) {
                return -LinuxError::EACCES.code() as isize;
            }
        }
    }

    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();

    let aligned_addr = addr & !(PAGE_SIZE - 1);
    let map_addr = if (flags & MAP_FIXED) != 0 {
        aligned_addr
    } else {
        let limit = memory_addr::VirtAddrRange::from_start_size(
            VirtAddr::from(pulse_core::config::USER_SPACE_BASE),
            pulse_core::config::USER_SPACE_SIZE,
        );
        let hint = if aligned_addr == 0 {
            VirtAddr::from(pulse_core::config::USER_SPACE_BASE)
        } else {
            VirtAddr::from(aligned_addr)
        };
        match aspace.find_free_area(hint, aligned_length, limit) {
            Some(vaddr) => vaddr.as_usize(),
            None => {
                if aligned_addr != 0 {
                    match aspace.find_free_area(
                        VirtAddr::from(pulse_core::config::USER_SPACE_BASE),
                        aligned_length,
                        limit,
                    ) {
                        Some(vaddr) => vaddr.as_usize(),
                        None => {
                            axlog::error!("sys_mmap: no free area found");
                            return -crate::LinuxError::ENOMEM.code() as isize;
                        }
                    }
                } else {
                    axlog::error!("sys_mmap: no free area found");
                    return -crate::LinuxError::ENOMEM.code() as isize;
                }
            }
        }
    };

    if !proc.is_user_range(map_addr, aligned_length) {
        axlog::warn!(
            "sys_mmap: range out of user space, addr={:#x}, len={:#x}",
            map_addr,
            aligned_length
        );
        return -LinuxError::EINVAL.code() as isize;
    }

    if (flags & MAP_FIXED_NOREPLACE) != 0 {
        if addr == 0 || (addr & (PAGE_SIZE - 1)) != 0 {
            return -LinuxError::EINVAL.code() as isize;
        }
        if aspace.has_overlap(VirtAddr::from(map_addr), aligned_length) {
            return -LinuxError::EEXIST.code() as isize;
        }
    }

    if (flags & MAP_FIXED) != 0 {
        if let Err(e) = aspace.unmap(VirtAddr::from(map_addr), aligned_length) {
            axlog::warn!(
                "sys_mmap: MAP_FIXED pre-unmap failed at {:#x}, len={:#x}, err={:?}",
                map_addr,
                aligned_length,
                e
            );
        } else {
            let _ = proc.memlock_unlock_range(map_addr, aligned_length);
        }
    }

    let mut is_zero_device = false;
    if let Some(file) = file.as_ref() {
        if let Some(loc) = file.location() {
            if let Ok(path) = loc.absolute_path() {
                if path.as_str() == "/dev/zero" {
                    is_zero_device = true;
                }
            }
        }
    }

    let map_result = if is_zero_device {
        if is_shared {
            use axhal::paging::PageSize;
            if let Some(backend) = axmm::Backend::new_shared(aligned_length, true, PageSize::Size4K) {
                aspace.map_with_backend(VirtAddr::from(map_addr), aligned_length, map_flags, backend)
            } else {
                Err(axerrno::AxError::NoMemory)
            }
        } else {
            aspace.map_alloc(VirtAddr::from(map_addr), aligned_length, map_flags, false)
        }
    } else if let Some(file) = file.as_ref() {
        let Some(location) = file.location() else {
            return -LinuxError::ENODEV.code() as isize;
        };
        let file_flags = file
            .mmap_file_flags()
            .unwrap_or_else(|| file_flags_for_mapping(map_flags));
        let cached = CachedFile::get_or_create(location);
        aspace.map_file(
            VirtAddr::from(map_addr),
            aligned_length,
            map_flags,
            cached,
            file_flags,
            offset,
            length,
            is_shared,
        )
    } else if is_shared {
        use axhal::paging::PageSize;
        if let Some(backend) = axmm::Backend::new_shared(aligned_length, true, PageSize::Size4K) {
            aspace.map_with_backend(VirtAddr::from(map_addr), aligned_length, map_flags, backend)
        } else {
            Err(axerrno::AxError::NoMemory)
        }
    } else if (flags & MAP_GROWSDOWN) != 0 {
        let backend = axmm::Backend::new_alloc_grows_down(false, true);
        aspace.map_with_backend(VirtAddr::from(map_addr), aligned_length, map_flags, backend)
    } else {
        aspace.map_alloc(VirtAddr::from(map_addr), aligned_length, map_flags, false)
    };

    match map_result {
        Ok(_) => {
            drop(aspace);

            if let Err(e) = proc.maybe_lock_future_range(map_addr, aligned_length) {
                let aspace_handle = proc.aspace_handle();
                let mut aspace = aspace_handle.lock();
                if let Err(unmap_e) = aspace.unmap(VirtAddr::from(map_addr), aligned_length) {
                    axlog::warn!(
                        "sys_mmap: rollback unmap failed at {:#x}, len={:#x}, err={:?}",
                        map_addr,
                        aligned_length,
                        unmap_e
                    );
                }
                return -e.code() as isize;
            }

            if (flags & MAP_POPULATE) != 0 {
                if let Err(e) = proc.prefault_user_range(map_addr, aligned_length) {
                    axlog::warn!(
                        "sys_mmap: MAP_POPULATE prefault failed at {:#x}, len={:#x}, err={:?}",
                        map_addr,
                        aligned_length,
                        e
                    );
                }
            }

            axlog::debug!(
                "sys_mmap: mapped at {:#x}, length={:#x}",
                map_addr,
                aligned_length
            );
            map_addr as isize
        }
        Err(e) => {
            axlog::error!("sys_mmap: failed to map at {:#x}: {:?}", map_addr, e);
            -LinuxError::from(e).code() as isize
        }
    }
}

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    axlog::debug!("sys_munmap: addr={:#x}, length={:#x}", addr, length);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let aligned_addr = addr & !(PAGE_SIZE - 1);
    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    if !proc.is_user_range(aligned_addr, aligned_length) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();
    match aspace.unmap(VirtAddr::from(aligned_addr), aligned_length) {
        Ok(_) => {
            let _ = proc.memlock_unlock_range(aligned_addr, aligned_length);
            axlog::debug!(
                "sys_munmap: unmapped {:#x} length {:#x}",
                aligned_addr,
                aligned_length
            );
            0
        }
        Err(e) => {
            axlog::error!("sys_munmap: failed: {:?}", e);
            -LinuxError::from(e).code() as isize
        }
    }
}

pub fn sys_mlock(addr: usize, len: usize) -> isize {
    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    let (aligned_addr, aligned_len) = match proc.align_user_range(addr, len) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    if aligned_len == 0 {
        return 0;
    }
    match proc.lock_mapped_range(aligned_addr, aligned_len) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_munlock(addr: usize, len: usize) -> isize {
    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    let (aligned_addr, aligned_len) = match proc.align_user_range(addr, len) {
        Ok(v) => v,
        Err(e) => return -e.code() as isize,
    };
    if aligned_len == 0 {
        return 0;
    }
    if !proc.is_mapped_range(aligned_addr, aligned_len) {
        return -LinuxError::ENOMEM.code() as isize;
    }
    match proc.memlock_unlock_range(aligned_addr, aligned_len) {
        Ok(()) => 0,
        Err(_) => -LinuxError::EINVAL.code() as isize,
    }
}

pub fn sys_mprotect(addr: usize, length: usize, prot: usize) -> isize {
    axlog::debug!(
        "sys_mprotect: addr={:#x}, length={:#x}, prot={:#x}",
        addr,
        length,
        prot
    );

    if length == 0 {
        return 0;
    }
    if (addr & (PAGE_SIZE - 1)) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let allowed = PROT_READ | PROT_WRITE | PROT_EXEC;
    if (prot & !allowed) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    if !proc.is_user_range(addr, aligned_length) {
        return -LinuxError::ENOMEM.code() as isize;
    }

    let mut map_flags = MappingFlags::USER;
    if (prot & PROT_READ) != 0 {
        map_flags |= MappingFlags::READ;
    }
    if (prot & PROT_WRITE) != 0 {
        map_flags |= MappingFlags::WRITE;
    }
    if (prot & PROT_EXEC) != 0 {
        map_flags |= MappingFlags::EXECUTE;
    }

    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();
    let start = VirtAddr::from(addr);
    if !aspace.can_access_range(start, aligned_length, MappingFlags::empty()) {
        return -LinuxError::ENOMEM.code() as isize;
    }

    match aspace.protect(start, aligned_length, map_flags) {
        Ok(_) => 0,
        Err(e) => {
            axlog::error!(
                "sys_mprotect: failed to protect [{:#x}, {:#x}): {:?}",
                addr,
                addr + aligned_length,
                e
            );
            -LinuxError::ENOMEM.code() as isize
        }
    }
}

pub fn sys_mlockall(flags: usize) -> isize {
    let allowed = MCL_CURRENT as usize | MCL_FUTURE as usize | MCL_ONFAULT as usize;
    if (flags & !allowed) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if flags == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & MCL_ONFAULT as usize) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    if (flags & MCL_CURRENT as usize) != 0 {
        if let Err(e) = proc.lock_all_current_mappings() {
            return -e.code() as isize;
        }
    }
    if (flags & MCL_FUTURE as usize) != 0 {
        proc.memlock_set_future(true);
    }
    0
}

pub fn sys_munlockall() -> isize {
    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    proc.memlock_unlock_all();
    0
}

pub fn sys_msync(addr: usize, length: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_msync: addr={:#x}, length={:#x}, flags={:#x}",
        addr,
        length,
        flags
    );

    // Validate flags: MS_ASYNC and MS_SYNC are mutually exclusive.
    let has_async = (flags & MS_ASYNC) != 0;
    let has_sync = (flags & MS_SYNC) != 0;
    if has_async && has_sync {
        return -LinuxError::EINVAL.code() as isize;
    }
    if !has_async && !has_sync && (flags & MS_INVALIDATE) == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    // Reject unknown bits.
    if (flags & !(MS_ASYNC | MS_SYNC | MS_INVALIDATE)) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    // addr must be page-aligned.
    if addr & (PAGE_SIZE - 1) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if length == 0 {
        return 0;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    if !proc.is_user_range(addr, length) {
        return -LinuxError::ENOMEM.code() as isize;
    }

    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
    let aspace_handle = proc.aspace_handle();
    let aspace = aspace_handle.lock();

    match aspace.writeback_file_range(VirtAddr::from(addr), aligned_length, has_sync) {
        Ok(()) => 0,
        Err(e) => -LinuxError::from(e).code() as isize,
    }
}
