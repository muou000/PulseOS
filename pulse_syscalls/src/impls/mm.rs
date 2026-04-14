use crate::LinuxError;
use alloc::sync::Arc;
use axhal::paging::MappingFlags;
use memory_addr::{MemoryAddr, VirtAddr};
use pulse_core::fd_table::FdObject;

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_EXEC: usize = 0x4;
const MAP_ANONYMOUS: usize = 0x20;
const PAGE_SIZE: usize = 0x1000;

fn user_space_end() -> Option<usize> {
    pulse_core::config::USER_SPACE_BASE.checked_add(pulse_core::config::USER_SPACE_SIZE)
}

fn is_user_range(addr: usize, len: usize) -> bool {
    if len == 0 {
        return true;
    }
    let Some(end) = addr.checked_add(len) else {
        return false;
    };
    let Some(user_end) = user_space_end() else {
        return false;
    };
    addr >= pulse_core::config::USER_SPACE_BASE && end <= user_end
}

fn get_fd_object(fd: usize) -> Result<Arc<dyn FdObject>, LinuxError> {
    let proc = pulse_core::task::current_process()?;
    proc.fd_table
        .lock()
        .get(fd)
        .map(|entry| entry.object.clone())
        .ok_or(LinuxError::EBADF)
}

pub fn sys_brk(addr: usize) -> isize {
    axlog::debug!("sys_brk: addr={:#x}", addr);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let mut heap_top = proc.heap_top.lock();

    if addr == 0 {
        return *heap_top as isize;
    }

    if !(pulse_core::config::USER_HEAP_BASE
        ..=pulse_core::config::USER_HEAP_BASE + pulse_core::config::USER_HEAP_SIZE_MAX)
        .contains(&addr)
    {
        axlog::warn!("sys_brk: invalid addr {:#x}", addr);
        return *heap_top as isize;
    }

    let old_heap_top = *heap_top;
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
        }
    }

    *heap_top = new_heap_top;
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

    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let file_backed = (flags & MAP_ANONYMOUS) == 0;
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

    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();

    const MAP_FIXED: usize = 0x10;

    // 如果 addr 为 0，由内核选择地址
    let map_addr = if addr == 0 {
        let limit = memory_addr::VirtAddrRange::from_start_size(
            VirtAddr::from(pulse_core::config::USER_SPACE_BASE),
            pulse_core::config::USER_SPACE_SIZE,
        );
        match aspace.find_free_area(
            VirtAddr::from(addr.align_down(PAGE_SIZE)),
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
        // 使用指定地址（需要对齐）
        addr & !(PAGE_SIZE - 1)
    };

    if !is_user_range(map_addr, aligned_length) {
        axlog::warn!(
            "sys_mmap: range out of user space, addr={:#x}, len={:#x}",
            map_addr,
            aligned_length
        );
        return -LinuxError::EINVAL.code() as isize;
    }

    if (flags & MAP_FIXED) != 0 {
        if let Err(e) = aspace.unmap(VirtAddr::from(map_addr), aligned_length) {
            axlog::warn!(
                "sys_mmap: MAP_FIXED pre-unmap failed at {:#x}, len={:#x}, err={:?}",
                map_addr,
                aligned_length,
                e
            );
        }
    }

    let populate = file_backed;
    match aspace.map_alloc(
        VirtAddr::from(map_addr),
        aligned_length,
        map_flags,
        populate,
    ) {
        Ok(_) => {
            drop(aspace);

            if let Some(file) = file {
                let file_off = match u64::try_from(offset) {
                    Ok(v) => v,
                    Err(_) => {
                        let aspace_handle = proc.aspace_handle();
                        let mut aspace = aspace_handle.lock();
                        if let Err(unmap_e) = aspace.unmap(VirtAddr::from(map_addr), aligned_length)
                        {
                            axlog::warn!(
                                "sys_mmap: rollback unmap failed at {:#x}, len={:#x}, err={:?}",
                                map_addr,
                                aligned_length,
                                unmap_e
                            );
                        }
                        return -LinuxError::EINVAL.code() as isize;
                    }
                };

                let mut copied = 0usize;
                let mut remain = length;
                let mut buf = [0u8; PAGE_SIZE];
                while remain > 0 {
                    let want = remain.min(PAGE_SIZE);
                    let n = match file.read_at(&mut buf[..want], file_off + copied as u64) {
                        Ok(n) => n,
                        Err(e) => {
                            let aspace_handle = proc.aspace_handle();
                            let mut aspace = aspace_handle.lock();
                            if let Err(unmap_e) =
                                aspace.unmap(VirtAddr::from(map_addr), aligned_length)
                            {
                                axlog::warn!(
                                    "sys_mmap: rollback unmap failed at {:#x}, len={:#x}, err={:?}",
                                    map_addr,
                                    aligned_length,
                                    unmap_e
                                );
                            }
                            return -e.code() as isize;
                        }
                    };
                    if n == 0 {
                        break;
                    }
                    let write_res = proc
                        .aspace_handle()
                        .lock()
                        .write(VirtAddr::from(map_addr + copied), &buf[..n]);
                    if write_res.is_err() {
                        let aspace_handle = proc.aspace_handle();
                        let mut aspace = aspace_handle.lock();
                        if let Err(unmap_e) = aspace.unmap(VirtAddr::from(map_addr), aligned_length)
                        {
                            axlog::warn!(
                                "sys_mmap: rollback unmap failed at {:#x}, len={:#x}, err={:?}",
                                map_addr,
                                aligned_length,
                                unmap_e
                            );
                        }
                        return -LinuxError::EFAULT.code() as isize;
                    }
                    copied += n;
                    remain -= n;
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

    if !is_user_range(aligned_addr, aligned_length) {
        return -LinuxError::EINVAL.code() as isize;
    }

    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();
    match aspace.unmap(VirtAddr::from(aligned_addr), aligned_length) {
        Ok(_) => {
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

    if !is_user_range(addr, aligned_length) {
        return -LinuxError::ENOMEM.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
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
