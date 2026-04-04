use crate::LinuxError;
use arceos_posix_api::sys_lseek as ax_sys_lseek;
use arceos_posix_api::sys_read as ax_sys_read;
use axhal::paging::MappingFlags;
use core::ffi::c_void;
use memory_addr::{MemoryAddr, VirtAddr};

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_EXEC: usize = 0x4;
const MAP_ANONYMOUS: usize = 0x20;
const PAGE_SIZE: usize = 0x1000;
const SEEK_SET: i32 = 0;
const SEEK_CUR: i32 = 1;

pub fn sys_brk(addr: usize) -> isize {
    axlog::debug!("sys_brk: addr={:#x}", addr);

    use axtask::TaskExtRef;
    let binding = axtask::current();
    let proc: &pulse_core::task::Process = binding.task_ext();

    let mut heap_top = proc.heap_top.lock();

    if addr == 0 {
        return *heap_top as isize;
    }

    if addr < pulse_core::config::USER_HEAP_BASE
        || addr > pulse_core::config::USER_HEAP_BASE + pulse_core::config::USER_HEAP_SIZE_MAX
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
            let mut aspace = proc.aspace.lock();
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
            let mut aspace = proc.aspace.lock();
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

    use axtask::TaskExtRef;
    let binding = axtask::current();
    let proc: &pulse_core::task::Process = binding.task_ext();

    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let file_backed = (flags & MAP_ANONYMOUS) == 0;
    if file_backed && fd < 0 {
        return -LinuxError::EBADF.code() as isize;
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

    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let mut aspace = proc.aspace.lock();

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

    if (flags & MAP_FIXED) != 0 {
        let _ = aspace.unmap(VirtAddr::from(map_addr), aligned_length);
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

            if file_backed {
                let file_off = match i64::try_from(offset) {
                    Ok(v) => v,
                    Err(_) => {
                        let mut aspace = proc.aspace.lock();
                        let _ = aspace.unmap(VirtAddr::from(map_addr), aligned_length);
                        return -LinuxError::EINVAL.code() as isize;
                    }
                };

                let old_off = ax_sys_lseek(fd, 0, SEEK_CUR);
                if old_off < 0 {
                    let mut aspace = proc.aspace.lock();
                    let _ = aspace.unmap(VirtAddr::from(map_addr), aligned_length);
                    return old_off as isize;
                }

                let seek_ret = ax_sys_lseek(fd, file_off, SEEK_SET);
                if seek_ret < 0 {
                    let mut aspace = proc.aspace.lock();
                    let _ = aspace.unmap(VirtAddr::from(map_addr), aligned_length);
                    return seek_ret as isize;
                }

                let mut copied = 0usize;
                let mut remain = length;
                let mut buf = [0u8; PAGE_SIZE];
                while remain > 0 {
                    let want = remain.min(PAGE_SIZE);
                    let n = ax_sys_read(fd, buf.as_mut_ptr() as *mut c_void, want);
                    if n < 0 {
                        let _ = ax_sys_lseek(fd, old_off, SEEK_SET);
                        let mut aspace = proc.aspace.lock();
                        let _ = aspace.unmap(VirtAddr::from(map_addr), aligned_length);
                        return n as isize;
                    }
                    if n == 0 {
                        break;
                    }
                    let n = n as usize;
                    let write_res = proc
                        .aspace
                        .lock()
                        .write(VirtAddr::from(map_addr + copied), &buf[..n]);
                    if write_res.is_err() {
                        let _ = ax_sys_lseek(fd, old_off, SEEK_SET);
                        let mut aspace = proc.aspace.lock();
                        let _ = aspace.unmap(VirtAddr::from(map_addr), aligned_length);
                        return -LinuxError::EFAULT.code() as isize;
                    }
                    copied += n;
                    remain -= n;
                }

                let _ = ax_sys_lseek(fd, old_off, SEEK_SET);
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
            -LinuxError::ENOMEM.code() as isize
        }
    }
}

pub fn sys_munmap(addr: usize, length: usize) -> isize {
    axlog::debug!("sys_munmap: addr={:#x}, length={:#x}", addr, length);

    use axtask::TaskExtRef;
    let binding = axtask::current();
    let proc: &pulse_core::task::Process = binding.task_ext();

    if length == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let aligned_addr = addr & !(PAGE_SIZE - 1);
    let aligned_length = (length + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);

    let mut aspace = proc.aspace.lock();
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
            -LinuxError::EINVAL.code() as isize
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

    use axtask::TaskExtRef;
    let binding = axtask::current();
    let proc: &pulse_core::task::Process = binding.task_ext();

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

    let mut aspace = proc.aspace.lock();
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
