use crate::LinuxError;
use axhal::paging::MappingFlags;
use memory_addr::{MemoryAddr, VirtAddr};

const PROT_READ: usize = 0x1;
const PROT_WRITE: usize = 0x2;
const PROT_EXEC: usize = 0x4;
const MAP_ANONYMOUS: usize = 0x20;
const PAGE_SIZE: usize = 0x1000;

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
        let expand_size = new_heap_top - old_heap_top;
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
        let shrink_size = old_heap_top - new_heap_top;
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

    // 暂时只支持匿名映射
    if (flags & MAP_ANONYMOUS) == 0 {
        axlog::warn!("sys_mmap: file-backed mmap not supported yet");
        return -LinuxError::ENOSYS.code() as isize;
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
        match aspace.find_free_area(VirtAddr::from(addr.align_down(PAGE_SIZE)), aligned_length, limit) {
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

    match aspace.map_alloc(VirtAddr::from(map_addr), aligned_length, map_flags, false) {
        Ok(_) => {
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
