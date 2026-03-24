//! Trap 处理模块 - 处理 page fault 和其他异常

use axhal::paging::MappingFlags;
use axhal::trap::{PAGE_FAULT, register_trap_handler};
use memory_addr::VirtAddr;

/// Page fault处理程序
#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(vaddr: VirtAddr, access_flags: MappingFlags, is_user: bool) -> bool {
    axlog::debug!(
        "Page fault @ VA:{:#x}, flags:{:?}, user={}",
        vaddr,
        access_flags,
        is_user
    );

    // 如果不是用户空间，不处理
    if !is_user {
        axlog::error!("Page fault in kernel space: vaddr={:#x}", vaddr);
        return false;
    }

    // 获取当前进程
    let proc = match crate::task::current_process() {
        Some(p) => p,
        None => {
            axlog::error!("Page fault in user space but no current process!");
            axlog::error!("  vaddr={:#x}", vaddr);
            return false;
        }
    };

    // 委托给进程的地址空间处理
    // 注意：axmm 的 handle_page_fault 使用 PageFaultFlags，需要转换
    use axhal::trap::PageFaultFlags;
    let pf_flags = if access_flags.contains(MappingFlags::WRITE) {
        PageFaultFlags::WRITE
    } else {
        PageFaultFlags::empty()
    };

    if proc.handle_page_fault(vaddr, pf_flags) {
        axlog::debug!("Page fault handled successfully");
        true
    } else {
        axlog::error!("Failed to handle page fault!");
        axlog::error!("  vaddr={:#x}, flags={:?}", vaddr, access_flags);
        axlog::error!("  This usually means invalid memory access");
        false
    }
}
