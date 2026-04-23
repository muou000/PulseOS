//! Trap 处理模块 - 处理 page fault 和其他异常

use axhal::{
    paging::MappingFlags,
    trap::{PAGE_FAULT, register_trap_handler},
};
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

    let Ok(thread) = crate::task::current_thread() else {
        axlog::error!("user page fault without Thread context: vaddr={:#x}", vaddr);
        return false;
    };
    let proc = thread.process();
    let enter_ns = axhal::time::monotonic_time_nanos() as u64;
    proc.on_kernel_entry_from_user(enter_ns);
    if proc.group_exiting() {
        thread.exit_current(proc.group_exit_code());
    }

    if proc.handle_page_fault(vaddr, access_flags) {
        let leave_ns = axhal::time::monotonic_time_nanos() as u64;
        proc.add_sys_time_ns(leave_ns.saturating_sub(enter_ns));
        if proc.group_exiting() {
            thread.exit_current(proc.group_exit_code());
        }
        proc.mark_user_resume();
        axlog::debug!("Page fault handled successfully");
        true
    } else {
        let leave_ns = axhal::time::monotonic_time_nanos() as u64;
        proc.add_sys_time_ns(leave_ns.saturating_sub(enter_ns));
        axlog::error!("Failed to handle page fault!");
        axlog::error!("  vaddr={:#x}, flags={:?}", vaddr, access_flags);
        thread.exit_current(139);
        false
    }
}
