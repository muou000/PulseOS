//! Trap 处理模块 - 处理 page fault 和其他异常

use axhal::{
    context::TrapFrame,
    paging::MappingFlags,
    trap::{PAGE_FAULT, USER_RETURN, register_trap_handler},
};
use memory_addr::VirtAddr;

fn deliver_pending_signal(tf: &mut TrapFrame) {
    let Ok(thread) = crate::task::current_thread() else {
        return;
    };
    let process = thread.process();
    if process.group_exiting() {
        thread.exit_current(process.group_exit_code());
    }
    if let Some(delivery) = crate::task::check_signals_and_deliver(thread.as_ref(), tf) {
        use crate::task::{DefaultSignalAction, SignalAction};
        match delivery.action {
            SignalAction::Default(DefaultSignalAction::Terminate) => {
                process.set_exit_signal(delivery.sig as i32, false);
                process.begin_group_exit(delivery.sig as i32);
                thread.exit_current(process.group_exit_code());
            }
            SignalAction::Default(DefaultSignalAction::CoreDump) => {
                process.set_exit_signal(delivery.sig as i32, true);
                process.begin_group_exit(delivery.sig as i32);
                thread.exit_current(process.group_exit_code());
            }
            SignalAction::Default(DefaultSignalAction::Stop)
            | SignalAction::Default(DefaultSignalAction::Continue)
            | SignalAction::Default(DefaultSignalAction::Ignore)
            | SignalAction::Ignore
            | SignalAction::Handler(_) => {}
        }
    }
}

#[register_trap_handler(USER_RETURN)]
fn handle_user_return(tf: &mut TrapFrame) {
    deliver_pending_signal(tf);
}

/// Page fault处理程序
#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(vaddr: VirtAddr, access_flags: MappingFlags, is_user: bool) -> bool {
    axlog::debug!(
        "Page fault @ VA:{:#x}, flags:{:?}, user={}",
        vaddr,
        access_flags,
        is_user
    );

    if !is_user {
        panic!("Page fault in kernel space: vaddr={:#x}", vaddr);
    }

    let Ok(thread) = crate::task::current_thread() else {
        panic!("user page fault without Thread context: vaddr={:#x}", vaddr);
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
        axlog::error!(
            "Failed to handle page fault! pid={} exe={:?}",
            proc.pid(),
            proc.exec_path()
        );
        axlog::error!("  vaddr={:#x}, flags={:?}", vaddr, access_flags);
        thread.exit_current(139);
    }
}
