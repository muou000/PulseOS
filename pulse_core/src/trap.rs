//! Trap 处理模块 - 处理 page fault 和其他异常

use axhal::{
    context::TrapFrame,
    paging::MappingFlags,
    trap::{ADDRESS_ERROR, ILLEGAL_INSTRUCTION, PAGE_FAULT, USER_RETURN, register_trap_handler},
};
use memory_addr::VirtAddr;

#[register_trap_handler(ILLEGAL_INSTRUCTION)]
fn handle_illegal_instruction(tf: &mut TrapFrame, _vaddr: usize, is_user: bool) -> bool {
    if is_user {
        if let Ok(thread) = crate::task::current_thread() {
            #[cfg(target_arch = "riscv64")]
            let pc = tf.sepc;
            #[cfg(target_arch = "loongarch64")]
            let pc = tf.era;

            axlog::error!(
                "Illegal instruction! pid={} exe={:?} ip={:#x}",
                thread.process().pid(),
                thread.process().exec_path(),
                pc
            );
            crate::task::queue_signal_to_thread(thread.as_ref(), 4); // SIGILL
            return true;
        }
    }
    false
}

#[register_trap_handler(ADDRESS_ERROR)]
fn handle_address_error(tf: &mut TrapFrame, vaddr: usize, is_user: bool) -> bool {
    if is_user {
        if let Ok(thread) = crate::task::current_thread() {
            #[cfg(target_arch = "riscv64")]
            let pc = tf.sepc;
            #[cfg(target_arch = "loongarch64")]
            let pc = tf.era;

            axlog::error!(
                "Address error! pid={} exe={:?} ip={:#x} vaddr={:#x}",
                thread.process().pid(),
                thread.process().exec_path(),
                pc,
                vaddr
            );
            // Usually SIGSEGV, sometimes SIGBUS. We use SIGSEGV as default.
            crate::task::queue_signal_to_thread(thread.as_ref(), 11); // SIGSEGV
            return true;
        }
    }
    false
}

fn deliver_pending_signal(tf: &mut TrapFrame) {
    let Ok(thread) = crate::task::current_thread() else {
        return;
    };
    let process = thread.process();
    if process.group_exiting() {
        axlog::debug!(
            "Process group exiting: pid={} exit_code={}",
            process.pid(),
            process.group_exit_code()
        );
        thread.exit_current(process.group_exit_code());
    }
    if thread.signal().has_pending_or_skip_once() {
        if let Some(delivery) = crate::task::check_signals_and_deliver(thread.as_ref(), tf) {
            use crate::task::{DefaultSignalAction, SignalAction};
            axlog::debug!(
                "Delivering signal: pid={} sig={} action={:?}",
                process.pid(),
                delivery.sig,
                delivery.action
            );
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
}

#[register_trap_handler(USER_RETURN)]
fn handle_user_return(tf: &mut TrapFrame) {
    deliver_pending_signal(tf);
    axtask::check_preempt_pending();
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

    let thread_result = crate::task::current_thread();
    let is_kernel_address = vaddr.as_usize() >= axconfig::plat::KERNEL_ASPACE_BASE;

    if thread_result.is_err() || (!is_user && is_kernel_address) {
        if !is_user {
            panic!("Page fault in kernel space: vaddr={:#x}", vaddr);
        } else {
            panic!("user page fault without Thread context: vaddr={:#x}", vaddr);
        }
    }

    let thread = thread_result.unwrap();

    if !is_user {
        let proc = thread.process();
        const SIGSEGV: i32 = 11;
        proc.set_exit_signal(SIGSEGV, true);
        proc.begin_group_exit(SIGSEGV);
        thread.exit_current(proc.group_exit_code());
    }
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

        let mut signo = 11; // Default to SIGSEGV
        let aspace_handle = proc.aspace_handle();
        let aspace = aspace_handle.read();
        aspace.for_each_area_with_backend(|start, end, _flags, backend| {
            if vaddr >= start && vaddr < end {
                let mut curr_backend = backend.clone();
                while let axmm::Backend::Cow(cow) = &curr_backend {
                    curr_backend = cow.inner().clone();
                }
                if let axmm::Backend::File(mapping) = curr_backend {
                    let current_file_bytes = mapping.file_bytes();
                    let relative = vaddr.as_usize().saturating_sub(start.as_usize());
                    if relative >= current_file_bytes {
                        signo = 7; // SIGBUS for out-of-bounds file mapping
                    }
                }
            }
        });
        drop(aspace);

        crate::task::queue_signal_to_thread(thread.as_ref(), signo as usize);
        proc.mark_user_resume();
        true
    }
}

/// Ensure the module is linked.
pub fn init() {}
