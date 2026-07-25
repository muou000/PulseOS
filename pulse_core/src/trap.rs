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

            axlog::warn!(
                "Illegal instruction! pid={} exe={:?} ip={:#x}",
                thread.process().pid(),
                thread.process().exec_path(),
                pc
            );
            crate::task::force_signal_to_thread(thread.as_ref(), 4); // SIGILL
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

            axlog::warn!(
                "Address error! pid={} exe={:?} ip={:#x} vaddr={:#x}",
                thread.process().pid(),
                thread.process().exec_path(),
                pc,
                vaddr
            );
            // Usually SIGSEGV, sometimes SIGBUS. We use SIGSEGV as default.
            crate::task::force_signal_to_thread(thread.as_ref(), 11); // SIGSEGV
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
    thread.exit_if_exec_requested();
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

#[register_trap_handler(PAGE_FAULT)]
fn handle_page_fault(
    tf: &mut TrapFrame,
    vaddr: VirtAddr,
    access_flags: MappingFlags,
    is_user: bool,
) -> bool {
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
            if tf.fixup_exception() {
                return true;
            }
            panic!("Page fault in kernel space: vaddr={:#x}", vaddr);
        } else {
            panic!("user page fault without Thread context: vaddr={:#x}", vaddr);
        }
    }

    let thread = thread_result.unwrap();
    let proc = thread.process();
    let enter_ns = axhal::time::monotonic_time_nanos() as u64;

    if is_user {
        thread.exit_if_exec_requested();
        proc.on_kernel_entry_from_user(enter_ns);
        if proc.group_exiting() {
            thread.exit_current(proc.group_exit_code());
        }
    }

    if proc.handle_page_fault(vaddr, access_flags) {
        axhal::asm::flush_tlb(Some(vaddr));
        if is_user {
            let leave_ns = axhal::time::monotonic_time_nanos() as u64;
            proc.add_sys_time_ns(leave_ns.saturating_sub(enter_ns));
            if proc.group_exiting() {
                thread.exit_current(proc.group_exit_code());
            }
            proc.mark_user_resume_at(leave_ns);
        }
        axlog::debug!("Page fault handled successfully");
        return true;
    }

    if !is_user {
        if tf.fixup_exception() {
            axlog::debug!("Kernel page fault fixup applied for vaddr={:#x}", vaddr);
            return true;
        }
        panic!("Unhandled page fault in kernel space: vaddr={:#x}", vaddr);
    }
    let leave_ns = axhal::time::monotonic_time_nanos() as u64;
    proc.add_sys_time_ns(leave_ns.saturating_sub(enter_ns));
    axlog::warn!(
        "Failed to handle page fault! pid={} exe={:?}",
        proc.pid(),
        proc.exec_path()
    );
    axlog::warn!("  vaddr={:#x}, flags={:?}", vaddr, access_flags);

    let mut signo = 11; // Default to SIGSEGV
    let mut fault_area = None;
    let mut previous_area = None;
    let mut next_area = None;
    let aspace_handle = proc.aspace_handle();
    let aspace = aspace_handle.read();
    aspace.for_each_area_with_backend(|start, end, flags, backend| {
        if end <= vaddr {
            previous_area = Some((start, end, flags));
        } else if start > vaddr && next_area.is_none() {
            next_area = Some((start, end, flags));
        }
        if vaddr >= start && vaddr < end {
            fault_area = Some((start, end, flags));
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

    let signal = thread.signal();
    let blocked_mask = signal.blocked_mask();
    let signal_bit = 1u64 << (signo - 1);
    let action = crate::task::resolve_action(&signal.shared(), signo as usize);
    axlog::warn!(
        "  heap_top={:#x}, area={:?}, previous_area={:?}, next_area={:?}",
        proc.get_heap_top(),
        fault_area,
        previous_area,
        next_area
    );
    axlog::warn!(
        "  synchronous signal: signo={}, action={:?}, blocked={}, blocked_mask={:#x}, \
         in_handler={}",
        signo,
        action,
        (blocked_mask & signal_bit) != 0,
        blocked_mask,
        signal.is_in_handler()
    );
    let newly_queued = crate::task::force_signal_to_thread(thread.as_ref(), signo as usize);
    axlog::warn!(
        "  synchronous signal newly_queued={}, pending_mask={:#x}",
        newly_queued,
        signal.pending_mask()
    );
    proc.mark_user_resume_at(leave_ns);
    true
}

/// Ensure the module is linked and register memory reclaim callbacks.
pub fn init() {
    axalloc::register_page_reclaim_fn(axfs::page_cache_reclaim);
    axlog::info!("page cache reclaim function registered");
}
