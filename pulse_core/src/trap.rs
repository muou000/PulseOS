//! Trap 处理模块 - 处理 page fault 和其他异常

use axerrno::AxError;
use axhal::{
    context::TrapFrame,
    paging::MappingFlags,
    trap::{
        ADDRESS_ERROR, AddressError, ILLEGAL_INSTRUCTION, PAGE_FAULT, USER_RETURN,
        register_trap_handler,
    },
};
use linux_raw_sys::general::{
    BUS_ADRALN, BUS_ADRERR, ILL_ILLOPC, SEGV_ACCERR, SEGV_MAPERR, SIGBUS, SIGILL, SIGKILL, SIGSEGV,
};
use memory_addr::VirtAddr;

/// Restores interrupt delivery while a user-originated trap runs a sleepable
/// slow path, then returns to the IRQ-disabled trap-exit contract.
#[must_use]
pub struct TrapIrqEnableGuard {
    restore_disabled: bool,
    _not_send_or_sync: core::marker::PhantomData<*mut ()>,
}

impl TrapIrqEnableGuard {
    pub fn new() -> Self {
        let restore_disabled = !axhal::asm::irqs_enabled();
        if restore_disabled {
            axhal::asm::enable_irqs();
        }
        Self {
            restore_disabled,
            _not_send_or_sync: core::marker::PhantomData,
        }
    }
}

impl Drop for TrapIrqEnableGuard {
    fn drop(&mut self) {
        if self.restore_disabled {
            axhal::asm::disable_irqs();
        }
    }
}

#[cfg(all(target_arch = "loongarch64", feature = "ls2k1000"))]
fn emulate_user_unaligned(
    tf: &mut TrapFrame,
    fault_address: usize,
    process: &crate::task::Process,
) -> Result<(), ()> {
    let access = unsafe { tf.decode_unaligned_access_at(fault_address as u64) }.map_err(|_| ())?;
    let address = usize::try_from(access.address()).map_err(|_| ())?;
    let mapping_flags = match access.access_type() {
        axcpu::UnalignedAccessType::Read => MappingFlags::READ,
        axcpu::UnalignedAccessType::Write => MappingFlags::WRITE,
    };

    process
        .validate_user_range(address, access.size())
        .map_err(|_| ())?;
    {
        let _irq_guard = TrapIrqEnableGuard::new();
        process
            .try_fault_in_user_range(address, access.size(), mapping_flags)
            .map_err(|_| ())?;
    }

    // Keep mappings and permissions stable through the byte accesses. This is
    // especially important for stores, where a concurrent munmap must not leave
    // a partially committed operation.
    let aspace_handle = process.aspace_handle();
    let aspace = aspace_handle.read();
    if !aspace.can_access_range(
        VirtAddr::from(address),
        access.size(),
        mapping_flags | MappingFlags::USER,
    ) {
        return Err(());
    }

    unsafe { tf.emulate_unaligned_access(access) }.map_err(|_| ())
}

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
            crate::task::force_signal_to_thread_with_info(
                thread.as_ref(),
                SIGILL as usize,
                crate::task::signal_info_for_fault(SIGILL as usize, ILL_ILLOPC as i32, pc),
            );
            return true;
        }
    }
    false
}

#[register_trap_handler(ADDRESS_ERROR)]
fn handle_address_error(
    tf: &mut TrapFrame,
    vaddr: usize,
    error: AddressError,
    is_user: bool,
) -> bool {
    if is_user {
        if let Ok(thread) = crate::task::current_thread() {
            #[cfg(target_arch = "riscv64")]
            let pc = tf.sepc;
            #[cfg(target_arch = "loongarch64")]
            let pc = tf.era;

            #[cfg(all(target_arch = "loongarch64", feature = "ls2k1000"))]
            if error == AddressError::Misaligned {
                let process = thread.process();
                thread.exit_if_exec_requested();
                if process.group_exiting() {
                    thread.exit_current(process.group_exit_code());
                }
                if emulate_user_unaligned(tf, vaddr, process.as_ref()).is_ok() {
                    return true;
                }
            }

            axlog::warn!(
                "Address error! pid={} exe={:?} ip={:#x} vaddr={:#x} kind={error:?}",
                thread.process().pid(),
                thread.process().exec_path(),
                pc,
                vaddr
            );
            let (signo, code, fault_addr) = match error {
                AddressError::BadAddress => (SIGBUS, BUS_ADRERR, vaddr),
                AddressError::Misaligned => {
                    #[cfg(target_arch = "riscv64")]
                    {
                        // Linux reports the instruction address for a RISC-V
                        // misalignment trap, rather than stval's memory address.
                        (SIGBUS, BUS_ADRALN, pc)
                    }
                    #[cfg(target_arch = "loongarch64")]
                    {
                        (SIGBUS, BUS_ADRALN, vaddr)
                    }
                }
            };
            crate::task::force_signal_to_thread_with_info(
                thread.as_ref(),
                signo as usize,
                crate::task::signal_info_for_fault(signo as usize, code as i32, fault_addr),
            );
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
                SignalAction::Default(DefaultSignalAction::Stop) => {
                    process.enter_group_stop(delivery.sig as i32);
                }
                SignalAction::Default(DefaultSignalAction::Continue) => {
                    process.continue_group();
                }
                SignalAction::Default(DefaultSignalAction::Ignore)
                | SignalAction::Ignore
                | SignalAction::Handler(_) => {}
            }
        }
    }
}

#[register_trap_handler(USER_RETURN)]
fn handle_user_return(tf: &mut TrapFrame) {
    loop {
        deliver_pending_signal(tf);
        let Ok(thread) = crate::task::current_thread() else {
            break;
        };
        let process = thread.process();
        if process.group_exiting() {
            thread.exit_current(process.group_exit_code());
        }
        if !process.group_stopped() {
            break;
        }

        // SIGCONT wakes this wait even when it is blocked or ignored.  Other
        // deliverable signals wake it so fatal actions can be processed before
        // the group is parked again.
        process.wait_while_group_stopped(thread.as_ref());
    }
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

    let fault_result = {
        let _irq_guard = is_user.then(TrapIrqEnableGuard::new);
        proc.handle_page_fault(vaddr, access_flags)
    };
    let fault_error = match fault_result {
        Ok(true) => {
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
        Ok(false) => None,
        Err(error) => {
            axlog::error!("page fault resolution failed: {error:?}");
            Some(error)
        }
    };

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
    #[cfg(target_arch = "loongarch64")]
    axlog::warn!(
        "  era={:#x}, badi={:#010x}, ra={:#x}, sp={:#x}, tp={:#x}, a0={:#x}, a1={:#x}, a2={:#x}",
        tf.era,
        tf.bad_instruction(),
        tf.regs.ra,
        tf.regs.sp,
        tf.regs.tp,
        tf.regs.a0,
        tf.regs.a1,
        tf.regs.a2
    );

    let out_of_memory = fault_error == Some(AxError::NoMemory);
    let mut signo = if out_of_memory { SIGKILL } else { SIGSEGV };
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
            if !out_of_memory && let axmm::Backend::File(mapping) = curr_backend {
                let current_file_bytes = mapping.file_bytes();
                let relative = vaddr.as_usize().saturating_sub(start.as_usize());
                if relative >= current_file_bytes {
                    signo = SIGBUS;
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
    let fault_info = match signo {
        SIGSEGV => Some(crate::task::signal_info_for_fault(
            signo as usize,
            if fault_area.is_some() {
                SEGV_ACCERR as i32
            } else {
                SEGV_MAPERR as i32
            },
            vaddr.as_usize(),
        )),
        SIGBUS => Some(crate::task::signal_info_for_fault(
            signo as usize,
            BUS_ADRERR as i32,
            vaddr.as_usize(),
        )),
        _ => None,
    };
    let newly_queued = match fault_info {
        Some(info) => {
            crate::task::force_signal_to_thread_with_info(thread.as_ref(), signo as usize, info)
        }
        None => crate::task::force_signal_to_thread(thread.as_ref(), signo as usize),
    };
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
