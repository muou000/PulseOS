//! IRQ-local freezing of one privilege domain's FP chain.
//!
//! No trap/task/address-space references escape this module. The worker only
//! receives integer registers, bounded IPs, and a termination reason. In
//! particular a kernel observation never invents an outer userspace frame.

use hal::{context::TrapFrame, paging::MappingFlags};
use pulse_bpf_schema::{FrozenStack, StackLimits, StackRegisters, StackStatus, walk_frame_pointers};

#[cfg(target_arch = "riscv64")]
fn registers(tf: &TrapFrame) -> StackRegisters {
    StackRegisters { ip: tf.ip() as u64, sp: tf.regs.sp as u64,
        fp: tf.regs.s0 as u64, ra: tf.regs.ra as u64 }
}

#[cfg(target_arch = "loongarch64")]
fn registers(tf: &TrapFrame) -> StackRegisters {
    StackRegisters { ip: tf.ip() as u64, sp: tf.regs.sp as u64,
        fp: tf.regs.fp as u64, ra: tf.regs.ra as u64 }
}

fn aligned_pc(ip: u64) -> bool {
    #[cfg(target_arch = "riscv64")]
    { ip & 1 == 0 }
    #[cfg(target_arch = "loongarch64")]
    { ip & 3 == 0 }
}

/// Freeze the interrupted current task's stack before it resumes.
///
/// # Safety
/// `tf` must be the live timer-IRQ entry frame for `task`, and `from_user` must
/// be the architecture trap-entry privilege classification. `task` must be the
/// currently executing task; if user mode, its process must own the active user
/// page table. IRQs must remain disabled and no scheduling may occur until the
/// function returns. No other CPU may execute this task concurrently.
pub(super) unsafe fn freeze(
    tf: &TrapFrame,
    from_user: bool,
    task: &task::TaskInner,
) -> FrozenStack {
    let origin = registers(tf);
    if hal::asm::irqs_enabled() {
        return FrozenStack::unavailable(origin, StackStatus::Unavailable);
    }
    let start = hal::time::monotonic_time_nanos();
    let mut stack = if from_user {
        freeze_user(origin, task)
    } else {
        freeze_kernel(origin, task)
    };
    stack.capture_ns = hal::time::monotonic_time_nanos().saturating_sub(start);
    stack
}

fn freeze_user(origin: StackRegisters, task: &task::TaskInner) -> FrozenStack {
    // This is the interrupted current task, whose process stays registered
    // until its exit path can run. The temporary Arc cannot outlive this IRQ.
    let Ok(thread) = crate::thread_ref_from_task(task) else {
        return FrozenStack::unavailable(origin, StackStatus::Unavailable);
    };
    let process = thread.process();
    process.with_sampling_aspace(|aspace| {
        walk_frame_pointers(origin, StackLimits::default(), |address| {
            let address = usize::try_from(address).map_err(|_| StackStatus::AddressOverflow)?;
            if !crate::uaccess::USER_MEMORY_RANGE.contains(address, 16)
                || !aspace.sampling_frame_readable(address.into())
            {
                return Err(StackStatus::ReadFault);
            }
            // SAFETY: trap entry disabled IRQs; this observer cannot switch or
            // migrate. The process slot read lease prevents exec replacement,
            // the VMA read lease prevents unmap/protection changes, and the
            // checked mapping is readable user RAM. No PTE lock is acquired:
            // an absent resident page exits via the dedicated load-PC fixup.
            // UserAccessGuard restores SUM. These leases cover the entire walk.
            unsafe { crate::uaccess::read_sampling_frame(address) }
                .ok_or(StackStatus::ReadFault)
        }, |ip| {
            aligned_pc(ip) && usize::try_from(ip).is_ok_and(|address| {
                crate::uaccess::USER_MEMORY_RANGE.contains(address, 1)
                    && aspace.can_access_range(address.into(), 1, MappingFlags::USER | MappingFlags::EXECUTE)
            })
        })
    }).unwrap_or_else(|| FrozenStack::unavailable(origin, StackStatus::Busy))
}

fn freeze_kernel(origin: StackRegisters, task: &task::TaskInner) -> FrozenStack {
    let Some(bounds) = task.kernel_stack_range() else {
        return FrozenStack::unavailable(origin, StackStatus::Unavailable);
    };
    if !bounds.contains(&(origin.sp as usize)) {
        return FrozenStack::unavailable(origin, StackStatus::InvalidFrame);
    }
    unsafe extern "C" {
        fn _stext();
        fn _etext();
    }
    let text_start = _stext as *const () as usize as u64;
    let text_end = _etext as *const () as usize as u64;
    walk_frame_pointers(origin, StackLimits::default(), |address| {
        let address = usize::try_from(address).map_err(|_| StackStatus::AddressOverflow)?;
        if address & 7 != 0 || address < bounds.start
            || address.checked_add(16).is_none_or(|end| end > bounds.end)
        {
            return Err(StackStatus::InvalidFrame);
        }
        // SAFETY: `task` retains its immutable, owned TaskStack allocation.
        // This is the current interrupted stack; IRQs remain disabled and no
        // scheduling occurs. The checked record lies in that ordinary RAM
        // allocation, at/above the interrupted SP (walker invariant), away
        // from the observer's own frames below it. Dedicated assembly reads
        // opaque machine words and handles data faults before the resolver;
        // no Rust slice/reference to interrupted stack locals is formed.
        unsafe { cpu::sampling::read_frame_nofault(address) }.ok_or(StackStatus::ReadFault)
    }, |ip| aligned_pc(ip) && (text_start..text_end).contains(&ip))
}
