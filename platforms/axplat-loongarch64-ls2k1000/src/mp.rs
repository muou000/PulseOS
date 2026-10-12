use axplat::{mem::PhysAddr, power::CpuBootError};
use loongArch64::ipi::{csr_mail_send, send_ipi_single};

use crate::{
    config::plat::{MAX_CPU_NUM, PHYS_VIRT_OFFSET},
    mp_common::{kernel_virt_to_cached_dmw, phys_to_cached_dmw, valid_stack_top},
};

const ACTION_BOOT_CPU: u32 = 1;

/// Starts the given secondary CPU with its boot stack.
pub fn start_secondary_cpu(cpu_id: usize, stack_top: PhysAddr) -> Result<(), CpuBootError> {
    if cpu_id == 0 || cpu_id >= MAX_CPU_NUM {
        return Err(CpuBootError::InvalidParameter);
    }
    let target_cpu_id =
        crate::topology::hardware_cpu_id(cpu_id).ok_or(CpuBootError::InvalidParameter)?;

    let stack_top = stack_top.as_usize();
    if !crate::mem::ram_ranges()
        .iter()
        .any(|&(base, size)| valid_stack_top(stack_top, base, size))
    {
        return Err(CpuBootError::InvalidAddress);
    }

    let entry = kernel_virt_to_cached_dmw(
        crate::boot::_start_secondary as *const () as usize,
        PHYS_VIRT_OFFSET,
    )
    .ok_or(CpuBootError::InvalidAddress)?;
    let stack_top = phys_to_cached_dmw(stack_top).ok_or(CpuBootError::InvalidAddress)?;

    unsafe {
        core::arch::asm!("dbar 0", options(nostack));
    }
    csr_mail_send(stack_top as u64, target_cpu_id, 1);
    csr_mail_send(entry as u64, target_cpu_id, 0);
    send_ipi_single(target_cpu_id, ACTION_BOOT_CPU);
    Ok(())
}
