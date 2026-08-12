use axplat::power::{CpuBootError, PowerIf};

struct PowerImpl;

#[impl_plat_interface]
impl PowerIf for PowerImpl {
    /// Bootstraps the given CPU core with the given initial stack (in physical
    /// address).
    ///
    /// Where `cpu_id` is the logical CPU ID (0, 1, ..., N-1, N is the number of
    /// CPU cores on the platform).
    #[cfg(feature = "smp")]
    fn cpu_boot(cpu_id: usize, stack_top_paddr: usize) -> Result<(), CpuBootError> {
        use axplat::mem::{va, virt_to_phys};
        unsafe extern "C" {
            fn _start_secondary();
        }
        if sbi_rt::probe_extension(sbi_rt::Hsm).is_unavailable() {
            return Err(CpuBootError::NotSupported);
        }
        let hart_id = crate::topology::hart_id(cpu_id).ok_or(CpuBootError::InvalidParameter)?;
        let entry = virt_to_phys(va!(_start_secondary as *const () as usize));
        info!(
            "Starting logical CPU {cpu_id} on JH7110 hart {hart_id}: entry={:#x}, \
             stack={stack_top_paddr:#x}",
            entry.as_usize()
        );
        let result = sbi_rt::hart_start(hart_id, entry.as_usize(), stack_top_paddr);
        decode_hart_start(result)
    }

    /// Shutdown the whole system.
    fn system_off() -> ! {
        info!("Shutting down...");
        sbi_rt::system_reset(sbi_rt::Shutdown, sbi_rt::NoReason);
        warn!("It should shutdown!");
        loop {
            axcpu::asm::halt();
        }
    }

    /// Get the number of CPU cores available on this platform.
    fn cpu_num() -> usize {
        crate::topology::cpu_count()
    }
}

#[cfg(feature = "smp")]
fn decode_hart_start(result: sbi_rt::SbiRet) -> Result<(), CpuBootError> {
    match result.error {
        error if error == sbi_rt::SbiRet::success(0).error => Ok(()),
        error if error == sbi_rt::SbiRet::not_supported().error => Err(CpuBootError::NotSupported),
        error if error == sbi_rt::SbiRet::invalid_param().error => {
            Err(CpuBootError::InvalidParameter)
        }
        error if error == sbi_rt::SbiRet::invalid_address().error => {
            Err(CpuBootError::InvalidAddress)
        }
        error
            if error == sbi_rt::SbiRet::already_available().error
                || error == sbi_rt::SbiRet::already_started().error =>
        {
            Err(CpuBootError::AlreadyOn)
        }
        error => Err(CpuBootError::Firmware(error as isize)),
    }
}
