#[cfg(feature = "smp")]
use axplat::power::CpuBootError;
use axplat::{
    mem::pa,
    power::{PowerIf, SystemResetResult},
};

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
        crate::mp::start_secondary_cpu(cpu_id, pa!(stack_top_paddr))
    }

    /// Shutdown the whole system.
    fn system_off() -> ! {
        const HALT_ADDR: *mut u8 =
            crate::mem::phys_to_virt(pa!(crate::config::devices::GED_PADDR)).as_mut_ptr();

        info!("Shutting down...");
        unsafe { HALT_ADDR.write_volatile(0x34) };
        axcpu::asm::halt();
        warn!("It should shutdown!");
        loop {
            axcpu::asm::halt();
        }
    }

    /// Reset the QEMU virt machine through its ACPI GED reset register.
    fn system_reset() -> SystemResetResult {
        const GED_RESET_OFFSET: usize = 2;
        const GED_RESET_VALUE: u8 = 0x42;
        const GED_ADDR: *mut u8 =
            crate::mem::phys_to_virt(pa!(crate::config::devices::GED_PADDR)).as_mut_ptr();

        info!("Rebooting...");
        unsafe {
            GED_ADDR
                .add(GED_RESET_OFFSET)
                .write_volatile(GED_RESET_VALUE)
        };
        loop {
            axcpu::asm::halt();
        }
    }

    /// Get the number of CPU cores available on this platform.
    fn cpu_num() -> usize {
        crate::topology::cpu_count()
    }
}
