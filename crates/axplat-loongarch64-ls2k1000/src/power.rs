#[cfg(feature = "smp")]
use axplat::power::CpuBootError;
use axplat::{
    mem::pa,
    power::{PowerIf, SystemResetResult},
};

struct PowerImpl;

#[impl_plat_interface]
impl PowerIf for PowerImpl {
    #[cfg(feature = "smp")]
    fn cpu_boot(cpu_id: usize, stack_top_paddr: usize) -> Result<(), CpuBootError> {
        crate::mp::start_secondary_cpu(cpu_id, pa!(stack_top_paddr))
    }

    fn system_off() -> ! {
        // The LS2K1000 PMC is exposed as a syscon-poweroff controller in the
        // reference DTB: PMC + 0x14, written with 0x3c00.
        const PMC_POWEROFF_ADDR: *mut u32 =
            crate::mem::phys_to_virt(pa!(0x1fe2_7014)).as_mut_ptr().cast();

        info!("Powering off...");
        unsafe { PMC_POWEROFF_ADDR.write_volatile(0x3c00) };
        loop {
            axcpu::asm::halt();
        }
    }

    fn system_reset() -> SystemResetResult {
        // The LS2K1000 PMC is exposed as a syscon-reboot controller in the
        // reference DTB: PMC + 0x30, written with bit 0 set.
        const PMC_REBOOT_ADDR: *mut u32 =
            crate::mem::phys_to_virt(pa!(0x1fe2_7030)).as_mut_ptr().cast();

        info!("Rebooting...");
        unsafe { PMC_REBOOT_ADDR.write_volatile(1) };
        loop {
            axcpu::asm::halt();
        }
    }

    fn cpu_num() -> usize {
        crate::topology::cpu_count()
    }
}
