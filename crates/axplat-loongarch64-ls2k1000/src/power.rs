#[cfg(feature = "smp")]
use axplat::power::CpuBootError;
use axplat::{mem::pa, power::PowerIf};

struct PowerImpl;

#[impl_plat_interface]
impl PowerIf for PowerImpl {
    #[cfg(feature = "smp")]
    fn cpu_boot(cpu_id: usize, stack_top_paddr: usize) -> Result<(), CpuBootError> {
        crate::mp::start_secondary_cpu(cpu_id, pa!(stack_top_paddr))
    }

    fn system_off() -> ! {
        // The reference 2K1000 DTB has no standard poweroff controller. Do
        // not issue QEMU's GED write on physical hardware.
        info!("LS2K1000 shutdown requested; halting CPUs");
        loop {
            axcpu::asm::halt();
        }
    }

    fn cpu_num() -> usize {
        crate::topology::cpu_count()
    }
}
