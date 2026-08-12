use axplat::init::InitIf;

struct InitIfImpl;

#[impl_plat_interface]
impl InitIf for InitIfImpl {
    /// This function should be called immediately after the kernel has booted,
    /// and performed earliest platform configuration and initialization (e.g.,
    /// early console, clocking).
    fn init_early(_cpu_id: usize, mbi: usize) {
        unsafe { crate::console::early_putchar(b'I') };
        crate::console::init_early();
        crate::topology::init_platform_from_dtb(mbi);
        unsafe { crate::console::early_putchar(b'D') };
        axcpu::init::init_trap();
        unsafe { crate::console::early_putchar(b'R') };
        crate::time::init_early(mbi);
        unsafe {
            crate::console::early_putchar(b'E');
            crate::console::early_putchar(b'\r');
            crate::console::early_putchar(b'\n');
        }
    }

    /// Initializes the platform at the early stage for secondary cores.
    #[cfg(feature = "smp")]
    fn init_early_secondary(_cpu_id: usize) {
        axcpu::init::init_trap();
    }

    /// Initializes the platform at the later stage for the primary core.
    ///
    /// This function should be called after the kernel has done part of its
    /// initialization (e.g, logging, memory management), and finalized the rest of
    /// platform configuration and initialization.
    fn init_later(cpu_id: usize, _arg: usize) {
        crate::time::report_init();
        #[cfg(feature = "irq")]
        crate::irq::init_primary(cpu_id);
        crate::time::init_percpu();
    }

    /// Initializes the platform at the later stage for secondary cores.
    #[cfg(feature = "smp")]
    fn init_later_secondary(cpu_id: usize) {
        #[cfg(feature = "irq")]
        crate::irq::init_secondary(cpu_id);
        crate::time::init_percpu();
    }
}
