use core::sync::atomic::{AtomicUsize, Ordering};

use config::{TASK_STACK_SIZE, plat::MAX_CPU_NUM};
use hal::{
    mem::{VirtAddr, virt_to_phys},
    power::CpuBootError,
};

#[unsafe(link_section = ".bss.stack")]
static mut SECONDARY_BOOT_STACK: [[u8; TASK_STACK_SIZE]; MAX_CPU_NUM - 1] =
    [[0; TASK_STACK_SIZE]; MAX_CPU_NUM - 1];

static ENTERED_CPU_MASK: AtomicUsize = AtomicUsize::new(0);

#[allow(clippy::absurd_extreme_comparisons)]
pub fn start_secondary_cpus(primary_cpu_id: usize) {
    let mut stack_slot = 0;
    let cpu_num = hal::cpu_num();
    for cpu_id in 0..cpu_num {
        if cpu_id != primary_cpu_id && stack_slot < MAX_CPU_NUM - 1 {
            let stack_top = virt_to_phys(VirtAddr::from(unsafe {
                SECONDARY_BOOT_STACK[stack_slot].as_ptr_range().end as usize
            }));
            stack_slot += 1;

            debug!("starting CPU {}...", cpu_id);
            let cpu_bit = 1usize << cpu_id;
            super::BOOTED_CPU_MASK.fetch_or(cpu_bit, Ordering::Release);
            match hal::power::cpu_boot(cpu_id, stack_top.as_usize()) {
                Ok(()) => {}
                Err(CpuBootError::AlreadyOn) => {
                    warn!("CPU {cpu_id} is already running; waiting for its runtime entry");
                }
                Err(error) => {
                    super::BOOTED_CPU_MASK.fetch_and(!cpu_bit, Ordering::AcqRel);
                    warn!("failed to start CPU {cpu_id}: {error}");
                    if error == CpuBootError::NotSupported {
                        break;
                    }
                    continue;
                }
            }

            while ENTERED_CPU_MASK.load(Ordering::Acquire) & cpu_bit == 0 {
                core::hint::spin_loop();
            }
        }
    }
    super::SECONDARY_START_COMPLETE.store(true, Ordering::Release);
}

/// The main entry point of the ArceOS runtime for secondary cores.
///
/// It is called from the bootstrapping code in the specific platform crate.
#[axplat::secondary_main]
pub fn rust_main_secondary(cpu_id: usize) -> ! {
    hal::init_percpu_secondary(cpu_id);
    #[cfg(feature = "alloc")]
    kernel_alloc::init_percpu_slab(cpu_id);
    hal::init_early_secondary(cpu_id);

    ENTERED_CPU_MASK.fetch_or(1usize << cpu_id, Ordering::Release);
    info!("Secondary CPU {} started.", cpu_id);

    #[cfg(feature = "paging")]
    mm::init_memory_management_secondary();

    hal::init_later_secondary(cpu_id);

    #[cfg(feature = "multitask")]
    task::init_scheduler_secondary();

    #[cfg(feature = "ipi")]
    {
        ipi::init();
        ipi::mark_current_cpu_ready();
    }

    // With boot accounting checks enabled, publishing readiness promises that
    // this CPU will stay quiescent until the primary releases is_init_ok().
    // Its PCP was initialized at entry; no task/GC loop may run in this window.
    #[cfg(feature = "pcp-boot-checks")]
    assert!(!hal::asm::irqs_enabled(), "secondary CPU enabled IRQs before PCP boot barrier");
    info!("Secondary CPU {:x} init OK.", cpu_id);
    super::INITED_CPUS.fetch_add(1, Ordering::Release);

    while !super::is_init_ok() {
        core::hint::spin_loop();
    }

    #[cfg(feature = "irq")]
    hal::asm::enable_irqs();

    hal::mark_cpu_online(cpu_id);

    #[cfg(all(feature = "tls", not(feature = "multitask")))]
    super::init_tls();

    #[cfg(feature = "multitask")]
    task::run_idle();
    #[cfg(not(feature = "multitask"))]
    loop {
        hal::asm::wait_for_irqs();
    }
}
