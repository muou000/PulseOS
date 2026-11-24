//! Runtime library of [ArceOS](https://github.com/arceos-org/arceos).
//!
//! Any application uses ArceOS should link this library. It does some
//! initialization work before entering the application's `main` function.
//!
//! # Cargo Features
//!
//! - `alloc`: Enable global memory allocator.
//! - `paging`: Enable page table manipulation support.
//! - `irq`: Enable interrupt handling support.
//! - `multitask`: Enable multi-threading support.
//! - `smp`: Enable SMP (symmetric multiprocessing) support.
//! - `fs`: Enable filesystem support.
//! - `net`: Enable networking support.
//! - `display`: Enable graphics support.
//!
//! All the features are optional and disabled by default.

#![cfg_attr(not(test), no_std)]

#[macro_use]
extern crate kernel_log;

#[cfg(all(target_os = "none", not(test)))]
mod lang_items;

#[cfg(feature = "smp")]
mod mp;

pub mod vdso;

#[cfg(feature = "smp")]
pub use self::mp::rust_main_secondary;

const LOGO: &str = r#"
       d8888                            .d88888b.   .d8888b.
      d88888                           d88P" "Y88b d88P  Y88b
     d88P888                           888     888 Y88b.
    d88P 888 888d888  .d8888b  .d88b.  888     888  "Y888b.
   d88P  888 888P"   d88P"    d8P  Y8b 888     888     "Y88b.
  d88P   888 888     888      88888888 888     888       "888
 d8888888888 888     Y88b.    Y8b.     Y88b. .d88P Y88b  d88P
d88P     888 888      "Y8888P  "Y8888   "Y88888P"   "Y8888P"
"#;

unsafe extern "C" {
    /// Application's entry point.
    fn main();
}

struct LogIfImpl;

#[crate_interface::impl_interface]
impl kernel_log::LogIf for LogIfImpl {
    fn console_write_str(s: &str) {
        hal::console::write_bytes(s.as_bytes());
    }

    fn current_time() -> core::time::Duration {
        hal::time::monotonic_time()
    }

    fn current_cpu_id() -> Option<usize> {
        #[cfg(feature = "smp")]
        if is_init_ok() {
            Some(hal::percpu::this_cpu_id())
        } else {
            None
        }
        #[cfg(not(feature = "smp"))]
        Some(0)
    }

    fn current_task_id() -> Option<u64> {
        if is_init_ok() {
            #[cfg(feature = "multitask")]
            {
                task::current_may_uninit().map(|curr| curr.id().as_u64())
            }
            #[cfg(not(feature = "multitask"))]
            None
        } else {
            None
        }
    }
}

use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(feature = "smp")]
use core::sync::atomic::AtomicBool;

/// Number of CPUs that have completed initialization.
static INITED_CPUS: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "smp")]
static BOOTED_CPU_MASK: AtomicUsize = AtomicUsize::new(0);

#[cfg(feature = "smp")]
static SECONDARY_START_COMPLETE: AtomicBool = AtomicBool::new(false);

fn is_init_ok() -> bool {
    #[cfg(feature = "smp")]
    {
        SECONDARY_START_COMPLETE.load(Ordering::Acquire)
            && INITED_CPUS.load(Ordering::Acquire)
                == BOOTED_CPU_MASK.load(Ordering::Acquire).count_ones() as usize
    }
    #[cfg(not(feature = "smp"))]
    {
        INITED_CPUS.load(Ordering::Acquire) == 1
    }
}

/// The main entry point of the ArceOS runtime.
///
/// It is called from the bootstrapping code in the specific platform crate (see
/// [`axplat::main`]).
///
/// `cpu_id` is the logic ID of the current CPU, and `arg` is passed from the
/// bootloader (typically the device tree blob address).
///
/// In multi-core environment, this function is called on the primary core, and
/// secondary cores call [`rust_main_secondary`].
#[cfg_attr(not(test), axplat::main)]
pub fn rust_main(cpu_id: usize, arg: usize) -> ! {
    unsafe { hal::mem::clear_bss() };
    hal::init_percpu(cpu_id);
    #[cfg(feature = "alloc")]
    kernel_alloc::init_percpu_slab(cpu_id);
    #[cfg(feature = "smp")]
    BOOTED_CPU_MASK.store(1usize << cpu_id, Ordering::Release);
    hal::init_early(cpu_id, arg);

    ax_println!("{}", LOGO);
    ax_println!(
        "\
        arch = {}\n\
        platform = {}\n\
        target = {}\n\
        build_mode = {}\n\
        log_level = {}\n\
        ",
        config::ARCH,
        config::PLATFORM,
        option_env!("AX_TARGET").unwrap_or(""),
        option_env!("AX_MODE").unwrap_or(""),
        option_env!("AX_LOG").unwrap_or(""),
    );
    #[cfg(feature = "rtc")]
    ax_println!(
        "Boot at {}\n",
        chrono::DateTime::from_timestamp_nanos(hal::time::wall_time_nanos() as _),
    );

    kernel_log::init();
    kernel_log::set_max_level(option_env!("AX_LOG").unwrap_or("")); // no effect if set `log-level-*` features
    info!("Logging is enabled.");
    info!("Primary CPU {} started, arg = {:#x}.", cpu_id, arg);

    hal::mem::init();
    info!("Found physcial memory regions:");
    for r in hal::mem::memory_regions() {
        info!(
            "  [{:x?}, {:x?}) {} ({:?})",
            r.paddr,
            r.paddr + r.size,
            r.name,
            r.flags
        );
    }

    #[cfg(feature = "alloc")]
    init_allocator();

    #[cfg(feature = "paging")]
    axmm::init_memory_management();

    info!("Initialize platform devices...");
    hal::init_later(cpu_id, arg);

    #[cfg(feature = "multitask")]
    task::init_scheduler();

    #[cfg(feature = "ipi")]
    {
        ipi::init();
        ipi::mark_current_cpu_ready();
    }

    #[cfg(feature = "irq")]
    {
        info!("Initialize interrupt handlers...");
        init_interrupt();
    }

    hal::mark_cpu_online(cpu_id);

    #[cfg(any(feature = "fs", feature = "net", feature = "display"))]
    {
        #[allow(unused_variables)]
        let all_devices = axdriver::init_drivers();

        #[cfg(feature = "fs")]
        axfs::init_filesystems(all_devices.block);

        #[cfg(feature = "net")]
        axnet::init_network(all_devices.net);

        #[cfg(feature = "display")]
        axdisplay::init_display(all_devices.display);
    }

    #[cfg(feature = "smp")]
    self::mp::start_secondary_cpus(cpu_id);

    #[cfg(feature = "irq")]
    hal::asm::enable_irqs();

    #[cfg(all(feature = "tls", not(feature = "multitask")))]
    {
        info!("Initialize thread local storage...");
        init_tls();
    }

    ctor_bare::call_ctors();

    // Keep constructors' original IRQ-enabled environment. After they return,
    // the primary CPU can validate global allocator accounting while secondary
    // CPUs have initialized their caches/schedulers but still spin IRQ-off in
    // rust_main_secondary(). None can enter its idle/GC loop until our release.
    #[cfg(feature = "pcp-boot-checks")]
    let pcp_boot_guard = {
        let guard = kernel_guard::NoPreemptIrqSave::new();
        assert!(!hal::asm::irqs_enabled(), "PCP boot checks require local IRQ exclusion");
        #[cfg(feature = "smp")]
        while INITED_CPUS.load(Ordering::Acquire) + 1
            != BOOTED_CPU_MASK.load(Ordering::Acquire).count_ones() as usize
        {
            core::hint::spin_loop();
        }
        kernel_alloc::run_pcp_guest_checks().expect("pcp guest checks failed");
        guard
    };

    info!("Primary CPU {} init OK.", cpu_id);
    INITED_CPUS.fetch_add(1, Ordering::Release);
    // Do not expose a primary-CPU preemption window between the checks and
    // publishing the barrier that releases the initialized secondary CPUs.
    #[cfg(feature = "pcp-boot-checks")]
    drop(pcp_boot_guard);

    while !is_init_ok() {
        core::hint::spin_loop();
    }

    #[cfg(feature = "smp")]
    while hal::online_cpu_count() != BOOTED_CPU_MASK.load(Ordering::Acquire).count_ones() as usize
    {
        core::hint::spin_loop();
    }

    #[cfg(feature = "ipi")]
    {
        ipi::wait_for_all_cpus_ready();
    }

    unsafe { main() };

    #[cfg(feature = "multitask")]
    task::exit(0);
    #[cfg(not(feature = "multitask"))]
    {
        debug!("main task exited: exit_code={}", 0);
        hal::power::system_off();
    }
}

#[cfg(feature = "alloc")]
fn init_allocator() {
    use hal::mem::{MemRegionFlags, memory_regions, phys_to_virt};

    info!("Initialize global memory allocator...");
    info!("  use {} allocator.", kernel_alloc::global_allocator().name());

    let mut max_region_size = 0;
    let mut max_region_paddr = 0.into();
    for r in memory_regions() {
        if r.flags.contains(MemRegionFlags::FREE) && r.size > max_region_size {
            max_region_size = r.size;
            max_region_paddr = r.paddr;
        }
    }
    for r in memory_regions() {
        if r.flags.contains(MemRegionFlags::FREE) && r.paddr == max_region_paddr {
            kernel_alloc::global_init(phys_to_virt(r.paddr).as_usize(), r.size);
        }
    }
    for r in memory_regions() {
        if r.flags.contains(MemRegionFlags::FREE) && r.paddr != max_region_paddr {
            kernel_alloc::global_add_memory(phys_to_virt(r.paddr).as_usize(), r.size)
                .expect("add heap memory region failed");
        }
    }
}

#[cfg(feature = "irq")]
fn init_interrupt() {
    // Setup timer interrupt handler
    #[cfg(not(feature = "multitask"))]
    const PERIODIC_INTERVAL_NANOS: u64 =
        hal::time::NANOS_PER_SEC / config::TICKS_PER_SEC as u64;

    #[cfg(not(feature = "multitask"))]
    #[percpu::def_percpu]
    static NEXT_DEADLINE: u64 = 0;

    #[cfg(not(feature = "multitask"))]
    fn update_timer() {
        let now_ns = hal::time::monotonic_time_nanos();
        // Safety: we have disabled preemption in IRQ handler.
        let mut deadline = unsafe { NEXT_DEADLINE.read_current_raw() };
        if now_ns >= deadline {
            deadline = now_ns + PERIODIC_INTERVAL_NANOS;
        }
        unsafe { NEXT_DEADLINE.write_current_raw(deadline) };
        hal::time::set_oneshot_timer(deadline);
    }

    hal::irq::register(config::devices::TIMER_IRQ, |_irq| {
        #[cfg(feature = "ipi")]
        ipi::service_tlb_shootdown();
        #[cfg(not(feature = "multitask"))]
        update_timer();
        crate::vdso::update_vdso_data();
        #[cfg(feature = "multitask")]
        task::on_timer_tick();
    });

    #[cfg(feature = "ipi")]
    hal::irq::register(hal::irq::IPI_IRQ, |_irq| {
        ipi::ipi_handler();
    });

}

#[cfg(all(feature = "tls", not(feature = "multitask")))]
fn init_tls() {
    let main_tls = hal::tls::TlsArea::alloc();
    unsafe { hal::asm::write_thread_pointer(main_tls.tls_ptr() as usize) };
    core::mem::forget(main_tls);
}
