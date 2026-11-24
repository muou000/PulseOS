#![no_std]
#![no_main]

#[macro_use]
extern crate kernel_log;
extern crate alloc;
extern crate hal;
#[cfg(all(target_arch = "loongarch64", feature = "ls2k1000"))]
extern crate axplat_loongarch64_ls2k1000;
#[cfg(all(target_arch = "riscv64", feature = "visionfive2"))]
extern crate axplat_riscv64_visionfive2;
extern crate runtime;
extern crate net;
extern crate sync;
extern crate pulse_core;
extern crate pulse_syscalls;
extern crate starry_vdso;

mod cpu_reservation;

use alloc::vec::Vec;
use pulse_core::task::exec::resolve_exec_path_and_args;

/// The test-runner exit path bypasses `reboot(2)`, so it must uphold the same
/// durability rule itself: never hand control to firmware after a failed
/// global writeback checkpoint.
fn power_off_after_writeback() -> ! {
    let result = pulse_syscalls::sys_sync();
    if result != 0 {
        error!(
            "refusing test-runner power-off because filesystem writeback failed: {}",
            result
        );
        loop {
            task::yield_now();
        }
    }
    hal::power::system_off()
}

#[unsafe(no_mangle)]
fn main() {
    cpu_reservation::init();

    starry_vdso::vdso::init_vdso_data();
    runtime::vdso::set_update_hook(starry_vdso::vdso::update_vdso_data);

    pulse_core::task::init_itimer_hook();
    info!("itimer hook registered");

    pulse_core::task::init_procfs_provider();
    info!("procfs provider registered");

    pulse_core::fd_table::init_tty_callbacks();
    info!("TTY callbacks registered");

    pulse_core::trap::init();

    const SHELL_ELF_PATH: &str = "/bin/sh";

    let inner = pulse_core::task::try_new_user_task(
        || {
            let thread =
                pulse_core::task::current_thread().expect("init task entered without Thread");
            let proc = thread.process();

            #[cfg(feature = "mapping-lifecycle-test")]
            {
                pulse_core::mm::lifecycle_checks::run().expect("mapping lifecycle kernel checks failed");
                fs::run_mapping_lifecycle_checks().expect("mapping cache kernel checks failed");
                pulse_syscalls::run_mapping_shutdown_checks().expect("mapping shutdown kernel checks failed");
                info!("MLC_KERNEL RESULT PASS");
            }

            #[cfg(feature = "guest-checks")]
            {
                pulse_syscalls::run_bpf_guest_checks().expect("bpf guest checks failed");
                pulse_core::fd_table::run_pipe_guest_checks().expect("pipe guest checks failed");
                pulse_core::io_uring::run_io_uring_resource_guest_checks()
                    .expect("io_uring resource guest checks failed");
            }
            pulse_core::task::run_futex_guest_checks().expect("futex guest checks failed");
            pulse_core::task::run_process_registry_guest_checks().expect("process registry guest checks failed");
            fs::run_dma_and_writeback_guest_checks().expect("dma & writeback guest checks failed");
            net::run_tcp_endpoint_concurrency_checks().expect("tcp endpoint concurrency checks failed");
            sync::run_lock_stress_checks().expect("sync lock stress checks failed");

            // Start the sampling worker after isolated boot checks: its timer
            // wakeups/allocations must not race allocator accounting assertions
            // or the synthetic BPF model checks. It is ready before userspace.
            #[cfg(feature = "bpf-trace")]
            pulse_core::bpf::sampling::init();

            let shell_args_base: &[&str] = &["sh"];
            let shell_envs: &[&str] = &["PATH=/usr/sbin:/usr/bin:/sbin:/bin"];

            let fs_handle = proc.fs_context_handle();
            let fs_ctx = fs_handle.lock();
            match resolve_exec_path_and_args(&fs_ctx, SHELL_ELF_PATH, shell_args_base) {
                Ok((shell_path, shell_args)) => {
                    info!("Preparing to load shell: path={}, args={:?}", shell_path, shell_args);
                    let args_refs: Vec<&str> = shell_args.iter().map(|s| s.as_str()).collect();

                    core::mem::drop(fs_ctx);

                    match proc.load_elf(&shell_path, &args_refs, shell_envs) {
                        Ok(_) => {
                            info!("User process loaded successfully, activating address space...");
                            proc.activate();
                            info!("User space activated, entering uspace...");
                            proc.enter_user_mode();
                        }
                        Err(e) => {
                            error!("Failed to load shell ELF: {:?}", e);
                            thread.exit_current(1);
                        }
                    }
                }
                Err(e) => {
                    error!("Failed to resolve shell path: {:?}", e);
                    thread.exit_current(1);
                }
            }
        },
        "pulse_init".into(),
        0x8000,
    ).expect("allocate init task context");

    // Linux reserves PID/TID 1 for init. Kernel tasks have already consumed
    // scheduler IDs, which remain independent of this userspace identity.
    let init_tid = 1;
    match pulse_core::task::Process::new_uspace(init_tid) {
        Ok(proc) => {
            let init_thread = pulse_core::task::Thread::new(proc.clone(), init_tid, inner.id());
            pulse_core::task::register_thread_global(init_tid, init_thread.clone());
            info!("Created initial user process");

            let init_task = pulse_core::task::spawn_task_with_thread(inner, init_thread.clone(), true);
            loop {
                task::yield_now();
            }
        }
        Err(e) => {
            error!("Failed to create user process: {:?}", e);
            loop {
                task::yield_now();
            }
        }
    }
}
