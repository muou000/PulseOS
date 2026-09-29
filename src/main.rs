#![no_std]
#![no_main]

#[macro_use]
extern crate axlog;
extern crate alloc;
extern crate axhal;
#[cfg(all(target_arch = "loongarch64", feature = "ls2k1000"))]
extern crate axplat_loongarch64_ls2k1000;
#[cfg(all(target_arch = "riscv64", feature = "visionfive2"))]
extern crate axplat_riscv64_visionfive2;
extern crate axruntime;
extern crate pulse_core;
extern crate pulse_syscalls;
extern crate starry_vdso;

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
            axtask::yield_now();
        }
    }
    axhal::power::system_off()
}

#[unsafe(no_mangle)]
fn main() {
    starry_vdso::vdso::init_vdso_data();
    axruntime::vdso::set_update_hook(starry_vdso::vdso::update_vdso_data);

    pulse_core::task::init_itimer_hook();
    info!("itimer hook registered");

    pulse_core::task::init_procfs_provider();
    info!("procfs provider registered");

    pulse_core::fd_table::init_tty_callbacks();
    info!("TTY callbacks registered");

    pulse_core::trap::init();

    const SHELL_ELF_PATH: &str = "/bin/sh";

    use axtask::TaskInner;

    let inner = TaskInner::new(
        || {
            let thread =
                pulse_core::task::current_thread().expect("init task entered without Thread");
            let proc = thread.process();

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
    );

    let init_tid = inner.id().as_u64();
    match pulse_core::task::Process::new_uspace(init_tid) {
        Ok(proc) => {
            let init_thread = pulse_core::task::Thread::new(proc.clone(), init_tid);
            pulse_core::task::register_thread_global(init_tid, init_thread.clone());
            info!("Created initial user process");

            let init_task = pulse_core::task::spawn_task_with_thread(inner, init_thread.clone(), true);
            loop {
                axtask::yield_now();
            }
        }
        Err(e) => {
            error!("Failed to create user process: {:?}", e);
            loop {
                axtask::yield_now();
            }
        }
    }
}
