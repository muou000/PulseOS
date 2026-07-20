#![no_std]
#![no_main]

#[macro_use]
extern crate axlog;
extern crate alloc;
extern crate axhal;
extern crate axruntime;
extern crate pulse_core;
extern crate pulse_syscalls;
extern crate starry_vdso;

use alloc::vec::Vec;
use pulse_core::task::exec::resolve_exec_path_and_args;

#[unsafe(no_mangle)]
fn main() {
    starry_vdso::vdso::init_vdso_data();
    axruntime::vdso::set_update_hook(starry_vdso::vdso::update_vdso_data);

    pulse_core::task::init_itimer_hook();
    info!("itimer hook registered");

    if cfg!(feature = "testcode") {
        pulse_core::task::set_stdin_polling_enabled(false);
        info!("testcode feature active: stdin polling disabled");
    }

    pulse_core::task::init_procfs_provider();
    info!("procfs provider registered");

    pulse_core::fd_table::init_tty_callbacks();
    info!("TTY callbacks registered");

    pulse_core::trap::init();

    const SHELL_ELF_PATH: &str = "/bin/sh";

    use axtask::TaskInner;

    let mut inner = TaskInner::new(
        || {
            let thread =
                pulse_core::task::current_thread().expect("init task entered without Thread");
            let proc = thread.process();

            let shell_args_base: &[&str] = if cfg!(feature = "testcode") {
                &["sh", "/testcode.sh"]
            } else {
                &["sh"]
            };
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

            let pt_root = init_thread.process().page_table_root();
            let asid = init_thread.process().asid();
            inner.ctx_mut().set_page_table_root(pt_root, asid);

            init_thread.process().sync_fs_context();

            let init_proc = init_thread.process_arc();
            pulse_core::task::register_process(init_proc.pid(), init_proc.clone());
            inner.init_task_ext(pulse_core::task::ThreadHandle::new(init_thread.clone()));
            let init_task = axtask::spawn_task(inner);
            init_thread.process().register_task_ref(init_task.clone());

            if cfg!(feature = "testcode") {
                match init_task.join() {
                    Some(0) => info!("Init task exited normally"),
                    Some(exit_code) => error!("Init task exited with failure code {}", exit_code),
                    None => error!("Init task join returned no exit code"),
                }
                pulse_core::task::unregister_thread_global(init_tid);
                let _ = init_thread.process().take_task_ref_by_tid(init_tid);
                init_thread.process().release_task_refs();

                pulse_syscalls::sys_sync();
                axhal::power::system_off();
            } else {
                loop {
                    axtask::yield_now();
                }
            }
        }
        Err(e) => {
            error!("Failed to create user process: {:?}", e);
            if cfg!(feature = "testcode") {
                pulse_syscalls::sys_sync();
                axhal::power::system_off();
            } else {
                loop {
                    axtask::yield_now();
                }
            }
        }
    }
}
