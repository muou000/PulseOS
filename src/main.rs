#![no_std]
#![no_main]

#[macro_use]
extern crate axlog;
extern crate alloc;
extern crate axruntime;
extern crate pulse_core;
extern crate pulse_syscalls;

#[unsafe(no_mangle)]
fn main() {
    use axtask::TaskInner;
    #[cfg(feature = "auto-testcode")]
    const AUTO_TESTCODE_CMD: &str = "for t in /fs/*_testcode.sh; do if [ -f \"$t\" ]; then echo \"[auto-testcode] running $t\"; sh \"$t\"; fi; done";

    match pulse_core::task::Process::new_uspace() {
        Ok(proc) => {
            info!("Created initial user process");
            let mut inner = TaskInner::new(
                || {
                    use axtask::TaskExtRef;
                    let binding = axtask::current();
                    let proc: &pulse_core::task::Process = binding.task_ext();
                    proc.activate();
                    info!("User process address space activated");

                    #[cfg(feature = "auto-testcode")]
                    let shell_args = ["/bin/sh", "-c", AUTO_TESTCODE_CMD];
                    #[cfg(not(feature = "auto-testcode"))]
                    let shell_args: [&str; 0] = [];

                    match proc.load_elf("/bin/sh", &shell_args, &[]) {
                        Ok(_) => {
                            info!("Successfully loaded /bin/sh");
                            info!("Jumping to user mode...");
                            proc.enter_user_mode();
                        }
                        Err(e) => {
                            error!("Failed to load /bin/sh: {:?}", e);
                        }
                    }
                },
                "pulse_init".into(),
                0x8000,
            );

            let pt_root = proc.aspace.lock().page_table_root();
            inner.ctx_mut().set_page_table_root(pt_root);

            inner.init_task_ext(proc);
            let init_task = axtask::spawn_task(inner);

            #[cfg(feature = "auto-testcode")]
            loop {
                if let Some(exit_code) = init_task.try_join() {
                    info!(
                        "Auto testcode run finished, init task exited with code: {}",
                        exit_code
                    );
                    arceos_api::sys::ax_terminate();
                }
                axtask::yield_now();
            }
        }
        Err(e) => {
            error!("Failed to create user process: {:?}", e);
        }
    }
}
