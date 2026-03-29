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

                    match proc.load_elf("/bin/busybox", &["sh"]) {
                        Ok(_) => {
                            info!("Successfully loaded /bin/busybox");
                            info!("Jumping to user mode...");
                            proc.enter_user_mode();
                        }
                        Err(e) => {
                            error!("Failed to load /bin/busybox: {:?}", e);
                        }
                    }
                },
                "pulse_init".into(),
                0x8000,
            );

            let pt_root = proc.aspace.lock().page_table_root();
            inner.ctx_mut().set_page_table_root(pt_root);

            inner.init_task_ext(proc);
            axtask::spawn_task(inner);
        }
        Err(e) => {
            error!("Failed to create user process: {:?}", e);
        }
    }

    info!("MyOS is ready and running!");
    info!("Entering idle loop...");

    loop {
        axtask::yield_now();
    }
}
