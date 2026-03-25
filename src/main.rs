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
    // 创建第一个用户进程
    use alloc::sync::Arc;
    match pulse_core::task::Process::new_user() {
        Ok(proc) => {
            info!("Created initial user process");

            // 设置为当前进程
            let proc = Arc::new(proc);
            pulse_core::task::set_current_process(proc.clone());

            // 激活其地址空间
            proc.activate();
            info!("User process address space activated");

            // 加载 /bin/busybox sh 启动 shell
            // TODO：检查软链接支持情况并修改为加载/bin/sh
            match proc.load_elf("/bin/busybox", &["sh"]) {
                Ok(_) => {
                    info!("Successfully loaded /bin/busybox");
                    info!("Jumping to user mode...");

                    // 跳转到用户态执行
                    proc.enter_user_mode();
                }
                Err(e) => {
                    error!("Failed to load /bin/busybox: {:?}", e);
                }
            }
        }
        Err(e) => {
            error!("Failed to create user process: {:?}", e);
        }
    }

    info!("MyOS is ready and running!");
    info!("Entering idle loop...");

    // 主循环
    loop {
        core::hint::spin_loop();
    }
}
