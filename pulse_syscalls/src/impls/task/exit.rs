use pulse_core::task::current_thread;

pub fn sys_exit(exit_code: i32) -> ! {
    axlog::debug!("sys_exit: exit_code={}", exit_code);
    axlog::info!("Task exit with code: {}", exit_code);
    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => panic!("sys_exit without thread: {:?}", e),
    };
    thread.exit_current(exit_code);
}

pub fn sys_exit_group(exit_code: i32) -> ! {
    axlog::debug!("sys_exit_group: exit_code={}", exit_code);
    axlog::info!("Task group exit with code: {}", exit_code);
    let thread = match current_thread() {
        Ok(thread) => thread,
        Err(e) => panic!("sys_exit_group without thread: {:?}", e),
    };
    thread.process().begin_group_exit(exit_code);
    thread.exit_current(exit_code);
}

pub fn sys_yield() -> isize {
    axtask::yield_now();
    0
}
