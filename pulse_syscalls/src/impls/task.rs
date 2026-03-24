use crate::LinuxError;

pub fn sys_getpid() -> isize {
    axtask::current().id().as_u64() as isize
}

pub fn sys_exit(exit_code: i32) -> ! {
    axlog::info!("Task exit with code: {}", exit_code);
    axtask::exit(exit_code);
}

pub fn sys_yield() -> isize {
    axtask::yield_now();
    0
}

pub fn sys_clone(args: [usize; 6]) -> isize {
    let _flags = args[0];
    let _stack = args[1];
    let _parent_tid = args[2];
    let _tls = args[3];
    let _child_tid = args[4];

    axlog::warn!("sys_clone not fully implemented");
    -LinuxError::ENOSYS.code() as isize
}
