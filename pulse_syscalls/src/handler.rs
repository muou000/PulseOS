use axhal::{
    context::TrapFrame,
    trap::{SYSCALL, register_trap_handler},
};

use crate::*;

#[register_trap_handler(SYSCALL)]
pub fn syscall_handler(tf: &TrapFrame, syscall_num: usize) -> isize {
    let syscall_enter_ns = axhal::time::monotonic_time_nanos() as u64;
    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(_) => {
            let task = axtask::current();
            let task_ext_ptr = unsafe { task.task_ext_ptr() };
            axlog::error!(
                "syscall without Thread context: syscall={}, task={} {:?}, task_ext_ptr={:p}",
                syscall_num,
                task.id().as_u64(),
                task.name(),
                task_ext_ptr
            );
            return -LinuxError::ENOSYS.code() as isize;
        }
    };
    let process = thread.process_arc();
    process.on_kernel_entry_from_user(syscall_enter_ns);
    if process.group_exiting() {
        thread.exit_current(process.group_exit_code());
    }

    let args = [tf.arg0(), tf.arg1(), tf.arg2(), tf.arg3(), tf.arg4(), tf.arg5()];

    axlog::debug!(
        "Syscall: id={}, args=[{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
        syscall_num,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5]
    );
    let ret = syscall_dispatcher(tf, syscall_num, args, process.as_ref());

    let syscall_leave_ns = axhal::time::monotonic_time_nanos() as u64;
    let delta_ns = syscall_leave_ns.saturating_sub(syscall_enter_ns);
    process.add_sys_time_ns(delta_ns);
    if process.group_exiting() {
        thread.exit_current(process.group_exit_code());
    }
    process.mark_user_resume();

    ret
}

fn syscall_dispatcher(
    tf: &TrapFrame,
    syscall_id: usize,
    args: [usize; 6],
    process: &pulse_core::task::Process,
) -> isize {
    process.sync_fs_context();

    let sysno = match Sysno::new(syscall_id) {
        Some(sysno) => sysno,
        None => {
            axlog::warn!("Unknown syscall: {}", syscall_id);
            return -LinuxError::ENOSYS.code() as isize;
        }
    };

    match sysno {
        Sysno::getpid => impls::sys_getpid(),
        Sysno::exit => {
            impls::sys_exit(args[0] as i32);
        }
        Sysno::exit_group => {
            impls::sys_exit_group(args[0] as i32);
        }
        Sysno::clone => impls::sys_clone(tf, args),
        Sysno::wait4 => impls::sys_wait4(args[0] as isize, args[1], args[2] as i32, args[3]),
        Sysno::sched_yield => impls::sys_yield(),
        Sysno::sched_getaffinity => impls::sys_sched_getaffinity(args[0], args[1], args[2]),
        Sysno::sched_setaffinity => impls::sys_sched_setaffinity(args[0], args[1], args[2]),
        Sysno::sched_getscheduler => impls::sys_sched_getscheduler(args[0]),
        Sysno::sched_setscheduler => impls::sys_sched_setscheduler(args[0], args[1], args[2]),
        Sysno::sched_getparam => impls::sys_sched_getparam(args[0], args[1]),

        Sysno::read => impls::sys_read(args[0], args[1], args[2]),
        Sysno::readv => impls::sys_readv(args[0], args[1], args[2]),
        Sysno::write => impls::sys_write(args[0], args[1], args[2]),
        Sysno::writev => impls::sys_writev(args[0], args[1], args[2]),
        Sysno::sendfile => impls::sys_sendfile(args[0], args[1], args[2], args[3]),
        Sysno::openat => impls::sys_openat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::mkdirat => impls::sys_mkdirat(args[0] as i32, args[1], args[2]),
        Sysno::mount => impls::sys_mount(args[0], args[1], args[2], args[3], args[4]),
        Sysno::umount2 => impls::sys_umount2(args[0], args[1]),
        Sysno::getdents64 => impls::sys_getdents64(args[0], args[1], args[2]),
        Sysno::close => impls::sys_close(args[0]),
        Sysno::fstat => impls::sys_fstat(args[0], args[1]),
        Sysno::statfs => impls::sys_statfs(args[0], args[1]),
        Sysno::fstatfs => impls::sys_fstatfs(args[0], args[1]),
        #[cfg(target_arch = "loongarch64")]
        Sysno::fstatat => impls::sys_fstatat(args[0] as i32, args[1], args[2], args[3]),
        #[cfg(target_arch = "riscv64")]
        Sysno::newfstatat => impls::sys_fstatat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::statx => impls::sys_statx(args[0] as i32, args[1], args[2], args[3], args[4]),

        Sysno::brk => impls::sys_brk(args[0]),
        Sysno::mmap => impls::sys_mmap(args[0], args[1], args[2], args[3], args[4] as i32, args[5]),
        Sysno::munmap => impls::sys_munmap(args[0], args[1]),
        Sysno::mprotect => impls::sys_mprotect(args[0], args[1], args[2]),
        Sysno::mlock => impls::sys_mlock(args[0], args[1]),
        Sysno::munlock => impls::sys_munlock(args[0], args[1]),
        Sysno::mlockall => impls::sys_mlockall(args[0]),
        Sysno::munlockall => impls::sys_munlockall(),

        Sysno::nanosleep => impls::sys_nanosleep(args[0], args[1]),
        Sysno::clock_nanosleep => {
            impls::sys_clock_nanosleep(args[0] as i32, args[1], args[2], args[3])
        }
        Sysno::clock_getres => impls::sys_clock_getres(args[0] as i32, args[1]),
        Sysno::clock_gettime => impls::sys_clock_gettime(args[0] as i32, args[1]),
        Sysno::gettimeofday => impls::sys_gettimeofday(args[0], args[1]),
        Sysno::times => impls::sys_times(args[0]),
        Sysno::prlimit64 => impls::sys_prlimit64(args[0] as i32, args[1], args[2], args[3]),
        Sysno::getrandom => impls::sys_getrandom(args[0], args[1], args[2]),

        Sysno::set_tid_address => impls::sys_set_tid_address(args[0]),
        Sysno::gettid => impls::sys_gettid(),
        Sysno::futex => {
            impls::sys_futex(args[0], args[1] as i32, args[2], args[3], args[4], args[5])
        }

        Sysno::uname => impls::sys_uname(args[0]),
        Sysno::sysinfo => impls::sys_sysinfo(args[0]),
        Sysno::syslog => impls::sys_syslog(args[0], args[1], args[2]),
        Sysno::rt_sigprocmask => impls::sys_rt_sigprocmask(args[0], args[1], args[2], args[3]),
        Sysno::get_mempolicy => 0,

        Sysno::getuid => impls::sys_getuid(),
        Sysno::geteuid => impls::sys_geteuid(),
        Sysno::umask => impls::sys_umask(args[0]),
        Sysno::getppid => impls::sys_getppid(),
        Sysno::getpgid => {
            axlog::warn!("sys_getpgid (stub): return 1");
            1
        }
        Sysno::setpgid => impls::sys_setpgid(args[0] as isize, args[1] as isize),
        Sysno::kill => impls::sys_kill(args[0] as isize, args[1] as isize),
        Sysno::getgid => impls::sys_getgid(),
        Sysno::getegid => impls::sys_getegid(),
        Sysno::setuid => impls::sys_setuid(args[0]),
        Sysno::setgid => impls::sys_setgid(args[0]),
        Sysno::setreuid => impls::sys_setreuid(args[0], args[1]),
        Sysno::setregid => impls::sys_setregid(args[0], args[1]),

        Sysno::rt_sigaction => impls::sys_rt_sigaction(args[0], args[1], args[2], args[3]),
        Sysno::rt_sigreturn => impls::sys_rt_sigreturn(),

        Sysno::ioctl => impls::sys_ioctl(args[0], args[1], args[2]),
        Sysno::fcntl => impls::sys_fcntl(args[0], args[1], args[2]),
        Sysno::dup => impls::sys_dup(args[0]),
        Sysno::dup3 => impls::sys_dup3(args[0], args[1], args[2]),
        Sysno::pipe2 => impls::sys_pipe2(args[0], args[1]),
        Sysno::socketpair => {
            impls::sys_socketpair(args[0] as u32, args[1] as u32, args[2] as u32, args[3])
        }
        Sysno::ppoll => impls::sys_ppoll(args[0], args[1], args[2], args[3], args[4]),
        Sysno::getcwd => impls::sys_getcwd(args[0], args[1]),
        Sysno::chdir => impls::sys_chdir(args[0]),
        Sysno::unlinkat => impls::sys_unlinkat(args[0] as i32, args[1], args[2]),
        #[cfg(target_arch = "loongarch64")]
        Sysno::renameat => {
            impls::sys_renameat2(args[0] as i32, args[1], args[2] as i32, args[3], 0)
        }
        Sysno::renameat2 => {
            impls::sys_renameat2(args[0] as i32, args[1], args[2] as i32, args[3], args[4])
        }
        Sysno::utimensat => impls::sys_utimensat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::readlinkat => impls::sys_readlinkat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::set_robust_list => impls::sys_set_robust_list(args[0], args[1]),
        Sysno::get_robust_list => impls::sys_get_robust_list(args[0], args[1], args[2]),
        Sysno::faccessat => impls::sys_faccessat(args[0] as i32, args[1], args[2], 0),
        Sysno::faccessat2 => impls::sys_faccessat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::lseek => impls::sys_lseek(args[0], args[1], args[2]),
        Sysno::ftruncate => impls::sys_ftruncate(args[0], args[1]),
        Sysno::execve => {
            axlog::debug!(
                "sys_execve: pathname={:#x}, argv={:#x}, envp={:#x}",
                args[0],
                args[1],
                args[2]
            );
            impls::sys_execve(tf, args[0], args[1], args[2])
        }

        _ => {
            axlog::warn!("Unimplemented syscall: {:?} ({})", sysno, syscall_id);
            -LinuxError::ENOSYS.code() as isize
        }
    }
}
