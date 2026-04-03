use crate::*;
use axhal::context::TrapFrame;
use axhal::trap::{SYSCALL, register_trap_handler};

#[register_trap_handler(SYSCALL)]
pub fn syscall_handler(tf: &TrapFrame, syscall_num: usize) -> isize {
    let args = [
        tf.arg0(),
        tf.arg1(),
        tf.arg2(),
        tf.arg3(),
        tf.arg4(),
        tf.arg5(),
    ];

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
    syscall_dispatcher(tf, syscall_num, args)
}

fn syscall_dispatcher(tf: &TrapFrame, syscall_id: usize, args: [usize; 6]) -> isize {
    let sysno = match Sysno::new(syscall_id) {
        Some(sysno) => sysno,
        None => {
            axlog::warn!("Unknown syscall: {}", syscall_id);
            return -LinuxError::ENOSYS.code() as isize;
        }
    };

    match sysno {
        Sysno::getpid => impls::sys_getpid(),
        Sysno::exit | Sysno::exit_group => {
            impls::sys_exit(args[0] as i32);
        }
        Sysno::clone => impls::sys_clone(tf, args),
        Sysno::wait4 => impls::sys_wait4(args[0] as isize, args[1], args[2] as i32, args[3]),
        Sysno::sched_yield => impls::sys_yield(),

        Sysno::read => impls::sys_read(args[0], args[1], args[2]),
        Sysno::write => impls::sys_write(args[0], args[1], args[2]),
        Sysno::writev => impls::sys_writev(args[0], args[1], args[2]),
        Sysno::openat => impls::sys_openat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::getdents64 => impls::sys_getdents64(args[0], args[1], args[2]),
        Sysno::close => impls::sys_close(args[0]),
        Sysno::fstat => impls::sys_fstat(args[0], args[1]),
        Sysno::fstatat => impls::sys_fstatat(args[0] as i32, args[1], args[2], args[3]),
        #[cfg(target_arch = "loongarch64")]
        Sysno::statx => impls::sys_statx(args[0] as i32, args[1], args[2], args[3], args[4]),

        Sysno::brk => impls::sys_brk(args[0]),
        Sysno::mmap => impls::sys_mmap(args[0], args[1], args[2], args[3], args[4] as i32, args[5]),
        Sysno::munmap => impls::sys_munmap(args[0], args[1]),
        Sysno::mprotect => {
            axlog::debug!(
                "sys_mprotect: addr={:#x}, len={:#x}, prot={:#x}",
                args[0],
                args[1],
                args[2]
            );
            0 // 暂时忽略保护属性变更
        }

        Sysno::nanosleep => impls::sys_nanosleep(args[0], args[1]),
        Sysno::clock_gettime => impls::sys_clock_gettime(args[0] as i32, args[1]),
        Sysno::gettimeofday => impls::sys_gettimeofday(args[0], args[1]),

        Sysno::set_tid_address => impls::sys_set_tid_address(args[0]),
        Sysno::gettid => impls::sys_gettid(),

        Sysno::uname => impls::sys_uname(args[0]),
        Sysno::getrandom => impls::sys_getrandom(args[0], args[1], args[2]),
        Sysno::prlimit64 => impls::sys_prlimit64(args[0], args[1], args[2], args[3]),
        Sysno::rt_sigprocmask => impls::sys_rt_sigprocmask(args[0], args[1], args[2], args[3]),

        Sysno::getuid | Sysno::geteuid | Sysno::getppid => 0,
        Sysno::getpgid => 1,
        Sysno::setpgid => impls::sys_setpgid(args[0] as isize, args[1] as isize),
        Sysno::kill => 0,
        Sysno::getgid | Sysno::getegid => 0, // root
        Sysno::setuid | Sysno::setgid | Sysno::setreuid | Sysno::setregid => 0,

        Sysno::rt_sigaction => impls::sys_rt_sigaction(args[0], args[1], args[2], args[3]),
        Sysno::rt_sigreturn => impls::sys_rt_sigreturn(),

        Sysno::ioctl => impls::sys_ioctl(args[0], args[1], args[2]),
        Sysno::fcntl => impls::sys_fcntl(args[0], args[1], args[2]),
        Sysno::dup => impls::sys_dup(args[0]),
        Sysno::dup3 => impls::sys_dup3(args[0], args[1], args[2]),
        Sysno::pipe2 => {
            axlog::debug!("sys_pipe2 (stub)");
            -LinuxError::ENOSYS.code() as isize
        }
        Sysno::ppoll => {
            // ppoll(fds, nfds, timeout, sigmask)
            // 简化实现：如果有 fd=0 (stdin)，等通过 yield 让出直到有输入
            axlog::debug!("sys_ppoll: nfds={}, timeout={:#x}", args[1], args[2]);
            // 返回 1 表示有 1 个 fd 就绪（简化处理）
            1
        }
        Sysno::getcwd => impls::sys_getcwd(args[0], args[1]),
        Sysno::chdir => impls::sys_chdir(args[0]),
        Sysno::set_robust_list => {
            axlog::debug!("sys_set_robust_list (stub)");
            0
        }
        Sysno::readlinkat => {
            axlog::debug!("sys_readlinkat (stub)");
            -LinuxError::EINVAL.code() as isize
        }
        Sysno::faccessat => {
            axlog::debug!("sys_faccessat (stub)");
            -LinuxError::ENOENT.code() as isize
        }
        Sysno::lseek => impls::sys_lseek(args[0], args[1], args[2]),
        Sysno::execve => {
            axlog::debug!(
                "sys_execve: pathname={:#x}, argv={:#x}, envp={:#x}",
                args[0],
                args[1],
                args[2]
            );
            impls::sys_execve(args[0], args[1], args[2])
        }

        _ => {
            axlog::warn!("Unimplemented syscall: {:?} ({})", sysno, syscall_id);
            -LinuxError::ENOSYS.code() as isize
        }
    }
}
