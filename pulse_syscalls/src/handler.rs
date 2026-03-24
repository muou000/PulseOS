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
    syscall_dispatcher(syscall_num, args)
}

fn syscall_dispatcher(syscall_id: usize, args: [usize; 6]) -> isize {
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
        Sysno::clone => impls::sys_clone(args),
        Sysno::sched_yield => impls::sys_yield(),

        Sysno::read => impls::sys_read(args[0], args[1], args[2]),
        Sysno::write => impls::sys_write(args[0], args[1], args[2]),
        Sysno::writev => impls::sys_writev(args[0], args[1], args[2]),
        Sysno::openat => impls::sys_openat(args[0] as i32, args[1], args[2], args[3]),
        Sysno::close => impls::sys_close(args[0]),
        Sysno::fstat => impls::sys_fstat(args[0], args[1]),
        Sysno::fstatat => {
            // newfstatat(dirfd, pathname, statbuf, flags)
            // 简化实现：如果 pathname 是绝对路径，忽略 dirfd
            // TODO: 完整实现需要支持相对路径
            axlog::debug!(
                "sys_newfstatat: dirfd={}, pathname={:#x}, statbuf={:#x}, flags={:#x}",
                args[0],
                args[1],
                args[2],
                args[3]
            );
            -LinuxError::ENOSYS.code() as isize
        }

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

        Sysno::set_tid_address => {
            axlog::debug!("sys_set_tid_address: tidptr={:#x}", args[0]);
            1 // 返回一个假的 TID
        }
        Sysno::gettid => 1, // 返回当前线程 ID

        Sysno::uname => impls::sys_uname(args[0]),
        Sysno::getrandom => {
            axlog::debug!("sys_getrandom: buf={:#x}, len={}", args[0], args[1]);
            // 简单实现：填充零
            if args[0] != 0 && args[1] > 0 {
                let slice = unsafe { core::slice::from_raw_parts_mut(args[0] as *mut u8, args[1]) };
                slice.fill(0x42); // 填充一个固定值
                args[1] as isize
            } else {
                0
            }
        }
        Sysno::prlimit64 => {
            axlog::debug!("sys_prlimit64 (stub)");
            0 // 暂时返回成功
        }
        Sysno::rt_sigprocmask => {
            axlog::debug!("sys_rt_sigprocmask (stub)");
            0 // 信号相关，暂时忽略
        }

        Sysno::getuid | Sysno::geteuid => 0, // root
        Sysno::getgid | Sysno::getegid => 0, // root
        Sysno::setuid | Sysno::setgid | Sysno::setreuid | Sysno::setregid => 0,

        Sysno::rt_sigaction => {
            axlog::debug!("sys_rt_sigaction (stub)");
            0
        }
        Sysno::rt_sigreturn => {
            axlog::debug!("sys_rt_sigreturn (stub)");
            0
        }

        Sysno::ioctl => {
            axlog::debug!("sys_ioctl: fd={}, cmd={:#x} (stub)", args[0], args[1]);
            0
        }
        Sysno::fcntl => {
            axlog::debug!("sys_fcntl: fd={}, cmd={} (stub)", args[0], args[1]);
            0
        }
        Sysno::dup => {
            axlog::debug!("sys_dup: fd={} (stub)", args[0]);
            args[0] as isize // 简单返回同一个 fd
        }
        Sysno::dup3 => {
            axlog::debug!("sys_dup3: oldfd={}, newfd={} (stub)", args[0], args[1]);
            args[1] as isize
        }
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
        Sysno::getcwd => {
            axlog::debug!("sys_getcwd: buf={:#x}, size={}", args[0], args[1]);
            if args[0] != 0 && args[1] > 1 {
                let buf = unsafe { core::slice::from_raw_parts_mut(args[0] as *mut u8, args[1]) };
                buf[0] = b'/';
                buf[1] = 0;
                args[0] as isize
            } else {
                -LinuxError::EINVAL.code() as isize
            }
        }
        Sysno::chdir => {
            axlog::debug!("sys_chdir (stub)");
            0
        }
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
        Sysno::lseek => {
            axlog::debug!(
                "sys_lseek: fd={}, offset={}, whence={} (stub)",
                args[0],
                args[1] as isize,
                args[2]
            );
            0
        }

        _ => {
            axlog::warn!("Unimplemented syscall: {:?} ({})", sysno, syscall_id);
            -LinuxError::ENOSYS.code() as isize
        }
    }
}
