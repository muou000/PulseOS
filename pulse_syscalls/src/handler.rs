use axhal::{
    context::TrapFrame,
    trap::{SYSCALL, register_trap_handler},
};

use crate::*;

#[register_trap_handler(SYSCALL)]
pub fn syscall_handler(tf: &mut TrapFrame, syscall_num: usize) -> isize {
    let syscall_enter_ns = axhal::time::monotonic_time_nanos() as u64;
    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(_) => {
            let task = axtask::current();
            let task_ext_ptr = unsafe { task.task_ext_ptr() };
            panic!(
                "syscall without Thread context: syscall={}, task={} {:?}, task_ext_ptr={:p}",
                syscall_num,
                task.id().as_u64(),
                task.name(),
                task_ext_ptr
            );
        }
    };
    let process = thread.process_arc();
    process.on_kernel_entry_from_user(syscall_enter_ns);
    if process.group_exiting() {
        thread.exit_current(process.group_exit_code());
    }

    let args = [
        tf.arg0(),
        tf.arg1(),
        tf.arg2(),
        tf.arg3(),
        tf.arg4(),
        tf.arg5(),
    ];

    let exe = process.exec_path().unwrap_or_default();
    axlog::debug!(
        "Syscall: pid={} exe={} tid={} id={} args=[{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
        process.pid(),
        exe,
        axtask::current().id().as_u64(),
        syscall_num,
        args[0],
        args[1],
        args[2],
        args[3],
        args[4],
        args[5]
    );
    let ret = syscall_dispatcher(tf, syscall_num, args, process.as_ref());
    axlog::debug!(
        "Syscall ret: pid={} exe={} tid={} id={} ret={}",
        process.pid(),
        exe,
        axtask::current().id().as_u64(),
        syscall_num,
        ret
    );

    if ret == -(pulse_core::task::ERESTARTSYS as isize) {
        let sig_state = thread.signal();
        let mut should_restart = true;

        // Peek to see if the next signal handler has SA_RESTART set.
        if let Some(sig) = sig_state.peek_unblocked() {
            let action = pulse_core::task::resolve_action(&sig_state.shared(), sig);
            if let pulse_core::task::SignalAction::Handler(act) = action {
                if (act.flags & (linux_raw_sys::general::SA_RESTART as usize)) == 0 {
                    should_restart = false;
                }
            }
        }

        if should_restart {
            restart_syscall(tf);
        } else {
            set_syscall_ret(tf, -LinuxError::EINTR.code() as isize);
        }
    } else {
        set_syscall_ret(tf, ret);
    }

    if let Some(delivery) = pulse_core::task::check_signals_and_deliver(thread.as_ref(), tf) {
        use pulse_core::task::{DefaultSignalAction, SignalAction};
        match delivery.action {
            SignalAction::Default(DefaultSignalAction::Terminate) => {
                process.set_exit_signal(delivery.sig as i32, false);
                process.begin_group_exit(delivery.sig as i32);
            }
            SignalAction::Default(DefaultSignalAction::CoreDump) => {
                process.set_exit_signal(delivery.sig as i32, true);
                process.begin_group_exit(delivery.sig as i32);
            }
            _ => {}
        }
    }

    let syscall_leave_ns = axhal::time::monotonic_time_nanos() as u64;
    let delta_ns = syscall_leave_ns.saturating_sub(syscall_enter_ns);
    process.add_sys_time_ns(delta_ns);
    if process.group_exiting() {
        thread.exit_current(process.group_exit_code());
    }
    process.mark_user_resume();

    syscall_ret(tf)
}

#[cfg(target_arch = "riscv64")]
fn set_syscall_ret(tf: &mut TrapFrame, ret: isize) {
    tf.regs.a0 = ret as usize;
}

#[cfg(target_arch = "riscv64")]
fn syscall_ret(tf: &TrapFrame) -> isize {
    tf.regs.a0 as isize
}

#[cfg(target_arch = "riscv64")]
fn restart_syscall(tf: &mut TrapFrame) {
    tf.sepc -= 4;
}

#[cfg(target_arch = "loongarch64")]
fn set_syscall_ret(tf: &mut TrapFrame, ret: isize) {
    tf.regs.a0 = ret as usize;
}

#[cfg(target_arch = "loongarch64")]
fn syscall_ret(tf: &TrapFrame) -> isize {
    tf.regs.a0 as isize
}

#[cfg(target_arch = "loongarch64")]
fn restart_syscall(tf: &mut TrapFrame) {
    tf.era -= 4;
}

fn syscall_dispatcher(
    tf: &mut TrapFrame,
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
        Sysno::sched_setparam => impls::sys_sched_setparam(args[0], args[1]),
        Sysno::sched_getscheduler => impls::sys_sched_getscheduler(args[0]),
        Sysno::sched_setscheduler => impls::sys_sched_setscheduler(args[0], args[1], args[2]),
        Sysno::sched_getparam => impls::sys_sched_getparam(args[0], args[1]),
        Sysno::sched_get_priority_max => impls::sys_sched_get_priority_max(args[0]),
        Sysno::sched_get_priority_min => impls::sys_sched_get_priority_min(args[0]),
        Sysno::sched_rr_get_interval => impls::sys_sched_rr_get_interval(args[0], args[1]),
        Sysno::sched_setattr => impls::sys_sched_setattr(args[0], args[1], args[2]),
        Sysno::sched_getattr => impls::sys_sched_getattr(args[0], args[1], args[2], args[3]),

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
        Sysno::msync => impls::sys_msync(args[0], args[1], args[2]),

        Sysno::setitimer => impls::sys_setitimer(args[0], args[1], args[2]),
        Sysno::getitimer => impls::sys_getitimer(args[0], args[1]),
        Sysno::nanosleep => impls::sys_nanosleep(args[0], args[1]),
        Sysno::clock_nanosleep => {
            impls::sys_clock_nanosleep(args[0] as i32, args[1], args[2], args[3])
        }
        Sysno::clock_getres => impls::sys_clock_getres(args[0] as i32, args[1]),
        Sysno::clock_gettime => impls::sys_clock_gettime(args[0] as i32, args[1]),
        Sysno::clock_settime => impls::sys_clock_settime(args[0] as i32, args[1]),
        Sysno::gettimeofday => impls::sys_gettimeofday(args[0], args[1]),
        Sysno::settimeofday => impls::sys_settimeofday(args[0], args[1]),
        Sysno::times => impls::sys_times(args[0]),
        Sysno::prlimit64 => impls::sys_prlimit64(args[0] as i32, args[1], args[2], args[3]),
        Sysno::getrlimit => impls::sys_prlimit64(0, args[0], 0, args[1]),
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
        Sysno::get_mempolicy => {
            axlog::warn!(
                "sys_get_mempolicy (stub): returning success without NUMA policy semantics"
            );
            0
        }

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
        Sysno::tkill => impls::sys_tkill(args[0] as isize, args[1] as isize),
        Sysno::tgkill => impls::sys_tgkill(args[0] as isize, args[1] as isize, args[2] as isize),
        Sysno::getgid => impls::sys_getgid(),
        Sysno::getegid => impls::sys_getegid(),
        Sysno::setuid => impls::sys_setuid(args[0]),
        Sysno::setgid => impls::sys_setgid(args[0]),
        Sysno::setreuid => impls::sys_setreuid(args[0], args[1]),
        Sysno::setregid => impls::sys_setregid(args[0], args[1]),

        Sysno::rt_sigaction => impls::sys_rt_sigaction(args[0], args[1], args[2], args[3]),
        Sysno::rt_sigreturn => impls::sys_rt_sigreturn(tf),
        Sysno::rt_sigsuspend => impls::sys_rt_sigsuspend(args[0], args[1]),
        Sysno::rt_sigtimedwait => impls::sys_rt_sigtimedwait(args[0], args[1], args[2], args[3]),

        Sysno::ioctl => impls::sys_ioctl(args[0], args[1], args[2]),
        Sysno::fcntl => impls::sys_fcntl(args[0], args[1], args[2]),
        Sysno::dup => impls::sys_dup(args[0]),
        Sysno::dup3 => impls::sys_dup3(args[0], args[1], args[2]),
        Sysno::pipe2 => impls::sys_pipe2(args[0], args[1]),
        Sysno::socket => impls::sys_socket(args[0], args[1], args[2]),
        Sysno::socketpair => impls::sys_socketpair(args[0], args[1], args[2], args[3]),
        Sysno::bind => impls::sys_bind(args[0], args[1], args[2]),
        Sysno::connect => impls::sys_connect(args[0], args[1], args[2]),
        Sysno::listen => impls::sys_listen(args[0], args[1]),
        Sysno::accept => impls::sys_accept(args[0], args[1], args[2]),
        Sysno::accept4 => impls::sys_accept4(args[0], args[1], args[2], args[3]),
        Sysno::shutdown => impls::sys_shutdown(args[0], args[1]),
        Sysno::sendto => impls::sys_sendto(args[0], args[1], args[2], args[3], args[4], args[5]),
        Sysno::recvfrom => {
            impls::sys_recvfrom(args[0], args[1], args[2], args[3], args[4], args[5])
        }
        Sysno::sendmsg => impls::sys_sendmsg(args[0], args[1], args[2]),
        Sysno::recvmsg => impls::sys_recvmsg(args[0], args[1], args[2]),
        Sysno::getsockname => impls::sys_getsockname(args[0], args[1], args[2]),
        Sysno::getpeername => impls::sys_getpeername(args[0], args[1], args[2]),
        Sysno::setsockopt => impls::sys_setsockopt(args[0], args[1], args[2], args[3], args[4]),
        Sysno::getsockopt => impls::sys_getsockopt(args[0], args[1], args[2], args[3], args[4]),
        Sysno::ppoll => impls::sys_ppoll(args[0], args[1], args[2], args[3], args[4]),
        Sysno::getrusage => impls::sys_getrusage(args[0] as i32, args[1]),
        Sysno::pselect6 => {
            impls::sys_pselect6(args[0], args[1], args[2], args[3], args[4], args[5])
        }
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
        Sysno::fchmodat => impls::sys_fchmodat(args[0] as i32, args[1], args[2], 0),
        Sysno::fchownat => impls::sys_fchownat(args[0] as i32, args[1], args[2], args[3], args[4]),
        Sysno::lseek => impls::sys_lseek(args[0], args[1], args[2]),
        Sysno::ftruncate => impls::sys_ftruncate(args[0], args[1]),
        Sysno::fsync => impls::sys_fsync(args[0]),
        Sysno::fdatasync => impls::sys_fdatasync(args[0]),
        Sysno::sync => impls::sys_sync(),
        Sysno::execve => impls::sys_execve(tf, args[0], args[1], args[2]),
        Sysno::setsid => impls::sys_setsid(),

        // System V shared memory
        Sysno::shmget => impls::sys_shmget(args[0] as i32, args[1], args[2] as i32),
        Sysno::shmat => impls::sys_shmat(args[0] as i32, args[1], args[2] as i32),
        Sysno::shmdt => impls::sys_shmdt(args[0]),
        Sysno::shmctl => impls::sys_shmctl(args[0] as i32, args[1] as i32, args[2]),
        _ => {
            axlog::warn!("Unimplemented syscall: {:?} ({})", sysno, syscall_id);
            -LinuxError::ENOSYS.code() as isize
        }
    }
}
