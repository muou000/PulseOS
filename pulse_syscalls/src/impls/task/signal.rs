use core::time::Duration;

use axhal::context::TrapFrame;
use linux_raw_sys::general::{
    MINSIGSTKSZ, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGKILL, SIGSTOP, SS_DISABLE, SS_FLAG_BITS,
    SS_ONSTACK, sigaction, siginfo, timespec,
};
use pulse_core::task::{NSIG, SigAction, uaccess};

use crate::{LinuxError, impls::utils::read_user_timespec};

fn timespec_to_duration(ts: timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec > 999_999_999 {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

pub fn sys_rt_sigprocmask(_how: usize, _set: usize, _oldset: usize, _sigsetsize: usize) -> isize {
    let how = _how;
    let set = _set;
    let oldset = _oldset;
    let sigsetsize = _sigsetsize;
    if sigsetsize != 0 && sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let old_mask = thread.signal_blocked_mask();
    if oldset != 0
        && let Err(e) = process.write_user_usize(oldset, old_mask as usize)
    {
        axlog::warn!(
            "sys_rt_sigprocmask: failed to write old mask: pid={}, tid={}, oldset={:#x}, err={:?}",
            process.pid(),
            thread.tid(),
            oldset,
            e
        );
        return -LinuxError::EFAULT.code() as isize;
    }
    if set != 0 {
        let new_bits = match process.read_user_usize(set) {
            Ok(v) => v as u64,
            Err(e) => {
                axlog::warn!(
                    "sys_rt_sigprocmask: failed to read new mask: pid={}, tid={}, set={:#x}, \
                     err={:?}",
                    process.pid(),
                    thread.tid(),
                    set,
                    e
                );
                return -LinuxError::EFAULT.code() as isize;
            }
        };
        let current = old_mask;
        let mask = match how as u32 {
            SIG_BLOCK => current | new_bits,
            SIG_UNBLOCK => current & !new_bits,
            SIG_SETMASK => new_bits,
            _ => return -LinuxError::EINVAL.code() as isize,
        };
        thread.set_signal_blocked_mask(mask);
    }
    0
}

pub fn sys_rt_sigaction(_signum: usize, _act: usize, _oldact: usize, _sigsetsize: usize) -> isize {
    let signum = _signum;
    let act = _act;
    let oldact = _oldact;
    let sigsetsize = _sigsetsize;
    if sigsetsize != 0 && sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }
    if signum == 0 || signum > NSIG || signum == SIGKILL as usize || signum == SIGSTOP as usize {
        return -LinuxError::EINVAL.code() as isize;
    }
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let shared = process.signal_shared();
    if oldact != 0 {
        let old = shared.action(signum);
        let mut raw: sigaction = unsafe { core::mem::zeroed() };
        raw.sa_handler = unsafe { core::mem::transmute(old.handler) };
        raw.sa_flags = old.flags as _;
        raw.sa_mask.sig = [old.mask as _];
        if let Err(e) = process.write_user_bytes(oldact, unsafe {
            core::slice::from_raw_parts(
                (&raw as *const sigaction).cast::<u8>(),
                core::mem::size_of::<sigaction>(),
            )
        }) {
            axlog::warn!(
                "sys_rt_sigaction: failed to write old action: pid={}, tid={}, signum={}, \
                 oldact={:#x}, err={:?}",
                process.pid(),
                thread.tid(),
                signum,
                oldact,
                e
            );
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    if act != 0 {
        let new_act: sigaction = match uaccess::read_user_plain(&process, act) {
            Ok(v) => v,
            Err(e) => {
                axlog::warn!(
                    "sys_rt_sigaction: failed to read new action: pid={}, tid={}, signum={}, \
                     act={:#x}, err={:?}",
                    process.pid(),
                    thread.tid(),
                    signum,
                    act,
                    e
                );
                return -LinuxError::EFAULT.code() as isize;
            }
        };
        let handler = unsafe { core::mem::transmute::<_, usize>(new_act.sa_handler) };
        let flags = new_act.sa_flags as usize;
        let mask = new_act.sa_mask.sig[0] as u64;
        shared.set_action(signum, SigAction::from_parts(handler, flags, mask));
    }
    0
}

pub fn sys_rt_sigpending(set: usize, sigsetsize: usize) -> isize {
    if set == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    match process.write_user_usize(set, thread.signal().pending_mask() as usize) {
        Ok(()) => 0,
        Err(_) => -LinuxError::EFAULT.code() as isize,
    }
}

pub fn sys_rt_sigreturn(tf: &mut TrapFrame) -> isize {
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };

    match thread.restore_from_sigreturn(tf) {
        Ok(ret) => ret as isize,
        Err(_) => -LinuxError::EINVAL.code() as isize,
    }
}

pub fn sys_rt_sigsuspend(mask: usize, sigsetsize: usize) -> isize {
    if sigsetsize != 0 && sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let new_mask = match process.read_user_usize(mask) {
        Ok(v) => v as u64,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };
    thread.begin_sigsuspend(new_mask);
    let signal_wait = thread.signal_wait_queue();
    let wait_context =
        axtask::WaitContext::new(|| (axtask::WaitReason::Signal, thread.tid(), new_mask));
    signal_wait.wait_until_with_context(wait_context, || {
        thread.has_pending_signal() || thread.process().group_exiting()
    });
    -LinuxError::EINTR.code() as isize
}

pub fn sys_rt_sigtimedwait(set: usize, info: usize, timeout: usize, sigsetsize: usize) -> isize {
    if set == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if sigsetsize != 0 && sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    let waitset = match process.read_user_usize(set) {
        Ok(v) => v as u64,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };
    let signal_wait = thread.signal_wait_queue();
    let wait_context =
        axtask::WaitContext::new(|| (axtask::WaitReason::Signal, thread.tid(), waitset));

    let deadline_ns = if timeout == 0 {
        None
    } else {
        let ts = match read_user_timespec(timeout).and_then(timespec_to_duration) {
            Ok(v) => v,
            Err(e) => return -e.code() as isize,
        };
        Some((axhal::time::monotonic_time_nanos() as u64).saturating_add(ts.as_nanos() as u64))
    };

    loop {
        if thread.exec_exit_requested() || thread.process().group_exiting() {
            return -LinuxError::EINTR.code() as isize;
        }

        if let Some((sig, siginfo)) = thread.dequeue_waitset_signal(waitset) {
            if info != 0 {
                let write_result = if let Some(raw) = siginfo {
                    process.write_user_bytes(info, &raw)
                } else {
                    let mut raw: siginfo = unsafe { core::mem::zeroed() };
                    raw.__bindgen_anon_1.__bindgen_anon_1.si_signo =
                        sig as linux_raw_sys::ctypes::c_int;
                    raw.__bindgen_anon_1.__bindgen_anon_1.si_errno = 0;
                    raw.__bindgen_anon_1.__bindgen_anon_1.si_code = 0;
                    uaccess::write_user_plain(&process, info, &raw)
                };
                if write_result.is_err() {
                    return -LinuxError::EFAULT.code() as isize;
                }
            }
            return sig as isize;
        }

        if thread.has_pending_unblocked_signal_not_in_set(waitset) {
            return -LinuxError::EINTR.code() as isize;
        }

        match deadline_ns {
            Some(deadline_ns) => {
                #[cfg(feature = "irq")]
                {
                    let now_ns = axhal::time::monotonic_time_nanos() as u64;
                    if now_ns >= deadline_ns {
                        return -LinuxError::EAGAIN.code() as isize;
                    }
                    let remain = Duration::from_nanos(deadline_ns - now_ns);
                    let timed_out =
                        signal_wait.wait_timeout_until_with_context(wait_context, remain, || {
                            thread.has_waitset_signal(waitset)
                                || thread.has_pending_unblocked_signal_not_in_set(waitset)
                                || thread.exec_exit_requested()
                                || thread.process().group_exiting()
                        });
                    if timed_out
                        && !thread.has_waitset_signal(waitset)
                        && !thread.has_pending_unblocked_signal_not_in_set(waitset)
                        && !thread.exec_exit_requested()
                        && !thread.process().group_exiting()
                    {
                        return -LinuxError::EAGAIN.code() as isize;
                    }
                }
                #[cfg(not(feature = "irq"))]
                {
                    if (axhal::time::monotonic_time_nanos() as u64) >= deadline_ns {
                        return -LinuxError::EAGAIN.code() as isize;
                    }
                    axtask::yield_now();
                }
            }
            None => {
                signal_wait.wait_until_with_context(wait_context, || {
                    thread.has_waitset_signal(waitset)
                        || thread.has_pending_unblocked_signal_not_in_set(waitset)
                        || thread.exec_exit_requested()
                        || thread.process().group_exiting()
                });
            }
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct stack_t {
    ss_sp: usize,
    ss_flags: i32,
    ss_size: usize,
}

pub fn sys_sigaltstack(ss: usize, oss: usize) -> isize {
    axlog::debug!("sys_sigaltstack: ss={:#x}, oss={:#x}", ss, oss);

    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    if oss != 0 {
        let current_altstack = thread.signal_altstack();
        let raw_oss = stack_t {
            ss_sp: current_altstack.sp,
            ss_flags: current_altstack.flags as i32,
            ss_size: current_altstack.size,
        };
        if uaccess::write_user_plain(&process, oss, &raw_oss).is_err() {
            return -LinuxError::EFAULT.code() as isize;
        }
    }

    if ss != 0 {
        let raw_ss: stack_t = match uaccess::read_user_plain(&process, ss) {
            Ok(v) => v,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        };

        let current_altstack = thread.signal_altstack();
        if current_altstack.flags & SS_ONSTACK as usize != 0 {
            return -LinuxError::EPERM.code() as isize;
        }

        let raw_flags = raw_ss.ss_flags as u32;
        if raw_flags & !(SS_DISABLE | SS_ONSTACK | SS_FLAG_BITS) != 0 {
            return -LinuxError::EINVAL.code() as isize;
        }

        if raw_flags & SS_DISABLE != 0 {
            thread.set_signal_altstack(pulse_core::task::SignalAltStack {
                sp: 0,
                size: 0,
                flags: SS_DISABLE as usize,
            });
        } else {
            if raw_ss.ss_size < MINSIGSTKSZ as usize {
                return -LinuxError::ENOMEM.code() as isize;
            }
            thread.set_signal_altstack(pulse_core::task::SignalAltStack {
                sp: raw_ss.ss_sp,
                size: raw_ss.ss_size,
                flags: raw_flags as usize,
            });
        }
    }

    0
}
