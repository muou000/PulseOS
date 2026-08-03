use core::time::Duration;

use axhal::context::TrapFrame;
use linux_raw_sys::general::{
    MINSIGSTKSZ, O_CLOEXEC, O_NONBLOCK, SA_NOCLDSTOP, SA_NOCLDWAIT, SA_NODEFER, SA_ONSTACK,
    SA_RESETHAND, SA_RESTART, SA_SIGINFO, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGKILL, SIGSEGV,
    SIGSTOP, SS_DISABLE, SS_ONSTACK, _NSIG, sigaction, siginfo, timespec,
};
use pulse_core::{
    fd_table::{FdEntry, FdFlags, SignalFdObject},
    task::{SigAction, uaccess},
};

use crate::{LinuxError, impls::utils::read_user_timespec};

fn timespec_to_duration(ts: timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec > 999_999_999 {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

fn duration_to_nanos_saturating(duration: Duration) -> u64 {
    duration
        .as_secs()
        .saturating_mul(1_000_000_000)
        .saturating_add(duration.subsec_nanos() as u64)
}

const SUPPORTED_SIGACTION_FLAGS: usize = SA_NOCLDSTOP as usize
    | SA_NOCLDWAIT as usize
    | SA_SIGINFO as usize
    | SA_ONSTACK as usize
    | SA_RESTART as usize
    | SA_NODEFER as usize
    | SA_RESETHAND as usize;

fn sanitize_signal_mask(mask: u64) -> u64 {
    let unmaskable = (1u64 << (SIGKILL as usize - 1)) | (1u64 << (SIGSTOP as usize - 1));
    mask & !unmaskable
}

pub fn sys_rt_sigprocmask(_how: usize, _set: usize, _oldset: usize, _sigsetsize: usize) -> isize {
    let how = _how;
    let set = _set;
    let oldset = _oldset;
    let sigsetsize = _sigsetsize;
    if sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let old_mask = thread.signal_blocked_mask();

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
    0
}

pub fn sys_rt_sigaction(_signum: usize, _act: usize, _oldact: usize, _sigsetsize: usize) -> isize {
    let signum = _signum;
    let act = _act;
    let oldact = _oldact;
    let sigsetsize = _sigsetsize;
    if sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }
    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let shared = process.signal_shared();

    // Linux copies `act` before validating the signal number.  Besides
    // matching EFAULT precedence, this leaves the disposition untouched when
    // userspace supplied an invalid action pointer.
    let new_action = if act != 0 {
        let raw: sigaction = match uaccess::read_user_plain(&process, act) {
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
        let handler = unsafe { core::mem::transmute::<_, usize>(raw.sa_handler) };
        // Linux does not let an action mask block SIGKILL or SIGSTOP, and it
        // clears unknown action bits so userspace can detect unsupported
        // extensions through a subsequent rt_sigaction call.
        let flags = raw.sa_flags as usize & SUPPORTED_SIGACTION_FLAGS;
        let mask = sanitize_signal_mask(raw.sa_mask.sig[0] as u64);
        Some(SigAction::from_parts(handler, flags, mask))
    } else {
        None
    };

    if signum == 0
        || signum > (_NSIG as usize)
        || signum == SIGKILL as usize
        || signum == SIGSTOP as usize
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    // This is one sighand transaction.  If copying oldact faults below, Linux
    // still leaves the new disposition installed, which is why the swap comes
    // before the user write.
    let old = shared.replace_action(signum, new_action);
    if new_action.is_some() {
        pulse_core::task::discard_pending_if_ignored(process.as_ref(), signum);
    }

    if oldact != 0 {
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
    0
}

pub fn sys_rt_sigpending(set: usize, sigsetsize: usize) -> isize {
    if sigsetsize > core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }
    // Linux's copy_to_user() has no address requirement for an empty copy.
    // Keep the same ABI behavior for rt_sigpending(NULL, 0).
    if sigsetsize == 0 {
        return 0;
    }
    if set == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let blocked_pending = thread.signal().pending_mask() & thread.signal_blocked_mask();
    match process.write_user_bytes(set, &blocked_pending.to_ne_bytes()[..sigsetsize]) {
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
        Err(err) => {
            axlog::warn!(
                "sys_rt_sigreturn: invalid signal frame: pid={}, tid={}, err={:?}",
                thread.process().pid(),
                thread.tid(),
                err
            );
            let _ = pulse_core::task::force_signal_to_thread(thread.as_ref(), SIGSEGV as usize);
            0
        }
    }
}

pub fn sys_rt_sigsuspend(mask: usize, sigsetsize: usize) -> isize {
    if sigsetsize != core::mem::size_of::<u64>() {
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
    if sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    let waitset = match process.read_user_usize(set) {
        Ok(v) => sanitize_signal_mask(v as u64),
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
        Some(
            (axhal::time::monotonic_time_nanos() as u64)
                .saturating_add(duration_to_nanos_saturating(ts)),
        )
    };

    loop {
        if thread.exec_exit_requested() || thread.process().group_exiting() {
            return -LinuxError::EINTR.code() as isize;
        }

        // A thread that did not dequeue the stop signal still has to join the
        // process-wide stop.  Once SIGCONT resumes the group, continue the
        // original signal wait rather than manufacturing an EINTR.
        if thread.process().group_stopped() {
            thread.process().wait_while_group_stopped(thread.as_ref());
            if thread.process().group_stopped() {
                return -LinuxError::EINTR.code() as isize;
            }
            continue;
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

    let old_altstack = thread.signal_altstack();
    let new_altstack = if ss != 0 {
        let raw_ss: stack_t = match uaccess::read_user_plain(&process, ss) {
            Ok(v) => v,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        };

        if old_altstack.flags & SS_ONSTACK as usize != 0 {
            return -LinuxError::EPERM.code() as isize;
        }

        let raw_flags = raw_ss.ss_flags as u32;
        let altstack = match pulse_core::task::SignalAltStack::from_user_parts(
            raw_ss.ss_sp,
            raw_ss.ss_size,
            raw_flags,
        ) {
            Some(altstack) => altstack,
            None => return -LinuxError::EINVAL.code() as isize,
        };
        if (altstack.flags & SS_DISABLE as usize) == 0
            && raw_ss.ss_size < MINSIGSTKSZ as usize
        {
            return -LinuxError::ENOMEM.code() as isize;
        }
        Some(altstack)
    } else {
        None
    };

    // Linux commits `ss` before copying `old_ss` back to userspace.  Preserve
    // that observable order when the output pointer faults.
    if let Some(altstack) = new_altstack {
        thread.set_signal_altstack(altstack);
    }

    if oss != 0 {
        let raw_oss = stack_t {
            ss_sp: old_altstack.sp,
            ss_flags: old_altstack.flags as i32,
            ss_size: old_altstack.size,
        };
        if uaccess::write_user_plain(&process, oss, &raw_oss).is_err() {
            return -LinuxError::EFAULT.code() as isize;
        }
    }

    0
}

pub fn sys_signalfd4(ufd: isize, mask: usize, sigsetsize: usize, flags: usize) -> isize {
    if sigsetsize != core::mem::size_of::<u64>() {
        return -LinuxError::EINVAL.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();
    let mask = match process.read_user_usize(mask) {
        Ok(mask) => sanitize_signal_mask(mask as u64),
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };

    let allowed = O_CLOEXEC as usize | O_NONBLOCK as usize;
    if flags & !allowed != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if ufd == -1 {
        let mut fd_flags = FdFlags::empty();
        if flags & O_CLOEXEC as usize != 0 {
            fd_flags.insert(FdFlags::CLOEXEC);
        }
        if flags & O_NONBLOCK as usize != 0 {
            fd_flags.insert(FdFlags::NONBLOCK);
        }
        let entry = FdEntry::new(
            alloc::sync::Arc::new(SignalFdObject::new(
                mask,
                fd_flags.contains(FdFlags::NONBLOCK),
            )),
            fd_flags,
        );
        return match process.insert_fd_entry(entry) {
            Ok(fd) => fd as isize,
            Err(e) => -e.code() as isize,
        };
    }

    if ufd < 0 {
        return -LinuxError::EBADF.code() as isize;
    }

    let entry = match process.get_fd_entry(ufd as usize) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let Some(signalfd) = entry.object.as_any().downcast_ref::<SignalFdObject>() else {
        return -LinuxError::EINVAL.code() as isize;
    };
    signalfd.set_mask(mask);
    ufd
}

#[cfg(test)]
mod tests {
    use super::*;
    use linux_raw_sys::general::SA_UNSUPPORTED;

    #[test]
    fn signal_masks_cannot_contain_kill_or_stop() {
        let mask = (1u64 << (SIGKILL as usize - 1))
            | (1u64 << (SIGSTOP as usize - 1))
            | (1u64 << 9);
        assert_eq!(sanitize_signal_mask(mask), 1u64 << 9);
    }

    #[test]
    fn sigtimedwait_set_ignores_kill_and_stop() {
        let waitset = (1u64 << (SIGKILL as usize - 1))
            | (1u64 << (SIGSTOP as usize - 1))
            | (1u64 << 9);
        assert_eq!(sanitize_signal_mask(waitset), 1u64 << 9);
    }

    #[test]
    fn unsupported_sigaction_flags_are_not_stored() {
        assert_eq!(SUPPORTED_SIGACTION_FLAGS & SA_UNSUPPORTED as usize, 0);
        assert_ne!(SUPPORTED_SIGACTION_FLAGS & SA_RESTART as usize, 0);
    }

    #[test]
    fn sigaction_exchange_returns_the_previous_disposition() {
        let shared = pulse_core::task::SignalShared::new();
        let first = SigAction::from_parts(0x1234, SA_RESTART as usize, 0x55);
        let second = SigAction::from_parts(0x5678, SA_NODEFER as usize, 0xaa);

        assert_eq!(
            shared.replace_action(10, Some(first)).handler,
            pulse_core::task::SIG_DFL
        );
        assert_eq!(shared.replace_action(10, Some(second)).handler, first.handler);
        assert_eq!(shared.action(10).handler, second.handler);
    }

    #[test]
    fn signal_wait_timeout_saturates_instead_of_wrapping() {
        assert_eq!(
            duration_to_nanos_saturating(Duration::new(u64::MAX, 999_999_999)),
            u64::MAX,
        );
    }
}
