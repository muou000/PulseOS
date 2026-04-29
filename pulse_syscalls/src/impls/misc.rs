//! 其他杂项系统调用

use core::time::Duration;

use axhal::context::TrapFrame;
use axalloc::global_allocator;
use linux_raw_sys::general::{
    RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA, RLIMIT_FSIZE, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE,
    RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC, RLIMIT_RSS, RLIMIT_RTPRIO, RLIMIT_RTTIME,
    RLIMIT_SIGPENDING, RLIMIT_STACK, SIG_BLOCK, SIG_SETMASK, SIG_UNBLOCK, SIGKILL, SIGSTOP,
    rlimit64, sigaction, siginfo, timespec,
};
use pulse_core::task::{NSIG, SIG_IGN, SigAction, uaccess};
use rand::{rngs::SmallRng, RngCore, SeedableRng};
use spin::Mutex;

use crate::{
    LinuxError,
    impls::utils::{alloc_zeroed_bytes, read_user_timespec},
};

static RANDOM_RNG: Mutex<Option<SmallRng>> = Mutex::new(None);

#[repr(C)]
#[derive(Clone, Copy)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Sysinfo {
    uptime: i64,
    loads: [u64; 3],
    totalram: u64,
    freeram: u64,
    sharedram: u64,
    bufferram: u64,
    totalswap: u64,
    freeswap: u64,
    procs: u16,
    pad: u16,
    totalhigh: u64,
    freehigh: u64,
    mem_unit: u32,
    _f: [i8; 0],
}

const SYSLOG_ACTION_CLOSE: usize = 0;
const SYSLOG_ACTION_OPEN: usize = 1;
const SYSLOG_ACTION_READ: usize = 2;
const SYSLOG_ACTION_READ_ALL: usize = 3;
const SYSLOG_ACTION_READ_CLEAR: usize = 4;
const SYSLOG_ACTION_CLEAR: usize = 5;
const SYSLOG_ACTION_CONSOLE_OFF: usize = 6;
const SYSLOG_ACTION_CONSOLE_ON: usize = 7;
const SYSLOG_ACTION_CONSOLE_LEVEL: usize = 8;
const SYSLOG_ACTION_SIZE_UNREAD: usize = 9;
const SYSLOG_ACTION_SIZE_BUFFER: usize = 10;
const KMSG_PLACEHOLDER: &[u8] = b"PulseOS kernel log buffer is not persisted yet.\n";

fn write_cstr_field(dst: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let len = bytes.len().min(dst.len().saturating_sub(1));
    dst[..len].copy_from_slice(&bytes[..len]);
    dst[len] = 0;
}

fn random_seed() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};

    static SEED_COUNTER: AtomicU64 = AtomicU64::new(0);

    axhal::time::monotonic_time_nanos() as u64
        ^ SEED_COUNTER.fetch_add(1, Ordering::Relaxed).rotate_left(17)
        ^ 0x9e37_79b9_7f4a_7c15
}

fn with_random_rng<R>(f: impl FnOnce(&mut SmallRng) -> R) -> R {
    let mut rng = RANDOM_RNG.lock();
    let rng = rng.get_or_insert_with(|| SmallRng::seed_from_u64(random_seed()));
    f(rng)
}

fn rlimit_for(resource: usize) -> Option<rlimit64> {
    const INF: u64 = u64::MAX;
    let rlim = match resource as u32 {
        RLIMIT_CPU | RLIMIT_FSIZE | RLIMIT_DATA | RLIMIT_CORE | RLIMIT_RSS | RLIMIT_NPROC
        | RLIMIT_MEMLOCK | RLIMIT_AS | RLIMIT_MSGQUEUE | RLIMIT_RTPRIO | RLIMIT_RTTIME
        | RLIMIT_SIGPENDING | RLIMIT_NICE => rlimit64 {
            rlim_cur: INF,
            rlim_max: INF,
        },
        RLIMIT_STACK => rlimit64 {
            rlim_cur: pulse_core::config::USER_STACK_SIZE as u64,
            rlim_max: pulse_core::config::USER_STACK_SIZE as u64,
        },
        RLIMIT_NOFILE => rlimit64 {
            rlim_cur: pulse_core::fd_table::FD_LIMIT as u64,
            rlim_max: pulse_core::fd_table::FD_LIMIT as u64,
        },
        _ => return None,
    };
    Some(rlim)
}

fn timespec_to_duration(ts: timespec) -> Result<Duration, LinuxError> {
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec > 999_999_999 {
        return Err(LinuxError::EINVAL);
    }
    Ok(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))
}

/// sys_uname - 获取系统信息
pub fn sys_uname(buf: usize) -> isize {
    axlog::debug!("sys_uname: buf={:#x}", buf);
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    // Keep values simple and stable for userspace probing.
    let mut uts = UtsName {
        sysname: [0; 65],
        nodename: [0; 65],
        release: [0; 65],
        version: [0; 65],
        machine: [0; 65],
        domainname: [0; 65],
    };
    write_cstr_field(&mut uts.sysname, "Linux");
    write_cstr_field(&mut uts.nodename, "pulseos");
    write_cstr_field(&mut uts.release, "6.1.0");
    write_cstr_field(&mut uts.version, "#1 PulseOS");
    #[cfg(target_arch = "riscv64")]
    write_cstr_field(&mut uts.machine, "riscv64");
    #[cfg(target_arch = "loongarch64")]
    write_cstr_field(&mut uts.machine, "loongarch64");
    write_cstr_field(&mut uts.domainname, "(none)");

    match pulse_core::task::with_current_process(|process| {
        uaccess::write_user_plain(process, buf, &uts)
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -LinuxError::EFAULT.code() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_umask(mask: usize) -> isize {
    axlog::debug!("sys_umask: mask={:#o}", mask);
    match pulse_core::task::current_process() {
        Ok(process) => process.set_umask((mask as u32) & 0o777) as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    axlog::debug!("sys_set_tid_address: tidptr={:#x}", tidptr);
    match pulse_core::task::current_thread() {
        Ok(thread) => {
            thread.set_clear_child_tid(tidptr);
            axtask::current().id().as_u64() as isize
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_gettid() -> isize {
    axlog::debug!("sys_gettid");
    match pulse_core::task::current_thread() {
        Ok(_) => axtask::current().id().as_u64() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_prlimit64(pid: i32, resource: usize, new_limit: usize, old_limit: usize) -> isize {
    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    if pid != 0 && pid != process.pid() as i32 {
        return -LinuxError::ESRCH.code() as isize;
    }
    let resource = resource as u32;
    if resource != RLIMIT_STACK && resource != RLIMIT_NOFILE && resource != RLIMIT_MEMLOCK {
        return -LinuxError::EINVAL.code() as isize;
    }

    let Some(old_rlim) = process.get_rlimit(resource) else {
        return -LinuxError::EINVAL.code() as isize;
    };

    if new_limit != 0 {
        let new_rlim: rlimit64 = match uaccess::read_user_plain(process.as_ref(), new_limit) {
            Ok(v) => v,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        };
        if new_rlim.rlim_cur > new_rlim.rlim_max {
            return -LinuxError::EINVAL.code() as isize;
        }
        if process.set_rlimit(resource, new_rlim).is_err() {
            return -LinuxError::EINVAL.code() as isize;
        }
    }

    if old_limit != 0 {
        match uaccess::write_user_plain(process.as_ref(), old_limit, &old_rlim) {
            Ok(()) => 0,
            Err(_) => -LinuxError::EFAULT.code() as isize,
        }
    } else {
        0
    }
}

pub fn sys_getrandom(buf: usize, buflen: usize, flags: usize) -> isize {
    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if buflen == 0 {
        return 0;
    }
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut tmp = match alloc_zeroed_bytes(buflen, "sys_getrandom.tmp") {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
    with_random_rng(|rng| rng.fill_bytes(&mut tmp));
    match pulse_core::task::with_current_process(|process| process.write_user_bytes(buf, &tmp)) {
        Ok(Ok(())) => buflen as isize,
        Ok(Err(_)) => -LinuxError::EFAULT.code() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_set_robust_list(head: usize, len: usize) -> isize {
    axlog::debug!("sys_set_robust_list: head={:#x}, len={}", head, len);
    if len != core::mem::size_of::<usize>() * 3 {
        return -LinuxError::EINVAL.code() as isize;
    }
    match pulse_core::task::current_thread() {
        Ok(thread) => {
            thread.set_robust_list_head(head);
            0
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_get_robust_list(pid: usize, head_ptr: usize, len_ptr: usize) -> isize {
    axlog::debug!(
        "sys_get_robust_list: pid={}, head_ptr={:#x}, len_ptr={:#x}",
        pid,
        head_ptr,
        len_ptr
    );
    if head_ptr == 0 || len_ptr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    if pid != 0 && pid != axtask::current().id().as_u64() as usize {
        return -LinuxError::ESRCH.code() as isize;
    }

    let process = thread.process();
    process
        .write_user_usize(head_ptr, thread.robust_list_head())
        .and_then(|_| process.write_user_usize(len_ptr, core::mem::size_of::<usize>() * 3))
        .map(|_| 0)
        .unwrap_or_else(|_| -LinuxError::EFAULT.code() as isize)
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
    if oldset != 0 && process.write_user_usize(oldset, old_mask as usize).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }
    if set != 0 {
        let new_bits = match process.read_user_usize(set) {
            Ok(v) => v as u64,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
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
        raw.sa_handler = if old.handler == 0 {
            None
        } else if old.handler == SIG_IGN {
            linux_raw_sys::signal_macros::sig_ign()
        } else {
            Some(unsafe { core::mem::transmute::<usize, _>(old.handler) })
        };
        raw.sa_flags = old.flags as _;
        raw.sa_mask.sig = [old.mask as _];
        if process
            .write_user_bytes(oldact, unsafe {
                core::slice::from_raw_parts(
                    (&raw as *const sigaction).cast::<u8>(),
                    core::mem::size_of::<sigaction>(),
                )
            })
            .is_err()
        {
            return -LinuxError::EFAULT.code() as isize;
        }
    }
    if act != 0 {
        let new_act: sigaction = match uaccess::read_user_plain(process, act) {
            Ok(v) => v,
            Err(_) => return -LinuxError::EFAULT.code() as isize,
        };
        let handler = match new_act.sa_handler {
            None => 0usize,
            Some(f) => unsafe { core::mem::transmute::<_, usize>(f) },
        };
        let flags = new_act.sa_flags as usize;
        let mask = new_act.sa_mask.sig[0] as u64;
        shared.set_action(signum, SigAction::from_parts(handler, flags, mask));
    }
    0
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
    loop {
        if thread.has_pending_signal() {
            return -LinuxError::EINTR.code() as isize;
        }
        axtask::yield_now();
    }
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
        if let Some(sig) = thread.dequeue_waitset_signal(waitset) {
            if info != 0 {
                let mut raw: siginfo = unsafe { core::mem::zeroed() };
                raw.__bindgen_anon_1.__bindgen_anon_1.si_signo =
                    sig as linux_raw_sys::ctypes::c_int;
                raw.__bindgen_anon_1.__bindgen_anon_1.si_errno = 0;
                raw.__bindgen_anon_1.__bindgen_anon_1.si_code = 0;
                if uaccess::write_user_plain(process, info, &raw).is_err() {
                    return -LinuxError::EFAULT.code() as isize;
                }
            }
            return sig as isize;
        }

        if thread.has_pending_unblocked_signal_not_in_set(waitset) {
            return -LinuxError::EINTR.code() as isize;
        }

        if let Some(deadline_ns) = deadline_ns
            && (axhal::time::monotonic_time_nanos() as u64) >= deadline_ns
        {
            return -LinuxError::EAGAIN.code() as isize;
        }

        axtask::yield_now();
    }
}

pub fn sys_setpgid(pid: isize, pgid: isize) -> isize {
    axlog::debug!("sys_setpgid (stub): pid={}, pgid={}", pid, pgid);
    0
}

pub fn sys_sysinfo(info: usize) -> isize {
    axlog::debug!("sys_sysinfo: info={:#x}", info);
    if info == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let allocator = global_allocator();
    let page_size = 4096u64;
    let total_pages = allocator
        .used_pages()
        .saturating_add(allocator.available_pages()) as u64;
    let free_pages = allocator.available_pages() as u64;
    let sysinfo: linux_raw_sys::system::sysinfo = linux_raw_sys::system::sysinfo {
        uptime: axhal::time::monotonic_time().as_secs() as _,
        loads: [0; 3],
        totalram: total_pages.saturating_mul(page_size) as _,
        freeram: free_pages.saturating_mul(page_size) as _,
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs: 1,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1,
        _f: linux_raw_sys::system::__IncompleteArrayField::new(),
    };
    match pulse_core::task::with_current_process(|process| {
        let bytes = unsafe {
            core::slice::from_raw_parts(
                (&sysinfo as *const linux_raw_sys::system::sysinfo).cast::<u8>(),
                core::mem::size_of::<linux_raw_sys::system::sysinfo>(),
            )
        };
        uaccess::write_user_bytes(process, info, bytes)
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -LinuxError::EFAULT.code() as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_syslog(action: usize, bufp: usize, len: usize) -> isize {
    axlog::debug!(
        "sys_syslog: action={}, bufp={:#x}, len={}",
        action,
        bufp,
        len
    );
    match action {
        SYSLOG_ACTION_CLOSE
        | SYSLOG_ACTION_OPEN
        | SYSLOG_ACTION_CLEAR
        | SYSLOG_ACTION_CONSOLE_OFF
        | SYSLOG_ACTION_CONSOLE_ON
        | SYSLOG_ACTION_CONSOLE_LEVEL => 0,
        SYSLOG_ACTION_SIZE_UNREAD | SYSLOG_ACTION_SIZE_BUFFER => KMSG_PLACEHOLDER.len() as isize,
        SYSLOG_ACTION_READ | SYSLOG_ACTION_READ_ALL | SYSLOG_ACTION_READ_CLEAR => {
            if bufp == 0 && len != 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let read_len = core::cmp::min(len, KMSG_PLACEHOLDER.len());
            if read_len == 0 {
                return 0;
            }
            let mut out = match alloc_zeroed_bytes(read_len, "sys_syslog.out") {
                Ok(v) => v,
                Err(e) => return -e.code() as isize,
            };
            out.copy_from_slice(&KMSG_PLACEHOLDER[..read_len]);
            match pulse_core::task::with_current_process(|process| {
                uaccess::write_user_bytes(process, bufp, &out)
            }) {
                Ok(Ok(())) => read_len as isize,
                Ok(Err(_)) => -LinuxError::EFAULT.code() as isize,
                Err(e) => -e.code() as isize,
            }
        }
        _ => -LinuxError::EINVAL.code() as isize,
    }
}
