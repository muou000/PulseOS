//! 其他杂项系统调用

use axalloc::global_allocator;
use axfs::FS_CONTEXT;
use linux_raw_sys::general::{
    GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM, RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
    RLIMIT_FSIZE, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC,
    RLIMIT_RSS, RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK, rlimit64,
};
use pulse_core::task::uaccess;

use crate::{LinuxError, impls::utils::alloc_zeroed_bytes};

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
    if new_limit != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if old_limit == 0 {
        return 0;
    }

    let Some(rlim) = rlimit_for(resource) else {
        return -LinuxError::EINVAL.code() as isize;
    };
    match uaccess::write_user_plain(process.as_ref(), old_limit, &rlim) {
        Ok(()) => 0,
        Err(_) => -LinuxError::EFAULT.code() as isize,
    }
}

pub fn sys_getrandom(buf: usize, buflen: usize, flags: usize) -> isize {
    let flags = flags as u32;
    if flags & !(GRND_RANDOM | GRND_NONBLOCK | GRND_INSECURE) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    if buflen == 0 {
        return 0;
    }
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let path = if flags & GRND_RANDOM != 0 {
        "/dev/random"
    } else {
        "/dev/urandom"
    };
    let tmp = match FS_CONTEXT.lock().read_prefix(path, buflen) {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
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
    axlog::debug!("sys_rt_sigprocmask (stub)");
    0
}

pub fn sys_rt_sigaction(_signum: usize, _act: usize, _oldact: usize, _sigsetsize: usize) -> isize {
    axlog::debug!("sys_rt_sigaction (stub)");
    0
}

pub fn sys_rt_sigreturn() -> isize {
    axlog::debug!("sys_rt_sigreturn (stub)");
    0
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
    let sysinfo = Sysinfo {
        uptime: axhal::time::monotonic_time().as_secs() as i64,
        loads: [0; 3],
        totalram: total_pages.saturating_mul(page_size),
        freeram: free_pages.saturating_mul(page_size),
        sharedram: 0,
        bufferram: 0,
        totalswap: 0,
        freeswap: 0,
        procs: 1,
        pad: 0,
        totalhigh: 0,
        freehigh: 0,
        mem_unit: 1,
        _f: [],
    };
    match pulse_core::task::with_current_process(|process| {
        uaccess::write_user_plain(process, info, &sysinfo)
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
