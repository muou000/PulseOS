//! 其他杂项系统调用

use crate::LinuxError;
use alloc::vec;
use axalloc::global_allocator;
use pulse_core::task::uaccess;
use rand::{RngCore, SeedableRng, rngs::SmallRng};

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

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    axlog::debug!("sys_set_tid_address: tidptr={:#x}", tidptr);
    match pulse_core::task::current_thread() {
        Ok(thread) => {
            thread.set_clear_child_tid(tidptr);
            thread.tid() as isize
        }
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_gettid() -> isize {
    axlog::debug!("sys_gettid");
    match pulse_core::task::current_thread() {
        Ok(thread) => thread.tid() as isize,
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
    if pid != 0 && pid != thread.tid() as usize {
        return -LinuxError::ESRCH.code() as isize;
    }

    let process = thread.process();
    process
        .write_user_usize(head_ptr, thread.robust_list_head())
        .and_then(|_| process.write_user_usize(len_ptr, core::mem::size_of::<usize>() * 3))
        .map(|_| 0)
        .unwrap_or_else(|_| -LinuxError::EFAULT.code() as isize)
}

pub fn sys_getrandom(buf: usize, len: usize, _flags: usize) -> isize {
    axlog::debug!("sys_getrandom: buf={:#x}, len={}", buf, len);
    if len == 0 {
        return 0;
    }
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let thread = match pulse_core::task::current_thread() {
        Ok(thread) => thread,
        Err(e) => return -e.code() as isize,
    };
    let process = thread.process();

    let time_seed = axhal::time::monotonic_time_nanos() as u64;
    let pid_seed = process.pid();
    let tid_seed = thread.tid();
    let mut rng =
        SmallRng::seed_from_u64(time_seed ^ pid_seed.rotate_left(13) ^ tid_seed.rotate_left(29));

    let mut out = alloc::vec![0u8; len];
    rng.fill_bytes(&mut out);
    match uaccess::write_user_bytes(process, buf, &out) {
        Ok(()) => len as isize,
        Err(_) => -LinuxError::EFAULT.code() as isize,
    }
}

pub fn sys_prlimit64(_pid: usize, _resource: usize, _new_limit: usize, _old_limit: usize) -> isize {
    axlog::debug!("sys_prlimit64 (stub)");
    0
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
            let mut out = vec![0u8; read_len];
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
