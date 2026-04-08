//! 其他杂项系统调用

use crate::LinuxError;

#[repr(C)]
struct UtsName {
    sysname: [u8; 65],
    nodename: [u8; 65],
    release: [u8; 65],
    version: [u8; 65],
    machine: [u8; 65],
    domainname: [u8; 65],
}

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

    let uts = unsafe { &mut *(buf as *mut UtsName) };
    // Keep values simple and stable for userspace probing.
    *uts = UtsName {
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
    0
}

pub fn sys_set_tid_address(tidptr: usize) -> isize {
    axlog::debug!("sys_set_tid_address: tidptr={:#x}", tidptr);
    sys_gettid()
}

pub fn sys_gettid() -> isize {
    axlog::debug!("sys_gettid");
    axtask::current().id().as_u64() as isize
}

pub fn sys_getrandom(buf: usize, len: usize, _flags: usize) -> isize {
    axlog::debug!("sys_getrandom: buf={:#x}, len={}", buf, len);
    if len == 0 {
        return 0;
    }
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    // Minimal non-cryptographic fallback for libc probes.
    let seed = axhal::time::monotonic_time_nanos() as u64;
    let out = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len) };
    let mut x = seed ^ 0x9e37_79b9_7f4a_7c15;
    for b in out.iter_mut() {
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        x = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
        *b = (x & 0xff) as u8;
    }
    len as isize
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
