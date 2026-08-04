use super::*;

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
static SYSLOG_PLACEHOLDER_WARNED: AtomicBool = AtomicBool::new(false);

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

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

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

    let hostname_handle = process.hostname_handle();
    let hostname_lock = hostname_handle.read();
    uts.nodename.copy_from_slice(&*hostname_lock);
    drop(hostname_lock);

    write_cstr_field(&mut uts.release, "6.1.0");
    write_cstr_field(&mut uts.version, "#1 PulseOS");
    #[cfg(target_arch = "riscv64")]
    write_cstr_field(&mut uts.machine, "riscv64");
    #[cfg(target_arch = "loongarch64")]
    write_cstr_field(&mut uts.machine, "loongarch64");
    write_cstr_field(&mut uts.domainname, "(none)");

    match uaccess::write_user_plain(process.as_ref(), buf, &uts) {
        Ok(()) => 0,
        Err(_) => -LinuxError::EFAULT.code() as isize,
    }
}

/// sys_sethostname - 设置系统主机名
pub fn sys_sethostname(name_addr: usize, len: usize) -> isize {
    axlog::debug!("sys_sethostname: name_addr={:#x}, len={}", name_addr, len);

    let process = match pulse_core::task::current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    // Only root user can change sethostname
    if process.euid() != 0 {
        return -LinuxError::EPERM.code() as isize;
    }

    if len > 64 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if name_addr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mut buf = [0u8; 64];
    if let Err(e) = crate::impls::utils::read_user_bytes(name_addr, &mut buf[..len]) {
        return -e.code() as isize;
    }

    let hostname_handle = process.hostname_handle();
    let mut hostname_lock = hostname_handle.write();
    hostname_lock.fill(0);
    hostname_lock[..len].copy_from_slice(&buf[..len]);

    0
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct Timeval {
    tv_sec: i64,
    tv_usec: i64,
}

#[repr(C)]
#[derive(Default, Copy, Clone)]
struct Rusage {
    ru_utime: Timeval,
    ru_stime: Timeval,
    ru_maxrss: i64,
    ru_ixrss: i64,
    ru_idrss: i64,
    ru_isrss: i64,
    ru_minflt: i64,
    ru_majflt: i64,
    ru_nswap: i64,
    ru_inblock: i64,
    ru_oublock: i64,
    ru_msgsnd: i64,
    ru_msgrcv: i64,
    ru_nsignals: i64,
    ru_nvcsw: i64,
    ru_nivcsw: i64,
}

pub fn sys_getrusage(who: i32, addr: usize) -> isize {
    axlog::debug!("sys_getrusage: who={}, addr={:#x}", who, addr);
    if who != (linux_raw_sys::general::RUSAGE_SELF as i32)
        && who != linux_raw_sys::general::RUSAGE_CHILDREN
        && who != (linux_raw_sys::general::RUSAGE_THREAD as i32)
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

    let (utime_ns, stime_ns) = match who {
        who if who == (linux_raw_sys::general::RUSAGE_SELF as i32)
            || who == (linux_raw_sys::general::RUSAGE_THREAD as i32) =>
        {
            let now_ns = axhal::time::monotonic_time_nanos() as u64;
            process.snapshot_cpu_time_ns(now_ns)
        }
        who if who == linux_raw_sys::general::RUSAGE_CHILDREN => {
            process.snapshot_children_cpu_time_ns()
        }
        _ => unreachable!(),
    };

    let ns_to_timeval = |ns: u64| -> Timeval {
        Timeval {
            tv_sec: (ns / 1_000_000_000) as i64,
            tv_usec: ((ns % 1_000_000_000) / 1000) as i64,
        }
    };

    let mut rusage = Rusage::default();
    rusage.ru_utime = ns_to_timeval(utime_ns);
    rusage.ru_stime = ns_to_timeval(stime_ns);

    match uaccess::write_user_plain(process.as_ref(), addr, &rusage) {
        Ok(()) => 0,
        Err(_) => -LinuxError::EFAULT.code() as isize,
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
    if resource != RLIMIT_STACK
        && resource != RLIMIT_NOFILE
        && resource != RLIMIT_MEMLOCK
        && resource != RLIMIT_CORE
        && resource != RLIMIT_DATA
        && resource != RLIMIT_SIGPENDING
    {
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
    let fs = FS_CONTEXT.lock().clone();
    let tmp = match axtask::future::block_on(fs.read_prefix(path, buflen)) {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
    match pulse_core::task::with_current_process(|process| process.write_user_bytes(buf, &tmp)) {
        Ok(Ok(())) => buflen as isize,
        Ok(Err(_)) => -LinuxError::EFAULT.code() as isize,
        Err(e) => -e.code() as isize,
    }
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
    if !SYSLOG_PLACEHOLDER_WARNED.swap(true, Ordering::AcqRel) {
        axlog::warn!(
            "sys_syslog: compatibility placeholder active; kernel log buffer is not persisted"
        );
    }
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

#[cfg(target_arch = "riscv64")]
#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct RiscvHwprobe {
    key: i64,
    value: u64,
}

#[cfg(target_arch = "riscv64")]
pub fn sys_riscv_hwprobe(
    pairs_addr: usize,
    pair_count: usize,
    cpusetsize: usize,
    cpus_addr: usize,
    flags: usize,
) -> isize {
    axlog::debug!(
        "sys_riscv_hwprobe: pairs_addr={:#x}, pair_count={}, cpusetsize={}, cpus_addr={:#x}, \
         flags={:#x}",
        pairs_addr,
        pair_count,
        cpusetsize,
        cpus_addr,
        flags
    );

    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if pairs_addr == 0 && pair_count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let res = pulse_core::task::with_current_process(|process| {
        let mut cpu_0_included = true;
        if cpus_addr != 0 && cpusetsize != 0 {
            let mut first_byte = 0u8;
            if process
                .read_user_bytes(cpus_addr, core::slice::from_mut(&mut first_byte))
                .is_err()
            {
                return Err(axerrno::AxError::BadAddress);
            }
            cpu_0_included = (first_byte & 1) != 0;
        }

        let mut pairs =
            match uaccess::read_user_plain_array::<RiscvHwprobe>(process, pairs_addr, pair_count) {
                Ok(p) => p,
                Err(e) => return Err(e),
            };

        const RISCV_HWPROBE_KEY_MVENDORID: i64 = 0;
        const RISCV_HWPROBE_KEY_MARCHID: i64 = 1;
        const RISCV_HWPROBE_KEY_MIMPID: i64 = 2;
        const RISCV_HWPROBE_KEY_BASE_BEHAVIOR: i64 = 3;
        const RISCV_HWPROBE_KEY_IMA_EXT_0: i64 = 4;
        const RISCV_HWPROBE_KEY_CPUPERF_0: i64 = 5;
        const RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE: i64 = 6;

        const RISCV_HWPROBE_BASE_BEHAVIOR_IMA: u64 = 1 << 0;

        const RISCV_HWPROBE_IMA_FD: u64 = 1 << 0;
        const RISCV_HWPROBE_IMA_C: u64 = 1 << 1;

        let mvendorid = sbi_rt::get_mvendorid() as u64;
        let marchid = sbi_rt::get_marchid() as u64;
        let mimpid = sbi_rt::get_mimpid() as u64;

        for pair in pairs.iter_mut() {
            if !cpu_0_included {
                match pair.key {
                    RISCV_HWPROBE_KEY_MVENDORID
                    | RISCV_HWPROBE_KEY_MARCHID
                    | RISCV_HWPROBE_KEY_MIMPID => {
                        pair.value = u64::MAX;
                    }
                    RISCV_HWPROBE_KEY_BASE_BEHAVIOR
                    | RISCV_HWPROBE_KEY_IMA_EXT_0
                    | RISCV_HWPROBE_KEY_CPUPERF_0
                    | RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE => {
                        pair.value = 0;
                    }
                    _ => {
                        pair.key = -1;
                        pair.value = 0;
                    }
                }
                continue;
            }

            match pair.key {
                RISCV_HWPROBE_KEY_MVENDORID => {
                    pair.value = mvendorid;
                }
                RISCV_HWPROBE_KEY_MARCHID => {
                    pair.value = marchid;
                }
                RISCV_HWPROBE_KEY_MIMPID => {
                    pair.value = mimpid;
                }
                RISCV_HWPROBE_KEY_BASE_BEHAVIOR => {
                    pair.value = RISCV_HWPROBE_BASE_BEHAVIOR_IMA;
                }
                RISCV_HWPROBE_KEY_IMA_EXT_0 => {
                    pair.value = RISCV_HWPROBE_IMA_FD | RISCV_HWPROBE_IMA_C;
                }
                RISCV_HWPROBE_KEY_CPUPERF_0 => {
                    pair.value = 0;
                }
                RISCV_HWPROBE_KEY_ZICBOZ_BLOCK_SIZE => {
                    pair.value = 64;
                }
                _ => {
                    pair.key = -1;
                    pair.value = 0;
                }
            }
        }

        uaccess::write_user_plain_array(process, pairs_addr, &pairs)
    });

    match res {
        Ok(Ok(())) => 0,
        Ok(Err(_)) => -LinuxError::EFAULT.code() as isize,
        Err(e) => -e.code() as isize,
    }
}
use linux_raw_sys::general::membarrier_cmd::*;

static REGISTERED_PRIVATE_EXPEDITED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static REGISTERED_PRIVATE_EXPEDITED_SYNC_CORE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
static REGISTERED_GLOBAL_EXPEDITED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

pub fn sys_membarrier(cmd: i32, flags: i32, _cpu_id: i32) -> isize {
    axlog::debug!("sys_membarrier: cmd={}, flags={}", cmd, flags);
    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let cmd_enum = match cmd {
        0 => MEMBARRIER_CMD_QUERY,
        1 => MEMBARRIER_CMD_GLOBAL,
        2 => MEMBARRIER_CMD_GLOBAL_EXPEDITED,
        4 => MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED,
        8 => MEMBARRIER_CMD_PRIVATE_EXPEDITED,
        16 => MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED,
        32 => MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,
        64 => MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        _ => return -LinuxError::EINVAL.code() as isize,
    };

    match cmd_enum {
        MEMBARRIER_CMD_GLOBAL => {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            0
        }

        MEMBARRIER_CMD_PRIVATE_EXPEDITED => {
            if REGISTERED_PRIVATE_EXPEDITED.load(core::sync::atomic::Ordering::Acquire) {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                0
            } else {
                -LinuxError::EPERM.code() as isize
            }
        }

        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED => {
            REGISTERED_PRIVATE_EXPEDITED.store(true, core::sync::atomic::Ordering::Release);
            0
        }

        MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE => {
            if REGISTERED_PRIVATE_EXPEDITED_SYNC_CORE.load(core::sync::atomic::Ordering::Acquire) {
                core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
                0
            } else {
                -LinuxError::EPERM.code() as isize
            }
        }

        MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => {
            REGISTERED_PRIVATE_EXPEDITED_SYNC_CORE
                .store(true, core::sync::atomic::Ordering::Release);
            0
        }

        MEMBARRIER_CMD_GLOBAL_EXPEDITED => {
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            0
        }

        MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED => {
            REGISTERED_GLOBAL_EXPEDITED.store(true, core::sync::atomic::Ordering::Release);
            0
        }

        _ => -LinuxError::EINVAL.code() as isize,
    }
}
