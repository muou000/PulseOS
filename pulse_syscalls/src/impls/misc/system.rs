use core::mem::MaybeUninit;

use linux_raw_sys::{
    general::{
        AT_FDCWD, CAP_SYS_BOOT, LINUX_REBOOT_CMD_CAD_OFF, LINUX_REBOOT_CMD_CAD_ON,
        LINUX_REBOOT_CMD_HALT, LINUX_REBOOT_CMD_POWER_OFF, LINUX_REBOOT_CMD_RESTART,
        LINUX_REBOOT_CMD_RESTART2, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2, LINUX_REBOOT_MAGIC2A,
        LINUX_REBOOT_MAGIC2B, LINUX_REBOOT_MAGIC2C,
    },
    mempolicy::{MPOL_DEFAULT, MPOL_F_ADDR, MPOL_F_MEMS_ALLOWED, MPOL_F_NODE},
};

use super::*;
use crate::impls::fs::common::context_for_dirfd;
use crate::impls::flush_filesystems_for_shutdown;

const MPOL_QUERY_FLAGS: usize = (MPOL_F_ADDR | MPOL_F_MEMS_ALLOWED | MPOL_F_NODE) as usize;
const REBOOT_RESTART2_ARG_MAX: usize = 256;

static CAD_ENABLED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RebootAction {
    Restart,
    Restart2,
    Halt,
    PowerOff,
    SetCad(bool),
}

/// A reset or power transition must not bypass dirty filesystem state.
///
/// CAD toggles only change the automatic-reboot policy and therefore do not
/// need to enter the writeback barrier.
fn reboot_action_requires_filesystem_flush(action: RebootAction) -> bool {
    matches!(
        action,
        RebootAction::Restart
            | RebootAction::Restart2
            | RebootAction::Halt
            | RebootAction::PowerOff
    )
}

fn decode_reboot_action(
    magic1: usize,
    magic2: usize,
    cmd: usize,
) -> Result<RebootAction, LinuxError> {
    let valid_magic2 = matches!(
        magic2 as u32,
        LINUX_REBOOT_MAGIC2 | LINUX_REBOOT_MAGIC2A | LINUX_REBOOT_MAGIC2B | LINUX_REBOOT_MAGIC2C
    );
    if magic1 as u32 != LINUX_REBOOT_MAGIC1 || !valid_magic2 {
        return Err(LinuxError::EINVAL);
    }

    match cmd as u32 {
        LINUX_REBOOT_CMD_RESTART => Ok(RebootAction::Restart),
        LINUX_REBOOT_CMD_RESTART2 => Ok(RebootAction::Restart2),
        LINUX_REBOOT_CMD_HALT => Ok(RebootAction::Halt),
        LINUX_REBOOT_CMD_POWER_OFF => Ok(RebootAction::PowerOff),
        LINUX_REBOOT_CMD_CAD_ON => Ok(RebootAction::SetCad(true)),
        LINUX_REBOOT_CMD_CAD_OFF => Ok(RebootAction::SetCad(false)),
        _ => Err(LinuxError::EINVAL),
    }
}

fn validate_restart2_arg(arg: usize) -> Result<(), LinuxError> {
    // Linux accepts a reboot command string of up to 255 bytes and truncates
    // longer strings. PulseOS has no boot-command handoff yet, but still
    // validates the user pointer so restart2 preserves Linux's EFAULT rule.
    let mut command = [MaybeUninit::<u8>::uninit(); REBOOT_RESTART2_ARG_MAX];
    match crate::impls::utils::read_user_cstring_to_slice(arg, &mut command) {
        Ok(_) | Err(LinuxError::ENAMETOOLONG) => Ok(()),
        Err(_) => Err(LinuxError::EFAULT),
    }
}

fn reset_system() -> isize {
    match axhal::power::system_reset() {
        Ok(never) => match never {},
        Err(axhal::power::SystemResetError::NotSupported) => -LinuxError::ENOSYS.code() as isize,
        Err(axhal::power::SystemResetError::Firmware(error)) => {
            axlog::error!("sys_reboot: platform reset failed with firmware error {error}");
            -LinuxError::EIO.code() as isize
        }
    }
}

fn flush_before_power_transition() -> Result<(), isize> {
    flush_filesystems_for_shutdown().map_err(|error| -error.code() as isize)
}

/// Implements Linux `reboot(2)` for the shared RISC-V64/LoongArch64 syscall ABI.
pub fn sys_reboot(magic1: usize, magic2: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!(
        "sys_reboot: magic1={:#x}, magic2={:#x}, cmd={:#x}, arg={:#x}",
        magic1,
        magic2,
        cmd,
        arg
    );

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(error) => return -error.code() as isize,
    };
    // Linux checks CAP_SYS_BOOT, not merely euid == 0. This keeps a process
    // that has dropped its effective capabilities from resetting the machine.
    if !process.has_capability(CAP_SYS_BOOT) {
        return -LinuxError::EPERM.code() as isize;
    }

    let action = match decode_reboot_action(magic1, magic2, cmd) {
        Ok(action) => action,
        Err(error) => return -error.code() as isize,
    };

    // Validate restart2's user pointer before doing any irreversible work.
    if matches!(action, RebootAction::Restart2)
        && let Err(error) = validate_restart2_arg(arg)
    {
        return -error.code() as isize;
    }

    if reboot_action_requires_filesystem_flush(action) {
        if let Err(error) = flush_before_power_transition() {
            axlog::error!(
                "sys_reboot: refusing power transition because filesystem writeback failed: {}",
                error
            );
            return error;
        }
    }

    match action {
        RebootAction::Restart => reset_system(),
        RebootAction::Restart2 => reset_system(),
        RebootAction::Halt | RebootAction::PowerOff => axhal::power::system_off(),
        RebootAction::SetCad(enabled) => {
            CAD_ENABLED.store(enabled, Ordering::Release);
            0
        }
    }
}

fn mempolicy_nodemask_bytes(nodemask: usize, maxnode: usize) -> Result<usize, LinuxError> {
    if nodemask == 0 {
        return Ok(0);
    }
    if maxnode == 0 {
        return Err(LinuxError::EINVAL);
    }

    let word_bits = usize::BITS as usize;
    let words = maxnode
        .checked_add(word_bits - 1)
        .ok_or(LinuxError::EINVAL)?
        / word_bits;
    words
        .checked_mul(core::mem::size_of::<usize>())
        .ok_or(LinuxError::EINVAL)
}

pub fn sys_get_mempolicy(
    mode: usize,
    nodemask: usize,
    maxnode: usize,
    addr: usize,
    flags: usize,
) -> isize {
    axlog::debug!(
        "sys_get_mempolicy: mode={:#x}, nodemask={:#x}, maxnode={}, addr={:#x}, flags={:#x}",
        mode,
        nodemask,
        maxnode,
        addr,
        flags
    );

    if flags & !MPOL_QUERY_FLAGS != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let query_addr = flags & MPOL_F_ADDR as usize != 0;
    let query_node = flags & MPOL_F_NODE as usize != 0;
    let mems_allowed = flags & MPOL_F_MEMS_ALLOWED as usize != 0;
    if (mems_allowed && flags != MPOL_F_MEMS_ALLOWED as usize)
        || (query_node && !query_addr)
        || (!mems_allowed && !query_addr && addr != 0)
    {
        return -LinuxError::EINVAL.code() as isize;
    }

    let nodemask_bytes = if query_node {
        0
    } else {
        match mempolicy_nodemask_bytes(nodemask, maxnode) {
            Ok(bytes) => bytes,
            Err(e) => return -e.code() as isize,
        }
    };

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    if query_addr && (addr == 0 || !process.is_mapped_range(addr, 1)) {
        return -LinuxError::EFAULT.code() as isize;
    }

    let mode_value = if query_node { 0 } else { MPOL_DEFAULT as i32 };
    if mode != 0 && process.write_user_i32(mode, mode_value).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }

    if nodemask_bytes != 0 {
        let mut output = match alloc_zeroed_bytes(nodemask_bytes, "sys_get_mempolicy.nodemask") {
            Ok(output) => output,
            Err(e) => return -e.code() as isize,
        };
        if mems_allowed {
            output[0] = 1;
        }
        if process.write_user_bytes(nodemask, &output).is_err() {
            return -LinuxError::EFAULT.code() as isize;
        }
    }

    0
}

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
        && resource != RLIMIT_FSIZE
        && resource != RLIMIT_NOFILE
        && resource != RLIMIT_MEMLOCK
        && resource != RLIMIT_CORE
        && resource != RLIMIT_DATA
        && resource != RLIMIT_AS
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

        // Raising a soft or hard limit requires CAP_SYS_RESOURCE.  The
        // RLIMIT_NOFILE hard limit is also bounded by the kernel-wide
        // descriptor limit, including for privileged callers.
        let has_sys_resource =
            process.has_capability(linux_raw_sys::general::CAP_SYS_RESOURCE);
        if !has_sys_resource
            && (new_rlim.rlim_cur > old_rlim.rlim_cur
                || new_rlim.rlim_max > old_rlim.rlim_max)
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if resource == RLIMIT_NOFILE
            && new_rlim.rlim_max > pulse_core::fd_table::FD_LIMIT as u64
        {
            return -LinuxError::EPERM.code() as isize;
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

/// `setrlimit(resource, new_limit)` is the RISC-V64 ABI entry point backed by
/// the same per-process resource state as `prlimit64`.
#[cfg(target_arch = "riscv64")]
pub fn sys_setrlimit(resource: usize, new_limit: usize) -> isize {
    sys_prlimit64(0, resource, new_limit, 0)
}

pub fn sys_getrandom(buf: usize, buflen: usize, flags: usize) -> isize {
    let flags = flags as u32;
    if flags & !(GRND_RANDOM | GRND_NONBLOCK | GRND_INSECURE) != 0
        || flags & (GRND_RANDOM | GRND_INSECURE) == (GRND_RANDOM | GRND_INSECURE)
    {
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
    let fs = match context_for_dirfd(AT_FDCWD as i32) {
        Ok(fs) => fs,
        Err(e) => return -e.code() as isize,
    };
    let tmp = match axtask::future::block_on(fs.read_prefix(path, buflen)) {
        Ok(buf) => buf,
        Err(e) => return -e.code() as isize,
    };
    match pulse_core::task::with_current_process(|process| process.write_user_bytes(buf, &tmp)) {
        Ok(Ok(())) => tmp.len() as isize,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reboot_accepts_every_linux_magic2_value() {
        for magic2 in [
            LINUX_REBOOT_MAGIC2,
            LINUX_REBOOT_MAGIC2A,
            LINUX_REBOOT_MAGIC2B,
            LINUX_REBOOT_MAGIC2C,
        ] {
            assert_eq!(
                decode_reboot_action(
                    LINUX_REBOOT_MAGIC1 as usize,
                    magic2 as usize,
                    LINUX_REBOOT_CMD_RESTART as usize,
                ),
                Ok(RebootAction::Restart)
            );
        }
    }

    #[test]
    fn reboot_rejects_bad_magic_and_unsupported_commands() {
        assert_eq!(
            decode_reboot_action(
                (LINUX_REBOOT_MAGIC1 ^ 1) as usize,
                LINUX_REBOOT_MAGIC2 as usize,
                LINUX_REBOOT_CMD_RESTART as usize,
            ),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            decode_reboot_action(
                LINUX_REBOOT_MAGIC1 as usize,
                LINUX_REBOOT_MAGIC2 as usize,
                linux_raw_sys::general::LINUX_REBOOT_CMD_KEXEC as usize,
            ),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn reboot_decodes_supported_actions() {
        let magic1 = LINUX_REBOOT_MAGIC1 as usize;
        let magic2 = LINUX_REBOOT_MAGIC2 as usize;

        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_RESTART2 as usize),
            Ok(RebootAction::Restart2)
        );
        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_HALT as usize),
            Ok(RebootAction::Halt)
        );
        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_POWER_OFF as usize),
            Ok(RebootAction::PowerOff)
        );
        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_CAD_ON as usize),
            Ok(RebootAction::SetCad(true))
        );
        assert_eq!(
            decode_reboot_action(magic1, magic2, LINUX_REBOOT_CMD_CAD_OFF as usize),
            Ok(RebootAction::SetCad(false))
        );
    }

    #[test]
    fn reboot_power_transitions_require_writeback_barrier() {
        assert!(reboot_action_requires_filesystem_flush(RebootAction::Restart));
        assert!(reboot_action_requires_filesystem_flush(RebootAction::Restart2));
        assert!(reboot_action_requires_filesystem_flush(RebootAction::Halt));
        assert!(reboot_action_requires_filesystem_flush(RebootAction::PowerOff));
        assert!(!reboot_action_requires_filesystem_flush(RebootAction::SetCad(true)));
        assert!(!reboot_action_requires_filesystem_flush(RebootAction::SetCad(false)));
    }
}
