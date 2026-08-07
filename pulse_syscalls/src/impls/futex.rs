use linux_raw_sys::general::{
    CLOCK_MONOTONIC, CLOCK_REALTIME, FUTEX_32, FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK,
    FUTEX_CMP_REQUEUE, FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE, FUTEX_WAIT, FUTEX_WAIT_BITSET,
    FUTEX_WAKE, FUTEX2_PRIVATE, FUTEX2_SIZE_MASK,
};

use crate::{LinuxError, impls::utils::read_user_timespec};

const FUTEX2_SUPPORTED_FLAGS: u32 = FUTEX_32 | FUTEX2_PRIVATE;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Futex2Waiter {
    val: u64,
    uaddr: u64,
    flags: u32,
    reserved: u32,
}

struct ParsedFutex2Waiter {
    addr: usize,
    val: u32,
    is_private: bool,
}

fn parse_futex2_flags(flags: u32) -> Result<bool, LinuxError> {
    if flags & !FUTEX2_SUPPORTED_FLAGS != 0 || flags & FUTEX2_SIZE_MASK != FUTEX_32 {
        return Err(LinuxError::EINVAL);
    }
    Ok(flags & FUTEX2_PRIVATE != 0)
}

fn validate_futex2_addr(addr: usize) -> Result<(), LinuxError> {
    if addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    if addr & (core::mem::size_of::<u32>() - 1) != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

fn parse_futex2_mask(mask: usize) -> Result<u32, LinuxError> {
    if mask == 0 || mask > u32::MAX as usize {
        return Err(LinuxError::EINVAL);
    }
    Ok(mask as u32)
}

fn parse_futex2_count(count: isize) -> Result<usize, LinuxError> {
    if count < 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(count as usize)
}

fn read_futex2_timeout_ns(timeout: usize, clockid: i32) -> Result<Option<u64>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }
    let clock_realtime = match clockid as u32 {
        CLOCK_REALTIME => true,
        CLOCK_MONOTONIC => false,
        _ => return Err(LinuxError::EINVAL),
    };
    read_absolute_timeout_ns(timeout, clock_realtime)
}

fn read_futex2_waiter(
    process: &pulse_core::task::Process,
    addr: usize,
) -> Result<ParsedFutex2Waiter, LinuxError> {
    let mut waiter = Futex2Waiter::default();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            &mut waiter as *mut Futex2Waiter as *mut u8,
            core::mem::size_of::<Futex2Waiter>(),
        )
    };
    process
        .read_user_bytes(addr, bytes)
        .map_err(|_| LinuxError::EFAULT)?;
    if waiter.reserved != 0 {
        return Err(LinuxError::EINVAL);
    }
    let is_private = parse_futex2_flags(waiter.flags)?;
    let addr = usize::try_from(waiter.uaddr).map_err(|_| LinuxError::EFAULT)?;
    validate_futex2_addr(addr)?;
    let val = u32::try_from(waiter.val).map_err(|_| LinuxError::EINVAL)?;
    Ok(ParsedFutex2Waiter {
        addr,
        val,
        is_private,
    })
}

fn read_absolute_timeout_ns(
    timeout: usize,
    clock_realtime: bool,
) -> Result<Option<u64>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }

    let ts = read_user_timespec(timeout)?;
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LinuxError::EINVAL);
    }

    let target_ns = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);

    let now_ns = if clock_realtime {
        axhal::time::wall_time().as_nanos() as u64
    } else {
        axhal::time::monotonic_time_nanos() as u64
    };
    if target_ns <= now_ns {
        return Err(LinuxError::ETIMEDOUT);
    }

    Ok(Some(target_ns - now_ns))
}

fn read_timeout_ns(timeout: usize) -> Result<Option<u64>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }

    let ts = read_user_timespec(timeout)?;
    if ts.tv_sec < 0 || ts.tv_nsec < 0 || ts.tv_nsec >= 1_000_000_000 {
        return Err(LinuxError::EINVAL);
    }

    let sec = (ts.tv_sec as u64).saturating_mul(1_000_000_000);
    let nsec = ts.tv_nsec as u64;
    Ok(Some(sec.saturating_add(nsec)))
}

pub fn sys_futex(
    uaddr: usize,
    op: i32,
    val: usize,
    timeout_or_val2: usize,
    uaddr2: usize,
    val3: usize,
) -> isize {
    axlog::debug!(
        "sys_futex: uaddr={:#x}, op={:#x}, val={}, timeout/val2={:#x}, uaddr2={:#x}, val3={}",
        uaddr,
        op,
        val,
        timeout_or_val2,
        uaddr2,
        val3
    );
    if uaddr == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let cmd = (op & FUTEX_CMD_MASK) as u32;
    let is_private = (op & (FUTEX_PRIVATE_FLAG as i32)) != 0;
    let clock_realtime = (op & (FUTEX_CLOCK_REALTIME as i32)) != 0;

    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            if cmd == FUTEX_WAIT_BITSET && val3 == 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            let timeout_ns = if cmd == FUTEX_WAIT_BITSET {
                match read_absolute_timeout_ns(timeout_or_val2, clock_realtime) {
                    Ok(timeout) => timeout,
                    Err(LinuxError::ETIMEDOUT) => return -LinuxError::ETIMEDOUT.code() as isize,
                    Err(e) => return -e.code() as isize,
                }
            } else {
                match read_timeout_ns(timeout_or_val2) {
                    Ok(timeout) => timeout,
                    Err(e) => return -e.code() as isize,
                }
            };
            match process.futex_wait(uaddr, val as u32, timeout_ns, is_private) {
                Ok(()) => 0,
                Err(e) => {
                    let errno: LinuxError = e.into();
                    -errno.code() as isize
                }
            }
        }
        FUTEX_WAKE => process.futex_wake(uaddr, val, is_private) as isize,
        FUTEX_REQUEUE => {
            if (val as isize) < 0 || (timeout_or_val2 as isize) < 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            if uaddr2 == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            process.futex_requeue(uaddr, val, uaddr2, timeout_or_val2, is_private) as isize
        }
        FUTEX_CMP_REQUEUE => {
            if (val as isize) < 0 || (timeout_or_val2 as isize) < 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            if uaddr2 == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            match process.read_user_u32(uaddr) {
                Ok(current) if current == val3 as u32 => {
                    process.futex_requeue(uaddr, val, uaddr2, timeout_or_val2, is_private) as isize
                }
                Ok(_) => -LinuxError::EAGAIN.code() as isize,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            }
        }
        _ => {
            axlog::warn!("unsupported futex op: {:#x}", op);
            -LinuxError::ENOSYS.code() as isize
        }
    }
}

pub fn sys_futex_waitv(
    waiters: usize,
    nr_futexes: u32,
    flags: u32,
    timeout: usize,
    clockid: u32,
) -> isize {
    axlog::debug!(
        "sys_futex_waitv: waiters={:#x}, nr_futexes={}, flags={}, timeout={:#x}, clockid={}",
        waiters,
        nr_futexes,
        flags,
        timeout,
        clockid
    );

    if flags != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if nr_futexes == 0 || nr_futexes > 128 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if waiters == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if waiters % 8 != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let clock_realtime = match clockid {
        0 => true,  // CLOCK_REALTIME
        1 => false, // CLOCK_MONOTONIC
        _ => return -LinuxError::EINVAL.code() as isize,
    };

    let timeout_ns = match read_absolute_timeout_ns(timeout, clock_realtime) {
        Ok(t) => t,
        Err(LinuxError::ETIMEDOUT) => return -LinuxError::ETIMEDOUT.code() as isize,
        Err(e) => return -e.code() as isize,
    };

    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };

    match process.futex_waitv(waiters, nr_futexes, flags, timeout_ns) {
        Ok(idx) => idx,
        Err(e) => {
            let errno: LinuxError = e.into();
            -errno.code() as isize
        }
    }
}

pub fn sys_futex_wake(uaddr: usize, mask: usize, nr: isize, flags: u32) -> isize {
    let is_private = match parse_futex2_flags(flags) {
        Ok(is_private) => is_private,
        Err(e) => return -e.code() as isize,
    };
    let mask = match validate_futex2_addr(uaddr).and_then(|_| parse_futex2_mask(mask)) {
        Ok(mask) => mask,
        Err(e) => return -e.code() as isize,
    };
    let nr = match parse_futex2_count(nr) {
        Ok(nr) => nr,
        Err(e) => return -e.code() as isize,
    };
    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    if process.read_user_u32(uaddr).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }
    process.futex_wake_mask(uaddr, nr, is_private, mask) as isize
}

pub fn sys_futex_wait(
    uaddr: usize,
    val: usize,
    mask: usize,
    flags: u32,
    timeout: usize,
    clockid: i32,
) -> isize {
    let is_private = match parse_futex2_flags(flags) {
        Ok(is_private) => is_private,
        Err(e) => return -e.code() as isize,
    };
    let mask = match validate_futex2_addr(uaddr).and_then(|_| parse_futex2_mask(mask)) {
        Ok(mask) => mask,
        Err(e) => return -e.code() as isize,
    };
    let expected = match u32::try_from(val) {
        Ok(value) => value,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    let timeout_ns = match read_futex2_timeout_ns(timeout, clockid) {
        Ok(timeout) => timeout,
        Err(e) => return -e.code() as isize,
    };
    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    match process.futex_wait_mask(uaddr, expected, timeout_ns, is_private, mask) {
        Ok(()) => 0,
        Err(e) => {
            let errno: LinuxError = e.into();
            -errno.code() as isize
        }
    }
}

pub fn sys_futex_requeue(waiters: usize, flags: u32, nr_wake: isize, nr_requeue: isize) -> isize {
    if flags != 0 || waiters == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let nr_wake = match parse_futex2_count(nr_wake) {
        Ok(count) => count,
        Err(e) => return -e.code() as isize,
    };
    let nr_requeue = match parse_futex2_count(nr_requeue) {
        Ok(count) => count,
        Err(e) => return -e.code() as isize,
    };
    let process = match pulse_core::task::current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let source = match read_futex2_waiter(process.as_ref(), waiters) {
        Ok(waiter) => waiter,
        Err(e) => return -e.code() as isize,
    };
    let target_addr = match waiters.checked_add(core::mem::size_of::<Futex2Waiter>()) {
        Some(addr) => addr,
        None => return -LinuxError::EFAULT.code() as isize,
    };
    let target = match read_futex2_waiter(process.as_ref(), target_addr) {
        Ok(waiter) => waiter,
        Err(e) => return -e.code() as isize,
    };
    if source.is_private != target.is_private {
        return -LinuxError::EINVAL.code() as isize;
    }
    match process.read_user_u32(source.addr) {
        Ok(current) if current == source.val => {}
        Ok(_) => return -LinuxError::EAGAIN.code() as isize,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    }
    if process.read_user_u32(target.addr).is_err() {
        return -LinuxError::EFAULT.code() as isize;
    }

    process.futex_requeue(
        source.addr,
        nr_wake,
        target.addr,
        nr_requeue,
        source.is_private,
    ) as isize
}
