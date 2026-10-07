use linux_raw_sys::general::{
    FUTEX_CLOCK_REALTIME, FUTEX_CMD_MASK, FUTEX_CMP_REQUEUE, FUTEX_PRIVATE_FLAG, FUTEX_REQUEUE,
    FUTEX_WAIT, FUTEX_WAIT_BITSET, FUTEX_WAKE, FUTEX_WAKE_BITSET,
};

use crate::{
    LinuxError,
    impls::utils::read_user_timespec,
    validation::{
        futex::{
            futex_deadline_remaining_ns, parse_futex_bitset, parse_futex_clock, parse_futex2_count,
            parse_futex2_flags, parse_futex2_mask, validate_futex_waitv, validate_futex_word_addr,
            validate_futex2_addr,
        },
        time::{duration_to_nanos_saturating, timespec_to_duration},
    },
};

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

fn read_futex2_timeout_ns(timeout: usize, clockid: i32) -> Result<Option<u64>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }
    let clock_realtime = parse_futex_clock(clockid as u32)?;
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

    let target = timespec_to_duration(read_user_timespec(timeout)?)?;
    let target_ns = duration_to_nanos_saturating(target);

    let now_ns = if clock_realtime {
        axhal::time::wall_time().as_nanos() as u64
    } else {
        axhal::time::monotonic_time_nanos() as u64
    };
    futex_deadline_remaining_ns(target_ns, now_ns).map(Some)
}

fn read_timeout_ns(timeout: usize) -> Result<Option<u64>, LinuxError> {
    if timeout == 0 {
        return Ok(None);
    }

    let duration = timespec_to_duration(read_user_timespec(timeout)?)?;
    Ok(Some(duration_to_nanos_saturating(duration)))
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

    if clock_realtime && cmd != FUTEX_WAIT_BITSET {
        return -LinuxError::ENOSYS.code() as isize;
    }

    match cmd {
        FUTEX_WAIT | FUTEX_WAIT_BITSET => {
            if cmd == FUTEX_WAIT_BITSET {
                if let Err(e) = validate_futex_word_addr(uaddr) {
                    return -e.code() as isize;
                }
            }
            let bitset = if cmd == FUTEX_WAIT_BITSET {
                match parse_futex_bitset(val3) {
                    Ok(bitset) => bitset,
                    Err(e) => return -e.code() as isize,
                }
            } else {
                u32::MAX
            };
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
            match process.futex_wait_mask(uaddr, val as u32, timeout_ns, is_private, bitset) {
                Ok(()) => 0,
                Err(e) => {
                    let errno: LinuxError = e.into();
                    -errno.code() as isize
                }
            }
        }
        FUTEX_WAKE => process.futex_wake(uaddr, val, is_private) as isize,
        FUTEX_WAKE_BITSET => {
            if let Err(e) = validate_futex_word_addr(uaddr) {
                return -e.code() as isize;
            }
            let bitset = match parse_futex_bitset(val3) {
                Ok(bitset) => bitset,
                Err(e) => return -e.code() as isize,
            };
            if process.read_user_u32(uaddr).is_err() {
                return -LinuxError::EFAULT.code() as isize;
            }
            process.futex_wake_mask(uaddr, (val as u32) as usize, is_private, bitset) as isize
        }
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

    let clock_realtime = match validate_futex_waitv(waiters, nr_futexes, flags, clockid) {
        Ok(clock_realtime) => clock_realtime,
        Err(e) => return -e.code() as isize,
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
