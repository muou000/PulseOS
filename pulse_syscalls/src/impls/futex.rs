use crate::{LinuxError, impls::utils::read_user_timespec};

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_REQUEUE: i32 = 3;
const FUTEX_CMP_REQUEUE: i32 = 4;
const FUTEX_WAIT_BITSET: i32 = 9;
const FUTEX_CMD_MASK: i32 = 0x7f;

fn read_absolute_timeout_ns(timeout: usize, clock_realtime: bool) -> Result<Option<u64>, LinuxError> {
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
    let cmd = op & FUTEX_CMD_MASK;
    let is_private = (op & 0x80) != 0;
    let clock_realtime = (op & 0x100) != 0;

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
            if uaddr2 == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            process.futex_requeue(uaddr, val, uaddr2, timeout_or_val2, is_private) as isize
        }
        FUTEX_CMP_REQUEUE => {
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
        waiters, nr_futexes, flags, timeout, clockid
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
