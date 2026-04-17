use crate::LinuxError;
use crate::impls::utils::read_user_timespec;
use axerrno::AxError;

const FUTEX_WAIT: i32 = 0;
const FUTEX_WAKE: i32 = 1;
const FUTEX_REQUEUE: i32 = 3;
const FUTEX_CMP_REQUEUE: i32 = 4;
const FUTEX_CMD_MASK: i32 = 0x7f;

fn ax_error_to_linux(e: AxError) -> LinuxError {
    e.into()
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

    match cmd {
        FUTEX_WAIT => {
            let timeout_ns = match read_timeout_ns(timeout_or_val2) {
                Ok(timeout) => timeout,
                Err(e) => return -e.code() as isize,
            };
            match process.futex_wait(uaddr, val as u32, timeout_ns) {
                Ok(()) => 0,
                Err(e) => {
                    let errno = ax_error_to_linux(e);
                    -errno.code() as isize
                }
            }
        }
        FUTEX_WAKE => process.futex_wake(uaddr, val) as isize,
        FUTEX_REQUEUE => {
            if uaddr2 == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            process.futex_requeue(uaddr, val, uaddr2, timeout_or_val2) as isize
        }
        FUTEX_CMP_REQUEUE => {
            if uaddr2 == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            match process.read_user_u32(uaddr) {
                Ok(current) if current == val3 as u32 => {
                    process.futex_requeue(uaddr, val, uaddr2, timeout_or_val2) as isize
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
