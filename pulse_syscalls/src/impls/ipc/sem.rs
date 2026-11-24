//! System V semaphore syscall implementations.

use core::time::Duration;

use axerrno::{LinuxError, LinuxResult};
use ipc::sem::{
    self, GETALL, GETNCNT, GETPID, GETVAL, GETZCNT, IPC_RMID, IPC_SET, IPC_STAT, SETALL, SETVAL,
    SemBuf, SemSet, SemidDs,
};
use pulse_core::task::{current_process, current_thread, uaccess};

use crate::impls::utils::read_user_timespec;

fn read_timeout(timeout: usize) -> LinuxResult<Option<Duration>> {
    if timeout == 0 {
        return Ok(None);
    }
    let ts = read_user_timespec(timeout)?;
    if ts.tv_sec < 0 || !(0..1_000_000_000).contains(&ts.tv_nsec) {
        return Err(LinuxError::EINVAL);
    }
    let nanos = (ts.tv_sec as u64)
        .saturating_mul(1_000_000_000)
        .saturating_add(ts.tv_nsec as u64);
    Ok(Some(Duration::from_nanos(nanos)))
}

/// Creates a semaphore set or obtains its ID by key.
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> isize {
    axlog::debug!(
        "sys_semget: key={}, nsems={}, semflg={:#o}",
        key,
        nsems,
        semflg
    );
    current_process()
        .and_then(|process| sem::get_or_create(key, nsems, semflg, process.pid() as i32))
        .map(|id| id as isize)
        .unwrap_or_else(|e| -e.code() as isize)
}

fn semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> LinuxResult<isize> {
    let process = current_process()?;
    let pid = process.pid() as i32;
    let set = SemSet::lookup(semid)?;

    if arg == 0 && matches!(cmd, IPC_STAT | IPC_SET | GETALL | SETALL) {
        return Err(LinuxError::EFAULT);
    }
    match cmd {
        IPC_RMID => set.remove()?,
        IPC_STAT => {
            uaccess::write_user_value(&process, arg, &set.status()?)
                .map_err(|_| LinuxError::EFAULT)?;
        }
        IPC_SET => {
            let ds: SemidDs =
                uaccess::read_user_value(&process, arg).map_err(|_| LinuxError::EFAULT)?;
            set.set_permissions(ds.sem_perm)?;
        }
        GETVAL | GETPID | GETNCNT | GETZCNT => return set.get_scalar(semnum, cmd),
        SETVAL => set.set_value(semnum, arg as i32, pid)?,
        GETALL => {
            uaccess::write_user_value_array(&process, arg, &set.values()?)
                .map_err(|_| LinuxError::EFAULT)?;
        }
        SETALL => {
            let values =
                uaccess::read_user_value_array_sequential(&process, arg, set.status()?.sem_nsems)
                    .map_err(|_| LinuxError::EFAULT)?;
            set.set_values(&values, pid)?;
        }
        _ => return Err(LinuxError::EINVAL),
    }
    Ok(0)
}

/// Decodes the semaphore control command and its scalar or pointer argument.
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> isize {
    axlog::debug!(
        "sys_semctl: semid={}, semnum={}, cmd={}, arg={:#x}",
        semid,
        semnum,
        cmd,
        arg
    );
    semctl(semid, semnum, cmd, arg).unwrap_or_else(|e| -e.code() as isize)
}

fn semtimedop(semid: i32, sops: usize, nsops: usize, timeout: usize) -> LinuxResult {
    if nsops == 0 {
        return Err(LinuxError::EINVAL);
    }
    let thread = current_thread()?;
    let process = thread.process();
    let ops = uaccess::read_user_value_array_sequential::<SemBuf>(&process, sops, nsops)
        .map_err(|_| LinuxError::EFAULT)?;
    let set = SemSet::lookup(semid)?;
    let timeout = read_timeout(timeout)?;
    set.operate(
        &ops,
        process.pid() as i32,
        &process.ipc.sem_undos,
        timeout,
        thread.signal_wait_queue(),
        || thread.has_pending_signal(),
    )
}

/// Applies the supplied semaphore operations with an optional relative timeout.
pub fn sys_semtimedop(semid: i32, sops: usize, nsops: usize, timeout: usize) -> isize {
    axlog::debug!(
        "sys_semtimedop: semid={}, sops={:#x}, nsops={}, timeout={:#x}",
        semid,
        sops,
        nsops,
        timeout
    );
    semtimedop(semid, sops, nsops, timeout)
        .map(|()| 0)
        .unwrap_or_else(|e| -e.code() as isize)
}

/// Applies the supplied semaphore operations.
pub fn sys_semop(semid: i32, sops: usize, nsops: usize) -> isize {
    sys_semtimedop(semid, sops, nsops, 0)
}
