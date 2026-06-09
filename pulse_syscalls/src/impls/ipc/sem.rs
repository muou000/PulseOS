//! System V semaphore syscall implementations.

use alloc::vec::Vec;
use axerrno::LinuxError;
use pulse_core::ipc::sem::{
    IPC_CREAT, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, GETALL, GETNCNT, GETPID, GETVAL,
    GETZCNT, SEM_MANAGER, SETALL, SETVAL, SemBuf, SemUndoEntry, SemidDs,
};
use pulse_core::task::current_thread;
use crate::impls::utils::read_user_timespec;

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

/// semget: create or get a semaphore set.
///
/// args[0] = key (i32)
/// args[1] = nsems (i32)
/// args[2] = semflg (i32)
pub fn sys_semget(key: i32, nsems: i32, semflg: i32) -> isize {
    axlog::debug!(
        "sys_semget: key={}, nsems={}, semflg={:#o}",
        key,
        nsems,
        semflg
    );

    if nsems < 0 || nsems > 250 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let pid = match pulse_core::task::current_process() {
        Ok(proc) => proc.pid() as i32,
        Err(e) => return -e.code() as isize,
    };

    let mut manager = SEM_MANAGER.lock();

    if key != IPC_PRIVATE && (semflg & IPC_CREAT) == 0 {
        match manager.get_semid_by_key(key) {
            Some(semid) => return semid as isize,
            None => return -LinuxError::ENOENT.code() as isize,
        }
    }

    match manager.create_sem(key, nsems as usize, semflg, pid) {
        Ok(semid) => semid as isize,
        Err(e) => -LinuxError::from(e).code() as isize,
    }
}

/// semctl: semaphore control operations.
///
/// args[0] = semid (i32)
/// args[1] = semnum (i32)
/// args[2] = cmd (i32)
/// args[3] = arg (usize, pointer or value)
pub fn sys_semctl(semid: i32, semnum: i32, cmd: i32, arg: usize) -> isize {
    axlog::debug!(
        "sys_semctl: semid={}, semnum={}, cmd={}, arg={:#x}",
        semid,
        semnum,
        cmd,
        arg
    );

    let process = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let semset_arc = {
        let manager = SEM_MANAGER.lock();
        match manager.get_inner_by_semid(semid) {
            Some(semset) => semset,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    };

    let mut semset = semset_arc.lock();

    if semset.removed {
        return -LinuxError::EIDRM.code() as isize;
    }

    match cmd {
        IPC_RMID => {
            semset.removed = true;
            semset.wait_queue.notify_all(true);
            drop(semset);
            let mut manager = SEM_MANAGER.lock();
            manager.remove_semid(semid);
            0
        }
        IPC_STAT => {
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let ds = semset.semid_ds;
            match pulse_core::task::uaccess::write_user_plain(process.as_ref(), arg, &ds) {
                Ok(()) => 0,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            }
        }
        IPC_SET => {
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let new_ds: SemidDs = match pulse_core::task::uaccess::read_user_plain(process.as_ref(), arg) {
                Ok(v) => v,
                Err(_) => return -LinuxError::EFAULT.code() as isize,
            };
            semset.semid_ds.sem_perm.uid = new_ds.sem_perm.uid;
            semset.semid_ds.sem_perm.gid = new_ds.sem_perm.gid;
            semset.semid_ds.sem_perm.mode = (new_ds.sem_perm.mode & 0o777) | (semset.semid_ds.sem_perm.mode & !0o777);
            semset.semid_ds.sem_ctime = axhal::time::wall_time().as_secs() as i64;
            0
        }
        GETVAL => {
            if semnum < 0 || semnum as usize >= semset.nsems {
                return -LinuxError::EINVAL.code() as isize;
            }
            semset.sems[semnum as usize].semval as isize
        }
        SETVAL => {
            if semnum < 0 || semnum as usize >= semset.nsems {
                return -LinuxError::EINVAL.code() as isize;
            }
            let val = arg as i32;
            if val < 0 || val > 65535 {
                return -LinuxError::EINVAL.code() as isize;
            }
            semset.sems[semnum as usize].semval = val as u16;
            semset.sems[semnum as usize].sempid = process.pid() as i32;
            semset.semid_ds.sem_ctime = axhal::time::wall_time().as_secs() as i64;
            semset.wait_queue.notify_all(true);
            0
        }
        GETPID => {
            if semnum < 0 || semnum as usize >= semset.nsems {
                return -LinuxError::EINVAL.code() as isize;
            }
            semset.sems[semnum as usize].sempid as isize
        }
        GETNCNT => {
            if semnum < 0 || semnum as usize >= semset.nsems {
                return -LinuxError::EINVAL.code() as isize;
            }
            semset.sems[semnum as usize].semncnt as isize
        }
        GETZCNT => {
            if semnum < 0 || semnum as usize >= semset.nsems {
                return -LinuxError::EINVAL.code() as isize;
            }
            semset.sems[semnum as usize].semzcnt as isize
        }
        GETALL => {
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let vals: Vec<u16> = semset.sems.iter().map(|s| s.semval).collect();
            match pulse_core::task::uaccess::write_user_plain_array(process.as_ref(), arg, &vals) {
                Ok(()) => 0,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            }
        }
        SETALL => {
            if arg == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let vals: Vec<u16> = match pulse_core::task::uaccess::read_user_plain_array(process.as_ref(), arg, semset.nsems) {
                Ok(v) => v,
                Err(_) => return -LinuxError::EFAULT.code() as isize,
            };
            for (i, val) in vals.into_iter().enumerate() {
                semset.sems[i].semval = val;
                semset.sems[i].sempid = process.pid() as i32;
            }
            semset.semid_ds.sem_ctime = axhal::time::wall_time().as_secs() as i64;
            semset.wait_queue.notify_all(true);
            0
        }
        _ => -LinuxError::EINVAL.code() as isize,
    }
}

fn check_ops(sems: &[pulse_core::ipc::sem::Sem], sops: &[SemBuf]) -> bool {
    let mut temp_vals: Vec<u16> = sems.iter().map(|s| s.semval).collect();
    for op in sops {
        let idx = op.sem_num as usize;
        if idx >= temp_vals.len() {
            return false;
        }
        if op.sem_op > 0 {
            temp_vals[idx] = temp_vals[idx].saturating_add(op.sem_op as u16);
        } else if op.sem_op == 0 {
            if temp_vals[idx] != 0 {
                return false;
            }
        } else {
            let val = (-op.sem_op) as u16;
            if temp_vals[idx] < val {
                return false;
            }
            temp_vals[idx] -= val;
        }
    }
    true
}

fn apply_ops(sems: &mut [pulse_core::ipc::sem::Sem], sops: &[SemBuf], pid: i32) {
    for op in sops {
        let idx = op.sem_num as usize;
        if op.sem_op > 0 {
            sems[idx].semval = sems[idx].semval.saturating_add(op.sem_op as u16);
        } else if op.sem_op < 0 {
            sems[idx].semval -= (-op.sem_op) as u16;
        }
        sems[idx].sempid = pid;
    }
}

/// semtimedop: semaphore operations with timeout.
///
/// args[0] = semid (i32)
/// args[1] = sops (usize, pointer to struct sembuf array)
/// args[2] = nsops (usize)
/// args[3] = timeout (usize, pointer to struct timespec)
pub fn sys_semtimedop(semid: i32, sops: usize, nsops: usize, timeout: usize) -> isize {
    axlog::debug!(
        "sys_semtimedop: semid={}, sops={:#x}, nsops={}, timeout={:#x}",
        semid,
        sops,
        nsops,
        timeout
    );

    if nsops == 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let process = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let sops_vec = match pulse_core::task::uaccess::read_user_plain_array::<SemBuf>(process.as_ref(), sops, nsops) {
        Ok(v) => v,
        Err(_) => return -LinuxError::EFAULT.code() as isize,
    };

    let semset_arc = {
        let manager = SEM_MANAGER.lock();
        match manager.get_inner_by_semid(semid) {
            Some(semset) => semset,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    };

    let thread = match current_thread() {
        Ok(t) => t,
        Err(e) => return -e.code() as isize,
    };

    let timeout_ns = if timeout != 0 {
        match read_timeout_ns(timeout) {
            Ok(t) => t,
            Err(e) => return -e.code() as isize,
        }
    } else {
        None
    };

    let start_time = axhal::time::monotonic_time_nanos() as u64;

    loop {
        let mut semset = semset_arc.lock();

        if semset.removed {
            return -LinuxError::EIDRM.code() as isize;
        }

        // Verify all semaphore indices are valid
        for op in &sops_vec {
            if op.sem_num as usize >= semset.nsems {
                return -LinuxError::EFBIG.code() as isize;
            }
        }

        if check_ops(&semset.sems, &sops_vec) {
            apply_ops(&mut semset.sems, &sops_vec, process.pid() as i32);
            semset.semid_ds.sem_otime = axhal::time::wall_time().as_secs() as i64;

            let mut undos = process.ipc.sem_undos.lock();
            for op in &sops_vec {
                if (op.sem_flg & 0o10000) != 0 { // SEM_UNDO
                    if let Some(entry) = undos.iter_mut().find(|e| e.semid == semid && e.sem_num == op.sem_num) {
                        entry.undo_val = entry.undo_val.saturating_sub(op.sem_op);
                    } else {
                        undos.push(SemUndoEntry {
                            semid,
                            sem_num: op.sem_num,
                            undo_val: -op.sem_op,
                        });
                    }
                }
            }

            semset.wait_queue.notify_all(true);
            return 0;
        }

        let has_nowait = sops_vec.iter().any(|op| (op.sem_flg & 0o4000) != 0); // IPC_NOWAIT
        if has_nowait {
            return -LinuxError::EAGAIN.code() as isize;
        }

        let now = axhal::time::monotonic_time_nanos() as u64;
        let elapsed = now.saturating_sub(start_time);
        if let Some(limit) = timeout_ns {
            if elapsed >= limit {
                return -LinuxError::EAGAIN.code() as isize;
            }
        }

        for op in &sops_vec {
            let idx = op.sem_num as usize;
            if idx < semset.sems.len() {
                if op.sem_op == 0 {
                    semset.sems[idx].semzcnt += 1;
                } else {
                    semset.sems[idx].semncnt += 1;
                }
            }
        }

        let queue = semset.wait_queue.clone();
        drop(semset);

        let timed_out = if let Some(limit) = timeout_ns {
            let remaining = limit.saturating_sub(elapsed);
            let dur = core::time::Duration::from_nanos(remaining);
            queue.wait_timeout(dur)
        } else {
            queue.wait();
            false
        };

        let mut semset = semset_arc.lock();
        for op in &sops_vec {
            let idx = op.sem_num as usize;
            if idx < semset.sems.len() {
                if op.sem_op == 0 {
                    semset.sems[idx].semzcnt = semset.sems[idx].semzcnt.saturating_sub(1);
                } else {
                    semset.sems[idx].semncnt = semset.sems[idx].semncnt.saturating_sub(1);
                }
            }
        }

        if semset.removed {
            return -LinuxError::EIDRM.code() as isize;
        }

        drop(semset);

        if thread.has_pending_signal() {
            return -LinuxError::EINTR.code() as isize;
        }

        if timed_out {
            return -LinuxError::EAGAIN.code() as isize;
        }
    }
}

/// semop: semaphore operations.
///
/// args[0] = semid (i32)
/// args[1] = sops (usize, pointer to struct sembuf array)
/// args[2] = nsops (usize)
pub fn sys_semop(semid: i32, sops: usize, nsops: usize) -> isize {
    sys_semtimedop(semid, sops, nsops, 0)
}
