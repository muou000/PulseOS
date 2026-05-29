use axerrno::LinuxError;
use pulse_core::task::current_process;

fn parse_id_arg(raw: usize) -> u32 {
    raw as u32
}

fn parse_optional_id_arg(raw: usize) -> Option<u32> {
    let id = parse_id_arg(raw);
    if id == u32::MAX { None } else { Some(id) }
}

pub fn sys_setuid(raw_uid: usize) -> isize {
    let uid = parse_id_arg(raw_uid);
    if uid == u32::MAX {
        return -LinuxError::EINVAL.code() as isize;
    }
    let process = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let (old_ruid, old_euid, old_suid) = process.uid_snapshot();
    if old_euid == 0 {
        process.set_uids(uid, uid, uid);
    } else if uid == old_ruid || uid == old_suid {
        process.set_uids(old_ruid, uid, old_suid);
    } else {
        return -LinuxError::EPERM.code() as isize;
    }
    let (new_ruid, new_euid, new_suid) = process.uid_snapshot();
    axlog::debug!(
        "sys_setuid: uid={}, old=({},{},{}), new=({},{},{})",
        uid,
        old_ruid,
        old_euid,
        old_suid,
        new_ruid,
        new_euid,
        new_suid
    );
    0
}

pub fn sys_setgid(raw_gid: usize) -> isize {
    let gid = parse_id_arg(raw_gid);
    if gid == u32::MAX {
        return -LinuxError::EINVAL.code() as isize;
    }
    let process = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let (old_rgid, old_egid, old_sgid) = process.gid_snapshot();
    if process.euid() == 0 {
        process.set_gids(gid, gid, gid);
    } else if gid == old_rgid || gid == old_sgid {
        process.set_gids(old_rgid, gid, old_sgid);
    } else {
        return -LinuxError::EPERM.code() as isize;
    }
    let (new_rgid, new_egid, new_sgid) = process.gid_snapshot();
    axlog::debug!(
        "sys_setgid: gid={}, old=({},{},{}), new=({},{},{})",
        gid,
        old_rgid,
        old_egid,
        old_sgid,
        new_rgid,
        new_egid,
        new_sgid
    );
    0
}

pub fn sys_setreuid(raw_ruid: usize, raw_euid: usize) -> isize {
    let new_ruid = parse_optional_id_arg(raw_ruid);
    let new_euid = parse_optional_id_arg(raw_euid);
    let process = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let (old_ruid, old_euid, old_suid) = process.uid_snapshot();
    if old_euid != 0 {
        if let Some(ruid) = new_ruid
            && ruid != old_ruid
            && ruid != old_euid
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if let Some(euid) = new_euid
            && euid != old_ruid
            && euid != old_euid
            && euid != old_suid
        {
            return -LinuxError::EPERM.code() as isize;
        }
    }
    let final_ruid = new_ruid.unwrap_or(old_ruid);
    let final_euid = new_euid.unwrap_or(old_euid);
    let should_update_suid = new_ruid.is_some() || new_euid.is_some_and(|euid| euid != old_ruid);
    let final_suid = if should_update_suid {
        final_euid
    } else {
        old_suid
    };
    process.set_uids(final_ruid, final_euid, final_suid);
    axlog::debug!(
        "sys_setreuid: ruid={:?}, euid={:?}, old=({},{},{}), new=({},{},{})",
        new_ruid,
        new_euid,
        old_ruid,
        old_euid,
        old_suid,
        final_ruid,
        final_euid,
        final_suid
    );
    0
}

pub fn sys_setregid(raw_rgid: usize, raw_egid: usize) -> isize {
    let new_rgid = parse_optional_id_arg(raw_rgid);
    let new_egid = parse_optional_id_arg(raw_egid);
    let process = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let (old_rgid, old_egid, old_sgid) = process.gid_snapshot();
    if process.euid() != 0 {
        if let Some(rgid) = new_rgid
            && rgid != old_rgid
            && rgid != old_egid
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if let Some(egid) = new_egid
            && egid != old_rgid
            && egid != old_egid
            && egid != old_sgid
        {
            return -LinuxError::EPERM.code() as isize;
        }
    }
    let final_rgid = new_rgid.unwrap_or(old_rgid);
    let final_egid = new_egid.unwrap_or(old_egid);
    let should_update_sgid = new_rgid.is_some() || new_egid.is_some_and(|egid| egid != old_rgid);
    let final_sgid = if should_update_sgid {
        final_egid
    } else {
        old_sgid
    };
    process.set_gids(final_rgid, final_egid, final_sgid);
    axlog::debug!(
        "sys_setregid: rgid={:?}, egid={:?}, old=({},{},{}), new=({},{},{})",
        new_rgid,
        new_egid,
        old_rgid,
        old_egid,
        old_sgid,
        final_rgid,
        final_egid,
        final_sgid
    );
    0
}

pub fn sys_setresuid(raw_ruid: usize, raw_euid: usize, raw_suid: usize) -> isize {
    let new_ruid = parse_optional_id_arg(raw_ruid);
    let new_euid = parse_optional_id_arg(raw_euid);
    let new_suid = parse_optional_id_arg(raw_suid);
    let process = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let (old_ruid, old_euid, old_suid) = process.uid_snapshot();
    if old_euid != 0 {
        if let Some(ruid) = new_ruid
            && ruid != old_ruid
            && ruid != old_euid
            && ruid != old_suid
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if let Some(euid) = new_euid
            && euid != old_ruid
            && euid != old_euid
            && euid != old_suid
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if let Some(suid) = new_suid
            && suid != old_ruid
            && suid != old_euid
            && suid != old_suid
        {
            return -LinuxError::EPERM.code() as isize;
        }
    }
    let final_ruid = new_ruid.unwrap_or(old_ruid);
    let final_euid = new_euid.unwrap_or(old_euid);
    let final_suid = new_suid.unwrap_or(old_suid);
    process.set_uids(final_ruid, final_euid, final_suid);
    axlog::debug!(
        "sys_setresuid: ruid={:?}, euid={:?}, suid={:?}, old=({},{},{}), new=({},{},{})",
        new_ruid,
        new_euid,
        new_suid,
        old_ruid,
        old_euid,
        old_suid,
        final_ruid,
        final_euid,
        final_suid
    );
    0
}

pub fn sys_setresgid(raw_rgid: usize, raw_egid: usize, raw_sgid: usize) -> isize {
    let new_rgid = parse_optional_id_arg(raw_rgid);
    let new_egid = parse_optional_id_arg(raw_egid);
    let new_sgid = parse_optional_id_arg(raw_sgid);
    let process = match current_process() {
        Ok(process) => process,
        Err(e) => return -e.code() as isize,
    };
    let (old_rgid, old_egid, old_sgid) = process.gid_snapshot();
    if process.euid() != 0 {
        if let Some(rgid) = new_rgid
            && rgid != old_rgid
            && rgid != old_egid
            && rgid != old_sgid
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if let Some(egid) = new_egid
            && egid != old_rgid
            && egid != old_egid
            && egid != old_sgid
        {
            return -LinuxError::EPERM.code() as isize;
        }
        if let Some(sgid) = new_sgid
            && sgid != old_rgid
            && sgid != old_egid
            && sgid != old_sgid
        {
            return -LinuxError::EPERM.code() as isize;
        }
    }
    let final_rgid = new_rgid.unwrap_or(old_rgid);
    let final_egid = new_egid.unwrap_or(old_egid);
    let final_sgid = new_sgid.unwrap_or(old_sgid);
    process.set_gids(final_rgid, final_egid, final_sgid);
    axlog::debug!(
        "sys_setresgid: rgid={:?}, egid={:?}, sgid={:?}, old=({},{},{}), new=({},{},{})",
        new_rgid,
        new_egid,
        new_sgid,
        old_rgid,
        old_egid,
        old_sgid,
        final_rgid,
        final_egid,
        final_sgid
    );
    0
}


pub fn sys_setsid() -> isize {
    axlog::warn!("sys_setsid (stub): returning success");
    1
}
