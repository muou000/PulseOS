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

pub fn sys_getgroups(size: isize, list: usize) -> isize {
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    let groups = process.groups();
    if size < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let size = size as usize;
    if size == 0 {
        return groups.len() as isize;
    }
    if groups.len() > size {
        return -LinuxError::EINVAL.code() as isize;
    }
    if list == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if let Err(e) = pulse_core::task::uaccess::write_user_plain_array(process.as_ref(), list, &groups) {
        let errno: LinuxError = e.into();
        return -errno.code() as isize;
    }
    groups.len() as isize
}

pub fn sys_setgroups(size: usize, list: usize) -> isize {
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    if !process.is_root_user() {
        return -LinuxError::EPERM.code() as isize;
    }
    if size > 65536 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let groups = if size == 0 {
        alloc::vec::Vec::new()
    } else {
        if list == 0 {
            return -LinuxError::EFAULT.code() as isize;
        }
        match pulse_core::task::uaccess::read_user_plain_array::<u32>(process.as_ref(), list, size) {
            Ok(g) => g,
            Err(e) => {
                let errno: LinuxError = e.into();
                return -errno.code() as isize;
            }
        }
    };
    process.set_groups(groups);
    0
}

/// setfsuid(2): 返回旧 fsuid；合法值才生效，非法值静默忽略
pub fn sys_setfsuid(raw_fsuid: usize) -> isize {
    let new_fsuid = raw_fsuid as u32;
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    let (ruid, euid, suid) = process.uid_snapshot();
    let old_fsuid = process.fsuid();
    // root 可设置任意值；否则只能设置为 ruid/euid/suid/old_fsuid 之一
    // 且 u32::MAX (-1) 或 0xFFFF (16-bit -1) 始终被忽略（用于查询）
    let allowed = new_fsuid != 0xFFFFFFFF && new_fsuid != 0xFFFF && (
        euid == 0 || new_fsuid == ruid || new_fsuid == euid || new_fsuid == suid || new_fsuid == old_fsuid
    );
    if allowed {
        process.set_fsuid(new_fsuid);
    }
    old_fsuid as isize
}

/// setfsgid(2): 返回旧 fsgid；合法值才生效，非法值静默忽略
pub fn sys_setfsgid(raw_fsgid: usize) -> isize {
    let new_fsgid = raw_fsgid as u32;
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };
    let (rgid, egid, sgid) = process.gid_snapshot();
    let old_fsgid = process.fsgid();
    let allowed = new_fsgid != 0xFFFFFFFF && new_fsgid != 0xFFFF && (
        process.euid() == 0 || new_fsgid == rgid || new_fsgid == egid || new_fsgid == sgid || new_fsgid == old_fsgid
    );
    if allowed {
        process.set_fsgid(new_fsgid);
    }
    old_fsgid as isize
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CapUserHeader {
    version: u32,
    pid: i32,
}

#[repr(C)]
#[derive(Copy, Clone)]
struct CapUserData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_VERSION_1: u32 = 0x19980330;
const CAP_VERSION_2: u32 = 0x20071026;
const CAP_VERSION_3: u32 = 0x20080522;

/// capget(2): 查询进程 capability
pub fn sys_capget(hdrp: usize, datap: usize) -> isize {
    if hdrp == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let mut header: CapUserHeader = match pulse_core::task::uaccess::read_user_plain(process.as_ref(), hdrp) {
        Ok(h) => h,
        Err(e) => {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    };

    if header.version != CAP_VERSION_1 && header.version != CAP_VERSION_2 && header.version != CAP_VERSION_3 {
        header.version = CAP_VERSION_3;
        let _ = pulse_core::task::uaccess::write_user_plain(process.as_ref(), hdrp, &header);
        return -LinuxError::EINVAL.code() as isize;
    }

    if header.pid < 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if header.pid != 0 && header.pid != process.pid() as i32 {
        axlog::warn!("capget: lookup for pid {} not fully implemented, returning ESRCH", header.pid);
        return -LinuxError::ESRCH.code() as isize;
    }

    if datap == 0 {
        return 0;
    }

    let (cap_p, cap_e, cap_i) = process.capabilities();
    let data0 = CapUserData {
        effective: cap_e as u32,
        permitted: cap_p as u32,
        inheritable: cap_i as u32,
    };

    if let Err(e) = pulse_core::task::uaccess::write_user_plain(process.as_ref(), datap, &data0) {
        let errno: LinuxError = e.into();
        return -errno.code() as isize;
    }

    if header.version == CAP_VERSION_2 || header.version == CAP_VERSION_3 {
        let data1 = CapUserData {
            effective: (cap_e >> 32) as u32,
            permitted: (cap_p >> 32) as u32,
            inheritable: (cap_i >> 32) as u32,
        };
        if let Err(e) = pulse_core::task::uaccess::write_user_plain(process.as_ref(), datap + core::mem::size_of::<CapUserData>(), &data1) {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    }

    0
}

/// capset(2): 设置进程 capability
pub fn sys_capset(hdrp: usize, datap: usize) -> isize {
    if hdrp == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let process = match current_process() {
        Ok(p) => p,
        Err(e) => return -e.code() as isize,
    };

    let mut header: CapUserHeader = match pulse_core::task::uaccess::read_user_plain(process.as_ref(), hdrp) {
        Ok(h) => h,
        Err(e) => {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    };

    if header.version != CAP_VERSION_1 && header.version != CAP_VERSION_2 && header.version != CAP_VERSION_3 {
        header.version = CAP_VERSION_3;
        let _ = pulse_core::task::uaccess::write_user_plain(process.as_ref(), hdrp, &header);
        return -LinuxError::EINVAL.code() as isize;
    }

    if header.pid < -1 {
        return -LinuxError::EINVAL.code() as isize;
    }

    if header.pid != 0 && header.pid != process.pid() as i32 {
        return -LinuxError::ESRCH.code() as isize;
    }

    if datap == 0 {
        return 0;
    }

    let data0: CapUserData = match pulse_core::task::uaccess::read_user_plain(process.as_ref(), datap) {
        Ok(d) => d,
        Err(e) => {
            let errno: LinuxError = e.into();
            return -errno.code() as isize;
        }
    };

    let (mut cap_p, mut cap_e, mut cap_i) = (data0.permitted as u64, data0.effective as u64, data0.inheritable as u64);

    if header.version == CAP_VERSION_2 || header.version == CAP_VERSION_3 {
        let data1: CapUserData = match pulse_core::task::uaccess::read_user_plain(process.as_ref(), datap + core::mem::size_of::<CapUserData>()) {
            Ok(d) => d,
            Err(e) => {
                let errno: LinuxError = e.into();
                return -errno.code() as isize;
            }
        };
        cap_p |= (data1.permitted as u64) << 32;
        cap_e |= (data1.effective as u64) << 32;
        cap_i |= (data1.inheritable as u64) << 32;
    }

    // 权限校验：非 root 只能缩小能力集，root 可任意（简化）
    let (old_p, _old_e, _old_i) = process.capabilities();
    if process.euid() != 0 {
        // 非 root 只能设置 permitted 的子集
        if (cap_p & !old_p) != 0 || (cap_e & !cap_p) != 0 {
            return -LinuxError::EPERM.code() as isize;
        }
    }

    process.set_capabilities(cap_p, cap_e, cap_i);
    0
}

