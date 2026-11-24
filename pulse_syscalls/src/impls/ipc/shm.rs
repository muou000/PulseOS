//! System V shared memory syscall implementations.

use axerrno::LinuxError;
use hal::mem::virt_to_phys;
use ipc::{
    IPC_CREAT, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT,
    shm::{
        self, IPC_INFO, SHM_INFO, SHM_MANAGER, SHM_RDONLY, SHM_REMAP, SHM_RND, SHM_STAT, ShmidDs,
    },
};
use memory_addr::{PAGE_SIZE_4K, VirtAddr};

/// shmget: create or get a shared memory segment.
///
/// args[0] = key (i32)
/// args[1] = size (usize)
/// args[2] = shmflg (i32, permission + IPC_CREAT/IPC_EXCL)
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> isize {
    kernel_log::debug!(
        "sys_shmget: key={}, size={}, shmflg={:#o}",
        key,
        size,
        shmflg
    );

    if size == 0 && key != IPC_PRIVATE {
        return -LinuxError::EINVAL.code() as isize;
    }

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    let credentials = proc.credentials.read();
    let euid = credentials.euid;
    let egid = credentials.egid;
    let groups = credentials.groups.clone();
    drop(credentials);
    let pid = proc.pid() as i32;

    let mut manager = SHM_MANAGER.lock();

    // If key is not IPC_PRIVATE and IPC_CREAT is not set, just look up.
    if key != IPC_PRIVATE && (shmflg & IPC_CREAT) == 0 {
        match manager.get_shmid_by_key(key) {
            Some(shmid) => {
                let inner = manager.get_inner_by_shmid(shmid).unwrap();
                let inner_guard = inner.lock();
                let req_mode = (shmflg & 0o777) as u32;
                if !shm::ipc_has_permission(
                    &inner_guard.stat().shm_perm,
                    req_mode,
                    euid,
                    egid,
                    &groups,
                ) {
                    return -LinuxError::EACCES.code() as isize;
                }
                return shmid as isize;
            }
            None => return -LinuxError::ENOENT.code() as isize,
        }
    }

    // Try to create or get existing.
    match manager.create_shm(key, size, shmflg, pid, euid, egid, &groups) {
        Ok(shmid) => shmid as isize,
        Err(e) => -LinuxError::from(e).code() as isize,
    }
}

/// shmat: attach a shared memory segment to the calling process's address space.
///
/// args[0] = shmid (i32)
/// args[1] = shmaddr (usize, preferred address or 0)
/// args[2] = shmflg (i32, e.g. SHM_RDONLY, SHM_REMAP, SHM_RND)
pub fn sys_shmat(shmid: i32, shmaddr: usize, shmflg: i32) -> isize {
    kernel_log::debug!(
        "sys_shmat: shmid={}, shmaddr={:#x}, shmflg={:#o}",
        shmid,
        shmaddr,
        shmflg
    );

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    let pid = proc.pid();

    let credentials = proc.credentials.read();
    let euid = credentials.euid;
    let egid = credentials.egid;
    let groups = credentials.groups.clone();
    drop(credentials);

    proc.ipc.with_shared_memory(|registry| {
        let manager = SHM_MANAGER.lock();
        let Some(shm_inner) = manager.get_inner_by_shmid(shmid) else {
            return -LinuxError::EINVAL.code() as isize;
        };
        // Acquire the segment before releasing the manager so the last detach or
        // IPC_RMID cannot reap it between lookup and attachment.
        let mut inner = shm_inner.lock();
        drop(manager);

        // Permission check:
        let req_mode = if (shmflg as u32) & SHM_RDONLY != 0 {
            0o400
        } else {
            0o600
        };
        if !shm::ipc_has_permission(&inner.stat().shm_perm, req_mode, euid, egid, &groups) {
            return -LinuxError::EACCES.code() as isize;
        }

        // Allocate physical pages on first attach.
        let page_addr = match inner.alloc_pages() {
            Ok(addr) => addr,
            Err(e) => return -LinuxError::from(e).code() as isize,
        };

        let length = inner.mapping_size();
        let mut mapping_flags = inner.mapping_flags;
        if (shmflg as u32) & SHM_RDONLY != 0 {
            mapping_flags.remove(hal::paging::MappingFlags::WRITE);
        }

        // Determine the virtual address to map at.
        let aspace_handle = proc.aspace_handle();
        let mut aspace = aspace_handle.write();
        let mut pending_shootdown = None;

        let map_addr = if shmaddr != 0 && (shmflg as u32) & SHM_RND != 0 {
            // SHM_RND: round down to SHMLBA (use PAGE_SIZE_4K for now)
            shmaddr & !(PAGE_SIZE_4K - 1)
        } else if shmaddr != 0 {
            if shmaddr & (PAGE_SIZE_4K - 1) != 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            shmaddr
        } else {
            // Let the kernel choose an address.
            let limit = memory_addr::VirtAddrRange::from_start_size(
                VirtAddr::from(pulse_core::config::USER_SPACE_BASE),
                pulse_core::config::USER_SPACE_SIZE,
            );
            match aspace.find_free_area(
                VirtAddr::from(pulse_core::config::USER_SPACE_BASE),
                length,
                limit,
            ) {
                Some(vaddr) => vaddr.as_usize(),
                None => {
                    kernel_log::debug!("sys_shmat: no free area found");
                    return -LinuxError::ENOMEM.code() as isize;
                }
            }
        };

        if (shmflg as u32) & SHM_REMAP != 0 {
            // Unmap existing mapping at the target address if SHM_REMAP is set.
            let (unmap_result, shootdown) =
                aspace.unmap(VirtAddr::from(map_addr), length).into_parts();
            pending_shootdown = shootdown;
            if let Err(error) = unmap_result {
                kernel_log::warn!("sys_shmat: SHM_REMAP pre-unmap failed: {error:?}");
            }
        }

        // Map the shared physical pages into this process's address space.
        let paddr = virt_to_phys(page_addr);
        let map_result = aspace.map_linear(VirtAddr::from(map_addr), paddr, length, mapping_flags);
        drop(aspace);
        // Once map_linear succeeds the mapping owns a reference even if a prior
        // SHM_REMAP invalidation subsequently reports a shootdown error.
        if map_result.is_ok() {
            inner.attach_process(pid);
            registry.insert(VirtAddr::from(map_addr), shm_inner.clone());
        }
        drop(inner);
        if let Some(shootdown) = pending_shootdown
            && let Err(error) = shootdown.complete_after_unlock()
        {
            kernel_log::error!("sys_shmat: SHM_REMAP TLB shootdown failed: {error:?}");
            return -LinuxError::EIO.code() as isize;
        }
        if let Err(e) = map_result {
            kernel_log::debug!("sys_shmat: map_linear failed: {:?}", e);
            return -LinuxError::from(e).code() as isize;
        }

        kernel_log::debug!("sys_shmat: mapped at {:#x}, size={}", map_addr, length);
        map_addr as isize
    })
}

/// shmdt: detach a shared memory segment from the calling process's address space.
///
/// args[0] = shmaddr (usize, the address returned by shmat)
pub fn sys_shmdt(shmaddr: usize) -> isize {
    kernel_log::debug!("sys_shmdt: shmaddr={:#x}", shmaddr);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    let pid = proc.pid();

    let addr = VirtAddr::from(shmaddr);
    proc.ipc.with_shared_memory(|registry| {
        let Some(segment) = registry.remove(&addr) else {
            return -LinuxError::EINVAL.code() as isize;
        };
        let length = segment.lock().mapping_size();

        // Unmap the virtual address range.
        let aspace_handle = proc.aspace_handle();
        let mut aspace = aspace_handle.write();
        let mutation = aspace.unmap(addr, length);
        drop(aspace);
        if let Err(e) = mutation.complete_after_unlock() {
            kernel_log::warn!("sys_shmdt: unmap or TLB shootdown failed: {:?}", e);
            registry.insert(addr, segment);
            return -LinuxError::from(e).code() as isize;
        }

        shm::detach(&segment, pid);
        0
    })
}

/// shmctl: shared memory control operations.
///
/// args[0] = shmid (i32)
/// args[1] = cmd (i32)
/// args[2] = buf (usize, pointer to ShmidDs or 0)
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: usize) -> isize {
    kernel_log::debug!("sys_shmctl: shmid={}, cmd={}, buf={:#x}", shmid, cmd, buf);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let credentials = proc.credentials.read();
    let euid = credentials.euid;
    let egid = credentials.egid;
    let groups = credentials.groups.clone();
    drop(credentials);

    match cmd {
        IPC_INFO => {
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let info = shm::IpcInfo::new();
            return match pulse_core::task::uaccess::write_user_value(proc.as_ref(), buf, &info) {
                Ok(()) => {
                    let manager = SHM_MANAGER.lock();
                    manager.get_highest_index() as isize
                }
                Err(_) => -LinuxError::EFAULT.code() as isize,
            };
        }
        SHM_INFO => {
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let (shm_tot, shm_rss) = {
                let manager = SHM_MANAGER.lock();
                manager.get_total_resources()
            };
            let info = shm::ShmInfo {
                used_ids: {
                    let manager = SHM_MANAGER.lock();
                    manager.len() as i32
                },
                shm_tot,
                shm_rss,
                shm_swp: 0,
                swap_attempts: 0,
                swap_successes: 0,
            };
            return match pulse_core::task::uaccess::write_user_value(proc.as_ref(), buf, &info) {
                Ok(()) => {
                    let manager = SHM_MANAGER.lock();
                    manager.get_highest_index() as isize
                }
                Err(_) => -LinuxError::EFAULT.code() as isize,
            };
        }
        SHM_STAT => {
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let (actual_shmid, inner_arc) = {
                let manager = SHM_MANAGER.lock();
                match manager.get_inner_by_index(shmid as usize) {
                    Some(val) => val,
                    None => return -LinuxError::EINVAL.code() as isize,
                }
            };
            let inner = inner_arc.lock();
            if !shm::ipc_has_permission(&inner.stat().shm_perm, 0o400, euid, egid, &groups) {
                return -LinuxError::EACCES.code() as isize;
            }
            let ds = inner.stat();
            drop(inner);
            return match pulse_core::task::uaccess::write_user_value(proc.as_ref(), buf, &ds) {
                Ok(()) => actual_shmid as isize,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            };
        }
        IPC_RMID => {
            return match SHM_MANAGER.lock().mark_for_removal(shmid, euid) {
                Ok(()) => 0,
                Err(e) => -e.code() as isize,
            };
        }
        _ => {}
    }

    let inner_arc = {
        let manager = SHM_MANAGER.lock();
        match manager.get_inner_by_shmid(shmid) {
            Some(inner) => inner,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    };

    let mut inner = inner_arc.lock();

    match cmd {
        IPC_STAT => {
            if !shm::ipc_has_permission(&inner.stat().shm_perm, 0o400, euid, egid, &groups) {
                return -LinuxError::EACCES.code() as isize;
            }
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let ds = inner.stat();
            drop(inner);
            match pulse_core::task::uaccess::write_user_value(proc.as_ref(), buf, &ds) {
                Ok(()) => 0,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            }
        }
        IPC_SET => {
            if !inner.stat().shm_perm.is_owner(euid) {
                return -LinuxError::EPERM.code() as isize;
            }
            drop(inner);
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let new_ds: ShmidDs =
                match pulse_core::task::uaccess::read_user_value(proc.as_ref(), buf) {
                    Ok(v) => v,
                    Err(_) => return -LinuxError::EFAULT.code() as isize,
                };
            // Ownership can change while the user copy faults.
            let mut inner = inner_arc.lock();
            let perm = inner.permissions_mut();
            if !perm.is_owner(euid) {
                return -LinuxError::EPERM.code() as isize;
            }
            perm.uid = new_ds.shm_perm.uid;
            perm.gid = new_ds.shm_perm.gid;
            perm.mode = new_ds.shm_perm.mode;
            0
        }
        shm::SHM_LOCK => {
            if euid != 0 {
                return -LinuxError::EPERM.code() as isize;
            }
            inner.permissions_mut().mode |= shm::SHM_LOCKED;
            0
        }
        shm::SHM_UNLOCK => {
            if euid != 0 {
                return -LinuxError::EPERM.code() as isize;
            }
            inner.permissions_mut().mode &= !shm::SHM_LOCKED;
            0
        }
        _ => -LinuxError::EINVAL.code() as isize,
    }
}
