//! System V shared memory syscall implementations.

use axerrno::LinuxError;
use axhal::mem::virt_to_phys;
use memory_addr::{PAGE_SIZE_4K, VirtAddr};
use pulse_core::ipc::shm::{
    IPC_INFO, IPC_PRIVATE, IPC_RMID, IPC_SET, IPC_STAT, SHM_INFO, SHM_MANAGER, SHM_RDONLY,
    SHM_REMAP, SHM_RND, SHM_STAT, ShmidDs,
};

/// shmget: create or get a shared memory segment.
///
/// args[0] = key (i32)
/// args[1] = size (usize)
/// args[2] = shmflg (i32, permission + IPC_CREAT/IPC_EXCL)
pub fn sys_shmget(key: i32, size: usize, shmflg: i32) -> isize {
    axlog::debug!(
        "sys_shmget: key={}, size={}, shmflg={:#o}",
        key,
        size,
        shmflg
    );

    if size == 0 && key != IPC_PRIVATE {
        return -LinuxError::EINVAL.code() as isize;
    }

    const IPC_CREAT: i32 = 0o1000;

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
                if !pulse_core::ipc::shm::ipc_has_permission(&inner_guard.shmid_ds.shm_perm, req_mode, euid, egid, &groups) {
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
    axlog::debug!(
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

    // Get the ShmInner.
    let shm_inner = {
        let manager = SHM_MANAGER.lock();
        match manager.get_inner_by_shmid(shmid) {
            Some(inner) => inner,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    };

    let credentials = proc.credentials.read();
    let euid = credentials.euid;
    let egid = credentials.egid;
    let groups = credentials.groups.clone();
    drop(credentials);

    let mut inner = shm_inner.lock();

    // Permission check:
    let req_mode = if (shmflg as u32) & SHM_RDONLY != 0 { 0o400 } else { 0o600 };
    if !pulse_core::ipc::shm::ipc_has_permission(&inner.shmid_ds.shm_perm, req_mode, euid, egid, &groups) {
        return -LinuxError::EACCES.code() as isize;
    }

    // Allocate physical pages on first attach.
    if let Err(e) = inner.alloc_pages() {
        return -LinuxError::from(e).code() as isize;
    }

    let length = inner.page_num * PAGE_SIZE_4K;
    let mut mapping_flags = inner.mapping_flags;
    if (shmflg as u32) & SHM_RDONLY != 0 {
        mapping_flags.remove(axhal::paging::MappingFlags::WRITE);
    }

    // Determine the virtual address to map at.
    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();

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
                axlog::error!("sys_shmat: no free area found");
                return -LinuxError::ENOMEM.code() as isize;
            }
        }
    };

    if (shmflg as u32) & SHM_REMAP != 0 {
        // Unmap existing mapping at the target address if SHM_REMAP is set.
        let _ = aspace.unmap(VirtAddr::from(map_addr), length);
    }

    // Map the shared physical pages into this process's address space.
    let paddr = virt_to_phys(VirtAddr::from(inner.addr));
    if let Err(e) = aspace.map_linear(VirtAddr::from(map_addr), paddr, length, mapping_flags) {
        axlog::error!("sys_shmat: map_linear failed: {:?}", e);
        return -LinuxError::from(e).code() as isize;
    }

    drop(aspace);

    // Record the attachment.
    inner.attach_process(pid);
    drop(inner);
    proc.ipc.shared_memory
        .write()
        .insert(VirtAddr::from(map_addr), shm_inner.clone());

    axlog::debug!("sys_shmat: mapped at {:#x}, size={}", map_addr, length);
    map_addr as isize
}

/// shmdt: detach a shared memory segment from the calling process's address space.
///
/// args[0] = shmaddr (usize, the address returned by shmat)
pub fn sys_shmdt(shmaddr: usize) -> isize {
    axlog::debug!("sys_shmdt: shmaddr={:#x}", shmaddr);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };
    let pid = proc.pid();

    // Find the ShmInner for this address in the process's registry.
    let shm_inner_arc = {
        let mut shm_registry = proc.ipc.shared_memory.write();
        match shm_registry.remove(&VirtAddr::from(shmaddr)) {
            Some(inner) => inner,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    };

    let mut inner = shm_inner_arc.lock();
    let length = inner.page_num * PAGE_SIZE_4K;
    let shmid = inner.shmid;

    // Unmap the virtual address range.
    let aspace_handle = proc.aspace_handle();
    let mut aspace = aspace_handle.lock();
    if let Err(e) = aspace.unmap(VirtAddr::from(shmaddr), length) {
        axlog::warn!("sys_shmdt: unmap failed: {:?}", e);
    }
    drop(aspace);

    // Detach the process from the ShmInner.
    inner.detach_process(pid);

    // If IPC_RMID was set and no more attachers, remove from global manager.
    // Note: The memory will be freed when the last Arc is dropped.
    if inner.rmid && inner.attach_count() == 0 {
        drop(inner);
        let mut manager = SHM_MANAGER.lock();
        manager.remove_shmid(shmid);
    }

    0
}

/// shmctl: shared memory control operations.
///
/// args[0] = shmid (i32)
/// args[1] = cmd (i32)
/// args[2] = buf (usize, pointer to ShmidDs or 0)
pub fn sys_shmctl(shmid: i32, cmd: i32, buf: usize) -> isize {
    axlog::debug!("sys_shmctl: shmid={}, cmd={}, buf={:#x}", shmid, cmd, buf);

    let proc = match pulse_core::task::current_process() {
        Ok(proc) => proc,
        Err(e) => return -e.code() as isize,
    };

    let inner_arc = {
        let manager = SHM_MANAGER.lock();
        match manager.get_inner_by_shmid(shmid) {
            Some(inner) => inner,
            None => return -LinuxError::EINVAL.code() as isize,
        }
    };

    let credentials = proc.credentials.read();
    let euid = credentials.euid;
    let egid = credentials.egid;
    let groups = credentials.groups.clone();
    drop(credentials);

    let mut inner = inner_arc.lock();

    match cmd {
        IPC_STAT => {
            if !pulse_core::ipc::shm::ipc_has_permission(&inner.shmid_ds.shm_perm, 0o400, euid, egid, &groups) {
                return -LinuxError::EACCES.code() as isize;
            }
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let ds = inner.shmid_ds;
            match pulse_core::task::uaccess::write_user_plain(proc.as_ref(), buf, &ds) {
                Ok(()) => 0,
                Err(_) => -LinuxError::EFAULT.code() as isize,
            }
        }
        IPC_SET => {
            if euid != 0 && euid != inner.shmid_ds.shm_perm.uid && euid != inner.shmid_ds.shm_perm.cuid {
                return -LinuxError::EPERM.code() as isize;
            }
            if buf == 0 {
                return -LinuxError::EFAULT.code() as isize;
            }
            let new_ds: ShmidDs =
                match pulse_core::task::uaccess::read_user_plain(proc.as_ref(), buf) {
                    Ok(v) => v,
                    Err(_) => return -LinuxError::EFAULT.code() as isize,
                };
            // Only uid, gid, and mode can be changed.
            inner.shmid_ds.shm_perm.uid = new_ds.shm_perm.uid;
            inner.shmid_ds.shm_perm.gid = new_ds.shm_perm.gid;
            inner.shmid_ds.shm_perm.mode = new_ds.shm_perm.mode;
            0
        }
        IPC_RMID => {
            if euid != 0 && euid != inner.shmid_ds.shm_perm.uid && euid != inner.shmid_ds.shm_perm.cuid {
                return -LinuxError::EPERM.code() as isize;
            }
            inner.rmid = true;
            if inner.attach_count() == 0 {
                drop(inner);
                let mut manager = SHM_MANAGER.lock();
                manager.remove_shmid(shmid);
            }
            0
        }
        IPC_INFO | SHM_INFO | SHM_STAT => {
            // Stub: return 0 for now.
            axlog::warn!("sys_shmctl: cmd={} not fully implemented", cmd);
            0
        }
        _ => -LinuxError::EINVAL.code() as isize,
    }
}
