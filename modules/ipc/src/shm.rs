//! System V shared memory implementation.

use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicI32, Ordering};

use kernel_alloc::GlobalPage;
use axerrno::{AxError, AxResult, LinuxError, ax_err};
use hal::paging::MappingFlags;
use memory_addr::{PAGE_SIZE_4K, VirtAddr};
use spin::{Lazy, Mutex};

use crate::{IPC_EXCL, IPC_PRIVATE, IpcPerm};

pub const IPC_INFO: i32 = 3;
pub const SHM_INFO: i32 = 14;
pub const SHM_STAT: i32 = 13;
pub const SHM_RDONLY: u32 = 0o10000;
pub const SHM_RND: u32 = 0o20000;
pub const SHM_REMAP: u32 = 0o40000;

pub const SHM_LOCK: i32 = 11;
pub const SHM_UNLOCK: i32 = 12;
pub const SHM_LOCKED: u16 = 0o2000;

/// Linux-compatible `shminfo` structure (C ABI).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct IpcInfo {
    pub shmmax: usize,
    pub shmmin: usize,
    pub shmmni: usize,
    pub shmseg: usize,
    pub shmall: usize,
}

pulse_user_abi::impl_user_abi_struct! {
    for IpcInfo, size = 40 => {
        shmmax: usize,
        shmmin: usize,
        shmmni: usize,
        shmseg: usize,
        shmall: usize,
    }
}

impl IpcInfo {
    pub fn new() -> Self {
        Self {
            shmmax: usize::MAX,
            shmmin: 1,
            shmmni: 4096,
            shmseg: 4096,
            shmall: usize::MAX,
        }
    }
}

/// Linux-compatible `shm_info` structure (C ABI).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct ShmInfo {
    pub used_ids: i32,
    pub shm_tot: usize,
    pub shm_rss: usize,
    pub shm_swp: usize,
    pub swap_attempts: usize,
    pub swap_successes: usize,
}

pulse_user_abi::impl_user_abi_struct! {
    for ShmInfo, size = 48 => {
        used_ids: i32,
        shm_tot: usize,
        shm_rss: usize,
        shm_swp: usize,
        swap_attempts: usize,
        swap_successes: usize,
    }
}

/// Linux-compatible `shmid_ds` structure (C ABI).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ShmidDs {
    /// operation permission struct
    pub shm_perm: IpcPerm,
    /// size of segment in bytes
    pub shm_segsz: usize,
    /// time of last shmat
    pub shm_atime: i64,
    /// time of last shmdt
    pub shm_dtime: i64,
    /// time of last change by shmctl
    pub shm_ctime: i64,
    /// pid of creator
    pub shm_cpid: i32,
    /// pid of last shmop
    pub shm_lpid: i32,
    /// number of current attaches
    pub shm_nattch: u16,
    _pad: [u8; 6],
}

pulse_user_abi::impl_user_abi_struct! {
    for ShmidDs, size = 88 => {
        shm_perm: IpcPerm,
        shm_segsz: usize,
        shm_atime: i64,
        shm_dtime: i64,
        shm_ctime: i64,
        shm_cpid: i32,
        shm_lpid: i32,
        shm_nattch: u16,
        _pad: [u8; 6],
    }
}

impl ShmidDs {
    pub fn new(key: i32, size: usize, mode: u16, uid: u32, gid: u32, pid: i32) -> Self {
        Self {
            shm_perm: IpcPerm {
                key,
                uid,
                gid,
                cuid: uid,
                cgid: gid,
                mode,
                ..Default::default()
            },
            shm_segsz: size,
            shm_atime: 0,
            shm_dtime: 0,
            shm_ctime: 0,
            shm_cpid: pid,
            shm_lpid: pid,
            shm_nattch: 0,
            _pad: [0; 6],
        }
    }
}

/// Internal state for a single shared memory segment.
pub struct ShmInner {
    /// Shared memory segment identifier.
    shmid: i32,
    /// Number of pages in the segment.
    page_num: usize,
    /// Backing pages allocated on first attach and kept alive by the segment.
    pages: Option<GlobalPage>,
    /// Whether to remove on last detach (set by IPC_RMID).
    rmid: bool,
    /// Mapping flags for this segment.
    pub mapping_flags: MappingFlags,
    /// C-compatible metadata.
    shmid_ds: ShmidDs,
}

impl ShmInner {
    fn new(
        key: i32,
        shmid: i32,
        size: usize,
        mapping_flags: MappingFlags,
        uid: u32,
        gid: u32,
        pid: i32,
    ) -> Self {
        Self {
            shmid,
            page_num: align_up_4k(size) / PAGE_SIZE_4K,
            pages: None,
            rmid: false,
            mapping_flags,
            shmid_ds: ShmidDs::new(key, size, mapping_flags.bits() as u16, uid, gid, pid),
        }
    }
}

/// Helper to check SysV IPC permissions based on standard Linux logic.
pub fn ipc_has_permission(
    perm: &IpcPerm,
    req_mode: u32,
    euid: u32,
    egid: u32,
    groups: &[u32],
) -> bool {
    if euid == 0 {
        return true;
    }
    let granted_mode = if euid == perm.uid || euid == perm.cuid {
        perm.mode as u32
    } else if egid == perm.gid
        || egid == perm.cgid
        || groups.contains(&perm.gid)
        || groups.contains(&perm.cgid)
    {
        (perm.mode as u32) << 3
    } else {
        (perm.mode as u32) << 6
    };
    (req_mode & !granted_mode & 0o777) == 0
}

impl ShmInner {
    /// Allocate zeroed backing pages on first attach and return their kernel address.
    pub fn alloc_pages(&mut self) -> AxResult<VirtAddr> {
        if let Some(pages) = &self.pages {
            return Ok(pages.start_vaddr());
        }
        let mut pages = GlobalPage::alloc_contiguous(self.page_num, PAGE_SIZE_4K)
            .map_err(|_| AxError::NoMemory)?;
        pages.zero();
        Ok(self.pages.insert(pages).start_vaddr())
    }

    pub fn mapping_size(&self) -> usize {
        self.page_num * PAGE_SIZE_4K
    }

    pub fn stat(&self) -> ShmidDs {
        self.shmid_ds
    }

    pub fn permissions_mut(&mut self) -> &mut IpcPerm {
        &mut self.shmid_ds.shm_perm
    }

    /// Try to update the segment if a matching key exists.
    fn try_update(&mut self, size: usize, mapping_flags: MappingFlags, pid: i32) -> AxResult<i32> {
        if align_up_4k(size) / PAGE_SIZE_4K != self.page_num {
            return ax_err!(InvalidInput, "shm: size mismatch for existing key");
        }
        if mapping_flags.bits() != self.mapping_flags.bits() {
            return ax_err!(InvalidInput, "shm: flags mismatch for existing key");
        }
        self.shmid_ds.shm_lpid = pid;
        Ok(self.shmid)
    }

    /// Attach a process to this segment.
    pub fn attach_process(&mut self, pid: u64) {
        self.shmid_ds.shm_nattch += 1;
        self.shmid_ds.shm_lpid = pid as i32;
    }
}

/// Bi-directional BTreeMap for key <-> shmid mapping.
struct BiBTreeMap<K: Ord, V: Ord> {
    forward: BTreeMap<K, V>,
    reverse: BTreeMap<V, K>,
}

impl<K: Ord + Clone, V: Ord + Clone> BiBTreeMap<K, V> {
    const fn new() -> Self {
        Self {
            forward: BTreeMap::new(),
            reverse: BTreeMap::new(),
        }
    }

    fn insert(&mut self, key: K, value: V) {
        self.forward.insert(key.clone(), value.clone());
        self.reverse.insert(value, key);
    }

    fn get_by_key(&self, key: &K) -> Option<&V> {
        self.forward.get(key)
    }

    fn remove_by_value(&mut self, value: &V) {
        if let Some(key) = self.reverse.remove(value) {
            self.forward.remove(&key);
        }
    }
}

/// Global shared memory manager.
pub struct ShmManager {
    /// key <-> shm_id
    key_shmid: BiBTreeMap<i32, i32>,
    /// shm_id -> shm_inner
    shmid_inner: BTreeMap<i32, Arc<Mutex<ShmInner>>>,
    /// Next shared memory ID.
    next_shmid: AtomicI32,
}

impl ShmManager {
    const fn new() -> Self {
        Self {
            key_shmid: BiBTreeMap::new(),
            shmid_inner: BTreeMap::new(),
            next_shmid: AtomicI32::new(1),
        }
    }

    fn next_id(&self) -> i32 {
        self.next_shmid.fetch_add(1, Ordering::Relaxed)
    }

    /// Get shmid by key.
    pub fn get_shmid_by_key(&self, key: i32) -> Option<i32> {
        self.key_shmid.get_by_key(&key).copied()
    }

    /// Get ShmInner by shmid.
    pub fn get_inner_by_shmid(&self, shmid: i32) -> Option<Arc<Mutex<ShmInner>>> {
        self.shmid_inner.get(&shmid).cloned()
    }

    /// Insert key -> shmid mapping.
    fn insert_key_shmid(&mut self, key: i32, shmid: i32) {
        self.key_shmid.insert(key, shmid);
    }

    /// Insert shmid -> ShmInner mapping.
    fn insert_shmid_inner(&mut self, shmid: i32, shm_inner: Arc<Mutex<ShmInner>>) {
        self.shmid_inner.insert(shmid, shm_inner);
    }

    /// Mark a segment for removal. Its identifier remains usable while attached.
    pub fn mark_for_removal(&mut self, shmid: i32, euid: u32) -> Result<(), LinuxError> {
        let segment = self.get_inner_by_shmid(shmid).ok_or(LinuxError::EINVAL)?;
        let mut inner = segment.lock();
        let perm = &inner.shmid_ds.shm_perm;
        if !perm.is_owner(euid) {
            return Err(LinuxError::EPERM);
        }
        inner.rmid = true;
        self.reap_if_unattached(&inner);
        Ok(())
    }

    fn reap_if_unattached(&mut self, inner: &ShmInner) {
        if inner.rmid && inner.shmid_ds.shm_nattch == 0 {
            self.key_shmid.remove_by_value(&inner.shmid);
            self.shmid_inner.remove(&inner.shmid);
        }
    }

    /// Get the highest index of the shared memory segments.
    pub fn get_highest_index(&self) -> usize {
        self.shmid_inner.len().saturating_sub(1)
    }

    /// Get the shared memory inner state by index.
    pub fn get_inner_by_index(&self, index: usize) -> Option<(i32, Arc<Mutex<ShmInner>>)> {
        self.shmid_inner
            .iter()
            .nth(index)
            .map(|(&shmid, inner)| (shmid, inner.clone()))
    }

    /// Get total resources (total bytes, total allocated resident pages).
    pub fn get_total_resources(&self) -> (usize, usize) {
        let mut tot = 0;
        let mut rss = 0;
        for inner in self.shmid_inner.values() {
            let guard = inner.lock();
            tot += guard.shmid_ds.shm_segsz;
            if guard.pages.is_some() {
                rss += guard.page_num;
            }
        }
        (tot, rss)
    }

    /// Get the number of shared memory segments.
    pub fn len(&self) -> usize {
        self.shmid_inner.len()
    }

    /// Create a new shared memory segment.
    pub fn create_shm(
        &mut self,
        key: i32,
        size: usize,
        shmflg: i32,
        pid: i32,
        euid: u32,
        egid: u32,
        groups: &[u32],
    ) -> AxResult<i32> {
        let page_num = align_up_4k(size) / PAGE_SIZE_4K;
        if page_num == 0 {
            return ax_err!(InvalidInput, "shm: size must be > 0");
        }

        // Build mapping flags from shmflg permission bits.
        let mut mapping_flags = MappingFlags::USER | MappingFlags::READ | MappingFlags::WRITE;
        if (shmflg & 0o100) != 0 {
            mapping_flags |= MappingFlags::EXECUTE;
        }

        if key != IPC_PRIVATE {
            if let Some(shmid) = self.get_shmid_by_key(key) {
                if (shmflg & IPC_EXCL) != 0 {
                    return ax_err!(AlreadyExists, "shmget: key already exists with IPC_EXCL");
                }
                let inner = self
                    .get_inner_by_shmid(shmid)
                    .ok_or(AxError::InvalidInput)?;
                let mut inner_guard = inner.lock();

                let req_mode = (shmflg & 0o777) as u32;
                if !ipc_has_permission(&inner_guard.shmid_ds.shm_perm, req_mode, euid, egid, groups)
                {
                    return ax_err!(PermissionDenied, "shmget: permission denied");
                }

                return inner_guard.try_update(size, mapping_flags, pid);
            }
        }

        let shmid = self.next_id();
        let inner = ShmInner::new(key, shmid, size, mapping_flags, euid, egid, pid);
        let inner = Arc::new(Mutex::new(inner));
        self.insert_key_shmid(key, shmid);
        self.insert_shmid_inner(shmid, inner);
        Ok(shmid)
    }
}

/// Global shared memory manager instance.
pub static SHM_MANAGER: Lazy<Mutex<ShmManager>> = Lazy::new(|| Mutex::new(ShmManager::new()));

/// Release one attachment and reap a marked segment at its last detach.
/// The manager precedes the segment lock, as in lookup for a new attachment.
pub fn detach(segment: &Mutex<ShmInner>, pid: u64) {
    let mut manager = SHM_MANAGER.lock();
    let mut inner = segment.lock();
    inner.shmid_ds.shm_nattch = inner.shmid_ds.shm_nattch.saturating_sub(1);
    inner.shmid_ds.shm_lpid = pid as i32;
    manager.reap_if_unattached(&inner);
}

fn align_up_4k(size: usize) -> usize {
    (size + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1)
}
