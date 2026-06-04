//! System V shared memory implementation.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicI32, Ordering};

use axalloc::global_allocator;
use axerrno::{AxError, AxResult, ax_err};
use axhal::paging::MappingFlags;
use memory_addr::PAGE_SIZE_4K;
use spin::{Lazy, Mutex};

// IPC constants (from linux-raw-sys / Linux ABI)
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_RMID: i32 = 0;
pub const IPC_INFO: i32 = 3;
pub const SHM_INFO: i32 = 14;
pub const SHM_STAT: i32 = 13;
pub const SHM_RDONLY: u32 = 0o10000;
pub const SHM_RND: u32 = 0o20000;
pub const SHM_REMAP: u32 = 0o40000;

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

/// Linux-compatible `ipc_perm` structure (C ABI).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpcPerm {
    /// key supplied to shmget
    pub key: i32,
    /// effective UID of owner
    pub uid: u32,
    /// effective GID of owner
    pub gid: u32,
    /// effective UID of creator
    pub cuid: u32,
    /// effective GID of creator
    pub cgid: u32,
    /// permissions + SHM_DEST and SHM_LOCKED flags
    pub mode: u16,
    _pad: [u8; 2],
    _seq: u16,
    _pad2: u16,
    _pad3: u32,
    _pad4: u32,
}

impl IpcPerm {
    pub fn new(key: i32, mode: u16, pid: i32) -> Self {
        Self {
            key,
            uid: 0,
            gid: 0,
            cuid: pid as u32,
            cgid: pid as u32,
            mode,
            _pad: [0; 2],
            _seq: 0,
            _pad2: 0,
            _pad3: 0,
            _pad4: 0,
        }
    }
}

impl ShmidDs {
    pub fn new(key: i32, size: usize, mode: u16, pid: i32) -> Self {
        Self {
            shm_perm: IpcPerm::new(key, mode, pid),
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
    pub shmid: i32,
    /// Number of pages in the segment.
    pub page_num: usize,
    /// Virtual kernel address of the shared memory segment.
    pub addr: usize,
    /// Whether to remove on last detach (set by IPC_RMID).
    pub rmid: bool,
    /// Mapping flags for this segment.
    pub mapping_flags: MappingFlags,
    /// C-compatible metadata.
    pub shmid_ds: ShmidDs,
}

impl ShmInner {
    pub fn new(key: i32, shmid: i32, size: usize, mapping_flags: MappingFlags, pid: i32) -> Self {
        Self {
            shmid,
            page_num: align_up_4k(size) / PAGE_SIZE_4K,
            addr: 0,
            rmid: false,
            mapping_flags,
            shmid_ds: ShmidDs::new(key, size, mapping_flags.bits() as u16, pid),
        }
    }

    /// Allocate physical pages for this segment (first attach).
    pub fn alloc_pages(&mut self) -> AxResult<()> {
        if self.addr != 0 {
            return Ok(());
        }
        let vaddr = global_allocator()
            .alloc_pages(self.page_num, PAGE_SIZE_4K)
            .map_err(|_| AxError::NoMemory)?;
        // Zero the pages
        unsafe {
            core::ptr::write_bytes(vaddr as *mut u8, 0, self.page_num * PAGE_SIZE_4K);
        }
        self.addr = vaddr;
        Ok(())
    }

    /// Try to update the segment if a matching key exists.
    pub fn try_update(
        &mut self,
        size: usize,
        mapping_flags: MappingFlags,
        pid: i32,
    ) -> AxResult<i32> {
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

    /// Detach a process from this segment.
    pub fn detach_process(&mut self, pid: u64) {
        self.shmid_ds.shm_nattch = self.shmid_ds.shm_nattch.saturating_sub(1);
        self.shmid_ds.shm_lpid = pid as i32;
    }

    /// Current attach count.
    pub fn attach_count(&self) -> u16 {
        self.shmid_ds.shm_nattch
    }
}

impl Drop for ShmInner {
    fn drop(&mut self) {
        if self.addr != 0 {
            global_allocator().dealloc_pages(self.addr, self.page_num);
            axlog::debug!(
                "[SharedMemory] dealloc pages: addr: {:#x}, page_count: {}, shmid: {}",
                self.addr,
                self.page_num,
                self.shmid
            );
        }
    }
}

// ShmInner is not Send+Sync because of kernel virtual address, but we wrap it in Arc<Mutex<>>
unsafe impl Send for ShmInner {}
unsafe impl Sync for ShmInner {}

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

    #[allow(dead_code)]
    fn get_by_value(&self, value: &V) -> Option<&K> {
        self.reverse.get(value)
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
    pub fn insert_key_shmid(&mut self, key: i32, shmid: i32) {
        self.key_shmid.insert(key, shmid);
    }

    /// Insert shmid -> ShmInner mapping.
    pub fn insert_shmid_inner(&mut self, shmid: i32, shm_inner: Arc<Mutex<ShmInner>>) {
        self.shmid_inner.insert(shmid, shm_inner);
    }

    /// Remove a shmid from the manager.
    pub fn remove_shmid(&mut self, shmid: i32) {
        self.key_shmid.remove_by_value(&shmid);
        self.shmid_inner.remove(&shmid);
    }

    /// Create a new shared memory segment.
    pub fn create_shm(&mut self, key: i32, size: usize, shmflg: i32, pid: i32) -> AxResult<i32> {
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
                let inner = self
                    .get_inner_by_shmid(shmid)
                    .ok_or(AxError::InvalidInput)?;
                let mut inner = inner.lock();
                return inner.try_update(size, mapping_flags, pid);
            }
        }

        let shmid = self.next_id();
        let inner = ShmInner::new(key, shmid, size, mapping_flags, pid);
        let inner = Arc::new(Mutex::new(inner));
        self.insert_key_shmid(key, shmid);
        self.insert_shmid_inner(shmid, inner);
        Ok(shmid)
    }
}

/// Global shared memory manager instance.
pub static SHM_MANAGER: Lazy<Mutex<ShmManager>> = Lazy::new(|| Mutex::new(ShmManager::new()));

fn align_up_4k(size: usize) -> usize {
    (size + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1)
}
