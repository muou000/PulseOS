//! System V semaphore implementation.

extern crate alloc;

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Lazy;
use crate::sync::Mutex;
use axerrno::{AxError, AxResult, ax_err};
use axtask::WaitQueue;

// IPC constants
pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;
pub const IPC_INFO: i32 = 3;
pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;

/// Linux-compatible `ipc_perm` structure (C ABI).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpcPerm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
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

/// Linux-compatible `semid_ds` structure (C ABI).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SemidDs {
    pub sem_perm: IpcPerm,
    pub sem_otime: i64,
    pub sem_ctime: i64,
    pub sem_nsems: usize,
    _reserved3: usize,
    _reserved4: usize,
}

impl SemidDs {
    pub fn new(key: i32, nsems: usize, mode: u16, pid: i32) -> Self {
        let now = axhal::time::wall_time().as_secs() as i64;
        Self {
            sem_perm: IpcPerm::new(key, mode, pid),
            sem_otime: 0,
            sem_ctime: now,
            sem_nsems: nsems,
            _reserved3: 0,
            _reserved4: 0,
        }
    }
}

pub struct Sem {
    pub semval: u16,
    pub sempid: i32,
    pub semncnt: u16,
    pub semzcnt: u16,
}

pub struct SemSetInner {
    pub semid: i32,
    pub nsems: usize,
    pub sems: Vec<Sem>,
    pub semid_ds: SemidDs,
    pub wait_queue: Arc<WaitQueue>,
    pub removed: bool,
}

impl SemSetInner {
    pub fn new(key: i32, semid: i32, nsems: usize, mode: u16, pid: i32) -> Self {
        let mut sems = Vec::with_capacity(nsems);
        for _ in 0..nsems {
            sems.push(Sem {
                semval: 0,
                sempid: pid,
                semncnt: 0,
                semzcnt: 0,
            });
        }
        Self {
            semid,
            nsems,
            sems,
            semid_ds: SemidDs::new(key, nsems, mode, pid),
            wait_queue: Arc::new(WaitQueue::new()),
            removed: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SemUndoEntry {
    pub semid: i32,
    pub sem_num: u16,
    pub undo_val: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SemBuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

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

pub struct SemManager {
    key_semid: BiBTreeMap<i32, i32>,
    semid_inner: BTreeMap<i32, Arc<Mutex<SemSetInner>>>,
    next_semid: AtomicI32,
}

impl SemManager {
    const fn new() -> Self {
        Self {
            key_semid: BiBTreeMap::new(),
            semid_inner: BTreeMap::new(),
            next_semid: AtomicI32::new(1),
        }
    }

    fn next_id(&self) -> i32 {
        self.next_semid.fetch_add(1, Ordering::Relaxed)
    }

    pub fn get_semid_by_key(&self, key: i32) -> Option<i32> {
        self.key_semid.get_by_key(&key).copied()
    }

    pub fn get_inner_by_semid(&self, semid: i32) -> Option<Arc<Mutex<SemSetInner>>> {
        self.semid_inner.get(&semid).cloned()
    }

    pub fn insert_key_semid(&mut self, key: i32, semid: i32) {
        self.key_semid.insert(key, semid);
    }

    pub fn insert_semid_inner(&mut self, semid: i32, sem_inner: Arc<Mutex<SemSetInner>>) {
        self.semid_inner.insert(semid, sem_inner);
    }

    pub fn remove_semid(&mut self, semid: i32) {
        self.key_semid.remove_by_value(&semid);
        self.semid_inner.remove(&semid);
    }

    pub fn create_sem(&mut self, key: i32, nsems: usize, semflg: i32, pid: i32) -> AxResult<i32> {
        let mode = (semflg & 0o777) as u16;

        if key != IPC_PRIVATE {
            if let Some(semid) = self.get_semid_by_key(key) {
                if (semflg & IPC_EXCL) != 0 {
                    return ax_err!(AlreadyExists, "semget: key already exists with IPC_EXCL");
                }
                let inner = self
                    .get_inner_by_semid(semid)
                    .ok_or(AxError::InvalidInput)?;
                let inner = inner.lock();
                if nsems > inner.nsems {
                    return ax_err!(InvalidInput, "semget: nsems greater than existing set");
                }
                return Ok(semid);
            }
        }

        if nsems == 0 {
            return ax_err!(InvalidInput, "semget: nsems must be > 0 when creating a new set");
        }

        let semid = self.next_id();
        let inner = SemSetInner::new(key, semid, nsems, mode, pid);
        let inner = Arc::new(Mutex::new(inner));
        if key != IPC_PRIVATE {
            self.insert_key_semid(key, semid);
        }
        self.insert_semid_inner(semid, inner);
        Ok(semid)
    }
}

pub static SEM_MANAGER: Lazy<Mutex<SemManager>> = Lazy::new(|| Mutex::new(SemManager::new()));

pub fn exit_sem_undos(pid: i32, undos: Vec<SemUndoEntry>) {
    let manager = SEM_MANAGER.lock();
    for entry in undos {
        if let Some(semset_arc) = manager.get_inner_by_semid(entry.semid) {
            let mut semset = semset_arc.lock();
            let idx = entry.sem_num as usize;
            if idx < semset.sems.len() {
                let sem = &mut semset.sems[idx];
                sem.semval = (sem.semval as i16).saturating_add(entry.undo_val) as u16;
                sem.sempid = pid;
            }
            semset.wait_queue.notify_all(true);
        }
    }
}
