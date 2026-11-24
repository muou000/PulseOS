//! System V semaphore implementation.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::time::Duration;

use axerrno::{LinuxError, LinuxResult};
use task::WaitQueue;
use spin::{Mutex, MutexGuard};

use crate::{IPC_CREAT, IPC_EXCL, IPC_PRIVATE, IpcPerm};

const IPC_NOWAIT: i16 = 0o4000;
const SEM_UNDO: i16 = 0o10000;
pub const GETPID: i32 = 11;
pub const GETVAL: i32 = 12;
pub const GETALL: i32 = 13;
pub const GETNCNT: i32 = 14;
pub const GETZCNT: i32 = 15;
pub const SETVAL: i32 = 16;
pub const SETALL: i32 = 17;

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

pulse_user_abi::impl_user_abi_struct! {
    for SemidDs, size = 80 => {
        sem_perm: IpcPerm,
        sem_otime: i64,
        sem_ctime: i64,
        sem_nsems: usize,
        _reserved3: usize,
        _reserved4: usize,
    }
}

impl SemidDs {
    fn new(key: i32, nsems: usize, mode: u16, pid: i32) -> Self {
        let now = hal::time::wall_time().as_secs() as i64;
        Self {
            sem_perm: IpcPerm {
                key,
                cuid: pid as u32,
                cgid: pid as u32,
                mode,
                ..Default::default()
            },
            sem_otime: 0,
            sem_ctime: now,
            sem_nsems: nsems,
            _reserved3: 0,
            _reserved4: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SemBuf {
    pub sem_num: u16,
    pub sem_op: i16,
    pub sem_flg: i16,
}

pulse_user_abi::impl_user_abi_struct! {
    for SemBuf, size = 6 => {
        sem_num: u16,
        sem_op: i16,
        sem_flg: i16,
    }
}

#[derive(Clone, Copy)]
struct Semaphore {
    value: u16,
    pid: i32,
    ncnt: usize,
    zcnt: usize,
}

struct SetState {
    sems: Vec<Semaphore>,
    status: SemidDs,
    removed: bool,
    revision: u64,
}

impl SetState {
    fn semaphore(&mut self, index: i32) -> LinuxResult<&mut Semaphore> {
        self.sems.get_mut(index as usize).ok_or(LinuxError::EINVAL)
    }

    // Stage the entire vector so an unsatisfied operation leaves every
    // semaphore unchanged, including when a later op repeats an index.
    fn try_commit(&mut self, ops: &[SemBuf], pid: i32) -> bool {
        let mut values: Vec<_> = self.sems.iter().map(|sem| sem.value).collect();
        for op in ops {
            let value = &mut values[usize::from(op.sem_num)];
            if op.sem_op > 0 {
                *value = value.saturating_add(op.sem_op as u16);
            } else if op.sem_op == 0 {
                if *value != 0 {
                    return false;
                }
            } else if let Some(reduced) = value.checked_sub(op.sem_op.unsigned_abs()) {
                *value = reduced;
            } else {
                return false;
            }
        }
        for op in ops {
            let index = usize::from(op.sem_num);
            self.sems[index].value = values[index];
            self.sems[index].pid = pid;
        }
        self.status.sem_otime = hal::time::wall_time().as_secs() as i64;
        self.revision = self.revision.wrapping_add(1);
        true
    }

    fn wait_counts(&mut self, ops: &[SemBuf], enrolling: bool) {
        for op in ops {
            let sem = &mut self.sems[usize::from(op.sem_num)];
            let count = if op.sem_op == 0 {
                &mut sem.zcnt
            } else {
                &mut sem.ncnt
            };
            if enrolling {
                *count += 1;
            } else {
                *count -= 1;
            }
        }
    }
}

struct Registry {
    keys: BTreeMap<i32, i32>,
    sets: BTreeMap<i32, Arc<SemSet>>,
    next_id: i32,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    keys: BTreeMap::new(),
    sets: BTreeMap::new(),
    next_id: 1,
});

/// Creates a semaphore set or resolves an existing key.
pub fn get_or_create(key: i32, nsems: i32, flags: i32, pid: i32) -> LinuxResult<i32> {
    if !(0..=250).contains(&nsems) {
        return Err(LinuxError::EINVAL);
    }
    let mut registry = REGISTRY.lock();
    if key != IPC_PRIVATE {
        let existing = registry.keys.get(&key).copied();
        if flags & IPC_CREAT == 0 {
            return existing.ok_or(LinuxError::ENOENT);
        }
        if let Some(id) = existing {
            if flags & IPC_EXCL != 0 {
                return Err(LinuxError::EEXIST);
            }
            if nsems as usize > registry.sets[&id].nsems {
                return Err(LinuxError::EINVAL);
            }
            return Ok(id);
        }
    }
    if nsems == 0 {
        return Err(LinuxError::EINVAL);
    }

    let nsems = nsems as usize;
    let id = registry.next_id;
    registry.next_id = id.wrapping_add(1);
    let set = SemSet {
        id,
        nsems,
        state: Mutex::new(SetState {
            sems: alloc::vec![Semaphore {value: 0, pid, ncnt: 0, zcnt: 0}; nsems],
            status: SemidDs::new(key, nsems, (flags & 0o777) as u16, pid),
            removed: false,
            revision: 0,
        }),
        wait_queue: WaitQueue::new(),
    };
    if key != IPC_PRIVATE {
        registry.keys.insert(key, id);
    }
    registry.sets.insert(id, Arc::new(set));
    Ok(id)
}

/// A System V semaphore set. An in-flight caller keeps its handle across sleeps.
pub struct SemSet {
    id: i32,
    nsems: usize,
    state: Mutex<SetState>,
    wait_queue: WaitQueue,
}

impl SemSet {
    /// Looks up an ID before the caller decodes further syscall arguments.
    pub fn lookup(id: i32) -> LinuxResult<Arc<Self>> {
        REGISTRY
            .lock()
            .sets
            .get(&id)
            .cloned()
            .ok_or(LinuxError::EINVAL)
    }

    fn live_state(&self) -> LinuxResult<MutexGuard<'_, SetState>> {
        let state = self.state.lock();
        if state.removed {
            Err(LinuxError::EIDRM)
        } else {
            Ok(state)
        }
    }

    pub fn remove(&self) -> LinuxResult {
        {
            let mut registry = REGISTRY.lock();
            let mut state = self.live_state()?;
            state.removed = true;
            registry.keys.remove(&state.status.sem_perm.key);
            registry.sets.remove(&self.id);
        }
        self.wait_queue.notify_all(true);
        Ok(())
    }

    pub fn status(&self) -> LinuxResult<SemidDs> {
        Ok(self.live_state()?.status)
    }

    pub fn set_permissions(&self, perms: IpcPerm) -> LinuxResult {
        let mut state = self.live_state()?;
        let current = &mut state.status.sem_perm;
        current.uid = perms.uid;
        current.gid = perms.gid;
        current.mode = (perms.mode & 0o777) | (current.mode & !0o777);
        state.status.sem_ctime = hal::time::wall_time().as_secs() as i64;
        Ok(())
    }

    pub fn get_scalar(&self, index: i32, command: i32) -> LinuxResult<isize> {
        let mut state = self.live_state()?;
        let sem = state.semaphore(index)?;
        match command {
            GETVAL => Ok(sem.value as isize),
            GETPID => Ok(sem.pid as isize),
            GETNCNT => Ok(sem.ncnt as isize),
            GETZCNT => Ok(sem.zcnt as isize),
            _ => Err(LinuxError::EINVAL),
        }
    }

    pub fn values(&self) -> LinuxResult<Vec<u16>> {
        Ok(self
            .live_state()?
            .sems
            .iter()
            .map(|sem| sem.value)
            .collect())
    }

    pub fn set_value(&self, index: i32, value: i32, pid: i32) -> LinuxResult {
        let mut state = self.live_state()?;
        let sem = state.semaphore(index)?;
        sem.value = u16::try_from(value).map_err(|_| LinuxError::EINVAL)?;
        sem.pid = pid;
        self.values_updated(state);
        Ok(())
    }

    pub fn set_values(&self, values: &[u16], pid: i32) -> LinuxResult {
        let mut state = self.live_state()?;
        if values.len() != self.nsems {
            return Err(LinuxError::EINVAL);
        }
        for (sem, &value) in state.sems.iter_mut().zip(values) {
            sem.value = value;
            sem.pid = pid;
        }
        self.values_updated(state);
        Ok(())
    }

    fn values_updated(&self, mut state: MutexGuard<'_, SetState>) {
        state.status.sem_ctime = hal::time::wall_time().as_secs() as i64;
        state.revision = state.revision.wrapping_add(1);
        drop(state);
        self.wait_queue.notify_all(true);
    }

    /// Applies one atomic semop vector, including its exit adjustments.
    /// The caller supplies the interruptible wait context for its thread.
    pub fn operate(
        &self,
        ops: &[SemBuf],
        pid: i32,
        undos: &SemUndo,
        timeout: Option<Duration>,
        signal_queue: &WaitQueue,
        signal_pending: impl Fn() -> bool,
    ) -> LinuxResult {
        let start = hal::time::monotonic_time();
        let mut state = self.live_state()?;
        if ops.is_empty() {
            return Err(LinuxError::EINVAL);
        }
        if ops.iter().any(|op| usize::from(op.sem_num) >= self.nsems) {
            return Err(LinuxError::EFBIG);
        }
        loop {
            if state.try_commit(ops, pid) {
                undos.record(self.id, ops);
                drop(state);
                self.wait_queue.notify_all(true);
                return Ok(());
            }
            if ops.iter().any(|op| op.sem_flg & IPC_NOWAIT != 0) {
                return Err(LinuxError::EAGAIN);
            }
            let elapsed = hal::time::monotonic_time().saturating_sub(start);
            let remaining = timeout.map(|limit| limit.saturating_sub(elapsed));
            if remaining == Some(Duration::ZERO) {
                return Err(LinuxError::EAGAIN);
            }

            state.wait_counts(ops, true);
            let observed = state.revision;
            drop(state);
            // Recheck the revision and signal state after wait-queue enrollment
            // so a wakeup between the failed operation and enrollment is visible.
            let wake = WaitQueue::wait_multiple_timeout_until(
                &[&self.wait_queue, signal_queue],
                remaining,
                || {
                    let state = self.state.lock();
                    let changed = state.removed || state.revision != observed;
                    drop(state);
                    changed || signal_pending()
                },
            );
            state = self.state.lock();
            state.wait_counts(ops, false);
            if state.removed {
                return Err(LinuxError::EIDRM);
            }
            drop(state);
            if signal_pending() {
                return Err(LinuxError::EINTR);
            }
            if wake == Err(true) {
                return Err(LinuxError::EAGAIN);
            }
            state = self.live_state()?;
        }
    }
}

struct UndoEntry {
    semid: i32,
    sem_num: u16,
    adjustment: i16,
}

/// Accumulated SEM_UNDO adjustments for one process.
#[derive(Default)]
pub struct SemUndo(Mutex<Vec<UndoEntry>>);

impl SemUndo {
    fn record(&self, semid: i32, ops: &[SemBuf]) {
        let mut entries = self.0.lock();
        for op in ops.iter().filter(|op| op.sem_flg & SEM_UNDO != 0) {
            if let Some(entry) = entries
                .iter_mut()
                .find(|e| e.semid == semid && e.sem_num == op.sem_num)
            {
                entry.adjustment = entry.adjustment.saturating_sub(op.sem_op);
            } else {
                entries.push(UndoEntry {
                    semid,
                    sem_num: op.sem_num,
                    adjustment: op.sem_op.wrapping_neg(),
                });
            }
        }
    }

    pub fn clear(&self) {
        self.0.lock().clear();
    }

    pub fn apply_on_exit(&self, pid: i32) {
        // Operations hold the set lock while recording undo. Drain our log
        // before acquiring any set lock to keep that lock order acyclic.
        let entries = core::mem::take(&mut *self.0.lock());
        for entry in entries {
            let Ok(set) = SemSet::lookup(entry.semid) else {
                continue;
            };
            let Ok(mut state) = set.live_state() else {
                continue;
            };
            let sem = &mut state.sems[usize::from(entry.sem_num)];
            sem.value = (sem.value as i16).saturating_add(entry.adjustment) as u16;
            sem.pid = pid;
            state.revision = state.revision.wrapping_add(1);
            drop(state);
            set.wait_queue.notify_all(true);
        }
    }
}
