use alloc::{
    collections::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, AtomicU64, Ordering};

use axconfig::TASK_STACK_SIZE;
use axerrno::{AxError, AxResult};
use axfs::FsContext;
use axhal::{
    context::{TrapFrame, UspaceContext},
    paging::MappingFlags,
};
use axmm::{AddrSpace, Backend};
use axtask::{AxTaskRef, TaskInner, WaitQueue};
use kernel_guard::NoPreemptIrqSave;
use linux_raw_sys::general::{RLIMIT_CORE, RLIMIT_MEMLOCK, RLIMIT_NOFILE, RLIMIT_STACK, SIGCHLD, rlimit64};
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr, va};
use spin::{Lazy, Mutex};

use super::{SignalShared, Thread, current_thread, queue_signal_to_process};
use crate::{
    config::*,
    fd_table::{FD_LIMIT, FdTable, SharedFdTable, stdio_entries},
};

const ROBUST_LIST_LIMIT: usize = 2048;
const DEFAULT_MEMLOCK_LIMIT_BYTES: u64 = u64::MAX;
const DEFAULT_STACK_LIMIT_BYTES: u64 = USER_STACK_SIZE as u64;
const MAX_STACK_LIMIT_BYTES: u64 = USER_STACK_SIZE as u64;
const DEFAULT_NOFILE_LIMIT: u64 = FD_LIMIT as u64;
const MAX_NOFILE_LIMIT: u64 = FD_LIMIT as u64;

static ZOMBIE_ASPACE_HANDLE: Lazy<Arc<Mutex<AddrSpace>>> = Lazy::new(|| {
    Arc::new(Mutex::new(
        axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)
            .expect("failed to create shared zombie addrspace"),
    ))
});

struct FutexTable {
    queues: Mutex<BTreeMap<usize, Arc<WaitQueue>>>,
}

#[derive(Clone, Copy, Debug)]
struct MemlockRange {
    start: usize,
    end: usize,
}

impl MemlockRange {
    const fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }
}

#[derive(Debug)]
struct MemlockState {
    ranges: Vec<MemlockRange>,
    locked_bytes: usize,
    soft_limit: u64,
    hard_limit: u64,
    mlock_future: bool,
}

impl MemlockState {
    fn new() -> Self {
        Self {
            ranges: Vec::new(),
            locked_bytes: 0,
            soft_limit: DEFAULT_MEMLOCK_LIMIT_BYTES,
            hard_limit: DEFAULT_MEMLOCK_LIMIT_BYTES,
            mlock_future: false,
        }
    }

    fn new_with_limits(soft_limit: u64, hard_limit: u64) -> Self {
        Self {
            ranges: Vec::new(),
            locked_bytes: 0,
            soft_limit,
            hard_limit,
            mlock_future: false,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct RlimitState {
    stack_soft: u64,
    stack_hard: u64,
    nofile_soft: u64,
    nofile_hard: u64,
    core_soft: u64,
    core_hard: u64,
}

impl Default for RlimitState {
    fn default() -> Self {
        Self {
            stack_soft: DEFAULT_STACK_LIMIT_BYTES,
            stack_hard: DEFAULT_STACK_LIMIT_BYTES,
            nofile_soft: DEFAULT_NOFILE_LIMIT,
            nofile_hard: DEFAULT_NOFILE_LIMIT,
            core_soft: 0,
            core_hard: u64::MAX,
        }
    }
}

impl FutexTable {
    fn new() -> Self {
        Self {
            queues: Mutex::new(BTreeMap::new()),
        }
    }

    fn queue(&self, addr: usize) -> Arc<WaitQueue> {
        let mut queues = self.queues.lock();
        queues
            .entry(addr)
            .or_insert_with(|| Arc::new(WaitQueue::new()))
            .clone()
    }

    fn wake(&self, addr: usize, count: usize) -> usize {
        let queue = {
            let queues = self.queues.lock();
            queues.get(&addr).cloned()
        };
        let Some(queue) = queue else {
            return 0;
        };

        let mut woken = 0;
        while woken < count && queue.notify_one(true) {
            woken += 1;
        }
        woken
    }

    fn wake_no_resched(&self, addr: usize, count: usize) -> usize {
        let queue = {
            let queues = self.queues.lock();
            queues.get(&addr).cloned()
        };
        let Some(queue) = queue else {
            return 0;
        };

        let mut woken = 0;
        while woken < count && queue.notify_one(false) {
            woken += 1;
        }
        woken
    }

    fn requeue(
        &self,
        addr: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
    ) -> usize {
        let source_queue = {
            let queues = self.queues.lock();
            queues.get(&addr).cloned()
        };
        let Some(source_queue) = source_queue else {
            return 0;
        };

        let mut moved = 0;
        let mut woken = 0;
        while woken < wake_count && source_queue.notify_one(true) {
            woken += 1;
        }

        if requeue_count != 0 {
            let target_queue = self.queue(target);
            moved = source_queue.requeue(requeue_count, &target_queue);
        }

        woken + moved
    }

    fn wake_all(&self) {
        let queues = {
            let queues = self.queues.lock();
            queues.values().cloned().collect::<Vec<_>>()
        };
        for queue in queues {
            queue.notify_all(false);
        }
    }

    fn clear(&self) {
        self.wake_all();
        self.queues.lock().clear();
    }
}

pub struct Process {
    pid: u64,
    parent_pid: u64,
    parent: Mutex<Option<Weak<Process>>>,
    aspace: Mutex<Arc<Mutex<AddrSpace>>>,
    pub heap_top: Arc<Mutex<usize>>,
    pub fs_context: Arc<Mutex<FsContext>>,
    pub fd_table: SharedFdTable,
    pub start_mono_ns: u64,
    pub user_time_ns: Arc<AtomicU64>,
    pub sys_time_ns: Arc<AtomicU64>,
    pub child_user_time_ns: Arc<AtomicU64>,
    pub child_sys_time_ns: Arc<AtomicU64>,
    pub last_user_enter_ns: Arc<AtomicU64>,
    pub in_user_mode: Arc<AtomicBool>,
    pub stack_top: Mutex<usize>,
    pub entry: Mutex<usize>,
    threads: Mutex<Vec<u64>>,
    task_refs: Mutex<Vec<AxTaskRef>>,
    children: Mutex<Vec<Arc<Process>>>,
    child_exit_event: WaitQueue,
    zombie: AtomicBool,
    user_resources_released: AtomicBool,
    exit_code: AtomicI32,
    /// 信号退出信息。
    /// 0 = 正常退出，>0 且低 7 位为信号号，bit8 (0x100) 为 core dump 标志
    exit_signal: AtomicI32,
    group_exiting: AtomicBool,
    group_exit_code: AtomicI32,
    futex_table: FutexTable,
    vfork_wait_enabled: AtomicBool,
    vfork_done: AtomicBool,
    vfork_event: WaitQueue,
    ruid: AtomicU32,
    euid: AtomicU32,
    suid: AtomicU32,
    rgid: AtomicU32,
    egid: AtomicU32,
    sgid: AtomicU32,
    umask: AtomicU32,
    rlimit_state: Mutex<RlimitState>,
    memlock_state: Mutex<MemlockState>,
    signal_shared: Arc<SignalShared>,
    exec_path: Mutex<Option<String>>,
    signal_trampoline: Mutex<usize>,
    pub shared_memory: Arc<Mutex<BTreeMap<VirtAddr, Arc<Mutex<crate::ipc::shm::ShmInner>>>>>,
    /// ITIMER_REAL state: (deadline_ns, interval_ns).
    /// 0 means the timer is disarmed. Uses atomics for interrupt-context safety.
    itimer_real_deadline_ns: AtomicU64,
    itimer_real_interval_ns: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ForkParams {
    pub child_stack: Option<usize>,
    pub is_vfork: bool,
    pub share_fs: bool,
    pub share_files: bool,
    pub parent_set_tid: Option<usize>,
    pub child_set_tid: Option<usize>,
    pub child_clear_tid: Option<usize>,
    pub share_sighand: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct CloneParams {
    pub child_stack: Option<usize>,
    pub is_thread_clone: bool,
    pub is_vfork: bool,
    pub share_fs: bool,
    pub share_files: bool,
    pub parent_set_tid: Option<usize>,
    pub child_set_tid: Option<usize>,
    pub child_clear_tid: Option<usize>,
    pub share_sighand: bool,
}

impl Process {
    fn memlock_additional_bytes(ranges: &[MemlockRange], start: usize, end: usize) -> usize {
        if start >= end {
            return 0;
        }
        let mut covered = 0usize;
        for range in ranges {
            if range.end <= start {
                continue;
            }
            if range.start >= end {
                break;
            }
            let overlap_start = core::cmp::max(range.start, start);
            let overlap_end = core::cmp::min(range.end, end);
            if overlap_start < overlap_end {
                covered = covered.saturating_add(overlap_end - overlap_start);
            }
        }
        (end - start).saturating_sub(covered)
    }

    fn memlock_insert_range(ranges: &mut Vec<MemlockRange>, start: usize, end: usize) -> AxResult {
        if start >= end {
            return Ok(());
        }
        let mut merged_start = start;
        let mut merged_end = end;
        let mut merged = Vec::new();
        if merged
            .try_reserve_exact(ranges.len().saturating_add(1))
            .is_err()
        {
            return Err(AxError::NoMemory);
        }
        let mut inserted = false;
        for range in ranges.iter().copied() {
            if range.end < merged_start {
                merged.push(range);
                continue;
            }
            if merged_end < range.start {
                if !inserted {
                    merged.push(MemlockRange::new(merged_start, merged_end));
                    inserted = true;
                }
                merged.push(range);
                continue;
            }
            merged_start = core::cmp::min(merged_start, range.start);
            merged_end = core::cmp::max(merged_end, range.end);
        }
        if !inserted {
            merged.push(MemlockRange::new(merged_start, merged_end));
        }
        *ranges = merged;
        Ok(())
    }

    fn memlock_remove_range(
        ranges: &mut Vec<MemlockRange>,
        start: usize,
        end: usize,
    ) -> AxResult<usize> {
        if start >= end {
            return Ok(0);
        }
        let mut removed = 0usize;
        let mut next = Vec::new();
        if next.try_reserve_exact(ranges.len()).is_err() {
            return Err(AxError::NoMemory);
        }
        for range in ranges.iter().copied() {
            if range.end <= start || range.start >= end {
                next.push(range);
                continue;
            }
            let overlap_start = core::cmp::max(range.start, start);
            let overlap_end = core::cmp::min(range.end, end);
            if overlap_start < overlap_end {
                removed = removed.saturating_add(overlap_end - overlap_start);
            }
            if range.start < overlap_start {
                next.push(MemlockRange::new(range.start, overlap_start));
            }
            if overlap_end < range.end {
                next.push(MemlockRange::new(overlap_end, range.end));
            }
        }
        *ranges = next;
        Ok(removed)
    }

    fn validate_user_range(&self, user_addr: usize, len: usize) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }

        let user_end = user_addr.checked_add(len).ok_or(AxError::BadAddress)?;
        let user_space_end = USER_SPACE_BASE
            .checked_add(USER_SPACE_SIZE)
            .ok_or(AxError::BadAddress)?;
        if user_addr < USER_SPACE_BASE || user_end > user_space_end {
            return Err(AxError::BadAddress);
        }
        Ok(())
    }

    fn clone_private_fs_context(parent: &Process) -> AxResult<Arc<Mutex<FsContext>>> {
        Ok(Arc::new(Mutex::new(parent.fs_context.lock().clone())))
    }

    pub fn pid(&self) -> u64 {
        self.pid
    }

    pub fn exec_path(&self) -> Option<String> {
        self.exec_path.lock().clone()
    }

    pub fn set_exec_path(&self, path: String) {
        *self.exec_path.lock() = Some(path);
    }

    pub fn signal_trampoline(&self) -> usize {
        *self.signal_trampoline.lock()
    }

    pub fn set_signal_trampoline(&self, trampoline: usize) {
        *self.signal_trampoline.lock() = trampoline;
    }

    pub fn parent_pid(&self) -> u64 {
        self.parent_pid
    }

    pub fn thread_count(&self) -> usize {
        self.threads.lock().len()
    }

    pub fn thread_ids_snapshot(&self) -> Vec<u64> {
        self.threads.lock().clone()
    }

    pub fn ruid(&self) -> u32 {
        self.ruid.load(Ordering::Acquire)
    }

    pub fn euid(&self) -> u32 {
        self.euid.load(Ordering::Acquire)
    }

    pub fn suid(&self) -> u32 {
        self.suid.load(Ordering::Acquire)
    }

    pub fn rgid(&self) -> u32 {
        self.rgid.load(Ordering::Acquire)
    }

    pub fn egid(&self) -> u32 {
        self.egid.load(Ordering::Acquire)
    }

    pub fn sgid(&self) -> u32 {
        self.sgid.load(Ordering::Acquire)
    }

    pub fn umask(&self) -> u32 {
        self.umask.load(Ordering::Acquire)
    }

    pub fn set_umask(&self, umask: u32) -> u32 {
        self.umask.swap(umask, Ordering::AcqRel)
    }

    pub fn uid_snapshot(&self) -> (u32, u32, u32) {
        (self.ruid(), self.euid(), self.suid())
    }

    pub fn gid_snapshot(&self) -> (u32, u32, u32) {
        (self.rgid(), self.egid(), self.sgid())
    }

    pub fn set_uids(&self, ruid: u32, euid: u32, suid: u32) {
        self.ruid.store(ruid, Ordering::Release);
        self.euid.store(euid, Ordering::Release);
        self.suid.store(suid, Ordering::Release);
    }

    pub fn set_gids(&self, rgid: u32, egid: u32, sgid: u32) {
        self.rgid.store(rgid, Ordering::Release);
        self.egid.store(egid, Ordering::Release);
        self.sgid.store(sgid, Ordering::Release);
    }

    pub fn is_root_user(&self) -> bool {
        self.euid() == 0
    }

    pub fn memlock_limit_snapshot(&self) -> (u64, u64) {
        let state = self.memlock_state.lock();
        (state.soft_limit, state.hard_limit)
    }

    pub fn memlock_set_limit(&self, soft: u64, hard: u64) {
        let mut state = self.memlock_state.lock();
        state.soft_limit = soft;
        state.hard_limit = hard;
    }

    pub fn get_rlimit(&self, resource: u32) -> Option<rlimit64> {
        match resource {
            RLIMIT_STACK => {
                let state = self.rlimit_state.lock();
                Some(rlimit64 {
                    rlim_cur: state.stack_soft,
                    rlim_max: state.stack_hard,
                })
            }
            RLIMIT_NOFILE => {
                let state = self.rlimit_state.lock();
                Some(rlimit64 {
                    rlim_cur: state.nofile_soft,
                    rlim_max: state.nofile_hard,
                })
            }
            RLIMIT_CORE => {
                let state = self.rlimit_state.lock();
                Some(rlimit64 {
                    rlim_cur: state.core_soft,
                    rlim_max: state.core_hard,
                })
            }
            RLIMIT_MEMLOCK => {
                let state = self.memlock_state.lock();
                Some(rlimit64 {
                    rlim_cur: state.soft_limit,
                    rlim_max: state.hard_limit,
                })
            }
            _ => None,
        }
    }

    pub fn set_rlimit(&self, resource: u32, limit: rlimit64) -> AxResult<()> {
        if limit.rlim_cur > limit.rlim_max {
            return Err(AxError::InvalidInput);
        }
        match resource {
            RLIMIT_STACK => {
                if limit.rlim_max > MAX_STACK_LIMIT_BYTES {
                    return Err(AxError::InvalidInput);
                }
                let mut state = self.rlimit_state.lock();
                state.stack_soft = limit.rlim_cur;
                state.stack_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_NOFILE => {
                if limit.rlim_max > MAX_NOFILE_LIMIT {
                    return Err(AxError::InvalidInput);
                }
                let mut state = self.rlimit_state.lock();
                state.nofile_soft = limit.rlim_cur;
                state.nofile_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_CORE => {
                let mut state = self.rlimit_state.lock();
                state.core_soft = limit.rlim_cur;
                state.core_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_MEMLOCK => {
                let mut state = self.memlock_state.lock();
                state.soft_limit = limit.rlim_cur;
                state.hard_limit = limit.rlim_max;
                Ok(())
            }
            _ => Err(AxError::InvalidInput),
        }
    }

    pub fn memlock_locked_bytes(&self) -> usize {
        self.memlock_state.lock().locked_bytes
    }

    pub fn memlock_future_enabled(&self) -> bool {
        self.memlock_state.lock().mlock_future
    }

    pub fn memlock_set_future(&self, enabled: bool) {
        self.memlock_state.lock().mlock_future = enabled;
    }

    pub fn memlock_try_lock_range(
        &self,
        start: usize,
        len: usize,
        privileged: bool,
    ) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start.checked_add(len).ok_or(AxError::BadAddress)?;
        let mut state = self.memlock_state.lock();
        let additional = Self::memlock_additional_bytes(&state.ranges, start, end);
        if additional == 0 {
            return Ok(());
        }
        if !privileged && state.soft_limit != u64::MAX {
            let new_total = (state.locked_bytes as u128).saturating_add(additional as u128);
            if new_total > state.soft_limit as u128 {
                return Err(AxError::NoMemory);
            }
        }
        Self::memlock_insert_range(&mut state.ranges, start, end)?;
        state.locked_bytes = state.locked_bytes.saturating_add(additional);
        Ok(())
    }

    pub fn memlock_unlock_range(&self, start: usize, len: usize) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start.checked_add(len).ok_or(AxError::BadAddress)?;
        let mut state = self.memlock_state.lock();
        let removed = Self::memlock_remove_range(&mut state.ranges, start, end)?;
        state.locked_bytes = state.locked_bytes.saturating_sub(removed);
        Ok(())
    }

    pub fn memlock_unlock_all(&self) {
        let mut state = self.memlock_state.lock();
        state.ranges.clear();
        state.locked_bytes = 0;
        state.mlock_future = false;
    }

    fn try_fault_in_user_range(
        &self,
        user_addr: usize,
        len: usize,
        access: MappingFlags,
    ) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = user_addr.checked_add(len).ok_or(AxError::BadAddress)?;
        let start_page = VirtAddr::from(user_addr).align_down_4k();
        let end_page = VirtAddr::from(end).align_up_4k();
        let access = access | MappingFlags::USER;

        let aspace_handle = self.aspace_handle();
        let mut aspace = aspace_handle.lock();
        let pages =
            memory_addr::PageIter4K::new(start_page, end_page).ok_or(AxError::BadAddress)?;
        for page in pages {
            if !aspace.handle_page_fault(page, access) {
                return Err(AxError::BadAddress);
            }
        }
        Ok(())
    }

    fn write_user_bytes_in_aspace(
        &self,
        aspace: &mut AddrSpace,
        user_addr: usize,
        bytes: &[u8],
    ) -> AxResult<()> {
        self.validate_user_range(user_addr, bytes.len())?;
        let start = VirtAddr::from(user_addr);

        // Try fast path first without faulting.
        if let Ok(()) = aspace.write(start, bytes) {
            return Ok(());
        }

        // If it fails, fault-in the pages and retry once.
        let end = user_addr
            .checked_add(bytes.len())
            .ok_or(AxError::BadAddress)?;
        let start_page = VirtAddr::from(user_addr).align_down_4k();
        let end_page = VirtAddr::from(end).align_up_4k();
        let pages =
            memory_addr::PageIter4K::new(start_page, end_page).ok_or(AxError::BadAddress)?;
        for page in pages {
            if !aspace.handle_page_fault(page, MappingFlags::WRITE | MappingFlags::USER) {
                return Err(AxError::BadAddress);
            }
        }
        aspace.write(start, bytes).map_err(AxError::from)
    }

    pub fn read_user_bytes(&self, user_addr: usize, bytes: &mut [u8]) -> AxResult<()> {
        self.validate_user_range(user_addr, bytes.len())?;
        let start = VirtAddr::from(user_addr);
        let aspace_handle = self.aspace_handle();

        // Try fast path first without faulting
        if let Ok(()) = aspace_handle.lock().read(start, bytes) {
            return Ok(());
        }

        // If it fails, fault-in the pages and retry once
        self.try_fault_in_user_range(user_addr, bytes.len(), MappingFlags::READ)?;
        aspace_handle
            .lock()
            .read(start, bytes)
            .map_err(AxError::from)
    }

    pub fn write_user_bytes(&self, user_addr: usize, bytes: &[u8]) -> AxResult<()> {
        let aspace_handle = self.aspace_handle();
        let mut aspace = aspace_handle.lock();
        self.write_user_bytes_in_aspace(&mut aspace, user_addr, bytes)
    }

    pub fn aspace_handle(&self) -> Arc<Mutex<AddrSpace>> {
        self.aspace.lock().clone()
    }

    pub fn replace_aspace_handle(
        &self,
        new_aspace: Arc<Mutex<AddrSpace>>,
    ) -> Arc<Mutex<AddrSpace>> {
        let mut slot = self.aspace.lock();
        core::mem::replace(&mut *slot, new_aspace)
    }

    pub fn page_table_root(&self) -> PhysAddr {
        self.aspace_handle().lock().page_table_root()
    }

    pub fn read_user_u32(&self, user_addr: usize) -> AxResult<u32> {
        let mut bytes = [0u8; core::mem::size_of::<u32>()];
        self.read_user_bytes(user_addr, &mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    pub fn read_user_usize(&self, user_addr: usize) -> AxResult<usize> {
        let mut bytes = [0u8; core::mem::size_of::<usize>()];
        self.read_user_bytes(user_addr, &mut bytes)?;
        Ok(usize::from_ne_bytes(bytes))
    }

    pub fn read_user_isize(&self, user_addr: usize) -> AxResult<isize> {
        let mut bytes = [0u8; core::mem::size_of::<isize>()];
        self.read_user_bytes(user_addr, &mut bytes)?;
        Ok(isize::from_ne_bytes(bytes))
    }

    pub fn write_user_u32(&self, user_addr: usize, value: u32) -> AxResult<()> {
        self.write_user_bytes(user_addr, &value.to_ne_bytes())
    }

    pub fn write_user_i32(&self, user_addr: usize, value: i32) -> AxResult<()> {
        self.write_user_bytes(user_addr, &value.to_ne_bytes())
    }

    pub fn write_user_usize(&self, user_addr: usize, value: usize) -> AxResult<()> {
        self.write_user_bytes(user_addr, &value.to_ne_bytes())
    }

    pub fn new_uspace(pid: u64) -> AxResult<Arc<Self>> {
        let mut aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;
        aspace.map_alloc(
            va!(USER_HEAP_BASE),
            USER_HEAP_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;
        let fs_context = axfs::ROOT_FS_CONTEXT
            .get()
            .expect("root fs context not initialized")
            .clone();

        let mut fd_table = FdTable::new();
        for (fd, entry) in stdio_entries().into_iter().enumerate() {
            let _ = fd_table.insert_at(fd, entry);
        }

        Ok(Arc::new(Self {
            pid,
            parent_pid: 0,
            parent: Mutex::new(None),
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            aspace: Mutex::new(Arc::new(Mutex::new(aspace))),
            fs_context: Arc::new(Mutex::new(fs_context)),
            fd_table: Arc::new(Mutex::new(fd_table)),
            user_time_ns: Arc::new(AtomicU64::new(0)),
            sys_time_ns: Arc::new(AtomicU64::new(0)),
            child_user_time_ns: Arc::new(AtomicU64::new(0)),
            child_sys_time_ns: Arc::new(AtomicU64::new(0)),
            last_user_enter_ns: Arc::new(AtomicU64::new(0)),
            in_user_mode: Arc::new(AtomicBool::new(false)),
            stack_top: Mutex::new(USER_STACK_TOP),
            entry: Mutex::new(0),
            threads: Mutex::new(alloc::vec![pid]),
            task_refs: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            user_resources_released: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            exit_signal: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_wait_enabled: AtomicBool::new(false),
            vfork_done: AtomicBool::new(false),
            vfork_event: WaitQueue::new(),
            ruid: AtomicU32::new(0),
            euid: AtomicU32::new(0),
            suid: AtomicU32::new(0),
            rgid: AtomicU32::new(0),
            heap_top: Arc::new(Mutex::new(USER_HEAP_BASE + USER_HEAP_SIZE)),
            egid: AtomicU32::new(0),
            sgid: AtomicU32::new(0),
            umask: AtomicU32::new(0o022),
            rlimit_state: Mutex::new(RlimitState::default()),
            memlock_state: Mutex::new(MemlockState::new()),
            signal_shared: SignalShared::new(),
            exec_path: Mutex::new(None),
            signal_trampoline: Mutex::new(0),
            shared_memory: Arc::new(Mutex::new(BTreeMap::new())),
            itimer_real_deadline_ns: AtomicU64::new(0),
            itimer_real_interval_ns: AtomicU64::new(0),
        }))
    }

    fn new_child_process(
        pid: u64,
        parent: Arc<Process>,
        aspace: Arc<Mutex<AddrSpace>>,
        share_vm: bool,
        is_vfork: bool,
        share_fs: bool,
        share_files: bool,
        share_sighand: bool,
    ) -> AxResult<Arc<Self>> {
        let parent_arc = parent;
        let parent = parent_arc.as_ref();
        let heap_top = if share_vm {
            parent.heap_top.clone()
        } else {
            Arc::new(Mutex::new(*parent.heap_top.lock()))
        };
        let shared_memory = if share_vm {
            parent.shared_memory.clone()
        } else {
            let mut new_shm = BTreeMap::new();
            let parent_shm = parent.shared_memory.lock();
            for (vaddr, inner_arc) in parent_shm.iter() {
                inner_arc.lock().attach_process(pid);
                new_shm.insert(*vaddr, inner_arc.clone());
            }
            Arc::new(Mutex::new(new_shm))
        };
        let fs_context = if share_fs {
            parent.fs_context.clone()
        } else {
            Self::clone_private_fs_context(parent)?
        };
        let fd_table = if share_files {
            parent.fd_table.clone()
        } else {
            Arc::new(Mutex::new(parent.fd_table.lock().clone_for_fork()?))
        };
        let (ruid, euid, suid) = parent.uid_snapshot();
        let (rgid, egid, sgid) = parent.gid_snapshot();
        let rlimit_state = *parent.rlimit_state.lock();
        let (memlock_soft_limit, memlock_hard_limit) = parent.memlock_limit_snapshot();
        let signal_shared = if share_sighand {
            parent.signal_shared.clone()
        } else {
            SignalShared::clone_actions_only(&parent.signal_shared)
        };
        let signal_trampoline = *parent.signal_trampoline.lock();

        Ok(Arc::new(Self {
            pid,
            parent_pid: parent.pid(),
            parent: Mutex::new(Some(Arc::downgrade(&parent_arc))),
            aspace: Mutex::new(aspace),
            heap_top,
            fs_context,
            fd_table,
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            user_time_ns: Arc::new(AtomicU64::new(0)),
            sys_time_ns: Arc::new(AtomicU64::new(0)),
            child_user_time_ns: Arc::new(AtomicU64::new(0)),
            child_sys_time_ns: Arc::new(AtomicU64::new(0)),
            last_user_enter_ns: Arc::new(AtomicU64::new(0)),
            in_user_mode: Arc::new(AtomicBool::new(false)),
            stack_top: Mutex::new(*parent.stack_top.lock()),
            entry: Mutex::new(*parent.entry.lock()),
            threads: Mutex::new(alloc::vec![pid]),
            task_refs: Mutex::new(Vec::new()),
            children: Mutex::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            user_resources_released: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            exit_signal: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_wait_enabled: AtomicBool::new(is_vfork),
            vfork_done: AtomicBool::new(false),
            vfork_event: WaitQueue::new(),
            ruid: AtomicU32::new(ruid),
            euid: AtomicU32::new(euid),
            suid: AtomicU32::new(suid),
            rgid: AtomicU32::new(rgid),
            egid: AtomicU32::new(egid),
            sgid: AtomicU32::new(sgid),
            umask: AtomicU32::new(parent.umask()),
            rlimit_state: Mutex::new(rlimit_state),
            memlock_state: Mutex::new(MemlockState::new_with_limits(
                memlock_soft_limit,
                memlock_hard_limit,
            )),
            signal_shared,
            exec_path: Mutex::new(None),
            signal_trampoline: Mutex::new(signal_trampoline),
            shared_memory,
            itimer_real_deadline_ns: AtomicU64::new(0),
            itimer_real_interval_ns: AtomicU64::new(0),
        }))
    }

    pub fn signal_shared(&self) -> Arc<SignalShared> {
        self.signal_shared.clone()
    }

    pub fn handle_page_fault(&self, vaddr: VirtAddr, flags: axhal::trap::PageFaultFlags) -> bool {
        self.aspace_handle().lock().handle_page_fault(vaddr, flags)
    }

    pub fn activate(&self) {
        let pt_root = self.page_table_root();
        unsafe {
            axhal::asm::write_user_page_table(pt_root);
            axhal::asm::flush_tlb(None);
        }
    }

    pub fn close_all_files(&self) {
        let _entries = {
            let mut table = self.fd_table.lock();
            table.drain_all()
        };
    }

    fn release_zombie_resources(&self, switch_current_aspace: bool) -> AxResult<()> {
        if self.user_resources_released.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let new_handle = ZOMBIE_ASPACE_HANDLE.clone();
        let new_pt_root = new_handle.lock().page_table_root();
        let old_handle = self.replace_aspace_handle(new_handle);
        if switch_current_aspace {
            axtask::set_current_page_table_root(new_pt_root);
            self.activate();
        }
        drop(old_handle);
        *self.heap_top.lock() = USER_HEAP_BASE;
        *self.stack_top.lock() = USER_STACK_TOP;
        *self.entry.lock() = 0;
        
        {
            let mut shm = self.shared_memory.lock();
            for inner_arc in shm.values() {
                inner_arc.lock().detach_process(self.pid());
            }
            shm.clear();
        }

        self.close_all_files();
        self.futex_table.clear();
        self.memlock_unlock_all();
        axlog::info!("release_zombie_resources: pid={}", self.pid());
        Ok(())
    }

    pub fn shrink_reaped_resources(&self) -> AxResult<()> {
        self.release_zombie_resources(false)
    }

    pub fn sync_fs_context(&self) {
        *axfs::FS_CONTEXT.lock() = self.fs_context.lock().clone();
    }

    pub fn save_fs_context(&self) {
        *self.fs_context.lock() = axfs::FS_CONTEXT.lock().clone();
    }

    pub fn register_thread(&self, tid: u64) {
        let mut threads = self.threads.lock();
        if !threads.contains(&tid) {
            threads.push(tid);
        }
    }

    pub fn register_task_ref(&self, task: AxTaskRef) {
        if let Some(handle) = super::thread_handle_from_task(&task) {
            handle.attach_task_ref(task.clone());
        }
        let mut task_refs = self.task_refs.lock();
        let tid = task.id().as_u64();
        if task_refs
            .iter()
            .any(|task_ref| task_ref.id().as_u64() == tid)
        {
            return;
        }
        task_refs.push(task);
    }

    pub fn task_ref_by_tid(&self, tid: u64) -> Option<AxTaskRef> {
        self.task_refs
            .lock()
            .iter()
            .find(|task| task.id().as_u64() == tid)
            .cloned()
    }

    pub fn take_task_ref_by_tid(&self, tid: u64) -> Option<AxTaskRef> {
        let mut task_refs = self.task_refs.lock();
        let idx = task_refs
            .iter()
            .position(|task| task.id().as_u64() == tid)?;
        Some(task_refs.remove(idx))
    }

    pub fn wait_task_refs_exited(&self) {
        let task_refs = self.task_refs.lock().clone();
        for task in task_refs {
            let _ = task.join();
        }
    }

    pub fn release_task_refs(&self) {
        self.task_refs.lock().clear();
    }

    pub fn unregister_thread(&self, tid: u64) -> usize {
        let mut threads = self.threads.lock();
        threads.retain(|thread_tid| *thread_tid != tid);
        threads.len()
    }

    pub fn begin_group_exit(&self, exit_code: i32) {
        self.group_exit_code.store(exit_code, Ordering::Release);
        self.group_exiting.store(true, Ordering::Release);
        self.futex_table.wake_all();
    }

    pub fn group_exiting(&self) -> bool {
        self.group_exiting.load(Ordering::Acquire)
    }

    pub fn group_exit_code(&self) -> i32 {
        self.group_exit_code.load(Ordering::Acquire)
    }

    pub fn is_zombie(&self) -> bool {
        self.zombie.load(Ordering::Acquire)
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code.load(Ordering::Acquire)
    }

    /// 设置信号终止信息。
    /// - `signo`：终止进程的信号号（SIGABRT=6, SIGSEGV=11 等）
    /// - `coredump`：是否设置 core dump 标志位（不需要实际写文件）
    pub fn set_exit_signal(&self, signo: i32, coredump: bool) {
        let val = if coredump { signo | 0x100 } else { signo };
        self.exit_signal.store(val, Ordering::Release);
    }

    /// 计算 Linux `wait4` 的 status word。
    /// - 正常退出：`(exit_code & 0xff) << 8`（WIFEXITED 为真）
    /// - 信号终止：`signo & 0x7f`（WIFSIGNALED 为真）
    /// - 信号终止且 core dump：`(signo & 0x7f) | 0x80`（WCOREDUMP 也为真）
    pub fn wait_status_word(&self) -> i32 {
        let sig_val = self.exit_signal.load(Ordering::Acquire);
        if sig_val == 0 {
            // 正常退出：(exit_code & 0xff) << 8
            (self.exit_code.load(Ordering::Acquire) & 0xff) << 8
        } else {
            let signo = sig_val & 0x7f;
            let coredump = if (sig_val & 0x100) != 0 { 0x80i32 } else { 0 };
            signo | coredump
        }
    }

    pub fn finish_thread_exit(&self, tid: u64, exit_code: i32) {
        if tid != self.pid() {
            let _ = self.take_task_ref_by_tid(tid);
        }
        let remaining = self.unregister_thread(tid);
        axlog::debug!(
            "finish_thread_exit: pid={}, tid={}, remaining_threads={}, group_exiting={}",
            self.pid(),
            tid,
            remaining,
            self.group_exiting()
        );
        if remaining != 0 {
            return;
        }

        let final_code = if self.group_exiting() {
            self.group_exit_code()
        } else {
            exit_code
        };
        self.task_refs.lock().clear();
        self.exit_code.store(final_code, Ordering::Release);
        self.zombie.store(true, Ordering::Release);
        self.complete_vfork();
        if let Err(e) = self.release_zombie_resources(true) {
            axlog::warn!(
                "finish_thread_exit: failed to release zombie resources for pid={}: {:?}",
                self.pid(),
                e
            );
        }

        let parent = self
            .parent
            .lock()
            .as_ref()
            .and_then(|parent| parent.upgrade());
        if let Some(parent) = parent {
            let _ = queue_signal_to_process(parent.as_ref(), SIGCHLD as usize);
            // The exiting task is still on its own kernel stack here.
            // Wake waiters without forcing an immediate reschedule from inside
            // the teardown path.
            parent.child_exit_event.notify_all(false);
        }
    }

    pub fn add_child(&self, child: Arc<Process>) {
        self.children.lock().push(child);
    }

    fn child_matches(child: &Process, pid: isize) -> bool {
        let child_pid = child.pid() as isize;
        pid == -1 || child_pid == pid || pid == 0 || (pid < -1 && child_pid == -pid)
    }

    pub fn has_matching_child(&self, pid: isize) -> bool {
        self.children
            .lock()
            .iter()
            .any(|child| Self::child_matches(child, pid))
    }

    pub fn reap_zombie_child(&self, pid: isize) -> Option<Arc<Process>> {
        let mut children = self.children.lock();
        let idx = children
            .iter()
            .position(|child| Self::child_matches(child, pid) && child.is_zombie())?;
        Some(children.remove(idx))
    }

    pub fn wait_for_child_exit(&self, pid: isize) {
        self.child_exit_event.wait_until(|| {
            self.children
                .lock()
                .iter()
                .any(|child| Self::child_matches(child, pid) && child.is_zombie())
        });
    }

    pub fn mark_user_resume(&self) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        self.last_user_enter_ns.store(now_ns, Ordering::Relaxed);
        self.in_user_mode.store(true, Ordering::Release);
    }

    pub fn on_kernel_entry_from_user(&self, now_ns: u64) {
        if self.in_user_mode.swap(false, Ordering::AcqRel) {
            let last = self.last_user_enter_ns.load(Ordering::Relaxed);
            let delta = now_ns.saturating_sub(last);
            self.user_time_ns.fetch_add(delta, Ordering::Relaxed);
        }
    }

    pub fn add_sys_time_ns(&self, delta_ns: u64) {
        self.sys_time_ns.fetch_add(delta_ns, Ordering::Relaxed);
    }

    pub fn add_child_time_ns(&self, child_user_ns: u64, child_sys_ns: u64) {
        self.child_user_time_ns
            .fetch_add(child_user_ns, Ordering::Relaxed);
        self.child_sys_time_ns
            .fetch_add(child_sys_ns, Ordering::Relaxed);
    }

    pub fn snapshot_cpu_time_ns(&self, now_ns: u64) -> (u64, u64) {
        let mut user = self.user_time_ns.load(Ordering::Relaxed);
        let sys = self.sys_time_ns.load(Ordering::Relaxed);
        if self.in_user_mode.load(Ordering::Acquire) {
            let last = self.last_user_enter_ns.load(Ordering::Relaxed);
            user = user.saturating_add(now_ns.saturating_sub(last));
        }
        (user, sys)
    }

    pub fn snapshot_children_cpu_time_ns(&self) -> (u64, u64) {
        (
            self.child_user_time_ns.load(Ordering::Relaxed),
            self.child_sys_time_ns.load(Ordering::Relaxed),
        )
    }

    pub fn read_sys_time_ns(&self) -> u64 {
        self.sys_time_ns.load(Ordering::Relaxed)
    }

    /// Set ITIMER_REAL. Returns the previous (remaining_ns, interval_ns).
    /// `value_ns` is the initial timeout in nanoseconds (0 = disarm).
    /// `interval_ns` is the repeat interval (0 = one-shot).
    pub fn set_itimer_real(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let old_deadline = self.itimer_real_deadline_ns.load(Ordering::Acquire);
        let old_interval = self.itimer_real_interval_ns.load(Ordering::Acquire);
        let old_remaining = if old_deadline == 0 {
            0
        } else if now_ns >= old_deadline {
            0
        } else {
            old_deadline - now_ns
        };

        if value_ns == 0 {
            // Disarm
            self.itimer_real_deadline_ns.store(0, Ordering::Release);
            self.itimer_real_interval_ns.store(0, Ordering::Release);
        } else {
            let deadline = now_ns.saturating_add(value_ns);
            self.itimer_real_deadline_ns.store(deadline, Ordering::Release);
            self.itimer_real_interval_ns.store(interval_ns, Ordering::Release);
        }
        (old_remaining, old_interval)
    }

    /// Get ITIMER_REAL. Returns (remaining_ns, interval_ns).
    pub fn get_itimer_real(&self) -> (u64, u64) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let deadline = self.itimer_real_deadline_ns.load(Ordering::Acquire);
        let interval = self.itimer_real_interval_ns.load(Ordering::Acquire);
        let remaining = if deadline == 0 {
            0
        } else if now_ns >= deadline {
            0
        } else {
            deadline - now_ns
        };
        (remaining, interval)
    }

    /// Called from timer tick hook (interrupt context). Checks if ITIMER_REAL
    /// has expired and sends SIGALRM if so. Returns true if the timer fired.
    pub fn check_itimer_real_tick(&self) -> bool {
        let deadline = self.itimer_real_deadline_ns.load(Ordering::Acquire);
        if deadline == 0 {
            return false;
        }
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        if now_ns < deadline {
            return false;
        }
        // Timer expired. Send SIGALRM (signal 14).
        let _ = queue_signal_to_process(self, 14 /* SIGALRM */);
        let interval = self.itimer_real_interval_ns.load(Ordering::Acquire);
        if interval == 0 {
            // One-shot: disarm
            self.itimer_real_deadline_ns.store(0, Ordering::Release);
        } else {
            // Repeating: advance deadline
            let new_deadline = deadline.saturating_add(interval);
            self.itimer_real_deadline_ns.store(new_deadline, Ordering::Release);
        }
        true
    }

    pub fn complete_vfork(&self) {
        if !self.vfork_wait_enabled.load(Ordering::Acquire) {
            return;
        }
        if !self.vfork_done.swap(true, Ordering::AcqRel) {
            // Keep vfork completion notification side-effect free with respect
            // to scheduling while the child is still unwinding its exit path.
            self.vfork_event.notify_all(false);
        }
    }

    pub fn wait_for_vfork_completion(&self) {
        if !self.vfork_wait_enabled.load(Ordering::Acquire) {
            return;
        }
        self.vfork_event
            .wait_until(|| self.vfork_done.load(Ordering::Acquire));
    }

    pub fn futex_wait(&self, addr: usize, expected: u32, timeout_ns: Option<u64>) -> AxResult<()> {
        if self.read_user_u32(addr)? != expected {
            return Err(AxError::WouldBlock);
        }
        let current_thread = super::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };
        if signal_pending() {
            return Err(AxError::Interrupted);
        }

        if let Some(timeout_ns) = timeout_ns {
            let deadline = (axhal::time::monotonic_time_nanos() as u64).saturating_add(timeout_ns);
            while !self.group_exiting() {
                if signal_pending() {
                    return Err(AxError::Interrupted);
                }
                match self.read_user_u32(addr) {
                    Ok(current) if current != expected => return Ok(()),
                    Ok(_) => {}
                    Err(e) => return Err(e),
                }
                if axhal::time::monotonic_time_nanos() as u64 >= deadline {
                    return Err(AxError::TimedOut);
                }
                axtask::yield_now();
            }
            return Ok(());
        }

        let queue = self.futex_table.queue(addr);
        loop {
            if self.group_exiting() {
                return Ok(());
            }
            if signal_pending() {
                return Err(AxError::Interrupted);
            }
            match self.read_user_u32(addr) {
                Ok(current) if current != expected => return Ok(()),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
            queue.wait_until(|| {
                self.group_exiting()
                    || signal_pending()
                    || self
                        .read_user_u32(addr)
                        .map(|current| current != expected)
                        .unwrap_or(true)
            });
        }
    }

    fn futex_wake_impl(&self, addr: usize, count: usize, resched: bool) -> usize {
        if resched {
            self.futex_table.wake(addr, count)
        } else {
            self.futex_table.wake_no_resched(addr, count)
        }
    }

    pub fn futex_wake(&self, addr: usize, count: usize) -> usize {
        self.futex_wake_impl(addr, count, true)
    }

    pub fn futex_wake_no_resched(&self, addr: usize, count: usize) -> usize {
        self.futex_wake_impl(addr, count, false)
    }

    pub fn futex_requeue(
        &self,
        addr: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
    ) -> usize {
        self.futex_table
            .requeue(addr, wake_count, target, requeue_count)
    }

    pub fn exit_robust_list(&self, head_addr: usize) -> AxResult<()> {
        if head_addr == 0 {
            return Ok(());
        }

        let list_next = self.read_user_usize(head_addr)?;
        let futex_offset = self.read_user_isize(head_addr + core::mem::size_of::<usize>())?;
        let pending = self.read_user_usize(head_addr + core::mem::size_of::<usize>() * 2)?;
        let mut entry = list_next;
        let mut limit = ROBUST_LIST_LIMIT;

        while entry != 0 && entry != head_addr {
            let next = self.read_user_usize(entry)?;
            if entry != pending {
                self.wake_robust_entry(entry, futex_offset);
            }
            entry = next;
            limit -= 1;
            if limit == 0 {
                return Err(AxError::InvalidData);
            }
        }

        if pending != 0 {
            self.wake_robust_entry(pending, futex_offset);
        }
        Ok(())
    }

    fn wake_robust_entry(&self, entry: usize, futex_offset: isize) {
        let futex_addr = if futex_offset >= 0 {
            entry.wrapping_add(futex_offset as usize)
        } else {
            entry.wrapping_sub(futex_offset.unsigned_abs())
        };
        let _ = self.futex_wake_no_resched(futex_addr, 1);
    }

    pub fn spawn_fork_from_trap_frame(
        self: &Arc<Self>,
        tf: &TrapFrame,
        params: ForkParams,
    ) -> AxResult<Arc<Process>> {
        let _guard = NoPreemptIrqSave::new();
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = params.child_stack {
            child_uctx.set_sp(sp);
        }

        let parent_aspace_handle = self.aspace_handle();
        let mut parent_aspace = parent_aspace_handle.lock();
        let new_aspace = parent_aspace.try_clone()?;

        let mut inner = TaskInner::try_new(
            move || {
                let thread = super::current_thread().expect("fork child without Thread context");
                if let Err(e) = thread.prepare_for_user_entry() {
                    panic!("fork child failed to prepare user entry: {:?}", e);
                }
                let kstack_top = axtask::current()
                    .kernel_stack_top()
                    .expect("child task has no kernel stack")
                    .as_usize();
                unsafe {
                    child_uctx.enter_uspace(va!(kstack_top));
                }
            },
            "fork_child".into(),
            TASK_STACK_SIZE,
        )?;

        let child_tid = inner.id().as_u64();
        let new_aspace_arc = Arc::new(Mutex::new(new_aspace));
        let child_proc = Self::new_child_process(
            child_tid,
            self.clone(),
            new_aspace_arc,
            false,
            params.is_vfork,
            params.share_fs,
            params.share_files,
            params.share_sighand,
        )?;

        if let Some(addr) = params.parent_set_tid {
            let child_tid = child_tid as u32;
            self.write_user_bytes_in_aspace(&mut parent_aspace, addr, &child_tid.to_ne_bytes())?;
        }
        let child_thread = Thread::new(child_proc.clone());
        if let Ok(parent_thread) = current_thread() {
            child_thread.set_signal_blocked_mask(parent_thread.signal_blocked_mask());
        }
        if let Some(addr) = params.child_set_tid {
            child_thread.set_child_tid_addr(addr);
        }
        if let Some(addr) = params.child_clear_tid {
            child_thread.set_clear_child_tid(addr);
        }

        let pt_root = child_proc.page_table_root();
        inner.ctx_mut().set_page_table_root(pt_root);
        super::register_process(child_proc.pid(), child_proc.clone());
        inner.init_task_ext(super::ThreadHandle::new(child_thread));

        self.add_child(child_proc.clone());
        let task = axtask::spawn_task(inner);
        child_proc.register_task_ref(task.clone());
        Ok(child_proc)
    }

    pub fn spawn_from_trap_frame(
        self: &Arc<Self>,
        tf: &TrapFrame,
        params: CloneParams,
    ) -> AxResult<(u64, Option<Arc<Process>>)> {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = params.child_stack {
            child_uctx.set_sp(sp);
        }

        let mut inner = TaskInner::try_new(
            move || {
                let thread = super::current_thread().expect("clone child without Thread context");
                if let Err(e) = thread.prepare_for_user_entry() {
                    panic!("clone child failed to prepare user entry: {:?}", e);
                }
                let kstack_top = axtask::current()
                    .kernel_stack_top()
                    .expect("child task has no kernel stack")
                    .as_usize();
                unsafe {
                    child_uctx.enter_uspace(va!(kstack_top));
                }
            },
            "clone_child".into(),
            TASK_STACK_SIZE,
        )?;

        let child_tid = inner.id().as_u64();
        let child_proc = if params.is_thread_clone {
            self.register_thread(child_tid);
            self.clone()
        } else {
            let parent_aspace_handle = self.aspace_handle();
            let mut parent_aspace = parent_aspace_handle.lock();
            let new_aspace = parent_aspace.try_clone()?;
            let new_aspace_arc = Arc::new(Mutex::new(new_aspace));
            Self::new_child_process(
                child_tid,
                self.clone(),
                new_aspace_arc,
                false,
                params.is_vfork,
                params.share_fs,
                params.share_files,
                params.share_sighand,
            )?
        };

        if let Some(parent_tid_addr) = params.parent_set_tid {
            if let Err(e) = self.write_user_u32(parent_tid_addr, child_tid as u32) {
                if params.is_thread_clone {
                    self.unregister_thread(child_tid);
                }
                return Err(e);
            }
        }

        let child_thread = Thread::new(child_proc.clone());
        if let Ok(parent_thread) = current_thread() {
            child_thread.set_signal_blocked_mask(parent_thread.signal_blocked_mask());
        }
        if let Some(addr) = params.child_set_tid {
            child_thread.set_child_tid_addr(addr);
        }
        if let Some(addr) = params.child_clear_tid {
            child_thread.set_clear_child_tid(addr);
        }

        let pt_root = child_proc.page_table_root();
        inner.ctx_mut().set_page_table_root(pt_root);
        if !params.is_thread_clone {
            // Thread clones reuse the existing PROCESS_REGISTRY entry for this pid.
            super::register_process(child_proc.pid(), child_proc.clone());
        }
        inner.init_task_ext(super::ThreadHandle::new(child_thread));

        if !params.is_thread_clone {
            self.add_child(child_proc.clone());
        }
        let task = axtask::spawn_task(inner);
        child_proc.register_task_ref(task.clone());
        Ok((child_tid, (!params.is_thread_clone).then_some(child_proc)))
    }
}
