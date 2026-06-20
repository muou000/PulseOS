use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    sync::{Arc, Weak},
    vec::Vec,
};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, AtomicUsize, Ordering};

use axconfig::TASK_STACK_SIZE;
use axerrno::{AxError, AxErrorKind, AxResult};
use axfs::FsContext;
use axhal::{
    context::{TrapFrame, UspaceContext},
    paging::MappingFlags,
};
use axmm::AddrSpace;
use axtask::{AxTaskRef, TaskInner, WaitQueue};
use kernel_guard::NoPreemptIrqSave;
use kspin::SpinNoIrq;
use linux_raw_sys::general::{
    RLIMIT_CORE, RLIMIT_MEMLOCK, RLIMIT_NOFILE, RLIMIT_STACK, SIGCHLD, itimerspec, rlimit64,
    sigevent,
};
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr, va};
use spin::{Lazy, Mutex, RwLock};

use super::{
    SignalShared, Thread, current_thread, queue_signal_to_process, thread_handle_from_task,
};
use crate::{
    config::*,
    fd_table::{FD_LIMIT, FdTable, SharedFdTable, stdio_entries},
};

#[derive(Clone)]
pub enum ThreadState {
    Pending,
    Active(AxTaskRef),
}

const ROBUST_LIST_LIMIT: usize = 2048;
const DEFAULT_MEMLOCK_LIMIT_BYTES: u64 = u64::MAX;
const DEFAULT_STACK_LIMIT_BYTES: u64 = USER_STACK_SIZE as u64;
const MAX_STACK_LIMIT_BYTES: u64 = USER_STACK_SIZE as u64;
const DEFAULT_NOFILE_LIMIT: u64 = 1024;
const MAX_NOFILE_LIMIT: u64 = FD_LIMIT as u64;

pub const MAX_POSIX_TIMER_COUNT: usize = 16;

#[derive(Clone, Copy)]
pub struct PosixTimer {
    pub id: usize,
    pub clock_id: i32,
    pub event: sigevent,
    pub itimer_spec: itimerspec,
    pub overrun: i32,
    pub next_deadline_ns: u64,
    pub interval_ns: u64,
}

unsafe impl Send for PosixTimer {}
unsafe impl Sync for PosixTimer {}

static ZOMBIE_ASPACE_HANDLE: Lazy<Arc<RwLock<AddrSpace>>> = Lazy::new(|| {
    Arc::new(RwLock::new(
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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct FutexWaitv {
    pub val: u64,
    pub uaddr: u64,
    pub flags: u32,
    pub __reserved: u32,
}

#[derive(Debug)]
pub struct MemlockState {
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
pub struct RlimitState {
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

    fn remove_if_empty(&self, addr: usize) {
        let mut queues = self.queues.lock();
        if let Some(queue) = queues.get(&addr) {
            queue.prune_exited();
            if queue.is_empty() {
                queues.remove(&addr);
            }
        }
    }
}

static GLOBAL_FUTEX_TABLE: Lazy<FutexTable> = Lazy::new(|| FutexTable::new());

/// 进程凭证
#[derive(Clone, Debug)]
pub struct Credentials {
    /// 真实用户ID
    pub ruid: u32,
    /// 有效用户ID
    pub euid: u32,
    /// 保存的用户ID
    pub suid: u32,
    /// 文件系统用户ID
    pub fsuid: u32,
    /// 真实组ID
    pub rgid: u32,
    /// 有效组ID
    pub egid: u32,
    /// 保存的组ID
    pub sgid: u32,
    /// 文件系统组ID
    pub fsgid: u32,
    /// 允许的能力集
    pub cap_permitted: u64,
    /// 有效的能力集
    pub cap_effective: u64,
    /// 可继承的能力集
    pub cap_inheritable: u64,
    /// 默认权限掩码
    pub umask: u32,
    /// 附加组ID 列表
    pub groups: Vec<u32>,
}

impl Credentials {
    fn new(
        ruid: u32,
        euid: u32,
        suid: u32,
        fsuid: u32,
        rgid: u32,
        egid: u32,
        sgid: u32,
        fsgid: u32,
        cap_permitted: u64,
        cap_effective: u64,
        cap_inheritable: u64,
        umask: u32,
        groups: Vec<u32>,
    ) -> Self {
        Self {
            ruid,
            euid,
            suid,
            fsuid,
            rgid,
            egid,
            sgid,
            fsgid,
            cap_permitted,
            cap_effective,
            cap_inheritable,
            umask,
            groups,
        }
    }
}

/// 进程资源限制上下文
#[derive(Debug)]
pub struct ResourceContext {
    /// 资源上限限制状态
    pub rlimit_state: RlimitState,
    /// 物理内存锁定状态与限制
    pub memlock_state: MemlockState,
}

/// UTS 命名空间
#[derive(Clone)]
pub struct UtsNamespace {
    /// 主机名称
    pub hostname: Arc<RwLock<[u8; 65]>>,
}

/// IPC 资源上下文
pub struct IpcContext {
    /// 共享内存注册表
    pub shared_memory: Arc<RwLock<BTreeMap<VirtAddr, Arc<Mutex<crate::ipc::shm::ShmInner>>>>>,
    /// 信号量退出撤销记录
    pub sem_undos: Mutex<Vec<crate::ipc::sem::SemUndoEntry>>,
}

/// vfork 挂起同步控制上下文
pub struct VforkContext {
    /// 是否开启 vfork 等待
    pub wait_enabled: bool,
    /// vfork 操作是否已完成
    pub done: AtomicBool,
    /// 用于通知和等待 vfork 完成的等待队列
    pub event: WaitQueue,
}

/// 进程时间与定时器上下文
pub struct TimeContext {
    /// 用户态执行时间
    pub user_time_ns: AtomicU64,
    /// 内核态执行时间
    pub sys_time_ns: AtomicU64,
    /// 子进程用户态消耗时间
    pub child_user_time_ns: AtomicU64,
    /// 子进程内核态消耗时间
    pub child_sys_time_ns: AtomicU64,
    /// 真实时间定时器截止单调时间戳
    pub itimer_real_deadline_ns: AtomicU64,
    /// 真实时间定时器重载时间间隔
    pub itimer_real_interval_ns: AtomicU64,
    /// 虚拟时间定时器剩余时间
    pub itimer_virt_remaining_ns: AtomicU64,
    /// 虚拟时间定时器重载时间间隔
    pub itimer_virt_interval_ns: AtomicU64,
    /// 剖析定时器剩余时间
    pub itimer_prof_remaining_ns: AtomicU64,
    /// 剖析定时器重载时间间隔
    pub itimer_prof_interval_ns: AtomicU64,
}

impl TimeContext {
    fn new() -> Self {
        Self {
            user_time_ns: AtomicU64::new(0),
            sys_time_ns: AtomicU64::new(0),
            child_user_time_ns: AtomicU64::new(0),
            child_sys_time_ns: AtomicU64::new(0),
            itimer_real_deadline_ns: AtomicU64::new(0),
            itimer_real_interval_ns: AtomicU64::new(0),
            itimer_virt_remaining_ns: AtomicU64::new(0),
            itimer_virt_interval_ns: AtomicU64::new(0),
            itimer_prof_remaining_ns: AtomicU64::new(0),
            itimer_prof_interval_ns: AtomicU64::new(0),
        }
    }
}

/// 进程控制块
pub struct Process {
    /// 进程ID
    pid: u64,
    /// 父进程ID
    parent_pid: AtomicU64,
    /// 父进程弱引用
    parent: RwLock<Option<Weak<Process>>>,
    /// 虚拟地址空间
    aspace: RwLock<Arc<RwLock<AddrSpace>>>,
    /// 堆顶指针
    pub heap_top: Arc<AtomicUsize>,
    /// brk 扩展排他锁
    pub brk_lock: Mutex<()>,
    /// 文件系统根目录与当前工作目录上下文
    fs_context: RwLock<Arc<Mutex<FsContext>>>,
    /// 文件描述符表
    fd_table: RwLock<SharedFdTable>,
    /// 启动时的单调时间
    pub start_mono_ns: u64,
    /// CPU 消耗时间及Itimer定时器
    pub time_context: TimeContext,
    /// 用户态栈顶指针
    pub stack_top: AtomicUsize,
    /// 程序入口地址
    pub entry: AtomicUsize,
    /// 线程与任务状态注册表
    threads: SpinNoIrq<BTreeMap<u64, ThreadState>>,
    /// 子进程列表，使用自旋锁保护
    children: SpinNoIrq<Vec<Arc<Process>>>,
    /// 子进程退出等待事件队列
    pub child_exit_event: WaitQueue,
    /// 标志进程是否已处于僵尸状态
    zombie: AtomicBool,
    /// 用户空间分配资源是否已经被全部释放
    user_resources_released: AtomicBool,
    /// 退出码
    exit_code: AtomicI32,
    /// 信号退出信息。
    /// 0 = 正常退出，>0 且低 7 位为信号号，bit8 (0x100) 为 core dump 标志
    exit_signal: AtomicI32,
    /// 标志进程组是否正在退出
    group_exiting: AtomicBool,
    /// 进程组退出码
    group_exit_code: AtomicI32,
    /// Futex管理表
    futex_table: FutexTable,
    /// 当以 vfork 创建子进程时挂起父进程的同步机制
    vfork_context: Option<VforkContext>,
    /// 进程安全凭证
    pub credentials: RwLock<Arc<Credentials>>,
    /// 进程的系统级资源限制限制缓存
    pub resources: Mutex<ResourceContext>,
    /// 组内共享的信号行为及挂起信号控制
    signal_shared: Arc<SignalShared>,
    /// 进程可执行文件的绝对路径
    exec_path: RwLock<Option<String>>,
    /// 命令行参数列表
    pub args: RwLock<Vec<String>>,
    /// 用户态信号处理器蹦床地址
    signal_trampoline: AtomicUsize,
    /// 共享内存与信号量撤销记录等 IPC 相关资源
    pub ipc: IpcContext,
    /// 被停止的挂起信号状态掩码
    pub stopped_signal_pending: AtomicI32,
    /// 进程是否收到 SIGCONT 信号并继续运行的标志
    pub continued_signal_pending: AtomicBool,
    /// 进程组标识符 (PGID)
    pgid: AtomicU64,
    /// 进程死亡时的死亡信号标志 (pdeath_sig)
    pub pdeath_sig: AtomicI32,
    /// 进程是否允许 Core Dump 的标志位 (Dumpable)
    pub dumpable: AtomicI32,
    /// 标志此进程是否曾被重新指定父进程（收养）
    pub reparented: AtomicBool,
    /// UTS 网络主机名隔离命名空间，通过 Arc 的 COW 机制实现命名空间共享和按需隔离
    uts_ns: RwLock<Arc<UtsNamespace>>,
    /// 进程死亡时发送给父进程的信号，默认为 SIGCHLD (17)
    pub parent_exit_signal: AtomicI32,
    /// POSIX 定时器列表
    pub posix_timers: SpinNoIrq<[Option<PosixTimer>; MAX_POSIX_TIMER_COUNT]>,
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
    pub share_uts: bool,
    pub exit_signal: Option<i32>,
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
    pub share_uts: bool,
    pub exit_signal: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub enum WaitidStatusType {
    Exited { exit_code: i32, exit_signal: i32 },
    Stopped { signo: i32 },
    Continued,
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

    pub fn validate_user_range(&self, user_addr: usize, len: usize) -> AxResult<()> {
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

    pub fn fs_context_handle(&self) -> Arc<Mutex<FsContext>> {
        self.fs_context.read().clone()
    }

    pub fn fd_table(&self) -> SharedFdTable {
        self.fd_table.read().clone()
    }

    pub fn hostname_handle(&self) -> Arc<RwLock<[u8; 65]>> {
        self.uts_ns.read().hostname.clone()
    }

    pub fn set_hostname_handle(&self, handle: Arc<RwLock<[u8; 65]>>) {
        let mut uts = self.uts_ns.write();
        Arc::make_mut(&mut uts).hostname = handle;
    }

    pub fn unshare_fs(&self) -> AxResult<()> {
        let new_fs = {
            let binding = self.fs_context_handle();
            let fs = binding.lock().clone();
            fs
        };
        let mut slot = self.fs_context.write();
        *slot = Arc::new(Mutex::new(new_fs));
        Ok(())
    }

    pub fn unshare_files(&self) -> Result<(), axerrno::LinuxError> {
        let new_fd_table = {
            let binding = self.fd_table();
            let table = binding.read();
            table.clone_for_fork()?
        };
        let mut slot = self.fd_table.write();
        *slot = Arc::new(RwLock::new(new_fd_table));
        Ok(())
    }

    pub fn unshare_uts(&self) {
        let current_hostname = *self.hostname_handle().read();
        *self.uts_ns.write() = Arc::new(UtsNamespace {
            hostname: Arc::new(RwLock::new(current_hostname)),
        });
    }

    fn clone_private_fs_context(parent: &Process) -> AxResult<Arc<Mutex<FsContext>>> {
        Ok(Arc::new(Mutex::new(
            parent.fs_context_handle().lock().clone(),
        )))
    }

    pub fn pid(&self) -> u64 {
        self.pid
    }

    pub fn name(&self) -> String {
        let name = self
            .exec_path
            .read()
            .as_deref()
            .and_then(|p| p.rsplit('/').next())
            .map(|s| s.to_string());
        name.unwrap_or_else(|| "pulse_init".to_string())
    }

    pub fn exec_path(&self) -> Option<String> {
        self.exec_path.read().clone()
    }

    pub fn is_exec_path(&self, path: &str) -> bool {
        self.exec_path.read().as_deref() == Some(path)
    }

    pub fn exec_path_or_default(&self) -> String {
        self.exec_path().unwrap_or_else(|| "pulse_init".to_string())
    }

    pub fn set_exec_path(&self, path: String) {
        *self.exec_path.write() = Some(path);
    }

    pub fn signal_trampoline(&self) -> usize {
        self.signal_trampoline.load(Ordering::Acquire)
    }

    pub fn set_signal_trampoline(&self, trampoline: usize) {
        self.signal_trampoline.store(trampoline, Ordering::Release);
    }

    pub fn parent_pid(&self) -> u64 {
        self.parent_pid.load(Ordering::Acquire)
    }

    pub fn thread_count(&self) -> usize {
        self.threads.lock().len()
    }

    pub fn thread_ids_snapshot(&self) -> Vec<u64> {
        self.threads.lock().keys().copied().collect()
    }

    pub fn children_pids_snapshot(&self) -> Vec<u64> {
        self.children.lock().iter().map(|c| c.pid()).collect()
    }

    pub fn task_tids_snapshot(&self) -> Vec<u64> {
        self.threads
            .lock()
            .iter()
            .filter_map(|(tid, state)| match state {
                ThreadState::Active(_) => Some(*tid),
                _ => None,
            })
            .collect()
    }

    pub fn ruid(&self) -> u32 {
        self.credentials.read().ruid
    }

    pub fn euid(&self) -> u32 {
        self.credentials.read().euid
    }

    pub fn suid(&self) -> u32 {
        self.credentials.read().suid
    }

    pub fn fsuid(&self) -> u32 {
        self.credentials.read().fsuid
    }

    pub fn rgid(&self) -> u32 {
        self.credentials.read().rgid
    }

    pub fn egid(&self) -> u32 {
        self.credentials.read().egid
    }

    pub fn sgid(&self) -> u32 {
        self.credentials.read().sgid
    }

    pub fn fsgid(&self) -> u32 {
        self.credentials.read().fsgid
    }

    pub fn umask(&self) -> u32 {
        self.credentials.read().umask
    }

    pub fn set_umask(&self, umask: u32) -> u32 {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);
        let old = creds.umask;
        creds.umask = umask;
        old
    }

    pub fn set_fsuid(&self, uid: u32) -> u32 {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);
        let old = creds.fsuid;
        creds.fsuid = uid;
        old
    }

    pub fn set_fsgid(&self, gid: u32) -> u32 {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);
        let old = creds.fsgid;
        creds.fsgid = gid;
        old
    }

    pub fn uid_snapshot(&self) -> (u32, u32, u32) {
        let creds = self.credentials.read();
        (creds.ruid, creds.euid, creds.suid)
    }

    pub fn gid_snapshot(&self) -> (u32, u32, u32) {
        let creds = self.credentials.read();
        (creds.rgid, creds.egid, creds.sgid)
    }

    pub fn capabilities(&self) -> (u64, u64, u64) {
        let creds = self.credentials.read();
        (
            creds.cap_permitted,
            creds.cap_effective,
            creds.cap_inheritable,
        )
    }

    pub fn set_capabilities(&self, p: u64, e: u64, i: u64) {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);
        creds.cap_permitted = p;
        creds.cap_effective = e;
        creds.cap_inheritable = i;
    }

    pub fn has_capability(&self, cap: u32) -> bool {
        if cap >= 64 {
            return false;
        }
        let effective = self.credentials.read().cap_effective;
        (effective & (1 << cap)) != 0
    }

    pub fn set_uids(&self, ruid: u32, euid: u32, suid: u32) {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);

        let old_ruid = creds.ruid;
        let old_euid = creds.euid;
        let old_suid = creds.suid;

        creds.ruid = ruid;
        creds.euid = euid;
        creds.suid = suid;

        if euid != old_euid {
            creds.fsuid = euid;
        }

        // Capability transition logic according to capabilities(7)
        if old_euid == 0 && euid != 0 {
            creds.cap_effective = 0;
        }
        if old_euid != 0 && euid == 0 {
            creds.cap_effective = creds.cap_permitted;
        }
        if (old_ruid == 0 || old_euid == 0 || old_suid == 0)
            && (ruid != 0 && euid != 0 && suid != 0)
        {
            creds.cap_permitted = 0;
            creds.cap_effective = 0;
        }
    }

    pub fn set_gids(&self, rgid: u32, egid: u32, sgid: u32) {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);

        let old_egid = creds.egid;
        creds.rgid = rgid;
        creds.egid = egid;
        creds.sgid = sgid;

        if egid != old_egid {
            creds.fsgid = egid;
        }
    }

    pub fn is_root_user(&self) -> bool {
        self.euid() == 0
    }

    pub fn groups(&self) -> Vec<u32> {
        self.credentials.read().groups.clone()
    }

    pub fn set_groups(&self, groups: Vec<u32>) {
        let mut creds_lock = self.credentials.write();
        let creds = Arc::make_mut(&mut *creds_lock);
        creds.groups = groups;
    }

    pub fn memlock_limit_snapshot(&self) -> (u64, u64) {
        let res = self.resources.lock();
        (res.memlock_state.soft_limit, res.memlock_state.hard_limit)
    }

    pub fn memlock_set_limit(&self, soft: u64, hard: u64) {
        let mut res = self.resources.lock();
        res.memlock_state.soft_limit = soft;
        res.memlock_state.hard_limit = hard;
    }

    pub fn get_rlimit(&self, resource: u32) -> Option<rlimit64> {
        let res = self.resources.lock();
        match resource {
            RLIMIT_STACK => Some(rlimit64 {
                rlim_cur: res.rlimit_state.stack_soft,
                rlim_max: res.rlimit_state.stack_hard,
            }),
            RLIMIT_NOFILE => Some(rlimit64 {
                rlim_cur: res.rlimit_state.nofile_soft,
                rlim_max: res.rlimit_state.nofile_hard,
            }),
            RLIMIT_CORE => Some(rlimit64 {
                rlim_cur: res.rlimit_state.core_soft,
                rlim_max: res.rlimit_state.core_hard,
            }),
            RLIMIT_MEMLOCK => Some(rlimit64 {
                rlim_cur: res.memlock_state.soft_limit,
                rlim_max: res.memlock_state.hard_limit,
            }),
            _ => None,
        }
    }

    pub fn set_rlimit(&self, resource: u32, limit: rlimit64) -> AxResult<()> {
        if limit.rlim_cur > limit.rlim_max {
            return Err(AxError::InvalidInput);
        }
        let mut res = self.resources.lock();
        match resource {
            RLIMIT_STACK => {
                if limit.rlim_max > MAX_STACK_LIMIT_BYTES {
                    return Err(AxError::InvalidInput);
                }
                res.rlimit_state.stack_soft = limit.rlim_cur;
                res.rlimit_state.stack_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_NOFILE => {
                if limit.rlim_max > MAX_NOFILE_LIMIT {
                    return Err(AxError::InvalidInput);
                }
                res.rlimit_state.nofile_soft = limit.rlim_cur;
                res.rlimit_state.nofile_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_CORE => {
                res.rlimit_state.core_soft = limit.rlim_cur;
                res.rlimit_state.core_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_MEMLOCK => {
                res.memlock_state.soft_limit = limit.rlim_cur;
                res.memlock_state.hard_limit = limit.rlim_max;
                Ok(())
            }
            _ => Err(AxError::InvalidInput),
        }
    }

    pub fn memlock_locked_bytes(&self) -> usize {
        self.resources.lock().memlock_state.locked_bytes
    }

    pub fn memlock_future_enabled(&self) -> bool {
        self.resources.lock().memlock_state.mlock_future
    }

    pub fn memlock_set_future(&self, enabled: bool) {
        self.resources.lock().memlock_state.mlock_future = enabled;
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
        let mut res = self.resources.lock();
        let additional = Self::memlock_additional_bytes(&res.memlock_state.ranges, start, end);
        if additional == 0 {
            return Ok(());
        }
        if !privileged && res.memlock_state.soft_limit != u64::MAX {
            let new_total =
                (res.memlock_state.locked_bytes as u128).saturating_add(additional as u128);
            if new_total > res.memlock_state.soft_limit as u128 {
                return Err(AxError::NoMemory);
            }
        }
        Self::memlock_insert_range(&mut res.memlock_state.ranges, start, end)?;
        res.memlock_state.locked_bytes = res.memlock_state.locked_bytes.saturating_add(additional);
        Ok(())
    }

    pub fn memlock_unlock_range(&self, start: usize, len: usize) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start.checked_add(len).ok_or(AxError::BadAddress)?;
        let mut res = self.resources.lock();
        let removed = Self::memlock_remove_range(&mut res.memlock_state.ranges, start, end)?;
        res.memlock_state.locked_bytes = res.memlock_state.locked_bytes.saturating_sub(removed);
        Ok(())
    }

    pub fn memlock_unlock_all(&self) {
        let mut res = self.resources.lock();
        res.memlock_state.ranges.clear();
        res.memlock_state.locked_bytes = 0;
        res.memlock_state.mlock_future = false;
    }

    pub fn get_heap_top(&self) -> usize {
        self.heap_top.load(Ordering::Acquire)
    }

    pub fn set_heap_top(&self, top: usize) {
        self.heap_top.store(top, Ordering::Release);
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
        let pages =
            memory_addr::PageIter4K::new(start_page, end_page).ok_or(AxError::BadAddress)?;
        for page in pages {
            let mut done = false;
            let aspace = aspace_handle.read();
            match aspace.handle_page_fault(page, access) {
                axmm::PageFaultResult::Handled(ok) => {
                    if !ok {
                        return Err(AxError::BadAddress);
                    }
                    done = true;
                }
                axmm::PageFaultResult::NeedWriteLock => {}
            }
            drop(aspace);
            if !done {
                let mut aspace = aspace_handle.write();
                if !aspace.handle_page_fault_write(page, access) {
                    return Err(AxError::BadAddress);
                }
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
            let pf_flags = MappingFlags::WRITE | MappingFlags::USER;
            match aspace.handle_page_fault(page, pf_flags) {
                axmm::PageFaultResult::Handled(ok) => {
                    if !ok {
                        return Err(AxError::BadAddress);
                    }
                }
                axmm::PageFaultResult::NeedWriteLock => {
                    if !aspace.handle_page_fault_write(page, pf_flags) {
                        return Err(AxError::BadAddress);
                    }
                }
            }
        }
        aspace.write(start, bytes).map_err(AxError::from)
    }

    pub fn read_user_bytes(&self, user_addr: usize, bytes: &mut [u8]) -> AxResult<()> {
        self.validate_user_range(user_addr, bytes.len())?;
        let start = VirtAddr::from(user_addr);
        let aspace_handle = self.aspace_handle();

        // Try fast path first without faulting
        if let Ok(()) = aspace_handle.read().read(start, bytes) {
            return Ok(());
        }

        // If it fails, fault-in the pages and retry once
        self.try_fault_in_user_range(user_addr, bytes.len(), MappingFlags::READ)?;
        aspace_handle
            .read()
            .read(start, bytes)
            .map_err(AxError::from)
    }

    pub fn write_user_bytes(&self, user_addr: usize, bytes: &[u8]) -> AxResult<()> {
        let aspace_handle = self.aspace_handle();
        let mut aspace = aspace_handle.write();
        self.write_user_bytes_in_aspace(&mut aspace, user_addr, bytes)
    }

    pub fn aspace_handle(&self) -> Arc<RwLock<AddrSpace>> {
        self.aspace.read().clone()
    }

    pub fn replace_aspace_handle(
        &self,
        new_aspace: Arc<RwLock<AddrSpace>>,
    ) -> Arc<RwLock<AddrSpace>> {
        let mut slot = self.aspace.write();
        core::mem::replace(&mut *slot, new_aspace)
    }

    pub fn page_table_root(&self) -> PhysAddr {
        self.aspace_handle().read().page_table_root()
    }

    pub fn asid(&self) -> usize {
        self.aspace_handle().read().asid()
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

    pub fn get_fd_entry(&self, fd: usize) -> Result<crate::fd_table::FdEntry, axerrno::LinuxError> {
        self.fd_table().read().get_entry_cloned(fd)
    }

    pub fn insert_fd_entry(
        &self,
        entry: crate::fd_table::FdEntry,
    ) -> Result<usize, axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        let binding = self.fd_table();
        let mut table = binding.write();
        let fd = table.insert_next(entry)?;
        if fd >= limit {
            table.remove(fd);
            return Err(axerrno::LinuxError::EMFILE);
        }
        Ok(fd)
    }

    pub fn insert_fd_entry_from(
        &self,
        min_fd: usize,
        entry: crate::fd_table::FdEntry,
    ) -> Result<usize, axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        let binding = self.fd_table();
        let mut table = binding.write();
        let fd = table.insert_from(min_fd, entry)?;
        if fd >= limit {
            table.remove(fd);
            return Err(axerrno::LinuxError::EMFILE);
        }
        Ok(fd)
    }

    pub fn set_fd_entry(
        &self,
        fd: usize,
        entry: crate::fd_table::FdEntry,
    ) -> Result<(), axerrno::LinuxError> {
        let limit = self.resources.lock().rlimit_state.nofile_soft as usize;
        if fd >= limit {
            return Err(axerrno::LinuxError::EBADF);
        }
        self.fd_table().write().insert_at(fd, entry)
    }

    pub fn remove_fd_entry(
        &self,
        fd: usize,
    ) -> Result<crate::fd_table::FdEntry, axerrno::LinuxError> {
        self.fd_table().write().remove_or_err(fd)
    }

    pub fn set_fd_cloexec(&self, fd: usize, cloexec: bool) -> Result<(), axerrno::LinuxError> {
        let binding = self.fd_table();
        let mut table = binding.write();
        let entry = table.get_mut(fd).ok_or(axerrno::LinuxError::EBADF)?;
        entry.flags.set(crate::fd_table::FdFlags::CLOEXEC, cloexec);
        Ok(())
    }

    pub fn set_fd_nonblocking(
        &self,
        fd: usize,
        nonblocking: bool,
    ) -> Result<(), axerrno::LinuxError> {
        let binding = self.fd_table();
        let mut table = binding.write();
        let entry = table.get_mut(fd).ok_or(axerrno::LinuxError::EBADF)?;
        entry
            .flags
            .set(crate::fd_table::FdFlags::NONBLOCK, nonblocking);
        entry.object.set_nonblocking(nonblocking)?;
        Ok(())
    }

    pub fn get_fd_location(&self, fd: usize) -> Result<axfs_ng_vfs::Location, axerrno::LinuxError> {
        self.fd_table().read().get_location(fd)
    }

    pub fn clone_all_fd_entries(&self) -> Vec<crate::fd_table::FdEntry> {
        self.fd_table().read().clone_all_entries()
    }

    pub fn is_user_range(&self, addr: usize, len: usize) -> bool {
        self.validate_user_range(addr, len).is_ok()
    }

    pub fn align_user_range(
        &self,
        addr: usize,
        len: usize,
    ) -> Result<(usize, usize), axerrno::LinuxError> {
        if len == 0 {
            return Ok((addr & !(4096 - 1), 0));
        }
        let aligned_addr = addr & !(4096 - 1);
        let end = addr.checked_add(len).ok_or(axerrno::LinuxError::EINVAL)?;
        let aligned_end = (end
            .checked_add(4096 - 1)
            .ok_or(axerrno::LinuxError::EINVAL)?)
            & !(4096 - 1);
        if aligned_end < aligned_addr {
            return Err(axerrno::LinuxError::EINVAL);
        }
        let aligned_len = aligned_end - aligned_addr;
        if !self.is_user_range(aligned_addr, aligned_len) {
            return Err(axerrno::LinuxError::EINVAL);
        }
        Ok((aligned_addr, aligned_len))
    }

    pub fn is_mapped_range(&self, addr: usize, len: usize) -> bool {
        if len == 0 {
            return true;
        }
        let aspace_handle = self.aspace_handle();
        let aspace = aspace_handle.read();
        aspace.can_access_range(VirtAddr::from(addr), len, MappingFlags::empty())
    }

    pub fn prefault_user_range(&self, addr: usize, len: usize) -> Result<(), axerrno::LinuxError> {
        if len == 0 {
            return Ok(());
        }
        let aspace_handle = self.aspace_handle();
        let mut aspace = aspace_handle.write();
        let start = VirtAddr::from(addr);
        if !aspace.can_access_range(start, len, MappingFlags::empty()) {
            return Err(axerrno::LinuxError::ENOMEM);
        }
        let end = addr.checked_add(len).ok_or(axerrno::LinuxError::EINVAL)?;
        let pages = memory_addr::PageIter4K::new(VirtAddr::from(addr), VirtAddr::from(end))
            .ok_or(axerrno::LinuxError::EINVAL)?;
        for page in pages {
            let already_resident = aspace
                .query_vaddr(page)
                .map(|(frame, flags, _)| frame.as_usize() != 0 && !flags.is_empty())
                .unwrap_or(false);
            if already_resident {
                continue;
            }
            let handled = match aspace.handle_page_fault(page, MappingFlags::USER) {
                axmm::PageFaultResult::Handled(success) => success,
                axmm::PageFaultResult::NeedWriteLock => {
                    aspace.handle_page_fault_write(page, MappingFlags::USER)
                }
            };
            if !handled {
                return Err(axerrno::LinuxError::ENOMEM);
            }
        }
        Ok(())
    }

    pub fn lock_mapped_range(&self, addr: usize, len: usize) -> Result<(), axerrno::LinuxError> {
        if len == 0 {
            return Ok(());
        }
        self.prefault_user_range(addr, len)?;
        let privileged = self.is_root_user();
        self.memlock_try_lock_range(addr, len, privileged)
            .map_err(|e| match e {
                AxError::NoMemory => axerrno::LinuxError::ENOMEM,
                _ => axerrno::LinuxError::EINVAL,
            })?;
        Ok(())
    }

    pub fn lock_all_current_mappings(&self) -> Result<(), axerrno::LinuxError> {
        let user_area_count = {
            let mut count = 0usize;
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            aspace.for_each_area(|_, _, flags| {
                if flags.contains(MappingFlags::USER) {
                    count = count.saturating_add(1);
                }
            });
            count
        };

        let mut ranges: Vec<(usize, usize)> = Vec::new();
        if ranges.try_reserve_exact(user_area_count).is_err() {
            return Err(axerrno::LinuxError::ENOMEM);
        }
        {
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            aspace.for_each_area(|start, end, flags| {
                if !flags.contains(MappingFlags::USER) {
                    return;
                }
                let s = start.align_down_4k().as_usize();
                let e = end.align_up_4k().as_usize();
                if e > s {
                    ranges.push((s, e - s));
                }
            });
        }
        for (start, len) in ranges {
            self.lock_mapped_range(start, len)?;
        }
        Ok(())
    }

    pub fn maybe_lock_future_range(
        &self,
        addr: usize,
        len: usize,
    ) -> Result<(), axerrno::LinuxError> {
        if len == 0 || !self.memlock_future_enabled() {
            return Ok(());
        }
        self.lock_mapped_range(addr, len)
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

        let mut hostname_buf = [0u8; 65];
        let default_name = b"pulseos";
        hostname_buf[..default_name.len()].copy_from_slice(default_name);

        let uts_ns = RwLock::new(Arc::new(UtsNamespace {
            hostname: Arc::new(RwLock::new(hostname_buf)),
        }));

        Ok(Arc::new(Self {
            pid,
            parent_pid: AtomicU64::new(0),
            parent: RwLock::new(None),
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            aspace: RwLock::new(Arc::new(RwLock::new(aspace))),
            fs_context: RwLock::new(Arc::new(Mutex::new(fs_context))),
            fd_table: RwLock::new(Arc::new(RwLock::new(fd_table))),
            time_context: TimeContext::new(),
            stack_top: AtomicUsize::new(USER_STACK_TOP),
            entry: AtomicUsize::new(0),
            threads: SpinNoIrq::new({
                let mut map = BTreeMap::new();
                map.insert(pid, ThreadState::Pending);
                map
            }),
            children: SpinNoIrq::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            user_resources_released: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            exit_signal: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_context: None,
            heap_top: Arc::new(AtomicUsize::new(USER_HEAP_BASE + USER_HEAP_SIZE)),
            brk_lock: Mutex::new(()),
            credentials: RwLock::new(Arc::new(Credentials::new(
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                u64::MAX,
                u64::MAX,
                0,
                0o022,
                Vec::new(),
            ))),
            resources: Mutex::new(ResourceContext {
                rlimit_state: RlimitState::default(),
                memlock_state: MemlockState::new(),
            }),
            signal_shared: SignalShared::new(),
            exec_path: RwLock::new(None),
            args: RwLock::new(alloc::vec![String::from("pulse_init")]),
            signal_trampoline: AtomicUsize::new(0),
            ipc: IpcContext {
                shared_memory: Arc::new(RwLock::new(BTreeMap::new())),
                sem_undos: Mutex::new(Vec::new()),
            },
            stopped_signal_pending: AtomicI32::new(0),
            continued_signal_pending: AtomicBool::new(false),
            pgid: AtomicU64::new(pid),
            pdeath_sig: AtomicI32::new(0),
            dumpable: AtomicI32::new(1),
            reparented: AtomicBool::new(false),
            uts_ns,
            parent_exit_signal: AtomicI32::new(SIGCHLD as i32),
            posix_timers: SpinNoIrq::new([None; MAX_POSIX_TIMER_COUNT]),
        }))
    }

    fn new_child_process(
        pid: u64,
        parent: Arc<Process>,
        aspace: Arc<RwLock<AddrSpace>>,
        share_vm: bool,
        is_vfork: bool,
        share_fs: bool,
        share_files: bool,
        share_sighand: bool,
        share_uts: bool,
    ) -> AxResult<Arc<Self>> {
        let parent_arc = parent;
        let parent = parent_arc.as_ref();
        let heap_top = if share_vm {
            parent.heap_top.clone()
        } else {
            Arc::new(AtomicUsize::new(parent.get_heap_top()))
        };
        let shared_memory = if share_vm {
            parent.ipc.shared_memory.clone()
        } else {
            let mut new_shm = BTreeMap::new();
            let parent_shm = parent.ipc.shared_memory.read();
            for (vaddr, inner_arc) in parent_shm.iter() {
                inner_arc.lock().attach_process(pid);
                new_shm.insert(*vaddr, inner_arc.clone());
            }
            Arc::new(RwLock::new(new_shm))
        };
        let fs_context = if share_fs {
            RwLock::new(parent.fs_context_handle())
        } else {
            RwLock::new(Self::clone_private_fs_context(parent)?)
        };
        let fd_table = if share_files {
            RwLock::new(parent.fd_table())
        } else {
            RwLock::new(Arc::new(RwLock::new(
                parent.fd_table().read().clone_for_fork()?,
            )))
        };
        let parent_creds = parent.credentials.read();
        let creds = Credentials::new(
            parent_creds.ruid,
            parent_creds.euid,
            parent_creds.suid,
            parent_creds.fsuid,
            parent_creds.rgid,
            parent_creds.egid,
            parent_creds.sgid,
            parent_creds.fsgid,
            parent_creds.cap_permitted,
            parent_creds.cap_effective,
            parent_creds.cap_inheritable,
            parent_creds.umask,
            parent.groups(),
        );
        let parent_resources = parent.resources.lock();
        let resources = ResourceContext {
            rlimit_state: parent_resources.rlimit_state,
            memlock_state: MemlockState::new_with_limits(
                parent_resources.memlock_state.soft_limit,
                parent_resources.memlock_state.hard_limit,
            ),
        };
        drop(parent_resources);
        let signal_shared = if share_sighand {
            SignalShared::clone_sighand_only(&parent.signal_shared)
        } else {
            SignalShared::clone_actions_only(&parent.signal_shared)
        };
        let signal_trampoline = parent.signal_trampoline.load(Ordering::Acquire);
        let exec_path = parent.exec_path();
        let uts_ns = if share_uts {
            parent.uts_ns.read().clone()
        } else {
            Arc::new(UtsNamespace {
                hostname: Arc::new(RwLock::new(*parent.hostname_handle().read())),
            })
        };

        let vfork_context = if is_vfork {
            Some(VforkContext {
                wait_enabled: true,
                done: AtomicBool::new(false),
                event: WaitQueue::new(),
            })
        } else {
            None
        };

        Ok(Arc::new(Self {
            pid,
            parent_pid: AtomicU64::new(parent.pid()),
            parent: RwLock::new(Some(Arc::downgrade(&parent_arc))),
            aspace: RwLock::new(aspace),
            heap_top,
            brk_lock: Mutex::new(()),
            fs_context,
            fd_table,
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            time_context: TimeContext::new(),
            stack_top: AtomicUsize::new(parent.stack_top.load(Ordering::Acquire)),
            entry: AtomicUsize::new(parent.entry.load(Ordering::Acquire)),
            threads: SpinNoIrq::new({
                let mut map = BTreeMap::new();
                map.insert(pid, ThreadState::Pending);
                map
            }),
            children: SpinNoIrq::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            user_resources_released: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            exit_signal: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_context,
            credentials: RwLock::new(Arc::new(creds)),
            resources: Mutex::new(resources),
            signal_shared,
            exec_path: RwLock::new(exec_path),
            args: RwLock::new(parent.args.read().clone()),
            signal_trampoline: AtomicUsize::new(signal_trampoline),
            ipc: IpcContext {
                shared_memory,
                sem_undos: Mutex::new(Vec::new()),
            },
            stopped_signal_pending: AtomicI32::new(0),
            continued_signal_pending: AtomicBool::new(false),
            pgid: AtomicU64::new(parent.pgid()),
            pdeath_sig: AtomicI32::new(0),
            dumpable: AtomicI32::new(parent.dumpable()),
            reparented: AtomicBool::new(false),
            uts_ns: RwLock::new(uts_ns),
            parent_exit_signal: AtomicI32::new(SIGCHLD as i32),
            posix_timers: SpinNoIrq::new([None; MAX_POSIX_TIMER_COUNT]),
        }))
    }

    pub fn pgid(&self) -> u64 {
        self.pgid.load(Ordering::Acquire)
    }

    pub fn set_pgid(&self, pgid: u64) {
        self.pgid.store(pgid, Ordering::Release);
    }

    pub fn pdeath_sig(&self) -> i32 {
        self.pdeath_sig.load(Ordering::Acquire)
    }

    pub fn set_pdeath_sig(&self, sig: i32) {
        self.pdeath_sig.store(sig, Ordering::Release);
    }

    pub fn dumpable(&self) -> i32 {
        self.dumpable.load(Ordering::Acquire)
    }

    pub fn set_dumpable(&self, dumpable: i32) {
        self.dumpable.store(dumpable, Ordering::Release);
    }

    pub fn parent_exit_signal(&self) -> i32 {
        self.parent_exit_signal.load(Ordering::Acquire)
    }

    pub fn set_parent_exit_signal(&self, sig: i32) {
        self.parent_exit_signal.store(sig, Ordering::Release);
    }

    pub fn signal_shared(&self) -> Arc<SignalShared> {
        self.signal_shared.clone()
    }

    pub fn handle_page_fault(&self, vaddr: VirtAddr, flags: axhal::trap::PageFaultFlags) -> bool {
        let aspace_handle = self.aspace_handle();
        let aspace = aspace_handle.read();
        match aspace.handle_page_fault(vaddr, flags) {
            axmm::PageFaultResult::Handled(success) => success,
            axmm::PageFaultResult::NeedWriteLock => {
                drop(aspace);
                let mut aspace = aspace_handle.write();
                aspace.handle_page_fault_write(vaddr, flags)
            }
        }
    }

    pub fn activate(&self) {
        let pt_root = self.page_table_root();
        let asid = self.asid();
        unsafe {
            #[cfg(target_arch = "riscv64")]
            {
                axhal::asm::write_user_page_table(pt_root, asid);
                axhal::asm::flush_tlb(None);
            }
            #[cfg(target_arch = "loongarch64")]
            {
                axhal::asm::write_user_page_table(pt_root);
                axhal::asm::write_user_asid(asid);
                axhal::asm::flush_tlb(None);
            }
            #[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
            {
                axhal::asm::write_user_page_table(pt_root);
                axhal::asm::flush_tlb(None);
            }
        }
    }

    pub fn close_all_files(&self) {
        let _entries = {
            let binding = self.fd_table();
            let mut table = binding.write();
            table.drain_all()
        };
    }

    pub fn detach_all_shared_memory(&self) {
        let mut shm = self.ipc.shared_memory.write();
        for inner_arc in shm.values() {
            let mut inner = inner_arc.lock();
            inner.detach_process(self.pid());
            if inner.rmid && inner.attach_count() == 0 {
                let shmid = inner.shmid;
                drop(inner);
                let mut manager = crate::ipc::shm::SHM_MANAGER.lock();
                manager.remove_shmid(shmid);
            }
        }
        shm.clear();
    }

    fn release_zombie_resources(&self, switch_current_aspace: bool) -> AxResult<()> {
        if self.user_resources_released.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let new_handle = ZOMBIE_ASPACE_HANDLE.clone();
        let new_pt_root = new_handle.read().page_table_root();
        let new_asid = new_handle.read().asid();
        let old_handle = self.replace_aspace_handle(new_handle);
        if switch_current_aspace {
            axtask::set_current_page_table_root(new_pt_root, new_asid);
            self.activate();
        }
        drop(old_handle);
        self.heap_top.store(USER_HEAP_BASE, Ordering::Release);
        self.stack_top.store(USER_STACK_TOP, Ordering::Release);
        self.entry.store(0, Ordering::Release);

        self.detach_all_shared_memory();

        {
            let undos = {
                let mut guard = self.ipc.sem_undos.lock();
                core::mem::take(&mut *guard)
            };
            crate::ipc::sem::exit_sem_undos(self.pid() as i32, undos);
        }

        self.close_all_files();
        self.futex_table.clear();
        self.memlock_unlock_all();

        // Release fs_context, credentials, uts_ns, args, and exec_path early during exit phase.
        if let Some(root_context) = axfs::ROOT_FS_CONTEXT.get() {
            *self.fs_context.write() = Arc::new(Mutex::new(root_context.clone()));
        }

        // Keep original UIDs/GIDs to preserve status and signal permission checks (like kill(pid, 0)),
        // but drop group vectors and capabilities.
        let (ruid, euid, suid, fsuid, rgid, egid, sgid, fsgid) = {
            let creds = self.credentials.read();
            (
                creds.ruid,
                creds.euid,
                creds.suid,
                creds.fsuid,
                creds.rgid,
                creds.egid,
                creds.sgid,
                creds.fsgid,
            )
        };
        let dummy_credentials = Credentials::new(
            ruid,
            euid,
            suid,
            fsuid,
            rgid,
            egid,
            sgid,
            fsgid,
            0,
            0,
            0,
            0o022,
            Vec::new(),
        );
        *self.credentials.write() = Arc::new(dummy_credentials);

        let mut hostname_buf = [0u8; 65];
        let default_name = b"pulseos";
        hostname_buf[..default_name.len()].copy_from_slice(default_name);
        let dummy_uts_ns = UtsNamespace {
            hostname: Arc::new(RwLock::new(hostname_buf)),
        };
        *self.uts_ns.write() = Arc::new(dummy_uts_ns);

        self.args.write().clear();
        *self.exec_path.write() = None;

        axlog::debug!("release_zombie_resources: pid={}", self.pid());
        Ok(())
    }

    pub fn shrink_reaped_resources(&self) -> AxResult<()> {
        self.release_zombie_resources(false)
    }

    pub fn sync_fs_context(&self) {
        let mut fs = self.fs_context_handle().lock().clone();
        fs.credentials = Some((self.fsuid(), self.fsgid()));
        *axfs::FS_CONTEXT.lock() = fs;
    }

    pub fn save_fs_context(&self) {
        *self.fs_context_handle().lock() = axfs::FS_CONTEXT.lock().clone();
    }

    pub fn register_thread(&self, tid: u64) {
        let mut registry = self.threads.lock();
        registry.insert(tid, ThreadState::Pending);
    }

    pub fn register_task_ref(&self, task: AxTaskRef) {
        if let Some(handle) = super::thread_handle_from_task(&task) {
            handle.attach_task_ref(task.clone());
        }
        let mut registry = self.threads.lock();
        let tid = task.id().as_u64();
        registry.insert(tid, ThreadState::Active(task));
    }

    pub fn task_ref_by_tid(&self, tid: u64) -> Option<AxTaskRef> {
        let registry = self.threads.lock();
        match registry.get(&tid) {
            Some(ThreadState::Active(task)) => Some(task.clone()),
            _ => None,
        }
    }

    pub fn take_task_ref_by_tid(&self, tid: u64) -> Option<AxTaskRef> {
        let mut registry = self.threads.lock();
        match registry.remove(&tid) {
            Some(ThreadState::Active(task)) => Some(task),
            _ => None,
        }
    }

    pub fn wait_task_refs_exited(&self) {
        let tasks = {
            let registry = self.threads.lock();
            let mut tasks = Vec::with_capacity(registry.len());
            for state in registry.values() {
                if let ThreadState::Active(task) = state {
                    tasks.push(task.clone());
                }
            }
            tasks
        };
        for task in tasks {
            let _ = task.join();
        }
    }

    pub fn release_task_refs(&self) {
        self.threads.lock().clear();
    }

    pub fn unregister_thread(&self, tid: u64) -> usize {
        let mut registry = self.threads.lock();
        registry.remove(&tid);
        registry.len()
    }

    pub fn begin_group_exit(&self, exit_code: i32) {
        self.group_exit_code.store(exit_code, Ordering::Release);
        self.group_exiting.store(true, Ordering::Release);
        self.futex_table.wake_all();

        let tasks = {
            let registry = self.threads.lock();
            let mut tasks = Vec::with_capacity(registry.len());
            for state in registry.values() {
                if let ThreadState::Active(task) = state {
                    tasks.push(task.clone());
                }
            }
            tasks
        };

        for task in tasks {
            if let Some(handle) = thread_handle_from_task(&task) {
                handle.signal_wait_queue().notify_all(false);
            }
            axtask::wake_task(task, true);
        }
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
        super::unregister_thread_global(tid);
        if let Some(task) = self.task_ref_by_tid(tid) {
            if let Some(handle) = super::thread_handle_from_task(&task) {
                let now_ns = axhal::time::monotonic_time_nanos() as u64;
                let (u, s) = handle.snapshot_cpu_time_ns(now_ns);
                self.time_context
                    .user_time_ns
                    .fetch_add(u, Ordering::Relaxed);
                self.time_context
                    .sys_time_ns
                    .fetch_add(s, Ordering::Relaxed);
            }
        }

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
        self.threads.lock().clear();
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

        let is_reparented = self.reparented.load(Ordering::Acquire);
        let parent = self
            .parent
            .read()
            .as_ref()
            .and_then(|parent| parent.upgrade());

        if is_reparented {
            // Reap it immediately from the parent (which is init)!
            if let Some(parent) = parent {
                let mut children = parent.children.lock();
                if let Some(idx) = children.iter().position(|c| c.pid() == self.pid()) {
                    children.remove(idx);
                }
            }
            // Ensure all underlying tasks are joined before releasing resources
            self.wait_task_refs_exited();
            if let Err(e) = self.shrink_reaped_resources() {
                axlog::warn!(
                    "finish_thread_exit (reparented): failed to release zombie resources for \
                     pid={}: {:?}",
                    self.pid(),
                    e
                );
            }
            self.release_task_refs();
            super::unregister_process(self.pid());
        } else {
            // Re-parent all children of this process to the init process
            if let Some(init) = super::init_process() {
                if self.pid() != init.pid() {
                    let children_to_reparent = {
                        let mut my_children = self.children.lock();
                        let list = my_children.clone();
                        my_children.clear();
                        list
                    };
                    for child in children_to_reparent {
                        if child.is_zombie() {
                            // Reap zombie child immediately instead of reparenting it
                            let exited_pid = child.pid();
                            child.wait_task_refs_exited();
                            let _ = child.take_task_ref_by_tid(exited_pid);
                            if let Err(e) = child.shrink_reaped_resources() {
                                axlog::warn!("failed to shrink reaped child resources: {:?}", e);
                            }
                            child.release_task_refs();
                            super::unregister_process(exited_pid);
                        } else {
                            child.parent_pid.store(init.pid(), Ordering::Release);
                            child.reparented.store(true, Ordering::Release);
                            child
                                .parent_exit_signal
                                .store(SIGCHLD as i32, Ordering::Release);
                            *child.parent.write() = Some(Arc::downgrade(&init));
                            init.add_child(child.clone());

                            let pdeath_sig = child.pdeath_sig();
                            if pdeath_sig != 0 {
                                let _ =
                                    queue_signal_to_process(child.as_ref(), pdeath_sig as usize);
                            }

                            if child.is_zombie() {
                                let _ = queue_signal_to_process(init.as_ref(), SIGCHLD as usize);
                                init.child_exit_event.notify_all(false);
                            }
                        }
                    }
                } else {
                    self.children.lock().clear();
                }
            } else {
                self.children.lock().clear();
            }

            if let Some(parent) = parent {
                let sig = self.parent_exit_signal();
                if sig > 0 {
                    let _ = queue_signal_to_process(parent.as_ref(), sig as usize);
                }
                // The exiting task is still on its own kernel stack here.
                // Wake waiters without forcing an immediate reschedule from inside
                // the teardown path.
                parent.child_exit_event.notify_all(false);
            }
        }
    }

    pub fn add_child(&self, child: Arc<Process>) {
        self.children.lock().push(child);
    }

    pub fn parent_process(&self) -> Option<Arc<Process>> {
        self.parent.read().as_ref().and_then(|p| p.upgrade())
    }

    pub fn waitid_find_and_reap(
        &self,
        idtype: usize,
        id: usize,
        options: i32,
    ) -> Result<Option<(Arc<Process>, WaitidStatusType)>, isize> {
        let is_match = |child: &Process| -> bool {
            match idtype {
                0 => true,                     // P_ALL
                1 => child.pid() == id as u64, // P_PID
                2 => {
                    // P_PGID
                    let target_pgid = if id == 0 { self.pgid() } else { id as u64 };
                    child.pgid() == target_pgid
                }
                _ => false,
            }
        };

        let mut children = self.children.lock();
        let mut has_matching_child = false;
        let mut found_idx = None;
        let mut found_status = None;

        for (idx, child) in children.iter().enumerate() {
            if is_match(child) {
                has_matching_child = true;

                // 1. Check STOPPED
                if (options & 2) != 0 {
                    // WSTOPPED
                    let stop_sig = child.stopped_signal_pending.load(Ordering::Acquire);
                    if stop_sig != 0 {
                        found_idx = Some((idx, false));
                        found_status = Some(WaitidStatusType::Stopped { signo: stop_sig });
                        break;
                    }
                }
                // 2. Check CONTINUED
                if (options & 8) != 0 {
                    // WCONTINUED
                    if child.continued_signal_pending.load(Ordering::Acquire) {
                        found_idx = Some((idx, false));
                        found_status = Some(WaitidStatusType::Continued);
                        break;
                    }
                }
                // 3. Check EXITED (Zombie)
                if (options & 4) != 0 {
                    // WEXITED
                    if child.is_zombie() {
                        let wnowait = (options & 0x01000000) != 0;
                        found_idx = Some((idx, !wnowait));
                        let exit_code = child.exit_code.load(Ordering::Acquire);
                        let exit_signal = child.exit_signal.load(Ordering::Acquire);
                        found_status = Some(WaitidStatusType::Exited {
                            exit_code,
                            exit_signal,
                        });
                        break;
                    }
                }
            }
        }

        if !has_matching_child {
            return Err(-axerrno::LinuxError::ECHILD.code() as isize);
        }

        if let Some((idx, remove)) = found_idx {
            let child = if remove {
                children.remove(idx)
            } else {
                children[idx].clone()
            };

            let wnowait = (options & 0x01000000) != 0;
            if !wnowait {
                match found_status.as_ref().unwrap() {
                    WaitidStatusType::Stopped { .. } => {
                        child.stopped_signal_pending.store(0, Ordering::Release);
                    }
                    WaitidStatusType::Continued => {
                        child
                            .continued_signal_pending
                            .store(false, Ordering::Release);
                    }
                    _ => {}
                }
            }

            Ok(Some((child, found_status.unwrap())))
        } else {
            Ok(None)
        }
    }

    pub fn wait_for_child_state_change_interruptible(
        &self,
        idtype: usize,
        id: usize,
        options: i32,
    ) -> Result<(), i32> {
        let thread = match current_thread() {
            Ok(t) => t,
            Err(e) => return Err(e.code()),
        };

        let is_match = |child: &Process| -> bool {
            match idtype {
                0 => true,
                1 => child.pid() == id as u64,
                2 => {
                    let target_pgid = if id == 0 { self.pgid() } else { id as u64 };
                    child.pgid() == target_pgid
                }
                _ => false,
            }
        };

        let check_state = || -> bool {
            let children = self.children.lock();
            for child in children.iter() {
                if is_match(child) {
                    if (options & 2) != 0
                        && child.stopped_signal_pending.load(Ordering::Acquire) != 0
                    {
                        return true;
                    }
                    if (options & 8) != 0 && child.continued_signal_pending.load(Ordering::Acquire)
                    {
                        return true;
                    }
                    if (options & 4) != 0 && child.is_zombie() {
                        return true;
                    }
                }
            }
            false
        };

        self.child_exit_event
            .wait_until(|| check_state() || thread.has_pending_signal() || self.group_exiting());

        if check_state() {
            return Ok(());
        }

        if thread.has_pending_signal() {
            return Err(super::ERESTARTSYS);
        }
        Ok(())
    }

    fn child_matches(&self, child: &Process, pid: isize) -> bool {
        if pid == -1 {
            true
        } else if pid > 0 {
            child.pid() as isize == pid
        } else if pid == 0 {
            child.pgid() == self.pgid()
        } else {
            child.pgid() as isize == -pid
        }
    }

    pub fn has_matching_child(&self, pid: isize) -> bool {
        self.children
            .lock()
            .iter()
            .any(|child| self.child_matches(child, pid))
    }

    pub fn reap_zombie_child(&self, pid: isize) -> Option<Arc<Process>> {
        let mut children = self.children.lock();
        let idx = children
            .iter()
            .position(|child| self.child_matches(child, pid) && child.is_zombie())?;
        Some(children.remove(idx))
    }

    pub fn wait_for_child_exit(&self, pid: isize) {
        self.child_exit_event.wait_until(|| {
            self.children
                .lock()
                .iter()
                .any(|child| self.child_matches(child, pid) && child.is_zombie())
        });
    }

    pub fn wait_for_child_exit_interruptible(&self, pid: isize) -> Result<(), i32> {
        let thread = match current_thread() {
            Ok(t) => t,
            Err(e) => return Err(e.code()),
        };
        // wait_until 会在持有 WaitQueue 锁的同时执行闭包
        self.child_exit_event.wait_until(|| {
            self.children
                .lock()
                .iter()
                .any(|child| self.child_matches(child, pid) && child.is_zombie())
                || thread.has_pending_signal()
        });

        // 优先检查是否有子进程已经退出，如果有，即使有挂起信号也返回 Ok(())
        // 这样 sys_wait4 的 loop 会在下一次调用 reap_zombie_child 时成功。
        if self
            .children
            .lock()
            .iter()
            .any(|child| self.child_matches(child, pid) && child.is_zombie())
        {
            return Ok(());
        }

        if thread.has_pending_signal() {
            return Err(super::ERESTARTSYS);
        }
        Ok(())
    }

    pub fn mark_user_resume(&self) {
        if let Ok(thread) = super::current_thread() {
            thread.mark_user_resume();
        }
    }

    pub fn on_kernel_entry_from_user(&self, now_ns: u64) {
        if let Ok(thread) = super::current_thread() {
            thread.on_kernel_entry_from_user(now_ns);
        }
    }

    pub fn add_sys_time_ns(&self, delta_ns: u64) {
        if let Ok(thread) = super::current_thread() {
            thread.add_sys_time_ns(delta_ns);
        }
    }

    pub fn add_child_time_ns(&self, child_user_ns: u64, child_sys_ns: u64) {
        self.time_context
            .child_user_time_ns
            .fetch_add(child_user_ns, Ordering::Relaxed);
        self.time_context
            .child_sys_time_ns
            .fetch_add(child_sys_ns, Ordering::Relaxed);
    }

    pub fn snapshot_cpu_time_ns(&self, now_ns: u64) -> (u64, u64) {
        let mut total_user = self.time_context.user_time_ns.load(Ordering::Relaxed);
        let mut total_sys = self.time_context.sys_time_ns.load(Ordering::Relaxed);
        let registry = self.threads.lock();
        for state in registry.values() {
            if let ThreadState::Active(task) = state {
                if let Some(handle) = super::thread_handle_from_task(task) {
                    let (u, s) = handle.snapshot_cpu_time_ns(now_ns);
                    total_user = total_user.saturating_add(u);
                    total_sys = total_sys.saturating_add(s);
                }
            }
        }
        (total_user, total_sys)
    }

    pub fn snapshot_children_cpu_time_ns(&self) -> (u64, u64) {
        (
            self.time_context.child_user_time_ns.load(Ordering::Relaxed),
            self.time_context.child_sys_time_ns.load(Ordering::Relaxed),
        )
    }

    pub fn read_sys_time_ns(&self) -> u64 {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        self.snapshot_cpu_time_ns(now_ns).1
    }

    /// Set ITIMER_REAL. Returns the previous (remaining_ns, interval_ns).
    /// `value_ns` is the initial timeout in nanoseconds (0 = disarm).
    /// `interval_ns` is the repeat interval (0 = one-shot).
    pub fn set_itimer_real(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let old_deadline = self
            .time_context
            .itimer_real_deadline_ns
            .load(Ordering::Acquire);
        let old_interval = self
            .time_context
            .itimer_real_interval_ns
            .load(Ordering::Acquire);
        let old_remaining = if old_deadline == 0 {
            0
        } else if now_ns >= old_deadline {
            0
        } else {
            old_deadline - now_ns
        };

        if value_ns == 0 {
            // Disarm
            self.time_context
                .itimer_real_deadline_ns
                .store(0, Ordering::Release);
            self.time_context
                .itimer_real_interval_ns
                .store(0, Ordering::Release);
        } else {
            let deadline = now_ns.saturating_add(value_ns);
            self.time_context
                .itimer_real_deadline_ns
                .store(deadline, Ordering::Release);
            self.time_context
                .itimer_real_interval_ns
                .store(interval_ns, Ordering::Release);
            super::schedule_itimer_event(self.pid(), deadline);
        }
        (old_remaining, old_interval)
    }

    /// Get ITIMER_REAL. Returns (remaining_ns, interval_ns).
    pub fn get_itimer_real(&self) -> (u64, u64) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let deadline = self
            .time_context
            .itimer_real_deadline_ns
            .load(Ordering::Acquire);
        let interval = self
            .time_context
            .itimer_real_interval_ns
            .load(Ordering::Acquire);
        let remaining = if deadline == 0 {
            0
        } else if now_ns >= deadline {
            0
        } else {
            deadline - now_ns
        };
        (remaining, interval)
    }

    pub fn set_itimer_virt(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let old_remaining = self
            .time_context
            .itimer_virt_remaining_ns
            .swap(value_ns, Ordering::AcqRel);
        let old_interval = self
            .time_context
            .itimer_virt_interval_ns
            .swap(interval_ns, Ordering::AcqRel);
        (old_remaining, old_interval)
    }

    pub fn get_itimer_virt(&self) -> (u64, u64) {
        let remaining = self
            .time_context
            .itimer_virt_remaining_ns
            .load(Ordering::Acquire);
        let interval = self
            .time_context
            .itimer_virt_interval_ns
            .load(Ordering::Acquire);
        (remaining, interval)
    }

    pub fn set_itimer_prof(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let old_remaining = self
            .time_context
            .itimer_prof_remaining_ns
            .swap(value_ns, Ordering::AcqRel);
        let old_interval = self
            .time_context
            .itimer_prof_interval_ns
            .swap(interval_ns, Ordering::AcqRel);
        (old_remaining, old_interval)
    }

    pub fn get_itimer_prof(&self) -> (u64, u64) {
        let remaining = self
            .time_context
            .itimer_prof_remaining_ns
            .load(Ordering::Acquire);
        let interval = self
            .time_context
            .itimer_prof_interval_ns
            .load(Ordering::Acquire);
        (remaining, interval)
    }

    /// Called from timer tick hook (interrupt context). Checks if ITIMER_REAL

    pub fn check_itimer_virt_tick(&self, elapsed_ns: u64) {
        let mut remaining = self
            .time_context
            .itimer_virt_remaining_ns
            .load(Ordering::Acquire);
        if remaining == 0 {
            return;
        }

        if remaining <= elapsed_ns {
            // Expired. Send SIGVTALRM (signal 26).
            let _ = queue_signal_to_process(self, 26 /* SIGVTALRM */);
            let interval = self
                .time_context
                .itimer_virt_interval_ns
                .load(Ordering::Acquire);
            remaining = interval; // might be 0, which disarms it
        } else {
            remaining -= elapsed_ns;
        }
        self.time_context
            .itimer_virt_remaining_ns
            .store(remaining, Ordering::Release);
    }

    pub fn check_itimer_prof_tick(&self, elapsed_ns: u64) {
        let mut remaining = self
            .time_context
            .itimer_prof_remaining_ns
            .load(Ordering::Acquire);
        if remaining == 0 {
            return;
        }

        if remaining <= elapsed_ns {
            // Expired. Send SIGPROF (signal 27).
            let _ = queue_signal_to_process(self, 27 /* SIGPROF */);
            let interval = self
                .time_context
                .itimer_prof_interval_ns
                .load(Ordering::Acquire);
            remaining = interval; // might be 0, which disarms it
        } else {
            remaining -= elapsed_ns;
        }
        self.time_context
            .itimer_prof_remaining_ns
            .store(remaining, Ordering::Release);
    }

    pub fn complete_vfork(&self) {
        if let Some(ref ctx) = self.vfork_context {
            if !ctx.wait_enabled {
                return;
            }
            if !ctx.done.swap(true, Ordering::AcqRel) {
                // Keep vfork completion notification side-effect free with respect
                // to scheduling while the child is still unwinding its exit path.
                ctx.event.notify_all(false);
            }
        }
    }

    pub fn wait_for_vfork_completion(&self) {
        if let Some(ref ctx) = self.vfork_context {
            if !ctx.wait_enabled {
                return;
            }
            ctx.event.wait_until(|| ctx.done.load(Ordering::Acquire));
        }
    }

    fn futex_key(&self, addr: usize, is_private: bool) -> (usize, bool) {
        if is_private {
            (addr, true)
        } else {
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            let vaddr = VirtAddr::from(addr);
            let query_res = aspace.query_vaddr(vaddr);
            let paddr = match query_res {
                Ok((paddr, ..)) => paddr.as_usize(),
                Err(_) => {
                    // Try to handle page fault on-demand (simulate a read fault from user space to populate it)
                    let mut paddr_res = addr;
                    match aspace.handle_page_fault(
                        vaddr,
                        axhal::trap::PageFaultFlags::READ | axhal::trap::PageFaultFlags::USER,
                    ) {
                        axmm::PageFaultResult::Handled(success) => {
                            if success {
                                if let Ok((paddr, ..)) = aspace.query_vaddr(vaddr) {
                                    paddr_res = paddr.as_usize();
                                }
                            }
                        }
                        axmm::PageFaultResult::NeedWriteLock => {
                            drop(aspace);
                            let mut aspace_write = aspace_handle.write();
                            if aspace_write.handle_page_fault_write(
                                vaddr,
                                axhal::trap::PageFaultFlags::READ
                                    | axhal::trap::PageFaultFlags::USER,
                            ) {
                                if let Ok((paddr, ..)) = aspace_write.query_vaddr(vaddr) {
                                    paddr_res = paddr.as_usize();
                                }
                            }
                        }
                    }
                    paddr_res
                }
            };
            (paddr, false)
        }
    }

    pub fn futex_waitv(
        &self,
        waiters_addr: usize,
        nr_futexes: u32,
        _flags: u32,
        timeout_ns: Option<u64>,
    ) -> AxResult<isize> {
        let mut waiters = alloc::vec::Vec::with_capacity(nr_futexes as usize);
        for i in 0..nr_futexes {
            let mut w = FutexWaitv::default();
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    &mut w as *mut _ as *mut u8,
                    core::mem::size_of::<FutexWaitv>(),
                )
            };
            self.read_user_bytes(
                waiters_addr + i as usize * core::mem::size_of::<FutexWaitv>(),
                buf,
            )?;
            waiters.push(w);
        }

        for w in &waiters {
            if w.__reserved != 0 {
                return Err(AxError::InvalidInput);
            }
            let valid_flags = 0x02 | 0x80;
            if (w.flags & !valid_flags) != 0 || (w.flags & 0x03) != 0x02 {
                return Err(AxError::InvalidInput);
            }
            if w.uaddr % 4 != 0 {
                return Err(AxError::InvalidInput);
            }
            if w.uaddr == 0 {
                return Err(AxError::BadAddress);
            }
            self.read_user_u32(w.uaddr as usize)?;
        }

        let current_thread = super::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };

        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) }); // ERESTARTSYS
        }

        let mut queues = alloc::vec::Vec::with_capacity(waiters.len());
        for w in &waiters {
            let is_priv = w.flags & 128 != 0; // 128 is FUTEX_PRIVATE_FLAG
            let (key, is_priv) = self.futex_key(w.uaddr as usize, is_priv);
            let queue = if is_priv {
                self.futex_table.queue(key)
            } else {
                GLOBAL_FUTEX_TABLE.queue(key)
            };
            queues.push(queue);
        }

        let q_refs: alloc::vec::Vec<&axtask::WaitQueue> =
            queues.iter().map(|q| q.as_ref()).collect();

        let mut mismatch = false;

        let res = axtask::WaitQueue::wait_multiple_timeout_until(
            &q_refs,
            timeout_ns.map(core::time::Duration::from_nanos),
            || {
                if self.group_exiting() || signal_pending() {
                    return true;
                }
                mismatch = false;
                for w in waiters.iter() {
                    match self.read_user_u32(w.uaddr as usize) {
                        Ok(v) => {
                            if v != w.val as u32 {
                                mismatch = true;
                                return true;
                            }
                        }
                        Err(_) => {
                            mismatch = true;
                            return true;
                        }
                    }
                }
                false
            },
        );

        // Remove from GLOBAL_FUTEX_TABLE if empty
        if self.group_exiting() || mismatch || res.is_ok() || res.is_err() {
            for (_i, w) in waiters.iter().enumerate() {
                let is_priv = w.flags & 128 != 0;
                if !is_priv {
                    let (key, _) = self.futex_key(w.uaddr as usize, is_priv);
                    GLOBAL_FUTEX_TABLE.remove_if_empty(key);
                }
            }
        }

        if mismatch {
            return Err(AxError::from(AxErrorKind::WouldBlock)); // EAGAIN
        }

        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) }); // ERESTARTSYS
        }

        match res {
            Ok(idx) => Ok(idx as isize),
            Err(true) => Err(AxError::from(AxErrorKind::TimedOut)),
            Err(false) => Err(unsafe { core::mem::transmute(-512i32) }), // Aborted not by timeout
        }
    }

    pub fn futex_wait(
        &self,
        addr: usize,
        expected: u32,
        timeout_ns: Option<u64>,
        is_private: bool,
    ) -> AxResult<()> {
        if match self.read_user_u32(addr) {
            Ok(v) => v != expected,
            Err(e) => return Err(e),
        } {
            return Err(AxError::from(AxErrorKind::WouldBlock));
        }
        let current_thread = super::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };
        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) });
        }

        let (key, is_priv) = self.futex_key(addr, is_private);

        let queue = if is_priv {
            self.futex_table.queue(key)
        } else {
            GLOBAL_FUTEX_TABLE.queue(key)
        };

        if self.group_exiting() {
            if !is_priv {
                GLOBAL_FUTEX_TABLE.remove_if_empty(key);
            }
            return Ok(());
        }

        let timed_out = if let Some(timeout_ns) = timeout_ns {
            let dur = core::time::Duration::from_nanos(timeout_ns);
            queue.wait_timeout(dur)
        } else {
            queue.wait();
            false
        };

        if !is_priv {
            GLOBAL_FUTEX_TABLE.remove_if_empty(key);
        }

        if self.group_exiting() {
            return Ok(());
        }
        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) });
        }
        if timed_out {
            return Err(AxError::from(AxErrorKind::TimedOut));
        }

        Ok(())
    }

    fn futex_wake_impl(&self, addr: usize, count: usize, resched: bool, is_private: bool) -> usize {
        let (key, is_priv) = self.futex_key(addr, is_private);
        let woken = if is_priv {
            if resched {
                self.futex_table.wake(key, count)
            } else {
                self.futex_table.wake_no_resched(key, count)
            }
        } else {
            if resched {
                GLOBAL_FUTEX_TABLE.wake(key, count)
            } else {
                GLOBAL_FUTEX_TABLE.wake_no_resched(key, count)
            }
        };

        if !is_priv {
            GLOBAL_FUTEX_TABLE.remove_if_empty(key);
        }
        woken
    }

    pub fn futex_wake(&self, addr: usize, count: usize, is_private: bool) -> usize {
        self.futex_wake_impl(addr, count, true, is_private)
    }

    pub fn futex_wake_no_resched(&self, addr: usize, count: usize, is_private: bool) -> usize {
        self.futex_wake_impl(addr, count, false, is_private)
    }

    pub fn futex_requeue(
        &self,
        addr: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
        is_private: bool,
    ) -> usize {
        let (key, is_priv) = self.futex_key(addr, is_private);
        let (target_key, _) = self.futex_key(target, is_private);
        let woken_requeued = if is_priv {
            self.futex_table
                .requeue(key, wake_count, target_key, requeue_count)
        } else {
            GLOBAL_FUTEX_TABLE.requeue(key, wake_count, target_key, requeue_count)
        };

        if !is_priv {
            GLOBAL_FUTEX_TABLE.remove_if_empty(key);
            GLOBAL_FUTEX_TABLE.remove_if_empty(target_key);
        }
        woken_requeued
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
        let _ = self.futex_wake_no_resched(futex_addr, 1, true);
        let _ = self.futex_wake_no_resched(futex_addr, 1, false);
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
        let mut parent_aspace = parent_aspace_handle.write();
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
            axtask::current().name(),
            TASK_STACK_SIZE,
        )?;

        let child_tid = inner.id().as_u64();
        let new_aspace_arc = Arc::new(RwLock::new(new_aspace));
        let child_proc = Self::new_child_process(
            child_tid,
            self.clone(),
            new_aspace_arc,
            false,
            params.is_vfork,
            params.share_fs,
            params.share_files,
            params.share_sighand,
            params.share_uts,
        )?;

        if let Some(sig) = params.exit_signal {
            child_proc.set_parent_exit_signal(sig);
        }

        if let Some(addr) = params.parent_set_tid {
            let child_tid = child_tid as u32;
            self.write_user_bytes_in_aspace(&mut parent_aspace, addr, &child_tid.to_ne_bytes())?;
        }
        let child_thread = Thread::new(child_proc.clone());
        super::register_thread_global(child_tid, child_thread.clone());
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
        let asid = child_proc.asid();
        inner.ctx_mut().set_page_table_root(pt_root, asid);
        super::register_process(child_proc.pid(), child_proc.clone());
        inner.init_task_ext(super::ThreadHandle::new(child_thread));

        self.add_child(child_proc.clone());
        let task_ref = inner.into_arc();
        child_proc.register_task_ref(task_ref.clone());
        axtask::spawn_task_ref(task_ref);
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
            axtask::current().name(),
            TASK_STACK_SIZE,
        )?;

        let child_tid = inner.id().as_u64();
        let child_proc = if params.is_thread_clone {
            self.register_thread(child_tid);
            self.clone()
        } else {
            let parent_aspace_handle = self.aspace_handle();
            let proc = Self::new_child_process(
                child_tid,
                self.clone(),
                parent_aspace_handle.clone(),
                true,
                params.is_vfork,
                params.share_fs,
                params.share_files,
                params.share_sighand,
                params.share_uts,
            )?;
            if let Some(sig) = params.exit_signal {
                proc.set_parent_exit_signal(sig);
            }
            proc
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
        super::register_thread_global(child_tid, child_thread.clone());
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
        let asid = child_proc.asid();
        inner.ctx_mut().set_page_table_root(pt_root, asid);
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

    pub fn alloc_posix_timer(
        &self,
        clock_id: i32,
        event: sigevent,
    ) -> Result<i32, axerrno::LinuxError> {
        match clock_id {
            0 | 1 | 2 | 3 | 7 => {}
            _ => return Err(axerrno::LinuxError::EINVAL),
        }

        let mut timers = self.posix_timers.lock();
        for (i, slot) in timers.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(PosixTimer {
                    id: i,
                    clock_id,
                    event,
                    itimer_spec: unsafe { core::mem::zeroed() },
                    overrun: 0,
                    next_deadline_ns: 0,
                    interval_ns: 0,
                });
                return Ok(i as i32);
            }
        }
        Err(axerrno::LinuxError::ENOSPC)
    }
}
