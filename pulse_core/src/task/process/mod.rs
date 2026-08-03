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
use axtask::{AxTaskRef, TaskInner, WaitContext, WaitQueue, WaitReason, WakeContext, WakeSource};
use kernel_guard::NoPreemptIrqSave;
use kspin::SpinNoIrq;
use linux_raw_sys::general::{
    RLIMIT_CORE, RLIMIT_DATA, RLIMIT_MEMLOCK, RLIMIT_NOFILE, RLIMIT_SIGPENDING, RLIMIT_STACK,
    SIGCHLD, itimerspec, rlimit64, sigevent,
};
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr, va};
use spin::{Lazy, Mutex, RwLock};

use super::{
    AddressSpaceLock, SignalShared, Thread, current_thread, queue_signal_to_process,
    thread_handle_from_task,
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
    pub generation: u64,
    pub clock_id: i32,
    pub event: sigevent,
    pub itimer_spec: itimerspec,
    pub overrun: i32,
    pub next_deadline_ns: u64,
    pub interval_ns: u64,
    pub is_absolute: bool,
    pub first_expired: bool,
}

unsafe impl Send for PosixTimer {}
unsafe impl Sync for PosixTimer {}

static ZOMBIE_ASPACE_HANDLE: Lazy<Arc<AddressSpaceLock>> = Lazy::new(|| {
    Arc::new(AddressSpaceLock::new(
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
    data_soft: u64,
    data_hard: u64,
    sigpending_soft: u64,
    sigpending_hard: u64,
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
            data_soft: u64::MAX,
            data_hard: u64::MAX,
            sigpending_soft: u64::MAX,
            sigpending_hard: u64::MAX,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BrkState {
    start: usize,
    current: usize,
    start_data: usize,
    end_data: usize,
}

impl BrkState {
    fn new(start: usize, current: usize, start_data: usize, end_data: usize) -> Self {
        Self {
            start,
            current,
            start_data,
            end_data,
        }
    }

    pub fn start(&self) -> usize {
        self.start
    }

    pub fn current(&self) -> usize {
        self.current
    }

    pub fn set_current(&mut self, current: usize) {
        self.current = current;
    }

    pub fn data_segment_size(&self) -> usize {
        self.end_data.saturating_sub(self.start_data)
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
        let context = WakeContext::new(|| (WakeSource::Futex, addr as u64));
        while woken < count && queue.notify_one_with_context(true, context) {
            woken += 1;
        }
        drop(queue);
        self.remove_if_empty(addr);
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
        let context = WakeContext::new(|| (WakeSource::Futex, addr as u64));
        while woken < count && queue.notify_one_with_context(false, context) {
            woken += 1;
        }
        drop(queue);
        self.remove_if_empty(addr);
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
        let context = WakeContext::new(|| (WakeSource::Futex, addr as u64));
        while woken < wake_count && source_queue.notify_one_with_context(true, context) {
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
            queues
                .iter()
                .map(|(key, queue)| (*key, queue.clone()))
                .collect::<Vec<_>>()
        };
        for (key, queue) in queues {
            queue.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Futex, key as u64)),
            );
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
            // The table must be the sole Arc owner. A waiter obtains an Arc
            // before it enrolls in the WaitQueue, so removing at a count of 2
            // can orphan that waiter before a concurrent wake lookup.
            if queue.is_empty() && Arc::strong_count(queue) == 1 {
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
    aspace: RwLock<Arc<AddressSpaceLock>>,
    /// Program-break state, shared by processes that share the address space.
    brk_state: RwLock<Arc<Mutex<BrkState>>>,
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
    /// Serializes exec and identifies the thread performing irreversible teardown.
    exec_lock: Mutex<()>,
    exec_teardown_owner: AtomicU64,
    /// Set after this process has successfully installed a new executable image.
    /// Parents use it to enforce setpgid(2)'s post-exec EACCES rule.
    has_execed: AtomicBool,
    thread_exit_event: WaitQueue,
    /// 子进程列表，使用自旋锁保护
    children: SpinNoIrq<Vec<Arc<Process>>>,
    /// 子进程退出等待事件队列
    pub child_exit_event: WaitQueue,
    /// 进程自身进入僵尸态时唤醒等待本进程 pidfd 的观察者。
    /// 与 `child_exit_event` 不同：后者由父进程等待子进程使用，前者由
    /// `PidfdObject::register_poll` 持有，用于在 epoll/poll 中唤醒观察者。
    pub pid_exit_event: WaitQueue,
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
    /// Keeps executable inodes write-denied for the lifetime of this image.
    exec_access: RwLock<Vec<axfs::ExecAccessGuard>>,
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
    /// 当前的作业控制停止状态。它独立于 waitid 的一次性状态报告，避免
    /// 父进程消费 WSTOPPED 后错误地让子进程继续执行。
    job_control_stop_signal: AtomicI32,
    /// 被停止的组内线程在此等待 SIGCONT、致命信号或组退出。
    job_control_event: WaitQueue,
    /// 进程组标识符 (PGID)
    pgid: AtomicU64,
    /// 会话标识符 (SID)
    sid: AtomicU64,
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
    posix_timer_generation: AtomicU64,
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
    pub clear_sighand: bool,
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
    pub clear_sighand: bool,
    pub share_uts: bool,
    pub exit_signal: Option<i32>,
}

#[derive(Debug, Clone, Copy)]
pub enum WaitidStatusType {
    Exited { exit_code: i32, exit_signal: i32 },
    Stopped { signo: i32 },
    Continued,
}

mod fd;
mod futex;
mod memory;
mod resources;
mod runtime;
mod setup;
mod spawn;
mod time;

impl Process {
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
            table.clone_for_fork()
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

    pub fn exec_path_or_default(&self) -> String {
        self.exec_path().unwrap_or_else(|| "pulse_init".to_string())
    }

    pub fn set_exec_path(&self, path: String) {
        *self.exec_path.write() = Some(path);
    }

    pub(super) fn replace_exec_access(
        &self,
        access: Vec<axfs::ExecAccessGuard>,
    ) -> Vec<axfs::ExecAccessGuard> {
        core::mem::replace(&mut *self.exec_access.write(), access)
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

    pub(super) fn try_lock_exec(&self) -> Option<spin::MutexGuard<'_, ()>> {
        self.exec_lock.try_lock()
    }

    pub(super) fn begin_exec_teardown(&self, caller_tid: u64) {
        self.exec_teardown_owner
            .store(caller_tid, Ordering::Release);
    }

    pub(super) fn end_exec_teardown(&self) {
        self.exec_teardown_owner.store(0, Ordering::Release);
    }

    fn has_exec_siblings(&self, caller_tid: u64) -> bool {
        self.threads.lock().keys().any(|tid| *tid != caller_tid)
    }

    pub(super) fn terminate_exec_siblings(&self, caller_tid: u64) {
        loop {
            let siblings = {
                let registry = self.threads.lock();
                registry
                    .iter()
                    .filter_map(|(tid, state)| {
                        if *tid == caller_tid {
                            return None;
                        }
                        match state {
                            ThreadState::Active(task) => Some(task.clone()),
                            ThreadState::Pending => None,
                        }
                    })
                    .collect::<Vec<_>>()
            };

            if siblings.is_empty() && !self.has_exec_siblings(caller_tid) {
                return;
            }

            for task in siblings {
                if let Some(handle) = super::thread_handle_from_task(&task) {
                    handle.request_exec_exit();
                }
                axtask::interrupt_task(task, true);
            }

            self.thread_exit_event
                .wait_until(|| !self.has_exec_siblings(caller_tid));
        }
    }

    pub(super) fn rebind_exec_thread(&self, thread: &Arc<Thread>, old_tid: u64, new_tid: u64) {
        if old_tid == new_tid {
            return;
        }

        let mut registry = self.threads.lock();
        assert_eq!(registry.len(), 1, "exec TID rebind with live siblings");
        let state = registry
            .remove(&old_tid)
            .expect("exec caller missing from process thread registry");
        assert!(
            !registry.contains_key(&new_tid),
            "exec target TID is still occupied"
        );

        thread.set_tid_for_exec(new_tid);
        super::rebind_thread_global_for_exec(old_tid, new_tid, thread);
        registry.insert(new_tid, state);
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
}
