use super::Thread;
use crate::config::*;
use crate::fd_table::{FdTable, SharedFdTable, stdio_entries};
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use axconfig::TASK_STACK_SIZE;
use axerrno::{AxError, AxResult};
use axfs::FsContext;
use axhal::context::{TrapFrame, UspaceContext};
use axhal::paging::MappingFlags;
use axmm::{AddrSpace, Backend};
use axtask::{AxTaskRef, TaskInner, WaitQueue};
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use kernel_guard::NoPreemptIrqSave;
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, PhysAddr, VirtAddr, va};
use spin::Mutex;

const ROBUST_LIST_LIMIT: usize = 2048;
const REAPED_CHILD_CACHE_LIMIT: usize = 1024;

fn align_up_4k(value: usize) -> usize {
    (value + 0xfff) & !0xfff
}

fn collect_user_areas(
    aspace: &AddrSpace,
    start: VirtAddr,
    end: VirtAddr,
) -> Vec<(VirtAddr, VirtAddr, MappingFlags, Backend)> {
    let mut areas = Vec::new();
    aspace.for_each_area_with_backend(|area_start, area_end, flags, backend| {
        let user_flags = flags
            & (MappingFlags::READ
                | MappingFlags::WRITE
                | MappingFlags::EXECUTE
                | MappingFlags::USER);
        if !user_flags.contains(MappingFlags::USER) {
            return;
        }
        let clipped_start = core::cmp::max(area_start.as_usize(), start.as_usize());
        let clipped_end = core::cmp::min(area_end.as_usize(), end.as_usize());
        if clipped_start >= clipped_end {
            return;
        }
        areas.push((
            va!(clipped_start).align_down_4k(),
            va!(align_up_4k(clipped_end)),
            user_flags,
            backend.clone(),
        ));
    });

    areas
}

fn share_user_page(
    parent_aspace: &mut AddrSpace,
    new_aspace: &mut AddrSpace,
    vaddr: VirtAddr,
    frame: PhysAddr,
    pte_flags: MappingFlags,
) -> AxResult<()> {
    let child_flags = if pte_flags.contains(MappingFlags::WRITE) {
        pte_flags - MappingFlags::WRITE
    } else {
        pte_flags
    };

    if pte_flags.contains(MappingFlags::WRITE) {
        parent_aspace.protect_pte_only(vaddr, PAGE_SIZE_4K, child_flags)?;
    }

    axmm::cow_inc_frame_ref(frame);
    new_aspace.remap_page(vaddr, frame, child_flags)?;
    Ok(())
}

fn share_present_pages_cow(
    parent_aspace: &mut AddrSpace,
    new_aspace: &mut AddrSpace,
    start: VirtAddr,
    end: VirtAddr,
) -> AxResult<()> {
    for vaddr in memory_addr::PageIter4K::new(start, end).unwrap() {
        let Ok((frame, pte_flags, _)) = parent_aspace.page_table().query(vaddr) else {
            continue;
        };
        if frame.as_usize() == 0 || !frame.is_aligned_4k() {
            continue;
        }
        if !pte_flags.contains(MappingFlags::USER) {
            continue;
        }
        share_user_page(parent_aspace, new_aspace, vaddr, frame, pte_flags)?;
    }
    Ok(())
}

struct FutexTable {
    queues: Mutex<BTreeMap<usize, Arc<WaitQueue>>>,
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
            queue.notify_all(true);
        }
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
    reaped_children: Mutex<Vec<Arc<Process>>>,
    child_exit_event: WaitQueue,
    zombie: AtomicBool,
    exit_code: AtomicI32,
    group_exiting: AtomicBool,
    group_exit_code: AtomicI32,
    futex_table: FutexTable,
    vfork_wait_enabled: AtomicBool,
    vfork_done: AtomicBool,
    vfork_event: WaitQueue,
}

impl Process {
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

    fn clone_private_fs_context(parent: &Arc<Process>) -> AxResult<Arc<Mutex<FsContext>>> {
        Ok(Arc::new(Mutex::new(parent.fs_context.lock().clone())))
    }

    pub fn pid(&self) -> u64 {
        self.pid
    }

    pub fn parent_pid(&self) -> u64 {
        self.parent_pid
    }

    pub fn thread_count(&self) -> usize {
        self.threads.lock().len()
    }

    pub fn read_user_bytes(&self, user_addr: usize, bytes: &mut [u8]) -> AxResult<()> {
        self.validate_user_range(user_addr, bytes.len())?;
        self.aspace_handle()
            .lock()
            .read(VirtAddr::from(user_addr), bytes)
            .map_err(AxError::from)
    }

    pub fn write_user_bytes(&self, user_addr: usize, bytes: &[u8]) -> AxResult<()> {
        self.validate_user_range(user_addr, bytes.len())?;
        self.aspace_handle()
            .lock()
            .write(VirtAddr::from(user_addr), bytes)
            .map_err(AxError::from)
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
            true,
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
            heap_top: Arc::new(Mutex::new(USER_HEAP_BASE + USER_HEAP_SIZE)),
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
            reaped_children: Mutex::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_wait_enabled: AtomicBool::new(false),
            vfork_done: AtomicBool::new(false),
            vfork_event: WaitQueue::new(),
        }))
    }

    fn new_child_process(
        pid: u64,
        parent: &Arc<Process>,
        aspace: Arc<Mutex<AddrSpace>>,
        share_vm: bool,
        is_vfork: bool,
        share_fs: bool,
        share_files: bool,
    ) -> AxResult<Arc<Self>> {
        let heap_top = if share_vm {
            parent.heap_top.clone()
        } else {
            Arc::new(Mutex::new(*parent.heap_top.lock()))
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

        Ok(Arc::new(Self {
            pid,
            parent_pid: parent.pid(),
            parent: Mutex::new(Some(Arc::downgrade(parent))),
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
            reaped_children: Mutex::new(Vec::new()),
            child_exit_event: WaitQueue::new(),
            zombie: AtomicBool::new(false),
            exit_code: AtomicI32::new(0),
            group_exiting: AtomicBool::new(false),
            group_exit_code: AtomicI32::new(0),
            futex_table: FutexTable::new(),
            vfork_wait_enabled: AtomicBool::new(is_vfork),
            vfork_done: AtomicBool::new(false),
            vfork_event: WaitQueue::new(),
        }))
    }

    pub fn handle_page_fault(&self, vaddr: VirtAddr, flags: axhal::trap::PageFaultFlags) -> bool {
        self.aspace_handle().lock().handle_page_fault(vaddr, flags)
    }

    pub fn activate(&self) {
        #[cfg(any(target_arch = "riscv64", target_arch = "loongarch64"))]
        let pt_root = {
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.lock();
            aspace.page_table_root()
        };
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("csrw satp, {0}", "sfence.vma", in(reg) (8usize << 60) | (pt_root.as_usize() >> 12));
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            axhal::asm::write_user_page_table(pt_root);
            axhal::asm::flush_tlb(None);
        }
    }

    pub fn ensure_kernel_mappings(&self) {
        #[cfg(target_arch = "riscv64")]
        {
            let probe = va!(0xffffffc010001000usize);
            let aspace_handle = self.aspace_handle();
            let mut aspace = aspace_handle.lock();
            let mapped = aspace
                .page_table()
                .query(probe)
                .ok()
                .map(|(pa, flags, _)| (pa.as_usize(), flags));
            if mapped.is_none()
                && let Ok(kernel_shadow) = axmm::new_kernel_aspace()
            {
                if let Err(e) = aspace.copy_mappings_from(&kernel_shadow) {
                    axlog::warn!("failed to repair kernel mappings: {:?}", e);
                }
                core::mem::forget(kernel_shadow);
            }
        }
    }

    pub fn close_all_files(&self) {
        let entries = {
            let mut table = self.fd_table.lock();
            table.drain_all()
        };
        drop(entries);
    }

    pub fn shrink_reaped_resources(&self) -> AxResult<()> {
        let empty_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        {
            let new_handle = Arc::new(Mutex::new(empty_aspace));
            let _old = self.replace_aspace_handle(new_handle);
        }
        *self.heap_top.lock() = USER_HEAP_BASE;
        *self.stack_top.lock() = USER_STACK_TOP;
        *self.entry.lock() = 0;
        Ok(())
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
        self.task_refs.lock().push(task);
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

    pub fn finish_thread_exit(&self, tid: u64, exit_code: i32) {
        if self.unregister_thread(tid) != 0 {
            return;
        }

        let final_code = if self.group_exiting() {
            self.group_exit_code()
        } else {
            exit_code
        };
        self.exit_code.store(final_code, Ordering::Release);
        self.zombie.store(true, Ordering::Release);
        self.complete_vfork();
        self.close_all_files();

        let parent = self
            .parent
            .lock()
            .as_ref()
            .and_then(|parent| parent.upgrade());
        if let Some(parent) = parent {
            parent.child_exit_event.notify_all(true);
        }
    }

    pub fn add_child(&self, child: Arc<Process>) {
        self.children.lock().push(child);
    }

    pub fn stash_reaped_child(&self, child: Arc<Process>) {
        let mut reaped = self.reaped_children.lock();
        reaped.push(child);
        if reaped.len() > REAPED_CHILD_CACHE_LIMIT {
            reaped.remove(0);
        }
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

    pub fn complete_vfork(&self) {
        if !self.vfork_wait_enabled.load(Ordering::Acquire) {
            return;
        }
        if !self.vfork_done.swap(true, Ordering::AcqRel) {
            self.vfork_event.notify_all(true);
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

        if let Some(timeout_ns) = timeout_ns {
            let deadline = (axhal::time::monotonic_time_nanos() as u64).saturating_add(timeout_ns);
            while !self.group_exiting() {
                if self.read_user_u32(addr).unwrap_or(expected) != expected {
                    return Ok(());
                }
                if axhal::time::monotonic_time_nanos() as u64 >= deadline {
                    return Err(AxError::TimedOut);
                }
                axtask::yield_now();
            }
            return Ok(());
        }

        let queue = self.futex_table.queue(addr);
        queue.wait_until(|| {
            self.group_exiting()
                || self
                    .read_user_u32(addr)
                    .map(|current| current != expected)
                    .unwrap_or(true)
        });
        Ok(())
    }

    pub fn futex_wake(&self, addr: usize, count: usize) -> usize {
        self.futex_table.wake(addr, count)
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
            axtask::yield_now();
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
        let _ = self.futex_wake(futex_addr, 1);
    }

    pub fn spawn_fork_from_trap_frame(
        self: &Arc<Self>,
        tf: &TrapFrame,
        child_stack: Option<usize>,
        is_vfork: bool,
        share_fs: bool,
        share_files: bool,
        parent_set_tid: Option<usize>,
        child_set_tid: Option<usize>,
        child_clear_tid: Option<usize>,
    ) -> AxResult<Arc<Process>> {
        let _guard = NoPreemptIrqSave::new();
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = child_stack {
            child_uctx.set_sp(sp);
        }

        let mut new_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let parent_aspace_handle = self.aspace_handle();
        let mut parent_aspace = parent_aspace_handle.lock();
        let mapped_user_areas =
            collect_user_areas(&parent_aspace, va!(USER_SPACE_BASE), va!(USER_STACK_TOP));
        let mut cow_ranges = Vec::new();
        for (start, end, area_user_flags, backend) in mapped_user_areas {
            new_aspace.map_with_backend(
                start,
                end.as_usize() - start.as_usize(),
                area_user_flags,
                backend.clone(),
            )?;
            if matches!(backend, Backend::Alloc { .. }) {
                cow_ranges.push((start, end));
            }
        }

        for (start, end) in cow_ranges {
            share_present_pages_cow(&mut parent_aspace, &mut new_aspace, start, end)?;
        }
        drop(parent_aspace);
        let mut inner = TaskInner::new(
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
        );

        let child_tid = inner.id().as_u64();
        let child_proc = Self::new_child_process(
            child_tid,
            self,
            Arc::new(Mutex::new(new_aspace)),
            false,
            is_vfork,
            share_fs,
            share_files,
        )?;
        let child_thread = Thread::new(child_tid, child_proc.clone());
        if let Some(addr) = child_set_tid {
            child_thread.set_child_tid_addr(addr);
        }
        if let Some(addr) = child_clear_tid {
            child_thread.set_clear_child_tid(addr);
        }

        if let Some(parent_tid_addr) = parent_set_tid {
            self.write_user_u32(parent_tid_addr, child_tid as u32)?;
        }

        let new_pt_root = child_proc.page_table_root();
        inner.ctx_mut().set_page_table_root(new_pt_root);
        super::register_thread_task(child_tid, child_thread.clone());
        inner.init_task_ext(super::ThreadHandle::new(child_thread));

        let task = axtask::spawn_task(inner);
        child_proc.register_task_ref(task.clone());
        self.add_child(child_proc.clone());
        Ok(child_proc)
    }

    pub fn spawn_from_trap_frame(
        self: &Arc<Self>,
        tf: &TrapFrame,
        child_stack: Option<usize>,
        is_thread_clone: bool,
        is_vfork: bool,
        share_fs: bool,
        share_files: bool,
        parent_set_tid: Option<usize>,
        child_set_tid: Option<usize>,
        child_clear_tid: Option<usize>,
    ) -> AxResult<(u64, Option<Arc<Process>>)> {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = child_stack {
            child_uctx.set_sp(sp);
        }

        let mut inner = TaskInner::new(
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
        );

        let child_tid = inner.id().as_u64();
        let child_proc = if is_thread_clone {
            self.register_thread(child_tid);
            self.clone()
        } else {
            Self::new_child_process(
                child_tid,
                self,
                self.aspace_handle(),
                true,
                is_vfork,
                share_fs,
                share_files,
            )?
        };

        if let Some(parent_tid_addr) = parent_set_tid
            && let Err(e) = self.write_user_u32(parent_tid_addr, child_tid as u32)
        {
            if is_thread_clone {
                self.unregister_thread(child_tid);
            }
            return Err(e);
        }

        let child_thread = Thread::new(child_tid, child_proc.clone());
        if let Some(addr) = child_set_tid {
            child_thread.set_child_tid_addr(addr);
        }
        if let Some(addr) = child_clear_tid {
            child_thread.set_clear_child_tid(addr);
        }

        let pt_root = child_proc.page_table_root();
        inner.ctx_mut().set_page_table_root(pt_root);
        super::register_thread_task(child_tid, child_thread.clone());
        inner.init_task_ext(super::ThreadHandle::new(child_thread));

        let task = axtask::spawn_task(inner);
        child_proc.register_task_ref(task.clone());
        if !is_thread_clone {
            self.add_child(child_proc.clone());
        }
        Ok((child_tid, (!is_thread_clone).then_some(child_proc)))
    }
}
