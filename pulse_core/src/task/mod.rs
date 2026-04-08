use crate::config::*;
use crate::fd_table::{FdEntry, FdFlags, FdTable, RawFdObject, SharedFdTable};
use alloc::sync::Arc;
use alloc::vec::Vec;
use arceos_posix_api::sys_close as ax_sys_close;
use axconfig::TASK_STACK_SIZE;
use axerrno::AxResult;
use axfs::FsContext;
use axhal::context::{TrapFrame, UspaceContext};
use axhal::paging::MappingFlags;
use axmm::AddrSpace;
use axtask::{TaskInner, def_task_ext};
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use memory_addr::{VirtAddr, va};
use spin::Mutex;
pub struct Process {
    pub aspace: Arc<Mutex<AddrSpace>>,
    pub heap_top: Arc<Mutex<usize>>,
    pub fs_context: Arc<Mutex<FsContext>>,
    pub fd_table: SharedFdTable,
    pub parent_pid: Arc<Mutex<u64>>,
    pub start_mono_ns: u64,
    pub user_time_ns: Arc<AtomicU64>,
    pub sys_time_ns: Arc<AtomicU64>,
    pub child_user_time_ns: Arc<AtomicU64>,
    pub child_sys_time_ns: Arc<AtomicU64>,
    pub last_user_enter_ns: Arc<AtomicU64>,
    pub in_user_mode: Arc<AtomicBool>,
    pub stack_top: Mutex<usize>,
    pub entry: Mutex<usize>,
    pub children: Mutex<Vec<axtask::AxTaskRef>>,
}
def_task_ext!(Process);
impl Process {
    pub fn new_uspace() -> AxResult<Self> {
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
        let fs_context = axfs::FS_CONTEXT.lock().clone();

        let mut fd_table = FdTable::new();
        let _ = fd_table.insert_at(
            0,
            FdEntry {
                object: Arc::new(RawFdObject { raw_fd: 0 }),
                flags: FdFlags::empty(),
            },
        );
        let _ = fd_table.insert_at(
            1,
            FdEntry {
                object: Arc::new(RawFdObject { raw_fd: 1 }),
                flags: FdFlags::empty(),
            },
        );
        let _ = fd_table.insert_at(
            2,
            FdEntry {
                object: Arc::new(RawFdObject { raw_fd: 2 }),
                flags: FdFlags::empty(),
            },
        );

        Ok(Self {
            start_mono_ns: axhal::time::monotonic_time_nanos() as u64,
            aspace: Arc::new(Mutex::new(aspace)),
            heap_top: Arc::new(Mutex::new(USER_HEAP_BASE + USER_HEAP_SIZE)),
            fs_context: Arc::new(Mutex::new(fs_context)),
            fd_table: Arc::new(Mutex::new(fd_table)),
            parent_pid: Arc::new(Mutex::new(0)),
            user_time_ns: Arc::new(AtomicU64::new(0)),
            sys_time_ns: Arc::new(AtomicU64::new(0)),
            child_user_time_ns: Arc::new(AtomicU64::new(0)),
            child_sys_time_ns: Arc::new(AtomicU64::new(0)),
            last_user_enter_ns: Arc::new(AtomicU64::new(0)),
            in_user_mode: Arc::new(AtomicBool::new(false)),
            stack_top: Mutex::new(USER_STACK_TOP),
            entry: Mutex::new(0),
            children: Mutex::new(Vec::new()),
        })
    }
    pub fn handle_page_fault(&self, vaddr: VirtAddr, flags: axhal::trap::PageFaultFlags) -> bool {
        self.aspace.lock().handle_page_fault(vaddr, flags)
    }
    pub fn activate(&self) {
        let aspace = self.aspace.lock();
        let pt_root = aspace.page_table_root();
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("csrw satp, {0}", "sfence.vma", in(reg) (8usize << 60) | (pt_root.as_usize() >> 12));
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            // LoongArch64 user space page table root must be written to PGDL.
            axhal::asm::write_user_page_table(pt_root);
            axhal::asm::flush_tlb(None);
        }
    }
    pub fn load_elf(&self, path: &str, args: &[&str], envs: &[&str]) -> AxResult<()> {
        let mut aspace = self.aspace.lock();
        let load_info = crate::mm::load_user_app(&mut aspace, path, args, envs)?;
        *self.entry.lock() = load_info.entry;
        *self.stack_top.lock() = load_info.user_sp;
        Ok(())
    }
    pub fn enter_user_mode(&self) -> ! {
        let entry = *self.entry.lock();
        let stack_top = *self.stack_top.lock();
        let uctx = axhal::context::UspaceContext::new(entry, va!(stack_top), 0);
        self.mark_user_resume();
        let kstack_top = axtask::current()
            .kernel_stack_top()
            .expect("current task has no kernel stack")
            .as_usize();
        unsafe {
            uctx.enter_uspace(va!(kstack_top));
        }
    }

    pub fn exec(&self, path: &str, args: &[&str], envs: &[&str]) -> AxResult<()> {
        // Build the new image in an isolated address space first.
        // If loading fails, the current process image remains intact.
        let mut new_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        new_aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            true,
        )?;
        new_aspace.map_alloc(
            va!(USER_HEAP_BASE),
            USER_HEAP_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;

        let load_info = crate::mm::load_user_app(&mut new_aspace, path, args, envs)?;
        let new_pt_root = new_aspace.page_table_root();

        {
            let mut aspace = self.aspace.lock();
            *aspace = new_aspace;
        }

        axtask::set_current_page_table_root(new_pt_root);
        self.activate();
        let cloexec_raw_fds = self.fd_table.lock().close_cloexec_on_exec();
        for raw_fd in cloexec_raw_fds {
            let _ = ax_sys_close(raw_fd);
        }
        *self.heap_top.lock() = USER_HEAP_BASE + USER_HEAP_SIZE;
        *self.stack_top.lock() = load_info.user_sp;
        *self.entry.lock() = load_info.entry;
        Ok(())
    }

    pub fn close_all_files(&self) {
        let raw_fds = self.fd_table.lock().drain_all_raw_fds();
        for raw_fd in raw_fds {
            let _ = ax_sys_close(raw_fd);
        }
    }

    pub fn sync_fs_context(&self) {
        *axfs::FS_CONTEXT.lock() = self.fs_context.lock().clone();
    }

    pub fn save_fs_context(&self) {
        *self.fs_context.lock() = axfs::FS_CONTEXT.lock().clone();
    }

    pub fn clone_for_thread(&self) -> Self {
        Self {
            aspace: self.aspace.clone(),
            heap_top: self.heap_top.clone(),
            fs_context: self.fs_context.clone(),
            fd_table: self.fd_table.clone(),
            parent_pid: self.parent_pid.clone(),
            start_mono_ns: self.start_mono_ns,
            user_time_ns: self.user_time_ns.clone(),
            sys_time_ns: self.sys_time_ns.clone(),
            child_user_time_ns: self.child_user_time_ns.clone(),
            child_sys_time_ns: self.child_sys_time_ns.clone(),
            last_user_enter_ns: self.last_user_enter_ns.clone(),
            in_user_mode: self.in_user_mode.clone(),
            stack_top: Mutex::new(*self.stack_top.lock()),
            entry: Mutex::new(*self.entry.lock()),
            children: Mutex::new(Vec::new()),
        }
    }

    fn new_clone_process(
        &self,
        is_thread_clone: bool,
        share_fs: bool,
        share_files: bool,
    ) -> AxResult<Self> {
        let mut child_proc = self.clone_for_thread();
        if !is_thread_clone {
            child_proc.start_mono_ns = axhal::time::monotonic_time_nanos() as u64;
            child_proc.heap_top = Arc::new(Mutex::new(*self.heap_top.lock()));
            child_proc.parent_pid = Arc::new(Mutex::new(axtask::current().id().as_u64()));
            child_proc.user_time_ns = Arc::new(AtomicU64::new(0));
            child_proc.sys_time_ns = Arc::new(AtomicU64::new(0));
            child_proc.child_user_time_ns = Arc::new(AtomicU64::new(0));
            child_proc.child_sys_time_ns = Arc::new(AtomicU64::new(0));
            child_proc.last_user_enter_ns = Arc::new(AtomicU64::new(0));
            child_proc.in_user_mode = Arc::new(AtomicBool::new(false));
            child_proc.children = Mutex::new(Vec::new());
        }
        if !share_fs {
            child_proc.fs_context = Arc::new(Mutex::new(self.fs_context.lock().clone()));
        }
        if !share_files {
            child_proc.fd_table =
                Arc::new(Mutex::new(self.fd_table.lock().clone_for_fork()?));
        }
        Ok(child_proc)
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

    /// Implement fork with COW: parent and child initially share read-only user pages,
    /// and writable pages are copied on the first write page fault.
    pub fn spawn_fork_from_trap_frame(
        &self,
        tf: &TrapFrame,
        child_stack: Option<usize>,
        share_fs: bool,
        share_files: bool,
    ) -> AxResult<u64> {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = child_stack {
            child_uctx.set_sp(sp);
        }

        // 1. Create a new Address Space
        let mut new_aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;

        let mut parent_aspace = self.aspace.lock();
        // 2. Share only existing user mappings into child and mark writable pages as read-only.
        // Walking the entire lower user VA range (e.g. 0x1000..0x4000_0000) is too expensive.
        let mut mapped_user_ranges: Vec<(VirtAddr, VirtAddr, MappingFlags)> = Vec::new();
        parent_aspace.for_each_area(|start, end, flags| {
            if !flags.contains(MappingFlags::USER) {
                return;
            }
            let clipped_start = start.max(va!(USER_SPACE_BASE));
            let clipped_end = end.min(va!(USER_STACK_TOP));
            if clipped_start < clipped_end {
                mapped_user_ranges.push((clipped_start, clipped_end, flags));
            }
        });

        for (start, end, area_flags) in mapped_user_ranges {
            for vaddr in memory_addr::PageIter4K::new(start, end).unwrap() {
                if let Ok((paddr, flags, _page_size)) = parent_aspace.page_table().query(vaddr) {
                    let pte_user_flags = flags
                        & (MappingFlags::READ
                            | MappingFlags::WRITE
                            | MappingFlags::EXECUTE
                            | MappingFlags::USER);
                    let area_user_flags = area_flags
                        & (MappingFlags::READ
                            | MappingFlags::WRITE
                            | MappingFlags::EXECUTE
                            | MappingFlags::USER);
                    if !area_user_flags.contains(MappingFlags::USER) {
                        continue;
                    }

                    // Keep child VMA permissions from area metadata (the
                    // authoritative desired rights), not from transient PTE
                    // states that may already be read-only due to prior COW.
                    let mut child_pte_flags = pte_user_flags;
                    // Parent and child share this mapped frame initially.
                    // Track refs for all shared user pages (including RX RO
                    // pages), otherwise child exit may free frames still used
                    // by parent.
                    if paddr.as_usize() != 0 {
                        axmm::cow_inc_frame_ref(paddr);
                    }
                    if area_user_flags.contains(MappingFlags::WRITE) {
                        child_pte_flags.remove(MappingFlags::WRITE);
                        // Keep parent VMA permissions unchanged (still writable)
                        // so later write faults can be recognized as COW.
                        if pte_user_flags.contains(MappingFlags::WRITE) {
                            parent_aspace.protect_pte_only(
                                vaddr,
                                memory_addr::PAGE_SIZE_4K,
                                child_pte_flags,
                            )?;
                        }
                    }

                    // Keep area permissions (including WRITE for COW candidates) in child metadata,
                    // but install a read-only shared PTE for writable pages.
                    new_aspace.map_alloc(
                        vaddr,
                        memory_addr::PAGE_SIZE_4K,
                        area_user_flags,
                        false,
                    )?;
                    if paddr.as_usize() != 0 {
                        new_aspace.remap_page(vaddr, paddr, child_pte_flags)?;
                    }
                }
            }
        }

        // 3. Create the child Process wrapper
        let mut child_proc = self.new_clone_process(false, share_fs, share_files)?;
        child_proc.aspace = Arc::new(Mutex::new(new_aspace));

        let mut inner = TaskInner::new(
            move || {
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

        let new_pt_root = child_proc.aspace.lock().page_table_root();
        inner.ctx_mut().set_page_table_root(new_pt_root);
        inner.init_task_ext(child_proc);

        let task = axtask::spawn_task(inner);
        let child_tid = task.id().as_u64();

        if let Some(mut children) = self.children.try_lock() {
            children.push(task);
        } else {
            self.children.lock().push(task);
        }

        Ok(child_tid)
    }

    pub fn spawn_from_trap_frame(
        &self,
        tf: &TrapFrame,
        child_stack: Option<usize>,
        is_thread_clone: bool,
        share_fs: bool,
        share_files: bool,
    ) -> AxResult<u64> {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = child_stack {
            child_uctx.set_sp(sp);
        }

        let child_proc = self.new_clone_process(is_thread_clone, share_fs, share_files)?;
        let mut inner = TaskInner::new(
            move || {
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

        let pt_root = self.aspace.lock().page_table_root();
        inner.ctx_mut().set_page_table_root(pt_root);
        inner.init_task_ext(child_proc);

        let task = axtask::spawn_task(inner);
        let child_tid = task.id().as_u64();
        if let Some(mut children) = self.children.try_lock() {
            children.push(task);
        } else {
            self.children.lock().push(task);
        }
        Ok(child_tid)
    }
}
