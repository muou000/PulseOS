use crate::config::*;
use alloc::sync::Arc;
use alloc::vec::Vec;
use axconfig::TASK_STACK_SIZE;
use axerrno::AxResult;
use axhal::context::{TrapFrame, UspaceContext};
use axhal::paging::MappingFlags;
use axmm::AddrSpace;
use axtask::{TaskExtRef, TaskInner, def_task_ext};
use log::info;
use memory_addr::{VirtAddr, va};
use spin::Mutex;
pub struct Process {
    pub aspace: Arc<Mutex<AddrSpace>>,
    pub heap_top: Arc<Mutex<usize>>,
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
        Ok(Self {
            aspace: Arc::new(Mutex::new(aspace)),
            heap_top: Arc::new(Mutex::new(USER_HEAP_BASE + USER_HEAP_SIZE)),
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
        *self.heap_top.lock() = USER_HEAP_BASE + USER_HEAP_SIZE;
        *self.stack_top.lock() = load_info.user_sp;
        *self.entry.lock() = load_info.entry;
        Ok(())
    }

    pub fn clone_for_thread(&self) -> Self {
        Self {
            aspace: self.aspace.clone(),
            heap_top: self.heap_top.clone(),
            stack_top: Mutex::new(*self.stack_top.lock()),
            entry: Mutex::new(*self.entry.lock()),
            children: Mutex::new(Vec::new()),
        }
    }

    /// Implement fork with COW: parent and child initially share read-only user pages,
    /// and writable pages are copied on the first write page fault.
    pub fn spawn_fork_from_trap_frame(
        &self,
        tf: &TrapFrame,
        child_stack: Option<usize>,
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
        let mut mapped_user_ranges: Vec<(VirtAddr, VirtAddr)> = Vec::new();
        parent_aspace.for_each_area(|start, end, flags| {
            if !flags.contains(MappingFlags::USER) {
                return;
            }
            let clipped_start = start.max(va!(USER_SPACE_BASE));
            let clipped_end = end.min(va!(USER_STACK_TOP));
            if clipped_start < clipped_end {
                mapped_user_ranges.push((clipped_start, clipped_end));
            }
        });

        for (start, end) in mapped_user_ranges {
            for vaddr in memory_addr::PageIter4K::new(start, end).unwrap() {
                if let Ok((paddr, flags, _page_size)) = parent_aspace.page_table().query(vaddr) {
                    let user_flags = flags
                        & (MappingFlags::READ
                            | MappingFlags::WRITE
                            | MappingFlags::EXECUTE
                            | MappingFlags::USER);
                    if !user_flags.contains(MappingFlags::USER) {
                        continue;
                    }

                    let mut child_pte_flags = user_flags;
                    if user_flags.contains(MappingFlags::WRITE) {
                        child_pte_flags.remove(MappingFlags::WRITE);
                        parent_aspace.protect(vaddr, memory_addr::PAGE_SIZE_4K, child_pte_flags)?;
                    }
                    axmm::cow_inc_frame_ref(paddr);

                    // Keep area permissions (including WRITE for COW candidates) in child metadata,
                    // but install a read-only shared PTE for writable pages.
                    new_aspace.map_alloc(vaddr, memory_addr::PAGE_SIZE_4K, user_flags, false)?;
                    new_aspace.remap_page(vaddr, paddr, child_pte_flags)?;
                }
            }
        }

        // 3. Create the child Process wrapper
        let child_proc = Self {
            aspace: Arc::new(Mutex::new(new_aspace)),
            heap_top: Arc::new(Mutex::new(*self.heap_top.lock())),
            stack_top: Mutex::new(*self.stack_top.lock()),
            entry: Mutex::new(*self.entry.lock()),
            children: Mutex::new(Vec::new()),
        };

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

    pub fn spawn_from_trap_frame(&self, tf: &TrapFrame, child_stack: Option<usize>) -> u64 {
        let mut child_uctx = UspaceContext::from(tf);
        child_uctx.set_retval(0);
        if let Some(sp) = child_stack {
            child_uctx.set_sp(sp);
        }

        let child_proc = self.clone_for_thread();
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
        child_tid
    }
}
