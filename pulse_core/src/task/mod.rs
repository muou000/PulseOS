use crate::config::*;
use alloc::sync::Arc;
use axerrno::AxResult;
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
    pub fn load_elf(&self, path: &str, args: &[&str]) -> AxResult<()> {
        let mut aspace = self.aspace.lock();
        let load_info = crate::mm::load_user_app(&mut aspace, path, args)?;
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

    pub fn exec(&self, path: &str, args: &[&str]) -> AxResult<()> {
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

        let load_info = crate::mm::load_user_app(&mut new_aspace, path, args)?;
        *self.aspace.lock() = new_aspace;
        self.activate();
        *self.heap_top.lock() = USER_HEAP_BASE + USER_HEAP_SIZE;
        *self.stack_top.lock() = load_info.user_sp;
        *self.entry.lock() = load_info.entry;
        Ok(())
    }
}
