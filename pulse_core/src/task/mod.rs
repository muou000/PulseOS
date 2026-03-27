use alloc::sync::Arc;
use spin::Mutex;
use axtask::{def_task_ext, TaskExtRef, TaskInner};
use axmm::AddrSpace;
use axerrno::AxResult;
use axhal::paging::MappingFlags;
use memory_addr::{VirtAddr, va};
use crate::config::*;
pub struct Process {
    pub aspace: Arc<Mutex<AddrSpace>>,
    pub heap_top: Arc<Mutex<usize>>,
    pub mmap_base: Arc<Mutex<usize>>,
    pub stack_top: Mutex<usize>,
    pub entry: Mutex<usize>,
}
def_task_ext!(Process);
impl Process {
    pub fn new_user() -> AxResult<Self> {
        let mut aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        aspace.map_alloc(va!(stack_bottom), USER_STACK_SIZE, MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER, true)?;
        aspace.map_alloc(va!(USER_HEAP_BASE), USER_HEAP_SIZE, MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER, false)?;
        Ok(Self {
            aspace: Arc::new(Mutex::new(aspace)),
            heap_top: Arc::new(Mutex::new(USER_HEAP_BASE + USER_HEAP_SIZE)),
            mmap_base: Arc::new(Mutex::new(MMAP_BASE)),
            stack_top: Mutex::new(USER_STACK_TOP),
            entry: Mutex::new(0),
        })
    }
    pub fn handle_page_fault(&self, vaddr: VirtAddr, flags: axhal::trap::PageFaultFlags) -> bool {
        self.aspace.lock().handle_page_fault(vaddr, flags)
    }
    pub fn activate(&self) {
        let aspace = self.aspace.lock();
        let _pt_root = aspace.page_table_root();
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("csrw satp, {0}", "sfence.vma", in(reg) (8usize << 60) | (_pt_root.as_usize() >> 12)); }
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
        let kstack_top: usize;
        #[cfg(target_arch = "riscv64")]
        unsafe { core::arch::asm!("mv {}, sp", out(reg) kstack_top); }
        unsafe { uctx.enter_uspace(va!(kstack_top)); }
    }
}
