//! 任务/进程管理模块

use alloc::sync::Arc;
use axerrno::AxResult;
use axhal::paging::MappingFlags;
use memory_addr::{VirtAddr, va};
use spin::Mutex;

use axmm::AddrSpace;

use crate::config::*;
use crate::fs::FdTable;

/// 进程控制块 (Process Control Block)
pub struct Process {
    /// 进程地址空间
    pub aspace: Arc<Mutex<AddrSpace>>,

    /// 堆顶指针 (brk)
    pub heap_top: Mutex<usize>,

    /// 匿名 mmap 分配游标（向上增长）
    pub mmap_base: Mutex<usize>,

    /// 当前用户栈指针
    pub stack_top: Mutex<usize>,

    /// 程序入口地址
    pub entry: Mutex<usize>,

    /// 文件描述符表
    pub fd_table: Mutex<FdTable>,
}

impl Process {
    /// 创建新的用户进程
    pub fn new_user() -> AxResult<Self> {
        // 1. 创建用户地址空间 (0x1000 ~ 0x3f_ffff_f000)
        let mut aspace = axmm::new_user_aspace(va!(USER_SPACE_BASE), USER_SPACE_SIZE)?;

        // 2. 分配用户栈（预分配，便于内核写入初始用户栈帧）
        let stack_bottom = USER_STACK_TOP - USER_STACK_SIZE;
        aspace.map_alloc(
            va!(stack_bottom),
            USER_STACK_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            true, // 初始化用户栈时会直接写入初始栈帧，需预分配页
        )?;

        // 3. 分配初始堆区域 (同样 lazy)
        aspace.map_alloc(
            va!(USER_HEAP_BASE),
            USER_HEAP_SIZE,
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER,
            false,
        )?;

        Ok(Self {
            aspace: Arc::new(Mutex::new(aspace)),
            heap_top: Mutex::new(USER_HEAP_BASE + USER_HEAP_SIZE),
            mmap_base: Mutex::new(MMAP_BASE),
            stack_top: Mutex::new(USER_STACK_TOP),
            entry: Mutex::new(0),
            fd_table: Mutex::new(FdTable::new()),
        })
    }

    /// 处理页错误 (Page Fault)
    pub fn handle_page_fault(&self, vaddr: VirtAddr, flags: axhal::trap::PageFaultFlags) -> bool {
        let mut aspace = self.aspace.lock();
        aspace.handle_page_fault(vaddr, flags)
    }

    /// 切换到该进程的地址空间
    pub fn activate(&self) {
        let aspace = self.aspace.lock();
        let _pt_root = aspace.page_table_root();

        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!(
                "csrw satp, {0}",
                "sfence.vma",
                in(reg) (8usize << 60) | (_pt_root.as_usize() >> 12),
            );
        }

        #[cfg(target_arch = "loongarch64")]
        unsafe {
            core::arch::asm!(
                "csrwr {0}, 0x19", // pgdl
                "csrwr {0}, 0x1a", // pgdh
                in(reg) _pt_root.as_usize(),
            );
        }
    }

    /// 加载 ELF 程序到进程地址空间
    pub fn load_elf(&self, path: &str, args: &[&str]) -> AxResult<()> {
        let mut aspace = self.aspace.lock();
        let load_info = crate::mm::load_user_app(&mut aspace, path, args)?;
        *self.entry.lock() = load_info.entry;
        *self.stack_top.lock() = load_info.user_sp;
        axlog::info!(
            "Loaded ELF from {} with entry={:#x}, user_sp={:#x}",
            path,
            load_info.entry,
            load_info.user_sp
        );
        Ok(())
    }

    /// 获取程序入口地址
    pub fn entry(&self) -> usize {
        *self.entry.lock()
    }

    pub fn enter_user_mode(&self) -> ! {
        let entry = self.entry();
        let stack_top = *self.stack_top.lock();

        axlog::info!(
            "Entering user mode: entry={:#x}, stack={:#x}",
            entry,
            stack_top
        );

        let uctx = axhal::context::UspaceContext::new(entry, va!(stack_top), 0);

        let kstack_top: usize;
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("mv {}, sp", out(reg) kstack_top);
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            core::arch::asm!("move {}, $sp", out(reg) kstack_top);
        }

        unsafe {
            uctx.enter_uspace(va!(kstack_top));
        }
    }
}

static FALLBACK_CURRENT_PROCESS: Mutex<Option<Arc<Process>>> = Mutex::new(None);

pub fn current_process() -> Option<Arc<Process>> {
    FALLBACK_CURRENT_PROCESS.lock().clone()
}

pub fn set_current_process(proc: Arc<Process>) {
    *FALLBACK_CURRENT_PROCESS.lock() = Some(proc);
}
