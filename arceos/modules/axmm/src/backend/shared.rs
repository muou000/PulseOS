use crate::Backend;
use alloc::sync::Arc;
use axalloc::global_allocator;
use axhal::mem::virt_to_phys;
use axhal::paging::{MappingFlags, PageSize, PageTable};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};

pub struct SharedFrame {
    pub vaddr: usize,
    pub page_count: usize,
}

impl Drop for SharedFrame {
    fn drop(&mut self) {
        debug!(
            "[Backend::Shared] deallocating {} pages at pa {:#x}",
            self.page_count,
            virt_to_phys(VirtAddr::from(self.vaddr))
        );
        global_allocator().dealloc_pages(self.vaddr, self.page_count);
    }
}

impl Backend {
    pub fn new_shared(size: usize, zeroed: bool, align: PageSize) -> Option<Self> {
        let page_count = (size + PAGE_SIZE_4K - 1) / PAGE_SIZE_4K;
        let vaddr = global_allocator().alloc_pages(page_count, PAGE_SIZE_4K).ok()?;
        debug!(
            "[Backend::Shared] allocated {} pages at pa {:#x}",
            page_count,
            virt_to_phys(VirtAddr::from(vaddr))
        );
        if zeroed {
            unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, page_count * PAGE_SIZE_4K) };
        }
        let shared_frame = SharedFrame { vaddr, page_count };
        Some(Self::Shared {
            shared_frame: Arc::new(shared_frame),
            align,
        })
    }

    pub fn map_shared(
        start_va: VirtAddr,
        size: usize,
        flags: MappingFlags,
        pt: &mut PageTable,
        frame_va: VirtAddr,
    ) -> bool {
        let frame_pa = virt_to_phys(frame_va);
        let va_to_pa = |va: VirtAddr| frame_pa.wrapping_add(va - start_va);
        debug!(
            "map_shared: [{:#x}, {:#x}) -> [{:#x}, {:#x}) {:?}",
            start_va,
            start_va + size,
            frame_pa,
            frame_pa + size,
            flags
        );
        pt.map_region(start_va, va_to_pa, size, flags, true, false)
            .map(|tlb| tlb.ignore()) 
            .is_ok()
    }

    pub(crate) fn unmap_shared(start_va: VirtAddr, size: usize, pt: &mut PageTable) -> bool {
        debug!("unmap_shared: [{:#x}, {:#x})", start_va, start_va + size);
        pt.unmap_region(start_va, size, true)
            .map(|tlb| tlb.ignore())
            .is_ok()
    }
}
