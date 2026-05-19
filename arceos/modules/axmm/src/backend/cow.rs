use alloc::boxed::Box;
use axhal::paging::{MappingFlags, PageTable};
use memory_addr::{VirtAddr, PAGE_SIZE_4K, MemoryAddr};
use axhal::mem::phys_to_virt;
use super::Backend;
use super::alloc::{alloc_frame, dealloc_frame};
use crate::frameinfo::frame_table;

#[derive(Clone)]
pub struct CowMapping {
    pub(crate) inner: Box<Backend>,
}

impl CowMapping {
    pub fn new(inner: Box<Backend>) -> Self {
        Self { inner }
    }

    pub(crate) fn handle_page_fault(
        &self,
        vaddr: VirtAddr,
        orig_flags: MappingFlags,
        pt: &mut PageTable,
    ) -> bool {
        let page = vaddr.align_down_4k();
        if let Ok((old_frame, old_flags, _)) = pt.query(page) {
            if old_frame.as_usize() != 0 {
                // Page is mapped. Check if it's a COW fault (write to read-only page).
                if orig_flags.contains(MappingFlags::WRITE) && !old_flags.contains(MappingFlags::WRITE) {
                    let ref_count = frame_table().get_ref(old_frame);
                    if ref_count == 1 {
                        // Only one reference, upgrade to WRITE.
                        let new_flags = old_flags | MappingFlags::WRITE;
                        return pt.remap(page, old_frame, new_flags)
                            .map(|(_, tlb)| {
                                tlb.flush();
                                self.sync_executable_if_needed(new_flags);
                            })
                            .is_ok();
                    } else {
                        // Multiple references, copy-on-write
                        let Some(new_frame) = alloc_frame(false) else {
                            return false;
                        };

                        let src = phys_to_virt(old_frame).as_ptr();
                        let dst = phys_to_virt(new_frame).as_mut_ptr();
                        unsafe {
                            core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE_4K);
                        }

                        // Map new frame with WRITE permission
                        let new_flags = old_flags | MappingFlags::WRITE;
                        if pt.remap(page, new_frame, new_flags)
                            .map(|(_, tlb)| {
                                tlb.flush();
                                self.sync_executable_if_needed(new_flags);
                            })
                            .is_ok()
                        {
                            dealloc_frame(old_frame);
                            return true;
                        } else {
                            dealloc_frame(new_frame);
                            return false;
                        }
                    }
                } else {
                    // Not a COW fault, maybe just a permission upgrade (e.g. READ -> READ|EXEC)
                    // or the page is already writable.
                    // Delegate to inner to be safe, although we could handle it here.
                    return self.inner.handle_page_fault(vaddr, orig_flags, pt);
                }
            }
        }

        // Page is not mapped or inner needs to handle it (e.g. demand paging).
        self.inner.handle_page_fault(vaddr, orig_flags, pt)
    }

    fn sync_executable_if_needed(&self, flags: MappingFlags) {
        if !flags.contains(MappingFlags::EXECUTE) {
            return;
        }
        #[cfg(target_arch = "riscv64")]
        unsafe {
            core::arch::asm!("fence.i", options(nostack, preserves_flags));
        }
        #[cfg(target_arch = "loongarch64")]
        unsafe {
            core::arch::asm!("dbar 0; ibar 0", options(nostack, preserves_flags));
        }
    }
}
