use alloc::boxed::Box;
use axhal::paging::MappingFlags;
use memory_addr::{VirtAddr, PAGE_SIZE_4K, MemoryAddr};
use axhal::mem::phys_to_virt;
use super::Backend;
use super::alloc::{alloc_frame, dealloc_frame};
use axalloc::frame_table;

#[derive(Clone)]
pub struct CowMapping {
    pub(crate) inner: Box<Backend>,
}

impl CowMapping {
    pub fn new(inner: Box<Backend>) -> Self {
        Self { inner }
    }

    pub fn inner(&self) -> &Backend {
        &self.inner
    }

    pub(crate) fn handle_page_fault(
        &self,
        vaddr: VirtAddr,
        area_end: VirtAddr,
        orig_flags: MappingFlags,
        pt: &crate::PageTableLockManager,
        access_flags: MappingFlags,
    ) -> bool {
        let page = vaddr.align_down_4k();
        let query_res = pt.lock_for_addr(page).query(page).ok().map(|(frame, flags, _)| (frame, flags));
        if let Some((old_frame, old_flags)) = query_res {
            if old_frame.as_usize() != 0 {
                if orig_flags.contains(MappingFlags::WRITE)
                    && access_flags.contains(MappingFlags::WRITE)
                    && !old_flags.contains(MappingFlags::WRITE)
                {
                    let ref_count = if frame_table().contains(old_frame) {
                        frame_table().get_ref(old_frame)
                    } else {
                        2 // Treat unknown frames as shared (ref_count > 1) to reject exclusive upgrade
                    };
                    if ref_count == 1 {
                        // Only one reference, upgrade to WRITE.
                        let mut pt_guard = pt.lock_for_addr(page);
                        if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page) {
                            if curr_frame == old_frame && !curr_flags.contains(MappingFlags::WRITE) {
                                let new_flags = curr_flags | MappingFlags::WRITE;
                                return pt_guard.remap(page, old_frame, new_flags)
                                    .map(|(_, tlb)| {
                                        tlb.flush();
                                        self.sync_executable_if_needed(new_flags);
                                    })
                                    .is_ok();
                            }
                        }
                        return true;
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
                        let mut pt_guard = pt.lock_for_addr(page);
                        // Re-verify under lock
                        let (ok, already_handled) = if let Ok((curr_frame, curr_flags, _)) = pt_guard.query(page) {
                            if curr_frame == old_frame && !curr_flags.contains(MappingFlags::WRITE) {
                                let new_flags = curr_flags | MappingFlags::WRITE;
                                let success = pt_guard.remap(page, new_frame, new_flags)
                                    .map(|(_, tlb)| {
                                        tlb.flush();
                                        self.sync_executable_if_needed(new_flags);
                                    })
                                    .is_ok();
                                (success, false)
                            } else if curr_flags.contains(MappingFlags::WRITE) {
                                (false, true)
                            } else {
                                (false, false)
                            }
                        } else {
                            (false, false)
                        };

                        if ok {
                            drop(pt_guard); // Release lock before deallocating
                            dealloc_frame(old_frame);
                            return true;
                        } else {
                            dealloc_frame(new_frame);
                            return already_handled;
                        }
                    }
                } else {
                    // Not a COW fault, maybe just a permission upgrade (e.g. READ -> READ|EXEC)
                    // or the page is already writable.
                    // Delegate to inner to be safe, although we could handle it here.
                    return self.inner.handle_page_fault(vaddr, area_end, orig_flags, pt, access_flags);
                }
            }
        }

        // Page is not mapped or inner needs to handle it (e.g. demand paging).
        self.inner.handle_page_fault(vaddr, area_end, orig_flags, pt, access_flags)
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
