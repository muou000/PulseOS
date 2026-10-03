use axerrno::{AxError, AxResult};
use axhal::{mem::{flush_dcache_range, phys_to_virt}, paging::MappingFlags};
use memory_addr::{PhysAddr, VirtAddr, PAGE_SIZE_4K};

use crate::{backend::{alloc_frame, dealloc_frame}, lifecycle::MappingGeneration};

pub struct CowPageLoad {
    pub(crate) page: VirtAddr,
    pub(crate) flags: MappingFlags,
    pub(crate) generation: MappingGeneration,
    pub(crate) original: PhysAddr,
}

impl core::fmt::Debug for CowPageLoad {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CowPageLoad").field("page", &self.page).finish()
    }
}

impl Drop for CowPageLoad {
    fn drop(&mut self) {
        dealloc_frame(self.original);
    }
}

pub struct CowPagePrepared {
    pub(crate) source: CowPageLoad,
    pub(crate) copied: Option<PhysAddr>,
    pub(crate) reclaims: Option<crate::backend::DeferredReclaims>,
}

impl CowPageLoad {
    pub fn prepare(self) -> AxResult<CowPagePrepared> {
        let copied = alloc_frame(false).ok_or(AxError::NoMemory)?;
        flush_dcache_range(self.original, PAGE_SIZE_4K);
        unsafe {
            core::ptr::copy_nonoverlapping(
                phys_to_virt(self.original).as_ptr(),
                phys_to_virt(copied).as_mut_ptr(),
                PAGE_SIZE_4K,
            );
        }
        flush_dcache_range(copied, PAGE_SIZE_4K);
        Ok(CowPagePrepared { source: self, copied: Some(copied), reclaims: Some(crate::backend::DeferredReclaims::with_capacity(1)) })
    }
}

impl Drop for CowPagePrepared {
    fn drop(&mut self) {
        if let Some(frame) = self.copied.take() {
            dealloc_frame(frame);
        }
    }
}
