use alloc::boxed::Box;
use core::sync::atomic::{AtomicU32, Ordering, fence};

use lazyinit::LazyInit;
use memory_addr::PhysAddr;

const FRAME_SHIFT: usize = 12;

static FRAME_TABLE: LazyInit<FrameTable> = LazyInit::new();

pub struct FrameInfo {
    ref_count: AtomicU32,
}

impl Default for FrameInfo {
    fn default() -> Self {
        Self {
            ref_count: AtomicU32::new(0),
        }
    }
}

pub struct FrameTable {
    base_paddr: PhysAddr,
    data: Box<[FrameInfo]>,
}

impl FrameTable {
    pub fn new(base_paddr: PhysAddr, total_memory_size: usize) -> Self {
        let num_frames = total_memory_size >> FRAME_SHIFT;
        let mut data = Box::new_uninit_slice(num_frames);
        for i in 0..num_frames {
            data[i].write(FrameInfo::default());
        }
        let data = unsafe { data.assume_init() };
        Self { base_paddr, data }
    }

    fn info(&self, paddr: PhysAddr) -> &FrameInfo {
        let index = (paddr.as_usize() - self.base_paddr.as_usize()) >> FRAME_SHIFT;
        if index >= self.data.len() {
            panic!(
                "FrameTable: physical address {:#x} out of range (base={:#x}, size={:#x})",
                paddr,
                self.base_paddr,
                self.data.len() << FRAME_SHIFT
            );
        }
        &self.data[index]
    }

    pub fn inc_ref(&self, paddr: PhysAddr) {
        // The caller already owns a live reference. Creating another owner
        // does not publish frame contents, so no cross-location ordering is
        // required here.
        self.info(paddr).ref_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_ref(&self, paddr: PhysAddr) -> usize {
        let old_ref = self.info(paddr).ref_count.fetch_sub(1, Ordering::Release);
        if old_ref == 0 {
            panic!(
                "FrameTable: dec_ref on frame with 0 references at {:#x}",
                paddr
            );
        }
        let remaining = old_ref - 1;
        if remaining == 0 {
            // Pair with releases from all previous owners before the caller
            // returns the frame to the allocator for reuse.
            fence(Ordering::Acquire);
        }
        remaining as usize
    }

    pub fn mark_used(&self, paddr: PhysAddr) {
        let info = self.info(paddr);
        // First-owner establishment is serialized by the page allocator or
        // the page-cache lock. Use a CAS so it cannot overwrite a concurrent
        // reference increment if that invariant is violated.
        let _ = info
            .ref_count
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed);
    }

    pub fn get_ref(&self, paddr: PhysAddr) -> usize {
        self.info(paddr).ref_count.load(Ordering::Relaxed) as usize
    }

    pub fn try_get_ref(&self, paddr: PhysAddr) -> Option<usize> {
        let offset = paddr.as_usize().checked_sub(self.base_paddr.as_usize())?;
        let info = self.data.get(offset >> FRAME_SHIFT)?;
        Some(info.ref_count.load(Ordering::Relaxed) as usize)
    }

    pub fn contains(&self, paddr: PhysAddr) -> bool {
        let paddr = paddr.as_usize();
        paddr >= self.base_paddr.as_usize()
            && paddr < self.base_paddr.as_usize() + (self.data.len() << FRAME_SHIFT)
    }
}

pub fn init_frame_table(base_paddr: PhysAddr, total_memory_size: usize) {
    FRAME_TABLE.init_once(FrameTable::new(base_paddr, total_memory_size));
}

pub fn frame_table() -> &'static FrameTable {
    &FRAME_TABLE
}
