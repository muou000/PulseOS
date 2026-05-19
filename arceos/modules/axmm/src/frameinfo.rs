use core::sync::atomic::{AtomicUsize, Ordering};
use alloc::boxed::Box;
use lazyinit::LazyInit;
use memory_addr::PhysAddr;

const FRAME_SHIFT: usize = 12;

static FRAME_TABLE: LazyInit<FrameTable> = LazyInit::new();

pub struct FrameInfo {
    ref_count: AtomicUsize,
}

impl Default for FrameInfo {
    fn default() -> Self {
        Self {
            ref_count: AtomicUsize::new(0),
        }
    }
}

pub struct FrameTable {
    base_paddr: PhysAddr,
    data: Box<[FrameInfo]>,
    total_refs: AtomicUsize,
}

impl FrameTable {
    pub fn new(base_paddr: PhysAddr, total_memory_size: usize) -> Self {
        let num_frames = total_memory_size >> FRAME_SHIFT;
        let mut data = Box::new_uninit_slice(num_frames);
        for i in 0..num_frames {
            data[i].write(FrameInfo::default());
        }
        let data = unsafe { data.assume_init() };
        Self { base_paddr, data, total_refs: AtomicUsize::new(0) }
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
        self.info(paddr).ref_count.fetch_add(1, Ordering::SeqCst);
        self.total_refs.fetch_add(1, Ordering::SeqCst);
    }

    pub fn dec_ref(&self, paddr: PhysAddr) -> usize {
        let old_ref = self.info(paddr).ref_count.fetch_sub(1, Ordering::SeqCst);
        if old_ref == 0 {
            panic!("FrameTable: dec_ref on frame with 0 references at {:#x}", paddr);
        }
        self.total_refs.fetch_sub(1, Ordering::SeqCst);
        old_ref - 1
    }

    pub fn mark_used(&self, paddr: PhysAddr) {
        let info = self.info(paddr);
        if info.ref_count.load(Ordering::SeqCst) == 0 {
            info.ref_count.store(1, Ordering::SeqCst);
            self.total_refs.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub fn get_ref(&self, paddr: PhysAddr) -> usize {
        self.info(paddr).ref_count.load(Ordering::SeqCst)
    }

    pub fn total_refs(&self) -> usize {
        self.total_refs.load(Ordering::SeqCst)
    }

    pub fn contains(&self, paddr: PhysAddr) -> bool {
        let paddr = paddr.as_usize();
        paddr >= self.base_paddr.as_usize() && paddr < self.base_paddr.as_usize() + (self.data.len() << FRAME_SHIFT)
    }
}

pub fn init_frame_table(base_paddr: PhysAddr, total_memory_size: usize) {
    FRAME_TABLE.init_once(FrameTable::new(base_paddr, total_memory_size));
}

pub fn frame_table() -> &'static FrameTable {
    &FRAME_TABLE
}
