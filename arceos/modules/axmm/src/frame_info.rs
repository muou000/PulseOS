use core::sync::atomic::{AtomicU16, Ordering};
use memory_addr::{PhysAddr, PAGE_SIZE_4K};

const MAX_FRAME_NUM: usize = axconfig::plat::PHYS_MEMORY_SIZE / PAGE_SIZE_4K;
pub const COW_FLAG_OWNED: u16 = 0x8000;
pub const COW_REF_MASK: u16 = 0x7FFF;

pub struct FrameRefTable {
    data: [AtomicU16; MAX_FRAME_NUM],
}

impl FrameRefTable {
    const fn new() -> Self {
        const INIT: AtomicU16 = AtomicU16::new(0);
        Self {
            data: [INIT; MAX_FRAME_NUM],
        }
    }

    fn index(&self, paddr: PhysAddr) -> usize {
        let paddr_val = paddr.as_usize();
        let base = axconfig::plat::PHYS_MEMORY_BASE;
        assert!(
            paddr_val >= base && paddr_val < base + axconfig::plat::PHYS_MEMORY_SIZE,
            "PhysAddr {:#x} out of range [{:#x}, {:#x})",
            paddr_val,
            base,
            base + axconfig::plat::PHYS_MEMORY_SIZE
        );
        (paddr_val - base) / PAGE_SIZE_4K
    }

    pub fn get_raw(&self, paddr: PhysAddr) -> u16 {
        self.data[self.index(paddr)].load(Ordering::Acquire)
    }

    pub fn set_raw(&self, paddr: PhysAddr, val: u16) {
        self.data[self.index(paddr)].store(val, Ordering::Release);
    }

    pub fn compare_exchange(&self, paddr: PhysAddr, old: u16, new: u16) -> Result<u16, u16> {
        self.data[self.index(paddr)]
            .compare_exchange(old, new, Ordering::AcqRel, Ordering::Acquire)
    }
}

pub static FRAME_INFO_TABLE: FrameRefTable = FrameRefTable::new();
