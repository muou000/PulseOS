use core::ptr::{read_volatile, write_volatile};
use axplat::mem::PhysAddr;

const PCH_PIC_INT_EDGE: usize = 0x000;
const PCH_PIC_INT_POL: usize = 0x080;
const PCH_PIC_INT_MASK: usize = 0x100;
const PCH_PIC_HTE: usize = 0x180;
const PCH_PIC_INT_EN: usize = 0x200;
const PCH_PIC_INT_CLR: usize = 0x280;
const PCH_PIC_INT_STATUS: usize = 0x300;
const PCH_PIC_INT_ROUTE: usize = 0x380;

pub struct PchPic {
    base_vaddr: usize,
}

impl PchPic {
    pub const fn new(base_vaddr: usize) -> Self {
        Self { base_vaddr }
    }

    unsafe fn write_reg64(&self, offset: usize, val: u64) {
        write_volatile((self.base_vaddr + offset) as *mut u64, val);
    }

    unsafe fn read_reg64(&self, offset: usize) -> u64 {
        read_volatile((self.base_vaddr + offset) as *const u64)
    }

    unsafe fn write_reg8(&self, offset: usize, val: u8) {
        write_volatile((self.base_vaddr + offset) as *mut u8, val);
    }

    pub fn init(&self) {
        unsafe {
            // Mask all interrupts
            self.write_reg64(PCH_PIC_INT_MASK, 0xffff_ffff_ffff_ffff);
            // Set all to level-triggered (0 for level, 1 for edge)
            self.write_reg64(PCH_PIC_INT_EDGE, 0);
            // Set all to high-level/rising-edge active (0 for high, 1 for low)
            self.write_reg64(PCH_PIC_INT_POL, 0);
            // Disable all High Trigger Enable
            self.write_reg64(PCH_PIC_HTE, 0);
            
            // Route interrupts 0..64 to outputs 0..64 (which go to EIOINTC)
            for i in 0..64 {
                self.write_reg8(PCH_PIC_INT_ROUTE + i, i as u8);
            }
            
            // Clear all pending interrupts
            self.write_reg64(PCH_PIC_INT_CLR, 0xffff_ffff_ffff_ffff);
            // Enable all interrupts in the controller (still masked by INT_MASK)
            self.write_reg64(PCH_PIC_INT_EN, 0xffff_ffff_ffff_ffff);
        }
    }

    pub fn set_enable(&self, irq: usize, enabled: bool) {
        if irq >= 64 { return; }
        unsafe {
            let mask = self.read_reg64(PCH_PIC_INT_MASK);
            if enabled {
                self.write_reg64(PCH_PIC_INT_MASK, mask & !(1 << irq));
            } else {
                self.write_reg64(PCH_PIC_INT_MASK, mask | (1 << irq));
            }
        }
    }

    pub fn clear_irq(&self, irq: usize) {
        if irq >= 64 { return; }
        unsafe {
            self.write_reg64(PCH_PIC_INT_CLR, 1 << irq);
        }
    }

    pub fn pending_irqs(&self) -> u64 {
        unsafe { self.read_reg64(PCH_PIC_INT_STATUS) }
    }
}

pub static PCH_PIC: lazyinit::LazyInit<PchPic> = lazyinit::LazyInit::new();

pub fn init(base_paddr: PhysAddr) {
    let base_vaddr = crate::mem::phys_to_virt(base_paddr).as_usize();
    let pic = PchPic::new(base_vaddr);
    pic.init();
    PCH_PIC.init_once(pic);
}
