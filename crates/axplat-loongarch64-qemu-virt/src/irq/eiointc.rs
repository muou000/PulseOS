#[inline]
fn iocsr_read_d(reg: usize) -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("iocsrrd.d {},{}", out(reg) val, in(reg) reg);
    }
    val
}

#[inline]
fn iocsr_write_b(reg: usize, value: u8) {
    unsafe {
        core::arch::asm!("iocsrwr.b {},{}", in(reg) value, in(reg) reg);
    }
}

#[inline]
fn iocsr_write_d(reg: usize, value: u64) {
    unsafe {
        core::arch::asm!("iocsrwr.d {},{}", in(reg) value, in(reg) reg);
    }
}
const EIOINTC_BASE: usize = 0x1400;
const EIOINTC_NODEMAP: usize = 0x14a0;
const EIOINTC_IPMAP: usize = 0x14c0;
const EIOINTC_ENABLE: usize = 0x1600;
const EIOINTC_ISR: usize = 0x1800;
const EIOINTC_ROUTE: usize = 0x1c00;

#[inline(never)]
fn route_interrupt(irq: usize, cpu: u8) {
    iocsr_write_b(EIOINTC_ROUTE + irq, cpu);
}

pub fn init() {
    // 1. Route EIOINTC inputs 0..256 to CPU0
    for i in 0..256 {
        route_interrupt(i, 0); // 0 means CPU0
    }

    // 2. Map EIOINTC interrupts to CPU HWI lines
    // We want IRQs 0..255 to go to HWI0 (IP2).
    // IPMAP: each group of 32 interrupts uses 4 bits.
    // So for 256 interrupts (8 groups), we set the low 32 bits to 0x2222_2222.
    let mut ipmap0 = iocsr_read_d(EIOINTC_IPMAP);
    ipmap0 &= !0xffff_ffff;
    ipmap0 |= 0x2222_2222; // Map IRQ 0..255 to IP2
    iocsr_write_d(EIOINTC_IPMAP, ipmap0);

    // 3. Enable EIOINTC for IRQ 0..255
    iocsr_write_d(EIOINTC_ENABLE, 0xffff_ffff_ffff_ffff);
    iocsr_write_d(EIOINTC_ENABLE + 8, 0xffff_ffff_ffff_ffff);
    iocsr_write_d(EIOINTC_ENABLE + 16, 0xffff_ffff_ffff_ffff);
    iocsr_write_d(EIOINTC_ENABLE + 24, 0xffff_ffff_ffff_ffff);
}

pub fn get_pending() -> u64 {
    iocsr_read_d(EIOINTC_ISR)
}

pub fn get_pending_group(group: usize) -> u64 {
    iocsr_read_d(EIOINTC_ISR + group * 8)
}

pub fn clear_pending(irq_num: usize) {
    let group = irq_num / 64;
    let bit = irq_num % 64;
    iocsr_write_d(EIOINTC_ISR + group * 8, 1u64 << bit);
}
