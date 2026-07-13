#[inline]
fn iocsr_read_d(reg: usize) -> u64 {
    let val: u64;
    unsafe {
        core::arch::asm!("iocsrrd.d {},{}", out(reg) val, in(reg) reg);
    }
    val
}

#[inline]
fn iocsr_write_d(reg: usize, value: u64) {
    unsafe {
        core::arch::asm!("iocsrwr.d {},{}", in(reg) value, in(reg) reg);
    }
}

#[inline]
fn iocsr_read_w(reg: usize) -> u32 {
    let val: u32;
    unsafe {
        core::arch::asm!("iocsrrd.w {},{}", out(reg) val, in(reg) reg);
    }
    val
}

#[inline]
fn iocsr_write_w(reg: usize, value: u32) {
    unsafe {
        core::arch::asm!("iocsrwr.w {},{}", in(reg) value, in(reg) reg);
    }
}

const LOONGARCH_IOCSR_MISC_FUNC: usize = 0x0420;
const EIOINTC_BASE: usize = 0x1400;
const EIOINTC_NODEMAP: usize = 0x14a0;
const EIOINTC_IPMAP: usize = 0x14c0;
const EIOINTC_ENABLE: usize = 0x1600;
const EIOINTC_BOUNCE: usize = 0x1680;
const EIOINTC_ISR: usize = 0x1800;
const EIOINTC_ROUTE: usize = 0x1c00;

#[inline(never)]
fn route_interrupt(irq: usize, cpu: u8) {
    let reg = EIOINTC_ROUTE + (irq & !3);
    let shift = (irq & 3) * 8;
    let old = iocsr_read_w(reg);
    let new = (old & !(0xff << shift)) | ((cpu as u32) << shift);
    iocsr_write_w(reg, new);
}

pub fn init() {
    // Enable Extended I/O Interrupt (EXT_INT_en, bit 48 of 0x0420)
    let misc = iocsr_read_d(LOONGARCH_IOCSR_MISC_FUNC);
    iocsr_write_d(LOONGARCH_IOCSR_MISC_FUNC, misc | (1u64 << 48));

    // 1. Route EIOINTC inputs 0..256 to CPU0.
    for i in 0..256 {
        route_interrupt(i, 0); // 0 means CPU0
    }

    // 2. Map all 256 EIOINTC interrupts to CPU HWI0 (IP2 / pin index 0).
    iocsr_write_w(EIOINTC_IPMAP, 0);
    iocsr_write_w(EIOINTC_IPMAP + 4, 0);

    // 3. Enable EIOINTC for IRQ 0..255 and allow bounce delivery.
    for i in 0..8 {
        iocsr_write_w(EIOINTC_ENABLE + i * 4, 0xffff_ffff);
        iocsr_write_w(EIOINTC_BOUNCE + i * 4, 0xffff_ffff);
    }
}

pub fn get_pending() -> u64 {
    let low = iocsr_read_w(EIOINTC_ISR) as u64;
    let high = iocsr_read_w(EIOINTC_ISR + 4) as u64;
    low | (high << 32)
}

pub fn get_pending_group(group: usize) -> u64 {
    let reg = EIOINTC_ISR + group * 8;
    let low = iocsr_read_w(reg) as u64;
    let high = iocsr_read_w(reg + 4) as u64;
    low | (high << 32)
}

pub fn clear_pending(irq_num: usize) {
    if irq_num >= 256 {
        return;
    }
    let group = irq_num / 64;
    let bit = irq_num % 64;
    iocsr_write_d(EIOINTC_ISR + group * 8, 1u64 << bit);
}

pub fn set_enable(irq_num: usize, enabled: bool) {
    if irq_num >= 256 {
        return;
    }
    let group = irq_num / 64;
    let bit = irq_num % 64;
    let reg = EIOINTC_ENABLE + group * 8;
    let old = iocsr_read_d(reg);
    let new = if enabled {
        old | (1u64 << bit)
    } else {
        old & !(1u64 << bit)
    };
    iocsr_write_d(reg, new);
}

