use kspin::SpinNoIrq;
use loongArch64::iocsr::*;

use super::irq_common::{
    EIOINTC_CPU0_ROUTE_WORD, EIOINTC_IPMAP_WORD, EIOINTC_VECTOR_COUNT, eiointc_nodemap_word,
    eiointc_reg_bit, update_enable_mask,
};

static ENABLE_LOCK: SpinNoIrq<()> = SpinNoIrq::new(());

const LOONGARCH_IOCSR_MISC_FUNC: usize = 0x0420;
const EIOINTC_NODEMAP: usize = 0x14a0;
const EIOINTC_IPMAP: usize = 0x14c0;
const EIOINTC_ENABLE: usize = 0x1600;
const EIOINTC_BOUNCE: usize = 0x1680;
const EIOINTC_ISR: usize = 0x1800;
const EIOINTC_ROUTE: usize = 0x1c00;

pub fn init() {
    // Enable Extended I/O Interrupt (EXT_INT_en, bit 48 of 0x0420).
    let misc = iocsr_read_d(LOONGARCH_IOCSR_MISC_FUNC);
    iocsr_write_d(LOONGARCH_IOCSR_MISC_FUNC, misc | (1u64 << 48));

    // Start from a masked state so inherited firmware state cannot dispatch an
    // interrupt before its handler is registered.
    for group in 0..(EIOINTC_VECTOR_COUNT / 64) {
        iocsr_write_d(EIOINTC_ENABLE + group * 8, 0);
        iocsr_write_d(EIOINTC_ISR + group * 8, u64::MAX);
    }

    for word in 0..(EIOINTC_VECTOR_COUNT / 32) {
        iocsr_write_w(EIOINTC_NODEMAP + word * 4, eiointc_nodemap_word(word));
    }

    for word in 0..(EIOINTC_VECTOR_COUNT / 128) {
        iocsr_write_w(EIOINTC_IPMAP + word * 4, EIOINTC_IPMAP_WORD);
    }

    for word in 0..(EIOINTC_VECTOR_COUNT / 4) {
        iocsr_write_w(EIOINTC_ROUTE + word * 4, EIOINTC_CPU0_ROUTE_WORD);
    }

    for word in 0..(EIOINTC_VECTOR_COUNT / 32) {
        iocsr_write_w(EIOINTC_BOUNCE + word * 4, u32::MAX);
    }
}

pub fn claim_irq() -> Option<usize> {
    for group in 0..(EIOINTC_VECTOR_COUNT / 64) {
        let pending = iocsr_read_d(EIOINTC_ISR + group * 8);
        if pending != 0 {
            return Some(group * 64 + pending.trailing_zeros() as usize);
        }
    }
    None
}

pub fn complete_irq(irq_num: usize) {
    if irq_num >= EIOINTC_VECTOR_COUNT {
        return;
    }
    let (offset, bit) = eiointc_reg_bit(irq_num);
    iocsr_write_d(EIOINTC_ISR + offset, bit);
}

pub fn set_enable(irq_num: usize, enabled: bool) {
    if irq_num >= EIOINTC_VECTOR_COUNT {
        return;
    }
    let (offset, bit) = eiointc_reg_bit(irq_num);
    let reg = EIOINTC_ENABLE + offset;
    let _guard = ENABLE_LOCK.lock();
    let old = iocsr_read_d(reg);
    let new = update_enable_mask(old, bit, enabled);
    iocsr_write_d(reg, new);
}
