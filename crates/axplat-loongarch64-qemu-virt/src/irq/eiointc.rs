use loongArch64::iocsr::{iocsr_read_d, iocsr_write_b, iocsr_write_d};

const EIOINTC_BASE: usize = 0x1400;
const EIOINTC_NODEMAP: usize = 0x14a0;
const EIOINTC_IPMAP: usize = 0x14c0;
const EIOINTC_ENABLE: usize = 0x1600;
const EIOINTC_ISR: usize = 0x1800;
const EIOINTC_ROUTE: usize = 0x1c00;

pub fn init() {
    // 1. Route EIOINTC inputs 0..64 to CPU0
    // Each 32 interrupts share 8 bytes for node mapping? 
    // Actually, on qemu-virt, it's often simpler.
    // Let's set the first 64 interrupts to be routed to CPU0 (node 0).
    for i in 0..64 {
        // EIOINTC_ROUTE has 1 byte per interrupt
        iocsr_write_b(EIOINTC_ROUTE + i, 0); // 0 means CPU0
    }

    // 2. Map EIOINTC interrupts to CPU HWI lines
    // IPMAP has 8 bytes, each 4 bits per 32-interrupt group? No.
    // IPMAP: 4 groups, each group for 64 interrupts.
    // Group 0 (IRQs 0-63) -> 0x14c0
    // We want IRQs 0-63 to go to HWI0 (which is index 0 in IPMAP if it maps to IP0..IP7)
    // In LoongArch, HWI0 is IP2.
    // Wait, let's check the IPMAP mapping.
    // IPMAP0 maps IRQ0-63 to IP0-7.
    // We want to map them to IP2 (HWI0).
    // IPMAP0 (64 bits): each 8 bits for 8 IRQs? No.
    // IPMAP: 32 bits for 256 IRQs? 1 bit per IRQ? 
    // Actually, it's: IRQ 0..31 map to IP x, IRQ 32..63 map to IP y.
    // IPMAP0: bits 0..3 for IRQ 0..31, bits 4..7 for IRQ 32..63, etc.
    // We want IRQ 0..63 to go to IP2 (HWI0). IP2 is value 2.
    // So IPMAP0 bits 0..3 = 2, bits 4..7 = 2.
    let mut ipmap0 = iocsr_read_d(EIOINTC_IPMAP);
    ipmap0 &= !0xff;
    ipmap0 |= 0x22; // Map IRQ 0..63 to IP2
    iocsr_write_d(EIOINTC_IPMAP, ipmap0);

    // 3. Enable EIOINTC for IRQ 0..63
    iocsr_write_d(EIOINTC_ENABLE, 0xffff_ffff_ffff_ffff);
}

pub fn get_pending() -> u64 {
    iocsr_read_d(EIOINTC_ISR)
}
