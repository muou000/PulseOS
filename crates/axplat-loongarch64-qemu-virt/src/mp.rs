use axplat::mem::PhysAddr;
const IOCSR_DMW_BASE: usize = 0x8000_0000_0000_0000;

const LOONGARCH_IOCSR_IPI_SEND: usize = 0x1040;
const LOONGARCH_IOCSR_MBUF_SEND: usize = 0x1048;

const IOCSR_IPI_SEND_CPU_SHIFT: usize = 16;
const IOCSR_IPI_SEND_BLOCKING: u32 = 1 << 31;

const IOCSR_MBUF_SEND_CPU_SHIFT: usize = 16;
const IOCSR_MBUF_SEND_BOX_SHIFT: usize = 26;
const IOCSR_MBUF_SEND_BUF_SHIFT: usize = 32;
const IOCSR_MBUF_SEND_BLOCKING: u64 = 1 << 31;
const IOCSR_MBUF_SEND_H32_MASK: u64 = 0xffff_ffff_0000_0000;

#[inline]
fn iocsr_write_u32(addr: usize, value: u32) {
    let addr = addr | IOCSR_DMW_BASE;
    unsafe {
        core::arch::asm!("iocsrwr.w {},{}", in(reg) value, in(reg) addr);
    }
}

#[inline]
fn iocsr_write_u64(addr: usize, value: u64) {
    let addr = addr | IOCSR_DMW_BASE;
    unsafe {
        core::arch::asm!("iocsrwr.d {},{}", in(reg) value, in(reg) addr);
    }
}

fn iocsr_mbuf_send_box_lo(box_: usize) -> usize {
    box_ << 1
}
fn iocsr_mbuf_send_box_hi(box_: usize) -> usize {
    (box_ << 1) + 1
}

pub fn csr_mail_send(entry: u64, cpu: usize, mailbox: usize) {
    let mut val: u64;
    val = IOCSR_MBUF_SEND_BLOCKING;
    val |= (iocsr_mbuf_send_box_hi(mailbox) << IOCSR_MBUF_SEND_BOX_SHIFT) as u64;
    val |= (cpu << IOCSR_MBUF_SEND_CPU_SHIFT) as u64;
    val |= entry & IOCSR_MBUF_SEND_H32_MASK;
    iocsr_write_u64(LOONGARCH_IOCSR_MBUF_SEND, val);
    val = IOCSR_MBUF_SEND_BLOCKING;
    val |= (iocsr_mbuf_send_box_lo(mailbox) << IOCSR_MBUF_SEND_BOX_SHIFT) as u64;
    val |= (cpu << IOCSR_MBUF_SEND_CPU_SHIFT) as u64;
    val |= entry << IOCSR_MBUF_SEND_BUF_SHIFT;
    iocsr_write_u64(LOONGARCH_IOCSR_MBUF_SEND, val);
}

pub fn send_ipi_single(cpu: usize, action: u32) {
    for i in 0..32 {
        if (action & (1 << i)) != 0 {
            let mut val: u32 = IOCSR_IPI_SEND_BLOCKING;
            val |= (cpu << IOCSR_IPI_SEND_CPU_SHIFT) as u32;
            val |= i as u32;
            iocsr_write_u32(LOONGARCH_IOCSR_IPI_SEND, val);
        }
    }
}

use crate::mem::phys_to_virt;

const ACTION_BOOT_CPU: u32 = 1;

pub static mut SMP_BOOT_STACK_TOP: usize = 0;

/// Starts the given secondary CPU with its boot stack.
pub fn start_secondary_cpu(cpu_id: usize, stack_top: PhysAddr) {
    unsafe extern "C" {
        fn _start_secondary();
    }
    let stack_top_virt_addr = phys_to_virt(stack_top).as_usize();
    unsafe {
        SMP_BOOT_STACK_TOP = stack_top_virt_addr;
    }
    csr_mail_send(_start_secondary as *const () as _, cpu_id, 0);
    send_ipi_single(cpu_id, ACTION_BOOT_CPU);
}
