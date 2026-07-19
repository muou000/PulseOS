use axplat::mem::{Aligned4K, pa};

use crate::config::plat::{BOOT_STACK_SIZE, PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET};

const GIGA_PAGE_SIZE: usize = 0x4000_0000;
const GIGA_PAGE_FLAGS: u64 = 0xef;

#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

#[unsafe(link_section = ".data")]
static mut BOOT_PT_SV39: Aligned4K<[u64; 512]> = Aligned4K::new([0; 512]);

unsafe fn init_boot_page_table() {
    unsafe {
        // Keep low MMIO reachable through both identity and direct mappings.
        BOOT_PT_SV39[0] = giga_page_entry(0);
        BOOT_PT_SV39[direct_map_index(0)] = giga_page_entry(0);

        // QEMU places the DTB near the top of RAM, so all configured RAM must
        // be reachable before init_topology() parses it.
        let first = PHYS_MEMORY_BASE / GIGA_PAGE_SIZE;
        let end = (PHYS_MEMORY_BASE + PHYS_MEMORY_SIZE).div_ceil(GIGA_PAGE_SIZE);
        for index in first..end {
            let paddr = index * GIGA_PAGE_SIZE;
            let entry = giga_page_entry(paddr);
            BOOT_PT_SV39[index] = entry;
            BOOT_PT_SV39[direct_map_index(paddr)] = entry;
        }
    }
}

const fn giga_page_entry(paddr: usize) -> u64 {
    ((paddr >> 12) as u64) << 10 | GIGA_PAGE_FLAGS
}

const fn direct_map_index(paddr: usize) -> usize {
    (PHYS_VIRT_OFFSET.wrapping_add(paddr) >> 30) & 0x1ff
}

unsafe fn init_mmu() {
    unsafe {
        axcpu::asm::write_kernel_page_table(pa!(&raw const BOOT_PT_SV39 as usize));
        axcpu::asm::flush_tlb(None);
    }
}

/// The earliest entry point for the primary CPU.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start() -> ! {
    // PC = 0x8020_0000
    // a0 = hartid
    // a1 = dtb
    core::arch::naked_asm!("
        mv      s0, a0                  // save hartid
        mv      s1, a1                  // save DTB pointer
        la      sp, {boot_stack}
        li      t0, {boot_stack_size}
        add     sp, sp, t0              // setup boot stack

        call    {init_boot_page_table}
        call    {init_mmu}              // setup boot page table and enabel MMU

        mv      a0, s0
        mv      a1, s1
        call    {init_topology}          // map the boot hart to a logical CPU ID
        mv      s0, a0

        li      s2, {phys_virt_offset}  // fix up virtual high address
        add     sp, sp, s2

        mv      a0, s0
        mv      a1, s1
        la      a2, {entry}
        add     a2, a2, s2
        jalr    a2                      // call_main(cpu_id, dtb)
        j       .",
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        boot_stack_size = const BOOT_STACK_SIZE,
        boot_stack = sym BOOT_STACK,
        init_boot_page_table = sym init_boot_page_table,
        init_mmu = sym init_mmu,
        init_topology = sym crate::topology::init_from_dtb,
        entry = sym axplat::call_main,
    )
}

/// The earliest entry point for secondary CPUs.
#[cfg(feature = "smp")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn _start_secondary() -> ! {
    // a0 = hartid
    // a1 = SP
    core::arch::naked_asm!("
        mv      s0, a0                  // save hartid
        mv      sp, a1                  // set SP

        call    {init_mmu}              // setup boot page table and enabel MMU

        mv      a0, s0
        call    {logical_cpu_id}         // map the firmware hart ID to a logical CPU ID
        mv      s0, a0

        li      s1, {phys_virt_offset}  // fix up virtual high address
        add     sp, sp, s1

        mv      a0, s0
        la      a1, {entry}
        add     a1, a1, s1
        jalr    a1                      // call_secondary_main(cpu_id)
        j       .",
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        init_mmu = sym init_mmu,
        logical_cpu_id = sym crate::topology::logical_cpu_id,
        entry = sym axplat::call_secondary_main,
    )
}
