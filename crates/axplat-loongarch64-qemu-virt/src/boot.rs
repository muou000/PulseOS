use axplat::mem::{Aligned4K, PAGE_SIZE_4K, PhysAddr, pa};
use page_table_entry::{GenericPTE, MappingFlags, loongarch64::LA64PTE};

use crate::{
    boot_common::{L1_BLOCK_SIZE, high_memory_l1_blocks, l1_block_index},
    config::plat::{BOOT_STACK_SIZE, PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE, PHYS_VIRT_OFFSET},
};

const DMW_VIRT_MASK: usize = 0x0fff_ffff_ffff_ffff;
const DMW_CACHED_BASE: usize = 0x9000_0000_0000_0000;
const IOCSR_MAILBOX1: usize = 0x1028;
const BOOT_RAM_L1_START: usize = l1_block_index(PHYS_MEMORY_BASE);
const BOOT_RAM_L1_BLOCKS: usize = high_memory_l1_blocks(PHYS_MEMORY_SIZE);

const _: () = assert!(PHYS_MEMORY_BASE % L1_BLOCK_SIZE == 0);
const _: () = assert!(BOOT_RAM_L1_START + BOOT_RAM_L1_BLOCKS <= 512);

#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L0: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L1: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

unsafe fn init_boot_page_table() {
    unsafe {
        // Empty dynamic page-table entries point at PA 0 during the branchless
        // LDDIR/LDPTE refill walk. DMW1 is active here, so initialize the
        // platform-reserved invalid table through its cached direct mapping.
        core::ptr::write_bytes(DMW_CACHED_BASE as *mut u8, 0, PAGE_SIZE_4K);
        core::arch::asm!("dbar 0");

        let l1_paddr = boot_paddr(&raw const BOOT_PT_L1);
        // 0x0000_0000_0000 ~ 0x0080_0000_0000, table
        BOOT_PT_L0[0] = LA64PTE::new_table(l1_paddr);
        // Higher-half mapping for canonical addresses (bit 47 = 1).
        BOOT_PT_L0[0x100] = LA64PTE::new_table(l1_paddr);
        // 0x0000_0000..0x4000_0000, VPWXGD, 1G block
        BOOT_PT_L1[0] = LA64PTE::new_page(
            pa!(0),
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::DEVICE,
            true,
        );
        // 0x4000_0000..0x8000_0000, VPWXGD, 1G block
        BOOT_PT_L1[1] = LA64PTE::new_page(
            pa!(0x4000_0000),
            MappingFlags::READ | MappingFlags::WRITE | MappingFlags::DEVICE,
            true,
        );
        // QEMU places RAM above the MMIO hole at PHYS_MEMORY_BASE. Map every
        // 1G block needed while the final kernel page table is being built.
        for index in BOOT_RAM_L1_START..BOOT_RAM_L1_START + BOOT_RAM_L1_BLOCKS {
            BOOT_PT_L1[index] = LA64PTE::new_page(
                PhysAddr::from(index * L1_BLOCK_SIZE),
                MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE,
                true,
            );
        }
    }
}

fn boot_paddr<T>(ptr: *const T) -> PhysAddr {
    pa!((ptr as usize) & DMW_VIRT_MASK)
}

fn enable_fp_simd() {
    // Enable FP unconditionally to avoid FloatingPointUnavailable traps before
    // the regular exception path is ready.
    axcpu::asm::enable_fp();
    #[cfg(feature = "fp-simd")]
    {
        axcpu::asm::enable_lsx();
    }
}

fn init_mmu() {
    axcpu::init::init_mmu(boot_paddr(&raw const BOOT_PT_L0), PHYS_VIRT_OFFSET);
}

/// The earliest entry point for the primary CPU.
///
/// We can't use bl to jump to higher address, so we use jirl to jump to higher address.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("
        ori         $t0, $zero, 0x1     # CSR_DMW1_PLV0
        lu52i.d     $t0, $t0, -2048     # UC, PLV0, 0x8000 xxxx xxxx xxxx
        csrwr       $t0, 0x180          # LOONGARCH_CSR_DMWIN0
        ori         $t0, $zero, 0x11    # CSR_DMW1_MAT | CSR_DMW1_PLV0
        lu52i.d     $t0, $t0, -1792     # CA, PLV0, 0x9000 xxxx xxxx xxxx
        csrwr       $t0, 0x181          # LOONGARCH_CSR_DMWIN1
        la.pcrel    $t0, 2f
        li.d        $t1, {dmw_cached_base}
        or          $t0, $t0, $t1
        jirl        $zero, $t0, 0

    2:

        # Setup Stack
        la.pcrel    $sp, {boot_stack}
        li.d        $t0, {boot_stack_size}
        add.d       $sp, $sp, $t0       # setup boot stack

        # Init MMU
        bl          {enable_fp_simd}    # enable FP/SIMD instructions
        bl          {init_boot_page_table}
        bl          {init_mmu}          # setup boot page table and enable MMU
        li.d        $t0, {dmw_virt_mask}
        and         $sp, $sp, $t0
        li.d        $t0, {phys_virt_offset}
        add.d       $sp, $sp, $t0       # switch boot stack to higher-half VA

        # Switch PC to higher-half VA so that subsequent PC-relative symbol
        # accesses resolve to the linked addresses (0xffff_8000_...) instead
        # of DMW1 addresses (0x9000_...).
        la.pcrel    $t0, 3f
        li.d        $t1, {dmw_virt_mask}
        and         $t0, $t0, $t1
        li.d        $t1, {phys_virt_offset}
        add.d       $t0, $t0, $t1
        jirl        $zero, $t0, 0

    3:
        csrrd       $a0, 0x20           # cpuid
        li.d        $a1, 0              # TODO: parse dtb
        la.pcrel    $t0, {entry}
        jirl        $zero, $t0, 0",
        dmw_virt_mask = const DMW_VIRT_MASK,
        dmw_cached_base = const DMW_CACHED_BASE,
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        boot_stack_size = const BOOT_STACK_SIZE,
        boot_stack = sym BOOT_STACK,
        enable_fp_simd = sym enable_fp_simd,
        init_boot_page_table = sym init_boot_page_table,
        init_mmu = sym init_mmu,
        entry = sym axplat::call_main,
    )
}

/// The earliest entry point for secondary CPUs.
#[cfg(feature = "smp")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn _start_secondary() -> ! {
    core::arch::naked_asm!("
        ori          $t0, $zero, 0x1     # CSR_DMW1_PLV0
        lu52i.d      $t0, $t0, -2048     # UC, PLV0, 0x8000 xxxx xxxx xxxx
        csrwr        $t0, 0x180          # LOONGARCH_CSR_DMWIN0
        ori          $t0, $zero, 0x11    # CSR_DMW1_MAT | CSR_DMW1_PLV0
        lu52i.d      $t0, $t0, -1792     # CA, PLV0, 0x9000 xxxx xxxx xxxx
        csrwr        $t0, 0x181          # LOONGARCH_CSR_DMWIN1
        la.pcrel     $t0, 2f
        li.d         $t1, {dmw_cached_base}
        or           $t0, $t0, $t1
        jirl         $zero, $t0, 0

    2:
        li.w         $t0, {iocsr_mailbox1}
        iocsrrd.d    $sp, $t0             # read this CPU's boot stack top

        # Init MMU
        bl           {enable_fp_simd}    # enable FP/SIMD instructions
        bl           {init_mmu}          # setup boot page table and enable MMU
        li.d         $t0, {dmw_virt_mask}
        and          $sp, $sp, $t0
        li.d         $t0, {phys_virt_offset}
        add.d        $sp, $sp, $t0       # switch boot stack to higher-half VA

        # Switch PC to higher-half VA
        la.pcrel     $t0, 3f
        li.d         $t1, {dmw_virt_mask}
        and          $t0, $t0, $t1
        li.d         $t1, {phys_virt_offset}
        add.d        $t0, $t0, $t1
        jirl         $zero, $t0, 0

    3:
        csrrd        $a0, 0x20                  # cpuid
        la.pcrel     $t0, {entry}
        jirl         $zero, $t0, 0",
        dmw_virt_mask = const DMW_VIRT_MASK,
        dmw_cached_base = const DMW_CACHED_BASE,
        iocsr_mailbox1 = const IOCSR_MAILBOX1,
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        enable_fp_simd = sym enable_fp_simd,
        init_mmu = sym init_mmu,
        entry = sym axplat::call_secondary_main,
    )
}
