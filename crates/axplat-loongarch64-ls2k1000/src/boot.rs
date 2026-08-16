use axplat::mem::{Aligned4K, PhysAddr, pa};
use page_table_entry::{GenericPTE, MappingFlags, loongarch64::LA64PTE};

use crate::{
    boot_common::{L1_BLOCK_SIZE, l1_block_index},
    config::plat::{BOOT_STACK_SIZE, PHYS_VIRT_OFFSET},
};

const DMW_VIRT_MASK: usize = 0x0fff_ffff_ffff_ffff;
const DMW_CACHED_BASE: usize = 0x9000_0000_0000_0000;
const IOCSR_MAILBOX1: usize = 0x1028;

const BOOT_LOW_L1_INDEX: usize = l1_block_index(0);
const BOOT_DEVICE_L1_INDEX: usize = l1_block_index(0x4000_0000);
const BOOT_KERNEL_PADDR_L1_INDEX: usize = l1_block_index(crate::config::plat::KERNEL_BASE_PADDR);
const BOOT_HIGH_PGD_INDEX: usize = (crate::config::plat::KERNEL_BASE_VADDR >> 39) & 0x1ff;
const BOOT_HIGH_LOW_DIR2_INDEX: usize = (PHYS_VIRT_OFFSET >> 30) & 0x1ff;
const BOOT_HIGH_DEVICE_DIR2_INDEX: usize =
    (PHYS_VIRT_OFFSET.wrapping_add(L1_BLOCK_SIZE) >> 30) & 0x1ff;
const BOOT_HIGH_DIR2_INDEX: usize = (crate::config::plat::KERNEL_BASE_VADDR >> 30) & 0x1ff;
const BOOT_HIGH_DIR1_INDEX: usize = (crate::config::plat::KERNEL_BASE_VADDR >> 21) & 0x1ff;
const L2_BLOCK_SIZE: usize = 0x20_0000;
const L2_ENTRIES: usize = L1_BLOCK_SIZE / L2_BLOCK_SIZE;

const _: () = assert!(BOOT_LOW_L1_INDEX == 0);
const _: () = assert!(BOOT_DEVICE_L1_INDEX == 1);
const _: () = assert!(BOOT_KERNEL_PADDR_L1_INDEX == 2);
const _: () = assert!(BOOT_HIGH_PGD_INDEX == 0x1ff);
const _: () = assert!(BOOT_HIGH_LOW_DIR2_INDEX == 0x1fc);
const _: () = assert!(BOOT_HIGH_DEVICE_DIR2_INDEX == 0x1fd);
const _: () = assert!(BOOT_HIGH_DIR2_INDEX == 0x1fe);
const _: () = assert!(BOOT_HIGH_DIR1_INDEX == 0xc0);
const _: () = assert!(L2_ENTRIES == 512);

#[unsafe(link_section = ".bss.stack")]
static mut BOOT_STACK: [u8; BOOT_STACK_SIZE] = [0; BOOT_STACK_SIZE];

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L0: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L1: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L2_LOW: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L2_DEVICE: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_PT_L2_KERNEL: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

#[unsafe(link_section = ".data")]
static mut BOOT_INVALID_PT: Aligned4K<[LA64PTE; 512]> = Aligned4K::new([LA64PTE::empty(); 512]);

unsafe fn init_boot_page_table() {
    unsafe {
        let l1_paddr = boot_paddr(&raw const BOOT_PT_L1);
        let l2_low_paddr = boot_paddr(&raw const BOOT_PT_L2_LOW);
        let l2_device_paddr = boot_paddr(&raw const BOOT_PT_L2_DEVICE);
        let l2_kernel_paddr = boot_paddr(&raw const BOOT_PT_L2_KERNEL);
        let invalid_paddr = boot_paddr(&raw const BOOT_INVALID_PT);

        // LDDIR follows table pointers even for an invalid translation. Point
        // every unused entry at a self-referential table in the kernel image,
        // so the final LDPTE sees an invalid leaf without ever reading or
        // writing PA 0. LS2K1000 does not describe PA 0 as usable RAM.
        for index in 0..512 {
            write_boot_pte(
                &raw const BOOT_INVALID_PT,
                index,
                LA64PTE::new_table(invalid_paddr),
            );
            write_boot_pte(
                &raw const BOOT_PT_L0,
                index,
                LA64PTE::new_table(invalid_paddr),
            );
            write_boot_pte(
                &raw const BOOT_PT_L1,
                index,
                LA64PTE::new_table(invalid_paddr),
            );
            write_boot_pte(
                &raw const BOOT_PT_L2_LOW,
                index,
                LA64PTE::new_table(invalid_paddr),
            );
            write_boot_pte(
                &raw const BOOT_PT_L2_DEVICE,
                index,
                LA64PTE::new_table(invalid_paddr),
            );
            write_boot_pte(
                &raw const BOOT_PT_L2_KERNEL,
                index,
                LA64PTE::new_table(invalid_paddr),
            );
        }

        write_boot_pte(&raw const BOOT_PT_L0, 0, LA64PTE::new_table(l1_paddr));
        // LS2K1000 accepts the sign-extended 40-bit upper window
        // 0xffff_ffff_xxxx_xxxx, whose Dir3 index is 0x1ff.
        write_boot_pte(
            &raw const BOOT_PT_L0,
            BOOT_HIGH_PGD_INDEX,
            LA64PTE::new_table(l1_paddr),
        );

        // LS2K1000 accepts 2 MiB huge leaves at Dir1. QEMU's 1 GiB Dir2
        // leaves reach the same virtual addresses but fault on this CPU.
        write_boot_pte(
            &raw const BOOT_PT_L1,
            BOOT_LOW_L1_INDEX,
            LA64PTE::new_table(l2_low_paddr),
        );
        write_boot_pte(
            &raw const BOOT_PT_L1,
            BOOT_DEVICE_L1_INDEX,
            LA64PTE::new_table(l2_device_paddr),
        );
        // The platform's phys_to_virt() uses PHYS_VIRT_OFFSET for MMIO as
        // well as RAM. Mirror the first 2 GiB into that upper linear map so
        // console, interrupt-controller, and storage MMIO are reachable
        // before the runtime kernel page table replaces this bootstrap map.
        write_boot_pte(
            &raw const BOOT_PT_L1,
            BOOT_HIGH_LOW_DIR2_INDEX,
            LA64PTE::new_table(l2_low_paddr),
        );
        write_boot_pte(
            &raw const BOOT_PT_L1,
            BOOT_HIGH_DEVICE_DIR2_INDEX,
            LA64PTE::new_table(l2_device_paddr),
        );
        write_boot_pte(
            &raw const BOOT_PT_L1,
            BOOT_HIGH_DIR2_INDEX,
            LA64PTE::new_table(l2_kernel_paddr),
        );

        for index in 0..L2_ENTRIES {
            write_boot_pte(
                &raw const BOOT_PT_L2_LOW,
                index,
                LA64PTE::new_page(
                    PhysAddr::from(index * L2_BLOCK_SIZE),
                    MappingFlags::READ | MappingFlags::WRITE | MappingFlags::DEVICE,
                    true,
                ),
            );
            write_boot_pte(
                &raw const BOOT_PT_L2_DEVICE,
                index,
                LA64PTE::new_page(
                    PhysAddr::from(L1_BLOCK_SIZE + index * L2_BLOCK_SIZE),
                    MappingFlags::READ | MappingFlags::WRITE | MappingFlags::DEVICE,
                    true,
                ),
            );
            write_boot_pte(
                &raw const BOOT_PT_L2_KERNEL,
                index,
                LA64PTE::new_page(
                    PhysAddr::from(
                        BOOT_KERNEL_PADDR_L1_INDEX * L1_BLOCK_SIZE + index * L2_BLOCK_SIZE,
                    ),
                    MappingFlags::READ | MappingFlags::WRITE | MappingFlags::EXECUTE,
                    true,
                ),
            );
        }

        core::arch::asm!("dbar 0", options(nostack));
    }
}

fn boot_paddr<T>(ptr: *const T) -> PhysAddr {
    let vaddr = ptr as usize;

    // Symbols in this raw image retain their linked high virtual addresses,
    // even while the first instructions execute through DMW1.  Clearing only
    // DMW's top nibble would turn e.g. `ffff_ffff_9837_2000` into
    // `0fff_ffff_9837_2000`, not its physical address `9837_2000`.  That
    // programs the bootstrap walker with (and writes PTEs through) the wrong
    // physical address.  Convert linked kernel addresses through the actual
    // linear-map offset; retain the DMW form for an already-direct pointer.
    let paddr = if vaddr >= PHYS_VIRT_OFFSET {
        vaddr.wrapping_sub(PHYS_VIRT_OFFSET)
    } else {
        vaddr & DMW_VIRT_MASK
    };
    pa!(paddr)
}

/// Writes a bootstrap PTE through DMW1 (coherent cached).
///
/// LS2K1000 reports no hardware page-table walker, so refill is performed by
/// `LDDIR`/`LDPTE` while direct mode retains `CRMD.DATM=CoherentCached`.
/// Initializing and consuming these tables through the same cache domain avoids
/// stale D-cache lines overriding PTEs written through an uncached alias.
unsafe fn write_boot_pte(table: *const Aligned4K<[LA64PTE; 512]>, index: usize, entry: LA64PTE) {
    let entries = (DMW_CACHED_BASE | boot_paddr(table).as_usize()) as *mut LA64PTE;
    unsafe {
        core::ptr::write_volatile(entries.add(index), entry);
    }
}

fn enable_fp_simd() {
    axcpu::asm::enable_fp();
    #[cfg(feature = "fp-simd")]
    {
        axcpu::asm::enable_lsx();
    }
}

fn init_mmu() {
    let root_paddr = boot_paddr(&raw const BOOT_PT_L0);

    // The boot root contains safe low mappings as well as the high kernel
    // mapping. Install it in both PGDH and PGDL, matching the LS2K1000
    // reference boot path and avoiding a hardware-specific root-selection
    // ambiguity during the very first TLB refill.
    axcpu::init::init_mmu_with_user_root(root_paddr, root_paddr, PHYS_VIRT_OFFSET);
}

/// Primary entry for a raw image started by `U-Boot go`.
#[unsafe(naked)]
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.boot")]
unsafe extern "C" fn _start() -> ! {
    core::arch::naked_asm!("
        ori         $t0, $zero, 0x1
        lu52i.d     $t0, $t0, -2048     # DMW0: uncached, PLV0
        csrwr       $t0, 0x180
        ori         $t0, $zero, 0x11
        lu52i.d     $t0, $t0, -1792     # DMW1: cached, PLV0
        csrwr       $t0, 0x181
        la.pcrel    $t0, 2f
        li.d        $t1, {dmw_cached_base}
        or          $t0, $t0, $t1
        jirl        $zero, $t0, 0

    2:
        move        $s0, $a0            # U-Boot argc / UHI sentinel
        move        $s1, $a1            # U-Boot argv / direct FDT pointer
        la.pcrel    $sp, {boot_stack}
        li.d        $t0, {boot_stack_size}
        add.d       $sp, $sp, $t0

        bl          {enable_fp_simd}
        bl          {init_boot_page_table}
        li.d        $a0, {phys_virt_offset}
        bl          {init_trap_early}
        bl          {init_mmu}
        // Page-table/CRMD changes are architecturally visible, but the
        // instruction stream must be synchronized before the first
        // high-half fetch. This is also the ordering used by tgoskits.
        ibar        0
        dbar        0

        li.d        $t0, {dmw_virt_mask}
        and         $sp, $sp, $t0
        li.d        $t0, {phys_virt_offset}
        add.d       $sp, $sp, $t0

        la.pcrel    $t0, 3f
        li.d        $t1, {dmw_virt_mask}
        and         $t0, $t0, $t1
        li.d        $t1, {phys_virt_offset}
        add.d       $t0, $t0, $t1

        jirl        $zero, $t0, 0

    3:
        move        $a0, $s0
        move        $a1, $s1
        bl          {boot_fdt_paddr}
        move        $s1, $a0
        csrrd       $a0, 0x20
        move        $a1, $s1
        bl          {init_topology}
        move        $s0, $a0
        move        $a0, $s0
        move        $a1, $s1
        la.pcrel    $t0, {entry}
        jirl        $zero, $t0, 0
        ",
        dmw_virt_mask = const DMW_VIRT_MASK,
        dmw_cached_base = const crate::mp_common::DMW_CACHED_BASE,
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        boot_stack_size = const BOOT_STACK_SIZE,
        boot_stack = sym BOOT_STACK,
        enable_fp_simd = sym enable_fp_simd,
        init_boot_page_table = sym init_boot_page_table,
        init_trap_early = sym axcpu::init::init_trap_early,
        init_mmu = sym init_mmu,
        boot_fdt_paddr = sym crate::topology::boot_fdt_paddr,
        init_topology = sym crate::topology::init_from_dtb,
        entry = sym axplat::call_main,
    )
}

#[cfg(feature = "smp")]
#[unsafe(naked)]
#[unsafe(no_mangle)]
pub(crate) unsafe extern "C" fn _start_secondary() -> ! {
    core::arch::naked_asm!("
        ori         $t0, $zero, 0x1
        lu52i.d     $t0, $t0, -2048
        csrwr       $t0, 0x180
        ori         $t0, $zero, 0x11
        lu52i.d     $t0, $t0, -1792
        csrwr       $t0, 0x181
        la.pcrel    $t0, 2f
        li.d        $t1, {dmw_cached_base}
        or          $t0, $t0, $t1
        jirl        $zero, $t0, 0

    2:
        li.w        $t0, {iocsr_mailbox1}
        iocsrrd.d   $sp, $t0
        bl          {enable_fp_simd}
        bl          {init_mmu}
        li.d        $t0, {dmw_virt_mask}
        and         $sp, $sp, $t0
        li.d        $t0, {phys_virt_offset}
        add.d       $sp, $sp, $t0

        la.pcrel    $t0, 3f
        li.d        $t1, {dmw_virt_mask}
        and         $t0, $t0, $t1
        li.d        $t1, {phys_virt_offset}
        add.d       $t0, $t0, $t1
        jirl        $zero, $t0, 0

    3:
        csrrd       $a0, 0x20
        bl          {logical_cpu_id}
        la.pcrel    $t0, {entry}
        jirl        $zero, $t0, 0",
        dmw_virt_mask = const DMW_VIRT_MASK,
        dmw_cached_base = const crate::mp_common::DMW_CACHED_BASE,
        iocsr_mailbox1 = const IOCSR_MAILBOX1,
        phys_virt_offset = const PHYS_VIRT_OFFSET,
        enable_fp_simd = sym enable_fp_simd,
        init_mmu = sym init_mmu,
        logical_cpu_id = sym crate::topology::logical_cpu_id,
        entry = sym axplat::call_secondary_main,
    )
}
