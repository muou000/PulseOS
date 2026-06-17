//! vDSO data management.
extern crate alloc;
extern crate log;
use alloc::{alloc::alloc_zeroed, vec::Vec};
use core::alloc::Layout;

use axerrno::{AxError, AxResult};
use axplat::mem::{MemRegionFlags, virt_to_phys};
use kernel_elf_parser::{AuxEntry, AuxType};
use log::{debug, info, warn};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K};

/// Global vDSO data instance
#[unsafe(link_section = ".data")]
pub static mut VDSO_DATA: crate::vdso_data::VdsoData = crate::vdso_data::VdsoData::new();

/// Initialize vDSO data
pub fn init_vdso_data() {
    unsafe {
        let data_ptr = core::ptr::addr_of_mut!(VDSO_DATA);
        (*data_ptr).time_update();
        info!("vDSO data initialized at {:#x}", data_ptr as usize);
    }
}

use core::sync::atomic::{AtomicBool, Ordering};

static VDSO_UPDATE_LOCK: AtomicBool = AtomicBool::new(false);

/// Set the vDSO epoch offset.
pub fn set_vdso_epoch_offset(offset: u64) {
    crate::vdso_time_data::set_vdso_epoch_offset(offset);
}

/// Update vDSO data
pub fn update_vdso_data() {
    while VDSO_UPDATE_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        core::hint::spin_loop();
    }

    unsafe {
        let data_ptr = core::ptr::addr_of_mut!(VDSO_DATA);
        (*data_ptr).time_update();
    }

    VDSO_UPDATE_LOCK.store(false, Ordering::Release);
}

/// Get the physical address of vDSO data for mapping to userspace
pub fn vdso_data_paddr() -> usize {
    let data_ptr = core::ptr::addr_of!(VDSO_DATA) as usize;
    virt_to_phys(data_ptr.into()).into()
}

/// Information about loaded vDSO pages for userspace mapping and auxv update.
pub type VdsoPageInfo = (
    axplat::mem::PhysAddr,
    &'static [u8],
    usize,
    usize,
    Option<(usize, usize)>,
);

/// A single mapping request produced while loading vDSO data.
#[derive(Clone, Copy, Debug)]
pub struct VdsoMapping {
    pub user_start: usize,
    pub paddr: axplat::mem::PhysAddr,
    pub size: usize,
    pub flags: MemRegionFlags,
}

/// Load result that keeps the temporary vDSO allocation alive until mappings
/// are applied.
pub struct VdsoLoadData {
    pub mappings: Vec<VdsoMapping>,
    alloc_guard: crate::guard::VdsoAllocGuard,
}

impl VdsoLoadData {
    pub fn disarm(&mut self) {
        self.alloc_guard.disarm();
    }
}

/// Load vDSO into the given user address space and update auxv accordingly.
pub fn prepare_vdso_pages(vdso_kstart: usize, vdso_kend: usize) -> AxResult<VdsoPageInfo> {
    let orig_vdso_len = vdso_kend - vdso_kstart;
    let orig_page_off = vdso_kstart & (PAGE_SIZE_4K - 1);

    if orig_page_off == 0 {
        // Already page aligned: use original memory region directly.
        let vdso_paddr_page = virt_to_phys(vdso_kstart.into());
        let vdso_size = (vdso_kend - vdso_kstart + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1);
        let vdso_bytes =
            unsafe { core::slice::from_raw_parts(vdso_kstart as *const u8, orig_vdso_len) };
        Ok((vdso_paddr_page, vdso_bytes, vdso_size, 0usize, None))
    } else {
        let total_size = orig_vdso_len + orig_page_off;
        let num_pages = total_size.div_ceil(PAGE_SIZE_4K);
        let vdso_size = num_pages * PAGE_SIZE_4K;

        let layout = match Layout::from_size_align(vdso_size, PAGE_SIZE_4K) {
            Ok(l) => l,
            Err(_) => return Err(AxError::InvalidExecutable),
        };
        let alloc_ptr = unsafe { alloc_zeroed(layout) };
        if alloc_ptr.is_null() {
            return Err(AxError::InvalidExecutable);
        }
        // destination start where vdso_start should reside
        let dest = unsafe { alloc_ptr.add(orig_page_off) };
        let src = vdso_kstart as *const u8;
        unsafe { core::ptr::copy_nonoverlapping(src, dest, orig_vdso_len) };
        let alloc_vaddr = alloc_ptr as usize;
        let vdso_paddr_page = virt_to_phys(alloc_vaddr.into());
        let vdso_bytes = unsafe { core::slice::from_raw_parts(dest as *const u8, orig_vdso_len) };
        Ok((
            vdso_paddr_page,
            vdso_bytes,
            vdso_size,
            orig_page_off,
            Some((alloc_vaddr, num_pages)),
        ))
    }
}

/// Calculate ASLR-randomized vDSO user address
pub fn calculate_vdso_aslr_addr(
    vdso_kstart: usize,
    vdso_kend: usize,
    vdso_page_offset: usize,
) -> (usize, usize) {
    use rand_core::Rng;
    use rand_pcg::Pcg64Mcg;

    const VDSO_USER_ADDR_BASE: usize = 0x7f00_0000;
    const VDSO_ASLR_PAGES: usize = 256;

    let seed: u128 = (axplat::time::monotonic_time_nanos() as u128)
        ^ ((vdso_kstart as u128).rotate_left(13))
        ^ ((vdso_kend as u128).rotate_left(37));
    let mut rng = Pcg64Mcg::new(seed);
    let page_off: usize = (rng.next_u64() as usize) % VDSO_ASLR_PAGES;
    let base_addr = VDSO_USER_ADDR_BASE + page_off * PAGE_SIZE_4K;
    let vdso_addr = if vdso_page_offset != 0 {
        base_addr.wrapping_add(vdso_page_offset)
    } else {
        base_addr
    };

    (base_addr, vdso_addr)
}

fn segment_flags(ph: &xmas_elf::program::ProgramHeader64) -> MemRegionFlags {
    let mut map_flags = MemRegionFlags::empty();
    if ph.flags.is_read() {
        map_flags |= MemRegionFlags::READ;
    }
    if ph.flags.is_write() {
        map_flags |= MemRegionFlags::WRITE;
    }
    if ph.flags.is_execute() {
        map_flags |= MemRegionFlags::EXECUTE;
    }
    map_flags
}

/// Load vDSO metadata and mapping requests for the given user address space.
pub fn load_vdso_data(auxv: &mut Vec<AuxEntry>) -> AxResult<VdsoLoadData> {
    unsafe extern "C" {
        static vdso_start: u8;
        static vdso_end: u8;
    }
    let (vdso_kstart, vdso_kend) = unsafe {
        (
            &vdso_start as *const u8 as usize,
            &vdso_end as *const u8 as usize,
        )
    };
    debug!("vdso_kstart: {vdso_kstart:#x}, vdso_kend: {vdso_kend:#x}");

    if vdso_kend <= vdso_kstart {
        warn!("vDSO binary is missing or invalid.");
        return Err(AxError::InvalidExecutable);
    }

    let (vdso_paddr_page, vdso_bytes, vdso_size, vdso_page_offset, alloc_info) =
        prepare_vdso_pages(vdso_kstart, vdso_kend).map_err(|_| AxError::InvalidExecutable)?;

    let alloc_guard = crate::guard::VdsoAllocGuard::new(alloc_info);
    let mut mappings = Vec::new();

    let (_base_addr, vdso_user_addr) =
        calculate_vdso_aslr_addr(vdso_kstart, vdso_kend, vdso_page_offset);

    match kernel_elf_parser::ELFHeadersBuilder::new(vdso_bytes).and_then(|b| {
        let range = b.ph_range();
        b.build(&vdso_bytes[range.start as usize..range.end as usize])
    }) {
        Ok(headers) => {
            mappings.extend(map_vdso_segments(
                headers,
                vdso_user_addr,
                vdso_paddr_page,
                vdso_page_offset,
            )?);
        }
        Err(_) => {
            info!("vDSO ELF parsing failed, using fallback mapping");
            let map_user_start = if vdso_page_offset == 0 {
                vdso_user_addr
            } else {
                vdso_user_addr - vdso_page_offset
            };
            mappings.push(VdsoMapping {
                user_start: map_user_start,
                paddr: vdso_paddr_page,
                size: vdso_size,
                flags: MemRegionFlags::READ | MemRegionFlags::EXECUTE,
            });
        }
    }

    map_vvar_and_push_aux(auxv, vdso_user_addr, &mut mappings)?;

    Ok(VdsoLoadData {
        mappings,
        alloc_guard,
    })
}

fn map_vvar_and_push_aux(
    auxv: &mut Vec<AuxEntry>,
    vdso_user_addr: usize,
    mappings: &mut Vec<VdsoMapping>,
) -> AxResult<()> {
    use crate::config::VVAR_PAGES;
    let vvar_user_addr = vdso_user_addr - VVAR_PAGES * PAGE_SIZE_4K;
    let vvar_paddr = vdso_data_paddr();

    mappings.push(VdsoMapping {
        user_start: vvar_user_addr,
        paddr: vvar_paddr.into(),
        size: VVAR_PAGES * PAGE_SIZE_4K,
        flags: MemRegionFlags::READ,
    });

    debug!(
        "Mapped vvar pages at user {:#x}..{:#x} -> paddr {:#x}",
        vvar_user_addr,
        vvar_user_addr + VVAR_PAGES * PAGE_SIZE_4K,
        vvar_paddr,
    );

    let aux_entry = AuxEntry::new(AuxType::SYSINFO_EHDR, vdso_user_addr);
    auxv.push(aux_entry);

    Ok(())
}

fn map_vdso_segments(
    headers: kernel_elf_parser::ELFHeaders,
    vdso_user_addr: usize,
    vdso_paddr_page: axplat::mem::PhysAddr,
    vdso_page_offset: usize,
) -> AxResult<Vec<VdsoMapping>> {
    debug!("vDSO ELF parsed successfully, mapping segments");
    let mut mappings = Vec::new();
    for ph in headers
        .ph
        .iter()
        .filter(|ph| ph.get_type() == Ok(xmas_elf::program::Type::Load))
    {
        let vaddr = ph.virtual_addr as usize;
        let seg_pad = vaddr.align_offset_4k() + vdso_page_offset;
        let seg_align_size =
            (ph.mem_size as usize + seg_pad + PAGE_SIZE_4K - 1) & !(PAGE_SIZE_4K - 1);

        let map_base_user = vdso_user_addr & !(PAGE_SIZE_4K - 1);
        let seg_user_start = map_base_user + vaddr.align_down_4k();
        let seg_paddr = vdso_paddr_page + vaddr.align_down_4k();

        mappings.push(VdsoMapping {
            user_start: seg_user_start,
            paddr: seg_paddr,
            size: seg_align_size,
            flags: segment_flags(ph),
        });
    }
    Ok(mappings)
}

fn find_symbol_offset(elf_bytes: &[u8], symbol_name: &str) -> Option<usize> {
    use xmas_elf::symbol_table::Entry;
    let elf = xmas_elf::ElfFile::new(elf_bytes).ok()?;
    
    // Find the symbol table (either SHT_DYNSYM or SHT_SYMTAB)
    for section in elf.section_iter() {
        let sh_type = section.get_type().ok()?;
        if sh_type == xmas_elf::sections::ShType::DynSym || sh_type == xmas_elf::sections::ShType::SymTab {
            let data = section.get_data(&elf).ok()?;
            match data {
                xmas_elf::sections::SectionData::SymbolTable32(entries) => {
                    for entry in entries {
                        if let Ok(name) = entry.get_name(&elf) {
                            if name == symbol_name {
                                return Some(entry.value() as usize);
                            }
                        }
                    }
                }
                xmas_elf::sections::SectionData::SymbolTable64(entries) => {
                    for entry in entries {
                        if let Ok(name) = entry.get_name(&elf) {
                            if name == symbol_name {
                                return Some(entry.value() as usize);
                            }
                        }
                    }
                }
                xmas_elf::sections::SectionData::DynSymbolTable32(entries) => {
                    for entry in entries {
                        if let Ok(name) = entry.get_name(&elf) {
                            if name == symbol_name {
                                return Some(entry.value() as usize);
                            }
                        }
                    }
                }
                xmas_elf::sections::SectionData::DynSymbolTable64(entries) => {
                    for entry in entries {
                        if let Ok(name) = entry.get_name(&elf) {
                            if name == symbol_name {
                                return Some(entry.value() as usize);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }
    None
}

#[cfg(not(target_arch = "x86_64"))]
pub fn get_trampoline_addr(auxv: &[AuxEntry]) -> Option<usize> {
    let vdso_base = auxv
        .iter()
        .find(|entry| entry.get_type() == AuxType::SYSINFO_EHDR)
        .map(|entry| entry.value());

    if vdso_base.is_none() {
        warn!("get_trampoline_addr: AT_SYSINFO_EHDR not found in auxv");
        return None;
    }
    let vdso_base = vdso_base.unwrap();
    debug!("get_trampoline_addr: found vdso_base={:#x}", vdso_base);

    let mut sigreturn_offset: Option<usize> = None;

    unsafe {
        unsafe extern "C" {
            static vdso_start: u8;
            static vdso_end: u8;
        }
        let (start, end) = (
            &vdso_start as *const u8 as usize,
            &vdso_end as *const u8 as usize,
        );
        if end > start {
            let vdso_bytes = core::slice::from_raw_parts(&vdso_start as *const u8, end - start);
            sigreturn_offset = find_symbol_offset(vdso_bytes, "__vdso_rt_sigreturn");
            if sigreturn_offset.is_none() {
                warn!("__vdso_rt_sigreturn not found in vDSO ELF, falling back to config offset");
                sigreturn_offset = Some(crate::config::SIGRETURN_SYM_OFFSET);
            }
        }
    }

    let sigreturn_offset = sigreturn_offset.unwrap_or_default();
    let addr = vdso_base + sigreturn_offset;
    debug!(
        "get_trampoline_addr: vdso_base={:#x}, offset={:#x}, result={:#x}",
        vdso_base, sigreturn_offset, addr
    );
    Some(addr)
}

#[cfg(target_arch = "x86_64")]
pub fn get_trampoline_addr(_auxv: &[AuxEntry]) -> Option<usize> {
    None
}
