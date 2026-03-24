use alloc::string::{String, ToString};
use alloc::vec::Vec;

use axerrno::{AxError, AxResult};
use axhal::paging::MappingFlags;
use axmm::AddrSpace;
use kernel_elf_parser::{AuxEntry, AuxType, ELFHeadersBuilder, ELFParser, app_stack_region};
use memory_addr::VirtAddr;
use xmas_elf::ElfFile;
use xmas_elf::header::{Machine, Type as ElfType};
use xmas_elf::program::Type;

use crate::config::{USER_INTERP_BASE, USER_STACK_TOP};

const PAGE_SIZE_4K: usize = 0x1000;
const USER_DYN_BASE: usize = 0x20_0000;
const ELF_MACHINE_LOONGARCH: u16 = 0x102;

pub struct UserAppLoadInfo {
    pub entry: usize,
    pub user_sp: usize,
}

fn align_down_4k(v: usize) -> usize {
    v & !0xfff
}

fn align_up_4k(v: usize) -> AxResult<usize> {
    v.checked_add(0xfff)
        .ok_or(AxError::OutOfRange)
        .map(|x| x & !0xfff)
}

fn validate_machine(elf: &ElfFile<'_>, path: &str) -> AxResult {
    let machine = elf.header.pt2.machine().as_machine();
    let ok = match machine {
        Machine::RISC_V => cfg!(target_arch = "riscv64"),
        Machine::Other(v) if v == ELF_MACHINE_LOONGARCH => cfg!(target_arch = "loongarch64"),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        axlog::error!(
            "ELF machine {:?} of {} does not match current arch",
            machine,
            path
        );
        Err(AxError::InvalidExecutable)
    }
}

fn compute_load_bias(elf: &ElfFile<'_>, desired_base: usize) -> AxResult<usize> {
    let mut min_vaddr: Option<usize> = None;
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) || ph.mem_size() == 0 {
            continue;
        }
        let vaddr = ph.virtual_addr() as usize;
        min_vaddr = Some(match min_vaddr {
            Some(old) => old.min(vaddr),
            None => vaddr,
        });
    }
    let min_vaddr = min_vaddr.ok_or(AxError::InvalidExecutable)?;
    let min_page = align_down_4k(min_vaddr);
    desired_base
        .checked_sub(min_page)
        .ok_or(AxError::InvalidExecutable)
}

fn segment_flags(ph: &xmas_elf::program::ProgramHeader<'_>) -> MappingFlags {
    let mut map_flags = MappingFlags::USER;
    if ph.flags().is_read() {
        map_flags |= MappingFlags::READ;
    }
    if ph.flags().is_write() {
        map_flags |= MappingFlags::WRITE;
    }
    if ph.flags().is_execute() {
        map_flags |= MappingFlags::EXECUTE;
    }
    map_flags
}

fn load_segments(
    aspace: &mut AddrSpace,
    elf: &ElfFile<'_>,
    elf_data: &[u8],
    bias: usize,
) -> AxResult {
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) {
            continue;
        }

        let p_offset = ph.offset() as usize;
        let p_vaddr = (ph.virtual_addr() as usize)
            .checked_add(bias)
            .ok_or(AxError::OutOfRange)?;
        let p_filesz = ph.file_size() as usize;
        let p_memsz = ph.mem_size() as usize;

        if p_memsz == 0 {
            continue;
        }
        if p_filesz > p_memsz {
            return Err(AxError::InvalidExecutable);
        }

        let seg_end = p_offset
            .checked_add(p_filesz)
            .ok_or(AxError::InvalidExecutable)?;
        if seg_end > elf_data.len() {
            return Err(AxError::InvalidExecutable);
        }

        let seg_start_page = align_down_4k(p_vaddr);
        let seg_end = p_vaddr.checked_add(p_memsz).ok_or(AxError::OutOfRange)?;
        let seg_end_page = align_up_4k(seg_end)?;
        let map_size = seg_end_page - seg_start_page;

        aspace.map_alloc(
            VirtAddr::from_usize(seg_start_page),
            map_size,
            segment_flags(&ph),
            true,
        )?;

        if p_filesz > 0 {
            aspace.write(
                VirtAddr::from_usize(p_vaddr),
                &elf_data[p_offset..p_offset + p_filesz],
            )?;
        }

        let bss_size = p_memsz - p_filesz;
        if bss_size > 0 {
            let zero = [0u8; PAGE_SIZE_4K];
            let mut left = bss_size;
            let mut cur = p_vaddr.checked_add(p_filesz).ok_or(AxError::OutOfRange)?;
            while left > 0 {
                let n = left.min(zero.len());
                aspace.write(VirtAddr::from_usize(cur), &zero[..n])?;
                cur = cur.checked_add(n).ok_or(AxError::OutOfRange)?;
                left -= n;
            }
        }
    }
    Ok(())
}

fn read_interp_path<'a>(elf: &ElfFile<'a>, elf_data: &'a [u8]) -> AxResult<Option<String>> {
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Interp) {
            continue;
        }
        let off = ph.offset() as usize;
        let size = ph.file_size() as usize;
        if size == 0 {
            return Err(AxError::InvalidExecutable);
        }
        let end = off.checked_add(size).ok_or(AxError::InvalidExecutable)?;
        if end > elf_data.len() {
            return Err(AxError::InvalidExecutable);
        }
        let raw = &elf_data[off..end];
        let nul = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
        let s = core::str::from_utf8(&raw[..nul]).map_err(|_| AxError::InvalidExecutable)?;
        if s.is_empty() {
            return Err(AxError::InvalidExecutable);
        }
        return Ok(Some(s.to_string()));
    }
    Ok(None)
}

fn build_auxv(
    main_elf_data: &[u8],
    main_bias: usize,
    interp_base: Option<usize>,
) -> AxResult<Vec<AuxEntry>> {
    let hdr_builder =
        ELFHeadersBuilder::new(main_elf_data).map_err(|_| AxError::InvalidExecutable)?;
    let ph_range = hdr_builder.ph_range();
    let start = usize::try_from(ph_range.start).map_err(|_| AxError::InvalidExecutable)?;
    let end = usize::try_from(ph_range.end).map_err(|_| AxError::InvalidExecutable)?;
    if end > main_elf_data.len() || start > end {
        return Err(AxError::InvalidExecutable);
    }
    let headers = hdr_builder
        .build(&main_elf_data[start..end])
        .map_err(|_| AxError::InvalidExecutable)?;
    let parser = ELFParser::new(&headers, main_bias).map_err(|_| AxError::InvalidExecutable)?;

    let mut auxv: Vec<AuxEntry> = parser.aux_vector(PAGE_SIZE_4K, interp_base).collect();
    auxv.push(AuxEntry::new(AuxType::NULL, 0));
    Ok(auxv)
}

pub fn load_user_app(
    aspace: &mut AddrSpace,
    path: &str,
    args: &[&str],
) -> AxResult<UserAppLoadInfo> {
    let main_data = axfs::api::read(path).map_err(|_| AxError::NotFound)?;
    let main_elf = ElfFile::new(&main_data).map_err(|_| AxError::InvalidExecutable)?;
    validate_machine(&main_elf, path)?;

    let main_bias = match main_elf.header.pt2.type_().as_type() {
        ElfType::Executable => 0,
        ElfType::SharedObject => compute_load_bias(&main_elf, USER_DYN_BASE)?,
        _ => return Err(AxError::InvalidExecutable),
    };
    load_segments(aspace, &main_elf, &main_data, main_bias)?;
    let main_entry = (main_elf.header.pt2.entry_point() as usize)
        .checked_add(main_bias)
        .ok_or(AxError::OutOfRange)?;

    let interp_path = read_interp_path(&main_elf, &main_data)?;
    if main_elf.header.pt2.type_().as_type() == ElfType::SharedObject && interp_path.is_none() {
        axlog::error!("ET_DYN executable {} has no PT_INTERP", path);
        return Err(AxError::Unsupported);
    }

    let mut interp_base = None;
    let mut dispatch_entry = main_entry;

    if let Some(interp_path) = interp_path {
        let interp_data = axfs::api::read(&interp_path).map_err(|_| AxError::NotFound)?;
        let interp_elf = ElfFile::new(&interp_data).map_err(|_| AxError::InvalidExecutable)?;
        validate_machine(&interp_elf, &interp_path)?;

        let bias = match interp_elf.header.pt2.type_().as_type() {
            ElfType::Executable => 0,
            ElfType::SharedObject => compute_load_bias(&interp_elf, USER_INTERP_BASE)?,
            _ => return Err(AxError::InvalidExecutable),
        };
        load_segments(aspace, &interp_elf, &interp_data, bias)?;
        interp_base = Some(bias);
        dispatch_entry = (interp_elf.header.pt2.entry_point() as usize)
            .checked_add(bias)
            .ok_or(AxError::OutOfRange)?;
        axlog::info!(
            "Loaded interpreter {} at bias={:#x}, entry={:#x}",
            interp_path,
            bias,
            dispatch_entry
        );
    }

    let auxv = build_auxv(&main_data, main_bias, interp_base)?;
    let mut argv: Vec<String> = Vec::new();
    argv.push(path.to_string());
    for a in args {
        argv.push(a.to_string());
    }
    let envs: [String; 0] = [];
    let stack_region = app_stack_region(&argv, &envs, &auxv, USER_STACK_TOP);
    let user_sp = USER_STACK_TOP
        .checked_sub(stack_region.len())
        .ok_or(AxError::OutOfRange)?;
    aspace.write(VirtAddr::from_usize(user_sp), &stack_region)?;

    Ok(UserAppLoadInfo {
        entry: dispatch_entry,
        user_sp,
    })
}
