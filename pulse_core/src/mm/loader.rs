use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};

use axerrno::{AxError, AxResult};
use axfs::{CachedFile, File, FileFlags};
use axhal::{mem::MemRegionFlags, paging::MappingFlags};
use axmm::AddrSpace;
use kernel_elf_parser::{AuxEntry, AuxType, ELFHeadersBuilder, ELFParser, app_stack_region};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};
use xmas_elf::{
    ElfFile,
    header::{Machine, Type as ElfType},
    program::Type,
};

use crate::config::{USER_INTERP_BASE, USER_STACK_TOP};

const USER_DYN_BASE: usize = 0x20_0000;
const ELF_MACHINE_LOONGARCH: u16 = 0x102;
const ELF_CACHE_MAX_ENTRIES: usize = 16;

struct CachedElfImage {
    prefix: Vec<u8>,
    file: CachedFile,
}

impl CachedElfImage {
    fn bytes(&self) -> &[u8] {
        self.prefix.as_slice()
    }
}

static ELF_FILE_CACHE: spin::Mutex<Vec<(String, Arc<CachedElfImage>)>> =
    spin::Mutex::new(Vec::new());

pub struct UserAppLoadInfo {
    pub entry: usize,
    pub user_sp: usize,
    pub signal_trampoline: usize,
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
    let min_page = elf
        .program_iter()
        .filter(|ph| ph.get_type() == Ok(Type::Load) && ph.mem_size() != 0)
        .map(|ph| VirtAddr::from(ph.virtual_addr() as usize).align_down_4k())
        .min()
        .ok_or(AxError::InvalidExecutable)?
        .as_usize();
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

fn vdso_segment_flags(flags: MemRegionFlags) -> MappingFlags {
    let mut map_flags = MappingFlags::USER;
    if flags.contains(MemRegionFlags::READ) {
        map_flags |= MappingFlags::READ;
    }
    if flags.contains(MemRegionFlags::WRITE) {
        map_flags |= MappingFlags::WRITE;
    }
    if flags.contains(MemRegionFlags::EXECUTE) {
        map_flags |= MappingFlags::EXECUTE;
    }
    map_flags
}

pub fn prefault_range(
    aspace: &mut AddrSpace,
    start_vaddr: VirtAddr,
    size: usize,
    flags: MappingFlags,
) -> AxResult<()> {
    if size == 0 {
        return Ok(());
    }
    let end_vaddr = start_vaddr.checked_add(size).ok_or(AxError::OutOfRange)?;
    let pages = memory_addr::PageIter4K::new(start_vaddr.align_down_4k(), end_vaddr.align_up_4k())
        .ok_or(AxError::BadAddress)?;
    for page in pages {
        let mut access_flags = axhal::trap::PageFaultFlags::USER;
        if flags.contains(MappingFlags::READ) {
            access_flags |= axhal::trap::PageFaultFlags::READ;
        }
        if flags.contains(MappingFlags::WRITE) {
            access_flags |= axhal::trap::PageFaultFlags::WRITE;
        }
        if flags.contains(MappingFlags::EXECUTE) {
            access_flags |= axhal::trap::PageFaultFlags::EXECUTE;
        }

        let mut done = false;
        match aspace.handle_page_fault(page, access_flags) {
            axmm::PageFaultResult::Handled(ok) => {
                if !ok {
                    return Err(AxError::BadAddress);
                }
                done = true;
            }
            axmm::PageFaultResult::NeedWriteLock => {}
        }
        if !done {
            if !aspace.handle_page_fault_write(page, access_flags) {
                return Err(AxError::BadAddress);
            }
        }
    }
    Ok(())
}

fn load_segments(
    aspace: &mut AddrSpace,
    elf: &ElfFile<'_>,
    elf_file: &CachedFile,
    path: &str,
    bias: usize,
) -> AxResult {
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Load) {
            continue;
        }

        let p_offset = ph.offset() as usize;
        let p_filesz = ph.file_size() as usize;
        let p_memsz = ph.mem_size() as usize;

        if p_memsz == 0 {
            continue;
        }
        if p_filesz > p_memsz {
            return Err(AxError::InvalidExecutable);
        }
        let p_vaddr = VirtAddr::from(ph.virtual_addr() as usize)
            .checked_add(bias)
            .ok_or(AxError::OutOfRange)?;
        if p_offset.align_offset_4k() != p_vaddr.align_offset_4k() {
            return Err(AxError::InvalidExecutable);
        }

        let seg_start_page = p_vaddr.align_down_4k();
        let file_start_page = p_offset.align_down_4k();
        let seg_end = p_vaddr.checked_add(p_memsz).ok_or(AxError::OutOfRange)?;
        let file_backed_end = p_vaddr.checked_add(p_filesz).ok_or(AxError::OutOfRange)?;
        let file_backed_end_page = file_backed_end.align_up_4k();
        let seg_end_page = seg_end.align_up_4k();
        let flags = segment_flags(&ph);

        if ph.flags().is_write() {
            let seg_len = seg_end_page - seg_start_page;
            aspace.map_alloc(seg_start_page, seg_len, flags, true)?;
            if p_filesz > 0 {
                let file_buf = read_elf_range(path, p_offset as u64, p_filesz)?;
                write_user_region(aspace, p_vaddr, &file_buf)?;
            }
        } else {
            if p_filesz > 0 {
                let file_bytes = file_backed_end.sub_addr(seg_start_page);
                let map_len = file_backed_end_page - seg_start_page;
                aspace.map_file(
                    seg_start_page,
                    map_len,
                    flags,
                    elf_file.clone(),
                    file_flags_for_segment(&ph),
                    file_start_page,
                    file_bytes,
                    false, // ELF segments are private mappings
                )?;
                prefault_range(aspace, seg_start_page, map_len, flags)?;
            }

            if seg_end_page > file_backed_end_page {
                let map_len = seg_end_page - file_backed_end_page;
                aspace.map_alloc(
                    file_backed_end_page,
                    map_len,
                    flags,
                    false,
                )?;
                prefault_range(aspace, file_backed_end_page, map_len, flags)?;
            }
        }
    }
    Ok(())
}

fn write_user_region(aspace: &mut AddrSpace, start: VirtAddr, bytes: &[u8]) -> AxResult<()> {
    if let Ok(()) = aspace.write(start, bytes) {
        return Ok(());
    }

    let end = start.checked_add(bytes.len()).ok_or(AxError::OutOfRange)?;
    let pages = memory_addr::PageIter4K::new(start.align_down_4k(), end.align_up_4k())
        .ok_or(AxError::BadAddress)?;
    for page in pages {
        let pf_flags = axhal::trap::PageFaultFlags::WRITE | axhal::trap::PageFaultFlags::USER;
        match aspace.handle_page_fault(page, pf_flags) {
            axmm::PageFaultResult::Handled(ok) => {
                if !ok {
                    return Err(AxError::BadAddress);
                }
            }
            axmm::PageFaultResult::NeedWriteLock => {
                if !aspace.handle_page_fault_write(page, pf_flags) {
                    return Err(AxError::BadAddress);
                }
            }
        }
    }
    aspace.write(start, bytes).map_err(|e| AxError::from(e))
}

fn file_flags_for_segment(ph: &xmas_elf::program::ProgramHeader<'_>) -> FileFlags {
    let mut flags = FileFlags::READ;
    if ph.flags().is_write() {
        flags |= FileFlags::WRITE;
    }
    if ph.flags().is_execute() {
        flags |= FileFlags::EXECUTE;
    }
    flags
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
    #[cfg(target_arch = "loongarch64")]
    auxv.push(AuxEntry::new(
        AuxType::HWCAP,
        (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3),
    ));
    #[cfg(target_arch = "riscv64")]
    auxv.push(AuxEntry::new(
        AuxType::HWCAP,
        (1 << 0) | (1 << 2) | (1 << 3) | (1 << 5) | (1 << 6) | (1 << 8) | (1 << 12),
    ));
    Ok(auxv)
}

fn get_from_cache(path: &str) -> Option<Arc<CachedElfImage>> {
    ELF_FILE_CACHE
        .lock()
        .iter()
        .find(|(p, _)| p == path)
        .map(|(_, d)| d.clone())
}

fn invalidate_cache(path: &str) {
    let mut cache = ELF_FILE_CACHE.lock();
    if let Some(pos) = cache.iter().position(|(p, _)| p == path) {
        cache.remove(pos);
    }
}

fn compute_needed_prefix_len(prefix: &[u8]) -> AxResult<usize> {
    let hdr_builder = ELFHeadersBuilder::new(prefix).map_err(|_| AxError::InvalidExecutable)?;
    let ph_range = hdr_builder.ph_range();
    let mut needed = usize::try_from(ph_range.end).map_err(|_| AxError::InvalidExecutable)?;
    if needed > prefix.len() {
        return Ok(needed);
    }

    let elf = ElfFile::new(prefix).map_err(|_| AxError::InvalidExecutable)?;
    for ph in elf.program_iter() {
        if ph.get_type() != Ok(Type::Interp) {
            continue;
        }
        let interp_end = (ph.offset() as usize)
            .checked_add(ph.file_size() as usize)
            .ok_or(AxError::InvalidExecutable)?;
        needed = needed.max(interp_end);
    }
    Ok(needed)
}

fn validate_cached_image(path: &str, image: &CachedElfImage) -> bool {
    match compute_needed_prefix_len(image.bytes()) {
        Ok(needed) if needed <= image.bytes().len() => true,
        _ => {
            axlog::warn!("invalidating ELF cache entry: {}", path);
            false
        }
    }
}

fn put_into_cache(path: &str, data: Arc<CachedElfImage>) {
    let mut cache = ELF_FILE_CACHE.lock();
    if let Some((_, entry)) = cache.iter_mut().find(|(p, _)| p == path) {
        *entry = data;
        return;
    }
    if cache.len() >= ELF_CACHE_MAX_ENTRIES {
        cache.remove(0);
    }
    cache.push((path.to_string(), data));
}

fn read_elf_file(path: &str) -> AxResult<Arc<CachedElfImage>> {
    if let Some(image) = get_from_cache(path) {
        if validate_cached_image(path, &image) {
            return Ok(image);
        }
        invalidate_cache(path);
    }

    let fs_ctx = {
        let guard = axfs::FS_CONTEXT.lock();
        guard.clone()
    };

    let location = fs_ctx.resolve(path).map_err(|_| AxError::NotFound)?;
    let mut prefix = fs_ctx
        .read_prefix(path, PAGE_SIZE_4K)
        .map_err(|_| AxError::NotFound)?;
    let mut needed = compute_needed_prefix_len(&prefix)?;
    if needed > prefix.len() {
        prefix = fs_ctx
            .read_prefix(path, needed)
            .map_err(|_| AxError::NotFound)?;
        needed = compute_needed_prefix_len(&prefix)?;
    }
    if needed > prefix.len() {
        return Err(AxError::InvalidExecutable);
    }

    let image = Arc::new(CachedElfImage {
        prefix,
        file: CachedFile::get_or_create(location),
    });

    if !validate_cached_image(path, &image) {
        return Err(AxError::InvalidExecutable);
    }

    put_into_cache(path, image.clone());
    Ok(image)
}

fn read_elf_range(path: &str, offset: u64, len: usize) -> AxResult<Vec<u8>> {
    let fs_ctx = {
        let guard = axfs::FS_CONTEXT.lock();
        guard.clone()
    };
    let file = File::open(&fs_ctx, path).map_err(|_| AxError::NotFound)?;
    let mut buf = vec![0u8; len];
    let read = file
        .read_at(&mut buf[..], offset)
        .map_err(|_| AxError::InvalidExecutable)?;
    if read == len {
        return Ok(buf);
    }

    let whole = fs_ctx.read(path).map_err(|_| AxError::NotFound)?;
    let start = usize::try_from(offset).map_err(|_| AxError::InvalidExecutable)?;
    let end = start.checked_add(len).ok_or(AxError::InvalidExecutable)?;
    if end > whole.len() {
        axlog::error!(
            "short read while loading {}: offset={:#x} size={:#x} read={:#x} whole_len={:#x}",
            path,
            offset,
            len,
            read,
            whole.len()
        );
        return Err(AxError::InvalidExecutable);
    }
    Ok(whole[start..end].to_vec())
}

pub fn load_user_app(
    aspace: &mut AddrSpace,
    path: &str,
    args: &[&str],
    envs: &[&str],
) -> AxResult<UserAppLoadInfo> {
    let main_image = read_elf_file(path)?;
    let main_data = main_image.bytes();
    if main_data.is_empty() {
        return Err(AxError::InvalidExecutable);
    }
    let main_elf = ElfFile::new(main_data).map_err(|_| AxError::InvalidExecutable)?;
    validate_machine(&main_elf, path)?;

    let main_bias = match main_elf.header.pt2.type_().as_type() {
        ElfType::Executable => 0,
        ElfType::SharedObject => compute_load_bias(&main_elf, USER_DYN_BASE)?,
        _ => return Err(AxError::InvalidExecutable),
    };
    load_segments(aspace, &main_elf, &main_image.file, path, main_bias)?;
    let main_entry = VirtAddr::from(main_elf.header.pt2.entry_point() as usize)
        .checked_add(main_bias)
        .ok_or(AxError::OutOfRange)?;

    let interp_path = read_interp_path(&main_elf, main_data)?;
    if main_elf.header.pt2.type_().as_type() == ElfType::SharedObject && interp_path.is_none() {
        axlog::error!("ET_DYN executable {} has no PT_INTERP", path);
        return Err(AxError::Unsupported);
    }

    let mut interp_base = None;
    let mut dispatch_entry = main_entry;

    if let Some(interp_path) = interp_path {
        let interp_image = read_elf_file(&interp_path)?;
        let interp_data = interp_image.bytes();
        if interp_data.is_empty() {
            return Err(AxError::InvalidExecutable);
        }
        let interp_elf = ElfFile::new(interp_data).map_err(|_| AxError::InvalidExecutable)?;
        validate_machine(&interp_elf, &interp_path)?;

        let bias = match interp_elf.header.pt2.type_().as_type() {
            ElfType::Executable => 0,
            ElfType::SharedObject => compute_load_bias(&interp_elf, USER_INTERP_BASE)?,
            _ => return Err(AxError::InvalidExecutable),
        };
        load_segments(aspace, &interp_elf, &interp_image.file, &interp_path, bias)?;
        interp_base = Some(bias);
        dispatch_entry = VirtAddr::from(interp_elf.header.pt2.entry_point() as usize)
            .checked_add(bias)
            .ok_or(AxError::OutOfRange)?;
        axlog::debug!(
            "Loaded interpreter {} at bias={:#x}, entry={:#x}",
            interp_path,
            bias,
            dispatch_entry.as_usize()
        );
    }

    let mut auxv = build_auxv(main_data, main_bias, interp_base)?;
    let mut vdso_data = starry_vdso::vdso::load_vdso_data(&mut auxv)?;
    for mapping in &vdso_data.mappings {
        aspace.map_linear(
            VirtAddr::from(mapping.user_start),
            mapping.paddr,
            mapping.size,
            vdso_segment_flags(mapping.flags),
        )?;
    }
    vdso_data.disarm();
    let vdso_trampoline =
        starry_vdso::vdso::get_trampoline_addr(&auxv).ok_or(AxError::InvalidExecutable)?;
    auxv.push(AuxEntry::new(AuxType::NULL, 0));
    let argv: Vec<String> = if args.is_empty() {
        alloc::vec![path.to_string()]
    } else {
        args.iter().map(|a| (*a).to_string()).collect()
    };
    let envs_vec: Vec<String> = envs.iter().map(|e| (*e).to_string()).collect();

    let stack_region = app_stack_region(&argv, &envs_vec, &auxv, USER_STACK_TOP);
    let user_sp = VirtAddr::from(USER_STACK_TOP)
        .checked_sub(stack_region.len())
        .ok_or(AxError::OutOfRange)?;
    write_user_region(aspace, user_sp, &stack_region)?;
    Ok(UserAppLoadInfo {
        entry: dispatch_entry.as_usize(),
        user_sp: user_sp.as_usize(),
        signal_trampoline: vdso_trampoline,
    })
}
