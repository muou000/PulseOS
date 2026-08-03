use alloc::{
    collections::VecDeque,
    string::{String, ToString},
    sync::Arc,
    vec,
    vec::Vec,
};
use core::mem::size_of;

use axerrno::{AxError, AxResult};
use axfs::{CachedFile, ExecAccessGuard, FileFlags, FsContext};
use axhal::{mem::MemRegionFlags, paging::MappingFlags};
use axmm::AddrSpace;
use kernel_elf_parser::{AuxEntry, AuxType, ELFHeadersBuilder, ELFParser};
use linux_raw_sys::elf_uapi::{EM_LOONGARCH, PT_GNU_STACK};
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr, VirtAddrRange};
use xmas_elf::{
    ElfFile,
    header::{Machine, Type as ElfType},
    program::Type,
};

use crate::config::{USER_HEAP_BASE, USER_STACK_SIZE, USER_STACK_TOP};

const USER_DYN_BASE: usize = 0x20_0000;
const ELF_CACHE_MAX_ENTRIES: usize = 16;
const AT_RANDOM_BYTES: usize = 16;
const USER_STACK_ALIGNMENT: usize = 16;

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
    pub start_brk: usize,
    pub start_data: usize,
    pub end_data: usize,
    pub signal_trampoline: usize,
    pub exec_access: Vec<ExecAccessGuard>,
}

/// Process identity exposed to a freshly executed program through auxv.
#[derive(Clone, Copy, Debug)]
pub struct ExecCredentials {
    pub ruid: u32,
    pub euid: u32,
    pub rgid: u32,
    pub egid: u32,
}

impl ExecCredentials {
    pub const fn new(ruid: u32, euid: u32, rgid: u32, egid: u32) -> Self {
        Self {
            ruid,
            euid,
            rgid,
            egid,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct ElfLoadLayout {
    brk: usize,
    start_data: usize,
    end_data: usize,
}

#[derive(Clone, Copy, Debug)]
struct ElfLoadRequirements {
    min_page: usize,
    span: usize,
    max_align: usize,
}

impl ElfLoadRequirements {
    fn from_elf(elf: &ElfFile<'_>) -> AxResult<Self> {
        let mut min_page = usize::MAX;
        let mut max_page = 0;
        let mut max_align = PAGE_SIZE_4K;
        let mut has_load_segment = false;

        for ph in elf.program_iter() {
            if ph.get_type() != Ok(Type::Load) {
                continue;
            }

            let p_offset = usize::try_from(ph.offset()).map_err(|_| AxError::InvalidExecutable)?;
            let p_vaddr =
                usize::try_from(ph.virtual_addr()).map_err(|_| AxError::InvalidExecutable)?;
            let p_filesz =
                usize::try_from(ph.file_size()).map_err(|_| AxError::InvalidExecutable)?;
            let p_memsz = usize::try_from(ph.mem_size()).map_err(|_| AxError::InvalidExecutable)?;
            let p_align = usize::try_from(ph.align()).map_err(|_| AxError::InvalidExecutable)?;

            if p_filesz > p_memsz {
                return Err(AxError::InvalidExecutable);
            }
            p_offset
                .checked_add(p_filesz)
                .ok_or(AxError::InvalidExecutable)?;
            let seg_end = p_vaddr
                .checked_add(p_memsz)
                .ok_or(AxError::InvalidExecutable)?;

            if p_align > 1 {
                if !p_align.is_power_of_two() || p_offset % p_align != p_vaddr % p_align {
                    return Err(AxError::InvalidExecutable);
                }
            }
            if p_offset % PAGE_SIZE_4K != p_vaddr % PAGE_SIZE_4K {
                return Err(AxError::InvalidExecutable);
            }
            if p_memsz == 0 {
                continue;
            }
            if p_align > 1 {
                max_align = max_align.max(p_align);
            }

            let seg_start_page = p_vaddr & !(PAGE_SIZE_4K - 1);
            let seg_end_page =
                checked_align_up(seg_end, PAGE_SIZE_4K).ok_or(AxError::InvalidExecutable)?;
            min_page = min_page.min(seg_start_page);
            max_page = max_page.max(seg_end_page);
            has_load_segment = true;
        }

        if !has_load_segment {
            return Err(AxError::InvalidExecutable);
        }
        let span = max_page
            .checked_sub(min_page)
            .filter(|span| *span != 0)
            .ok_or(AxError::InvalidExecutable)?;
        Ok(Self {
            min_page,
            span,
            max_align,
        })
    }
}

fn checked_align_up(value: usize, align: usize) -> Option<usize> {
    debug_assert!(align.is_power_of_two());
    value
        .checked_add(align.checked_sub(1)?)
        .map(|value| value & !(align - 1))
}

fn validate_machine(elf: &ElfFile<'_>, path: &str) -> AxResult {
    let machine = elf.header.pt2.machine().as_machine();
    let ok = match machine {
        Machine::RISC_V => cfg!(target_arch = "riscv64"),
        Machine::Other(v) if v == (EM_LOONGARCH as u16) => cfg!(target_arch = "loongarch64"),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        axlog::warn!(
            "ELF machine {:?} of {} does not match current arch",
            machine,
            path
        );
        Err(AxError::InvalidExecutable)
    }
}

fn compute_load_bias(requirements: ElfLoadRequirements, mapping_start: usize) -> AxResult<usize> {
    let bias = mapping_start
        .checked_sub(requirements.min_page)
        .ok_or(AxError::InvalidExecutable)?;
    if bias % requirements.max_align != 0 || mapping_start.checked_add(requirements.span).is_none()
    {
        return Err(AxError::InvalidExecutable);
    }
    Ok(bias)
}

fn first_aligned_mapping_start(requirements: ElfLoadRequirements, hint: usize) -> AxResult<usize> {
    let hint = hint.max(requirements.min_page);
    let bias = hint
        .checked_sub(requirements.min_page)
        .ok_or(AxError::NoMemory)?;
    let aligned_bias = checked_align_up(bias, requirements.max_align).ok_or(AxError::NoMemory)?;
    requirements
        .min_page
        .checked_add(aligned_bias)
        .ok_or(AxError::NoMemory)
}

fn find_load_bias(
    aspace: &AddrSpace,
    requirements: ElfLoadRequirements,
    search_start: usize,
    search_end: usize,
) -> AxResult<usize> {
    let limit = VirtAddrRange::new(VirtAddr::from(search_start), VirtAddr::from(search_end));
    find_load_bias_in_window(requirements, search_start, search_end, |hint, size| {
        aspace
            .find_free_area(VirtAddr::from(hint), size, limit)
            .map(|start| start.as_usize())
    })
}

fn find_load_bias_in_window(
    requirements: ElfLoadRequirements,
    search_start: usize,
    search_end: usize,
    mut find_free_area: impl FnMut(usize, usize) -> Option<usize>,
) -> AxResult<usize> {
    let mut hint = first_aligned_mapping_start(requirements, search_start)?;

    loop {
        if !hint
            .checked_add(requirements.span)
            .is_some_and(|end| end <= search_end)
        {
            return Err(AxError::NoMemory);
        }
        let mapping_start = find_free_area(hint, requirements.span).ok_or(AxError::NoMemory)?;
        let aligned_start = first_aligned_mapping_start(requirements, mapping_start)?;
        if aligned_start == mapping_start {
            return compute_load_bias(requirements, mapping_start);
        }

        // The lower layer searches at page granularity. Advance within the
        // free range until the ELF load bias also satisfies p_align.
        hint = aligned_start;
    }
}

fn dynamic_load_window() -> (usize, usize) {
    (USER_DYN_BASE, USER_HEAP_BASE)
}

fn find_dynamic_load_bias(
    aspace: &AddrSpace,
    requirements: ElfLoadRequirements,
) -> AxResult<usize> {
    let (search_start, search_end) = dynamic_load_window();
    find_load_bias(aspace, requirements, search_start, search_end)
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

fn resolve_page_fault(
    aspace: &mut AddrSpace,
    page: VirtAddr,
    flags: axhal::trap::PageFaultFlags,
) -> AxResult<bool> {
    let mut outcome = aspace
        .handle_page_fault(page, flags)
        .complete_after_unlock()?;
    loop {
        outcome = match outcome {
            axmm::PageFaultOutcome::Handled(handled) => return Ok(handled),
            axmm::PageFaultOutcome::LoadFilePage(load) => {
                let mut prepared = load.prepare()?;
                aspace
                    .handle_prepared_file_page(page, flags, &mut prepared)
                    .complete_after_unlock()?
            }
            axmm::PageFaultOutcome::PrepareAnonPage(load) => {
                let mut prepared = load.prepare()?;
                aspace
                    .handle_prepared_anon_page(page, flags, &mut prepared)
                    .complete_after_unlock()?
            }
            axmm::PageFaultOutcome::RetryWithWriteLock => {
                let outcome = aspace
                    .handle_page_fault_write(page, flags)
                    .complete_after_unlock()?;
                if matches!(outcome, axmm::PageFaultOutcome::RetryWithWriteLock) {
                    return Err(AxError::BadState);
                }
                outcome
            }
        };
    }
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
    for (_page_idx, page) in pages.enumerate() {
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

        if !resolve_page_fault(aspace, page, access_flags)? {
            return Err(AxError::BadAddress);
        }
    }
    Ok(())
}

fn anonymous_segment_start(
    seg_start_page: VirtAddr,
    file_backed_end_page: VirtAddr,
    file_size: usize,
) -> VirtAddr {
    if file_size == 0 {
        seg_start_page
    } else {
        file_backed_end_page
    }
}

fn load_segments(
    aspace: &mut AddrSpace,
    elf: &ElfFile<'_>,
    elf_file: &CachedFile,
    bias: usize,
) -> AxResult<ElfLoadLayout> {
    let mut layout = ElfLoadLayout::default();
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

        if ph.flags().is_write() {
            if layout.start_data == 0 || p_vaddr.as_usize() < layout.start_data {
                layout.start_data = p_vaddr.as_usize();
            }
            layout.end_data = layout.end_data.max(file_backed_end.as_usize());
        }
        layout.brk = layout.brk.max(seg_end.as_usize());
        let file_backed_end_page = file_backed_end.align_up_4k();
        let seg_end_page = seg_end.align_up_4k();
        let flags = segment_flags(&ph);

        if p_filesz > 0 {
            let file_bytes = file_backed_end.sub_addr(seg_start_page);
            let map_len = file_backed_end_page - seg_start_page;
            let zero_len = file_backed_end_page.as_usize() - file_backed_end.as_usize();
            let zero_file_tail = zero_len > 0 && seg_end > file_backed_end;
            let load_flags = if zero_file_tail {
                flags | MappingFlags::WRITE
            } else {
                flags
            };
            aspace.map_file(
                seg_start_page,
                map_len,
                load_flags,
                elf_file.clone(),
                file_flags_for_segment(&ph),
                file_start_page,
                file_bytes,
                false, // ELF segments are private mappings
                None,
            )?;

            if zero_file_tail {
                let zeros = [0u8; PAGE_SIZE_4K];
                write_user_region(aspace, file_backed_end, &zeros[..zero_len])?;
                if load_flags != flags {
                    aspace
                        .protect(seg_start_page, map_len, flags)
                        .complete_after_unlock()?;
                }
            }
        }

        let anon_start = anonymous_segment_start(seg_start_page, file_backed_end_page, p_filesz);
        if seg_end_page > anon_start {
            let map_len = seg_end_page - anon_start;
            aspace.map_alloc(anon_start, map_len, flags, false)?;
        }
    }
    Ok(layout)
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
        if !resolve_page_fault(aspace, page, pf_flags)? {
            return Err(AxError::BadAddress);
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
    credentials: ExecCredentials,
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
    append_process_auxv(&mut auxv, credentials);
    Ok(auxv)
}

fn append_process_auxv(auxv: &mut Vec<AuxEntry>, credentials: ExecCredentials) {
    auxv.push(AuxEntry::new(AuxType::UID, credentials.ruid as usize));
    auxv.push(AuxEntry::new(AuxType::EUID, credentials.euid as usize));
    auxv.push(AuxEntry::new(AuxType::GID, credentials.rgid as usize));
    auxv.push(AuxEntry::new(AuxType::EGID, credentials.egid as usize));

    // PulseOS currently has no set-id or file-capability transition during
    // exec, so a successful exec never enters Linux's secure-execution mode.
    auxv.push(AuxEntry::new(AuxType::SECURE, 0));
}

fn initial_stack_mapping_flags(elf: &ElfFile<'_>) -> MappingFlags {
    let executable = elf
        .program_iter()
        .any(|ph| ph.get_type() == Ok(Type::OsSpecific(PT_GNU_STACK)) && ph.flags().is_execute());
    stack_mapping_flags(executable)
}

fn stack_mapping_flags(executable: bool) -> MappingFlags {
    let mut flags = MappingFlags::READ | MappingFlags::WRITE | MappingFlags::USER;
    if executable {
        flags |= MappingFlags::EXECUTE;
    }
    flags
}

struct InitialStackBuilder {
    data: VecDeque<u8>,
    stack_top: usize,
    stack_size: usize,
}

impl InitialStackBuilder {
    fn new(stack_top: usize, stack_size: usize) -> Self {
        Self {
            data: VecDeque::new(),
            stack_top,
            stack_size,
        }
    }

    fn current_sp(&self) -> usize {
        self.stack_top - self.data.len()
    }

    fn push_bytes(&mut self, bytes: &[u8]) -> AxResult<usize> {
        let new_len = self
            .data
            .len()
            .checked_add(bytes.len())
            .ok_or(AxError::NoMemory)?;
        if new_len > self.stack_size || new_len > self.stack_top {
            return Err(AxError::NoMemory);
        }
        for byte in bytes.iter().rev() {
            self.data.push_front(*byte);
        }
        Ok(self.current_sp())
    }

    fn push_c_string(&mut self, value: &str) -> AxResult<usize> {
        if value.as_bytes().contains(&0) {
            return Err(AxError::InvalidInput);
        }
        self.push_bytes(&[0])?;
        self.push_bytes(value.as_bytes())
    }

    fn push_word(&mut self, value: usize) -> AxResult<usize> {
        self.push_bytes(&value.to_ne_bytes())
    }

    fn push_auxv_entry(&mut self, entry: AuxEntry) -> AxResult<()> {
        self.push_word(entry.value())?;
        self.push_word(entry.get_type() as usize)?;
        Ok(())
    }

    fn into_vec(self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.data.len());
        let (first, second) = self.data.as_slices();
        result.extend_from_slice(first);
        result.extend_from_slice(second);
        result
    }
}

fn build_initial_stack(
    args: &[String],
    envs: &[String],
    auxv: &[AuxEntry],
    exec_path: &str,
    random_bytes: [u8; AT_RANDOM_BYTES],
    stack_top: usize,
    stack_size: usize,
) -> AxResult<Vec<u8>> {
    let mut stack = InitialStackBuilder::new(stack_top, stack_size);
    let random_ptr = stack.push_bytes(&random_bytes)?;
    let execfn_ptr = stack.push_c_string(exec_path)?;

    let mut env_ptrs = Vec::with_capacity(envs.len());
    for env in envs {
        env_ptrs.push(stack.push_c_string(env)?);
    }
    let mut argv_ptrs = Vec::with_capacity(args.len());
    for arg in args {
        argv_ptrs.push(stack.push_c_string(arg)?);
    }

    let mut stack_auxv = Vec::with_capacity(auxv.len().checked_add(3).ok_or(AxError::NoMemory)?);
    for entry in auxv {
        match entry.get_type() {
            AuxType::NULL | AuxType::RANDOM | AuxType::EXECFN => {}
            _ => stack_auxv.push(*entry),
        }
    }
    stack_auxv.push(AuxEntry::new(AuxType::RANDOM, random_ptr));
    stack_auxv.push(AuxEntry::new(AuxType::EXECFN, execfn_ptr));
    stack_auxv.push(AuxEntry::new(AuxType::NULL, 0));

    let control_words = argv_ptrs
        .len()
        .checked_add(env_ptrs.len())
        .and_then(|words| words.checked_add(3))
        .and_then(|words| {
            stack_auxv
                .len()
                .checked_mul(2)
                .and_then(|auxv_words| words.checked_add(auxv_words))
        })
        .ok_or(AxError::NoMemory)?;
    let control_bytes = control_words
        .checked_mul(size_of::<usize>())
        .ok_or(AxError::NoMemory)?;
    let unaligned_sp = stack
        .current_sp()
        .checked_sub(control_bytes)
        .ok_or(AxError::NoMemory)?;
    let padding = unaligned_sp % USER_STACK_ALIGNMENT;
    if padding != 0 {
        stack.push_bytes(&[0; USER_STACK_ALIGNMENT][..padding])?;
    }

    for entry in stack_auxv.iter().rev() {
        stack.push_auxv_entry(*entry)?;
    }
    stack.push_word(0)?;
    for ptr in env_ptrs.iter().rev() {
        stack.push_word(*ptr)?;
    }
    stack.push_word(0)?;
    for ptr in argv_ptrs.iter().rev() {
        stack.push_word(*ptr)?;
    }
    stack.push_word(argv_ptrs.len())?;

    if stack.current_sp() % USER_STACK_ALIGNMENT != 0 {
        return Err(AxError::BadState);
    }
    Ok(stack.into_vec())
}

fn read_at_random() -> [u8; AT_RANDOM_BYTES] {
    let mut random = [0; AT_RANDOM_BYTES];
    axfs::fill_random_bytes(&mut random);
    random
}

fn same_file(left: &axfs_ng_vfs::Location, right: &axfs_ng_vfs::Location) -> bool {
    let left_fs = left.filesystem() as *const dyn axfs_ng_vfs::FilesystemOps as *const ();
    let right_fs = right.filesystem() as *const dyn axfs_ng_vfs::FilesystemOps as *const ();
    left_fs == right_fs && left.inode() == right.inode()
}

fn get_from_cache(path: &str, location: &axfs_ng_vfs::Location) -> Option<Arc<CachedElfImage>> {
    ELF_FILE_CACHE
        .lock()
        .iter()
        .find(|(p, image)| p == path && same_file(image.file.location(), location))
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

fn read_prefix(file: &CachedFile, limit: usize) -> AxResult<Vec<u8>> {
    let size = axfs::cached_file_size(file.location()).map_err(|_| AxError::NotFound)?;
    let read_len = usize::try_from(size.min(limit as u64)).map_err(|_| AxError::OutOfRange)?;
    let mut prefix = vec![0u8; read_len];
    let read = file
        .read_at(&mut prefix[..], 0)
        .map_err(|_| AxError::NotFound)?;
    prefix.truncate(read);
    Ok(prefix)
}

fn read_elf_file_at(path: &str, location: axfs_ng_vfs::Location) -> AxResult<Arc<CachedElfImage>> {
    if let Some(image) = get_from_cache(path, &location) {
        if validate_cached_image(path, &image) {
            return Ok(image);
        }
    }
    invalidate_cache(path);

    let file = CachedFile::get_or_create(location)?;
    let mut prefix = read_prefix(&file, PAGE_SIZE_4K)?;
    let mut needed = compute_needed_prefix_len(&prefix)?;
    if needed > prefix.len() {
        prefix = read_prefix(&file, needed)?;
        needed = compute_needed_prefix_len(&prefix)?;
    }
    if needed > prefix.len() {
        return Err(AxError::InvalidExecutable);
    }

    let image = Arc::new(CachedElfImage { prefix, file });

    if !validate_cached_image(path, &image) {
        return Err(AxError::InvalidExecutable);
    }

    put_into_cache(path, image.clone());
    Ok(image)
}

fn read_elf_file(path: &str) -> AxResult<Arc<CachedElfImage>> {
    let fs_ctx = {
        let guard = axfs::FS_CONTEXT.lock();
        guard.clone()
    };
    let location = axtask::future::block_on(fs_ctx.resolve(path)).map_err(|_| AxError::NotFound)?;
    read_elf_file_at(path, location)
}

pub fn check_elf_header(path: &str) -> AxResult<()> {
    axlog::debug!("check_elf_header: path={:?}", path);
    let main_image = read_elf_file(path)?;
    let main_data = main_image.bytes();
    if main_data.is_empty() {
        return Err(AxError::InvalidExecutable);
    }
    let main_elf = ElfFile::new(main_data).map_err(|_| AxError::InvalidExecutable)?;
    validate_machine(&main_elf, path)?;
    let _ = ElfLoadRequirements::from_elf(&main_elf)?;

    // Check interpreter if present
    if let Some(interp_path) = read_interp_path(&main_elf, main_data)? {
        let interp_image = read_elf_file(&interp_path)?;
        let interp_data = interp_image.bytes();
        if interp_data.is_empty() {
            return Err(AxError::InvalidExecutable);
        }
        let interp_elf = ElfFile::new(interp_data).map_err(|_| AxError::InvalidExecutable)?;
        validate_machine(&interp_elf, &interp_path)?;
        let _ = ElfLoadRequirements::from_elf(&interp_elf)?;
    }
    Ok(())
}

pub fn load_user_app(
    aspace: &mut AddrSpace,
    fs: &FsContext,
    credentials: ExecCredentials,
    main_location: axfs_ng_vfs::Location,
    main_exec_access: ExecAccessGuard,
    path: &str,
    execfn_path: &str,
    args: &[&str],
    envs: &[&str],
) -> AxResult<UserAppLoadInfo> {
    let mut exec_access = vec![main_exec_access];
    let main_image = read_elf_file_at(path, main_location)?;
    let main_data = main_image.bytes();
    if main_data.is_empty() {
        return Err(AxError::InvalidExecutable);
    }
    let main_elf = ElfFile::new(main_data).map_err(|_| AxError::InvalidExecutable)?;
    validate_machine(&main_elf, path)?;
    let main_requirements = ElfLoadRequirements::from_elf(&main_elf)?;

    let main_bias = match main_elf.header.pt2.type_().as_type() {
        ElfType::Executable => 0,
        ElfType::SharedObject => find_dynamic_load_bias(aspace, main_requirements)?,
        _ => return Err(AxError::InvalidExecutable),
    };
    let main_layout = load_segments(aspace, &main_elf, &main_image.file, main_bias)?;
    let main_entry = VirtAddr::from(main_elf.header.pt2.entry_point() as usize)
        .checked_add(main_bias)
        .ok_or(AxError::OutOfRange)?;

    let interp_path = read_interp_path(&main_elf, main_data)?;
    // Linux permits an ET_DYN image to be executed directly. In particular,
    // `ld-linux-*.so.* --library-path ... program` has no PT_INTERP of its
    // own: the mapped main image remains the dispatch entry and AT_BASE is
    // intentionally absent from its auxiliary vector.

    let mut interp_base = None;
    let mut dispatch_entry = main_entry;

    if let Some(interp_path) = interp_path {
        let interp_location = axtask::future::block_on(fs.resolve(&interp_path))?;
        let interp_exec_access = axfs::acquire_exec_access(&interp_location)?;
        let interp_image = read_elf_file_at(&interp_path, interp_location)?;
        exec_access.push(interp_exec_access);
        let interp_data = interp_image.bytes();
        if interp_data.is_empty() {
            return Err(AxError::InvalidExecutable);
        }
        let interp_elf = ElfFile::new(interp_data).map_err(|_| AxError::InvalidExecutable)?;
        validate_machine(&interp_elf, &interp_path)?;
        let interp_requirements = ElfLoadRequirements::from_elf(&interp_elf)?;

        let bias = match interp_elf.header.pt2.type_().as_type() {
            ElfType::Executable => 0,
            // Main segments are already mapped, so the shared search window
            // selects a remaining non-overlapping hole for the interpreter.
            ElfType::SharedObject => find_dynamic_load_bias(aspace, interp_requirements)?,
            _ => return Err(AxError::InvalidExecutable),
        };
        let _ = load_segments(aspace, &interp_elf, &interp_image.file, bias)?;
        interp_base = Some(bias);
        dispatch_entry = VirtAddr::from(interp_elf.header.pt2.entry_point() as usize)
            .checked_add(bias)
            .ok_or(AxError::OutOfRange)?;
        let mapping_start = interp_requirements
            .min_page
            .checked_add(bias)
            .ok_or(AxError::OutOfRange)?;
        let mapping_end = mapping_start
            .checked_add(interp_requirements.span)
            .ok_or(AxError::OutOfRange)?;
        axlog::debug!(
            "Loaded interpreter {} in [{:#x}, {:#x}), bias={:#x}, align={:#x}, entry={:#x}",
            interp_path,
            mapping_start,
            mapping_end,
            bias,
            interp_requirements.max_align,
            dispatch_entry.as_usize()
        );
    }

    // Resolve the entry page while exec can still report an I/O failure, but
    // leave the rest of each PT_LOAD segment demand-paged. File-tail fixups and
    // the initial stack are populated separately only where the loader writes.
    prefault_range(
        aspace,
        dispatch_entry,
        1,
        MappingFlags::USER | MappingFlags::EXECUTE,
    )?;

    let mut auxv = build_auxv(main_data, main_bias, interp_base, credentials)?;
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
    let argv: Vec<String> = if args.is_empty() {
        alloc::vec![path.to_string()]
    } else {
        args.iter().map(|a| (*a).to_string()).collect()
    };
    let envs_vec: Vec<String> = envs.iter().map(|e| (*e).to_string()).collect();

    let stack_region = build_initial_stack(
        &argv,
        &envs_vec,
        &auxv,
        execfn_path,
        read_at_random(),
        USER_STACK_TOP,
        USER_STACK_SIZE,
    )?;
    let user_sp = VirtAddr::from(USER_STACK_TOP)
        .checked_sub(stack_region.len())
        .ok_or(AxError::OutOfRange)?;
    write_user_region(aspace, user_sp, &stack_region)?;
    aspace
        .protect(
            VirtAddr::from(USER_STACK_TOP - USER_STACK_SIZE),
            USER_STACK_SIZE,
            initial_stack_mapping_flags(&main_elf),
        )
        .complete_after_unlock()?;
    let start_brk = VirtAddr::from(main_layout.brk)
        .align_up_4k()
        .as_usize()
        .max(USER_HEAP_BASE);
    Ok(UserAppLoadInfo {
        entry: dispatch_entry.as_usize(),
        user_sp: user_sp.as_usize(),
        start_brk,
        start_data: main_layout.start_data,
        end_data: main_layout.end_data,
        signal_trampoline: vdso_trampoline,
        exec_access,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_word(bytes: &[u8], offset: &mut usize) -> usize {
        let end = *offset + size_of::<usize>();
        let mut word = [0; size_of::<usize>()];
        word.copy_from_slice(&bytes[*offset..end]);
        *offset = end;
        usize::from_ne_bytes(word)
    }

    fn bytes_at(bytes: &[u8], stack_top: usize, pointer: usize) -> &[u8] {
        let stack_base = stack_top - bytes.len();
        &bytes[pointer - stack_base..]
    }

    #[test]
    fn main_pie_alignment_search_handles_nonzero_min_page() {
        let requirements = ElfLoadRequirements {
            min_page: PAGE_SIZE_4K,
            span: PAGE_SIZE_4K,
            max_align: 0x20_0000,
        };

        let mapping_start = first_aligned_mapping_start(requirements, USER_DYN_BASE).unwrap();
        assert_eq!(mapping_start, USER_DYN_BASE + PAGE_SIZE_4K);
        assert_eq!(
            compute_load_bias(requirements, mapping_start).unwrap(),
            USER_DYN_BASE
        );
    }

    #[test]
    fn loongarch_rust_lld_span_fits_dynamic_load_window() {
        let main_requirements = ElfLoadRequirements {
            min_page: 0,
            span: 0x932_a000,
            max_align: 0x10_000,
        };
        let (search_start, search_end) = dynamic_load_window();
        assert!(matches!(
            find_load_bias_in_window(main_requirements, USER_DYN_BASE, 0x400_0000, |hint, _| {
                Some(hint)
            }),
            Err(AxError::NoMemory)
        ));
        let main_bias =
            find_load_bias_in_window(main_requirements, search_start, search_end, |hint, _| {
                Some(hint)
            })
            .unwrap();
        let main_start = main_requirements.min_page.checked_add(main_bias).unwrap();
        let main_end = main_start.checked_add(main_requirements.span).unwrap();

        let interpreter_requirements = ElfLoadRequirements {
            min_page: 0,
            span: 0x42_000,
            max_align: 0x10_000,
        };
        let interpreter_bias = find_load_bias_in_window(
            interpreter_requirements,
            search_start,
            search_end,
            |hint, size| {
                let candidate = hint.max(main_end);
                candidate
                    .checked_add(size)
                    .filter(|end| *end <= search_end)
                    .map(|_| candidate)
            },
        )
        .unwrap();
        let interpreter_start = interpreter_requirements
            .min_page
            .checked_add(interpreter_bias)
            .unwrap();
        let interpreter_end = interpreter_start
            .checked_add(interpreter_requirements.span)
            .unwrap();

        assert_eq!((search_start, search_end), (USER_DYN_BASE, USER_HEAP_BASE));
        assert_eq!(main_start, USER_DYN_BASE);
        assert_eq!(main_end, 0x952_a000);
        assert!(main_end > 0x400_0000);
        assert_eq!(interpreter_start, 0x953_0000);
        assert!(main_end <= interpreter_start);
        assert!(interpreter_end <= search_end);
    }

    #[test]
    fn initial_stack_uses_real_exec_path_and_random_bytes() {
        let args = vec![String::from("argv0"), String::from("arg")];
        let envs = vec![String::from("KEY=value")];
        let auxv = vec![
            AuxEntry::new(AuxType::PAGESZ, PAGE_SIZE_4K),
            AuxEntry::new(AuxType::RANDOM, 0xdead_beef),
            AuxEntry::new(AuxType::EXECFN, 0xcafe_babe),
            AuxEntry::new(AuxType::NULL, 0),
        ];
        let random = *b"0123456789abcdef";
        let stack_top = 0x10_0000;
        let stack = build_initial_stack(
            &args,
            &envs,
            &auxv,
            "/bin/actual-program",
            random,
            stack_top,
            stack_top,
        )
        .unwrap();
        let stack_base = stack_top - stack.len();
        assert_eq!(stack_base % USER_STACK_ALIGNMENT, 0);

        let mut offset = 0;
        assert_eq!(read_word(&stack, &mut offset), args.len());
        let argv0 = read_word(&stack, &mut offset);
        let argv1 = read_word(&stack, &mut offset);
        assert_eq!(read_word(&stack, &mut offset), 0);
        assert_eq!(&bytes_at(&stack, stack_top, argv0)[..6], b"argv0\0");
        assert_eq!(&bytes_at(&stack, stack_top, argv1)[..4], b"arg\0");

        let env0 = read_word(&stack, &mut offset);
        assert_eq!(read_word(&stack, &mut offset), 0);
        assert_eq!(&bytes_at(&stack, stack_top, env0)[..10], b"KEY=value\0");

        let mut random_ptr = None;
        let mut execfn_ptr = None;
        let mut random_count = 0;
        let mut execfn_count = 0;
        loop {
            let aux_type = read_word(&stack, &mut offset);
            let value = read_word(&stack, &mut offset);
            if aux_type == AuxType::RANDOM as usize {
                random_ptr = Some(value);
                random_count += 1;
            }
            if aux_type == AuxType::EXECFN as usize {
                execfn_ptr = Some(value);
                execfn_count += 1;
            }
            if aux_type == AuxType::NULL as usize {
                break;
            }
        }

        assert_eq!(random_count, 1);
        assert_eq!(execfn_count, 1);
        assert_eq!(
            &bytes_at(&stack, stack_top, random_ptr.unwrap())[..AT_RANDOM_BYTES],
            random.as_slice()
        );
        assert_eq!(
            &bytes_at(&stack, stack_top, execfn_ptr.unwrap())[..20],
            b"/bin/actual-program\0"
        );
    }

    #[test]
    fn process_identity_auxv_is_complete() {
        let credentials = ExecCredentials::new(1000, 1001, 1002, 1003);
        let mut auxv = Vec::new();
        append_process_auxv(&mut auxv, credentials);

        let value = |aux_type| {
            auxv.iter()
                .find(|entry| entry.get_type() == aux_type)
                .unwrap()
                .value()
        };
        assert_eq!(value(AuxType::UID), 1000);
        assert_eq!(value(AuxType::EUID), 1001);
        assert_eq!(value(AuxType::GID), 1002);
        assert_eq!(value(AuxType::EGID), 1003);
        assert_eq!(value(AuxType::SECURE), 0);
    }

    #[test]
    fn stack_mapping_defaults_to_nx_and_honors_gnu_stack_execute() {
        assert!(!stack_mapping_flags(false).contains(MappingFlags::EXECUTE));
        assert!(stack_mapping_flags(true).contains(MappingFlags::EXECUTE));
    }
}
