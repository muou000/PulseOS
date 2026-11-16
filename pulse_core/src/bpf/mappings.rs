//! Immutable, ordered mapping provenance. This boot journal is separate from
//! lossy sample transport; exhaustion is permanent and explicitly reported.
//!
//! VMA snapshots are taken with the address-space write lease held. Explicit
//! begin records precede every write lease and task identity mutation, so a
//! capture cut inside an unfinished operation cannot claim the old state is
//! current. These intervals and outstanding TLB invalidations are uncertain.
//! Paths are labels, never object identity.

use alloc::{format, string::{String, ToString}, sync::Arc, vec::Vec};
use core::{fmt::Write, sync::atomic::{AtomicU64, Ordering}};
use axerrno::AxResult;
use axmm::{Backend, FileMappingSource};
use memory_addr::{MemoryAddr, PhysAddr, VirtAddr};
use sha2::{Digest, Sha256};

const JOURNAL_LIMIT: usize = 8 * 1024 * 1024;
static NEXT_OBJECT: AtomicU64 = AtomicU64::new(1);
static NEXT_MUTATION: AtomicU64 = AtomicU64::new(1);
static JOURNAL: kspin::SpinNoIrq<Journal> = kspin::SpinNoIrq::new(Journal {
    entries: Vec::new(), bytes: 0, sequence: 0, dropped: 0,
});

struct Journal { entries: Vec<String>, bytes: usize, sequence: u64, dropped: u64 }

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() { return "-".into(); }
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes { let _ = write!(result, "{byte:02x}"); }
    result
}

fn append(kind: &str, fields: String) -> u64 {
    let mut journal = JOURNAL.lock();
    journal.sequence = journal.sequence.checked_add(1).expect("mapping journal sequence exhausted");
    let timestamp = axhal::time::monotonic_time_nanos();
    let row = format!("{kind} seq={} ts={timestamp} {fields}\n", journal.sequence);
    if row.len() > JOURNAL_LIMIT.saturating_sub(journal.bytes) {
        journal.dropped += 1;
        return timestamp;
    }
    journal.bytes += row.len();
    journal.entries.push(row);
    timestamp
}

/// Publishes an in-progress interval before exposing mutable state. Completion
/// is recorded only after the corresponding full snapshot or TASK record.
/// A journal cut containing only the begin is deliberately unresolved.
pub struct MutationGuard {
    target: &'static str,
    id: u64,
    token: u64,
    begin_ns: u64,
    active: bool,
}

impl MutationGuard {
    fn begin(target: &'static str, id: u64) -> Self {
        let token = NEXT_MUTATION.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |token| token.checked_add(1)).expect("mapping mutation token exhausted");
        let begin_ns = append("MUTATION", format!("target={target} id={id} token={token} complete=0"));
        Self { target, id, token, begin_ns, active: true }
    }

    pub(crate) fn space(id: usize) -> Self { Self::begin("space", id as u64) }

    pub fn task(id: u64) -> Self { Self::begin("task", id) }

    pub fn begin_ns(&self) -> u64 { self.begin_ns }

    pub(crate) fn finish(&mut self) {
        if self.active {
            append("MUTATION", format!("target={} id={} token={} complete=1", self.target, self.id, self.token));
            self.active = false;
        }
    }
}

impl Drop for MutationGuard {
    fn drop(&mut self) { self.finish(); }
}

/// Freeze one whole journal on open. The cut bounds metadata coverage, even
/// when a sampler continues producing records after this read.
pub fn render() -> String {
    let journal = JOURNAL.lock();
    let cut = axhal::time::monotonic_time_nanos();
    let mut text = format!("PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns={cut} dropped={} records={}\n",
        journal.dropped, journal.entries.len());
    for row in &journal.entries { text.push_str(row); }
    let _ = writeln!(text, "END records={} dropped={} snapshot_ns={cut}", journal.entries.len(), journal.dropped);
    text
}

/// A mapping source whose provenance survives VMA splits, COW and fork.
/// Delegation preserves page-cache identity and all existing memory ownership.
struct ObservedSource { inner: axfs::CachedFile, object: u64 }

impl FileMappingSource for ObservedSource {
    fn mapping_generation(&self) -> u64 { self.inner.mapping_generation() }
    fn get_shared_page_paddrs(&self, n: u32, count: usize, write: bool) -> AxResult<axmm::FileMappingPageBatch> {
        self.inner.get_shared_page_paddrs(n, count, write)
    }
    fn get_shared_page_paddrs_with_io(&self, n: u32, count: usize, write: bool) -> AxResult<(axmm::FileMappingPageBatch, axmm::FilePageIo)> {
        self.inner.get_shared_page_paddrs_with_io(n, count, write)
    }
    fn prefetch_pages(&self, n: u32, count: usize) { self.inner.prefetch_pages(n, count); }
    fn size(&self) -> u64 { self.inner.size() }
    fn shared_page_paddr(&self, n: u32) -> AxResult<PhysAddr> { self.inner.shared_page_paddr(n) }
    fn mark_page_dirty_if_paddr(&self, n: u32, p: PhysAddr) -> AxResult { self.inner.mark_page_dirty_if_paddr(n, p) }
    fn sync(&self, data_only: bool) -> AxResult { self.inner.sync(data_only) }
    fn page_cache_identity(&self) -> usize { self.inner.page_cache_identity() }
    fn as_any(&self) -> &dyn core::any::Any { self }
}

fn hash_file(file: &axfs::CachedFile) -> Option<String> {
    let size = file.size();
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 4096];
    let mut offset = 0;
    while offset < size {
        let count = ((size - offset) as usize).min(buffer.len());
        let read = file.read_at(&mut buffer[..count], offset).ok()?;
        if read != count { return None; }
        digest.update(&buffer[..read]);
        offset += read as u64;
    }
    Some(hex(&digest.finalize()))
}

/// Register an actual file before publishing its mapping. `exec_protected`
/// means the ELF loader already owns its normal deny-write execution lease.
/// Ordinary mmap files may change and deliberately carry an unknown SHA.
pub fn file_source(file: axfs::CachedFile, exec_protected: bool) -> Arc<dyn FileMappingSource> {
    if !exec_protected {
        // An ELF in this address space remains protected by the process's
        // execution leases, including fork inheritance. Reuse its identity.
        if let Ok(process) = crate::task::current_process() {
            let handle = process.aspace_handle();
            let aspace = handle.read();
            let mut found = None;
            aspace.for_each_area_with_backend(|_, _, _, backend| {
                let mut backend = backend;
                while let Backend::Cow(cow) = backend { backend = cow.inner(); }
                if let Backend::File(mapping) = backend {
                    if let Some(source) = mapping.file().as_any().downcast_ref::<ObservedSource>() {
                        if source.inner.ptr_eq(&file) { found = Some(mapping.file().clone()); }
                    }
                }
            });
            if let Some(source) = found { return source; }
        }
    }
    let object = NEXT_OBJECT.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
        |identity| identity.checked_add(1)).expect("mapping object identity exhausted");
    let path = file.location().absolute_path().map(|p| p.to_string()).unwrap_or_default();
    let sha = if exec_protected { hash_file(&file) } else { None };
    let build_id = if exec_protected {
        match pulse_bpf_schema::elf::elf_build_id(file.size(), |offset, bytes| {
            let expected = bytes.len();
            file.read_at(bytes, offset).is_ok_and(|read| read == expected)
        }) {
            Ok(Some(id)) => hex(id.as_bytes()),
            Ok(None) => "none".into(),
            Err(()) => "unknown".into(),
        }
    } else { "unknown".into() };
    append("OBJECT", format!("object={object} sha256={} build_id={build_id} path_hex={}",
        sha.as_deref().unwrap_or("unknown"), hex(path.as_bytes())));
    Arc::new(ObservedSource { inner: file, object })
}

/// Keep existing /proc/maps path rendering functional for observed sources.
pub fn cached_file(source: &dyn FileMappingSource) -> Option<&axfs::CachedFile> {
    source.as_any().downcast_ref::<ObservedSource>().map(|s| &s.inner)
        .or_else(|| source.as_any().downcast_ref::<axfs::CachedFile>())
}

fn file_mapping(backend: &Backend, start: VirtAddr) -> (u64, usize, bool) {
    match backend {
        Backend::File(file) => {
            let object = file.file().as_any().downcast_ref::<ObservedSource>().map_or(0, |s| s.object);
            (object, file.byte_offset_at(start).unwrap_or(usize::MAX), file.is_shared())
        }
        Backend::Cow(cow) => file_mapping(cow.inner(), start),
        Backend::Shared { .. } => (0, 0, true),
        _ => (0, 0, false),
    }
}

pub fn space_snapshot(aspace: &axmm::AddrSpace, begin_ns: u64) {
    use axhal::paging::MappingFlags as F;
    let (space, revision) = aspace.observation_identity();
    let mut rows = String::new();
    let mut count = 0;
    aspace.for_each_area_with_backend(|start, end, flags, backend| {
        if !flags.contains(F::USER) { return; }
        let (object, pgoff, shared) = file_mapping(backend, start);
        let perms = u8::from(flags.contains(F::READ)) | (u8::from(flags.contains(F::WRITE)) << 1)
            | (u8::from(flags.contains(F::EXECUTE)) << 2) | (u8::from(shared) << 3);
        let _ = writeln!(rows, "MAP start={} len={} pgoff={pgoff} perms={perms} object={object}",
            start.as_usize(), end.as_usize() - start.as_usize());
        count += 1;
    });
    append("SPACE", format!("begin_ns={begin_ns} space={space} revision={revision} count={count}\n{rows}ENDSPACE"));
}

pub fn task(task_id: u64, pid: u64, tid: u64, space: usize, exec: u64,
    kind: &str, parent: u64, name: &str, begin_ns: u64) {
    append("TASK", format!("task={task_id} pid={pid} tid={tid} space={space} exec={exec} kind={kind} parent={parent} class=user begin_ns={begin_ns} comm_hex={}", hex(name.as_bytes())));
}

pub fn register_space(aspace: &axmm::AddrSpace) {
    static KERNEL: spin::Once<()> = spin::Once::new();
    KERNEL.call_once(|| {
        let (start, end) = axhal::mem::kernel_text_range();
        let build_id = axhal::mem::kernel_build_id().map(hex).unwrap_or_else(|| "unknown".into());
        append("KERNEL", format!("start={start} len={} reference={start} symbol_hex={} build_id={build_id}", end - start, hex(b"_stext")));
    });
    axmm::register_tlb_observer(tlb);
    space_snapshot(aspace, axhal::time::monotonic_time_nanos());
}

fn tlb(space: usize, token: u64, complete: bool) {
    append("TLB", format!("space={space} token={token} complete={}", u8::from(complete)));
}
