//! BuildStorm filesystem counters carried by the qperf-trace build.
//!
//! The qperf-trace feature is the single diagnostic configuration: it carries
//! both qperf markers and these counters. Ordinary kernels carry neither the
//! counters nor the call-site checks.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

macro_rules! define_counters {
    ($($name:ident),+ $(,)?) => {
        $(pub static $name: AtomicU64 = AtomicU64::new(0);)+

        fn reset_counters() {
            $($name.store(0, Ordering::Relaxed);)+
        }
    };
}

define_counters!(
    FILE_CACHE_STATES_CREATED,
    PAGE_ACCESS_LOCK_LOOKUPS,
    PAGE_ACCESS_STRIPES_LOCKED,
    PAGE_ACCESS_LOCK_FAST,
    PAGE_ACCESS_LOCK_WAIT,
    PAGE_ACCESS_DEMAND_LOCK_FAST,
    PAGE_ACCESS_DEMAND_LOCK_WAIT,
    PAGE_ACCESS_DEMAND_LOCK_WAIT_NS,
    PAGE_ACCESS_DEMAND_LOCK_WAIT_MAX_NS,
    PAGE_ACCESS_DEMAND_LOCK_HOLD_NS,
    PAGE_ACCESS_DEMAND_LOCK_HOLD_MAX_NS,
    PAGE_ACCESS_PREFETCH_LOCK_FAST,
    PAGE_ACCESS_PREFETCH_LOCK_WAIT,
    PAGE_ACCESS_PREFETCH_LOCK_WAIT_NS,
    PAGE_ACCESS_PREFETCH_LOCK_WAIT_MAX_NS,
    PAGE_ACCESS_PREFETCH_LOCK_HOLD_NS,
    PAGE_ACCESS_PREFETCH_LOCK_HOLD_MAX_NS,
    PAGE_READ_HITS,
    PAGE_READ_MISSES,
    PAGE_FILL_CALLS,
    PAGE_FILL_PAGES,
    PAGE_FILL_DIRECT_PAGES,
    PAGE_FILL_CONTIGUOUS_PAGES,
    PAGE_FILL_DEVICE_BYTES,
    PAGE_FILL_COPY_BYTES,
    PAGE_FILL_MAPPING_DETACHES,
    PAGE_EVICTIONS,
    PAGE_PREFETCH_PAGES,
    PAGE_PREFETCH_HITS,
    PAGE_PREFETCH_UNUSED_EVICTIONS,
    PAGE_DEMAND_FILL_SUBMISSIONS,
    PAGE_DEMAND_FILL_COMPLETIONS,
    PAGE_DEMAND_FILL_WAIT_NS,
    PAGE_DEMAND_FILL_WAIT_MAX_NS,
    PAGE_FILL_INFLIGHT,
    PAGE_FILL_INFLIGHT_PEAK,
    PAGE_FILL_PER_FILE_INFLIGHT_PEAK,
    PAGE_FILL_PER_FILE_CONCURRENT_SUBMISSIONS,
    PAGE_FILL_GENERATION_RETRIES,
    PAGE_FILL_GENERATION_RETRY_PAGES,
    MMAP_PREFETCH_SUBMISSIONS,
    MMAP_PREFETCH_REQUESTED_PAGES,
    MMAP_PREFETCH_SKIPPED_PER_FILE,
    MMAP_PREFETCH_SKIPPED_GLOBAL,
    MMAP_PREFETCH_SKIPPED_PAGE_LOCK,
    MMAP_PREFETCH_COMPLETIONS,
    MMAP_PREFETCH_FAILURES,
    PAGE_WRITE_BYTES,
    EXT4_RANGE_READ_FAST,
    EXT4_RANGE_READ_WAIT,
    EXT4_RANGE_WRITE_FAST,
    EXT4_RANGE_WRITE_WAIT,
    EXT4_RANGE_BUCKETS_LOCKED,
    EXT4_BLOCK_CACHE_HITS,
    EXT4_BLOCK_CACHE_MISSES,
    EXT4_BYPASS_READS,
    EXT4_BYPASS_WRITES,
    EXT4_DEVICE_READ_OPS,
    EXT4_DEVICE_READ_BYTES,
    EXT4_DEVICE_WRITE_OPS,
    EXT4_DEVICE_WRITE_BYTES,
    EXT4_DIRTY_BLOCKS,
    EXT4_FLUSH_BATCHES,
    EXT4_FLUSH_BLOCKS,
    EXT4_DEVICE_FLUSHES,
    EXT4_DIR_MUTATION_LOCK_FAST,
    EXT4_DIR_MUTATION_LOCK_WAIT,
    EXT4_DIR_MUTATION_LOCK_WAIT_NS,
    EXT4_DIR_MUTATION_LOCK_HOLD_NS,
    DEVICE_INFLIGHT,
    DEVICE_INFLIGHT_PEAK,
    SYSCALL_IOV_DIRECT_WRITE_BYTES,
    SYSCALL_IOV_SCRATCH_COPY_BYTES,
    SYSCALL_IOV_SCRATCH_ALLOCS,
    MM_ANON_FAULT_BATCHES,
    MM_ANON_FAULT_FULL_BATCHES,
    MM_ANON_FAULT_EMPTY_REQUESTS,
    MM_ANON_FAULT_REQUESTED_PAGES,
    MM_ANON_FAULT_PREPARED_PAGES,
    MM_ANON_FAULT_SHORT_PREPARES,
    MM_ANON_FAULT_MAPPED_PAGES,
    MM_ANON_FAULT_PTE_READ_PROBES,
    MM_ANON_FAULT_PTE_WRITE_LOCKS,
    MM_ANON_FAULT_PTE_WRITE_GUARD_ACQUIRES,
    MM_ANON_FAULT_LOCAL_TLB_FLUSHES,
    MM_FILE_FAULT_COLD_BATCHES,
    MM_FILE_FAULT_COLD_FULL_BATCHES,
    MM_FILE_FAULT_COLD_REQUESTED_PAGES,
    MM_FILE_FAULT_COLD_PREPARED_PAGES,
    MM_FILE_FAULT_COLD_MAPPED_PAGES,
    MM_FILE_FAULT_SEQUENTIAL_BATCHES,
    MM_FILE_FAULT_SEQUENTIAL_FULL_BATCHES,
    MM_FILE_FAULT_SEQUENTIAL_REQUESTED_PAGES,
    MM_FILE_FAULT_SEQUENTIAL_PREPARED_PAGES,
    MM_FILE_FAULT_SEQUENTIAL_MAPPED_PAGES,
    MM_FILE_FAULT_PREPARED_PAGES,
    MM_FILE_FAULT_SHORT_PREPARES,
    MM_FILE_FAULT_MAPPED_PAGES,
    MM_FILE_FAULT_PTE_READ_PROBES,
    MM_FILE_FAULT_PTE_WRITE_LOCKS,
    MM_FILE_FAULT_PTE_WRITE_GUARD_ACQUIRES,
    MM_FILE_FAULT_LOCAL_TLB_FLUSHES,
);

static ACTIVE: AtomicBool = AtomicBool::new(false);
static WINDOW_GENERATION: AtomicU64 = AtomicU64::new(0);

#[inline]
pub fn is_active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Returns the active diagnostics window identity, if any.
///
/// Page-cache entries outlive a BuildStorm invocation. Associating speculative
/// pages with this generation prevents a later invocation from counting an old
/// prefetch as a new-window hit or unused eviction.
#[inline]
pub fn active_window() -> Option<u64> {
    if !ACTIVE.load(Ordering::Acquire) {
        return None;
    }
    let generation = WINDOW_GENERATION.load(Ordering::Acquire);
    (generation != 0 && ACTIVE.load(Ordering::Acquire)).then_some(generation)
}

#[inline]
pub fn add(counter: &AtomicU64, value: u64) {
    if ACTIVE.load(Ordering::Relaxed) {
        counter.fetch_add(value, Ordering::Relaxed);
    }
}

#[inline]
pub fn observe_max(counter: &AtomicU64, value: u64) {
    if !ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    let mut current = counter.load(Ordering::Relaxed);
    while value > current {
        match counter.compare_exchange_weak(current, value, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(observed) => current = observed,
        }
    }
}

/// Identifies the owner of a page-access stripe range. A demand-owned fill can
/// include a small read-ahead tail, but its locks are acquired on behalf of a
/// synchronous caller; a prefetch-owned fill has no synchronous consumer.
#[derive(Clone, Copy)]
pub enum PageAccessClass {
    Demand,
    Prefetch,
}

/// Records one page-access stripe acquisition. `wait_ns` is present only when
/// the caller entered the wait while the active BuildStorm window was open.
pub fn record_page_access_lock(class: PageAccessClass, wait_ns: Option<u64>) {
    if !is_active() {
        return;
    }

    match (class, wait_ns) {
        (PageAccessClass::Demand, Some(wait_ns)) => {
            add(&PAGE_ACCESS_LOCK_WAIT, 1);
            add(&PAGE_ACCESS_DEMAND_LOCK_WAIT, 1);
            add(&PAGE_ACCESS_DEMAND_LOCK_WAIT_NS, wait_ns);
            observe_max(&PAGE_ACCESS_DEMAND_LOCK_WAIT_MAX_NS, wait_ns);
        }
        (PageAccessClass::Prefetch, Some(wait_ns)) => {
            add(&PAGE_ACCESS_LOCK_WAIT, 1);
            add(&PAGE_ACCESS_PREFETCH_LOCK_WAIT, 1);
            add(&PAGE_ACCESS_PREFETCH_LOCK_WAIT_NS, wait_ns);
            observe_max(&PAGE_ACCESS_PREFETCH_LOCK_WAIT_MAX_NS, wait_ns);
        }
        (PageAccessClass::Demand, None) => {
            add(&PAGE_ACCESS_LOCK_FAST, 1);
            add(&PAGE_ACCESS_DEMAND_LOCK_FAST, 1);
        }
        (PageAccessClass::Prefetch, None) => {
            add(&PAGE_ACCESS_LOCK_FAST, 1);
            add(&PAGE_ACCESS_PREFETCH_LOCK_FAST, 1);
        }
    }
}

fn record_page_access_hold(class: PageAccessClass, hold_ns: u64) {
    if !is_active() {
        return;
    }

    match class {
        PageAccessClass::Demand => {
            add(&PAGE_ACCESS_DEMAND_LOCK_HOLD_NS, hold_ns);
            observe_max(&PAGE_ACCESS_DEMAND_LOCK_HOLD_MAX_NS, hold_ns);
        }
        PageAccessClass::Prefetch => {
            add(&PAGE_ACCESS_PREFETCH_LOCK_HOLD_NS, hold_ns);
            observe_max(&PAGE_ACCESS_PREFETCH_LOCK_HOLD_MAX_NS, hold_ns);
        }
    }
}

/// Times the lifetime of a page-access stripe range after its first stripe is
/// acquired. The range deliberately stays locked across backing I/O, so this
/// measures the blocking exposure seen by overlapping fills, not CPU time.
pub struct PageAccessHoldGuard {
    class: PageAccessClass,
    generation: u64,
    acquired_at_ns: Option<u64>,
}

impl PageAccessHoldGuard {
    /// Disarms timing when a range acquired only a prefix of its stripes and
    /// is abandoned before the fill can begin.
    pub fn cancel(&mut self) {
        self.acquired_at_ns = None;
    }
}

pub fn begin_page_access_hold(class: PageAccessClass) -> PageAccessHoldGuard {
    let Some(generation) = active_window() else {
        return PageAccessHoldGuard {
            class,
            generation: 0,
            acquired_at_ns: None,
        };
    };

    PageAccessHoldGuard {
        class,
        generation,
        acquired_at_ns: Some(axhal::time::monotonic_time_nanos()),
    }
}

impl Drop for PageAccessHoldGuard {
    fn drop(&mut self) {
        let Some(acquired_at_ns) = self.acquired_at_ns else {
            return;
        };
        // An older fill can outlive the window that measured it. Do not fold
        // its final duration into a later invocation after counters reset.
        if WINDOW_GENERATION.load(Ordering::Acquire) != self.generation {
            return;
        }
        let hold_ns = axhal::time::monotonic_time_nanos().saturating_sub(acquired_at_ns);
        record_page_access_hold(self.class, hold_ns);
    }
}

/// Tracks an in-flight cache fill for one file. The local count is retained in
/// the cache state, while the aggregate counters report the maximum overlap
/// observed for any one file during the active diagnostics window.
pub struct PageFillGuard<'a> {
    per_file_inflight: Option<&'a AtomicU64>,
    generation: u64,
}

pub fn begin_page_fill(per_file_inflight: &AtomicU64) -> PageFillGuard<'_> {
    let Some(generation) = active_window() else {
        return PageFillGuard {
            per_file_inflight: None,
            generation: 0,
        };
    };

    let file_inflight = per_file_inflight.fetch_add(1, Ordering::Relaxed) + 1;
    let global_inflight = PAGE_FILL_INFLIGHT.fetch_add(1, Ordering::Relaxed) + 1;
    observe_max(&PAGE_FILL_INFLIGHT_PEAK, global_inflight);
    observe_max(&PAGE_FILL_PER_FILE_INFLIGHT_PEAK, file_inflight);
    if file_inflight > 1 {
        add(&PAGE_FILL_PER_FILE_CONCURRENT_SUBMISSIONS, 1);
    }
    PageFillGuard {
        per_file_inflight: Some(per_file_inflight),
        generation,
    }
}

impl Drop for PageFillGuard<'_> {
    fn drop(&mut self) {
        let Some(per_file_inflight) = self.per_file_inflight else {
            return;
        };
        per_file_inflight.fetch_sub(1, Ordering::Relaxed);
        // A new diagnostics window resets the aggregate counters. An older
        // fill may finish later, but must not decrement the new window.
        if WINDOW_GENERATION.load(Ordering::Acquire) == self.generation {
            PAGE_FILL_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Marks one submitted device operation. The guard keeps the in-flight count
/// correct when the future is cancelled while the device request is pending.
pub struct DeviceIoGuard {
    active: bool,
}

pub fn begin_device_io() -> DeviceIoGuard {
    if !ACTIVE.load(Ordering::Relaxed) {
        return DeviceIoGuard { active: false };
    }

    let inflight = DEVICE_INFLIGHT.fetch_add(1, Ordering::Relaxed) + 1;
    let mut peak = DEVICE_INFLIGHT_PEAK.load(Ordering::Relaxed);
    while inflight > peak {
        match DEVICE_INFLIGHT_PEAK.compare_exchange_weak(
            peak,
            inflight,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(actual) => peak = actual,
        }
    }
    DeviceIoGuard { active: true }
}

impl Drop for DeviceIoGuard {
    fn drop(&mut self) {
        if self.active {
            DEVICE_INFLIGHT.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Starts a fresh diagnostics window immediately after `BUILDSTORM_BEGIN`.
pub fn begin() {
    ACTIVE.store(false, Ordering::Release);
    reset_counters();
    WINDOW_GENERATION.fetch_add(1, Ordering::AcqRel);
    ACTIVE.store(true, Ordering::Release);
}

/// Stops the window and emits a compact console snapshot.
pub fn finish() {
    if !ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }

    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS file_cache_states={} page hits={} misses={} access_lookups={} \
         access_stripes_locked={} page_lock_fast={} page_lock_wait={} fills={} fill_pages={} \
         direct_fill_pages={} contiguous_fill_pages={} fill_device_bytes={} fill_copy_bytes={} \
         mapping_detaches={} evictions={} write_bytes={}",
        load(&FILE_CACHE_STATES_CREATED),
        load(&PAGE_READ_HITS),
        load(&PAGE_READ_MISSES),
        load(&PAGE_ACCESS_LOCK_LOOKUPS),
        load(&PAGE_ACCESS_STRIPES_LOCKED),
        load(&PAGE_ACCESS_LOCK_FAST),
        load(&PAGE_ACCESS_LOCK_WAIT),
        load(&PAGE_FILL_CALLS),
        load(&PAGE_FILL_PAGES),
        load(&PAGE_FILL_DIRECT_PAGES),
        load(&PAGE_FILL_CONTIGUOUS_PAGES),
        load(&PAGE_FILL_DEVICE_BYTES),
        load(&PAGE_FILL_COPY_BYTES),
        load(&PAGE_FILL_MAPPING_DETACHES),
        load(&PAGE_EVICTIONS),
        load(&PAGE_WRITE_BYTES),
    );
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS page_access_demand_lock_fast={} page_access_demand_lock_wait={} \
         page_access_demand_lock_wait_ns={} page_access_demand_lock_wait_max_ns={} \
         page_access_demand_lock_hold_ns={} page_access_demand_lock_hold_max_ns={}",
        load(&PAGE_ACCESS_DEMAND_LOCK_FAST),
        load(&PAGE_ACCESS_DEMAND_LOCK_WAIT),
        load(&PAGE_ACCESS_DEMAND_LOCK_WAIT_NS),
        load(&PAGE_ACCESS_DEMAND_LOCK_WAIT_MAX_NS),
        load(&PAGE_ACCESS_DEMAND_LOCK_HOLD_NS),
        load(&PAGE_ACCESS_DEMAND_LOCK_HOLD_MAX_NS),
    );
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS page_access_prefetch_lock_fast={} page_access_prefetch_lock_wait={} \
         page_access_prefetch_lock_wait_ns={} page_access_prefetch_lock_wait_max_ns={} \
         page_access_prefetch_lock_hold_ns={} page_access_prefetch_lock_hold_max_ns={}",
        load(&PAGE_ACCESS_PREFETCH_LOCK_FAST),
        load(&PAGE_ACCESS_PREFETCH_LOCK_WAIT),
        load(&PAGE_ACCESS_PREFETCH_LOCK_WAIT_NS),
        load(&PAGE_ACCESS_PREFETCH_LOCK_WAIT_MAX_NS),
        load(&PAGE_ACCESS_PREFETCH_LOCK_HOLD_NS),
        load(&PAGE_ACCESS_PREFETCH_LOCK_HOLD_MAX_NS),
    );
    let prefetch_hits = load(&PAGE_PREFETCH_HITS);
    let prefetch_unused_evictions = load(&PAGE_PREFETCH_UNUSED_EVICTIONS);
    let prefetch_settled_pages = prefetch_hits.saturating_add(prefetch_unused_evictions);
    let prefetch_settled_hit_pct_x10000 = if prefetch_settled_pages == 0 {
        0
    } else {
        prefetch_hits.saturating_mul(10_000) / prefetch_settled_pages
    };
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS page_prefetch_pages={} page_prefetch_hits={} \
         page_prefetch_unused_evictions={} page_prefetch_settled_pages={} \
         page_prefetch_settled_hit_pct_x10000={} demand_fill_submissions={} \
         demand_fill_completions={} demand_fill_wait_ns={} demand_fill_wait_max_ns={} \
         fill_inflight={} fill_inflight_peak={} per_file_fill_peak={} \
         per_file_parallel_submissions={} generation_retries={} generation_retry_pages={} \
         mmap_prefetch_submissions={} mmap_prefetch_requested_pages={} \
         mmap_prefetch_skipped_per_file={} mmap_prefetch_skipped_global={} \
         mmap_prefetch_skipped_page_lock={} mmap_prefetch_completions={} mmap_prefetch_failures={}",
        load(&PAGE_PREFETCH_PAGES),
        prefetch_hits,
        prefetch_unused_evictions,
        prefetch_settled_pages,
        prefetch_settled_hit_pct_x10000,
        load(&PAGE_DEMAND_FILL_SUBMISSIONS),
        load(&PAGE_DEMAND_FILL_COMPLETIONS),
        load(&PAGE_DEMAND_FILL_WAIT_NS),
        load(&PAGE_DEMAND_FILL_WAIT_MAX_NS),
        load(&PAGE_FILL_INFLIGHT),
        load(&PAGE_FILL_INFLIGHT_PEAK),
        load(&PAGE_FILL_PER_FILE_INFLIGHT_PEAK),
        load(&PAGE_FILL_PER_FILE_CONCURRENT_SUBMISSIONS),
        load(&PAGE_FILL_GENERATION_RETRIES),
        load(&PAGE_FILL_GENERATION_RETRY_PAGES),
        load(&MMAP_PREFETCH_SUBMISSIONS),
        load(&MMAP_PREFETCH_REQUESTED_PAGES),
        load(&MMAP_PREFETCH_SKIPPED_PER_FILE),
        load(&MMAP_PREFETCH_SKIPPED_GLOBAL),
        load(&MMAP_PREFETCH_SKIPPED_PAGE_LOCK),
        load(&MMAP_PREFETCH_COMPLETIONS),
        load(&MMAP_PREFETCH_FAILURES),
    );
    // These are per-acquisition totals. Concurrent tasks can overlap, so the
    // time totals are not a fraction of BuildStorm wall-clock time.
    let dir_mutation_lock_fast = load(&EXT4_DIR_MUTATION_LOCK_FAST);
    let dir_mutation_lock_wait = load(&EXT4_DIR_MUTATION_LOCK_WAIT);
    let dir_mutation_lock_attempts = dir_mutation_lock_fast.saturating_add(dir_mutation_lock_wait);
    let dir_mutation_lock_wait_pct_x10000 = if dir_mutation_lock_attempts == 0 {
        0
    } else {
        dir_mutation_lock_wait.saturating_mul(10_000) / dir_mutation_lock_attempts
    };
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS ext4 range_read_fast={} range_read_wait={} range_write_fast={} \
         range_write_wait={} range_buckets_locked={} block_cache_hits={} block_cache_misses={} \
         bypass_reads={} bypass_writes={} dirty_blocks={} flush_batches={} flush_blocks={} \
         device_flushes={} dir_mutation_lock_fast={} dir_mutation_lock_wait={} \
         dir_mutation_lock_wait_pct_x10000={} dir_mutation_lock_wait_ns={} \
         dir_mutation_lock_hold_ns={}",
        load(&EXT4_RANGE_READ_FAST),
        load(&EXT4_RANGE_READ_WAIT),
        load(&EXT4_RANGE_WRITE_FAST),
        load(&EXT4_RANGE_WRITE_WAIT),
        load(&EXT4_RANGE_BUCKETS_LOCKED),
        load(&EXT4_BLOCK_CACHE_HITS),
        load(&EXT4_BLOCK_CACHE_MISSES),
        load(&EXT4_BYPASS_READS),
        load(&EXT4_BYPASS_WRITES),
        load(&EXT4_DIRTY_BLOCKS),
        load(&EXT4_FLUSH_BATCHES),
        load(&EXT4_FLUSH_BLOCKS),
        load(&EXT4_DEVICE_FLUSHES),
        dir_mutation_lock_fast,
        dir_mutation_lock_wait,
        dir_mutation_lock_wait_pct_x10000,
        load(&EXT4_DIR_MUTATION_LOCK_WAIT_NS),
        load(&EXT4_DIR_MUTATION_LOCK_HOLD_NS),
    );
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS device read_ops={} read_bytes={} write_ops={} write_bytes={} \
         inflight={} peak_inflight={}",
        load(&EXT4_DEVICE_READ_OPS),
        load(&EXT4_DEVICE_READ_BYTES),
        load(&EXT4_DEVICE_WRITE_OPS),
        load(&EXT4_DEVICE_WRITE_BYTES),
        load(&DEVICE_INFLIGHT),
        load(&DEVICE_INFLIGHT_PEAK),
    );
    axlog::ax_println!(
        "BUILDSTORM_FS_STATS iov direct_write_bytes={} scratch_copy_bytes={} scratch_allocs={}",
        load(&SYSCALL_IOV_DIRECT_WRITE_BYTES),
        load(&SYSCALL_IOV_SCRATCH_COPY_BYTES),
        load(&SYSCALL_IOV_SCRATCH_ALLOCS),
    );
    axlog::ax_println!(
        "BUILDSTORM_MM_STATS anon batches={} full_batches={} empty_requests={} requested_pages={} \
         prepared_pages={} short_prepares={} mapped_pages={} pte_read_probes={} \
         pte_write_attempts={} pte_write_guard_acquires={} local_tlb_flushes={}",
        load(&MM_ANON_FAULT_BATCHES),
        load(&MM_ANON_FAULT_FULL_BATCHES),
        load(&MM_ANON_FAULT_EMPTY_REQUESTS),
        load(&MM_ANON_FAULT_REQUESTED_PAGES),
        load(&MM_ANON_FAULT_PREPARED_PAGES),
        load(&MM_ANON_FAULT_SHORT_PREPARES),
        load(&MM_ANON_FAULT_MAPPED_PAGES),
        load(&MM_ANON_FAULT_PTE_READ_PROBES),
        load(&MM_ANON_FAULT_PTE_WRITE_LOCKS),
        load(&MM_ANON_FAULT_PTE_WRITE_GUARD_ACQUIRES),
        load(&MM_ANON_FAULT_LOCAL_TLB_FLUSHES),
    );
    axlog::ax_println!(
        "BUILDSTORM_MM_STATS file cold_batches={} cold_full_batches={} cold_requested_pages={} \
         cold_prepared_pages={} cold_mapped_pages={} sequential_batches={} \
         sequential_full_batches={} sequential_requested_pages={} sequential_prepared_pages={} \
         sequential_mapped_pages={} prepared_pages={} short_prepares={} mapped_pages={} \
         pte_read_probes={} pte_write_attempts={} pte_write_guard_acquires={} local_tlb_flushes={}",
        load(&MM_FILE_FAULT_COLD_BATCHES),
        load(&MM_FILE_FAULT_COLD_FULL_BATCHES),
        load(&MM_FILE_FAULT_COLD_REQUESTED_PAGES),
        load(&MM_FILE_FAULT_COLD_PREPARED_PAGES),
        load(&MM_FILE_FAULT_COLD_MAPPED_PAGES),
        load(&MM_FILE_FAULT_SEQUENTIAL_BATCHES),
        load(&MM_FILE_FAULT_SEQUENTIAL_FULL_BATCHES),
        load(&MM_FILE_FAULT_SEQUENTIAL_REQUESTED_PAGES),
        load(&MM_FILE_FAULT_SEQUENTIAL_PREPARED_PAGES),
        load(&MM_FILE_FAULT_SEQUENTIAL_MAPPED_PAGES),
        load(&MM_FILE_FAULT_PREPARED_PAGES),
        load(&MM_FILE_FAULT_SHORT_PREPARES),
        load(&MM_FILE_FAULT_MAPPED_PAGES),
        load(&MM_FILE_FAULT_PTE_READ_PROBES),
        load(&MM_FILE_FAULT_PTE_WRITE_LOCKS),
        load(&MM_FILE_FAULT_PTE_WRITE_GUARD_ACQUIRES),
        load(&MM_FILE_FAULT_LOCAL_TLB_FLUSHES),
    );
}
