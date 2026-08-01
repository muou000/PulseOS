//! BuildStorm-only filesystem counters.
//!
//! This module is compiled only for the diagnostic kernel.  The regular
//! BuildStorm artifact carries neither the counters nor the call-site checks.

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
    DEVICE_INFLIGHT,
    DEVICE_INFLIGHT_PEAK,
    SYSCALL_IOV_DIRECT_WRITE_BYTES,
    SYSCALL_IOV_SCRATCH_COPY_BYTES,
    SYSCALL_IOV_SCRATCH_ALLOCS,
);

static ACTIVE: AtomicBool = AtomicBool::new(false);

#[inline]
pub fn add(counter: &AtomicU64, value: u64) {
    if ACTIVE.load(Ordering::Relaxed) {
        counter.fetch_add(value, Ordering::Relaxed);
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
    ACTIVE.store(true, Ordering::Release);
}

/// Stops the window and emits a compact serial-log snapshot.
pub fn finish() {
    if !ACTIVE.swap(false, Ordering::AcqRel) {
        return;
    }

    let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
    log::info!(
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
    log::info!(
        "BUILDSTORM_FS_STATS ext4 range_read_fast={} range_read_wait={} range_write_fast={} \
         range_write_wait={} range_buckets_locked={} block_cache_hits={} block_cache_misses={} \
         bypass_reads={} bypass_writes={} dirty_blocks={} flush_batches={} flush_blocks={} \
         device_flushes={}",
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
    );
    log::info!(
        "BUILDSTORM_FS_STATS device read_ops={} read_bytes={} write_ops={} write_bytes={} \
         inflight={} peak_inflight={}",
        load(&EXT4_DEVICE_READ_OPS),
        load(&EXT4_DEVICE_READ_BYTES),
        load(&EXT4_DEVICE_WRITE_OPS),
        load(&EXT4_DEVICE_WRITE_BYTES),
        load(&DEVICE_INFLIGHT),
        load(&DEVICE_INFLIGHT_PEAK),
    );
    log::info!(
        "BUILDSTORM_FS_STATS iov direct_write_bytes={} scratch_copy_bytes={} scratch_allocs={}",
        load(&SYSCALL_IOV_DIRECT_WRITE_BYTES),
        load(&SYSCALL_IOV_SCRATCH_COPY_BYTES),
        load(&SYSCALL_IOV_SCRATCH_ALLOCS),
    );
}
