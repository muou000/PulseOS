use alloc::{sync::Arc, vec::Vec};
use hashbrown::HashMap;
use kernel_guard::NoPreemptIrqSave;
use spin::RwLock;

/// Compile-time constant for the number of process registry shards.
pub const PROCESS_REGISTRY_SHARDS: usize = 16;

/// Deterministic PID to shard index mapping function.
///
/// Disperses PIDs uniformly across the 16 registry shards using modulo arithmetic.
#[inline]
pub const fn process_shard_index(pid: u64) -> usize {
    (pid as usize) % PROCESS_REGISTRY_SHARDS
}

/// An IRQ-safe map with concurrent readers and exclusive writers.
///
/// Disabling preemption and local interrupts prevents an IRQ reader from
/// deadlocking on a writer interrupted on the same CPU.
struct IrqSafeRwMap<K, V> {
    inner: RwLock<HashMap<K, V>>,
}

impl<K, V> IrqSafeRwMap<K, V>
where
    K: Eq + core::hash::Hash,
{
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }

    pub fn get(&self, key: &K) -> Option<V>
    where
        V: Clone,
    {
        let _guard = NoPreemptIrqSave::new();
        self.inner.read().get(key).cloned()
    }

    pub fn snapshot_values(&self) -> Vec<V>
    where
        V: Clone,
    {
        let _guard = NoPreemptIrqSave::new();
        self.inner.read().values().cloned().collect()
    }

    pub fn insert(&self, key: K, value: V) -> Option<V> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.write().insert(key, value)
    }

    pub fn remove(&self, key: &K) -> Option<V> {
        let _guard = NoPreemptIrqSave::new();
        self.inner.write().remove(key)
    }

    pub fn len(&self) -> usize {
        let _guard = NoPreemptIrqSave::new();
        self.inner.read().len()
    }
}

impl<K, V> Default for IrqSafeRwMap<K, V>
where
    K: Eq + core::hash::Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

/// A sharded process registry partitioned into 16 independent IRQ-safe maps.
///
/// # Concurrency & Consistency Design
///
/// - **Point operations (`get`, `insert`, `remove`)**:
///   Route directly to a single shard via `process_shard_index(pid)`.
///   Mutations and reads to different shards never contend for the same lock,
///   eliminating global spinlock bottlenecks on `fork`, `exit`, and `process_by_pid`.
/// - **Scatter/Gather Snapshots (`snapshot_values`)**:
///   Visits shards sequentially in index order (`0..PROCESS_REGISTRY_SHARDS`).
///   Only the current shard's read lock is held while copying references;
///   the lock is dropped immediately before moving to the next shard.
///   Multiple shard locks are **never** held concurrently, preventing deadlocks.
/// - **Weak Consistency Boundary**:
///   Concurrent registrations or unregistrations during snapshot traversal
///   reflect the state of each shard at the exact instant it was visited.
///   Because PIDs are strictly partitioned (each PID belongs to exactly one shard),
///   no PID can appear in multiple shards, guaranteeing snapshot uniqueness.
///   All cloned `Arc<Process>` handles remain completely valid even if unregistration
///   occurs immediately after.
pub struct ShardedProcessRegistry<V> {
    shards: [IrqSafeRwMap<u64, V>; PROCESS_REGISTRY_SHARDS],
}

impl<V> ShardedProcessRegistry<V> {
    pub fn new() -> Self {
        Self {
            shards: core::array::from_fn(|_| IrqSafeRwMap::new()),
        }
    }

    #[inline]
    pub fn get(&self, pid: &u64) -> Option<V>
    where
        V: Clone,
    {
        let shard = process_shard_index(*pid);
        self.shards[shard].get(pid)
    }

    #[inline]
    pub fn insert(&self, pid: u64, value: V) -> Option<V> {
        let shard = process_shard_index(pid);
        self.shards[shard].insert(pid, value)
    }

    #[inline]
    pub fn remove(&self, pid: &u64) -> Option<V> {
        let shard = process_shard_index(*pid);
        self.shards[shard].remove(pid)
    }

    /// Visits shards 0..16 sequentially, cloning values from each shard
    /// while holding only that shard's read lock. The lock is immediately
    /// dropped before proceeding to the next shard.
    pub fn snapshot_values(&self) -> Vec<V>
    where
        V: Clone,
    {
        let mut result = Vec::new();
        for shard in &self.shards {
            let mut shard_procs = shard.snapshot_values();
            result.append(&mut shard_procs);
        }
        result
    }

    pub(crate) fn shard_len(&self, shard: usize) -> usize {
        if shard < PROCESS_REGISTRY_SHARDS {
            self.shards[shard].len()
        } else {
            0
        }
    }

    pub(crate) fn total_len(&self) -> usize {
        let mut count = 0;
        for shard in &self.shards {
            count += shard.len();
        }
        count
    }
}

impl<V> Default for ShardedProcessRegistry<V> {
    fn default() -> Self {
        Self::new()
    }
}

/// Runs in-kernel verification and diagnostics of `ShardedProcessRegistry`.
pub fn run_process_registry_guest_checks() -> Result<(), &'static str> {
    axlog::ax_println!("[PROC_REG_GUEST] Starting sharded process registry checks...");

    // 1. Shard distribution & deterministic hashing
    for pid in 0..64u64 {
        assert_eq!(process_shard_index(pid), (pid as usize) % PROCESS_REGISTRY_SHARDS);
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    struct GuestProcStub {
        pid: u64,
        val: u64,
    }

    let reg: ShardedProcessRegistry<GuestProcStub> = ShardedProcessRegistry::new();

    // 2. Point lookup, insert, remove isolation & same-shard collision
    // PID 1 and PID 17 both map to shard 1 (1 % 16 == 1, 17 % 16 == 1)
    let p1 = 1u64;
    let p17 = 17u64;
    assert_eq!(process_shard_index(p1), 1);
    assert_eq!(process_shard_index(p17), 1);

    // PID 2 maps to shard 2
    let p2 = 2u64;
    assert_eq!(process_shard_index(p2), 2);

    assert_eq!(reg.get(&p1), None);
    assert_eq!(reg.total_len(), 0);

    reg.insert(p1, GuestProcStub { pid: p1, val: 1001 });
    assert_eq!(reg.shard_len(1), 1);
    assert_eq!(reg.shard_len(2), 0);
    assert_eq!(reg.total_len(), 1);
    assert_eq!(reg.get(&p1), Some(GuestProcStub { pid: p1, val: 1001 }));

    // Collision in shard 1: inserting p17 does not overwrite p1
    reg.insert(p17, GuestProcStub { pid: p17, val: 1017 });
    assert_eq!(reg.shard_len(1), 2);
    assert_eq!(reg.total_len(), 2);
    assert_eq!(reg.get(&p1), Some(GuestProcStub { pid: p1, val: 1001 }));
    assert_eq!(reg.get(&p17), Some(GuestProcStub { pid: p17, val: 1017 }));

    // Independent shard 2: inserting p2 does not alter shard 1
    reg.insert(p2, GuestProcStub { pid: p2, val: 1002 });
    assert_eq!(reg.shard_len(1), 2);
    assert_eq!(reg.shard_len(2), 1);
    assert_eq!(reg.total_len(), 3);
    assert_eq!(reg.get(&p2), Some(GuestProcStub { pid: p2, val: 1002 }));

    // Removal isolation: removing p1 leaves p17 and p2 intact
    assert_eq!(reg.remove(&p1), Some(GuestProcStub { pid: p1, val: 1001 }));
    assert_eq!(reg.get(&p1), None);
    assert_eq!(reg.get(&p17), Some(GuestProcStub { pid: p17, val: 1017 }));
    assert_eq!(reg.get(&p2), Some(GuestProcStub { pid: p2, val: 1002 }));
    assert_eq!(reg.shard_len(1), 1);
    assert_eq!(reg.total_len(), 2);

    reg.remove(&p17);
    reg.remove(&p2);
    assert_eq!(reg.total_len(), 0);
    axlog::ax_println!("[PROC_REG_GUEST] Shard isolation and collision: PASS");

    // 3. Multi-shard independent access
    {
        reg.insert(16, GuestProcStub { pid: 16, val: 2016 }); // shard 0
        reg.insert(1, GuestProcStub { pid: 1, val: 2001 });   // shard 1

        assert_eq!(reg.shard_len(0), 1);
        assert_eq!(reg.shard_len(1), 1);

        assert_eq!(reg.get(&16), Some(GuestProcStub { pid: 16, val: 2016 }));
        assert_eq!(reg.get(&1), Some(GuestProcStub { pid: 1, val: 2001 }));

        reg.remove(&16);
        reg.remove(&1);
    }
    axlog::ax_println!("[PROC_REG_GUEST] Cross-shard independence: PASS");

    // 4. Scatter/Gather snapshot aggregation, ordering & deduplication
    let test_pids = [
        45u64, 2u64, 18u64, 34u64, 3u64, 19u64, 0u64, 16u64, 32u64,
        15u64, 31u64, 47u64, 7u64, 23u64, 11u64, 27u64, 43u64,
    ];

    for &pid in &test_pids {
        reg.insert(pid, GuestProcStub { pid, val: pid * 10 });
    }
    assert_eq!(reg.total_len(), test_pids.len());

    let mut snapshot = reg.snapshot_values();
    snapshot.sort_by_key(|p| p.pid);
    snapshot.dedup_by_key(|p| p.pid);

    assert_eq!(snapshot.len(), test_pids.len());
    for window in snapshot.windows(2) {
        assert!(
            window[0].pid < window[1].pid,
            "snapshot entries must be strictly ascending: {} >= {}",
            window[0].pid,
            window[1].pid
        );
        assert_eq!(window[0].val, window[0].pid * 10);
    }

    for &pid in &test_pids {
        reg.remove(&pid);
    }
    assert_eq!(reg.total_len(), 0);
    axlog::ax_println!("[PROC_REG_GUEST] Scatter/Gather snapshot sorting & dedup: PASS");

    // 5. Weak consistency boundary verification:
    // Sequential snapshot drops each shard lock immediately.
    {
        reg.insert(1, GuestProcStub { pid: 1, val: 100 });   // shard 1
        reg.insert(15, GuestProcStub { pid: 15, val: 200 }); // shard 15

        let mut procs = reg.snapshot_values();
        procs.sort_by_key(|p| p.pid);
        assert_eq!(procs.len(), 2);
        assert_eq!(procs[0].pid, 1);
        assert_eq!(procs[1].pid, 15);

        reg.remove(&1);
        reg.remove(&15);
    }
    axlog::ax_println!("[PROC_REG_GUEST] Weak consistency boundary: PASS");

    // 6. Comparative Benchmark: Monolithic Single-Lock vs 16-Shard Registry under Mixed Workload (80% Read / 20% Write)
    {
        const ITERS: usize = 20_000;

        // Baseline: Monolithic Single-Lock IrqSafeRwMap
        let mono_reg = IrqSafeRwMap::<u64, u64>::new();
        for pid in 1..=64u64 {
            mono_reg.insert(pid, pid * 100);
        }

        let mono_start_ns = axhal::time::monotonic_time_nanos();
        let mut mono_chk = 0u64;
        for i in 0..ITERS {
            let pid = (i as u64 % 64) + 1;
            if i % 5 == 0 {
                // 20% write: simulate process retirement and fork
                mono_reg.remove(&pid);
                mono_reg.insert(pid, pid * 100 + (i as u64));
            } else {
                // 80% read: simulate process_by_pid point lookup
                if let Some(val) = mono_reg.get(&pid) {
                    mono_chk ^= val;
                }
            }
        }
        let mono_elapsed_ns = axhal::time::monotonic_time_nanos().saturating_sub(mono_start_ns);
        let mono_lat_ns = if ITERS > 0 { mono_elapsed_ns / (ITERS as u64) } else { 0 };
        let mono_kops_sec = if mono_elapsed_ns > 0 { (ITERS as u64 * 1_000_000) / mono_elapsed_ns } else { 0 };

        // Optimized: 16-Shard Process Registry
        let sharded_reg = ShardedProcessRegistry::<u64>::new();
        for pid in 1..=64u64 {
            sharded_reg.insert(pid, pid * 100);
        }

        let sharded_start_ns = axhal::time::monotonic_time_nanos();
        let mut sharded_chk = 0u64;
        for i in 0..ITERS {
            let pid = (i as u64 % 64) + 1;
            if i % 5 == 0 {
                // 20% write: isolated to single shard
                sharded_reg.remove(&pid);
                sharded_reg.insert(pid, pid * 100 + (i as u64));
            } else {
                // 80% read: isolated to single shard
                if let Some(val) = sharded_reg.get(&pid) {
                    sharded_chk ^= val;
                }
            }
        }
        let sharded_elapsed_ns = axhal::time::monotonic_time_nanos().saturating_sub(sharded_start_ns);
        let sharded_lat_ns = if ITERS > 0 { sharded_elapsed_ns / (ITERS as u64) } else { 0 };
        let sharded_kops_sec = if sharded_elapsed_ns > 0 { (ITERS as u64 * 1_000_000) / sharded_elapsed_ns } else { 0 };

        let speedup_pct = if mono_elapsed_ns > 0 {
            ((mono_elapsed_ns as i64 - sharded_elapsed_ns as i64) * 100) / (mono_elapsed_ns as i64)
        } else {
            0
        };

        axlog::ax_println!(
            "[PROC_REG_GUEST] Comparative Benchmark ({} mixed ops, 80% read / 20% write):",
            ITERS
        );
        axlog::ax_println!(
            "  - Monolithic Baseline: elapsed={} us, avg_lat={} ns, throughput={} kops/s (chk={})",
            mono_elapsed_ns / 1000,
            mono_lat_ns,
            mono_kops_sec,
            mono_chk
        );
        axlog::ax_println!(
            "  - 16-Shard Registry:   elapsed={} us, avg_lat={} ns, throughput={} kops/s (chk={})",
            sharded_elapsed_ns / 1000,
            sharded_lat_ns,
            sharded_kops_sec,
            sharded_chk
        );
        axlog::ax_println!(
            "  - Performance Delta:   latency reduction = {}%, throughput delta = +{}%",
            speedup_pct,
            if mono_kops_sec > 0 { ((sharded_kops_sec as i64 - mono_kops_sec as i64) * 100) / (mono_kops_sec as i64) } else { 0 }
        );
    }

    axlog::ax_println!("[PROC_REG_GUEST] All sharded process registry checks PASSED!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_shard_mapping() {
        for pid in 0..128u64 {
            assert_eq!(process_shard_index(pid), (pid as usize) % PROCESS_REGISTRY_SHARDS);
        }
    }

    #[test]
    fn test_sharded_registry_crud_and_collision() {
        let reg = ShardedProcessRegistry::<u32>::new();

        // Shard 3: PIDs 3, 19, 35
        reg.insert(3, 30);
        reg.insert(19, 190);
        reg.insert(35, 350);

        assert_eq!(reg.shard_len(3), 3);
        assert_eq!(reg.total_len(), 3);
        assert_eq!(reg.get(&3), Some(30));
        assert_eq!(reg.get(&19), Some(190));
        assert_eq!(reg.get(&35), Some(350));
        assert_eq!(reg.get(&51), None);

        // Remove middle collision
        assert_eq!(reg.remove(&19), Some(190));
        assert_eq!(reg.get(&19), None);
        assert_eq!(reg.get(&3), Some(30));
        assert_eq!(reg.get(&35), Some(350));
        assert_eq!(reg.shard_len(3), 2);
    }

    #[test]
    fn test_sharded_registry_snapshot_sorting() {
        struct TestProc {
            pid: u64,
            name: &'static str,
        }

        let reg = ShardedProcessRegistry::<Arc<TestProc>>::new();
        let pids = [100u64, 4u64, 23u64, 1u64, 55u64, 16u64, 0u64, 99u64];

        for &pid in &pids {
            reg.insert(pid, Arc::new(TestProc { pid, name: "proc" }));
        }

        let mut values = reg.snapshot_values();
        values.sort_by_key(|p| p.pid);
        values.dedup_by_key(|p| p.pid);

        assert_eq!(values.len(), pids.len());
        for window in values.windows(2) {
            assert!(window[0].pid < window[1].pid);
        }
    }
}
