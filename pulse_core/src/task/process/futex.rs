use super::*;
use crate::task;

impl Process {
    fn futex_key(&self, addr: usize, is_private: bool) -> (usize, bool) {
        if is_private {
            (addr, true)
        } else {
            let _ =
                self.try_fault_in_user_range(addr, core::mem::size_of::<u32>(), MappingFlags::READ);
            let aspace_handle = self.aspace_handle();
            let aspace = aspace_handle.read();
            let vaddr = VirtAddr::from(addr);
            let paddr = aspace
                .query_vaddr(vaddr)
                .map(|(paddr, ..)| paddr.as_usize())
                .unwrap_or(addr);
            axlog::debug!("futex_key: addr={:#x}, paddr={:#x}", addr, paddr);
            (paddr, false)
        }
    }

    pub fn futex_waitv(
        &self,
        waiters_addr: usize,
        nr_futexes: u32,
        _flags: u32,
        timeout_ns: Option<u64>,
    ) -> AxResult<isize> {
        let mut waiters = alloc::vec::Vec::with_capacity(nr_futexes as usize);
        for i in 0..nr_futexes {
            let mut w = FutexWaitv::default();
            let buf = unsafe {
                core::slice::from_raw_parts_mut(
                    &mut w as *mut _ as *mut u8,
                    core::mem::size_of::<FutexWaitv>(),
                )
            };
            self.read_user_bytes(
                waiters_addr + i as usize * core::mem::size_of::<FutexWaitv>(),
                buf,
            )?;
            waiters.push(w);
        }

        for w in &waiters {
            if w.__reserved != 0 {
                return Err(AxError::InvalidInput);
            }
            let valid_flags = 0x02 | 0x80;
            if (w.flags & !valid_flags) != 0 || (w.flags & 0x03) != 0x02 {
                return Err(AxError::InvalidInput);
            }
            if w.uaddr % 4 != 0 {
                return Err(AxError::InvalidInput);
            }
            if w.uaddr == 0 {
                return Err(AxError::BadAddress);
            }
            self.try_fault_in_user_range(
                w.uaddr as usize,
                core::mem::size_of::<u32>(),
                MappingFlags::READ,
            )?;
            let val = self.read_user_u32(w.uaddr as usize)?;
            if val != w.val as u32 {
                return Err(AxError::from(AxErrorKind::WouldBlock));
            }
        }

        // Translate the virtual addresses to physical addresses outside the run queue lock.
        let mut kvaddrs = alloc::vec::Vec::with_capacity(waiters.len());
        let aspace = self.aspace_handle();
        let aspace_guard = aspace.read();
        for w in &waiters {
            let start = VirtAddr::from(w.uaddr as usize);
            let (paddr, ..) = aspace_guard
                .query_vaddr(start)
                .map_err(|_| AxError::BadAddress)?;
            let paddr = paddr.align_down_4k() + start.align_offset_4k();
            let kvaddr = axhal::mem::phys_to_virt(paddr);
            kvaddrs.push(kvaddr.as_usize());
        }
        drop(aspace_guard);

        let current_thread = task::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };

        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) }); // ERESTARTSYS
        }

        let mut queues = alloc::vec::Vec::with_capacity(waiters.len());
        let mut queue_keys = alloc::vec::Vec::with_capacity(waiters.len());
        for w in &waiters {
            let is_priv = w.flags & 128 != 0; // 128 is FUTEX_PRIVATE_FLAG
            let (key, is_priv) = self.futex_key(w.uaddr as usize, is_priv);
            let queue = if is_priv {
                self.futex_table.queue(key)
            } else {
                GLOBAL_FUTEX_TABLE.queue(key)
            };
            queues.push(queue);
            queue_keys.push((key, is_priv));
        }

        let q_refs: alloc::vec::Vec<&axtask::WaitQueue> =
            queues.iter().map(|q| q.as_ref()).collect();

        let mut mismatch = false;

        let resource_id = queue_keys.first().map(|(key, _)| *key as u64).unwrap_or(0);
        let res = axtask::WaitQueue::wait_multiple_timeout_until_with_context(
            &q_refs,
            timeout_ns.map(core::time::Duration::from_nanos),
            WaitContext::new(|| (WaitReason::FutexWaitV, resource_id, nr_futexes as u64)),
            || {
                if self.group_exiting() || signal_pending() {
                    return true;
                }
                mismatch = false;
                for (i, w) in waiters.iter().enumerate() {
                    let kvaddr = kvaddrs[i];
                    let val = unsafe { core::ptr::read_volatile(kvaddr as *const u32) };
                    if val != w.val as u32 {
                        mismatch = true;
                        return true;
                    }
                }
                false
            },
        );

        drop(q_refs);
        drop(queues);
        for (key, is_priv) in queue_keys {
            if is_priv {
                self.futex_table.remove_if_empty(key);
            } else {
                GLOBAL_FUTEX_TABLE.remove_if_empty(key);
            }
        }

        if mismatch {
            return Err(AxError::from(AxErrorKind::WouldBlock)); // EAGAIN
        }

        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) }); // ERESTARTSYS
        }

        match res {
            Ok(idx) => Ok(idx as isize),
            Err(true) => Err(AxError::from(AxErrorKind::TimedOut)),
            Err(false) => Err(unsafe { core::mem::transmute(-512i32) }), // Aborted not by timeout
        }
    }

    pub fn futex_wait(
        &self,
        addr: usize,
        expected: u32,
        timeout_ns: Option<u64>,
        is_private: bool,
    ) -> AxResult<()> {
        self.futex_wait_mask(addr, expected, timeout_ns, is_private, u32::MAX)
    }

    pub fn futex_wait_mask(
        &self,
        addr: usize,
        expected: u32,
        timeout_ns: Option<u64>,
        is_private: bool,
        bitset: u32,
    ) -> AxResult<()> {
        self.try_fault_in_user_range(addr, core::mem::size_of::<u32>(), MappingFlags::READ)?;
        let val = self.read_user_u32(addr)?;
        if val != expected {
            return Err(AxError::from(AxErrorKind::WouldBlock));
        }

        // Translate the virtual address to a physical address outside the run queue lock.
        let aspace = self.aspace_handle();
        let start = VirtAddr::from(addr);
        let (paddr, ..) = aspace
            .read()
            .query_vaddr(start)
            .map_err(|_| AxError::BadAddress)?;
        let paddr = paddr.align_down_4k() + start.align_offset_4k();
        let kvaddr = axhal::mem::phys_to_virt(paddr);

        let current_thread = task::current_thread().ok();
        let signal_pending = || {
            current_thread
                .as_ref()
                .map(|thread| thread.has_pending_signal())
                .unwrap_or(false)
        };
        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) });
        }

        let (key, is_priv) = self.futex_key(addr, is_private);

        axlog::debug!(
            "futex_wait: tid={}, addr={:#x}, paddr={:#x}, expected={}, is_private={}",
            current_thread
                .as_ref()
                .map(|thread| thread.tid())
                .unwrap_or(0),
            addr,
            paddr.as_usize(),
            expected,
            is_private
        );

        let queue = if is_priv {
            self.futex_table.queue_mask(key, bitset)
        } else {
            GLOBAL_FUTEX_TABLE.queue_mask(key, bitset)
        };

        if self.group_exiting() {
            drop(queue);
            if is_priv {
                self.futex_table.remove_mask_if_empty(key, bitset);
            } else {
                GLOBAL_FUTEX_TABLE.remove_mask_if_empty(key, bitset);
            }
            return Ok(());
        }

        let first_time = core::cell::Cell::new(true);
        let mismatch = core::sync::atomic::AtomicBool::new(false);

        let timed_out = if let Some(timeout_ns) = timeout_ns {
            let dur = core::time::Duration::from_nanos(timeout_ns);
            queue.wait_timeout_until_with_context(
                WaitContext::new(|| (WaitReason::Futex, key as u64, expected as u64)),
                dur,
                || {
                    if first_time.get() {
                        first_time.set(false);
                        if self.group_exiting() || signal_pending() {
                            return true;
                        }
                        let val =
                            unsafe { core::ptr::read_volatile(kvaddr.as_usize() as *const u32) };
                        if val != expected {
                            mismatch.store(true, core::sync::atomic::Ordering::Relaxed);
                            return true;
                        }
                        false
                    } else {
                        true
                    }
                },
            )
        } else {
            queue.wait_until_with_context(
                WaitContext::new(|| (WaitReason::Futex, key as u64, expected as u64)),
                || {
                    if first_time.get() {
                        first_time.set(false);
                        if self.group_exiting() || signal_pending() {
                            return true;
                        }
                        let val =
                            unsafe { core::ptr::read_volatile(kvaddr.as_usize() as *const u32) };
                        if val != expected {
                            mismatch.store(true, core::sync::atomic::Ordering::Relaxed);
                            return true;
                        }
                        false
                    } else {
                        true
                    }
                },
            );
            false
        };

        drop(queue);
        if is_priv {
            self.futex_table.remove_mask_if_empty(key, bitset);
        } else {
            GLOBAL_FUTEX_TABLE.remove_mask_if_empty(key, bitset);
        }

        if self.group_exiting() {
            return Ok(());
        }
        if signal_pending() {
            return Err(unsafe { core::mem::transmute(-512i32) });
        }
        if mismatch.load(core::sync::atomic::Ordering::Relaxed) {
            return Err(AxError::from(AxErrorKind::WouldBlock));
        }
        if timed_out {
            return Err(AxError::from(AxErrorKind::TimedOut));
        }

        Ok(())
    }

    fn futex_wake_impl(
        &self,
        addr: usize,
        count: usize,
        resched: bool,
        is_private: bool,
        bitset: u32,
    ) -> usize {
        let (key, is_priv) = self.futex_key(addr, is_private);
        let woken = if is_priv {
            if resched {
                self.futex_table.wake_mask(key, count, bitset)
            } else {
                self.futex_table.wake_no_resched(key, count)
            }
        } else {
            if resched {
                GLOBAL_FUTEX_TABLE.wake_mask(key, count, bitset)
            } else {
                GLOBAL_FUTEX_TABLE.wake_no_resched(key, count)
            }
        };

        axlog::debug!(
            "futex_wake: tid={}, addr={:#x}, count={}, is_private={}, woken={}",
            current_thread().map(|thread| thread.tid()).unwrap_or(0),
            addr,
            count,
            is_private,
            woken
        );

        woken
    }

    pub fn futex_wake(&self, addr: usize, count: usize, is_private: bool) -> usize {
        self.futex_wake_impl(addr, count, true, is_private, u32::MAX)
    }

    pub fn futex_wake_mask(
        &self,
        addr: usize,
        count: usize,
        is_private: bool,
        bitset: u32,
    ) -> usize {
        self.futex_wake_impl(addr, count, true, is_private, bitset)
    }

    pub fn futex_wake_no_resched(&self, addr: usize, count: usize, is_private: bool) -> usize {
        self.futex_wake_impl(addr, count, false, is_private, u32::MAX)
    }

    pub fn futex_requeue(
        &self,
        addr: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
        is_private: bool,
    ) -> usize {
        let (key, is_priv) = self.futex_key(addr, is_private);
        let (target_key, _) = self.futex_key(target, is_private);
        let woken_requeued = if is_priv {
            self.futex_table
                .requeue(key, wake_count, target_key, requeue_count)
        } else {
            GLOBAL_FUTEX_TABLE.requeue(key, wake_count, target_key, requeue_count)
        };

        if is_priv {
            self.futex_table.remove_if_empty(key);
            self.futex_table.remove_if_empty(target_key);
        } else {
            GLOBAL_FUTEX_TABLE.remove_if_empty(key);
            GLOBAL_FUTEX_TABLE.remove_if_empty(target_key);
        }
        woken_requeued
    }

    pub fn exit_robust_list(&self, head_addr: usize) -> AxResult<()> {
        if head_addr == 0 {
            return Ok(());
        }

        let list_next = self.read_user_usize(head_addr)?;
        let futex_offset = self.read_user_isize(head_addr + core::mem::size_of::<usize>())?;
        let pending = self.read_user_usize(head_addr + core::mem::size_of::<usize>() * 2)?;
        let mut entry = list_next;
        let mut limit = ROBUST_LIST_LIMIT;

        while entry != 0 && entry != head_addr {
            let next = self.read_user_usize(entry)?;
            if entry != pending {
                self.wake_robust_entry(entry, futex_offset);
            }
            entry = next;
            limit -= 1;
            if limit == 0 {
                return Err(AxError::InvalidData);
            }
        }

        if pending != 0 {
            self.wake_robust_entry(pending, futex_offset);
        }
        Ok(())
    }

    fn wake_robust_entry(&self, entry: usize, futex_offset: isize) {
        let futex_addr = if futex_offset >= 0 {
            entry.wrapping_add(futex_offset as usize)
        } else {
            entry.wrapping_sub(futex_offset.unsigned_abs())
        };
        let _ = self.futex_wake_no_resched(futex_addr, 1, true);
        let _ = self.futex_wake_no_resched(futex_addr, 1, false);
    }

    pub fn futex_prune_empty(&self) {
        self.futex_table.prune_empty_entries();
        GLOBAL_FUTEX_TABLE.prune_empty_entries();
    }
}

pub const FUTEX_SHARDS: usize = 32;

#[inline]
pub fn futex_shard_index(key: usize) -> usize {
    let shifted = key >> 2;
    let hash = shifted.wrapping_mul(0x9e3779b97f4a7c15usize);
    (hash ^ (hash >> 32)) & (FUTEX_SHARDS - 1)
}

struct FutexShard {
    queues: BTreeMap<usize, Arc<WaitQueue>>,
    bitset_queues: BTreeMap<usize, BTreeMap<u32, Arc<WaitQueue>>>,
}

impl FutexShard {
    const fn new() -> Self {
        Self {
            queues: BTreeMap::new(),
            bitset_queues: BTreeMap::new(),
        }
    }

    fn queue(&mut self, key: usize) -> Arc<WaitQueue> {
        self.queues
            .entry(key)
            .or_insert_with(|| Arc::new(WaitQueue::new()))
            .clone()
    }

    fn queue_mask(&mut self, key: usize, bitset: u32) -> Arc<WaitQueue> {
        self.bitset_queues
            .entry(key)
            .or_default()
            .entry(bitset)
            .or_insert_with(|| Arc::new(WaitQueue::new()))
            .clone()
    }

    fn bitset_queues_for(&self, key: usize, wake_bitset: u32) -> Vec<(u32, Arc<WaitQueue>)> {
        self.bitset_queues
            .get(&key)
            .map(|by_bitset| {
                by_bitset
                    .iter()
                    .filter(|(bitset, _)| **bitset & wake_bitset != 0)
                    .map(|(bitset, queue)| (*bitset, queue.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn remove_if_empty(&mut self, key: usize) {
        if let Some(queue) = self.queues.get(&key) {
            queue.prune_exited();
            // The table must be the sole Arc owner. A waiter obtains an Arc
            // before it enrolls in the WaitQueue, so removing at a count of 2
            // can orphan that waiter before a concurrent wake lookup.
            if queue.is_empty() && Arc::strong_count(queue) == 1 {
                self.queues.remove(&key);
            }
        }
    }

    fn remove_bitset_if_empty(&mut self, key: usize) {
        if let Some(by_bitset) = self.bitset_queues.get_mut(&key) {
            by_bitset.retain(|_, queue| {
                queue.prune_exited();
                !(queue.is_empty() && Arc::strong_count(queue) == 1)
            });
            if by_bitset.is_empty() {
                self.bitset_queues.remove(&key);
            }
        }
    }

    fn prune_empty_entries(&mut self) {
        self.queues.retain(|_, queue| {
            queue.prune_exited();
            !(queue.is_empty() && Arc::strong_count(queue) == 1)
        });
        self.bitset_queues.retain(|_, by_bitset| {
            by_bitset.retain(|_, queue| {
                queue.prune_exited();
                !(queue.is_empty() && Arc::strong_count(queue) == 1)
            });
            !by_bitset.is_empty()
        });
    }

    fn clear(&mut self) {
        self.queues.clear();
        self.bitset_queues.clear();
    }

    fn entry_counts(&self) -> (usize, usize) {
        let regular_count = self.queues.len();
        let bitset_count = self.bitset_queues.values().map(|m| m.len()).sum();
        (regular_count, bitset_count)
    }
}

pub struct FutexTable {
    shards: [Mutex<FutexShard>; FUTEX_SHARDS],
}

impl FutexTable {
    pub fn new() -> Self {
        Self {
            shards: core::array::from_fn(|_| Mutex::new(FutexShard::new())),
        }
    }

    pub fn queue(&self, key: usize) -> Arc<WaitQueue> {
        let shard_idx = futex_shard_index(key);
        self.shards[shard_idx].lock().queue(key)
    }

    pub fn queue_mask(&self, key: usize, bitset: u32) -> Arc<WaitQueue> {
        if bitset == u32::MAX {
            return self.queue(key);
        }

        let shard_idx = futex_shard_index(key);
        self.shards[shard_idx].lock().queue_mask(key, bitset)
    }

    pub fn bitset_queues_for(&self, key: usize, wake_bitset: u32) -> Vec<(u32, Arc<WaitQueue>)> {
        let shard_idx = futex_shard_index(key);
        self.shards[shard_idx].lock().bitset_queues_for(key, wake_bitset)
    }

    fn wake_internal(&self, key: usize, count: usize, resched: bool) -> usize {
        let queue = {
            let shard_idx = futex_shard_index(key);
            let shard = self.shards[shard_idx].lock();
            shard.queues.get(&key).cloned()
        };
        let Some(queue) = queue else {
            return 0;
        };

        let mut woken = 0;
        let context = WakeContext::new(|| (WakeSource::Futex, key as u64));
        while woken < count && queue.notify_one_with_context(resched, context) {
            woken += 1;
        }
        drop(queue);
        self.remove_if_empty(key);
        woken
    }

    pub fn wake(&self, key: usize, count: usize) -> usize {
        self.wake_internal(key, count, true)
    }

    pub fn wake_mask(&self, key: usize, count: usize, wake_bitset: u32) -> usize {
        let mut woken = self.wake(key, count);
        if woken < count {
            let bitset_queues = self.bitset_queues_for(key, wake_bitset);
            let context = WakeContext::new(|| (WakeSource::Futex, key as u64));
            for (_, queue) in bitset_queues {
                while woken < count && queue.notify_one_with_context(true, context) {
                    woken += 1;
                }
                if woken == count {
                    break;
                }
            }
        }
        self.remove_bitset_if_empty(key);
        woken
    }

    pub fn wake_no_resched(&self, key: usize, count: usize) -> usize {
        self.wake_internal(key, count, false)
    }

    pub fn requeue_primary(
        &self,
        key: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
    ) -> (usize, usize) {
        let source_queue = {
            let shard_idx = futex_shard_index(key);
            let shard = self.shards[shard_idx].lock();
            shard.queues.get(&key).cloned()
        };
        let Some(source_queue) = source_queue else {
            return (0, 0);
        };

        let mut moved = 0;
        let mut woken = 0;
        let context = WakeContext::new(|| (WakeSource::Futex, key as u64));
        while woken < wake_count && source_queue.notify_one_with_context(true, context) {
            woken += 1;
        }

        if requeue_count != 0 {
            let target_queue = self.queue(target);
            if !Arc::ptr_eq(&source_queue, &target_queue) {
                moved = source_queue.requeue(requeue_count, &target_queue);
            }
        }
        (woken, moved)
    }

    pub fn requeue(
        &self,
        key: usize,
        wake_count: usize,
        target: usize,
        requeue_count: usize,
    ) -> usize {
        let (mut woken, mut moved) = self.requeue_primary(key, wake_count, target, requeue_count);

        {
            let source_queues = self.bitset_queues_for(key, u32::MAX);
            let context = WakeContext::new(|| (WakeSource::Futex, key as u64));
            for (bitset, source_queue) in source_queues {
                while woken < wake_count && source_queue.notify_one_with_context(true, context) {
                    woken += 1;
                }
                if moved < requeue_count {
                    let target_queue = self.queue_mask(target, bitset);
                    if !Arc::ptr_eq(&source_queue, &target_queue) {
                        moved += source_queue.requeue(requeue_count - moved, &target_queue);
                    }
                }
                if woken == wake_count && moved == requeue_count {
                    break;
                }
            }
        }
        self.remove_if_empty(key);
        self.remove_if_empty(target);
        self.remove_bitset_if_empty(key);
        self.remove_bitset_if_empty(target);
        woken + moved
    }

    pub fn wake_all(&self) {
        let mut all_queues = Vec::new();
        for shard in &self.shards {
            let shard = shard.lock();
            for (key, queue) in shard.queues.iter() {
                all_queues.push((*key, queue.clone()));
            }
            for (key, by_bitset) in shard.bitset_queues.iter() {
                for queue in by_bitset.values() {
                    all_queues.push((*key, queue.clone()));
                }
            }
        }
        for (key, queue) in all_queues {
            queue.notify_all_with_context(
                false,
                WakeContext::new(|| (WakeSource::Futex, key as u64)),
            );
        }
    }

    pub fn clear(&self) {
        self.wake_all();
        for shard in &self.shards {
            shard.lock().clear();
        }
    }

    pub fn prune_empty_entries(&self) {
        for shard in &self.shards {
            shard.lock().prune_empty_entries();
        }
    }

    pub fn remove_if_empty(&self, key: usize) {
        let shard_idx = futex_shard_index(key);
        self.shards[shard_idx].lock().remove_if_empty(key);
    }

    pub fn remove_mask_if_empty(&self, key: usize, bitset: u32) {
        if bitset == u32::MAX {
            self.remove_if_empty(key);
        } else {
            self.remove_bitset_if_empty(key);
        }
    }

    pub fn remove_bitset_if_empty(&self, key: usize) {
        let shard_idx = futex_shard_index(key);
        self.shards[shard_idx].lock().remove_bitset_if_empty(key);
    }

    pub fn shard_entry_count(&self, shard_idx: usize) -> (usize, usize) {
        if shard_idx >= FUTEX_SHARDS {
            return (0, 0);
        }
        self.shards[shard_idx].lock().entry_counts()
    }

    pub fn total_entry_count(&self) -> (usize, usize) {
        let mut total_regular = 0;
        let mut total_bitset = 0;
        for shard in &self.shards {
            let (reg, bit) = shard.lock().entry_counts();
            total_regular += reg;
            total_bitset += bit;
        }
        (total_regular, total_bitset)
    }
}

pub static GLOBAL_FUTEX_TABLE: Lazy<FutexTable> = Lazy::new(FutexTable::new);

pub fn run_futex_guest_checks() -> Result<(), axerrno::LinuxError> {
    axlog::ax_println!("[FUTEX_GUEST] Starting FutexTable sharding & scatter/gather checks...");

    let table = FutexTable::new();

    // 1. Shard distribution & scatter:
    // Find keys that map to distinct shards.
    let mut keys_by_shard = [0usize; 32];
    let mut found = 0;
    let mut candidate = 0x10000;
    while found < 32 {
        let shard = futex_shard_index(candidate);
        if keys_by_shard[shard] == 0 {
            keys_by_shard[shard] = candidate;
            found += 1;
        }
        candidate += 4;
    }

    // Verify key scatter: inserting in shard 0 does not alter shard 1
    let k0 = keys_by_shard[0];
    let k1 = keys_by_shard[1];
    let k2 = keys_by_shard[2];
    assert_eq!(futex_shard_index(k0), 0);
    assert_eq!(futex_shard_index(k1), 1);
    assert_eq!(futex_shard_index(k2), 2);

    let q0 = table.queue(k0);
    assert_eq!(table.shard_entry_count(0), (1, 0));
    assert_eq!(table.shard_entry_count(1), (0, 0));
    assert_eq!(table.total_entry_count(), (1, 0));

    let q1 = table.queue(k1);
    assert_eq!(table.shard_entry_count(0), (1, 0));
    assert_eq!(table.shard_entry_count(1), (1, 0));
    assert_eq!(table.total_entry_count(), (2, 0));

    // Same key returns the exact same wait queue
    let q0_again = table.queue(k0);
    assert!(Arc::ptr_eq(&q0, &q0_again));
    assert_eq!(table.total_entry_count(), (2, 0));

    drop(q0);
    drop(q0_again);
    drop(q1);

    // Test pruning empty queues
    table.remove_if_empty(k0);
    assert_eq!(table.shard_entry_count(0), (0, 0));
    assert_eq!(table.shard_entry_count(1), (1, 0));
    table.remove_if_empty(k1);
    assert_eq!(table.total_entry_count(), (0, 0));
    axlog::ax_println!("[FUTEX_GUEST] Shard isolation and scatter: PASS");

    // 2. Bitset queue sharding & matching
    let bq0_1 = table.queue_mask(k0, 0b01);
    let bq0_2 = table.queue_mask(k0, 0b10);
    let bq1_1 = table.queue_mask(k1, 0b01);
    assert_eq!(table.shard_entry_count(0), (0, 2));
    assert_eq!(table.shard_entry_count(1), (0, 1));

    let matched_k0 = table.bitset_queues_for(k0, 0b01);
    assert_eq!(matched_k0.len(), 1);
    assert_eq!(matched_k0[0].0, 0b01);

    let matched_k0_all = table.bitset_queues_for(k0, 0b11);
    assert_eq!(matched_k0_all.len(), 2);

    let matched_k2 = table.bitset_queues_for(k2, 0b11);
    assert_eq!(matched_k2.len(), 0);

    drop(bq0_1);
    drop(bq0_2);
    drop(bq1_1);
    drop(matched_k0);
    drop(matched_k0_all);
    drop(matched_k2);

    table.remove_bitset_if_empty(k0);
    table.remove_bitset_if_empty(k1);
    assert_eq!(table.total_entry_count(), (0, 0));
    axlog::ax_println!("[FUTEX_GUEST] Bitset queues per shard: PASS");

    // 3. Active bitset wait and wake_mask test with worker task
    {
        let bitset_done = Arc::new(AtomicBool::new(false));
        let bitset_started = Arc::new(AtomicBool::new(false));
        let bq = table.queue_mask(k0, 0b010);

        let b_done = bitset_done.clone();
        let b_started = bitset_started.clone();
        let bq_clone = bq.clone();
        axtask::spawn_raw(
            move || {
                b_started.store(true, Ordering::Release);
                bq_clone.wait_until(|| b_done.load(Ordering::Acquire));
            },
            "futex_bitset_waiter".into(),
            axconfig::TASK_STACK_SIZE,
        );

        while !bitset_started.load(Ordering::Acquire) || bq.len() == 0 {
            axtask::yield_now();
        }

        // Waking with non-overlapping mask 0b101 should NOT wake the waiter
        let woken_nomatch = table.wake_mask(k0, 1, 0b101);
        assert_eq!(woken_nomatch, 0);

        // Waking with matching mask 0b010 SHOULD wake the waiter
        bitset_done.store(true, Ordering::Release);
        let woken_match = table.wake_mask(k0, 1, 0b010);
        assert_eq!(woken_match, 1);

        for _ in 0..100 {
            if bq.len() == 0 {
                break;
            }
            axtask::yield_now();
        }
        assert_eq!(bq.len(), 0);
        drop(bq);
        table.remove_bitset_if_empty(k0);
        axlog::ax_println!("[FUTEX_GUEST] Active bitset wait and wake_mask: PASS");
    }

    // 4. Active cross-shard requeue waiter migration
    {
        let k_src = keys_by_shard[0];
        let k_dst = keys_by_shard[1];
        let waiter_done = Arc::new(AtomicBool::new(false));
        let waiter_started = Arc::new(AtomicBool::new(false));

        let q_src = table.queue(k_src);
        let q_dst = table.queue(k_dst);

        let done_clone = waiter_done.clone();
        let started_clone = waiter_started.clone();
        let q_src_clone = q_src.clone();
        axtask::spawn_raw(
            move || {
                started_clone.store(true, Ordering::Release);
                q_src_clone.wait_until(|| done_clone.load(Ordering::Acquire));
            },
            "futex_test_waiter".into(),
            axconfig::TASK_STACK_SIZE,
        );

        while !waiter_started.load(Ordering::Acquire) || q_src.len() == 0 {
            axtask::yield_now();
        }
        assert_eq!(q_src.len(), 1);
        assert_eq!(q_dst.len(), 0);

        // Move waiter from shard 0 (k_src) to shard 1 (k_dst) via cross-shard requeue
        let moved = table.requeue(k_src, 0, k_dst, 1);
        assert_eq!(moved, 1);
        assert_eq!(q_src.len(), 0);
        assert_eq!(q_dst.len(), 1);

        // Waking k_src should not wake anyone now
        let woken_src = table.wake(k_src, 1);
        assert_eq!(woken_src, 0);
        assert!(!waiter_done.load(Ordering::Acquire));

        // Waking k_dst should wake the moved waiter!
        waiter_done.store(true, Ordering::Release);
        let woken_dst = table.wake(k_dst, 1);
        assert_eq!(woken_dst, 1);

        for _ in 0..100 {
            if q_dst.len() == 0 {
                break;
            }
            axtask::yield_now();
        }
        assert_eq!(q_dst.len(), 0);
        drop(q_src);
        drop(q_dst);
        table.remove_if_empty(k_src);
        table.remove_if_empty(k_dst);
        axlog::ax_println!("[FUTEX_GUEST] Active cross-shard requeue waiter migration: PASS");
    }

    // 5. Cross-shard requeue full ring traversal
    // Populate all 32 shards with queues
    for (shard, &k) in keys_by_shard.iter().enumerate() {
        let _ = table.queue(k);
        assert_eq!(table.shard_entry_count(shard), (1, 0));
    }
    assert_eq!(table.total_entry_count(), (32, 0));

    // Requeue between every pair (i -> (i + 1) % 32)
    for i in 0..32 {
        let src = keys_by_shard[i];
        let dst = keys_by_shard[(i + 1) % 32];
        let res = table.requeue(src, 0, dst, 10);
        assert_eq!(res, 0); // No active waiters, so 0 moved/woken
    }
    axlog::ax_println!("[FUTEX_GUEST] Cross-shard requeue traversal: PASS");

    // 6. Gather operations: wake_all and clear across all shards
    for (shard, &k) in keys_by_shard.iter().enumerate() {
        let _ = table.queue(k);
        let _ = table.queue_mask(k, 0b101);
        assert_eq!(table.shard_entry_count(shard), (1, 1));
    }
    assert_eq!(table.total_entry_count(), (32, 32));

    table.wake_all(); // notifies all 32 shards
    assert_eq!(table.total_entry_count(), (32, 32));

    table.clear(); // clears all 32 shards
    assert_eq!(table.total_entry_count(), (0, 0));
    axlog::ax_println!("[FUTEX_GUEST] Gather wake_all and clear: PASS");

    // 7. Arc ownership check in prune_empty_entries:
    // If a waiter holds an Arc, prune_empty_entries must NOT remove it from the shard.
    let retained_q = table.queue(k0);
    assert_eq!(table.total_entry_count(), (1, 0));
    table.prune_empty_entries();
    // Since retained_q is held here, strong_count > 1, so it should stay!
    assert_eq!(table.total_entry_count(), (1, 0));
    drop(retained_q);
    // Now strong_count == 1, prune_empty_entries will clean it up!
    table.prune_empty_entries();
    assert_eq!(table.total_entry_count(), (0, 0));
    axlog::ax_println!("[FUTEX_GUEST] Arc ownership retention and pruning: PASS");

    axlog::ax_println!("[FUTEX_GUEST] All FutexTable sharding checks PASSED!");
    Ok(())
}
