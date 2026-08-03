use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use axerrno::{LinuxError, LinuxResult};
use kspin::SpinNoIrq;
use spin::Lazy;

use crate::flock::{LOCK_TABLE_SHARDS, LockTarget, lock_target_shard};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordLockType {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordLockOwner {
    Posix(u64),
    Ofd(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordLockConflict {
    pub owner: RecordLockOwner,
    pub start: i64,
    pub end: i64,
    pub lock_type: RecordLockType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecordLock {
    owner: RecordLockOwner,
    start: i64,
    end: i64,
    lock_type: RecordLockType,
}

struct RecordLockState {
    entries: Vec<RecordLock>,
    wait_queue: Arc<axtask::WaitQueue>,
    waiters: usize,
}

impl Default for RecordLockState {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            wait_queue: Arc::new(axtask::WaitQueue::new()),
            waiters: 0,
        }
    }
}

impl RecordLockState {
    fn conflict(
        &self,
        owner: RecordLockOwner,
        start: i64,
        end: i64,
        lock_type: RecordLockType,
    ) -> Option<RecordLock> {
        self.entries
            .iter()
            .copied()
            .filter(|entry| {
                entry.owner != owner
                    && ranges_overlap(entry.start, entry.end, start, end)
                    && lock_types_conflict(entry.lock_type, lock_type)
            })
            .min_by_key(|entry| (entry.start, entry.end, entry.owner))
    }

    fn set(
        &mut self,
        owner: RecordLockOwner,
        start: i64,
        end: i64,
        lock_type: RecordLockType,
    ) -> LinuxResult<()> {
        validate_range(start, end)?;
        if self.conflict(owner, start, end, lock_type).is_some() {
            return Err(LinuxError::EAGAIN);
        }

        self.clear_owner_range(owner, start, end);
        self.entries.push(RecordLock {
            owner,
            start,
            end,
            lock_type,
        });
        self.coalesce();
        Ok(())
    }

    fn clear_owner_range(&mut self, owner: RecordLockOwner, start: i64, end: i64) -> bool {
        let mut changed = false;
        let mut index = 0;
        while index < self.entries.len() {
            let entry = self.entries[index];
            if entry.owner != owner || !ranges_overlap(entry.start, entry.end, start, end) {
                index += 1;
                continue;
            }

            changed = true;
            self.entries.swap_remove(index);
            if entry.start < start {
                self.entries.push(RecordLock {
                    end: start,
                    ..entry
                });
            }
            if entry.end > end {
                self.entries.push(RecordLock {
                    start: end,
                    ..entry
                });
            }
        }
        changed
    }

    fn release_owner(&mut self, owner: RecordLockOwner) -> bool {
        let old_len = self.entries.len();
        self.entries.retain(|entry| entry.owner != owner);
        self.entries.len() != old_len
    }

    fn coalesce(&mut self) {
        self.entries
            .sort_unstable_by_key(|entry| (entry.owner, entry.lock_type, entry.start, entry.end));

        let mut output = 0;
        for index in 0..self.entries.len() {
            let entry = self.entries[index];
            if output > 0 {
                let previous = &mut self.entries[output - 1];
                if previous.owner == entry.owner
                    && previous.lock_type == entry.lock_type
                    && entry.start <= previous.end
                {
                    previous.end = previous.end.max(entry.end);
                    continue;
                }
            }
            self.entries[output] = entry;
            output += 1;
        }
        self.entries.truncate(output);
    }
}

static RECORD_LOCKS: Lazy<[SpinNoIrq<BTreeMap<LockTarget, RecordLockState>>; LOCK_TABLE_SHARDS]> =
    Lazy::new(|| core::array::from_fn(|_| SpinNoIrq::new(BTreeMap::new())));

fn ranges_overlap(a_start: i64, a_end: i64, b_start: i64, b_end: i64) -> bool {
    a_start < b_end && b_start < a_end
}

fn lock_types_conflict(a: RecordLockType, b: RecordLockType) -> bool {
    !(a == RecordLockType::Read && b == RecordLockType::Read)
}

fn validate_range(start: i64, end: i64) -> LinuxResult<()> {
    if start < 0 || start >= end {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

fn current_has_pending_signal() -> bool {
    crate::task::current_thread()
        .map(|thread| thread.has_pending_signal())
        .unwrap_or(false)
}

pub fn resolve_range(base: i64, relative_start: i64, len: i64) -> LinuxResult<(i64, i64)> {
    let resolved_start = base.checked_add(relative_start).ok_or(LinuxError::EINVAL)?;
    if len == 0 {
        validate_range(resolved_start, i64::MAX)?;
        return Ok((resolved_start, i64::MAX));
    }

    let (start, end) = if len > 0 {
        (
            resolved_start,
            resolved_start.checked_add(len).ok_or(LinuxError::EINVAL)?,
        )
    } else {
        (
            resolved_start.checked_add(len).ok_or(LinuxError::EINVAL)?,
            resolved_start,
        )
    };
    validate_range(start, end)?;
    Ok((start, end))
}

pub fn get_lock(
    owner: RecordLockOwner,
    target: LockTarget,
    start: i64,
    end: i64,
    lock_type: RecordLockType,
) -> LinuxResult<Option<RecordLockConflict>> {
    validate_range(start, end)?;
    let locks = RECORD_LOCKS[lock_target_shard(target)].lock();
    Ok(locks.get(&target).and_then(|state| {
        state
            .conflict(owner, start, end, lock_type)
            .map(|entry| RecordLockConflict {
                owner: entry.owner,
                start: entry.start,
                end: entry.end,
                lock_type: entry.lock_type,
            })
    }))
}

pub fn set_lock(
    owner: RecordLockOwner,
    target: LockTarget,
    start: i64,
    end: i64,
    lock_type: RecordLockType,
    blocking: bool,
) -> LinuxResult<isize> {
    validate_range(start, end)?;

    loop {
        let wait_queue = {
            let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
            let state = locks.entry(target).or_default();
            if state.conflict(owner, start, end, lock_type).is_none() {
                state.set(owner, start, end, lock_type)?;
                let wait_queue = state.wait_queue.clone();
                drop(locks);
                wait_queue.notify_all(true);
                return Ok(0);
            }
            if !blocking {
                return Err(LinuxError::EAGAIN);
            }
            state.waiters += 1;
            state.wait_queue.clone()
        };

        if current_has_pending_signal() {
            finish_wait(target);
            return Err(LinuxError::EINTR);
        }

        wait_queue.wait_until(|| {
            if current_has_pending_signal() {
                return true;
            }
            let locks = RECORD_LOCKS[lock_target_shard(target)].lock();
            locks
                .get(&target)
                .is_none_or(|state| state.conflict(owner, start, end, lock_type).is_none())
        });
        finish_wait(target);

        if current_has_pending_signal() {
            return Err(LinuxError::EINTR);
        }
    }
}

fn finish_wait(target: LockTarget) {
    let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
    let remove_target = locks.get_mut(&target).is_some_and(|state| {
        debug_assert!(state.waiters > 0);
        state.waiters = state.waiters.saturating_sub(1);
        state.entries.is_empty() && state.waiters == 0
    });
    if remove_target {
        locks.remove(&target);
    }
}

pub fn unlock_lock(
    owner: RecordLockOwner,
    target: LockTarget,
    start: i64,
    end: i64,
) -> LinuxResult<isize> {
    validate_range(start, end)?;
    let wait_queue = {
        let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
        let mut wait_queue = None;
        let remove_target = locks.get_mut(&target).is_some_and(|state| {
            if state.clear_owner_range(owner, start, end) {
                wait_queue = Some(state.wait_queue.clone());
            }
            state.entries.is_empty() && state.waiters == 0
        });
        if remove_target {
            locks.remove(&target);
        }
        wait_queue
    };
    if let Some(wait_queue) = wait_queue {
        wait_queue.notify_all(true);
    }
    Ok(0)
}

pub fn release_posix_owner_target(owner: u64, target: LockTarget) {
    release_owner_target(RecordLockOwner::Posix(owner), target);
}

fn release_owner_target(owner: RecordLockOwner, target: LockTarget) {
    let wait_queue = {
        let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
        let mut wait_queue = None;
        let remove_target = locks.get_mut(&target).is_some_and(|state| {
            if state.release_owner(owner) {
                wait_queue = Some(state.wait_queue.clone());
            }
            state.entries.is_empty() && state.waiters == 0
        });
        if remove_target {
            locks.remove(&target);
        }
        wait_queue
    };
    if let Some(wait_queue) = wait_queue {
        wait_queue.notify_all(true);
    }
}

pub fn release_posix_owner(owner: u64) {
    release_owner(RecordLockOwner::Posix(owner));
}

pub fn release_ofd_owner(owner: usize) {
    release_owner(RecordLockOwner::Ofd(owner));
}

fn release_owner(owner: RecordLockOwner) {
    let mut wait_queues = Vec::new();
    for shard in RECORD_LOCKS.iter() {
        let mut locks = shard.lock();
        for state in locks.values_mut() {
            if state.release_owner(owner) {
                wait_queues.push(state.wait_queue.clone());
            }
        }
        locks.retain(|_, state| !state.entries.is_empty() || state.waiters != 0);
    }
    for wait_queue in wait_queues {
        wait_queue.notify_all(true);
    }
}

pub fn set_posix_lock(
    owner: u64,
    target: LockTarget,
    start: i64,
    end: i64,
    lock_type: RecordLockType,
) -> LinuxResult<isize> {
    set_lock(
        RecordLockOwner::Posix(owner),
        target,
        start,
        end,
        lock_type,
        false,
    )
}

pub fn unlock_posix_lock(
    owner: u64,
    target: LockTarget,
    start: i64,
    end: i64,
) -> LinuxResult<isize> {
    unlock_lock(RecordLockOwner::Posix(owner), target, start, end)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn posix(pid: u64) -> RecordLockOwner {
        RecordLockOwner::Posix(pid)
    }

    #[test]
    fn conflicting_locks_from_different_owners_fail() {
        let mut state = RecordLockState::default();
        state.set(posix(1), 0, 100, RecordLockType::Read).unwrap();
        state.set(posix(2), 0, 100, RecordLockType::Read).unwrap();

        assert!(matches!(
            state.set(posix(3), 50, 60, RecordLockType::Write),
            Err(LinuxError::EAGAIN)
        ));
        assert_eq!(state.entries.len(), 2);
    }

    #[test]
    fn same_owner_can_replace_part_of_a_lock() {
        let mut state = RecordLockState::default();
        state.set(posix(1), 0, 100, RecordLockType::Write).unwrap();
        state.set(posix(1), 25, 75, RecordLockType::Read).unwrap();

        assert!(
            state
                .conflict(posix(2), 10, 20, RecordLockType::Read)
                .is_some()
        );
        assert!(
            state
                .conflict(posix(2), 30, 40, RecordLockType::Read)
                .is_none()
        );
        assert!(
            state
                .conflict(posix(2), 30, 40, RecordLockType::Write)
                .is_some()
        );
        assert_eq!(state.entries.len(), 3);
    }

    #[test]
    fn partial_unlock_splits_an_existing_lock() {
        let mut state = RecordLockState::default();
        state.set(posix(1), 0, 100, RecordLockType::Write).unwrap();
        state.clear_owner_range(posix(1), 20, 80);

        assert!(
            state
                .conflict(posix(2), 10, 11, RecordLockType::Write)
                .is_some()
        );
        assert!(
            state
                .conflict(posix(2), 50, 51, RecordLockType::Write)
                .is_none()
        );
        assert!(
            state
                .conflict(posix(2), 90, 91, RecordLockType::Write)
                .is_some()
        );
    }

    #[test]
    fn posix_and_ofd_owners_conflict_even_with_the_same_numeric_id() {
        let mut state = RecordLockState::default();
        state.set(posix(7), 0, 100, RecordLockType::Write).unwrap();

        let conflict = state
            .conflict(RecordLockOwner::Ofd(7), 0, 100, RecordLockType::Write)
            .unwrap();
        assert_eq!(conflict.owner, posix(7));
    }

    #[test]
    fn conflict_query_returns_lowest_starting_lock() {
        let mut state = RecordLockState::default();
        state.set(posix(2), 40, 50, RecordLockType::Write).unwrap();
        state.set(posix(1), 10, 20, RecordLockType::Write).unwrap();

        let conflict = state
            .conflict(posix(3), 0, 100, RecordLockType::Write)
            .unwrap();
        assert_eq!((conflict.start, conflict.end), (10, 20));
    }

    #[test]
    fn range_resolution_handles_eof_and_negative_lengths() {
        assert_eq!(resolve_range(0, 10, 0).unwrap(), (10, i64::MAX));
        assert_eq!(resolve_range(0, 10, -5).unwrap(), (5, 10));
        assert!(matches!(resolve_range(0, 4, -5), Err(LinuxError::EINVAL)));
        assert!(matches!(
            resolve_range(i64::MAX, 1, 1),
            Err(LinuxError::EINVAL)
        ));
    }
}
