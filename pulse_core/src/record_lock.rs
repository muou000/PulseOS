use alloc::{collections::BTreeMap, vec::Vec};

use axerrno::{LinuxError, LinuxResult};
use kspin::SpinNoIrq;
use spin::Lazy;

use crate::flock::{LOCK_TABLE_SHARDS, LockTarget, lock_target_shard};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordLockType {
    Read,
    Write,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RecordLock {
    owner: u64,
    start: i64,
    end: i64,
    lock_type: RecordLockType,
}

#[derive(Default)]
struct RecordLockState {
    entries: Vec<RecordLock>,
}

impl RecordLockState {
    fn conflict(
        &self,
        owner: u64,
        start: i64,
        end: i64,
        lock_type: RecordLockType,
    ) -> Option<RecordLock> {
        self.entries.iter().copied().find(|entry| {
            entry.owner != owner
                && ranges_overlap(entry.start, entry.end, start, end)
                && lock_types_conflict(entry.lock_type, lock_type)
        })
    }

    fn set(
        &mut self,
        owner: u64,
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

    fn clear_owner_range(&mut self, owner: u64, start: i64, end: i64) -> bool {
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

    fn release_owner(&mut self, owner: u64) {
        self.entries.retain(|entry| entry.owner != owner);
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

pub fn set_posix_lock(
    owner: u64,
    target: LockTarget,
    start: i64,
    end: i64,
    lock_type: RecordLockType,
) -> LinuxResult<isize> {
    let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
    locks
        .entry(target)
        .or_default()
        .set(owner, start, end, lock_type)?;
    Ok(0)
}

pub fn unlock_posix_lock(
    owner: u64,
    target: LockTarget,
    start: i64,
    end: i64,
) -> LinuxResult<isize> {
    validate_range(start, end)?;
    let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
    let remove_target = locks.get_mut(&target).is_some_and(|state| {
        state.clear_owner_range(owner, start, end);
        state.entries.is_empty()
    });
    if remove_target {
        locks.remove(&target);
    }
    Ok(0)
}

pub fn release_posix_owner_target(owner: u64, target: LockTarget) {
    let mut locks = RECORD_LOCKS[lock_target_shard(target)].lock();
    let remove_target = locks.get_mut(&target).is_some_and(|state| {
        state.release_owner(owner);
        state.entries.is_empty()
    });
    if remove_target {
        locks.remove(&target);
    }
}

pub fn release_posix_owner(owner: u64) {
    for shard in RECORD_LOCKS.iter() {
        shard.lock().retain(|_, state| {
            state.release_owner(owner);
            !state.entries.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conflicting_locks_from_different_owners_fail() {
        let mut state = RecordLockState::default();
        state.set(1, 0, 100, RecordLockType::Read).unwrap();
        state.set(2, 0, 100, RecordLockType::Read).unwrap();

        assert!(matches!(
            state.set(3, 50, 60, RecordLockType::Write),
            Err(LinuxError::EAGAIN)
        ));
        assert_eq!(state.entries.len(), 2);
    }

    #[test]
    fn same_owner_can_replace_part_of_a_lock() {
        let mut state = RecordLockState::default();
        state.set(1, 0, 100, RecordLockType::Write).unwrap();
        state.set(1, 25, 75, RecordLockType::Read).unwrap();

        assert!(state.conflict(2, 10, 20, RecordLockType::Read).is_some());
        assert!(state.conflict(2, 30, 40, RecordLockType::Read).is_none());
        assert!(state.conflict(2, 30, 40, RecordLockType::Write).is_some());
        assert_eq!(state.entries.len(), 3);
    }

    #[test]
    fn partial_unlock_splits_an_existing_lock() {
        let mut state = RecordLockState::default();
        state.set(1, 0, 100, RecordLockType::Write).unwrap();
        state.clear_owner_range(1, 20, 80);

        assert!(state.conflict(2, 10, 11, RecordLockType::Write).is_some());
        assert!(state.conflict(2, 50, 51, RecordLockType::Write).is_none());
        assert!(state.conflict(2, 90, 91, RecordLockType::Write).is_some());
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
