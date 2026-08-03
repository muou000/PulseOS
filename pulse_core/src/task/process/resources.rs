use super::*;

impl Process {
    fn memlock_additional_bytes(ranges: &[MemlockRange], start: usize, end: usize) -> usize {
        if start >= end {
            return 0;
        }
        let mut covered = 0usize;
        for range in ranges {
            if range.end <= start {
                continue;
            }
            if range.start >= end {
                break;
            }
            let overlap_start = core::cmp::max(range.start, start);
            let overlap_end = core::cmp::min(range.end, end);
            if overlap_start < overlap_end {
                covered = covered.saturating_add(overlap_end - overlap_start);
            }
        }
        (end - start).saturating_sub(covered)
    }

    fn memlock_insert_range(ranges: &mut Vec<MemlockRange>, start: usize, end: usize) -> AxResult {
        if start >= end {
            return Ok(());
        }
        let mut merged_start = start;
        let mut merged_end = end;
        let mut merged = Vec::new();
        if merged
            .try_reserve_exact(ranges.len().saturating_add(1))
            .is_err()
        {
            return Err(AxError::NoMemory);
        }
        let mut inserted = false;
        for range in ranges.iter().copied() {
            if range.end < merged_start {
                merged.push(range);
                continue;
            }
            if merged_end < range.start {
                if !inserted {
                    merged.push(MemlockRange::new(merged_start, merged_end));
                    inserted = true;
                }
                merged.push(range);
                continue;
            }
            merged_start = core::cmp::min(merged_start, range.start);
            merged_end = core::cmp::max(merged_end, range.end);
        }
        if !inserted {
            merged.push(MemlockRange::new(merged_start, merged_end));
        }
        *ranges = merged;
        Ok(())
    }

    fn memlock_remove_range(
        ranges: &mut Vec<MemlockRange>,
        start: usize,
        end: usize,
    ) -> AxResult<usize> {
        if start >= end {
            return Ok(0);
        }
        let mut removed = 0usize;
        let mut next = Vec::new();
        if next.try_reserve_exact(ranges.len()).is_err() {
            return Err(AxError::NoMemory);
        }
        for range in ranges.iter().copied() {
            if range.end <= start || range.start >= end {
                next.push(range);
                continue;
            }
            let overlap_start = core::cmp::max(range.start, start);
            let overlap_end = core::cmp::min(range.end, end);
            if overlap_start < overlap_end {
                removed = removed.saturating_add(overlap_end - overlap_start);
            }
            if range.start < overlap_start {
                next.push(MemlockRange::new(range.start, overlap_start));
            }
            if overlap_end < range.end {
                next.push(MemlockRange::new(overlap_end, range.end));
            }
        }
        *ranges = next;
        Ok(removed)
    }
}

impl Process {
    pub fn memlock_limit_snapshot(&self) -> (u64, u64) {
        let res = self.resources.lock();
        (res.memlock_state.soft_limit, res.memlock_state.hard_limit)
    }

    pub fn memlock_set_limit(&self, soft: u64, hard: u64) {
        let mut res = self.resources.lock();
        res.memlock_state.soft_limit = soft;
        res.memlock_state.hard_limit = hard;
    }

    pub fn get_rlimit(&self, resource: u32) -> Option<rlimit64> {
        let res = self.resources.lock();
        match resource {
            RLIMIT_STACK => Some(rlimit64 {
                rlim_cur: res.rlimit_state.stack_soft,
                rlim_max: res.rlimit_state.stack_hard,
            }),
            RLIMIT_NOFILE => Some(rlimit64 {
                rlim_cur: res.rlimit_state.nofile_soft,
                rlim_max: res.rlimit_state.nofile_hard,
            }),
            RLIMIT_CORE => Some(rlimit64 {
                rlim_cur: res.rlimit_state.core_soft,
                rlim_max: res.rlimit_state.core_hard,
            }),
            RLIMIT_DATA => Some(rlimit64 {
                rlim_cur: res.rlimit_state.data_soft,
                rlim_max: res.rlimit_state.data_hard,
            }),
            RLIMIT_SIGPENDING => Some(rlimit64 {
                rlim_cur: res.rlimit_state.sigpending_soft,
                rlim_max: res.rlimit_state.sigpending_hard,
            }),
            RLIMIT_MEMLOCK => Some(rlimit64 {
                rlim_cur: res.memlock_state.soft_limit,
                rlim_max: res.memlock_state.hard_limit,
            }),
            _ => None,
        }
    }

    pub fn set_rlimit(&self, resource: u32, limit: rlimit64) -> AxResult<()> {
        if limit.rlim_cur > limit.rlim_max {
            return Err(AxError::InvalidInput);
        }
        let mut res = self.resources.lock();
        match resource {
            RLIMIT_STACK => {
                if limit.rlim_max > MAX_STACK_LIMIT_BYTES {
                    return Err(AxError::InvalidInput);
                }
                res.rlimit_state.stack_soft = limit.rlim_cur;
                res.rlimit_state.stack_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_NOFILE => {
                if limit.rlim_max > MAX_NOFILE_LIMIT {
                    return Err(AxError::InvalidInput);
                }
                res.rlimit_state.nofile_soft = limit.rlim_cur;
                res.rlimit_state.nofile_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_CORE => {
                res.rlimit_state.core_soft = limit.rlim_cur;
                res.rlimit_state.core_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_DATA => {
                res.rlimit_state.data_soft = limit.rlim_cur;
                res.rlimit_state.data_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_SIGPENDING => {
                res.rlimit_state.sigpending_soft = limit.rlim_cur;
                res.rlimit_state.sigpending_hard = limit.rlim_max;
                Ok(())
            }
            RLIMIT_MEMLOCK => {
                res.memlock_state.soft_limit = limit.rlim_cur;
                res.memlock_state.hard_limit = limit.rlim_max;
                Ok(())
            }
            _ => Err(AxError::InvalidInput),
        }
    }

    /// The queue allocator consults the target's current soft limit while
    /// charging records to its real UID, matching Linux's signal accounting
    /// boundary.
    pub fn sigpending_limit(&self) -> u64 {
        self.resources.lock().rlimit_state.sigpending_soft
    }

    pub fn memlock_locked_bytes(&self) -> usize {
        self.resources.lock().memlock_state.locked_bytes
    }

    pub fn memlock_future_enabled(&self) -> bool {
        self.resources.lock().memlock_state.mlock_future
    }

    pub fn memlock_set_future(&self, enabled: bool) {
        self.resources.lock().memlock_state.mlock_future = enabled;
    }

    pub fn memlock_try_lock_range(
        &self,
        start: usize,
        len: usize,
        privileged: bool,
    ) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start.checked_add(len).ok_or(AxError::BadAddress)?;
        let mut res = self.resources.lock();
        let additional = Self::memlock_additional_bytes(&res.memlock_state.ranges, start, end);
        if additional == 0 {
            return Ok(());
        }
        if !privileged && res.memlock_state.soft_limit != u64::MAX {
            let new_total =
                (res.memlock_state.locked_bytes as u128).saturating_add(additional as u128);
            if new_total > res.memlock_state.soft_limit as u128 {
                return Err(AxError::NoMemory);
            }
        }
        Self::memlock_insert_range(&mut res.memlock_state.ranges, start, end)?;
        res.memlock_state.locked_bytes = res.memlock_state.locked_bytes.saturating_add(additional);
        Ok(())
    }

    pub fn memlock_unlock_range(&self, start: usize, len: usize) -> AxResult<()> {
        if len == 0 {
            return Ok(());
        }
        let end = start.checked_add(len).ok_or(AxError::BadAddress)?;
        let mut res = self.resources.lock();
        let removed = Self::memlock_remove_range(&mut res.memlock_state.ranges, start, end)?;
        res.memlock_state.locked_bytes = res.memlock_state.locked_bytes.saturating_sub(removed);
        Ok(())
    }

    pub fn memlock_unlock_all(&self) {
        let mut res = self.resources.lock();
        res.memlock_state.ranges.clear();
        res.memlock_state.locked_bytes = 0;
        res.memlock_state.mlock_future = false;
    }
}
