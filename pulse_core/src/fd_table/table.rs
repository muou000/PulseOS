use super::*;

fn is_ns_location(location: &Location) -> Option<(u64, u32)> {
    let metadata = axtask::future::block_on(location.metadata()).ok()?;
    let ino = metadata.inode;
    if ino >= axfs::fs::procfs::PID_INODE_START {
        let offset = ino - axfs::fs::procfs::PID_INODE_START;
        let pid = offset >> axfs::fs::procfs::PID_INODE_SHIFT;
        let sub = offset & ((1 << axfs::fs::procfs::PID_INODE_SHIFT) - 1);
        let ns_type = match sub {
            axfs::fs::procfs::SUB_INO_NS_UTS => CLONE_NEWUTS,
            axfs::fs::procfs::SUB_INO_NS_IPC => CLONE_NEWIPC,
            axfs::fs::procfs::SUB_INO_NS_NET => CLONE_NEWNET,
            axfs::fs::procfs::SUB_INO_NS_MNT => CLONE_NEWNS,
            axfs::fs::procfs::SUB_INO_NS_PID => CLONE_NEWPID,
            axfs::fs::procfs::SUB_INO_NS_USER => CLONE_NEWUSER,
            axfs::fs::procfs::SUB_INO_NS_CGROUP => CLONE_NEWCGROUP,
            _ => return None,
        };
        Some((pid, ns_type))
    } else {
        None
    }
}

pub fn open_result_to_entry(result: OpenResult, flags: FdFlags) -> FdEntry {
    let object: Arc<dyn FdObject> = match result {
        OpenResult::File(file) => {
            if super::objects::is_cpu_dma_latency_device(file.location()) {
                Arc::new(CpuDmaLatencyObject::new(file.location().clone()))
            } else if let Some((pid, ns_type)) = is_ns_location(file.location()) {
                Arc::new(NsFdObject { ns_type, pid })
            } else {
                Arc::new(FileObject::new(file))
            }
        }
        OpenResult::Dir(dir) => Arc::new(DirObject::new(dir)),
    };
    if flags.contains(FdFlags::NONBLOCK) {
        let _ = object.set_nonblocking(true);
    }
    FdEntry::new(object, flags)
}

const FD_CHUNK_SIZE: usize = 64;

#[inline]
fn fd_range_mask(first_bit: usize, last_bit: usize) -> u64 {
    debug_assert!(first_bit <= last_bit);
    debug_assert!(last_bit < FD_CHUNK_SIZE);

    let from_first = u64::MAX << first_bit;
    let through_last = if last_bit + 1 == FD_CHUNK_SIZE {
        u64::MAX
    } else {
        (1u64 << (last_bit + 1)) - 1
    };
    from_first & through_last
}

#[derive(Clone)]
struct FdChunk {
    entries: [Option<FdEntry>; FD_CHUNK_SIZE],
}

impl Default for FdChunk {
    fn default() -> Self {
        Self {
            entries: core::array::from_fn(|_| None),
        }
    }
}

#[derive(Clone, Default)]
struct FdTableStorage {
    chunks: alloc::vec::Vec<Option<Arc<FdChunk>>>,
    open_fds: alloc::vec::Vec<u64>,
    count: usize,
}

pub struct FdTable {
    storage: Arc<FdTableStorage>,
}

/// Owns detached descriptor storage so its objects are released outside the table lock.
#[must_use = "drained fd entries must be dropped after releasing the fd-table lock"]
pub struct DrainedFdEntries {
    _storage: Arc<FdTableStorage>,
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            storage: Arc::new(FdTableStorage::default()),
        }
    }

    pub fn clone_for_fork(&self) -> Self {
        Self {
            storage: self.storage.clone(),
        }
    }

    pub fn take_cloexec_on_exec(&mut self) -> alloc::vec::Vec<FdEntry> {
        let mut removed = alloc::vec::Vec::new();
        let has_cloexec = self.storage.chunks.iter().any(|chunk_opt| {
            chunk_opt.as_ref().is_some_and(|chunk| {
                chunk.entries.iter().any(|slot| {
                    slot.as_ref()
                        .is_some_and(|entry| entry.flags.contains(FdFlags::CLOEXEC))
                })
            })
        });
        if !has_cloexec {
            return removed;
        }

        let storage = Arc::make_mut(&mut self.storage);
        for chunk_idx in 0..storage.chunks.len() {
            let chunk_has_cloexec = storage.chunks[chunk_idx].as_ref().is_some_and(|chunk| {
                chunk.entries.iter().any(|slot| {
                    slot.as_ref()
                        .is_some_and(|entry| entry.flags.contains(FdFlags::CLOEXEC))
                })
            });
            if !chunk_has_cloexec {
                continue;
            }

            let chunk_arc = storage.chunks[chunk_idx].as_mut().unwrap();
            let chunk = Arc::make_mut(chunk_arc);
            for bit_idx in 0..FD_CHUNK_SIZE {
                if let Some(entry) = &chunk.entries[bit_idx] {
                    if entry.flags.contains(FdFlags::CLOEXEC) {
                        let fd = chunk_idx * FD_CHUNK_SIZE + bit_idx;
                        axlog::debug!(
                            "take_cloexec_on_exec: removing cloexec fd entry fd={}, flags={:?}, \
                             object={:p}",
                            fd,
                            entry.flags,
                            Arc::as_ptr(&entry.object)
                        );
                        if let Some(taken) = chunk.entries[bit_idx].take() {
                            removed.push(taken);
                            storage.count = storage.count.saturating_sub(1);
                            if chunk_idx < storage.open_fds.len() {
                                storage.open_fds[chunk_idx] &= !(1 << bit_idx);
                            }
                        }
                    }
                }
            }
        }
        removed
    }

    pub fn drain_all(&mut self) -> DrainedFdEntries {
        let storage = core::mem::replace(&mut self.storage, Arc::new(FdTableStorage::default()));
        DrainedFdEntries { _storage: storage }
    }

    pub fn entries_snapshot(&self) -> alloc::vec::Vec<FdEntry> {
        self.storage
            .chunks
            .iter()
            .filter_map(|slot| slot.as_ref())
            .flat_map(|chunk| chunk.entries.iter())
            .flatten()
            .cloned()
            .collect()
    }

    pub fn get(&self, fd: usize) -> Option<&FdEntry> {
        let chunk_idx = fd / FD_CHUNK_SIZE;
        let bit_idx = fd % FD_CHUNK_SIZE;
        self.storage
            .chunks
            .get(chunk_idx)?
            .as_ref()?
            .entries
            .get(bit_idx)?
            .as_ref()
    }

    pub fn get_entry_cloned(&self, fd: usize) -> LinuxResult<FdEntry> {
        self.get(fd).cloned().ok_or(LinuxError::EBADF)
    }

    pub fn get_object(&self, fd: usize) -> LinuxResult<Arc<dyn FdObject>> {
        self.get(fd)
            .map(|entry| entry.object.clone())
            .ok_or(LinuxError::EBADF)
    }

    pub fn objects_snapshot(
        &self,
        fds: impl Iterator<Item = usize>,
    ) -> LinuxResult<Vec<Option<Arc<dyn FdObject>>>> {
        let mut objects = Vec::new();
        if let Some(upper) = fds.size_hint().1 {
            objects.try_reserve(upper).map_err(|_| LinuxError::ENOMEM)?;
        }
        for fd in fds {
            if objects.len() == objects.capacity() {
                objects.try_reserve(1).map_err(|_| LinuxError::ENOMEM)?;
            }
            objects.push(self.get(fd).map(|entry| entry.object.clone()));
        }
        Ok(objects)
    }

    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> {
        let chunk_idx = fd / FD_CHUNK_SIZE;
        let bit_idx = fd % FD_CHUNK_SIZE;
        if self.get(fd).is_none() {
            return None;
        }
        let storage = Arc::make_mut(&mut self.storage);
        let chunk_arc = storage.chunks.get_mut(chunk_idx)?.as_mut()?;
        let chunk = Arc::make_mut(chunk_arc);
        chunk.entries.get_mut(bit_idx)?.as_mut()
    }

    pub fn insert_at(&mut self, fd: usize, entry: FdEntry) -> LinuxResult {
        if fd >= FD_LIMIT {
            return Err(LinuxError::EBADF);
        }
        let chunk_idx = fd / FD_CHUNK_SIZE;
        let bit_idx = fd % FD_CHUNK_SIZE;

        let storage = Arc::make_mut(&mut self.storage);
        if chunk_idx >= storage.chunks.len() {
            let mut new_chunks_len = core::cmp::max(1, storage.chunks.len());
            while new_chunks_len <= chunk_idx {
                new_chunks_len = new_chunks_len.saturating_mul(2);
            }
            let max_chunks = (FD_LIMIT + FD_CHUNK_SIZE - 1) / FD_CHUNK_SIZE;
            new_chunks_len = core::cmp::min(new_chunks_len, max_chunks);
            if chunk_idx >= new_chunks_len {
                return Err(LinuxError::EMFILE);
            }
            storage.chunks.resize(new_chunks_len, None);
            storage.open_fds.resize(new_chunks_len, 0);
        }

        let chunk_slot = &mut storage.chunks[chunk_idx];
        if chunk_slot.is_none() {
            *chunk_slot = Some(Arc::new(FdChunk::default()));
        }
        let chunk = Arc::make_mut(chunk_slot.as_mut().unwrap());

        if chunk.entries[bit_idx].is_none() {
            storage.count = storage.count.saturating_add(1);
            storage.open_fds[chunk_idx] |= 1 << bit_idx;
        }
        chunk.entries[bit_idx] = Some(entry);
        Ok(())
    }

    pub fn insert_from(&mut self, min_fd: usize, entry: FdEntry) -> LinuxResult<usize> {
        let mut found_fd = None;
        let min_word = min_fd / FD_CHUNK_SIZE;

        if min_word < self.storage.open_fds.len() {
            for word_idx in min_word..self.storage.open_fds.len() {
                let mut word = self.storage.open_fds[word_idx];

                if word_idx == min_word {
                    let min_bit = min_fd % FD_CHUNK_SIZE;
                    let mask = (1u64 << min_bit) - 1;
                    word |= mask;
                }

                if word != u64::MAX {
                    let bit_idx = (!word).trailing_zeros() as usize;
                    let fd = word_idx * FD_CHUNK_SIZE + bit_idx;
                    if fd < FD_LIMIT {
                        found_fd = Some(fd);
                    }
                    break;
                }
            }
        }

        let fd = match found_fd {
            Some(fd) => fd,
            None => {
                let current_cap = self.storage.chunks.len() * FD_CHUNK_SIZE;
                let next_fd = core::cmp::max(min_fd, current_cap);
                if next_fd >= FD_LIMIT {
                    return Err(LinuxError::EMFILE);
                }
                next_fd
            }
        };

        self.insert_at(fd, entry)?;
        Ok(fd)
    }

    pub fn insert_next(&mut self, entry: FdEntry) -> LinuxResult<usize> {
        self.insert_from(0, entry)
    }

    pub fn remove(&mut self, fd: usize) -> Option<FdEntry> {
        let chunk_idx = fd / FD_CHUNK_SIZE;
        let bit_idx = fd % FD_CHUNK_SIZE;

        if chunk_idx >= self.storage.chunks.len() {
            return None;
        }

        let is_present = self.storage.chunks[chunk_idx]
            .as_ref()
            .and_then(|c| c.entries[bit_idx].as_ref())
            .is_some();
        if !is_present {
            return None;
        }

        let storage = Arc::make_mut(&mut self.storage);
        let chunk_slot = &mut storage.chunks[chunk_idx];
        let chunk = Arc::make_mut(chunk_slot.as_mut()?);
        let res = chunk.entries[bit_idx].take();
        if res.is_some() {
            storage.count = storage.count.saturating_sub(1);
            if chunk_idx < storage.open_fds.len() {
                storage.open_fds[chunk_idx] &= !(1 << bit_idx);
            }
        }
        res
    }

    pub fn remove_or_err(&mut self, fd: usize) -> LinuxResult<FdEntry> {
        self.remove(fd).ok_or(LinuxError::EBADF)
    }

    /// Removes all descriptors in the inclusive range and returns their entries.
    ///
    /// The storage and only the affected chunks are copied if this table is
    /// shared with a forked process. Returned entries must be dropped after
    /// releasing the table lock so closing an object cannot recurse into it.
    pub fn remove_range(&mut self, first: usize, last: usize) -> Vec<FdEntry> {
        if first > last || first >= FD_LIMIT || self.storage.chunks.is_empty() {
            return Vec::new();
        }

        let last = last.min(FD_LIMIT - 1);
        let first_chunk = first / FD_CHUNK_SIZE;
        if first_chunk >= self.storage.chunks.len() {
            return Vec::new();
        }
        let last_chunk = (last / FD_CHUNK_SIZE).min(self.storage.chunks.len() - 1);

        let has_open_fd = (first_chunk..=last_chunk).any(|chunk_idx| {
            let first_bit = if chunk_idx == first_chunk {
                first % FD_CHUNK_SIZE
            } else {
                0
            };
            let last_bit = if chunk_idx == last_chunk {
                last % FD_CHUNK_SIZE
            } else {
                FD_CHUNK_SIZE - 1
            };
            self.storage.open_fds[chunk_idx] & fd_range_mask(first_bit, last_bit) != 0
        });
        if !has_open_fd {
            return Vec::new();
        }

        let mut removed = Vec::new();
        let storage = Arc::make_mut(&mut self.storage);
        for chunk_idx in first_chunk..=last_chunk {
            let first_bit = if chunk_idx == first_chunk {
                first % FD_CHUNK_SIZE
            } else {
                0
            };
            let last_bit = if chunk_idx == last_chunk {
                last % FD_CHUNK_SIZE
            } else {
                FD_CHUNK_SIZE - 1
            };
            let mut pending = storage.open_fds[chunk_idx] & fd_range_mask(first_bit, last_bit);
            if pending == 0 {
                continue;
            }

            let mut removed_mask = 0u64;
            {
                let Some(chunk_arc) = storage.chunks[chunk_idx].as_mut() else {
                    continue;
                };
                let chunk = Arc::make_mut(chunk_arc);
                while pending != 0 {
                    let bit_idx = pending.trailing_zeros() as usize;
                    let bit = 1u64 << bit_idx;
                    pending &= !bit;
                    if let Some(entry) = chunk.entries[bit_idx].take() {
                        removed.push(entry);
                        removed_mask |= bit;
                    }
                }
            }

            if removed_mask != 0 {
                storage.open_fds[chunk_idx] &= !removed_mask;
                storage.count = storage
                    .count
                    .saturating_sub(removed_mask.count_ones() as usize);
            }
        }
        removed
    }

    /// Sets FD_CLOEXEC on every open descriptor in the inclusive range.
    pub fn set_cloexec_range(&mut self, first: usize, last: usize) {
        if first > last || first >= FD_LIMIT || self.storage.chunks.is_empty() {
            return;
        }

        let last = last.min(FD_LIMIT - 1);
        let first_chunk = first / FD_CHUNK_SIZE;
        if first_chunk >= self.storage.chunks.len() {
            return;
        }
        let last_chunk = (last / FD_CHUNK_SIZE).min(self.storage.chunks.len() - 1);

        let has_change = (first_chunk..=last_chunk).any(|chunk_idx| {
            let first_bit = if chunk_idx == first_chunk {
                first % FD_CHUNK_SIZE
            } else {
                0
            };
            let last_bit = if chunk_idx == last_chunk {
                last % FD_CHUNK_SIZE
            } else {
                FD_CHUNK_SIZE - 1
            };
            let mut pending = self.storage.open_fds[chunk_idx] & fd_range_mask(first_bit, last_bit);
            let Some(chunk) = self.storage.chunks[chunk_idx].as_ref() else {
                return false;
            };
            while pending != 0 {
                let bit_idx = pending.trailing_zeros() as usize;
                pending &= !(1u64 << bit_idx);
                if chunk.entries[bit_idx]
                    .as_ref()
                    .is_some_and(|entry| !entry.flags.contains(FdFlags::CLOEXEC))
                {
                    return true;
                }
            }
            false
        });
        if !has_change {
            return;
        }

        let storage = Arc::make_mut(&mut self.storage);
        for chunk_idx in first_chunk..=last_chunk {
            let first_bit = if chunk_idx == first_chunk {
                first % FD_CHUNK_SIZE
            } else {
                0
            };
            let last_bit = if chunk_idx == last_chunk {
                last % FD_CHUNK_SIZE
            } else {
                FD_CHUNK_SIZE - 1
            };
            let mut pending = storage.open_fds[chunk_idx] & fd_range_mask(first_bit, last_bit);
            if pending == 0 {
                continue;
            }
            let Some(chunk_arc) = storage.chunks[chunk_idx].as_mut() else {
                continue;
            };
            let chunk = Arc::make_mut(chunk_arc);
            while pending != 0 {
                let bit_idx = pending.trailing_zeros() as usize;
                pending &= !(1u64 << bit_idx);
                if let Some(entry) = chunk.entries[bit_idx].as_mut() {
                    entry.flags.insert(FdFlags::CLOEXEC);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.storage.count
    }

    pub fn is_empty(&self) -> bool {
        self.storage.count == 0
    }
}

pub type SharedFdTable = Arc<RwLock<FdTable>>;
