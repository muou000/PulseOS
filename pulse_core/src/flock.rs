use alloc::{collections::BTreeMap, sync::Arc};

use axerrno::{LinuxError, LinuxResult};
use linux_raw_sys::general::{LOCK_EX, LOCK_NB, LOCK_SH, LOCK_UN};
use spin::{Lazy, Mutex};

use crate::fd_table::FdObject;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum LockTarget {
    Location { fs_id: usize, inode: u64 },
    FdObject(usize),
}

pub fn get_lock_target(obj: &Arc<dyn FdObject>) -> LockTarget {
    if let Some(loc) = obj.location() {
        let fs_id = loc.filesystem() as *const dyn axfs_ng_vfs::FilesystemOps as *const () as usize;
        LockTarget::Location {
            fs_id,
            inode: loc.inode(),
        }
    } else {
        LockTarget::FdObject(Arc::as_ptr(obj) as *const () as usize)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FlockType {
    Shared,
    Exclusive,
}

struct LockState {
    lock_type: FlockType,
    owners: alloc::vec::Vec<usize>,
    wait_queue: Arc<axtask::WaitQueue>,
}

pub(crate) const LOCK_TABLE_SHARDS: usize = 32;

pub(crate) fn lock_target_shard(target: LockTarget) -> usize {
    let hash = match target {
        LockTarget::Location { fs_id, inode } => {
            fs_id.rotate_left(13) ^ (inode as usize).rotate_right(7)
        }
        LockTarget::FdObject(address) => address.rotate_right(4),
    };
    hash % LOCK_TABLE_SHARDS
}

static FLOCK_MAPS: Lazy<[Mutex<BTreeMap<LockTarget, LockState>>; LOCK_TABLE_SHARDS]> =
    Lazy::new(|| core::array::from_fn(|_| Mutex::new(BTreeMap::new())));

fn current_has_pending_signal() -> bool {
    crate::task::current_thread()
        .map(|thread| thread.has_pending_signal())
        .unwrap_or(false)
}

pub fn do_flock(owner: usize, target: LockTarget, operation: i32) -> LinuxResult<isize> {
    let is_sh = (operation & (LOCK_SH as i32)) != 0;
    let is_ex = (operation & (LOCK_EX as i32)) != 0;
    let is_un = (operation & (LOCK_UN as i32)) != 0;
    let is_nb = (operation & (LOCK_NB as i32)) != 0;

    let mode_count = (is_sh as i32) + (is_ex as i32) + (is_un as i32);
    if mode_count != 1 {
        return Err(LinuxError::EINVAL);
    }

    let allowed_flags = (LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN) as i32;
    if (operation & !allowed_flags) != 0 {
        return Err(LinuxError::EINVAL);
    }

    if is_un {
        flock_release_target_owner(owner, target);
        return Ok(0);
    }

    let lock_type = if is_sh {
        FlockType::Shared
    } else {
        FlockType::Exclusive
    };

    // First check if we need to convert/release an existing lock of a different type
    {
        let mut map = FLOCK_MAPS[lock_target_shard(target)].lock();
        if let Some(state) = map.get_mut(&target) {
            if state.owners.contains(&owner) {
                if state.lock_type == lock_type {
                    // Already have the same lock type, nothing to do
                    return Ok(0);
                }
                // Different lock type: release old lock first to prevent deadlocks during conversion
                let pos = state.owners.iter().position(|&x| x == owner).unwrap();
                state.owners.remove(pos);
                if state.owners.is_empty() {
                    let wq = state.wait_queue.clone();
                    map.remove(&target);
                    wq.notify_all(true);
                } else {
                    state.wait_queue.notify_all(true);
                }
            }
        }
    }

    loop {
        let mut map = FLOCK_MAPS[lock_target_shard(target)].lock();
        if let Some(state) = map.get_mut(&target) {
            let holds_already = state.owners.contains(&owner);
            let can_acquire = match lock_type {
                FlockType::Shared => match state.lock_type {
                    FlockType::Shared => true,
                    FlockType::Exclusive => state.owners.len() == 1 && holds_already,
                },
                FlockType::Exclusive => {
                    if holds_already {
                        state.owners.len() == 1
                    } else {
                        state.owners.is_empty()
                    }
                }
            };

            if can_acquire {
                state.lock_type = lock_type;
                if !holds_already {
                    state.owners.push(owner);
                }
                return Ok(0);
            }

            if is_nb {
                return Err(LinuxError::EAGAIN);
            }

            let wq = state.wait_queue.clone();
            drop(map);

            if current_has_pending_signal() {
                return Err(LinuxError::EINTR);
            }

            wq.wait_until(|| {
                let map = FLOCK_MAPS[lock_target_shard(target)].lock();
                if let Some(state) = map.get(&target) {
                    let holds_already = state.owners.contains(&owner);
                    let can_acquire = match lock_type {
                        FlockType::Shared => match state.lock_type {
                            FlockType::Shared => true,
                            FlockType::Exclusive => state.owners.len() == 1 && holds_already,
                        },
                        FlockType::Exclusive => {
                            if holds_already {
                                state.owners.len() == 1
                            } else {
                                state.owners.is_empty()
                            }
                        }
                    };
                    can_acquire || current_has_pending_signal()
                } else {
                    true
                }
            });

            if current_has_pending_signal() {
                return Err(LinuxError::EINTR);
            }
        } else {
            let state = LockState {
                lock_type,
                owners: alloc::vec![owner],
                wait_queue: Arc::new(axtask::WaitQueue::new()),
            };
            map.insert(target, state);
            return Ok(0);
        }
    }
}

pub fn flock_release_target_owner(owner: usize, target: LockTarget) {
    let mut map = FLOCK_MAPS[lock_target_shard(target)].lock();
    if let Some(state) = map.get_mut(&target) {
        if let Some(pos) = state.owners.iter().position(|&x| x == owner) {
            state.owners.remove(pos);
            if state.owners.is_empty() {
                let wq = state.wait_queue.clone();
                map.remove(&target);
                wq.notify_all(true);
            } else {
                state.wait_queue.notify_all(true);
            }
        }
    }
}

pub fn flock_release_owner(owner: usize) {
    for shard in FLOCK_MAPS.iter() {
        let mut map = shard.lock();
        let mut to_remove = alloc::vec::Vec::new();
        for (target, state) in map.iter_mut() {
            if let Some(pos) = state.owners.iter().position(|&x| x == owner) {
                state.owners.remove(pos);
                if state.owners.is_empty() {
                    to_remove.push(*target);
                } else {
                    state.wait_queue.notify_all(true);
                }
            }
        }
        for target in to_remove {
            if let Some(state) = map.remove(&target) {
                state.wait_queue.notify_all(true);
            }
        }
    }
}
