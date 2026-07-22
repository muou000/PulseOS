use core::ops::{Deref, DerefMut};

use axmm::AddrSpace;
use kernel_guard::NoPreempt;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

/// A preemption-safe address-space lock.
///
/// Address-space access can be nested inside non-sleepable syscall guards, so
/// contention cannot use a task-aware lock. Disabling preemption for every
/// holder prevents a local waiter from starving a preempted holder indefinitely.
pub struct AddressSpaceLock {
    inner: RwLock<AddrSpace>,
}

impl AddressSpaceLock {
    pub fn new(aspace: AddrSpace) -> Self {
        Self {
            inner: RwLock::new(aspace),
        }
    }

    pub fn read(&self) -> AddressSpaceReadGuard<'_> {
        let preempt = NoPreempt::new();
        let guard = self.inner.read();
        AddressSpaceReadGuard {
            guard,
            _preempt: preempt,
        }
    }

    pub fn write(&self) -> AddressSpaceWriteGuard<'_> {
        let preempt = NoPreempt::new();
        let guard = self.inner.write();
        AddressSpaceWriteGuard {
            guard,
            _preempt: preempt,
        }
    }
}

pub struct AddressSpaceReadGuard<'a> {
    // Fields drop in declaration order, releasing the lock before preemption.
    guard: RwLockReadGuard<'a, AddrSpace>,
    _preempt: NoPreempt,
}

impl Deref for AddressSpaceReadGuard<'_> {
    type Target = AddrSpace;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

pub struct AddressSpaceWriteGuard<'a> {
    // Fields drop in declaration order, releasing the lock before preemption.
    guard: RwLockWriteGuard<'a, AddrSpace>,
    _preempt: NoPreempt,
}

impl Deref for AddressSpaceWriteGuard<'_> {
    type Target = AddrSpace;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl DerefMut for AddressSpaceWriteGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}
