use core::ops::{Deref, DerefMut};

use axerrno::{AxError, AxResult};
use axhal::trap::PageFaultFlags;
use axmm::{AddrSpace, MappingPlacement, MappingWait, PreparedMapping};
use kernel_guard::NoPreempt;
use memory_addr::{PAGE_SIZE_4K, VirtAddr};
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

    pub fn resolve_page_fault(&self, address: VirtAddr, flags: PageFaultFlags) -> AxResult<bool> {
        let initial = self.read().handle_page_fault(address, flags);
        axmm::drive_page_fault(initial, |work| match work {
            axmm::PageFaultWork::Retry => self.write().handle_page_fault_write(address, flags),
            axmm::PageFaultWork::Completion(wait) => {
                Self::wait_for_mapping(wait.clone());
                if wait.result().is_err() {
                    return axmm::PageFaultResult::Handled(false);
                }
                self.read().handle_page_fault(address, flags)
            }
            axmm::PageFaultWork::File(prepared) => self
                .read()
                .handle_prepared_file_page(address, flags, prepared),
            axmm::PageFaultWork::Anon(prepared) => self
                .read()
                .handle_prepared_anon_page(address, flags, prepared),
            axmm::PageFaultWork::Cow(prepared) => self
                .read()
                .handle_prepared_cow_page(address, flags, prepared),
            axmm::PageFaultWork::WriteLock => self.write().handle_page_fault_write(address, flags),
        })
    }

    fn wait_for_mapping(wait: MappingWait) {
        while wait.is_pending() {
            axtask::yield_now();
        }
    }

    pub fn map(
        &self,
        mut prepared: PreparedMapping,
        placement: MappingPlacement,
    ) -> AxResult<VirtAddr> {
        let wait = axmm::MappingWait::new();
        let reservation = loop {
            let mut aspace = self.write();
            if let Some(pending) = aspace.any_pending_mapping() {
                drop(aspace);
                Self::wait_for_mapping(pending.clone());
                pending.result()?;
                continue;
            }
            break aspace.reserve_mapping(&mut prepared, placement, wait.clone())?;
        };
        let address = reservation.address();
        if matches!(placement, MappingPlacement::Fixed(_)) {
            let mutation = self.write().unmap_reserved(&reservation, &mut prepared);
            if let Err(error) = mutation.complete_after_unlock() {
                self.write()
                    .finish_mapping(reservation, error != AxError::BadState);
                return Err(error);
            }
        }
        let result = self.write().publish_reserved(&reservation, &prepared);
        self.write().finish_mapping(reservation, true);
        result.map(|()| address)
    }

    pub fn unmap(&self, start: VirtAddr, size: usize) -> AxResult<()> {
        let preparation = axmm::AddrSpaceUnmapPreparation::try_prepare(size)?;
        let wait = MappingWait::new();
        let reservation = loop {
            let mut aspace = self.write();
            if let Some(pending) = aspace.any_pending_mapping() {
                drop(aspace);
                Self::wait_for_mapping(pending.clone());
                pending.result()?;
                continue;
            }
            break aspace.reserve_unmap(start, size, wait.clone())?;
        };
        let mutation = self.write().unmap_reserved_range(&reservation, preparation);
        let result = mutation.complete_after_unlock();
        self.write().finish_mapping(reservation, result.is_ok());
        result
    }

    pub fn sync_mappings(&self, start: VirtAddr, size: usize, sync: bool) -> AxResult<()> {
        loop {
            let mut batch = axmm::FileWritebacks::try_prepare(size, sync)?;
            let aspace = self.read();
            if let Some(pending) = aspace.any_pending_mapping() {
                drop(aspace);
                Self::wait_for_mapping(pending.clone());
                pending.result()?;
                continue;
            }
            aspace.collect_file_writeback_range(start, size, sync, &mut batch)?;
            drop(aspace);
            return batch.complete();
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
