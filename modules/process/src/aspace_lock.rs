use core::ops::{Deref, DerefMut};

use axerrno::{AxError, AxResult};
use hal::trap::PageFaultFlags;
use axmm::{AddrSpace, MappingPlacement, MappingWait, PreparedMapping};
use kernel_guard::NoPreempt;
use memory_addr::{MemoryAddr, PAGE_SIZE_4K, VirtAddr};
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
        #[cfg(feature = "bpf-trace")]
        crate::bpf::mappings::register_space(&aspace);
        Self {
            inner: RwLock::new(aspace),
        }
    }

    pub fn resolve_page_fault(&self, address: VirtAddr, flags: PageFaultFlags) -> AxResult<bool> {
        self.resolve_page_fault_with_io(address, flags).map(|resolution| resolution.handled)
    }

    pub fn resolve_page_fault_with_io(&self, address: VirtAddr, flags: PageFaultFlags) -> AxResult<axmm::PageFaultResolution> {
        let initial = self.read().handle_page_fault(address, flags);
        axmm::drive_page_fault_with_io(initial, |work| match work {
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

    pub(crate) fn fault_in_user_range(
        &self,
        user_addr: usize,
        len: usize,
        access: PageFaultFlags,
    ) -> AxResult<()> {
        super::uaccess::validate_user_range(user_addr, len)?;
        if len == 0 {
            return Ok(());
        }
        let end = user_addr.checked_add(len).ok_or(AxError::BadAddress)?;
        let start_page = VirtAddr::from(user_addr).align_down_4k();
        let end_page = VirtAddr::from(end).align_up_4k();
        let access = access | PageFaultFlags::USER;

        let mut page = start_page;
        while page < end_page {
            {
                let aspace = self.read();
                while page < end_page {
                    let already_resident = aspace
                        .query_vaddr(page)
                        .is_ok_and(|(paddr, flags, _)| {
                            paddr.as_usize() != 0 && flags.contains(access)
                        });
                    if !already_resident {
                        break;
                    }
                    page += PAGE_SIZE_4K;
                }
            }

            if page >= end_page {
                break;
            }
            if !self.resolve_page_fault(page, access)? {
                return Err(AxError::BadAddress);
            }
            page += PAGE_SIZE_4K;
        }
        Ok(())
    }

    pub(crate) fn read_user_bytes_partial(&self, user_addr: usize, bytes: &mut [u8]) -> AxResult<usize> {
        super::uaccess::validate_user_range(user_addr, bytes.len())?;
        let start = VirtAddr::from(user_addr);
        if self.read().read(start, bytes).is_ok() {
            return Ok(bytes.len());
        }
        self.fault_in_user_range(user_addr, bytes.len(), PageFaultFlags::READ)?;
        self.read()
            .read(start, bytes)
            .map(|()| bytes.len())
            .map_err(AxError::from)
    }

    pub(crate) fn write_user_bytes_partial(&self, user_addr: usize, bytes: &[u8]) -> AxResult<usize> {
        super::uaccess::validate_user_range(user_addr, bytes.len())?;
        let start = VirtAddr::from(user_addr);
        if self.read().write(start, bytes).is_ok() {
            return Ok(bytes.len());
        }
        self.fault_in_user_range(user_addr, bytes.len(), PageFaultFlags::WRITE)?;
        self.read()
            .write(start, bytes)
            .map(|()| bytes.len())
            .map_err(AxError::from)
    }

    fn wait_for_mapping(wait: MappingWait) {
        while wait.is_pending() {
            task::yield_now();
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

    /// IRQ-only, nonblocking VMA read lease. No NoPreempt destructor may run
    /// before the timer is acknowledged. The sampling observer keeps IRQs
    /// disabled, never schedules, and drops this lease before returning.
    #[cfg(feature = "bpf-trace")]
    pub(crate) fn try_read_for_sampling(&self) -> Option<RwLockReadGuard<'_, AddrSpace>> {
        if hal::asm::irqs_enabled() {
            return None;
        }
        self.inner.try_read()
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
        #[cfg(feature = "bpf-trace")]
        let observation = (guard.observation_identity().1,
            crate::bpf::mappings::MutationGuard::space(guard.observation_identity().0));
        AddressSpaceWriteGuard {
            guard,
            _preempt: preempt,
            #[cfg(feature = "bpf-trace")]
            observation,
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
    #[cfg(feature = "bpf-trace")]
    observation: (usize, crate::bpf::mappings::MutationGuard),
}

#[cfg(feature = "bpf-trace")]
impl Drop for AddressSpaceWriteGuard<'_> {
    fn drop(&mut self) {
        if self.observation.0 != self.guard.observation_identity().1 {
            crate::bpf::mappings::space_snapshot(&self.guard, self.observation.1.begin_ns());
        }
        self.observation.1.finish();
    }
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
