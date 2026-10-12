use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

use axerrno::{AxError, AxResult};
use axfs::{CachedFile, FileFlags, WriteAccessGuard};
use axhal::paging::{MappingFlags, PageSize};
use memory_addr::{MemoryAddr, VirtAddr, VirtAddrRange, PAGE_SIZE_4K};

use crate::{backend::DeferredReclaims, Backend};

static NEXT_ADDRESS_SPACE_ID: AtomicUsize = AtomicUsize::new(1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MappingGeneration {
    identity: usize,
    revision: usize,
}

impl MappingGeneration {
    pub(crate) fn new() -> Self {
        let identity = NEXT_ADDRESS_SPACE_ID.fetch_add(1, Ordering::Relaxed);
        assert_ne!(identity, 0, "address-space identity exhausted");
        Self { identity, revision: 0 }
    }

    pub(crate) fn advance(&mut self) {
        self.revision = self.revision.checked_add(1).expect("mapping generation exhausted");
    }
}

#[derive(Clone, Copy, Debug)]
pub enum MappingPlacement {
    Anywhere(VirtAddr),
    Fixed(VirtAddr),
    FixedNoReplace(VirtAddr),
}

pub struct PreparedMapping {
    pub(crate) size: usize,
    pub(crate) flags: MappingFlags,
    pub(crate) backend: Backend,
    pub(crate) reclaims: Option<DeferredReclaims>,
}

impl PreparedMapping {
    pub fn anonymous(size: usize, flags: MappingFlags, shared: bool, grows_down: bool) -> AxResult<Self> {
        Self::validate_size(size)?;
        let backend = if shared {
            Backend::new_shared(size, true, PageSize::Size4K).ok_or(AxError::NoMemory)?
        } else {
            Backend::new_alloc_grows_down(false, grows_down)
        };
        Self::with_backend(size, flags, backend)
    }

    pub fn file(
        size: usize,
        flags: MappingFlags,
        file: CachedFile,
        file_flags: FileFlags,
        offset: usize,
        file_bytes: usize,
        shared: bool,
        write_access: Option<WriteAccessGuard>,
    ) -> AxResult<Self> {
        Self::validate_size(size)?;
        if offset % PAGE_SIZE_4K != 0 || offset.checked_add(file_bytes).is_none() {
            return Err(AxError::InvalidInput);
        }
        let backend = Backend::new_file(VirtAddr::from(0), file, file_flags, offset, file_bytes, shared, write_access);
        Self::with_backend(size, flags, backend)
    }

    fn with_backend(size: usize, flags: MappingFlags, backend: Backend) -> AxResult<Self> {
        Ok(Self {
            size,
            flags,
            backend,
            reclaims: Some(DeferredReclaims::try_prepare(size)?),
        })
    }

    fn validate_size(size: usize) -> AxResult<()> {
        if size == 0 || size % PAGE_SIZE_4K != 0 {
            Err(AxError::InvalidInput)
        } else {
            Ok(())
        }
    }

    pub(crate) fn relocate(&mut self, address: VirtAddr) {
        self.backend.relocate_prepared(address);
    }
}

#[derive(Clone, Debug)]
pub struct MappingWait(Arc<AtomicU8>);

impl MappingWait {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(0)))
    }

    pub fn is_pending(&self) -> bool {
        self.0.load(Ordering::Acquire) == 0
    }

    pub fn result(&self) -> AxResult<()> {
        match self.0.load(Ordering::Acquire) {
            1 => Ok(()),
            2 => Err(AxError::BadState),
            _ => Err(AxError::WouldBlock),
        }
    }

    pub(crate) fn finish(&self, succeeded: bool) {
        self.0.store(if succeeded { 1 } else { 2 }, Ordering::Release);
    }

    pub(crate) fn same_operation(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

pub(crate) struct PendingMapping {
    pub(crate) range: VirtAddrRange,
    pub(crate) wait: MappingWait,
}

#[must_use = "a reserved mapping range must be completed or quarantined"]
pub struct MappingReservation {
    pub(crate) range: VirtAddrRange,
    pub(crate) wait: MappingWait,
}

impl MappingReservation {
    pub fn address(&self) -> VirtAddr {
        self.range.start
    }

    pub fn wait(&self) -> MappingWait {
        self.wait.clone()
    }
}

impl Drop for MappingReservation {
    fn drop(&mut self) {
        if self.wait.is_pending() {
            self.wait.finish(false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_distinguishes_replacement_and_address_spaces() {
        let mut original = MappingGeneration::new();
        let prepared = original;
        let other = MappingGeneration::new();
        assert_ne!(prepared, other);
        original.advance();
        assert_ne!(prepared, original);
    }

    #[test]
    fn abandoned_published_range_stays_quarantined() {
        let wait = MappingWait::new();
        let reservation = MappingReservation {
            range: VirtAddrRange::from_start_size(VirtAddr::from(0x1000), PAGE_SIZE_4K),
            wait: wait.clone(),
        };
        assert!(wait.is_pending());
        drop(reservation);
        assert_eq!(wait.result(), Err(AxError::BadState));
    }
}
