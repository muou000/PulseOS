//! Hardware DMA abstractions, coherent allocations, and bus-address handling.
//!
//! This module provides hardware-facing DMA abstractions without depending on
//! higher-level virtual memory or filesystem modules.

use core::fmt;
use core::ptr::NonNull;
use core::slice;
use memory_addr::{PAGE_SIZE_4K, PhysAddr, VirtAddr};

/// A bus memory address.
///
/// Transparent wrapper around an [`u64`] representing device-visible addresses on
/// the system bus.
#[repr(transparent)]
#[derive(Copy, Clone, Default, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct BusAddr(u64);

impl BusAddr {
    /// Creates a new bus address from an `u64`.
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    /// Converts the address to an `u64`.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Converts the address to a `usize`. Returns `None` if the value exceeds
    /// `usize::MAX`.
    #[inline]
    pub const fn as_usize(self) -> Option<usize> {
        if self.0 <= usize::MAX as u64 {
            Some(self.0 as usize)
        } else {
            None
        }
    }
}

impl From<u64> for BusAddr {
    #[inline]
    fn from(value: u64) -> Self {
        Self::new(value)
    }
}

impl From<usize> for BusAddr {
    #[inline]
    fn from(value: usize) -> Self {
        Self::new(value as u64)
    }
}

impl From<BusAddr> for u64 {
    #[inline]
    fn from(addr: BusAddr) -> Self {
        addr.as_u64()
    }
}

impl fmt::Debug for BusAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BusAddr")
            .field(&format_args!("{:#X}", self.0))
            .finish()
    }
}

impl fmt::Display for BusAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#X}", self.0)
    }
}

impl fmt::LowerHex for BusAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for BusAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

/// Converts a physical address to a bus address with checked arithmetic.
///
/// Applies the platform-configured [`axconfig::plat::PHYS_BUS_OFFSET`].
/// Returns `None` if the addition overflows `u64`.
#[inline]
pub fn phys_to_bus(paddr: PhysAddr) -> Option<BusAddr> {
    let raw = paddr.as_usize() as u64;
    let offset = axconfig::plat::PHYS_BUS_OFFSET as u64;
    raw.checked_add(offset).map(BusAddr::new)
}

/// Converts a bus address to a physical address with checked arithmetic.
///
/// Subtracts the platform-configured [`axconfig::plat::PHYS_BUS_OFFSET`].
/// Returns `None` if the address underflows or cannot fit in a [`PhysAddr`].
#[inline]
pub fn bus_to_phys(baddr: BusAddr) -> Option<PhysAddr> {
    let offset = axconfig::plat::PHYS_BUS_OFFSET as u64;
    let raw_phys = baddr.as_u64().checked_sub(offset)?;
    if raw_phys <= usize::MAX as u64 {
        Some(PhysAddr::from(raw_phys as usize))
    } else {
        None
    }
}

/// Converts a virtual address to a bus address with checked arithmetic.
#[inline]
pub fn virt_to_bus(vaddr: VirtAddr) -> Option<BusAddr> {
    let paddr = crate::mem::virt_to_phys(vaddr);
    phys_to_bus(paddr)
}

/// Converts a bus address to a virtual address with checked arithmetic.
#[inline]
pub fn bus_to_virt(baddr: BusAddr) -> Option<VirtAddr> {
    let paddr = bus_to_phys(baddr)?;
    Some(crate::mem::phys_to_virt(paddr))
}

/// Direction of DMA transfer for explicit cache synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Data is transferred from CPU memory to the device.
    ToDevice,
    /// Data is transferred from the device into CPU memory.
    FromDevice,
    /// Data is transferred bidirectionally.
    Bidirectional,
}

/// Errors related to DMA allocation, mapping, or synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaError {
    /// The specified size, page count, or range is invalid.
    InvalidArgs,
    /// The allocator could not fulfill the allocation request.
    NoMemory,
    /// Physical or bus address conversion exceeded valid address range.
    AddressOverflow,
}

impl fmt::Display for DmaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgs => write!(f, "Invalid DMA arguments"),
            Self::NoMemory => write!(f, "Out of DMA memory"),
            Self::AddressOverflow => write!(f, "DMA address overflow"),
        }
    }
}

/// A contiguous, page-aligned coherent DMA memory region with RAII release ownership.
///
/// Memory allocated via this type is guaranteed to be zero-initialized upon creation,
/// accessible by the CPU via direct virtual address, visible to DMA controllers via
/// [`bus_addr`][Self::bus_addr], and automatically returned to the page allocator on drop.
pub struct DmaCoherentRegion {
    cpu_addr: NonNull<u8>,
    paddr: PhysAddr,
    bus_addr: BusAddr,
    size: usize,
    pages: usize,
}

unsafe impl Send for DmaCoherentRegion {}
unsafe impl Sync for DmaCoherentRegion {}

impl DmaCoherentRegion {
    /// Allocates `pages` contiguous 4KiB pages of coherent DMA memory.
    ///
    /// The allocated buffer is zero-initialized and cache-maintained.
    pub fn alloc(pages: usize) -> Result<Self, DmaError> {
        if pages == 0 {
            return Err(DmaError::InvalidArgs);
        }
        let size = pages.checked_mul(PAGE_SIZE_4K).ok_or(DmaError::InvalidArgs)?;

        #[cfg(any(feature = "dma", feature = "paging"))]
        let vaddr = axalloc::global_allocator()
            .alloc_pages(pages, PAGE_SIZE_4K)
            .map_err(|_| DmaError::NoMemory)?;

        #[cfg(not(any(feature = "dma", feature = "paging")))]
        return Err(DmaError::NoMemory);

        // Zero out freshly allocated DMA pages
        unsafe { core::ptr::write_bytes(vaddr as *mut u8, 0, size) };

        let paddr = crate::mem::virt_to_phys(VirtAddr::from(vaddr));
        let bus_addr = match phys_to_bus(paddr) {
            Some(b) => b,
            None => {
                #[cfg(any(feature = "dma", feature = "paging"))]
                axalloc::global_allocator().dealloc_pages(vaddr, pages);
                return Err(DmaError::AddressOverflow);
            }
        };

        crate::mem::flush_dcache_range(paddr, size);

        let cpu_addr = NonNull::new(vaddr as *mut u8).ok_or(DmaError::NoMemory)?;
        Ok(Self {
            cpu_addr,
            paddr,
            bus_addr,
            size,
            pages,
        })
    }

    /// Allocates coherent DMA memory of at least `size` bytes, rounded up to 4KiB pages.
    pub fn alloc_bytes(size: usize) -> Result<Self, DmaError> {
        if size == 0 {
            return Err(DmaError::InvalidArgs);
        }
        let pages = memory_addr::align_up_4k(size) / PAGE_SIZE_4K;
        let mut region = Self::alloc(pages)?;
        region.size = size;
        Ok(region)
    }

    /// CPU-accessible virtual pointer to the start of the DMA region.
    #[inline]
    pub fn cpu_addr(&self) -> NonNull<u8> {
        self.cpu_addr
    }

    /// Physical address corresponding to the start of the region.
    #[inline]
    pub fn paddr(&self) -> PhysAddr {
        self.paddr
    }

    /// Device-visible bus address for DMA controllers.
    #[inline]
    pub fn bus_addr(&self) -> BusAddr {
        self.bus_addr
    }

    /// Size of the region in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        self.size
    }

    /// Number of 4KiB pages backing this region.
    #[inline]
    pub fn pages(&self) -> usize {
        self.pages
    }

    /// Returns a slice view of the coherent region.
    #[inline]
    pub fn as_slice(&self) -> &[u8] {
        unsafe { slice::from_raw_parts(self.cpu_addr.as_ptr(), self.size) }
    }

    /// Returns a mutable slice view of the coherent region.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { slice::from_raw_parts_mut(self.cpu_addr.as_ptr(), self.size) }
    }

    /// Synchronizes the given sub-range with the device using platform cache primitives.
    ///
    /// - [`DmaDirection::ToDevice`]: Cleans/writes back CPU dirty cache lines to physical RAM
    ///   so DMA controllers observe the CPU's updates.
    /// - [`DmaDirection::FromDevice`]: Invalidates CPU cache lines so subsequent CPU reads
    ///   fetch the latest data written by the device.
    /// - [`DmaDirection::Bidirectional`]: Performs clean and invalidation for bidirectional transfers.
    pub fn sync(&self, direction: DmaDirection, offset: usize, len: usize) -> Result<(), DmaError> {
        if offset.checked_add(len).map_or(true, |end| end > self.size) {
            return Err(DmaError::InvalidArgs);
        }
        let target_paddr = self.paddr.as_usize().checked_add(offset).ok_or(DmaError::AddressOverflow)?;
        match direction {
            DmaDirection::ToDevice | DmaDirection::FromDevice | DmaDirection::Bidirectional => {
                crate::mem::flush_dcache_range(PhysAddr::from(target_paddr), len);
            }
        }
        Ok(())
    }

    /// Synchronizes CPU writes to device visibility.
    #[inline]
    pub fn sync_to_device(&self, offset: usize, len: usize) -> Result<(), DmaError> {
        self.sync(DmaDirection::ToDevice, offset, len)
    }

    /// Synchronizes device writes to CPU visibility.
    #[inline]
    pub fn sync_for_cpu(&self, offset: usize, len: usize) -> Result<(), DmaError> {
        self.sync(DmaDirection::FromDevice, offset, len)
    }

    /// Deconstructs the region into its components, relinquishing automatic RAII deallocation.
    pub fn into_raw(self) -> (NonNull<u8>, PhysAddr, BusAddr, usize) {
        let tuple = (self.cpu_addr, self.paddr, self.bus_addr, self.size);
        core::mem::forget(self);
        tuple
    }

    /// Reconstitutes a [`DmaCoherentRegion`] from raw components previously obtained from [`into_raw`][Self::into_raw].
    ///
    /// # Safety
    ///
    /// `cpu_addr`, `paddr`, and `size` must match a prior allocation made by this module
    /// that has not yet been deallocated.
    pub unsafe fn from_raw(
        cpu_addr: NonNull<u8>,
        paddr: PhysAddr,
        size: usize,
    ) -> Result<Self, DmaError> {
        if size == 0 {
            return Err(DmaError::InvalidArgs);
        }
        let pages = memory_addr::align_up_4k(size) / PAGE_SIZE_4K;
        let bus_addr = phys_to_bus(paddr).ok_or(DmaError::AddressOverflow)?;
        Ok(Self {
            cpu_addr,
            paddr,
            bus_addr,
            size,
            pages,
        })
    }
}

impl Drop for DmaCoherentRegion {
    fn drop(&mut self) {
        #[cfg(any(feature = "dma", feature = "paging"))]
        axalloc::global_allocator().dealloc_pages(self.cpu_addr.as_ptr() as usize, self.pages);
    }
}

/// Allocates coherent DMA memory of at least `size` bytes.
///
/// Returns the CPU virtual address, physical address, and device bus address.
pub fn alloc_coherent(size: usize) -> Result<(NonNull<u8>, PhysAddr, BusAddr), DmaError> {
    let region = DmaCoherentRegion::alloc_bytes(size)?;
    let (cpu, paddr, bus, _sz) = region.into_raw();
    Ok((cpu, paddr, bus))
}

/// Deallocates coherent DMA memory previously allocated via [`alloc_coherent`].
///
/// # Safety
///
/// `vaddr` and `size` must match an active allocation made by [`alloc_coherent`].
pub unsafe fn dealloc_coherent(vaddr: NonNull<u8>, size: usize) {
    if size == 0 {
        return;
    }
    let pages = memory_addr::align_up_4k(size) / PAGE_SIZE_4K;
    #[cfg(any(feature = "dma", feature = "paging"))]
    axalloc::global_allocator().dealloc_pages(vaddr.as_ptr() as usize, pages);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bus_addr_conversions() {
        let b = BusAddr::new(0x1234_5678);
        assert_eq!(b.as_u64(), 0x1234_5678);
        assert_eq!(b.as_usize(), Some(0x1234_5678));
        assert_eq!(u64::from(b), 0x1234_5678);
        assert_eq!(BusAddr::from(0x1234_5678u64), b);
        assert_eq!(BusAddr::from(0x1234_5678usize), b);
    }

    #[test]
    fn test_bus_phys_roundtrip() {
        let paddr = PhysAddr::from(0x8020_0000usize);
        let bus = phys_to_bus(paddr).expect("phys_to_bus failed");
        let expected = (0x8020_0000usize + axconfig::plat::PHYS_BUS_OFFSET) as u64;
        assert_eq!(bus.as_u64(), expected);

        let paddr_back = bus_to_phys(bus).expect("bus_to_phys failed");
        assert_eq!(paddr_back, paddr);
    }

    #[test]
    fn test_checked_underflow_overflow() {
        if axconfig::plat::PHYS_BUS_OFFSET > 0 {
            assert_eq!(bus_to_phys(BusAddr::new(0)), None);
        }
    }
}

