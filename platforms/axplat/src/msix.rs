//! PCI MSI-X configuration interface.

use memory_addr::PhysAddr;
use virtio_drivers::transport::pci::{
    PciTransport,
    bus::{BarInfo, DeviceFunction, PciRoot},
};

/// PCI capability ID for MSI-X.
pub const PCI_CAP_ID_MSIX: u8 = 0x11;

/// Error returned when configuring PCI MSI-X.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciMsixError {
    /// MSI-X is not supported on this platform or device.
    Unsupported,
    /// No MSI-X vector is available on the platform.
    NoVectorAvailable,
    /// Invalid BAR configuration, address, or table offset.
    InvalidBar,
    /// Invalid PCI MSI-X capability structure.
    InvalidCapability,
    /// Failed to map the MSI-X table.
    MappingFailed,
}

/// A PCI MSI/MSI-X message (target address and payload data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixMessage {
    /// 64-bit PCI message target address.
    pub address: u64,
    /// 32-bit PCI message data payload.
    pub data: u32,
}

/// An allocated MSI-X vector and its message target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixVectorAllocation {
    /// Interrupt identity (IRQ number recognized by the OS).
    pub irq: usize,
    /// PCI MSI-X message (target address and payload).
    pub message: MsixMessage,
}

/// Memory-mapped MSI-X table representation.
#[derive(Debug, PartialEq, Eq)]
pub struct MsixTableMapping {
    vaddr: usize,
    size: usize,
}

impl MsixTableMapping {
    /// Creates a mapping directly from a pre-mapped virtual address and size.
    ///
    /// # Safety
    ///
    /// `vaddr` must point to a valid, mapped, readable and writable memory region
    /// spanning at least `size` bytes. The memory must be aligned to at least 4 bytes.
    pub unsafe fn from_raw_parts(vaddr: usize, size: usize) -> Result<Self, PciMsixError> {
        if vaddr == 0 || size == 0 || vaddr % 4 != 0 {
            return Err(PciMsixError::InvalidBar);
        }
        Ok(Self { vaddr, size })
    }

    /// Maps an MSI-X table located in a memory BAR.
    ///
    /// Validates alignment and bounds:
    /// - `bar_base_paddr` must not be 0.
    /// - `table_offset` must be 8-byte aligned according to the PCI specification.
    /// - `table_offset + entry_count * 16 <= bar_size` without overflowing.
    /// - The table's physical end address must not overflow.
    pub fn from_bar_region(
        bar_base_paddr: usize,
        bar_size: usize,
        table_offset: usize,
        entry_count: usize,
    ) -> Result<Self, PciMsixError> {
        if bar_base_paddr == 0 {
            return Err(PciMsixError::InvalidBar);
        }
        if table_offset % 8 != 0 {
            return Err(PciMsixError::InvalidBar);
        }
        let table_bytes = entry_count
            .checked_mul(16)
            .ok_or(PciMsixError::InvalidBar)?;
        let end_offset = table_offset
            .checked_add(table_bytes)
            .ok_or(PciMsixError::InvalidBar)?;
        if end_offset > bar_size {
            return Err(PciMsixError::InvalidBar);
        }
        bar_base_paddr
            .checked_add(end_offset)
            .ok_or(PciMsixError::InvalidBar)?;
        let table_paddr = bar_base_paddr
            .checked_add(table_offset)
            .ok_or(PciMsixError::InvalidBar)?;
        let table_vaddr = crate::mem::phys_to_virt(PhysAddr::from(table_paddr)).as_usize();
        // SAFETY: `table_vaddr` is translated from a valid non-zero `bar_base_paddr`
        // and checked `table_offset` (which is 8-byte aligned, thus >= 4-byte aligned).
        // The region covers `table_bytes` which is guaranteed not to exceed `bar_size`.
        unsafe { Self::from_raw_parts(table_vaddr, table_bytes) }
    }

    fn entry_vaddr(&self, index: usize) -> Result<usize, PciMsixError> {
        let entry_offset = index
            .checked_mul(16)
            .ok_or(PciMsixError::InvalidBar)?;
        let end_offset = entry_offset
            .checked_add(16)
            .ok_or(PciMsixError::InvalidBar)?;
        if end_offset > self.size {
            return Err(PciMsixError::InvalidBar);
        }
        self.vaddr
            .checked_add(entry_offset)
            .ok_or(PciMsixError::InvalidBar)
    }

    /// Configures an MSI-X table entry with the given message and mask state.
    pub fn configure_entry(
        &self,
        index: usize,
        message: MsixMessage,
        masked: bool,
    ) -> Result<(), PciMsixError> {
        let entry_vaddr = self.entry_vaddr(index)?;
        // SAFETY: `entry_vaddr` is validated within `self.size` and checked for overflow.
        // The mapped memory corresponds to a valid memory-mapped BAR region, and all accesses
        // are aligned 32-bit volatile writes matching the PCI MSI-X specification.
        unsafe {
            core::ptr::write_volatile(
                (entry_vaddr + 0) as *mut u32,
                (message.address & 0xffff_ffff) as u32,
            );
            core::ptr::write_volatile(
                (entry_vaddr + 4) as *mut u32,
                (message.address >> 32) as u32,
            );
            core::ptr::write_volatile((entry_vaddr + 8) as *mut u32, message.data);
            core::ptr::write_volatile((entry_vaddr + 12) as *mut u32, if masked { 1 } else { 0 });
        }
        Ok(())
    }

    /// Reads an MSI-X table entry.
    pub fn read_entry(&self, index: usize) -> Result<(MsixMessage, bool), PciMsixError> {
        let entry_vaddr = self.entry_vaddr(index)?;
        // SAFETY: `entry_vaddr` is validated within `self.size` and checked for overflow.
        // Memory is an aligned 32-bit mapped BAR region.
        unsafe {
            let addr_lo = core::ptr::read_volatile((entry_vaddr + 0) as *const u32) as u64;
            let addr_hi = core::ptr::read_volatile((entry_vaddr + 4) as *const u32) as u64;
            let data = core::ptr::read_volatile((entry_vaddr + 8) as *const u32);
            let ctrl = core::ptr::read_volatile((entry_vaddr + 12) as *const u32);
            Ok((
                MsixMessage {
                    address: (addr_hi << 32) | addr_lo,
                    data,
                },
                (ctrl & 1) != 0,
            ))
        }
    }

    /// Returns the virtual base address of the mapped table.
    pub fn vaddr(&self) -> usize {
        self.vaddr
    }

    /// Returns the mapped size in bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

/// Platform interface for PCI MSI-X configuration and allocation.
#[def_plat_interface]
pub trait PciMsixIf {
    /// Allocates an MSI-X vector for a PCI device.
    /// Returns the allocated IRQ identity and MSI message address/data.
    fn allocate_vector() -> Result<MsixVectorAllocation, PciMsixError>;

    /// Enables the platform interrupt controller for the given allocated IRQ.
    fn enable_irq(irq: usize) -> Result<(), PciMsixError>;
}

/// Configures a VirtIO PCI device's MSI-X table and queue/config vectors.
///
/// The selected platform supplies the interrupt identity, message and routing
/// through [`PciMsixIf`]. Callers receive a usable IRQ or a controlled error and
/// need no knowledge of MSI-X table programming or platform interrupt hardware.
/// The device's BARs must already be assigned, and `transport` must belong to
/// `bdf` on `root`.
pub fn configure_virtio_pci_msix(
    root: &mut PciRoot,
    bdf: DeviceFunction,
    transport: &mut PciTransport,
) -> Result<usize, PciMsixError> {
    let offset = root
        .capabilities(bdf)
        .find(|cap| cap.id == PCI_CAP_ID_MSIX)
        .ok_or(PciMsixError::Unsupported)?
        .offset;
    // All three DWORDs must fit in conventional 256-byte configuration space.
    if offset > 244 {
        return Err(PciMsixError::InvalidCapability);
    }

    let cap_word0 = root.config_read_word(bdf, offset);
    let table_word = root.config_read_word(bdf, offset + 4);
    let table_bir = (table_word & 0x7) as u8;
    let table_offset = (table_word & !0x7) as usize;
    if table_bir >= 6 {
        return Err(PciMsixError::InvalidBar);
    }
    let bar_info = root
        .bar_info(bdf, table_bir)
        .map_err(|_| PciMsixError::InvalidBar)?;
    let (bar_address, bar_size) = match bar_info {
        BarInfo::Memory { address, size, .. } => (
            usize::try_from(address).map_err(|_| PciMsixError::InvalidBar)?,
            size as usize,
        ),
        _ => return Err(PciMsixError::InvalidBar),
    };
    let table = MsixTableMapping::from_bar_region(bar_address, bar_size, table_offset, 1)?;
    let allocation = allocate_vector()?;
    table.configure_entry(0, allocation.message, false)?;

    const MSIX_CONTROL_ENABLE: u32 = 1 << 31;
    root.config_write_word(bdf, offset, cap_word0 | MSIX_CONTROL_ENABLE);
    enable_irq(allocation.irq)?;

    transport.set_config_msix_vector(0);
    transport.set_default_queue_msix_vector(0);
    transport.set_msix_enabled(true);
    Ok(allocation.irq)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DummyMemIf;
    #[crate_interface::impl_interface]
    impl crate::mem::MemIf for DummyMemIf {
        fn phys_ram_ranges() -> &'static [crate::mem::RawRange] {
            &[]
        }
        fn reserved_phys_ram_ranges() -> &'static [crate::mem::RawRange] {
            &[]
        }
        fn mmio_ranges() -> &'static [crate::mem::RawRange] {
            &[]
        }
        fn flush_dcache_range(_paddr: PhysAddr, _size: usize) {}
        fn phys_to_virt(paddr: PhysAddr) -> memory_addr::VirtAddr {
            memory_addr::VirtAddr::from(paddr.as_usize())
        }
        fn virt_to_phys(vaddr: memory_addr::VirtAddr) -> PhysAddr {
            PhysAddr::from(vaddr.as_usize())
        }
    }

    #[test]
    fn test_msix_table_mapping_from_raw_parts() {
        let mut buffer = [0u32; 8]; // 32 bytes = 2 entries
        let vaddr = buffer.as_mut_ptr() as usize;
        let mapping = unsafe { MsixTableMapping::from_raw_parts(vaddr, 32) }.expect("valid mapping");
        assert_eq!(mapping.vaddr(), vaddr);
        assert_eq!(mapping.size(), 32);

        // Zero address should fail
        assert_eq!(
            unsafe { MsixTableMapping::from_raw_parts(0, 32) },
            Err(PciMsixError::InvalidBar)
        );
        // Zero size should fail
        assert_eq!(
            unsafe { MsixTableMapping::from_raw_parts(vaddr, 0) },
            Err(PciMsixError::InvalidBar)
        );
        // Unaligned virtual address (not 4-byte aligned) should fail
        assert_eq!(
            unsafe { MsixTableMapping::from_raw_parts(vaddr + 1, 32) },
            Err(PciMsixError::InvalidBar)
        );
    }

    #[test]
    fn test_msix_table_mapping_configure_and_read_entry() {
        let mut buffer = [0u32; 8];
        let vaddr = buffer.as_mut_ptr() as usize;
        let mapping = unsafe { MsixTableMapping::from_raw_parts(vaddr, 32) }.expect("valid mapping");

        let msg0 = MsixMessage {
            address: 0x1_2ff0_0000,
            data: 0x42,
        };
        mapping.configure_entry(0, msg0, false).expect("configure entry 0");

        let (read_msg0, masked0) = mapping.read_entry(0).expect("read entry 0");
        assert_eq!(read_msg0, msg0);
        assert!(!masked0);

        // Check raw volatile words in buffer
        assert_eq!(buffer[0], 0x2ff0_0000); // addr lo
        assert_eq!(buffer[1], 0x1);         // addr hi
        assert_eq!(buffer[2], 0x42);        // data
        assert_eq!(buffer[3], 0x0);         // unmasked

        // Test masked entry 1
        let msg1 = MsixMessage {
            address: 0x2ff0_0000,
            data: 0x65,
        };
        mapping.configure_entry(1, msg1, true).expect("configure entry 1");
        let (read_msg1, masked1) = mapping.read_entry(1).expect("read entry 1");
        assert_eq!(read_msg1, msg1);
        assert!(masked1);
        assert_eq!(buffer[7], 1); // masked

        // Out of bounds entry 2 (only 2 entries in 32 bytes)
        assert_eq!(
            mapping.configure_entry(2, msg0, false),
            Err(PciMsixError::InvalidBar)
        );
        assert_eq!(mapping.read_entry(2), Err(PciMsixError::InvalidBar));
    }

    #[test]
    fn test_msix_table_mapping_validation_logic() {
        // Unaligned table offset (must be 8-byte aligned)
        assert_eq!(
            MsixTableMapping::from_bar_region(0x1000, 0x1000, 4, 1),
            Err(PciMsixError::InvalidBar)
        );
        // Zero BAR address
        assert_eq!(
            MsixTableMapping::from_bar_region(0, 0x1000, 0, 1),
            Err(PciMsixError::InvalidBar)
        );
        // Table offset + entry bytes exceeds BAR size
        assert_eq!(
            MsixTableMapping::from_bar_region(0x1000, 32, 24, 1),
            Err(PciMsixError::InvalidBar)
        );
        // The table's entire physical extent must fit, not just its first byte.
        assert_eq!(
            MsixTableMapping::from_bar_region(usize::MAX - 7, 16, 0, 1),
            Err(PciMsixError::InvalidBar)
        );
    }
}
