//! Platform-owned seam and configuration helper for VirtIO PCI MSI-X.

pub mod compat;

use axdriver_pci::{BarInfo, DeviceFunction, PciRoot};
use axhal::msix::{
    MsixMessage, MsixTableMapping, MsixVectorAllocation, PCI_CAP_ID_MSIX, PciMsixError,
};
use virtio_drivers::transport::pci::PciTransport;

const MSIX_CONTROL_ENABLE: u16 = 1 << 15;

/// Platform-owned abstraction seam for PCI MSI-X configuration.
pub trait VirtioPciMsixPlatform {
    /// Allocates an MSI-X vector, returning its IRQ number and MSI message.
    fn allocate_vector(&mut self) -> Result<MsixVectorAllocation, PciMsixError>;

    /// Maps the MSI-X table for the device.
    fn map_table(
        &self,
        bar_base_paddr: usize,
        bar_size: usize,
        table_offset: usize,
        entry_count: usize,
    ) -> Result<MsixTableMapping, PciMsixError> {
        MsixTableMapping::from_bar_region(bar_base_paddr, bar_size, table_offset, entry_count)
    }

    /// Enables the platform interrupt routing for the given IRQ.
    fn enable_irq(&self, irq: usize) -> Result<(), PciMsixError>;
}

/// Standard platform seam delegating to `axhal::msix`.
pub struct PlatformMsixSeam;

impl VirtioPciMsixPlatform for PlatformMsixSeam {
    fn allocate_vector(&mut self) -> Result<MsixVectorAllocation, PciMsixError> {
        axhal::msix::allocate_vector()
    }

    fn enable_irq(&self, irq: usize) -> Result<(), PciMsixError> {
        axhal::msix::enable_irq(irq)
    }
}

/// Helper to configure MSI-X on a VirtIO PCI device using an explicit platform seam.
///
/// Ensures all BAR and capability reads are strictly validated, preventing unchecked panics.
pub fn configure_virtio_pci_msix_with<P: VirtioPciMsixPlatform>(
    root: &mut PciRoot,
    bdf: DeviceFunction,
    transport: &mut PciTransport,
    platform: &mut P,
) -> Result<usize, PciMsixError> {
    // 1. Find MSI-X capability
    let mut msix_cap_offset = None;
    for cap in root.capabilities(bdf) {
        if cap.id == PCI_CAP_ID_MSIX {
            msix_cap_offset = Some(cap.offset);
            break;
        }
    }
    let offset = msix_cap_offset.ok_or(PciMsixError::Unsupported)?;
    if offset > 248 {
        return Err(PciMsixError::InvalidCapability);
    }

    // 2. Read capability registers
    let cap_word0 = root.config_read_word(bdf, offset);
    let msg_ctrl = (cap_word0 >> 16) as u16;
    let table_word = root.config_read_word(bdf, offset + 4);
    let table_bir = (table_word & 0x7) as u8;
    let table_offset = (table_word & !0x7) as usize;

    if table_bir >= 6 {
        return Err(PciMsixError::InvalidBar);
    }

    // 3. Query and validate BAR info safely (never unwrap)
    let bar_info = root.bar_info(bdf, table_bir).map_err(|_| PciMsixError::InvalidBar)?;
    let (bar_address, bar_size) = match bar_info {
        BarInfo::Memory { address, size, .. } => {
            if address == 0 {
                return Err(PciMsixError::InvalidBar);
            }
            let addr = usize::try_from(address).map_err(|_| PciMsixError::InvalidBar)?;
            (addr, size as usize)
        }
        _ => return Err(PciMsixError::InvalidBar),
    };

    // 4. Map the MSI-X table memory
    let table_mapping = platform.map_table(bar_address, bar_size, table_offset, 1)?;

    // 5. Allocate an MSI-X vector and get message parameters
    let allocation = platform.allocate_vector()?;

    // 6. Program vector 0 into MSI-X table
    table_mapping.configure_entry(0, allocation.message, false)?;

    // 7. Enable MSI-X in device configuration space
    let new_msg_ctrl = msg_ctrl | MSIX_CONTROL_ENABLE;
    let new_cap_word0 = (cap_word0 & 0xffff) | ((new_msg_ctrl as u32) << 16);
    root.config_write_word(bdf, offset, new_cap_word0);

    // 8. Enable platform interrupt
    platform.enable_irq(allocation.irq)?;

    // 9. Bind VirtIO queue and config vectors
    transport.set_config_msix_vector(0);
    transport.set_default_queue_msix_vector(0);
    transport.set_msix_enabled(true);

    Ok(allocation.irq)
}

/// Primary entry point for configuring MSI-X on VirtIO PCI devices.
///
/// First tries the platform-owned seam; if unsupported, falls back to the
/// LoongArch compatibility adapter during the migration phase (Issue #151).
pub fn configure_virtio_pci_msix(
    root: &mut PciRoot,
    bdf: DeviceFunction,
    transport: &mut PciTransport,
) -> Result<usize, PciMsixError> {
    let mut platform = PlatformMsixSeam;
    match configure_virtio_pci_msix_with(root, bdf, transport, &mut platform) {
        Ok(irq) => Ok(irq),
        Err(PciMsixError::Unsupported) => {
            let mut compat = compat::LoongArchMsixCompatAdapter;
            configure_virtio_pci_msix_with(root, bdf, transport, &mut compat)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockUnsupportedPlatform;
    impl VirtioPciMsixPlatform for MockUnsupportedPlatform {
        fn allocate_vector(&mut self) -> Result<MsixVectorAllocation, PciMsixError> {
            Err(PciMsixError::Unsupported)
        }

        fn enable_irq(&self, _irq: usize) -> Result<(), PciMsixError> {
            Err(PciMsixError::Unsupported)
        }
    }

    #[test]
    fn test_mock_unsupported_platform() {
        let mut platform = MockUnsupportedPlatform;
        assert_eq!(platform.allocate_vector(), Err(PciMsixError::Unsupported));
        assert_eq!(platform.enable_irq(1), Err(PciMsixError::Unsupported));
    }
}
