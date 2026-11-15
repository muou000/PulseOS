//! Compatibility entry point for VirtIO MSI-X during migration (Issue #151).
//!
//! Hardware configuration is now owned by the selected platform (Issue #163).
//! This forwarding adapter remains until the compatibility path is removed (Issue #164).

use axhal::msix::{MsixVectorAllocation, PciMsixError};

/// Legacy adapter forwarding to the selected platform.
pub struct LoongArchMsixCompatAdapter;

impl super::VirtioPciMsixPlatform for LoongArchMsixCompatAdapter {
    fn allocate_vector(&mut self) -> Result<MsixVectorAllocation, PciMsixError> {
        axhal::msix::allocate_vector()
    }

    fn enable_irq(&self, irq: usize) -> Result<(), PciMsixError> {
        axhal::msix::enable_irq(irq)
    }
}
