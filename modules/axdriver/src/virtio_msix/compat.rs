//! Compatibility adapter for LoongArch VirtIO MSI-X during migration (Issue #151).
//!
//! This adapter retains the existing LoongArch QEMU PCH-MSI / EIOINTC MSI-X behavior
//! until full migration to the platform crate (Issue #163) and subsequent removal (Issue #164).

use axhal::msix::{MsixMessage, MsixVectorAllocation, PciMsixError};

/// LoongArch VirtIO MSI-X compatibility adapter.
pub struct LoongArchMsixCompatAdapter;

#[cfg(target_arch = "loongarch64")]
mod loongarch {
    use super::*;
    use core::sync::atomic::{AtomicUsize, Ordering};

    /// Base address of PCH-MSI register in LoongArch QEMU virt machine.
    pub const LOONGARCH_PCH_MSI_BASE: u64 = 0x2ff0_0000;
    /// Start of EIOINTC pin range for MSI vectors.
    pub const LOONGARCH_MSI_MIN: usize = 64;
    /// End of EIOINTC pin range for MSI vectors (exclusive).
    pub const LOONGARCH_MSI_MAX: usize = 256;

    static NEXT_MSI_VECTOR: AtomicUsize = AtomicUsize::new(LOONGARCH_MSI_MIN);

    pub fn allocate() -> Result<MsixVectorAllocation, PciMsixError> {
        let msi_vector = NEXT_MSI_VECTOR.fetch_add(1, Ordering::SeqCst);
        if msi_vector >= LOONGARCH_MSI_MAX {
            return Err(PciMsixError::NoVectorAvailable);
        }
        Ok(MsixVectorAllocation {
            irq: msi_vector,
            message: MsixMessage {
                address: LOONGARCH_PCH_MSI_BASE,
                data: msi_vector as u32,
            },
        })
    }
}

impl super::VirtioPciMsixPlatform for LoongArchMsixCompatAdapter {
    fn allocate_vector(&mut self) -> Result<MsixVectorAllocation, PciMsixError> {
        #[cfg(target_arch = "loongarch64")]
        {
            loongarch::allocate()
        }
        #[cfg(not(target_arch = "loongarch64"))]
        {
            Err(PciMsixError::Unsupported)
        }
    }

    fn enable_irq(&self, _irq: usize) -> Result<(), PciMsixError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(target_arch = "loongarch64")]
    fn test_loongarch_compat_allocator() {
        let mut adapter = LoongArchMsixCompatAdapter;
        use super::super::VirtioPciMsixPlatform;
        let alloc = adapter.allocate_vector().expect("valid allocation");
        assert!(alloc.irq >= 64 && alloc.irq < 256);
        assert_eq!(alloc.message.address, 0x2ff0_0000);
        assert_eq!(alloc.message.data, alloc.irq as u32);
    }
}

