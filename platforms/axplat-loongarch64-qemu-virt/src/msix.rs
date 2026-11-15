//! PCI MSI-X interrupt adapter for the QEMU LoongArch platform.

use core::sync::atomic::{AtomicUsize, Ordering};

use axplat::msix::{MsixMessage, MsixVectorAllocation, PciMsixError, PciMsixIf};

// QEMU's PCH-MSI inputs occupy EIOINTC pins 64..256; pins 0..64 belong to PCH-PIC.
const MSI_VECTOR_START: usize = 64;
const MSI_VECTOR_END: usize = 256;

// Vectors live for the lifetime of the boot-time PCI devices; there is no hot unplug.
static NEXT_MSI_VECTOR: AtomicUsize = AtomicUsize::new(MSI_VECTOR_START);

struct MsixImpl;

#[axplat::impl_plat_interface]
impl PciMsixIf for MsixImpl {
    fn allocate_vector() -> Result<MsixVectorAllocation, PciMsixError> {
        let irq = NEXT_MSI_VECTOR
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |next| {
                (next < MSI_VECTOR_END).then_some(next + 1)
            })
            .map_err(|_| PciMsixError::NoVectorAvailable)?;
        Ok(MsixVectorAllocation {
            irq,
            message: MsixMessage {
                address: crate::config::devices::PCH_MSI_PADDR as u64,
                data: irq as u32,
            },
        })
    }

    fn enable_irq(irq: usize) -> Result<(), PciMsixError> {
        if !(MSI_VECTOR_START..NEXT_MSI_VECTOR.load(Ordering::SeqCst)).contains(&irq) {
            return Err(PciMsixError::Unsupported);
        }
        // IrqIf routes these pins directly through EIOINTC, bypassing PCH-PIC.
        axplat::irq::set_enable(irq, true);
        Ok(())
    }
}
