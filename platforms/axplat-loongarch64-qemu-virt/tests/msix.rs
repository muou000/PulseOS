//! Exercise the production MSI-X adapter on the host through its public HAL seams.

use core::sync::atomic::{AtomicUsize, Ordering};

use axplat::irq::{IpiError, IpiTarget, IrqHandler, IrqIf};

#[allow(dead_code)]
mod config {
    axconfig_macros::include_configs!("../axplat-loongarch64-qemu-virt/axconfig.toml");
}

#[path = "../src/msix.rs"]
mod platform_msix;

static ENABLED_IRQ: AtomicUsize = AtomicUsize::new(usize::MAX);

struct RecordingInterruptController;

#[axplat::impl_plat_interface]
impl IrqIf for RecordingInterruptController {
    fn set_enable(irq: usize, enabled: bool) {
        assert!(enabled);
        ENABLED_IRQ.store(irq, Ordering::SeqCst);
    }

    fn register(_irq: usize, _handler: IrqHandler) -> bool {
        unreachable!("MSI-X configuration does not register device handlers")
    }

    fn unregister(_irq: usize) -> Option<IrqHandler> {
        unreachable!("MSI-X configuration does not unregister device handlers")
    }

    fn handle(_irq: usize, _cpu_id: usize) {
        unreachable!("host test has no physical interrupts")
    }

    fn cpu_online(_cpu_id: usize) {
        unreachable!("MSI-X configuration does not change CPU topology")
    }

    fn send_ipi(_irq: usize, _target: IpiTarget) -> Result<(), IpiError> {
        unreachable!("MSI-X configuration does not send IPIs")
    }
}

#[test]
fn platform_allocates_and_routes_pch_msi_interrupts() {
    for irq in [0, 63, 64, 255, 256, usize::MAX] {
        assert_eq!(
            axplat::msix::enable_irq(irq),
            Err(axplat::msix::PciMsixError::Unsupported)
        );
    }
    assert_eq!(ENABLED_IRQ.load(Ordering::SeqCst), usize::MAX);

    let allocation = axplat::msix::allocate_vector().expect("QEMU supports PCI MSI-X");
    assert_eq!(allocation.irq, 64);
    assert_eq!(allocation.message.address, 0x2ff0_0000);
    assert_eq!(allocation.message.data, 64);

    axplat::msix::enable_irq(allocation.irq).expect("allocated MSI interrupt is routable");
    assert_eq!(ENABLED_IRQ.load(Ordering::SeqCst), 64);
    assert_eq!(
        axplat::msix::enable_irq(65),
        Err(axplat::msix::PciMsixError::Unsupported)
    );
    assert_eq!(ENABLED_IRQ.load(Ordering::SeqCst), 64);

    // Concurrent PCI probes must get distinct vectors from the same platform pool.
    let workers: Vec<_> = (0..191)
        .map(|_| std::thread::spawn(axplat::msix::allocate_vector))
        .collect();
    let mut allocations: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap().unwrap())
        .collect();
    allocations.sort_by_key(|allocation| allocation.irq);
    let irqs: Vec<_> = allocations
        .iter()
        .map(|allocation| allocation.irq)
        .collect();
    assert_eq!(irqs, (65..256).collect::<Vec<_>>());
    for allocation in allocations {
        assert_eq!(allocation.message.address, 0x2ff0_0000);
        assert_eq!(allocation.message.data as usize, allocation.irq);
    }
    for _ in 0..512 {
        assert_eq!(
            axplat::msix::allocate_vector(),
            Err(axplat::msix::PciMsixError::NoVectorAvailable)
        );
    }
    axplat::msix::enable_irq(255).expect("last allocated MSI interrupt is routable");
    assert_eq!(ENABLED_IRQ.load(Ordering::SeqCst), 255);
    for irq in [0, 63, 256, usize::MAX] {
        assert_eq!(
            axplat::msix::enable_irq(irq),
            Err(axplat::msix::PciMsixError::Unsupported)
        );
    }
    assert_eq!(ENABLED_IRQ.load(Ordering::SeqCst), 255);
}
