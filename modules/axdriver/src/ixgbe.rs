use core::ptr::NonNull;

use axdriver_net::ixgbe::{IxgbeHal, PhysAddr as IxgbePhysAddr};
use axhal::dma::{alloc_coherent, dealloc_coherent};
use axhal::mem::{phys_to_virt, virt_to_phys};

pub struct IxgbeHalImpl;

unsafe impl IxgbeHal for IxgbeHalImpl {
    fn dma_alloc(size: usize) -> (IxgbePhysAddr, NonNull<u8>) {
        match alloc_coherent(size) {
            Ok((vaddr, _paddr, bus_addr)) => {
                let dev_addr = bus_addr.as_u64() as usize;
                (dev_addr, vaddr)
            }
            Err(_) => (0, NonNull::dangling()),
        }
    }

    unsafe fn dma_dealloc(_paddr: IxgbePhysAddr, vaddr: NonNull<u8>, size: usize) -> i32 {
        unsafe { dealloc_coherent(vaddr, size) };
        0
    }

    unsafe fn mmio_phys_to_virt(paddr: IxgbePhysAddr, _size: usize) -> NonNull<u8> {
        NonNull::new(phys_to_virt(paddr.into()).as_mut_ptr()).unwrap()
    }

    unsafe fn mmio_virt_to_phys(vaddr: NonNull<u8>, _size: usize) -> IxgbePhysAddr {
        virt_to_phys((vaddr.as_ptr() as usize).into()).into()
    }

    fn wait_until(duration: core::time::Duration) -> Result<(), &'static str> {
        axhal::time::busy_wait_until(duration);
        Ok(())
    }
}
