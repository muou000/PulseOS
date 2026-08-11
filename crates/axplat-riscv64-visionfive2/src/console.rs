use core::{
    hint::spin_loop,
    ptr::{read_volatile, write_volatile},
};

use axplat::{
    console::ConsoleIf,
    mem::{pa, phys_to_virt},
};
use kspin::SpinNoIrq;

// The board DTB identifies UART0 as a DW APB UART at 0x1000_0000 with
// 32-bit registers spaced four bytes apart. U-Boot has configured it before
// entering the kernel, so early output must not reset its baud configuration.
const UART0_PADDR: usize = 0x1000_0000;
const UART_REG_STRIDE: usize = 4;
const UART_RBR_THR: usize = 0;
const UART_LSR: usize = 5;
const UART_LSR_DATA_READY: u32 = 1 << 0;
const UART_LSR_THR_EMPTY: u32 = 1 << 5;

static UART_LOCK: SpinNoIrq<()> = SpinNoIrq::new(());

pub(super) fn init_early() {}

/// Writes one byte before the temporary Sv39 page table is enabled.
///
/// This deliberately uses the physical UART address, which is valid while
/// U-Boot's identity mapping is still active and after PulseOS installs its
/// own identity mapping.
#[inline(never)]
pub(super) unsafe extern "C" fn early_putchar(byte: u8) {
    write_byte_at(UART0_PADDR, byte);
}

#[inline]
fn uart_vaddr() -> usize {
    phys_to_virt(pa!(UART0_PADDR)).as_usize()
}

fn write_byte_at(base: usize, byte: u8) {
    let lsr = (base + UART_LSR * UART_REG_STRIDE) as *const u32;
    while unsafe { read_volatile(lsr) } & UART_LSR_THR_EMPTY == 0 {
        spin_loop();
    }
    unsafe {
        write_volatile(
            (base + UART_RBR_THR * UART_REG_STRIDE) as *mut u32,
            byte.into(),
        )
    };
}

fn try_read_byte_at(base: usize) -> Option<u8> {
    let lsr = (base + UART_LSR * UART_REG_STRIDE) as *const u32;
    if unsafe { read_volatile(lsr) } & UART_LSR_DATA_READY == 0 {
        None
    } else {
        Some(unsafe { read_volatile((base + UART_RBR_THR * UART_REG_STRIDE) as *const u32) as u8 })
    }
}

struct ConsoleIfImpl;

#[impl_plat_interface]
impl ConsoleIf for ConsoleIfImpl {
    /// Writes bytes to the console from input u8 slice.
    fn write_bytes(bytes: &[u8]) {
        let _guard = UART_LOCK.lock();
        let base = uart_vaddr();
        for &byte in bytes {
            if byte == b'\n' {
                write_byte_at(base, b'\r');
            }
            write_byte_at(base, byte);
        }
    }

    /// Reads bytes from the console into the given mutable slice.
    /// Returns the number of bytes read.
    fn read_bytes(bytes: &mut [u8]) -> usize {
        let _guard = UART_LOCK.lock();
        let base = uart_vaddr();
        for (index, byte) in bytes.iter_mut().enumerate() {
            let Some(value) = try_read_byte_at(base) else {
                return index;
            };
            *byte = value;
        }
        bytes.len()
    }
}
