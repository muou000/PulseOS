use kspin::SpinNoIrq;
use ns16550a::Uart;

use crate::mp_common::DMW_UNCACHED_BASE;

const UART_VADDR: usize = DMW_UNCACHED_BASE | crate::config::devices::UART_PADDR;
const _: () = assert!(UART_VADDR == 0x8000_0000_1fe2_0000);

static UART: SpinNoIrq<Uart> = SpinNoIrq::new(Uart::new(UART_VADDR));

use axplat::console::ConsoleIf;

struct ConsoleIfImpl;

#[inline]
fn write_byte(uart: &Uart, c: u8) {
    while uart.put(c).is_none() {
        core::hint::spin_loop();
    }
}

pub(crate) fn init() {
    // U-Boot has already configured this UART and successfully used it for
    // the handoff console. The generic ns16550a crate's BAUD115200 divisor
    // assumes a 1.8432 MHz input clock, which is not the LS2K1000 UART clock.
    // Preserve the firmware divisor until the platform consumes a reliable
    // clock-frequency from the board DTB.
}

#[impl_plat_interface]
impl ConsoleIf for ConsoleIfImpl {
    /// Writes bytes to the console from input u8 slice.
    fn write_bytes(bytes: &[u8]) {
        let uart = UART.lock();
        for &c in bytes {
            match c {
                b'\n' => {
                    write_byte(&uart, b'\r');
                    write_byte(&uart, b'\n');
                }
                c => {
                    write_byte(&uart, c);
                }
            }
        }
    }

    /// Reads bytes from the console into the given mutable slice.
    /// Returns the number of bytes read.
    fn read_bytes(bytes: &mut [u8]) -> usize {
        let uart = UART.lock();
        for (i, byte) in bytes.iter_mut().enumerate() {
            match uart.get() {
                Some(c) => *byte = c,
                None => return i,
            }
        }
        bytes.len()
    }
}
