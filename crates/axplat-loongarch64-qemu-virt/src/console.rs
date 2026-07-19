use axplat::mem::{PhysAddr, pa};
use kspin::SpinNoIrq;
use ns16550a::{
    Break, DMAMode, Divisor, ParityBit, ParitySelect, StickParity, StopBits, Uart, WordLength,
};

use crate::mem::phys_to_virt;

const UART_BASE: PhysAddr = pa!(crate::config::devices::UART_PADDR);

static UART: SpinNoIrq<Uart> = SpinNoIrq::new(Uart::new(phys_to_virt(UART_BASE).as_usize()));

use axplat::console::ConsoleIf;

struct ConsoleIfImpl;

#[inline]
fn write_byte(uart: &Uart, c: u8) {
    while uart.put(c).is_none() {
        core::hint::spin_loop();
    }
}

pub(crate) fn init() {
    let uart = UART.lock();
    uart.init(
        WordLength::EIGHT,
        StopBits::ONE,
        ParityBit::DISABLE,
        ParitySelect::EVEN,
        StickParity::DISABLE,
        Break::DISABLE,
        DMAMode::MODE0,
        Divisor::BAUD115200,
    );
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
