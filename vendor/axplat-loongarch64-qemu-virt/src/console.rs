use crate::mem::phys_to_virt;
use axplat::mem::{PhysAddr, pa};
use kspin::SpinNoIrq;
use ns16550a::{
    Break, Divisor, DMAMode, ParityBit, ParitySelect, StopBits, StickParity, Uart, WordLength,
};

const UART_BASE: PhysAddr = pa!(crate::config::devices::UART_PADDR);
const UART_COUNT: usize = 1;
const UART_BASES: [usize; UART_COUNT] = [crate::config::devices::UART_PADDR];

static UART: SpinNoIrq<Uart> = SpinNoIrq::new(Uart::new(phys_to_virt(UART_BASE).as_usize()));

use axplat::console::ConsoleIf;

struct ConsoleIfImpl;

#[inline]
fn write_raw_one(base: usize, c: u8) {
    unsafe {
        let ptr8 = phys_to_virt(PhysAddr::from(base)).as_usize() as *mut u8;
        ptr8.write_volatile(c);
    }
}

fn write_raw(c: u8) {
    for base in UART_BASES {
        write_raw_one(base, c);
    }
}

pub(crate) fn init() {
    let base = UART_BASES[0];
    let uart = Uart::new(phys_to_virt(PhysAddr::from(base)).as_usize());
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
        for &c in bytes {
            match c {
                b'\n' => {
                    write_raw(b'\r');
                    write_raw(b'\n');
                }
                c => {
                    write_raw(c);
                }
            }
        }
    }

    /// Reads bytes from the console into the given mutable slice.
    /// Returns the number of bytes read.
    fn read_bytes(bytes: &mut [u8]) -> usize {
        for (i, byte) in bytes.iter_mut().enumerate() {
            match UART.lock().get() {
                Some(c) => *byte = c,
                None => return i,
            }
        }
        bytes.len()
    }
}
