use axplat::mem::{VirtAddr, virt_to_phys};

/// The maximum number of bytes that can be read at once.
const MAX_RW_SIZE: usize = 256;

/// Tries to write bytes to the console from input u8 slice.
/// Returns the number of bytes written, or `None` if SBI rejected the call.
fn try_write_bytes(bytes: &[u8]) -> Option<usize> {
    let requested = bytes.len().min(MAX_RW_SIZE);
    let result = sbi_rt::console_write(sbi_rt::Physical::new(
        // A maximum of 256 bytes can be written at a time
        // to prevent SBI from disabling IRQs for too long.
        requested,
        virt_to_phys(VirtAddr::from_ptr_of(bytes.as_ptr())).as_usize(),
        0,
    ));
    completed_bytes(result.error, result.value, requested)
}

#[inline]
fn completed_bytes(error: usize, value: usize, requested: usize) -> Option<usize> {
    if error == 0 {
        Some(value.min(requested))
    } else {
        None
    }
}

fn write_byte(byte: u8) {
    if sbi_rt::console_write_byte(byte).is_err() {
        // Keep compatibility with firmware that predates the DBCN extension.
        #[allow(deprecated)]
        sbi_rt::legacy::console_putchar(byte as usize);
    }
}

use axplat::console::ConsoleIf;

struct ConsoleIfImpl;

#[impl_plat_interface]
impl ConsoleIf for ConsoleIfImpl {
    /// Writes bytes to the console from input u8 slice.
    fn write_bytes(bytes: &[u8]) {
        let mut write_len = 0;
        let mut buf = [0; MAX_RW_SIZE];
        while write_len < bytes.len() {
            let n = buf.len().min(bytes.len() - write_len);
            if n == 0 {
                break;
            }
            // `bytes` can be from user space, copy it into a kernel buffer
            // to correctly use `virt_to_phys`.
            buf[..n].copy_from_slice(&bytes[write_len..write_len + n]);
            match try_write_bytes(&buf[..n]) {
                Some(written) if written > 0 => write_len += written,
                // DBCN writes are non-blocking and may make no progress. Fall
                // back to its blocking byte operation (or legacy putchar) so
                // the loop cannot spin forever or silently lose the tail.
                _ => {
                    for &byte in &buf[..n] {
                        write_byte(byte);
                    }
                    write_len += n;
                }
            }
        }
    }

    /// Reads bytes from the console into the given mutable slice.
    /// Returns the number of bytes read.
    fn read_bytes(bytes: &mut [u8]) -> usize {
        let requested = bytes.len().min(MAX_RW_SIZE);
        if requested == 0 {
            return 0;
        }

        // Use a bounded kernel buffer: a caller slice may be user-backed or may
        // cross a physical page boundary even when its virtual range is contiguous.
        let mut buf = [0; MAX_RW_SIZE];
        let result = sbi_rt::console_read(sbi_rt::Physical::new(
            requested,
            virt_to_phys(VirtAddr::from_mut_ptr_of(buf.as_mut_ptr())).as_usize(),
            0,
        ));
        let Some(read) = completed_bytes(result.error, result.value, requested) else {
            return 0;
        };
        bytes[..read].copy_from_slice(&buf[..read]);
        read
    }
}
