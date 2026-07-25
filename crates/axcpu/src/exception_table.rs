use crate::TrapFrame;

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
struct ExceptionTableEntry {
    from: i32,
    to: i32,
}

impl ExceptionTableEntry {
    #[inline]
    fn source_addr(&self) -> usize {
        exception_addr(&self.from)
    }

    #[inline]
    fn to_addr(&self) -> usize {
        exception_addr(&self.to)
    }
}

#[inline]
fn exception_addr(offset: &i32) -> usize {
    #[cfg(any(
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    ))]
    {
        exception_table_start().wrapping_add_signed(*offset as isize)
    }

    #[cfg(not(any(
        target_arch = "riscv32",
        target_arch = "riscv64",
        target_arch = "loongarch64"
    )))]
    {
        (offset as *const i32 as usize).wrapping_add_signed(*offset as isize)
    }
}

unsafe extern "C" {
    static _ex_table_start: u8;
    static _ex_table_end: u8;
}

#[inline]
fn exception_table_start() -> usize {
    core::ptr::addr_of!(_ex_table_start) as usize
}

#[inline]
fn exception_table() -> &'static [ExceptionTableEntry] {
    let start = exception_table_start();
    let end = core::ptr::addr_of!(_ex_table_end) as usize;
    let byte_len = end.saturating_sub(start);
    debug_assert_eq!(byte_len % core::mem::size_of::<ExceptionTableEntry>(), 0);
    unsafe {
        core::slice::from_raw_parts(
            start as *const ExceptionTableEntry,
            byte_len / core::mem::size_of::<ExceptionTableEntry>(),
        )
    }
}

impl TrapFrame {
    pub fn fixup_exception(&mut self) -> bool {
        if let Some(entry) = exception_table()
            .iter()
            .find(|entry| entry.source_addr() == self.ip())
        {
            self.set_ip(entry.to_addr());
            true
        } else {
            false
        }
    }
}
