#![no_std]
#![no_main]
extern crate alloc;
mod runtime;
mod sys;
use core::arch::global_asm;
#[global_allocator]
static ALLOCATOR: sys::ProcessAllocator = sys::ProcessAllocator;

#[cfg(target_arch = "riscv64")]
global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    ".option push",
    ".option norelax",
    "la gp, __global_pointer$",
    ".option pop",
    "mv a0, sp",
    "call recorder_main",
    "unimp"
);
#[cfg(target_arch = "loongarch64")]
global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "move $a0, $sp",
    "bl recorder_main",
    "break 0"
);

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    use core::fmt::Write;
    struct Error;
    impl Write for Error {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            sys::print(s);
            Ok(())
        }
    }
    let _ = writeln!(Error, "RECORD PANIC {info}");
    sys::exit(1)
}

/// # Safety
/// Only `_start` calls this symbol, once, with the kernel-created ELF initial
/// stack: argc followed by argc readable NUL-terminated argument pointers.
// SAFETY: unique binary entry symbol; both assembly call sites use the C ABI.
#[unsafe(no_mangle)]
unsafe extern "C" fn recorder_main(stack: *const usize) -> ! {
    // SAFETY: the entry contract provides the readable aligned argc word.
    let argc = unsafe { stack.read() };
    if argc > 256 {
        sys::print("RECORD ERROR too many arguments\n");
        sys::exit(2);
    }
    let mut args = alloc::vec::Vec::new();
    for i in 1..argc {
        // SAFETY: initial stack supplies argc initialized argument pointers.
        let pointer = unsafe { stack.add(i + 1).read() } as *const u8;
        let mut length = 0;
        // SAFETY: each initial argument is a live NUL-terminated kernel string.
        while unsafe { pointer.add(length).read() } != 0 {
            length += 1;
            if length > 4096 {
                sys::print("RECORD ERROR argument too long\n");
                sys::exit(2);
            }
        }
        // SAFETY: bytes preceding discovered NUL are initialized in one live
        // initial-stack allocation; no code mutates argv until process exit.
        let bytes = unsafe { core::slice::from_raw_parts(pointer, length) };
        match core::str::from_utf8(bytes) {
            Ok(value) => args.push(value),
            Err(_) => {
                sys::print("RECORD ERROR argument encoding\n");
                sys::exit(2)
            }
        }
    }
    let code = match runtime::run(&args) {
        Ok(()) => 0,
        Err(error) => {
            sys::print(&alloc::format!("RECORD ERROR {error}\n"));
            1
        }
    };
    sys::exit(code)
}
