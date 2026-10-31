//! User-space ELF reading AT_HWCAP directly from initial stack auxv on LoongArch without libc.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::panic::PanicInfo;

global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "move $r4, $sp",
    "bl guest_main",
    "break 0",
);

#[inline(always)]
fn syscall(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let result: isize;
    unsafe {
        asm!("syscall 0", inlateout("$r4") a => result, in("$r5") b, in("$r6") c,
             in("$r7") d, in("$r8") e, in("$r9") f, in("$r11") n, options(nostack));
    }
    result
}

fn exit(code: usize) -> ! {
    syscall(93, code, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut bytes = text.as_bytes();
        while !bytes.is_empty() {
            let n = syscall(64, 1, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0);
            if n == -4 {
                continue;
            }
            if n <= 0 {
                return Err(fmt::Error);
            }
            bytes = &bytes[n as usize..];
        }
        Ok(())
    }
}

macro_rules! say {
    ($($arg:tt)*) => {{ let _ = writeln!(Console, $($arg)*); }};
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    say!("HWCAP FAIL guest_panic {}", info);
    exit(1)
}

const AT_NULL: usize = 0;
const AT_HWCAP: usize = 16;

#[unsafe(no_mangle)]
extern "C" fn guest_main(sp: *const usize) -> ! {
    say!("HWCAP START version=1");
    say!("HWCAP BEGIN check_auxv_hwcap");

    unsafe {
        let argc = *sp;
        let mut ptr = sp.add(1);
        ptr = ptr.add(argc);
        if *ptr != 0 {
            say!("HWCAP FAIL expected null after argv, got 0x{:x}", *ptr);
            exit(1);
        }
        ptr = ptr.add(1);

        while *ptr != 0 {
            ptr = ptr.add(1);
        }
        ptr = ptr.add(1);

        let mut hwcap_val: Option<usize> = None;
        loop {
            let a_type = *ptr;
            let a_val = *ptr.add(1);
            if a_type == AT_NULL {
                break;
            }
            if a_type == AT_HWCAP {
                hwcap_val = Some(a_val);
            }
            ptr = ptr.add(2);
        }

        let Some(hwcap) = hwcap_val else {
            say!("HWCAP FAIL AT_HWCAP not found in auxv");
            exit(1);
        };

        let cpucfg1: usize;
        asm!("cpucfg {}, {}", out(reg) cpucfg1, in(reg) 1);
        let ual_supported = (cpucfg1 & (1 << 20)) != 0;
        say!(
            "HWCAP NOTE cpucfg1=0x{:x} ual_supported={} hwcap=0x{:x}",
            cpucfg1,
            ual_supported,
            hwcap
        );

        let base_expected = (1 << 0) | (1 << 1) | (1 << 3);
        if (hwcap & base_expected) != base_expected {
            say!("HWCAP FAIL missing base capabilities in hwcap: 0x{:x}", hwcap);
            exit(1);
        }

        let hwcap_ual = (hwcap & (1 << 2)) != 0;
        if hwcap_ual != ual_supported {
            say!(
                "HWCAP FAIL hwcap UAL bit ({}) does not match CPUCFG1.UAL ({})",
                hwcap_ual,
                ual_supported
            );
            exit(1);
        }

        if (hwcap & !0xf) != 0 {
            say!("HWCAP FAIL unexpected bits in hwcap: 0x{:x}", hwcap);
            exit(1);
        }

        if ual_supported && hwcap != 0xf {
            say!("HWCAP FAIL expected hwcap 0xf with UAL, got 0x{:x}", hwcap);
            exit(1);
        } else if !ual_supported && hwcap != 0xb {
            say!("HWCAP FAIL expected hwcap 0xb without UAL, got 0x{:x}", hwcap);
            exit(1);
        }
    }

    say!("HWCAP PASS check_auxv_hwcap");
    say!("HWCAP SUMMARY pass=1 fail=0");
    say!("HWCAP RESULT PASS");
    exit(0);
}
