//! Independent external workload and byte-for-byte file transport for #195.
//! This executable has no BPF code and is never linked into bpf-record.
#![no_std]
#![no_main]

use core::{
    arch::{asm, global_asm},
    fmt::{self, Write},
    panic::PanicInfo,
};

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
    "call fixture_main",
    "unimp"
);
#[cfg(target_arch = "loongarch64")]
global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "move $a0, $sp",
    "bl fixture_main",
    "break 0"
);

fn call(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let result;
    // SAFETY: only the two configured guest architectures reach this code.
    // Register operands implement their Linux-shaped syscall ABI. Each caller
    // keeps its initialized input/output allocation live for the synchronous
    // syscall, and no nomem/pure option hides the kernel's buffer access.
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!("ecall", inlateout("a0") a => result, in("a1") b, in("a2") c,
             in("a3") d, in("a4") e, in("a5") f, in("a7") n, options(nostack));
        #[cfg(target_arch = "loongarch64")]
        asm!("syscall 0", inlateout("$r4") a => result, in("$r5") b, in("$r6") c,
             in("$r7") d, in("$r8") e, in("$r9") f, in("$r11") n, options(nostack));
    }
    result
}
fn exit(status: usize) -> ! {
    call(93, status, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}
struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut bytes = text.as_bytes();
        while !bytes.is_empty() {
            let n = call(64, 1, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0);
            if n == -4 {
                continue;
            }
            if n <= 0 || n as usize > bytes.len() {
                return Err(fmt::Error);
            }
            bytes = &bytes[n as usize..];
        }
        Ok(())
    }
}
macro_rules! say { ($($v:tt)*) => { output(format_args!($($v)*)) }; }
fn output(arguments: fmt::Arguments<'_>) {
    struct Line {
        data: [u8; 1024],
        length: usize,
    }
    impl Write for Line {
        fn write_str(&mut self, value: &str) -> fmt::Result {
            let end = self.length.checked_add(value.len()).ok_or(fmt::Error)?;
            if end > self.data.len() {
                return Err(fmt::Error);
            }
            self.data[self.length..end].copy_from_slice(value.as_bytes());
            self.length = end;
            Ok(())
        }
    }
    let mut line = Line {
        data: [0; 1024],
        length: 0,
    };
    line.write_fmt(arguments).unwrap();
    line.write_str("\n").unwrap();
    Console
        .write_str(core::str::from_utf8(&line.data[..line.length]).unwrap())
        .unwrap();
}
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    let _ = writeln!(Console, "FIXTURE FAIL {info}");
    exit(1)
}

fn checked(result: isize) -> usize {
    assert!(result >= 0, "syscall errno={result}");
    result as usize
}
fn now() -> u64 {
    let mut ts = [0i64; 2];
    assert_eq!(call(113, 1, ts.as_mut_ptr() as usize, 0, 0, 0, 0), 0);
    assert!(ts[0] >= 0 && (0..1_000_000_000).contains(&ts[1]));
    ts[0] as u64 * 1_000_000_000 + ts[1] as u64
}
fn sleep_ms(ms: u64) {
    let ts = [(ms / 1000) as i64, (ms % 1000 * 1_000_000) as i64];
    let rc = call(101, ts.as_ptr() as usize, 0, 0, 0, 0, 0);
    assert!(rc == 0 || rc == -4);
}

fn fault_iteration() {
    let address = checked(call(222, 0, 12288, 3, 0x22, usize::MAX, 0));
    assert!(address != 0 && address % 4096 == 0 && address.checked_add(12288).is_some());
    assert_eq!(call(226, address + 4096, 4096, 0, 0, 0, 0), 0);
    // SAFETY: successful mmap owns a zero-filled three-page allocation until
    // the munmap below. Only its middle page was protected. Both addresses are
    // inside its still-live readable/writable end pages; u8 has alignment one
    // and accepts every bit pattern. No references or aliases to these private
    // pages escape. Volatile accesses retain first-touch faults; no access
    // occurs after munmap and no concurrency synchronization is claimed.
    unsafe {
        assert_eq!(core::ptr::read_volatile(address as *const u8), 0);
        core::ptr::write_volatile((address + 8192) as *mut u8, 0x5a);
    }
    assert_eq!(call(215, address, 12288, 0, 0, 0, 0), 0);
    sleep_ms(1);
}

fn work(mode: &str, millis: u64, label: &str) {
    assert!((1..=120_000).contains(&millis));
    assert!(matches!(mode, "cpu" | "sched" | "fault" | "mixed"));
    let pid = checked(call(172, 0, 0, 0, 0, 0, 0));
    say!("WORKLOAD READY label={label} mode={mode} pid={pid}");
    let start = now();
    let mut iterations = 0u64;
    while now() - start < millis * 1_000_000 {
        match mode {
            "cpu" => {
                for value in 0..100_000u64 {
                    core::hint::black_box(value.wrapping_mul(17));
                }
            }
            "sched" => {
                checked(call(124, 0, 0, 0, 0, 0, 0));
                sleep_ms(1);
            }
            "fault" => fault_iteration(),
            "mixed" => {
                for value in 0..100_000u64 {
                    core::hint::black_box(value.wrapping_mul(17));
                }
                fault_iteration();
                checked(call(124, 0, 0, 0, 0, 0, 0));
            }
            _ => unreachable!(),
        }
        iterations += 1;
    }
    let stop = now();
    say!(
        "WORKLOAD RESULT label={label} mode={mode} pid={pid} start_ns={start} stop_ns={stop} \
         wall_ns={} iterations={iterations}",
        stop - start
    );
}

fn dump(path: &str, name: &str) {
    assert!(path.len() < 4096 && !path.as_bytes().contains(&0));
    assert!(
        !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    );
    let mut filename = [0u8; 4096];
    filename[..path.len()].copy_from_slice(path.as_bytes());
    let fd = checked(call(
        56,
        (-100isize) as usize,
        filename.as_ptr() as usize,
        0,
        0,
        0,
        0,
    ));
    say!("RECORD_FILE BEGIN name={name}");
    let mut data = [0u8; 256];
    let mut hex = [0u8; 512];
    let mut bytes = 0usize;
    let mut crc = !0u32;
    loop {
        let rc = call(63, fd, data.as_mut_ptr() as usize, data.len(), 0, 0, 0);
        if rc == -4 {
            continue;
        }
        let n = checked(rc);
        assert!(n <= data.len());
        if n == 0 {
            break;
        }
        for (i, byte) in data[..n].iter().enumerate() {
            crc ^= *byte as u32;
            for _ in 0..8 {
                crc = (crc >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(crc & 1)));
            }
            hex[2 * i] = b"0123456789abcdef"[(byte >> 4) as usize];
            hex[2 * i + 1] = b"0123456789abcdef"[(byte & 15) as usize];
        }
        say!(
            "RECORD_FILE DATA name={name} offset={bytes} hex={}",
            core::str::from_utf8(&hex[..n * 2]).unwrap()
        );
        bytes += n;
        assert!(bytes <= 32 * 1024 * 1024);
    }
    assert_eq!(call(57, fd, 0, 0, 0, 0, 0), 0);
    say!("RECORD_FILE END name={name} bytes={bytes} crc={}", !crc);
}

/// # Safety
/// `_start` supplies the untouched Linux initial stack: an aligned argc word,
/// argc argv pointers to NUL-terminated live immutable strings, then a null
/// pointer. The kernel owns these bytes for the entire process lifetime.
// SAFETY: the standalone linker includes exactly one fixture_main symbol; the
// architecture entry stub passes the initial stack using the C argument ABI.
#[unsafe(no_mangle)]
unsafe extern "C" fn fixture_main(stack: *const usize) -> ! {
    // SAFETY: the entry contract supplies the readable aligned argc word.
    let count = unsafe { *stack };
    assert!((2..=5).contains(&count));
    let mut args = [""; 5];
    for (index, arg) in args[..count].iter_mut().enumerate() {
        // SAFETY: index < argc, so this slot is in the initialized argv table.
        let ptr = unsafe { *stack.add(index + 1) as *const u8 };
        assert!(!ptr.is_null());
        let mut length = 0;
        // SAFETY: entry contract supplies each whole NUL-terminated string;
        // the loop stops before reading beyond it and imposes a size bound.
        while unsafe { *ptr.add(length) } != 0 {
            length += 1;
            assert!(length < 4096);
        }
        // SAFETY: these length initialized bytes precede the terminator in one
        // still-live immutable argv string, u8 alignment is one, size <4096.
        *arg = core::str::from_utf8(unsafe { core::slice::from_raw_parts(ptr, length) }).unwrap();
    }
    match args[1] {
        "dump" => {
            assert_eq!(count, 4);
            dump(args[2], args[3]);
        }
        "sleep" => {
            assert_eq!(count, 3);
            sleep_ms(args[2].parse().unwrap());
        }
        mode => {
            assert_eq!(count, 4);
            work(mode, args[2].parse().unwrap(), args[3]);
        }
    }
    exit(0)
}
