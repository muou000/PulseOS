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

// A raw clone changes the child's stack before returning. Keep that transition
// in assembly: the child never returns through a Rust frame on the old stack.
#[cfg(target_arch = "riscv64")]
global_asm!(
    ".section .text.fixture_clone,\"ax\"",
    ".global fixture_clone",
    "fixture_clone:",
    "addi a0, a0, -16",
    "sd a1, 0(a0)",
    "mv a1, a0",
    "li a0, 0x50f00",
    "li a2, 0",
    "li a3, 0",
    "li a4, 0",
    "li a7, 220",
    "ecall",
    "bnez a0, 2f",
    "ld a0, 0(sp)",
    "addi sp, sp, 16",
    "call fixture_child",
    "unimp",
    "2:",
    "ret"
);
#[cfg(target_arch = "loongarch64")]
global_asm!(
    ".section .text.fixture_clone,\"ax\"",
    ".global fixture_clone",
    "fixture_clone:",
    "addi.d $a0, $a0, -16",
    "st.d $a1, $a0, 0",
    "move $a1, $a0",
    "li.w $a0, 0x50f00",
    "move $a2, $zero",
    "move $a3, $zero",
    "move $a4, $zero",
    "li.w $a7, 220",
    "syscall 0",
    "bnez $a0, 2f",
    "ld.d $a0, $sp, 0",
    "addi.d $sp, $sp, 16",
    "bl fixture_child",
    "break 0",
    "2:",
    "jr $ra"
);

struct ChildArgs<'a> {
    binary: &'a str,
    duration: &'a str,
}
unsafe extern "C" {
    /// # Safety
    /// stack_top ends a private live RW mapping of at least 256KiB, aligned to
    /// 16 bytes. args is initialized, aligned and immutable while the child
    /// runs; both strings refer to NUL-terminated immutable initial argv bytes.
    /// Parent must not unmap the stack or return while child can access args.
    fn fixture_clone(stack_top: usize, args: *const core::ffi::c_void) -> isize;
}

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

fn exec_thread(binary: &str, duration: &str) -> ! {
    const STACK_SIZE: usize = 256 * 1024;
    let base = checked(call(222, 0, STACK_SIZE, 3, 0x22, usize::MAX, 0));
    assert!(base != 0 && base % 4096 == 0);
    let top = base.checked_add(STACK_SIZE).unwrap();
    let args = ChildArgs { binary, duration };
    // SAFETY: mmap owns the checked nonnull aligned 256KiB writable range.
    // args and its initial-argv strings remain immutable and alive: this parent
    // never returns or unmaps and is terminated by child's successful exec.
    // The assembly initializes the child's argument slot before clone, and the
    // kernel publishes those writes when creating the shared-VM thread. Only
    // the child accesses its new stack; no Rust reference aliases that range.
    let tid = checked(unsafe { fixture_clone(top, core::ptr::from_ref(&args).cast()) });
    assert!(tid != 0);
    let fd = checked(call(
        56,
        (-100isize) as usize,
        c"exec-thread.tid".as_ptr() as usize,
        0x241,
        0o600,
        0,
        0,
    ));
    let mut digits = [0u8; 32];
    let mut offset = digits.len();
    let mut value = tid;
    while value != 0 {
        offset -= 1;
        digits[offset] = b'0' + (value % 10) as u8;
        value /= 10;
    }
    assert_eq!(
        call(
            64,
            fd,
            digits[offset..].as_ptr() as usize,
            digits.len() - offset,
            0,
            0,
            0
        ),
        (digits.len() - offset) as isize
    );
    assert_eq!(call(57, fd, 0, 0, 0, 0, 0), 0);
    say!(
        "EXEC_THREAD READY parent_tid={} initial_tid={tid}",
        checked(call(178, 0, 0, 0, 0, 0, 0))
    );
    let start = now();
    while now() - start < 30_000_000_000 {
        core::hint::black_box(&args);
        sleep_ms(10);
    }
    say!("FIXTURE FAIL nonleader exec did not replace process");
    call(94, 1, 0, 0, 0, 0, 0);
    exit(1)
}

/// # Safety
/// Called only by fixture_clone's child trampoline, on its private aligned
/// stack. args satisfies fixture_clone's lifetime and initialization contract.
// SAFETY: this is the sole fixture_child symbol and the assembly stub invokes
// it with the C ABI; successful exec replaces the process and never returns.
#[unsafe(no_mangle)]
unsafe extern "C" fn fixture_child(args: *const core::ffi::c_void) -> ! {
    // SAFETY: the trampoline's entry contract provides a live aligned immutable
    // ChildArgs; parent remains in its no-return wait until exec terminates it.
    let args = unsafe { &*args.cast::<ChildArgs<'_>>() };
    let initial_tid = checked(call(178, 0, 0, 0, 0, 0, 0));
    let start = now();
    loop {
        for value in 0..1_000_000u64 {
            core::hint::black_box(value.wrapping_mul(17));
        }
        let ready = call(
            56,
            (-100isize) as usize,
            c"exec-thread.go".as_ptr() as usize,
            0,
            0,
            0,
            0,
        );
        if ready >= 0 {
            checked(call(57, ready as usize, 0, 0, 0, 0, 0));
            break;
        }
        assert_eq!(ready, -2);
        assert!(now() - start < 30_000_000_000, "exec go timeout");
    }
    say!("EXEC_THREAD EXEC initial_tid={initial_tid} at_ns={}", now());
    let argv = [
        args.binary.as_ptr() as usize,
        c"cpu".as_ptr() as usize,
        args.duration.as_ptr() as usize,
        c"exec-after".as_ptr() as usize,
        0,
    ];
    let env = [0usize];
    // Pointer arguments name initialized NUL-terminated initial argv or
    // literals; arrays stay live until synchronous exec succeeds or fails.
    let rc = call(
        221,
        args.binary.as_ptr() as usize,
        argv.as_ptr() as usize,
        env.as_ptr() as usize,
        0,
        0,
        0,
    );
    say!("FIXTURE FAIL nonleader exec errno={rc}");
    call(94, 1, 0, 0, 0, 0, 0);
    exit(1)
}

#[inline(never)]
fn sample_leaf() -> u64 {
    let mut value = 0u64;
    for index in 0..100_000u64 {
        value = core::hint::black_box(value.wrapping_add(index.wrapping_mul(17)));
    }
    core::hint::black_box(value)
}
#[inline(never)]
fn sample_middle() -> u64 {
    let value = sample_leaf();
    core::hint::black_box(value.wrapping_add(1))
}
#[inline(never)]
fn sample_outer() -> u64 {
    let value = sample_middle();
    core::hint::black_box(value.wrapping_add(2))
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
                core::hint::black_box(sample_outer());
            }
            "sched" => {
                checked(call(124, 0, 0, 0, 0, 0, 0));
                sleep_ms(1);
            }
            "fault" => fault_iteration(),
            "mixed" => {
                core::hint::black_box(sample_outer());
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

fn mapping_lifecycle() {
    let started = now();
    loop {
        let ready = call(56, (-100isize) as usize, c"mapping.go".as_ptr() as usize, 0, 0, 0, 0);
        if ready >= 0 {
            checked(call(57, ready as usize, 0, 0, 0, 0, 0));
            break;
        }
        assert!(now() - started < 30_000_000_000, "mapping recorder did not enable");
        sleep_ms(10);
    }
    let pid = checked(call(172, 0, 0, 0, 0, 0, 0));
    let fd = checked(call(56, (-100isize) as usize, c"mapping-fixture".as_ptr() as usize, 0, 0, 0, 0));
    // These mappings are only syscall operands. No reference or function
    // pointer is formed, so file contents cannot become Rust values or code.
    let base = checked(call(222, 0, 8192, 5, 2, fd, 4096));
    assert_ne!(base, 0);
    say!("MAPPING STEP phase=mapped pid={pid} base={base} len=8192 pgoff=4096 at_ns={}", now());
    work("cpu", 200, "mapping-mapped");
    checked(call(167, 15, c"mapping-renamed".as_ptr() as usize, 0, 0, 0, 0));
    checked(call(276, (-100isize) as usize, c"mapping-fixture".as_ptr() as usize,
        (-100isize) as usize, c"mapping-renamed.elf".as_ptr() as usize, 0, 0));
    say!("MAPPING STEP phase=renamed pid={pid} base={base} at_ns={}", now());
    work("cpu", 200, "mapping-renamed");
    // fork creates a separate address space with no shared Rust allocation;
    // both branches resume the initialized stack, and the child then execs.
    let child = checked(call(220, 17, 0, 0, 0, 0, 0));
    if child == 0 {
        checked(call(167, 15, c"mapping-fork".as_ptr() as usize, 0, 0, 0, 0));
        work("cpu", 200, "mapping-fork");
        let argv = [c"record-fixture".as_ptr() as usize, c"cpu".as_ptr() as usize,
            c"200".as_ptr() as usize, c"mapping-exec".as_ptr() as usize, 0];
        let env = [0usize];
        call(221, argv[0], argv.as_ptr() as usize, env.as_ptr() as usize, 0, 0, 0);
        panic!("mapping child exec returned");
    }
    let mut status = 0u32;
    checked(call(260, child, core::ptr::from_mut(&mut status) as usize, 0, 0, 0, 0));
    assert_eq!(status, 0);
    let destination = checked(call(222, 0, 8192, 0, 0x22, usize::MAX, 0));
    let moved = checked(call(216, base, 8192, 8192, 3, destination, 0));
    assert_eq!(moved, destination);
    assert_ne!(moved, base);
    say!("MAPPING STEP phase=remapped pid={pid} old={base} base={moved} len=8192 pgoff=4096 at_ns={}", now());
    work("cpu", 200, "mapping-remapped");
    checked(call(215, moved, 8192, 0, 0, 0, 0));
    let reused = checked(call(222, base, 8192, 3, 0x32, usize::MAX, 0));
    assert_eq!(reused, base);
    say!("MAPPING STEP phase=reused_address pid={pid} base={base} len=8192 at_ns={}", now());
    work("cpu", 200, "mapping-reused");
    checked(call(215, reused, 8192, 0, 0, 0, 0));
    checked(call(57, fd, 0, 0, 0, 0, 0));
    say!("MAPPING COMPLETE pid={pid} child={child} old={base} moved={moved} at_ns={}", now());
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
        "mapping" => {
            assert_eq!(count, 2);
            mapping_lifecycle();
        }
        "exec-thread" => {
            assert_eq!(count, 3);
            exec_thread(args[0], args[2]);
        }
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
