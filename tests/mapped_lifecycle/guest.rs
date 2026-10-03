//! Six deterministic issue #67 guest cases, no libc/allocator/pthreads.
//! Uses the common RISC-V64/LoongArch64 Linux syscall numbers directly.
//! Build via run.py build-raw. guest.ld places ENTRY(_start) at 0x400000.
//! Every case runs in a child so one assertion failure does not hide later cases.
//! Host driver bounds all waits/guest hangs; pipe rendezvous orders fork accesses.
//! Single-thread fixed replacement checks completed-syscall visibility, not remote
//! CPU shootdowns or a forced prepare/revalidate race. File readback may be cached.
//! Sync/reset fault injection and checkpoint stress remain explicitly unsupported.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::ptr::{read_volatile, write_volatile};

const PAGE: usize = 4096;
const RW: usize = 3;
const SHARED: usize = 1;
const PRIVATE: usize = 2;
const FIXED: usize = 0x10;
const ANONYMOUS: usize = 0x20;
const NOREPLACE: usize = 0x100000;
const MS_SYNC: usize = 4;
const EINVAL: isize = -22;
const ENOMEM: isize = -12;
const EEXIST: isize = -17;

#[cfg(target_arch = "riscv64")]
global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    ".option push",
    ".option norelax",
    "la gp, __global_pointer$",
    ".option pop",
    "call guest_main",
    "unimp",
);
#[cfg(target_arch = "loongarch64")]
global_asm!(
    ".section .text._start,\"ax\"",
    ".global _start",
    "_start:",
    "bl guest_main",
    "break 0",
);

#[inline(always)]
fn syscall(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let result: isize;
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
fn exit(code: usize) -> ! {
    syscall(93, code, 0, 0, 0, 0, 0);
    loop { core::hint::spin_loop(); }
}
struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut bytes = text.as_bytes();
        while !bytes.is_empty() {
            let n = syscall(64, 1, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0);
            if n == -4 { continue; }
            if n <= 0 { return Err(fmt::Error); }
            bytes = &bytes[n as usize..];
        }
        Ok(())
    }
}
macro_rules! say {
    ($($arg:tt)*) => {{ let _ = writeln!(Console, $($arg)*); }};
}
macro_rules! check {
    ($condition:expr) => {
        if !$condition {
            say!("MLC FAIL raw_assert line={} assertion={}", line!(), stringify!($condition));
            exit(1);
        }
    };
}
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    say!("MLC FAIL raw_panic {}", info);
    exit(1)
}
fn ok(name: &str, result: isize) -> usize {
    if result < 0 {
        say!("MLC FAIL raw_syscall {} result={}", name, result);
        exit(1);
    }
    result as usize
}
fn expect(name: &str, result: isize, wanted: isize) {
    if result != wanted {
        say!("MLC FAIL raw_errno {} actual={} expected={}", name, result, wanted);
        exit(1);
    }
}
fn close(fd: usize) { ok("close57", syscall(57, fd, 0, 0, 0, 0, 0)); }
fn open(path: &[u8], flags: usize) -> usize {
    ok("openat56", syscall(56, (-100isize) as usize, path.as_ptr() as usize,
                          flags, 0o600, 0, 0))
}
fn make_file(path: &[u8], pages: usize, seed: u8) -> usize {
    let fd = open(path, 2 | 0x40 | 0x200); // O_RDWR | O_CREAT | O_TRUNC
    ok("ftruncate46", syscall(46, fd, pages * PAGE, 0, 0, 0, 0));
    let mut buffer = [0u8; PAGE];
    for page in 0..pages {
        for byte in &mut buffer { *byte = seed + page as u8; }
        let mut offset = 0;
        while offset < PAGE {
            let n = ok("write64", syscall(64, fd, buffer[offset..].as_ptr() as usize,
                                          PAGE - offset, 0, 0, 0));
            check!(n > 0);
            offset += n;
        }
    }
    fd
}
fn mmap(at: usize, pages: usize, prot: usize, flags: usize, fd: usize, offset: usize) -> usize {
    ok("mmap222", syscall(222, at, pages * PAGE, prot, flags, fd, offset))
}
fn unmap(at: usize, pages: usize) {
    expect("munmap215", syscall(215, at, pages * PAGE, 0, 0, 0, 0), 0);
}
fn msync(at: usize, pages: usize) {
    expect("msync227", syscall(227, at, pages * PAGE, MS_SYNC, 0, 0, 0), 0);
}
fn protect(at: usize, pages: usize, prot: usize) {
    expect("mprotect226", syscall(226, at, pages * PAGE, prot, 0, 0, 0), 0);
}
fn fill(at: usize, value: u8) {
    for i in 0..PAGE { unsafe { write_volatile((at + i) as *mut u8, value) }; }
}
fn bytes(at: usize, value: u8) {
    for i in 0..PAGE {
        let actual = unsafe { read_volatile((at + i) as *const u8) };
        if actual != value {
            say!("MLC FAIL raw_bytes offset={} actual={} expected={}", i, actual, value);
            exit(1);
        }
    }
}
fn file_page(fd: usize, page: usize, value: u8) {
    let mut buffer = [0u8; PAGE];
    let mut pos = 0;
    while pos < PAGE {
        let n = ok("pread64_67", syscall(67, fd, buffer[pos..].as_mut_ptr() as usize,
                                        PAGE - pos, page * PAGE + pos, 0, 0));
        check!(n > 0);
        pos += n;
    }
    for (i, actual) in buffer.iter().enumerate() {
        if *actual != value {
            say!("MLC FAIL raw_readback page={} byte={} actual={} expected={}",
                 page, i, actual, value);
            exit(1);
        }
    }
}
fn fork() -> usize {
    ok("clone220_SIGCHLD", syscall(220, 17, 0, 0, 0, 0, 0))
}
fn wait(pid: usize) -> i32 {
    let mut status = -1i32;
    expect("wait4_260", syscall(260, pid, &mut status as *mut i32 as usize, 0, 0, 0, 0),
           pid as isize);
    status
}
struct Pipe { read: usize, write: usize }
fn pipe() -> Pipe {
    let mut fds = [-1i32; 2];
    expect("pipe2_59", syscall(59, fds.as_mut_ptr() as usize, 0, 0, 0, 0, 0), 0);
    Pipe { read: fds[0] as usize, write: fds[1] as usize }
}
fn send(fd: usize) {
    let byte = 0x58u8;
    expect("pipe_write64", syscall(64, fd, &byte as *const u8 as usize, 1, 0, 0, 0), 1);
}
fn receive(fd: usize) {
    let mut byte = 0u8;
    expect("pipe_read63", syscall(63, fd, &mut byte as *mut u8 as usize, 1, 0, 0, 0), 1);
    check!(byte == 0x58);
}

fn shared_alias_readback() {
    let fd = make_file(b"shared.bin\0", 2, 0x20);
    let a = mmap(0, 2, RW, SHARED, fd, 0);
    let b = mmap(0, 2, RW, SHARED, fd, 0);
    bytes(a, 0x20);
    bytes(b + PAGE, 0x21);
    fill(a, 0x40);
    bytes(b, 0x40); // before msync
    fill(b + PAGE, 0x41);
    bytes(a + PAGE, 0x41);
    msync(a, 2);
    unmap(a, 2);
    unmap(b, 2);
    close(fd);
    let fd = open(b"shared.bin\0", 0);
    file_page(fd, 0, 0x40);
    file_page(fd, 1, 0x41);
    close(fd);
}
fn private_cow_isolation() {
    let fd = make_file(b"private.bin\0", 1, 0x25);
    let shared = mmap(0, 1, RW, SHARED, fd, 0);
    let private = mmap(0, 1, RW, PRIVATE, fd, 0);
    bytes(shared, 0x25);
    bytes(private, 0x25);
    fill(private, 0x65);
    bytes(private, 0x65);
    bytes(shared, 0x25);
    msync(private, 1);
    file_page(fd, 0, 0x25);
    unmap(private, 1);
    let private = mmap(0, 1, RW, PRIVATE, fd, 0);
    bytes(private, 0x25);
    unmap(private, 1);
    unmap(shared, 1);
    close(fd);
}
fn fork_pipe_shared_private() {
    let fd = make_file(b"fork.bin\0", 3, 0x30);
    let shared = mmap(0, 1, RW, SHARED, fd, 0);
    let dirty = mmap(0, 1, RW, PRIVATE, fd, PAGE);
    let clean = mmap(0, 1, RW, PRIVATE, fd, 2 * PAGE);
    bytes(shared, 0x30);
    bytes(clean, 0x32);
    fill(dirty, 0x43); // COW present before fork
    let up = pipe();
    let down = pipe();
    let pid = fork();
    if pid == 0 {
        close(up.read);
        close(down.write);
        fill(shared, 0x51);
        fill(dirty, 0x52);
        fill(clean, 0x53); // first COW after fork
        send(up.write);
        receive(down.read);
        bytes(shared, 0x61);
        bytes(dirty, 0x52);
        bytes(clean, 0x53);
        exit(0); // intentionally leave mappings/descriptors live on exit
    }
    close(up.write);
    close(down.read);
    receive(up.read);
    bytes(shared, 0x51);
    bytes(dirty, 0x43); // unchanged parent's private pages
    bytes(clean, 0x32);
    fill(shared, 0x61);
    fill(dirty, 0x62);
    fill(clean, 0x63);
    send(down.write);
    check!(wait(pid) == 0);
    bytes(dirty, 0x62);
    bytes(clean, 0x63);
    msync(shared, 1);
    file_page(fd, 0, 0x61);
    file_page(fd, 1, 0x31);
    file_page(fd, 2, 0x32);
    close(up.read);
    close(down.write);
    unmap(shared, 1);
    unmap(dirty, 1);
    unmap(clean, 1);
    close(fd);
}
fn partial_unmap_sigsegv() {
    let fd = make_file(b"partial.bin\0", 3, 0x20);
    let at = mmap(0, 3, RW, SHARED, fd, 0);
    for page in 0..3 {
        bytes(at + page * PAGE, 0x20 + page as u8);
        fill(at + page * PAGE, 0x40 + page as u8);
    }
    unmap(at + PAGE, 1);
    bytes(at, 0x40);
    bytes(at + 2 * PAGE, 0x42);
    let pid = fork();
    if pid == 0 {
        unsafe { read_volatile((at + PAGE) as *const u8); }
        exit(99); // a readable hole is an assertion failure
    }
    let status = wait(pid);
    say!("MLC NOTE raw_partial_unmap child_wait_status={}", status);
    check!((status & 0x7f) == 11); // actual guest SIGSEGV, not simulated errno
    fill(at, 0x60);
    fill(at + 2 * PAGE, 0x62);
    check!(mmap(at + PAGE, 1, RW, PRIVATE | ANONYMOUS | FIXED, usize::MAX, 0) == at + PAGE);
    fill(at + PAGE, 0x7a);
    msync(at, 1);
    msync(at + 2 * PAGE, 1);
    unmap(at, 3);
    file_page(fd, 0, 0x60);
    file_page(fd, 1, 0x41);
    file_page(fd, 2, 0x62); // upper window retains original file offset
    close(fd);
}
fn fixed_replace_noreplace() {
    let a = make_file(b"fixed-a.bin\0", 1, 0x21);
    let b = make_file(b"fixed-b.bin\0", 1, 0x51);
    let at = mmap(0, 1, RW, SHARED, a, 0);
    bytes(at, 0x21); // warm translation
    let mut last = [0x21u8, 0x51];
    for round in 0..32 {
        let index = (round + 1) % 2;
        let target = if index == 0 { a } else { b };
        expect("MAP_FIXED_NOREPLACE occupied", syscall(222, at, PAGE, RW,
               SHARED | NOREPLACE, target, 0), EEXIST);
        bytes(at, last[1 - index]); // refusal preserves old mapping
        check!(mmap(at, 1, RW, SHARED | FIXED, target, 0) == at);
        bytes(at, last[index]); // syscall-completed translation sees new file
        last[index] = 0x80 + round as u8;
        fill(at, last[index]);
        msync(at, 1);
        file_page(a, 0, last[0]);
        file_page(b, 0, last[1]);
    }
    unmap(at, 1);
    // The same address must now be available to NOREPLACE.
    check!(mmap(at, 1, RW, SHARED | NOREPLACE, a, 0) == at);
    bytes(at, last[0]);
    unmap(at, 1);
    close(a);
    close(b);
}
fn msync_readonly_errors() {
    let fd = make_file(b"readonly.bin\0", 3, 0x20);
    let at = mmap(0, 3, RW, SHARED, fd, 0);
    for page in 0..3 { fill(at + page * PAGE, 0x60 + page as u8); }
    protect(at, 3, 1); // writable -> read-only must retain dirty publication
    msync(at, 3);
    for page in 0..3 { file_page(fd, page, 0x60 + page as u8); }
    expect("msync unaligned", syscall(227, at + 1, PAGE, MS_SYNC, 0, 0, 0), EINVAL);
    expect("msync incompatible flags", syscall(227, at, PAGE, MS_SYNC | 1, 0, 0, 0), EINVAL);
    unmap(at + PAGE, 1);
    expect("msync unmapped hole", syscall(227, at + PAGE, PAGE, MS_SYNC, 0, 0, 0), ENOMEM);
    expect("msync range crossing hole", syscall(227, at, 3 * PAGE, MS_SYNC, 0, 0, 0), ENOMEM);
    bytes(at, 0x60);
    bytes(at + 2 * PAGE, 0x62);
    unmap(at, 1);
    unmap(at + 2 * PAGE, 1);
    close(fd);
}

#[cfg(not(bootstrap))]
#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    say!("MLC START version=2 suite=raw6 page_size=4096 iterations=32");
    let tests: [(&str, fn()); 6] = [
        ("raw_shared_alias_readback", shared_alias_readback),
        ("raw_private_cow_isolation", private_cow_isolation),
        ("raw_fork_pipe_shared_private", fork_pipe_shared_private),
        ("raw_partial_unmap_sigsegv", partial_unmap_sigsegv),
        ("raw_fixed_replace_noreplace", fixed_replace_noreplace),
        ("raw_msync_readonly_errors", msync_readonly_errors),
    ];
    let mut passed = 0;
    for (name, run) in tests {
        say!("MLC BEGIN {}", name);
        let pid = fork();
        if pid == 0 {
            run();
            exit(0);
        }
        let status = wait(pid);
        if status == 0 {
            passed += 1;
            say!("MLC PASS {}", name);
        } else {
            say!("MLC FAIL {} child_wait_status={}", name, status);
        }
    }
    say!("MLC SKIP sync_failure_reset_refusal no integration FileNode fault/power hook");
    say!("MLC SKIP raw_mlocked_ebusy optional mlock semantics not exercised");
    say!("MLC NOTE raw6 no concurrent checkpoint/preparation stress or remote-CPU TLB proof");
    say!("MLC SUMMARY pass={} fail={} skip=2", passed, 6 - passed);
    if passed == 6 {
        say!("MLC RESULT PASS functional_only=1 suite=raw6");
        exit(0);
    }
    say!("MLC RESULT FAIL suite=raw6");
    exit(1)
}

// Minimal host-controlled console, NOT a POSIX shell. Installed as /bin/sh only
// in an isolated image copy with --bootstrap. Protocol: MLC_RUN PATH DIR TOKEN.
// Fork+exec+wait produces the real payload status; command echo is not evidence.
#[cfg(bootstrap)]
#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    say!("MLC BOOTSTRAP raw-console version=1");
    let _ = Console.write_str("/ # ");
    let mut line = [0u8; 512];
    let mut count = 0;
    while count + 1 < line.len() {
        let n = syscall(63, 0, line[count..].as_mut_ptr() as usize, 1, 0, 0, 0);
        if n == -4 { continue; }
        check!(n == 1);
        if line[count] == b'\n' || line[count] == b'\r' { break; }
        count += 1;
    }
    check!(count + 1 < line.len());
    let mut starts = [0usize; 4];
    let mut fields = 0;
    for i in 0..count {
        if line[i] == b' ' || line[i] == b'\t' {
            line[i] = 0;
        } else if i == 0 || line[i - 1] == 0 {
            check!(fields < 4);
            starts[fields] = i;
            fields += 1;
        }
    }
    check!(fields == 4 && &line[..7] == b"MLC_RUN");
    let token = core::str::from_utf8(&line[starts[3]..count]).unwrap();
    let pid = fork();
    if pid == 0 {
        expect("bootstrap chdir49", syscall(49, line[starts[2]..].as_ptr() as usize,
                                           0, 0, 0, 0, 0), 0);
        let argv = [line[starts[1]..].as_ptr() as usize, 0];
        let env = [0usize];
        let result = syscall(221, argv[0], argv.as_ptr() as usize, env.as_ptr() as usize,
                             0, 0, 0);
        say!("MLC FAIL bootstrap execve221 result={}", result);
        exit(127);
    }
    let status = wait(pid);
    let code = if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) };
    say!("\nMLC_HOST_EXIT {} {}", token, code);
    // Keep init alive; the driver terminates QEMU after it records the marker.
    loop { syscall(124, 0, 0, 0, 0, 0, 0); }
}
