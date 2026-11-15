//! Real file-backed executable mutations, fork inheritance and exec replacement.
//!
//! Binary deployment contract: run.py injects this exact ELF as payload
//! and a separately built child ELF. mapping_guest.ld fixes the relocation-free
//! assembly below at file offset 4096; the host checks that contract before boot.
use super::*;

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(r#"
    .section .text.mapping_loop,"ax"
    .balign 16
    .global mapped_busy_loop
    .type mapped_busy_loop,@function
mapped_busy_loop:
    addi a0, a0, -1
    bnez a0, mapped_busy_loop
    ret
    .size mapped_busy_loop, .-mapped_busy_loop
"#);
#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(r#"
    .section .text.mapping_loop,"ax"
    .balign 16
    .global mapped_busy_loop
    .type mapped_busy_loop,@function
mapped_busy_loop:
    addi.d $a0, $a0, -1
    bnez $a0, mapped_busy_loop
    jr $ra
    .size mapped_busy_loop, .-mapped_busy_loop
"#);

fn name(value: &core::ffi::CStr) {
    check!(syscall(167, 15, value.as_ptr() as usize, 0, 0, 0, 0) == 0, "mapping task rename");
}

fn spin_mapping(base: usize, phase: &str, mut rings: Option<&mut [Ring; CPUS]>, stats: &mut Stats) {
    let start = monotonic_ns();
    let pid = ok("mapping pid", syscall(172, 0, 0, 0, 0, 0, 0));
    while monotonic_ns() - start < 150_000_000 {
        // SAFETY (binary deployment contract above): successful file mmap
        // returned an RX mapping whose first byte is mapped_busy_loop's first
        // instruction. That loop has no relocations/data accesses, accepts one
        // usize in the target C argument register, clobbers only that register,
        // and returns through the C return-address register. Its bytes remain
        // mapped and executable throughout this call; only this thread mutates
        // the mapping. run.py independently verifies ELF offset and symbols.
        // No Rust reference aliases the mapping and no stack/unwind state is
        // created by the loop. Function/data pointers are both 64-bit on the
        // only two build targets selected by run.py (RV64 and LA64).
        unsafe {
            // Follow std::mem::transmute's pointer-to-function example:
            // https://doc.rust-lang.org/std/mem/fn.transmute.html#examples
            // Cast the integer address first; integer-to-pointer transmute has
            // unspecified semantics distinct from this raw-pointer conversion.
            let busy: unsafe extern "C" fn(usize) = core::mem::transmute(base as *const ());
            busy(2_000_000);
        }
        if let Some(rings) = rings.as_deref_mut() { drain_all(rings, stats); }
    }
    say!("MAPPING WORK phase={} pid={} start_ns={} end_ns={} start={} len={} pgoff={}",
         phase, pid, start, monotonic_ns(), base, PAGE, PAGE);
}

#[cfg(not(mapping_exec_child))]
pub fn run(rings: &mut [Ring; CPUS], stats: &mut Stats) {
    let old = c"payload";
    let renamed = c"mapping-renamed.elf";
    let fd = ok("mapping open", syscall(56, (-100isize) as usize, old.as_ptr() as usize, 0, 0, 0, 0));
    let base = ok("mapping executable mmap", syscall(222, 0, PAGE, 5, 2, fd, PAGE));
    check!(base != 0, "mapping executable mmap null");
    spin_mapping(base, "mapped", Some(rings), stats);
    name(c"mapping-renamed");
    check!(syscall(276, (-100isize) as usize, old.as_ptr() as usize,
                   (-100isize) as usize, renamed.as_ptr() as usize, 0, 0) == 0, "mapped file rename");
    spin_mapping(base, "renamed", Some(rings), stats);
    let child = ok("mapping fork", syscall(220, 17, 0, 0, 0, 0, 0));
    if child == 0 {
        name(c"mapping-fork");
        spin_mapping(base, "fork", None, stats);
        let path = c"mapping-child.elf";
        let argv = [path.as_ptr() as usize, 0];
        let env = [0usize];
        syscall(221, path.as_ptr() as usize, argv.as_ptr() as usize, env.as_ptr() as usize, 0, 0, 0);
        say!("SAMPLING FAIL mapping child exec returned");
        exit(1);
    }
    let wait_started = monotonic_ns();
    let mut status = 0u32;
    loop {
        let waited = ok("mapping wait", syscall(260, child, &mut status as *mut u32 as usize, 1, 0, 0, 0));
        if waited != 0 { break; }
        drain_all(rings, stats);
        check!(monotonic_ns() - wait_started < 10_000_000_000, "mapping child timed out");
        sleep_ms(1);
    }
    check!(status == 0, "mapping child failed");
    check!(syscall(226, base, PAGE, 1, 0, 0, 0) == 0, "mapping protect read");
    check!(syscall(226, base, PAGE, 5, 0, 0, 0) == 0, "mapping protect executable");
    let target = ok("mapping remap reserve", syscall(222, 0, PAGE * 2, 0, 0x22, usize::MAX, 0));
    let moved = ok("mapping remap", syscall(216, base, PAGE, PAGE * 2, 3, target, 0));
    check!(moved == target && moved != base, "mapping fixed move not performed");
    spin_mapping(moved, "remapped", Some(rings), stats);
    check!(syscall(215, moved, PAGE * 2, 0, 0, 0, 0) == 0, "mapping unmap");
    // Split a backend whose original file offset is zero. Moving only its
    // second page must retain byte pgoff=4096 rather than reusing offset zero.
    let partial = ok("partial mapping mmap", syscall(222, 0, PAGE * 2, 5, 2, fd, 0));
    let destination = ok("partial remap reserve", syscall(222, 0, PAGE, 0, 0x22, usize::MAX, 0));
    let partial_moved = ok("partial mapping remap", syscall(216, partial + PAGE, PAGE, PAGE, 3, destination, 0));
    check!(partial_moved == destination && partial_moved != partial + PAGE, "partial fixed move not performed");
    spin_mapping(partial_moved, "partial_remapped", Some(rings), stats);
    check!(syscall(215, partial_moved, PAGE, 0, 0, 0, 0) == 0, "partial moved unmap");
    check!(syscall(215, partial, PAGE, 0, 0, 0, 0) == 0, "partial prefix unmap");
    close(fd);
    say!("MAPPING COMPLETE child={} old={} moved={} status=0", child, base, moved);
}

#[cfg(mapping_exec_child)]
pub fn child(stats: &mut Stats) -> ! {
    name(c"mapping-exec");
    let fd = ok("child mapping open", syscall(56, (-100isize) as usize, c"mapping-child.elf".as_ptr() as usize, 0, 0, 0, 0));
    let base = ok("child mapping mmap", syscall(222, 0, PAGE, 5, 2, fd, PAGE));
    check!(base != 0, "child mmap null");
    spin_mapping(base, "exec", None, stats);
    check!(syscall(215, base, PAGE, 0, 0, 0, 0) == 0, "child mapping unmap");
    close(fd);
    exit(0);
}
