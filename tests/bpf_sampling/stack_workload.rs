//! Fixed-frame user code and real syscall work for the stack sampling gate.
use super::*;

#[cfg(target_arch = "riscv64")]
global_asm!(
    ".section .text._start,\"ax\"", ".global _start", "_start:",
    ".option push", ".option norelax", "la gp, __global_pointer$", ".option pop",
    "call guest_main", "unimp",
    ".section .text.sample_loops,\"ax\"",
    ".macro frame_enter", "addi sp, sp, -16", "sd ra, 8(sp)", "sd s0, 0(sp)", "addi s0, sp, 16", ".endm",
    ".macro frame_leave", "ld ra, 8(sp)", "ld s0, 0(sp)", "addi sp, sp, 16", "ret", ".endm",
    ".balign 16", ".global sample_loop_a", ".global sample_loop_a_end", "sample_loop_a:",
    "frame_enter", "2:", "addi a0, a0, -1", "bnez a0, 2b", "frame_leave", "sample_loop_a_end:",
    ".balign 16", ".global sample_loop_b", ".global sample_loop_b_end", "sample_loop_b:",
    "frame_enter", "2:", "addi a0, a0, -1", "nop", "bnez a0, 2b", "frame_leave", "sample_loop_b_end:",
    ".global sample_middle_a", "sample_middle_a:", "frame_enter", "call sample_loop_a",
    ".global sample_middle_a_return", "sample_middle_a_return:", "frame_leave",
    ".global sample_chain_a", "sample_chain_a:", "frame_enter", "call sample_middle_a",
    ".global sample_chain_a_return", "sample_chain_a_return:", "frame_leave",
    ".global sample_middle_b", "sample_middle_b:", "frame_enter", "call sample_loop_b",
    ".global sample_middle_b_return", "sample_middle_b_return:", "frame_leave",
    ".global sample_chain_b", "sample_chain_b:", "frame_enter", "call sample_middle_b",
    ".global sample_chain_b_return", "sample_chain_b_return:", "frame_leave",
);
#[cfg(target_arch = "loongarch64")]
global_asm!(
    ".section .text._start,\"ax\"", ".global _start", "_start:", "bl guest_main", "break 0",
    ".section .text.sample_loops,\"ax\"",
    ".macro frame_enter", "addi.d $sp, $sp, -16", "st.d $ra, $sp, 8", "st.d $fp, $sp, 0", "addi.d $fp, $sp, 16", ".endm",
    ".macro frame_leave", "ld.d $ra, $sp, 8", "ld.d $fp, $sp, 0", "addi.d $sp, $sp, 16", "jr $ra", ".endm",
    ".balign 16", ".global sample_loop_a", ".global sample_loop_a_end", "sample_loop_a:",
    "frame_enter", "2:", "addi.d $a0, $a0, -1", "bnez $a0, 2b", "frame_leave", "sample_loop_a_end:",
    ".balign 16", ".global sample_loop_b", ".global sample_loop_b_end", "sample_loop_b:",
    "frame_enter", "2:", "addi.d $a0, $a0, -1", "nop", "bnez $a0, 2b", "frame_leave", "sample_loop_b_end:",
    ".global sample_middle_a", "sample_middle_a:", "frame_enter", "bl sample_loop_a",
    ".global sample_middle_a_return", "sample_middle_a_return:", "frame_leave",
    ".global sample_chain_a", "sample_chain_a:", "frame_enter", "bl sample_middle_a",
    ".global sample_chain_a_return", "sample_chain_a_return:", "frame_leave",
    ".global sample_middle_b", "sample_middle_b:", "frame_enter", "bl sample_loop_b",
    ".global sample_middle_b_return", "sample_middle_b_return:", "frame_leave",
    ".global sample_chain_b", "sample_chain_b:", "frame_enter", "bl sample_middle_b",
    ".global sample_chain_b_return", "sample_chain_b_return:", "frame_leave",
);
unsafe extern "C" {
    pub fn sample_chain_a(iterations: usize);
    pub fn sample_chain_b(iterations: usize);
    static sample_middle_a_return: u8;
    static sample_chain_a_return: u8;
    static sample_middle_b_return: u8;
    static sample_chain_b_return: u8;
}

pub fn probes() {
    // Above the normal user stack, within the legal user address space. This
    // lazy READ VMA is never touched by the guest. mincore before/after proves
    // the sampler's no-fault load did not populate its missing resident page.
    let address = ok("probe lazy mmap", syscall(222, 0x5_0000_0000, PAGE, 1, 0x100022, usize::MAX, 0));
    check!(address == 0x5_0000_0000, "probe address changed");
    let mut resident = 0u8;
    check!(syscall(232,address,PAGE,&mut resident as *mut u8 as usize,0,0,0)==0 && resident==0,"probe page already resident");
    // SAFETY: each assembly entry saves/restores the real FP/RA and changes
    // only its own stack slots. Invalid frame records are sampling inputs only;
    // the probe never dereferences them or returns through them. The deep case
    // creates 41 real, initialized frames and restores each in reverse order.
    unsafe {
        sample_probe_zero(2_000_000,0);
        sample_probe_unmapped(2_000_000,address+16);
        sample_probe_cycle(2_000_000,0);
        sample_probe_badra(2_000_000,0);
        sample_probe_misaligned(2_000_000,0);
        sample_probe_deep(2_000_000,40);
    }
    check!(syscall(232,address,PAGE,&mut resident as *mut u8 as usize,0,0,0)==0 && resident==0,"sampling faulted in probe page");
    check!(syscall(215,address,PAGE,0,0,0,0)==0,"probe unmap");
}

pub fn kernel_work() {
    // MAP_POPULATE exercises the real mmap/fault-resolver/allocator chain while
    // timer IRQs remain enabled in the syscall. No test-only kernel hook exists.
    let length = 512 * 1024;
    let address = ok("stack workload populated mmap", syscall(222, 0, length, 3, 0x8022, usize::MAX, 0));
    check!(syscall(215, address, length, 0, 0, 0, 0) == 0, "stack workload munmap");
}

#[derive(Clone, Copy)]
pub struct StackStats {
    a: u64,
    b: u64,
    kernel: u64,
    partial: u64,
    sources: [u64; 16],
    periods: [u64; 16],
    source_count: usize,
    probes: [u64; 6],
}
impl StackStats {
    pub const fn new() -> Self {
        Self { a: 0, b: 0, kernel: 0, partial: 0, sources: [0; 16], periods: [0; 16], source_count: 0, probes: [0; 6] }
    }
    pub fn observe(&mut self, bytes: &[u8]) {
        let u16_at = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
        let source = u64_at(bytes, 64);
        let length = u16_at(108) as usize;
        let status = u16_at(110);
        check!(source != 0 && u16_at(104) == 3 && u16_at(106) == 32, "stack extension source/version/depth");
        check!(length <= 32 && status <= 13 && u64_at(bytes, 120) == 0
            && (length != 0 || (matches!(status, 9 | 13) && u32_at(bytes,112) == 0)), "stack length/status/flags");
        check!(u32_at(bytes,112) <= 512 && u32_at(bytes,112) % 16 == 0 && u32_at(bytes,116) == 512, "stack byte budget");
        check!(length == 0 || u64_at(bytes,128) == u64_at(bytes,48), "stack begins at another PC");
        check!(bytes[128 + length * 8..].iter().all(|b| *b == 0), "stack unused tail is not zero");
        let period = u64_at(bytes, 0);
        if let Some(index) = self.sources[..self.source_count].iter().position(|id| *id == source) {
            check!(self.periods[index] == period, "source period changed");
        } else {
            check!(self.source_count < self.sources.len(), "too many source instances");
            self.sources[self.source_count] = source;
            self.periods[self.source_count] = period;
            self.source_count += 1;
        }
        if status != 0 { self.partial += 1; }
        let ip = u64_at(bytes,48);
        if u32_at(bytes,56) == 1 && length >= 3 { self.kernel += 1; }
        if u32_at(bytes,56) == 2 {
            for (index, (start, end, expected)) in [(core::ptr::addr_of!(sample_probe_zero_start) as u64, core::ptr::addr_of!(sample_probe_zero_end) as u64, 1),
(core::ptr::addr_of!(sample_probe_unmapped_start) as u64, core::ptr::addr_of!(sample_probe_unmapped_end) as u64, 4),
(core::ptr::addr_of!(sample_probe_cycle_start) as u64, core::ptr::addr_of!(sample_probe_cycle_end) as u64, 3),
(core::ptr::addr_of!(sample_probe_badra_start) as u64, core::ptr::addr_of!(sample_probe_badra_end) as u64, 5),
(core::ptr::addr_of!(sample_probe_misaligned_start) as u64, core::ptr::addr_of!(sample_probe_misaligned_end) as u64, 2),
(core::ptr::addr_of!(sample_probe_deep_start) as u64, core::ptr::addr_of!(sample_probe_deep_end) as u64, 6)].iter().enumerate() {
                if (*start..*end).contains(&ip) {
                    check!(status == *expected || status == 11, "negative stack probe has wrong termination reason");
                    if status == *expected { self.probes[index] += 1; }
                }
            }
        }
        if u32_at(bytes,56) != 2 || length < 3 { return; }
        for (start,end,middle,outer,is_a) in [
            (sample_loop_a as *const () as u64, core::ptr::addr_of!(sample_loop_a_end) as u64,
             core::ptr::addr_of!(sample_middle_a_return) as u64,core::ptr::addr_of!(sample_chain_a_return) as u64,true),
            (sample_loop_b as *const () as u64, core::ptr::addr_of!(sample_loop_b_end) as u64,
             core::ptr::addr_of!(sample_middle_b_return) as u64,core::ptr::addr_of!(sample_chain_b_return) as u64,false),
        ] {
            if (start..end).contains(&ip) && u64_at(bytes,136) == middle && u64_at(bytes,144) == outer {
                if is_a { self.a += 1; } else { self.b += 1; }
            }
        }
    }
    pub fn finish(&self) {
        say!("SAMPLING STACKS user_a={} user_b={} kernel={} partial={} sources={} context=software-stack-v3",
             self.a, self.b, self.kernel, self.partial, self.source_count);
        say!("SAMPLING STACK_PROBES no_fp={} read_fault={} cycle={} bad_ra={} misaligned={} depth_limit={}",
            self.probes[0],self.probes[1],self.probes[2],self.probes[3],self.probes[4],self.probes[5]);
        check!(self.probes.iter().all(|count| *count > 0), "negative stack probe received no diagnostic sample");
        check!(self.a >= 2 && self.b >= 2, "no verified three-frame user chains");
        check!(self.kernel >= 2, "no three-frame kernel chains");
        check!(!cfg!(cpu_clock_test) || self.source_count == 16, "missing parallel CPU source instances");
    }
}

#[cfg(target_arch = "riscv64")]
global_asm!(r#"
.section .text.sample_probes,"ax"
.global sample_probe_zero
sample_probe_zero:
addi sp, sp, -32
sd ra, 24(sp)
sd s0, 16(sp)
li s0, 0
.global sample_probe_zero_start
sample_probe_zero_start:
addi a0, a0, -1
bnez a0, sample_probe_zero_start
.global sample_probe_zero_end
sample_probe_zero_end:
ld ra, 24(sp)
ld s0, 16(sp)
addi sp, sp, 32
ret
.global sample_probe_unmapped
sample_probe_unmapped:
addi sp, sp, -32
sd ra, 24(sp)
sd s0, 16(sp)
mv s0, a1
.global sample_probe_unmapped_start
sample_probe_unmapped_start:
addi a0, a0, -1
bnez a0, sample_probe_unmapped_start
.global sample_probe_unmapped_end
sample_probe_unmapped_end:
ld ra, 24(sp)
ld s0, 16(sp)
addi sp, sp, 32
ret
.global sample_probe_cycle
sample_probe_cycle:
addi sp, sp, -32
sd ra, 24(sp)
sd s0, 16(sp)
addi s0, sp, 16
sd s0, 0(sp)
la t0, sample_probe_cycle
sd t0, 8(sp)
.global sample_probe_cycle_start
sample_probe_cycle_start:
addi a0, a0, -1
bnez a0, sample_probe_cycle_start
.global sample_probe_cycle_end
sample_probe_cycle_end:
ld ra, 24(sp)
ld s0, 16(sp)
addi sp, sp, 32
ret
.global sample_probe_badra
sample_probe_badra:
addi sp, sp, -32
sd ra, 24(sp)
sd s0, 16(sp)
addi s0, sp, 16
sd zero, 0(sp)
sd zero, 8(sp)
.global sample_probe_badra_start
sample_probe_badra_start:
addi a0, a0, -1
bnez a0, sample_probe_badra_start
.global sample_probe_badra_end
sample_probe_badra_end:
ld ra, 24(sp)
ld s0, 16(sp)
addi sp, sp, 32
ret
.global sample_probe_misaligned
sample_probe_misaligned:
addi sp, sp, -32
sd ra, 24(sp)
sd s0, 16(sp)
addi s0, sp, 17
.global sample_probe_misaligned_start
sample_probe_misaligned_start:
addi a0, a0, -1
bnez a0, sample_probe_misaligned_start
.global sample_probe_misaligned_end
sample_probe_misaligned_end:
ld ra, 24(sp)
ld s0, 16(sp)
addi sp, sp, 32
ret
.global sample_probe_deep
sample_probe_deep:
addi sp, sp, -16
sd ra, 8(sp)
sd s0, 0(sp)
addi s0, sp, 16
beqz a1, sample_probe_deep_start
addi a1, a1, -1
call sample_probe_deep
j 9f
.global sample_probe_deep_start
sample_probe_deep_start:
addi a0, a0, -1
bnez a0, sample_probe_deep_start
.global sample_probe_deep_end
sample_probe_deep_end:
9:
ld ra, 8(sp)
ld s0, 0(sp)
addi sp, sp, 16
ret
"#);

#[cfg(target_arch = "loongarch64")]
global_asm!(r#"
.section .text.sample_probes,"ax"
.global sample_probe_zero
sample_probe_zero:
addi.d $sp, $sp, -32
st.d $ra, $sp, 24
st.d $fp, $sp, 16
move $fp, $zero
.global sample_probe_zero_start
sample_probe_zero_start:
addi.d $a0, $a0, -1
bnez $a0, sample_probe_zero_start
.global sample_probe_zero_end
sample_probe_zero_end:
ld.d $ra, $sp, 24
ld.d $fp, $sp, 16
addi.d $sp, $sp, 32
jr $ra
.global sample_probe_unmapped
sample_probe_unmapped:
addi.d $sp, $sp, -32
st.d $ra, $sp, 24
st.d $fp, $sp, 16
move $fp, $a1
.global sample_probe_unmapped_start
sample_probe_unmapped_start:
addi.d $a0, $a0, -1
bnez $a0, sample_probe_unmapped_start
.global sample_probe_unmapped_end
sample_probe_unmapped_end:
ld.d $ra, $sp, 24
ld.d $fp, $sp, 16
addi.d $sp, $sp, 32
jr $ra
.global sample_probe_cycle
sample_probe_cycle:
addi.d $sp, $sp, -32
st.d $ra, $sp, 24
st.d $fp, $sp, 16
addi.d $fp, $sp, 16
st.d $fp, $sp, 0
la.local $t0, sample_probe_cycle
st.d $t0, $sp, 8
.global sample_probe_cycle_start
sample_probe_cycle_start:
addi.d $a0, $a0, -1
bnez $a0, sample_probe_cycle_start
.global sample_probe_cycle_end
sample_probe_cycle_end:
ld.d $ra, $sp, 24
ld.d $fp, $sp, 16
addi.d $sp, $sp, 32
jr $ra
.global sample_probe_badra
sample_probe_badra:
addi.d $sp, $sp, -32
st.d $ra, $sp, 24
st.d $fp, $sp, 16
addi.d $fp, $sp, 16
st.d $zero, $sp, 0
st.d $zero, $sp, 8
.global sample_probe_badra_start
sample_probe_badra_start:
addi.d $a0, $a0, -1
bnez $a0, sample_probe_badra_start
.global sample_probe_badra_end
sample_probe_badra_end:
ld.d $ra, $sp, 24
ld.d $fp, $sp, 16
addi.d $sp, $sp, 32
jr $ra
.global sample_probe_misaligned
sample_probe_misaligned:
addi.d $sp, $sp, -32
st.d $ra, $sp, 24
st.d $fp, $sp, 16
addi.d $fp, $sp, 17
.global sample_probe_misaligned_start
sample_probe_misaligned_start:
addi.d $a0, $a0, -1
bnez $a0, sample_probe_misaligned_start
.global sample_probe_misaligned_end
sample_probe_misaligned_end:
ld.d $ra, $sp, 24
ld.d $fp, $sp, 16
addi.d $sp, $sp, 32
jr $ra
.global sample_probe_deep
sample_probe_deep:
addi.d $sp, $sp, -16
st.d $ra, $sp, 8
st.d $fp, $sp, 0
addi.d $fp, $sp, 16
beqz $a1, sample_probe_deep_start
addi.d $a1, $a1, -1
bl sample_probe_deep
b 9f
.global sample_probe_deep_start
sample_probe_deep_start:
addi.d $a0, $a0, -1
bnez $a0, sample_probe_deep_start
.global sample_probe_deep_end
sample_probe_deep_end:
9:
ld.d $ra, $sp, 8
ld.d $fp, $sp, 0
addi.d $sp, $sp, 16
jr $ra
"#);

unsafe extern "C" {
fn sample_probe_zero(iterations:usize,fp_or_depth:usize);
static sample_probe_zero_start:u8;
static sample_probe_zero_end:u8;
fn sample_probe_unmapped(iterations:usize,fp_or_depth:usize);
static sample_probe_unmapped_start:u8;
static sample_probe_unmapped_end:u8;
fn sample_probe_cycle(iterations:usize,fp_or_depth:usize);
static sample_probe_cycle_start:u8;
static sample_probe_cycle_end:u8;
fn sample_probe_badra(iterations:usize,fp_or_depth:usize);
static sample_probe_badra_start:u8;
static sample_probe_badra_end:u8;
fn sample_probe_misaligned(iterations:usize,fp_or_depth:usize);
static sample_probe_misaligned_start:u8;
static sample_probe_misaligned_end:u8;
fn sample_probe_deep(iterations:usize,fp_or_depth:usize);
static sample_probe_deep_start:u8;
static sample_probe_deep_end:u8;
}
