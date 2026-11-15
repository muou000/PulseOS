//! Real timer-driven BPF sampling regression (#190), without capture synthesis.
//! Deployment: one thread, RV64/LA64 Linux-shaped syscall ABI, eight online CPUs.
//! Only actual PERF_SAMPLE_RAW bytes from BPF_OUTPUT mmap rings count as evidence.
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

const CPUS: usize = 8;
const PAGE: usize = 4096;
#[cfg(perf_ring_one_page)]
const DATA_SIZE: usize = PAGE;
#[cfg(not(perf_ring_one_page))]
const DATA_SIZE: usize = 16 * PAGE;
const MAPPING_SIZE: usize = PAGE + DATA_SIZE;
const PERIOD_NS: u64 = 10_000_000;
#[cfg(all(not(tracepoint_test), not(stack_test)))]
const CONTEXT_SIZE: usize = 64;
#[cfg(stack_test)]
const CONTEXT_SIZE: usize = 640;
#[cfg(all(tracepoint_test, not(any(trace_wake, sched_trace_test, trace_fault))))]
const CONTEXT_SIZE: usize = 72;
#[cfg(any(trace_wake, sched_trace_test, trace_fault))]
const CONTEXT_SIZE: usize = 80;
#[cfg(all(tracepoint_test, not(any(trace_block, trace_wake, sched_trace_test, trace_fault))))]
const MODE: &str = "trace";
#[cfg(trace_fault)]
const MODE: &str = "fault";
#[cfg(sched_trace_test)]
const MODE: &str = "sched";
#[cfg(trace_block)]
const MODE: &str = "block";
#[cfg(trace_wake)]
const MODE: &str = "wake";
#[cfg(tracepoint_test)]
const TRACE_EVENT_ID: u32 = if cfg!(trace_fault) { 8 } else if cfg!(trace_block) { 3 } else if cfg!(trace_wake) { 4 } else { 2 };
#[cfg(tracepoint_test)]
const TRACE_MARKER: &str = if cfg!(trace_fault) { "FAULT" } else if cfg!(sched_trace_test) { "SCHED" } else if cfg!(trace_block) { "BLOCK" } else if cfg!(trace_wake) { "WAKE" } else { "TRACE" };
#[cfg(tracepoint_test)]
const TRACE_COUNT: &str = if cfg!(trace_fault) { "faults" } else if cfg!(sched_trace_test) { "events" } else if cfg!(trace_block) { "blocks" } else if cfg!(trace_wake) { "wakes" } else { "sched" };
#[cfg(cpu_clock_test)]
const MODE: &str = "cpu";
#[cfg(not(any(cpu_clock_test, tracepoint_test)))]
const MODE: &str = "task";
const PROGRAM_COUNT: usize = if cfg!(sched_trace_test) { 6 } else { 1 };
const SOURCE_COUNT: usize = if cfg!(cpu_clock_test) && cfg!(stack_test) { CPUS * 2 } else if cfg!(tracepoint_test) || cfg!(cpu_clock_test) { CPUS * PROGRAM_COUNT } else { 1 };
#[cfg(tracepoint_test)]
fn context_bytes(event: u32) -> usize {
    match event { 1|2|3=>72, 4|8=>80, 5=>56, 6=>64, _=>0 }
}
#[cfg(tracepoint_test)]
fn tracepoint_for_program(index: usize) -> u32 {
    if cfg!(sched_trace_test) { index as u32 + 1 } else { TRACE_EVENT_ID }
}
const ENABLE: usize = 0x2400;
const DISABLE: usize = 0x2401;

#[cfg(all(target_arch = "riscv64", not(stack_test)))]
global_asm!(
    ".section .text._start,\"ax\"", ".global _start", "_start:",
    ".option push", ".option norelax", "la gp, __global_pointer$", ".option pop",
    "call guest_main", "unimp",
    ".section .text.sample_loops,\"ax\"", ".balign 16",
    ".global sample_loop_a", ".global sample_loop_a_end", "sample_loop_a:",
    "addi a0, a0, -1", "bnez a0, sample_loop_a", "ret", "sample_loop_a_end:",
    ".balign 16", ".global sample_loop_b", ".global sample_loop_b_end", "sample_loop_b:",
    "addi a0, a0, -1", "nop", "bnez a0, sample_loop_b", "ret", "sample_loop_b_end:",
);
#[cfg(all(target_arch = "loongarch64", not(stack_test)))]
global_asm!(
    ".section .text._start,\"ax\"", ".global _start", "_start:", "bl guest_main", "break 0",
    ".section .text.sample_loops,\"ax\"", ".balign 16",
    ".global sample_loop_a", ".global sample_loop_a_end", "sample_loop_a:",
    "addi.d $a0, $a0, -1", "bnez $a0, sample_loop_a", "jr $ra", "sample_loop_a_end:",
    ".balign 16", ".global sample_loop_b", ".global sample_loop_b_end", "sample_loop_b:",
    "addi.d $a0, $a0, -1", "nop", "bnez $a0, sample_loop_b", "jr $ra", "sample_loop_b_end:",
);
unsafe extern "C" {
    fn sample_loop_a(iterations: usize);
    fn sample_loop_b(iterations: usize);
    static sample_loop_a_end: u8;
    static sample_loop_b_end: u8;
}

#[inline(always)]
fn syscall(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let result: isize;
    // SAFETY: these guest-only instructions obey the documented RV64/LA64 Linux
    // syscall register ABI. Each wrapper below retains its input/output buffers
    // across the synchronous call; no nomem/pure claim hides kernel memory access.
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
            let result = syscall(64, 1, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0);
            if result == -4 { continue; }
            if result <= 0 || result as usize > bytes.len() { return Err(fmt::Error); }
            bytes = &bytes[result as usize..];
        }
        Ok(())
    }
}
macro_rules! say { ($($arg:tt)*) => {{ let _ = writeln!(Console, $($arg)*); }}; }
macro_rules! check {
    ($condition:expr, $message:expr) => {
        if !$condition { say!("SAMPLING FAIL line={} {}", line!(), $message); exit(1); }
    };
}
#[cfg(stack_test)]
mod stack_workload;
#[cfg(stack_test)]
use stack_workload::*;
#[cfg(capture_export)]
mod archive;
#[cfg(trace_fault)]
mod fault_workload;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! { say!("SAMPLING FAIL panic {}", info); exit(1) }
fn ok(name: &str, value: isize) -> usize {
    if value < 0 { say!("SAMPLING FAIL syscall={} errno={}", name, value); exit(1); }
    value as usize
}
fn put32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}
fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn bpf(command: usize, attr: &[u8]) -> isize {
    syscall(280, command, attr.as_ptr() as usize, attr.len(), 0, 0, 0)
}
fn create_map(kind: u32, value_size: u32) -> usize {
    let mut attr = [0u8; 72];
    put32(&mut attr, 0, kind);
    put32(&mut attr, 4, 4);
    put32(&mut attr, 8, value_size);
    put32(&mut attr, 12, CPUS as u32);
    ok("map_create", bpf(0, &attr))
}
fn update_sink(map: usize, cpu: u32, sink: usize) -> isize {
    let value = sink as u32;
    let mut attr = [0u8; 32];
    put32(&mut attr, 0, map as u32);
    put64(&mut attr, 8, &cpu as *const u32 as u64);
    put64(&mut attr, 16, &value as *const u32 as u64);
    bpf(2, &attr)
}
fn bind_sink(map: usize, cpu: u32, sink: usize) {
    check!(update_sink(map, cpu, sink) == 0, "map output sink update");
}
fn reject_invalid_sinks(map: usize, source: usize, sinks: &[usize; CPUS]) {
    let source_result = update_sink(map, 0, source);
    let cpu_result = update_sink(map, 0, sinks[1]);
    check!(source_result == -22, "sampling source accepted as output sink");
    check!(cpu_result == -22, "wrong-CPU output sink accepted");
    let key = 0u32;
    let mut value = u32::MAX;
    let mut attr = [0u8; 32];
    put32(&mut attr, 0, map as u32);
    put64(&mut attr, 8, &key as *const u32 as u64);
    put64(&mut attr, 16, &mut value as *mut u32 as u64);
    check!(bpf(1, &attr) == 0 && value == sinks[0] as u32, "rejected update changed existing sink");
    say!("SAMPLING SINK_REJECT mode={} source_errno={} cpu_errno={} preserved=1",
         MODE, source_result, cpu_result);
}
fn perf_open(config: u64, pid: isize, cpu: isize, period: u64, disabled: bool) -> usize {
    let mut attr = [0u8; 64];
    put32(&mut attr, 0, if cfg!(tracepoint_test) && config != 10 { 2 } else { 1 }); // trace source vs SOFTWARE BPF_OUTPUT
    put32(&mut attr, 4, 64);
    put64(&mut attr, 8, config);
    put64(&mut attr, 16, period);
    put64(&mut attr, 24, 1 << 10); // PERF_SAMPLE_RAW
    put64(&mut attr, 40, u64::from(disabled));
    ok("perf_event_open", syscall(241, attr.as_ptr() as usize, pid as usize,
                                  cpu as usize, usize::MAX, 8, 0))
}
fn ioctl(fd: usize, request: usize) {
    check!(syscall(29, fd, request, 0, 0, 0, 0) == 0, "perf ioctl");
}
fn close(fd: usize) { check!(syscall(57, fd, 0, 0, 0, 0, 0) == 0, "close"); }
#[cfg(not(any(cpu_clock_test, tracepoint_test)))]
fn read_counter(fd: usize) -> u64 {
    let mut value = 0u64;
    check!(syscall(63, fd, &mut value as *mut u64 as usize, 8, 0, 0, 0) == 8, "read task clock counter");
    value
}
#[cfg(not(any(cpu_clock_test, tracepoint_test)))]
fn check_task_sleep(fd: usize) {
    let before = read_counter(fd);
    let start = monotonic_ns();
    sleep_ms(100);
    let wall = monotonic_ns() - start;
    let after = read_counter(fd);
    say!("SAMPLING TASK_SLEEP before_ns={} after_ns={} wall_ns={}", before, after, wall);
    check!(wall >= 80_000_000, "sleep did not establish a blocking interval");
    check!(after >= before, "task clock regressed");
    // Allow bounded syscall/scheduling overhead, but a wall-clock-based counter
    // increases by the entire sleeping interval and decisively fails this bound.
    check!(after - before <= wall / 5 + 2_000_000, "task clock counted sleeping time");
}
fn monotonic_ns() -> u64 {
    let mut time = [0i64; 2];
    check!(syscall(113, 1, time.as_mut_ptr() as usize, 0, 0, 0, 0) == 0, "clock_gettime");
    check!(time[0] >= 0 && (0..1_000_000_000).contains(&time[1]), "monotonic time invalid");
    time[0] as u64 * 1_000_000_000 + time[1] as u64
}
fn sleep_ms(ms: u64) {
    let time = [0i64, (ms * 1_000_000) as i64];
    let result = syscall(101, time.as_ptr() as usize, 0, 0, 0, 0, 0);
    check!(result == 0 || result == -4, "nanosleep");
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Insn { code: u8, regs: u8, off: i16, imm: i32 }
impl Insn {
    const fn new(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> Self {
        Self { code, regs: dst | src << 4, off, imm }
    }
}
struct Program { insns: [Insn; 192], len: usize }
impl Program {
    fn emit(&mut self, code: u8, dst: u8, src: u8, off: i16, imm: i32) {
        self.insns[self.len] = Insn::new(code, dst, src, off, imm);
        self.len += 1;
    }
    fn map(&mut self, reg: u8, fd: usize) {
        self.emit(0x18, reg, 1, 0, fd as i32);
        self.emit(0, 0, 0, 0, 0);
    }
}
fn load_program(scratch: usize, outputs: usize, context_size: usize) -> usize {
    let mut program = Program { insns: [Insn::new(0, 0, 0, 0, 0); 192], len: 0 };
    program.emit(0xbf, 6, 1, 0, 0); // save ctx
    program.emit(0x61, 2, 6, if cfg!(tracepoint_test) { 16 } else { 24 }, 0); // key = ctx.cpu
    program.emit(0x63, 10, 2, -4, 0);
    program.map(1, scratch);
    program.emit(0xbf, 2, 10, 0, 0);
    program.emit(0x07, 2, 0, 0, -4);
    program.emit(0x85, 0, 0, 0, 1); // map_lookup_elem
    let null_jump = program.len;
    program.emit(0x15, 0, 0, 0, 0); // null -> return 0
    program.emit(0xbf, 7, 0, 0, 0);
    for offset in (0..context_size).step_by(8) {
        program.emit(0x79, 8, 6, offset as i16, 0);
        program.emit(0x7b, 7, 8, offset as i16, 0);
    }
    program.emit(0xbf, 1, 6, 0, 0);
    program.map(2, outputs);
    // A 64-bit immediate with high half zero is BPF_F_CURRENT_CPU, not -1_u64.
    program.emit(0x18, 3, 0, 0, -1);
    program.emit(0, 0, 0, 0, 0);
    program.emit(0xbf, 4, 7, 0, 0);
    program.emit(0xb7, 5, 0, 0, context_size as i32);
    program.emit(0x85, 0, 0, 0, 25); // perf_event_output
    let return_index = program.len;
    program.emit(0xb7, 0, 0, 0, 0);
    program.emit(0x95, 0, 0, 0, 0);
    program.insns[null_jump].off = (return_index - null_jump - 1) as i16;
    let mut attr = [0u8; 144];
    let mut log = [0u8; 2048];
    put32(&mut attr, 0, if cfg!(tracepoint_test) { 5 } else { 7 }); // TRACEPOINT / PERF_EVENT
    put32(&mut attr, 4, program.len as u32);
    put64(&mut attr, 8, program.insns.as_ptr() as u64);
    put64(&mut attr, 16, c"GPL".as_ptr() as u64);
    put32(&mut attr, 24, 1);
    put32(&mut attr, 28, log.len() as u32);
    put64(&mut attr, 32, log.as_mut_ptr() as u64);
    let fd = bpf(5, &attr);
    if fd < 0 {
        let len = log.iter().position(|b| *b == 0).unwrap_or(log.len());
        say!("SAMPLING verifier {}", core::str::from_utf8(&log[..len]).unwrap_or("invalid utf8"));
    }
    ok(if cfg!(tracepoint_test) { "BPF_PROG_LOAD_trace_context_v1" } else { "BPF_PROG_LOAD_context_v2" }, fd)
}
fn attach(program: usize, event: usize) -> usize {
    let mut attr = [0u8; 64];
    put32(&mut attr, 0, program as u32);
    put32(&mut attr, 4, event as u32);
    put32(&mut attr, 8, 41);
    ok("BPF_LINK_CREATE", bpf(28, &attr))
}
fn detach(link: usize) {
    let attr = (link as u32).to_le_bytes();
    check!(bpf(34, &attr) == 0, "BPF_LINK_DETACH");
}

struct Ring { base: usize, cpu: usize, tail: u64, wraps: u64 }
impl Ring {
    fn map(fd: usize, cpu: usize) -> Self {
        let base = ok("mmap", syscall(222, 0, MAPPING_SIZE, 3, 1, fd, 0));
        check!(base != 0 && base % PAGE == 0, "ring mapping alignment");
        Self { base, cpu, tail: 0, wraps: 0 }
    }
    fn head(&self) -> u64 {
        // SAFETY: base owns a live page-aligned shared mapping until unmap().
        // The perf ABI's u64 head is initialized at aligned offset 1024 and is
        // updated atomically by the kernel. Acquire observes published records.
        unsafe { AtomicU64::from_ptr((self.base + 1024) as *mut u64).load(Ordering::Acquire) }
    }
    fn publish_tail(&self) {
        // SAFETY: same live aligned mapping as head(); this sole consumer writes
        // tail at offset 1032 only after copying all bytes it has consumed.
        unsafe { AtomicU64::from_ptr((self.base + 1032) as *mut u64).store(self.tail, Ordering::Release) }
    }
    fn copy(&self, absolute: u64, out: &mut [u8]) {
        check!(out.len() <= DATA_SIZE, "record copy exceeds ring");
        for (i, byte) in out.iter_mut().enumerate() {
            let offset = (absolute.wrapping_add(i as u64) as usize) & (DATA_SIZE - 1);
            // SAFETY: caller has acquired head and checked the full record lies
            // within [tail,head); no producer may reuse those bytes until tail
            // is released. Mask handles wrap; only initialized published bytes
            // inside the still-live mmap are read. No long-lived references.
            *byte = unsafe { core::ptr::read_volatile((self.base + PAGE + offset) as *const u8) };
        }
    }
    fn drain(&mut self, stats: &mut Stats) {
        #[cfg(fault_zero_consumer)]
        if stats.archive.is_some() { return; }
        let head = self.head();
        check!(head.wrapping_sub(self.tail) <= DATA_SIZE as u64, "producer overran unread ring");
        while self.tail != head {
            let available = head.wrapping_sub(self.tail);
            check!(available >= 8, "truncated perf header");
            let mut header = [0u8; 8];
            self.copy(self.tail, &mut header);
            let size = u16::from_le_bytes([header[6], header[7]]) as usize;
            check!(size >= 8 && size % 8 == 0 && size <= DATA_SIZE && size as u64 <= available, "bad perf record length");
            match u32_at(&header, 0) {
                9 => {
                    let mut raw = [0u8; 4 + CONTEXT_SIZE];
                    self.copy(self.tail + 8, &mut raw[..4]);
                    let length = u32_at(&raw, 0) as usize;
                    check!((40..=CONTEXT_SIZE).contains(&length) && size == ((12 + length + 7) & !7), "invalid perf sample boundary");
                    self.copy(self.tail + 12, &mut raw[4..4+length]);
                    stats.sample(&raw[4..4+length], self.cpu);
                }
                2 => {
                    check!(size == 24, "invalid lost record boundary");
                    let mut lost = [0u8; 16];
                    self.copy(self.tail + 8, &mut lost);
                    stats.lost += u64_at(&lost, 8);
                }
                _ => check!(false, "unknown perf record type"),
            }
            #[cfg(capture_export)]
            if let Some(archive) = &mut stats.archive {
                let mut raw = [0u8; (12 + CONTEXT_SIZE + 7) & !7];
                check!(size <= raw.len(), "archive frame exceeds supported context");
                self.copy(self.tail, &mut raw[..size]);
                archive.push(self.cpu, &raw[..size]);
            }
            if (self.tail as usize & (DATA_SIZE - 1)) + size > DATA_SIZE {
                self.wraps += 1;
            }
            self.tail = self.tail.wrapping_add(size as u64);
            self.publish_tail();
        }
    }
    fn unmap(self) {
        check!(syscall(215, self.base, MAPPING_SIZE, 0, 0, 0, 0) == 0, "munmap");
    }
}
#[cfg_attr(not(capture_export), derive(Clone, Copy))]
struct Stats {
    #[cfg(capture_export)]
    archive: Option<archive::Buffer>,
    pid: u32, tid: u32, samples: u64, foreign: u64, a: u64, b: u64, lost: u64, cpu_mask: u32,
    #[cfg(stack_test)]
    stacks: stack_workload::StackStats,
    last_time: [u64; CPUS], a_start: u64, a_end: u64, b_start: u64, b_end: u64,
    #[cfg(tracepoint_test)]
    subjects: [u64; 64],
    #[cfg(tracepoint_test)]
    subject_count: usize,
    #[cfg(tracepoint_test)]
    subject_overflow: bool,
    #[cfg(tracepoint_test)]
    target_contexts: u64,
    #[cfg(tracepoint_test)]
    event_counts: [u64; 9],
    #[cfg(trace_fault)]
    fault_targets: [(usize,usize);128],
    #[cfg(trace_fault)]
    fault_target_count: usize,
    #[cfg(trace_fault)]
    fault_read_hits: u64,
    #[cfg(trace_fault)]
    fault_write_hits: u64,
}
impl Stats {
    #[cfg(tracepoint_test)]
    fn add_subject(&mut self, task_id: u64) {
        if self.subjects[..self.subject_count].contains(&task_id) { return; }
        if self.subject_count == self.subjects.len() {
            self.subject_overflow = true;
        } else {
            self.subjects[self.subject_count] = task_id;
            self.subject_count += 1;
        }
    }
    #[cfg(tracepoint_test)]
    fn sample(&mut self, bytes: &[u8], ring_cpu: usize) {
        let event = u32_at(bytes, 0);
        check!((if cfg!(sched_trace_test) {(1..=6).contains(&event)} else {event == TRACE_EVENT_ID}) && u32_at(bytes, 4) == 1, "wrong trace event/version");
        check!(bytes.len() == context_bytes(event), "wrong trace context length");
        let timestamp = u64_at(bytes, 8);
        let cpu = u32_at(bytes, 16) as usize;
        check!(cpu == ring_cpu && cpu < CPUS, "trace CPU disagrees with output ring");
        check!(timestamp != 0 && timestamp >= self.last_time[cpu], "trace timestamp invalid");
        check!(u32_at(bytes, 28) == 0, "trace common reserved field nonzero");
        match event {
            1 => { let task=u64_at(bytes,40); check!(task!=0,"metadata lacks target task"); self.add_subject(task); }
            2 => {
                let previous=u64_at(bytes,40); let next=u64_at(bytes,48);
                check!(previous!=0 && next!=0 && previous!=next,"sched_switch lacks distinct task subjects");
                check!(u64_at(bytes,32)==previous,"sched_switch origin differs from previous task");
                check!(u32_at(bytes,68)==0,"sched_switch reserved field nonzero");
                self.add_subject(previous);self.add_subject(next);
            }
            3 => {
                let task=u64_at(bytes,32);
                check!(task!=0 && u64_at(bytes,40)!=0,"block lacks task identity or sequence");
                check!(u32_at(bytes,48)!=0 && u32_at(bytes,52)==0,"block reason/reserved invalid");
                self.add_subject(task);
            }
            4 => {
                let target=u64_at(bytes,40);let waker=u64_at(bytes,56);
                check!(target!=0 && u64_at(bytes,48)!=0,"wake lacks target or sequence");
                check!(u64_at(bytes,32)==waker,"wake origin differs from recorded waker");
                check!(u32_at(bytes,64)<=7 && u32_at(bytes,68)==0,"wake source/reserved invalid");
                self.add_subject(target);if waker!=0 {self.add_subject(waker);}
            }
            5|6 => {let task=u64_at(bytes,40);check!(task!=0,"lifecycle event lacks task");self.add_subject(task);}
            8 => {
                let start=u64_at(bytes,48);let elapsed=u64_at(bytes,56);
                let access=u32_at(bytes,64);let origin=u32_at(bytes,68);let outcome=u32_at(bytes,72);
                check!(timestamp.checked_sub(start)==Some(elapsed),"fault clock/duration mismatch");
                check!(access & !7==0 && (origin==1 || origin==2),"fault access/origin invalid");
                check!((1..=4).contains(&outcome) && u32_at(bytes,76)==0,"fault outcome/classification invalid");
                let task=u64_at(bytes,32);check!(task!=0,"fault lacks originating task");self.add_subject(task);
                #[cfg(trace_fault)]
                if origin==2 && u32_at(bytes,20)==self.pid && u32_at(bytes,24)==self.tid {
                    let addr=u64_at(bytes,40) as usize;
                    if self.fault_targets[..self.fault_target_count].iter().any(|pair|pair.0==addr) && access&1!=0 {self.fault_read_hits+=1;check!(outcome==1,"fresh read resolver failed");}
                    if self.fault_targets[..self.fault_target_count].iter().any(|pair|pair.1==addr) && access&2!=0 {self.fault_write_hits+=1;check!(outcome==1,"fresh write resolver failed");}
                }
            }
            _ => check!(false,"unsupported tracepoint"),
        }
        self.event_counts[event as usize] += 1;
        self.last_time[cpu] = timestamp;
        self.cpu_mask |= 1 << cpu;
        self.samples += 1;
        if u32_at(bytes, 20) == self.pid && u32_at(bytes, 24) == self.tid {
            self.target_contexts += 1;
        }
    }
    #[cfg(not(tracepoint_test))]
    fn sample(&mut self, bytes: &[u8], ring_cpu: usize) {
        check!(bytes.len() == CONTEXT_SIZE, "wrong software context length");
        let timestamp = u64_at(bytes, 16);
        let cpu = u32_at(bytes, 24) as usize;
        let ip = u64_at(bytes, 48);
        let mode = u32_at(bytes, 56);
        check!(u32_at(bytes, 60) == 2, "sample context version must be 2");
        check!(cpu == ring_cpu && cpu < CPUS, "sample CPU disagrees with output ring");
        check!(u64_at(bytes, 40) != 0, "sample lacks task identity");
        check!((u64_at(bytes, 0) == PERIOD_NS || (cfg!(stack_test) && cfg!(cpu_clock_test) && u64_at(bytes, 0) == 2 * PERIOD_NS)) && u64_at(bytes, 8) == 0, "period or legacy addr changed");
        check!(timestamp != 0 && timestamp >= self.last_time[cpu], "sample timestamp invalid");
        check!(ip != 0 && (mode == 1 || mode == 2), "missing PC or privilege mode");
        #[cfg(stack_test)]
        self.stacks.observe(bytes);
        self.last_time[cpu] = timestamp;
        self.cpu_mask |= 1 << cpu;
        if u32_at(bytes, 28) != self.pid || u32_at(bytes, 32) != self.tid {
            check!(cfg!(cpu_clock_test), "task-clock sample target identity mismatch");
            self.foreign += 1;
            return;
        }
        self.samples += 1;
        if (self.a_start..self.a_end).contains(&ip) {
            check!(mode == 2, "user loop A attributed as kernel"); self.a += 1;
        }
        if (self.b_start..self.b_end).contains(&ip) {
            check!(mode == 2, "user loop B attributed as kernel"); self.b += 1;
        }
    }
}
fn drain_all(rings: &mut [Ring; CPUS], stats: &mut Stats) {
    for ring in rings { ring.drain(stats); }
}
fn workload(loop_b: bool, duration_ms: u64, rings: &mut [Ring; CPUS], stats: &mut Stats) {
    let deadline = monotonic_ns() + duration_ms * 1_000_000;
    while monotonic_ns() < deadline {
        #[cfg(all(tracepoint_test, not(trace_fault)))]
        {
            check!(syscall(124, 0, 0, 0, 0, 0, 0) == 0, "sched_yield");
            sleep_ms(if loop_b { 2 } else { 1 });
        }
        #[cfg(trace_fault)]
        { let _ = fault_workload::iteration(); }
        #[cfg(not(tracepoint_test))]
        // SAFETY: the linked loops and chain entries preserve the target C ABI
        // and terminate for n>0. Stack entries save and restore FP/RA within
        // their own frames; the ordinary loops only modify argument a0.
        unsafe {
            #[cfg(not(stack_test))]
            if loop_b { sample_loop_b(2_000_000); } else { sample_loop_a(2_000_000); }
            #[cfg(stack_test)]
            { if loop_b { sample_chain_b(2_000_000); } else { sample_chain_a(2_000_000); } }
        }
        drain_all(rings, stats);
    }
}
#[cfg(capture_export)]
fn measure_archive_phase(phase: &str, mut rings: Option<&mut [Ring; CPUS]>, stats: &mut Stats, extra_mapped_bytes: usize) {
    let start = monotonic_ns();
    let mut iterations = 0u64;
    for _ in 0..128 {
        #[cfg(all(tracepoint_test, not(trace_fault)))]
        {
            check!(syscall(124, 0, 0, 0, 0, 0, 0) == 0, "phase sched_yield");
            sleep_ms(1);
        }
        #[cfg(trace_fault)]
        {
            let targets=fault_workload::iteration();
            if phase=="attached_capture" {
                check!(stats.fault_target_count<stats.fault_targets.len(),"fault target bound");
                stats.fault_targets[stats.fault_target_count]=targets;stats.fault_target_count+=1;
            }
        }
        #[cfg(not(tracepoint_test))]
        // SAFETY: linked loops/chains preserve the C ABI; chain entries only
        // access their own initialized frame records and restore SP/FP/RA.
        unsafe {
            #[cfg(not(stack_test))]
            { sample_loop_a(2_000_000); sample_loop_b(2_000_000); }
            #[cfg(stack_test)]
            { sample_chain_a(2_000_000); sample_chain_b(2_000_000); stack_workload::kernel_work(); stack_workload::probes(); }
        }
        if !(cfg!(fault_ring_overflow) && phase == "attached_capture") {
        if let Some(rings) = rings.as_deref_mut() { drain_all(rings, stats); }
        }
        iterations += 1;
    }
    let stop = monotonic_ns();
    say!("ARCHIVE MEASURE phase={} start_ns={} stop_ns={} wall_ns={} iterations={} extra_mapped_bytes={} memory_scope=sampler_mappings",
         phase, start, stop, stop - start, iterations, extra_mapped_bytes);
}

fn settle(rings: &mut [Ring; CPUS], stats: &mut Stats) {
    // Bounded grace for records already queued at disable/detach. The later
    // workload still tests that the stopped event produces no further output.
    for _ in 0..10 { sleep_ms(10); drain_all(rings, stats); }
}

#[cfg(not(any(cpu_clock_test, tracepoint_test)))]
fn check_fd_lifecycle(program: usize, rings: &mut [Ring; CPUS], template: &Stats) {
    for ioctl_owned in [false, true] {
        // Independent observed counters for these extra sessions. Ring tails
        // remain shared with the original consumer, so no record is replayed.
        let mut stats = Stats {
            #[cfg(capture_export)]
            archive: None,
            samples: 0, foreign: 0, a: 0, b: 0, lost: 0, cpu_mask: 0,
            last_time: [0; CPUS], ..*template
        };
        let source = perf_open(1, template.tid as isize, -1, PERIOD_NS, true);
        let owner = if ioctl_owned {
            check!(syscall(29, source, 0x40042408, program, 0, 0, 0) == 0, "PERF_EVENT_IOC_SET_BPF");
            ok("dup", syscall(23, source, 0, 0, 0, 0, 0))
        } else {
            attach(program, source)
        };
        ioctl(source, ENABLE);
        // In the Link case the link is the only owner left; in the ioctl case
        // a dup of the event FD must retain the same live event after this close.
        close(source);
        workload(false, 250, rings, &mut stats);
        drain_all(rings, &mut stats);
        let alive = stats.samples;
        let loop_a = stats.a;
        say!("SAMPLING FD_LIFECYCLE_ALIVE kind={} alive={} loop_a={}",
             if ioctl_owned { "ioctl_dup_final_close" } else { "link_target_close" }, alive, loop_a);
        check!(loop_a >= 2 && alive >= loop_a, "closing original source FD stopped retained sampling");
        if !ioctl_owned { detach(owner); }
        // Last ioctl-attached event FD closes here without DISABLE. The source
        // must retire and stop producing; a hidden output-map cycle would fail.
        close(owner);
        settle(rings, &mut stats);
        let settled = stats.samples;
        workload(true, 150, rings, &mut stats);
        settle(rings, &mut stats);
        check!(stats.samples == settled, "closed source still produced samples");
        check!(stats.lost == 0, "FD lifecycle sample loss");
        say!("SAMPLING FD_LIFECYCLE kind={} alive={} loop_a={} settled={} after_stop={} lost={}",
             if ioctl_owned { "ioctl_dup_final_close" } else { "link_target_close" },
             alive, loop_a, settled, stats.samples, stats.lost);
    }
}

#[unsafe(no_mangle)]
extern "C" fn guest_main() -> ! {
    let pid = ok("getpid", syscall(172, 0, 0, 0, 0, 0, 0)) as u32;
    let tid = ok("gettid", syscall(178, 0, 0, 0, 0, 0, 0)) as u32;
    say!("SAMPLING START version=2 mode={} cpus={} pid={} tid={}", MODE, CPUS, pid, tid);
    let mut stats = Stats {
        #[cfg(capture_export)]
        archive: None,
        #[cfg(stack_test)]
        stacks: stack_workload::StackStats::new(),
        pid, tid, samples: 0, foreign: 0, a: 0, b: 0, lost: 0, cpu_mask: 0, last_time: [0; CPUS],
        a_start: sample_loop_a as *const () as u64,
        a_end: core::ptr::addr_of!(sample_loop_a_end) as u64,
        b_start: sample_loop_b as *const () as u64,
        b_end: core::ptr::addr_of!(sample_loop_b_end) as u64,
        #[cfg(tracepoint_test)]
        subjects: [0; 64],
        #[cfg(tracepoint_test)]
        subject_count: 0,
        #[cfg(tracepoint_test)]
        subject_overflow: false,
        #[cfg(tracepoint_test)]
        target_contexts: 0,
        #[cfg(tracepoint_test)]
        event_counts: [0;9],
        #[cfg(trace_fault)]
        fault_targets: [(0,0);128],
        #[cfg(trace_fault)]
        fault_target_count: 0,
        #[cfg(trace_fault)]
        fault_read_hits: 0,
        #[cfg(trace_fault)]
        fault_write_hits: 0,
    };
    say!("SAMPLING RANGES a={:#x}..{:#x} b={:#x}..{:#x}", stats.a_start, stats.a_end, stats.b_start, stats.b_end);
    check!(stats.a_start < stats.a_end && stats.a_end <= stats.b_start && stats.b_start < stats.b_end, "bad assembly symbol ranges");
    #[cfg(capture_export)]
    measure_archive_phase("baseline", None, &mut stats, 0);
    let outputs = create_map(4, 4);
    let scratch = create_map(2, CONTEXT_SIZE as u32);
    let mut sinks = [0usize; CPUS];
    let mut rings = core::array::from_fn(|cpu| {
        let sink = perf_open(10, -1, cpu as isize, 0, true);
        sinks[cpu] = sink;
        let ring = Ring::map(sink, cpu);
        bind_sink(outputs, cpu as u32, sink);
        ioctl(sink, ENABLE);
        ring
    });
    let programs: [usize; PROGRAM_COUNT] = core::array::from_fn(|index| {
        #[cfg(tracepoint_test)]
        let size = context_bytes(tracepoint_for_program(index));
        #[cfg(not(tracepoint_test))]
        let size = { let _ = index; CONTEXT_SIZE };
        load_program(scratch, outputs, size)
    });
    let program = programs[0];
    let events: [usize; SOURCE_COUNT] = core::array::from_fn(|index| {
        #[cfg(tracepoint_test)]
        { perf_open(tracepoint_for_program(index / CPUS) as u64, -1, (index % CPUS) as isize, 0, true) }
        #[cfg(cpu_clock_test)]
        { perf_open(0, -1, (index % CPUS) as isize, PERIOD_NS * (1 + (index / CPUS) as u64), true) }
        #[cfg(not(any(cpu_clock_test,tracepoint_test)))]
        { let _ = index; perf_open(1, tid as isize, -1, PERIOD_NS, true) }
    });
    reject_invalid_sinks(outputs, events[0], &sinks);
    #[cfg(capture_export)]
    measure_archive_phase("loaded_detached", Some(&mut rings), &mut stats, CPUS * MAPPING_SIZE);
    let links: [usize; SOURCE_COUNT] = core::array::from_fn(|index| attach(programs[if cfg!(tracepoint_test) { index / CPUS } else { 0 }], events[index]));
    #[cfg(capture_export)]
    let mut enable_times = [(0u64, 0u64); SOURCE_COUNT];
    #[cfg(capture_export)]
    let mut disable_times = [(0u64, 0u64); SOURCE_COUNT];
    #[cfg(capture_export)]
    {
        archive::stats("before", &events);
        stats.archive = Some(archive::Buffer::new(monotonic_ns()));
    }
    for (index, event) in events.iter().enumerate() {
        #[cfg(capture_export)]
        let before = monotonic_ns();
        #[cfg(not(fault_zero_producer))]
        ioctl(*event, ENABLE);
        #[cfg(capture_export)]
        { enable_times[index] = (before, monotonic_ns()); }
    }
    #[cfg(not(any(cpu_clock_test, tracepoint_test)))]
    check_task_sleep(events[0]);
    #[cfg(capture_export)]
    measure_archive_phase("attached_capture", Some(&mut rings), &mut stats, CPUS * MAPPING_SIZE + archive::MAPPED_BYTES);
    #[cfg(not(capture_export))]
    {
        workload(false, 350, &mut rings, &mut stats);
        workload(true, 350, &mut rings, &mut stats);
    }
    for (index, event) in events.iter().enumerate() {
        #[cfg(capture_export)]
        let before = monotonic_ns();
        ioctl(*event, DISABLE);
        #[cfg(capture_export)]
        { disable_times[index] = (before, monotonic_ns()); }
    }
    #[cfg(capture_export)]
    let capture_stop_ns = monotonic_ns();
    #[cfg(not(capture_export))]
    settle(&mut rings, &mut stats);
    #[cfg(capture_export)]
    {
        archive::wait_quiescent(&events);
        drain_all(&mut rings, &mut stats);
        for ring in &rings {
            say!("ARCHIVE RING cpu={} head={} tail={} wraps={}", ring.cpu, ring.head(), ring.tail, ring.wraps);
        }
        archive::stats("after", &events);
        say!("ARCHIVE CONFIG program_id={} output_map_id={} scratch_map_id={} buffer_pages={} mode={} ring_diagnostics=1",
            archive::object_id(program), archive::object_id(outputs), archive::object_id(scratch), DATA_SIZE/PAGE, MODE);
        #[cfg(sched_trace_test)]
        for (index, program) in programs.iter().enumerate() {
            let tracepoint=tracepoint_for_program(index);
            say!("ARCHIVE PROGRAM tracepoint={} program_id={} context_bytes={}", tracepoint, archive::object_id(*program), context_bytes(tracepoint));
        }
        for (index, event) in events.iter().enumerate() {
            say!("ARCHIVE SOURCE fd={} link_id={} enable_before={} enable_after={} disable_before={} disable_after={}",
                event, archive::object_id(links[index]), enable_times[index].0, enable_times[index].1,
                disable_times[index].0, disable_times[index].1);
        }
        #[cfg(trace_fault)]
        {
            say!("ARCHIVE FAULT_WORKLOAD pid={} tid={} iterations={} read_hits={} write_hits={}",pid,tid,stats.fault_target_count,stats.fault_read_hits,stats.fault_write_hits);
            for (index,(read,write)) in stats.fault_targets[..stats.fault_target_count].iter().enumerate() {
                say!("ARCHIVE FAULT_TARGET index={} read={} write={}",index,read,write);
            }
            check!(stats.fault_read_hits>0 && stats.fault_write_hits>0,"fresh pages produced no read/write fault evidence");
        }
        #[cfg(stack_test)]
        say!("ARCHIVE CONTEXT format=software-stack-v3");
        stats.archive.take().unwrap().emit(capture_stop_ns);
    }
    #[cfg(tracepoint_test)]
    {
        say!("SAMPLING {}_OBSERVED {}={} subjects={} subjects_capped={} target_contexts={} lost={} cpu_mask={:#x}",
             TRACE_MARKER, TRACE_COUNT, stats.samples, stats.subject_count, u8::from(stats.subject_overflow), stats.target_contexts, stats.lost, stats.cpu_mask);
        #[cfg(sched_trace_test)]
        {
            say!("SAMPLING SCHED_EVENTS metadata={} switches={} blocks={} wakes={} exits={} enqueues={}",stats.event_counts[1],stats.event_counts[2],stats.event_counts[3],stats.event_counts[4],stats.event_counts[5],stats.event_counts[6]);
            check!(stats.event_counts[2]>1 && stats.event_counts[3]>1 && stats.event_counts[4]>1 && stats.event_counts[6]>0,"scheduler session lacks required event streams");
        }
        let min_subjects = if TRACE_EVENT_ID == 2 { 2 } else { 1 };
        check!(stats.samples >= 2 && stats.subject_count >= min_subjects, "no real trace events with valid subjects");
    }
    #[cfg(not(tracepoint_test))]
    {
        say!("SAMPLING OBSERVED mode={} samples={} foreign={} a={} b={} lost={} cpu_mask={:#x}",
             MODE, stats.samples, stats.foreign, stats.a, stats.b, stats.lost, stats.cpu_mask);
        check!(stats.a >= 2 && stats.b >= 2, "no real timer samples in both user loop ranges");
    }
    #[cfg(stack_test)]
    stats.stacks.finish();
    check!(stats.lost == 0, "unexpected output loss");
    let disabled_count = stats.samples + stats.foreign;
    workload(false, 150, &mut rings, &mut stats);
    settle(&mut rings, &mut stats);
    check!(stats.samples + stats.foreign == disabled_count, "disabled event still emits new samples");
    say!("SAMPLING PASS disabled mode={} records={}", MODE, disabled_count);
    for link in links { detach(link); }
    for event in events { ioctl(event, ENABLE); }
    workload(true, 150, &mut rings, &mut stats);
    settle(&mut rings, &mut stats);
    check!(stats.samples + stats.foreign == disabled_count, "detached event still emits new samples");
    say!("SAMPLING PASS detached mode={} records={}", MODE, disabled_count);
    for event in events { ioctl(event, DISABLE); }
    for link in links { close(link); }
    for event in events { close(event); }
    #[cfg(not(any(cpu_clock_test, tracepoint_test)))]
    check_fd_lifecycle(program, &mut rings, &stats);
    for program in programs { close(program); } close(scratch); close(outputs);
    for (ring, sink) in rings.into_iter().zip(sinks) {
        ioctl(sink, DISABLE); ring.unmap(); close(sink);
    }
    #[cfg(tracepoint_test)]
    say!("SAMPLING {}_RESULT PASS {}={} subjects={} subjects_capped={} target_contexts={} lost={} source=kernel_ring",
         TRACE_MARKER, TRACE_COUNT, stats.samples, stats.subject_count, u8::from(stats.subject_overflow), stats.target_contexts, stats.lost);
    #[cfg(not(tracepoint_test))]
    say!("SAMPLING RESULT PASS mode={} samples={} foreign={} a={} b={} lost={} source=kernel_ring",
         MODE, stats.samples, stats.foreign, stats.a, stats.b, stats.lost);
    exit(0)
}
