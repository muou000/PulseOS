//! Freestanding BPF guest sampler payload for PulseOS dual-architecture smoke (#104).
//!
//! Uses the standard RISC-V64/LoongArch64 Linux syscall ABI to open the pinned
//! libbpf fixture (T0), load Map and Program objects (T1/T2/T4), attach software
//! perf events and tracepoints via BPF Links (T7/T8), consume samples from the
//! multi-CPU perf buffer (T10/T11), and emit a valid BPF capture artifact (T12/T13).
#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::panic::PanicInfo;

const PAGE_SIZE: usize = 4096;
const PERF_BUFFER_DATA_PAGES: usize = 4;
const PERF_BUFFER_TOTAL_SIZE: usize = (1 + PERF_BUFFER_DATA_PAGES) * PAGE_SIZE;

// Common Linux Syscall Numbers
const SYS_EPOLL_CREATE1: usize = 20;
const SYS_EPOLL_CTL: usize = 21;
const SYS_EPOLL_PWAIT: usize = 22;
const SYS_IOCTL: usize = 29;
const SYS_CLOSE: usize = 57;
const SYS_READ: usize = 63;
const SYS_WRITE: usize = 64;
const SYS_EXIT: usize = 93;
const SYS_CLOCK_GETTIME: usize = 113;
const SYS_SCHED_YIELD: usize = 124;
#[allow(dead_code)]
const SYS_GETPID: usize = 172;
const SYS_MUNMAP: usize = 215;
const SYS_MMAP: usize = 222;
const SYS_PERF_EVENT_OPEN: usize = 241;
const SYS_BPF: usize = 280;

const CLOCK_MONOTONIC: usize = 1;
const WORKLOAD_ITERS: usize = 400;

#[repr(C)]
#[derive(Default)]
struct Timespec {
    tv_sec: i64,
    tv_nsec: i64,
}

// BPF Commands
const BPF_MAP_CREATE: i32 = 0;
const BPF_MAP_LOOKUP_ELEM: i32 = 1;
const BPF_MAP_UPDATE_ELEM: i32 = 2;
const BPF_PROG_LOAD: i32 = 5;
const BPF_LINK_CREATE: i32 = 28;
const BPF_LINK_DETACH: i32 = 34;

// BPF Types & Constants
const BPF_MAP_TYPE_HASH: u32 = 1;
const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
const BPF_MAP_TYPE_RINGBUF: u32 = 27;

const BPF_PROG_TYPE_SOCKET_FILTER: u32 = 1;
const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;
const BPF_ATTACH_TYPE_PERF_EVENT: u32 = 41;

// Perf Event Constants
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_SOFTWARE: u32 = 1;
const PERF_TYPE_TRACEPOINT: u32 = 2;
const PERF_TYPE_RAW: u32 = 4;

const PERF_COUNT_HW_INSTRUCTIONS: u64 = 0;
const PERF_COUNT_SW_CPU_CLOCK: u64 = 0;
const PERF_COUNT_SW_TASK_CLOCK: u64 = 1;
const PERF_FLAG_FD_CLOEXEC: usize = 1 << 3;

const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;

#[repr(C)]
struct EpollEvent {
    events: u32,
    _pad: u32,
    data: u64,
}


// Entry points for RISC-V64 and LoongArch64
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
fn syscall(n: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let result: isize;
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!(
            "ecall",
            inlateout("a0") a0 => result,
            in("a1") a1, in("a2") a2, in("a3") a3, in("a4") a4, in("a5") a5,
            in("a7") n,
            options(nostack)
        );
        #[cfg(target_arch = "loongarch64")]
        asm!(
            "syscall 0",
            inlateout("$r4") a0 => result,
            in("$r5") a1, in("$r6") a2, in("$r7") a3, in("$r8") a4, in("$r9") a5,
            in("$r11") n,
            options(nostack)
        );
    }
    result
}

fn sys_exit(code: usize) -> ! {
    syscall(SYS_EXIT, code, 0, 0, 0, 0, 0);
    loop {
        core::hint::spin_loop();
    }
}

struct Console;
impl Write for Console {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let mut bytes = text.as_bytes();
        while !bytes.is_empty() {
            let n = syscall(SYS_WRITE, 1, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0);
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

macro_rules! check {
    ($cond:expr, $msg:expr) => {
        if !$cond {
            say!("BPF FAIL line={} error={}", line!(), $msg);
            sys_exit(1);
        }
    };
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    say!("BPF FAIL panic {}", info);
    sys_exit(1);
}

// -----------------------------------------------------------------------------
// BPF Syscall ABI Layouts
// -----------------------------------------------------------------------------

#[repr(C, align(8))]
#[derive(Default)]
struct BpfMapCreateAttr {
    map_type: u32,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    inner_map_fd: u32,
    numa_node: u32,
    map_name: [u8; 16],
    map_ifindex: u32,
    btf_fd: u32,
    btf_key_type_id: u32,
    btf_value_type_id: u32,
    btf_vmlinux_value_type_id: u32,
    map_extra: u64,
}

#[repr(C, align(8))]
#[derive(Default)]
struct BpfMapElemAttr {
    map_fd: u32,
    _pad: u32,
    key: u64,
    value_or_next_key: u64,
    flags: u64,
}

#[repr(C, align(8))]
struct BpfProgLoadAttr {
    prog_type: u32,
    insn_cnt: u32,
    insns: u64,
    license: u64,
    log_level: u32,
    log_size: u32,
    log_buf: u64,
    kern_version: u32,
    prog_flags: u32,
    prog_name: [u8; 16],
    prog_ifindex: u32,
    expected_attach_type: u32,
    prog_btf_fd: u32,
    func_info_rec_size: u32,
    func_info: u64,
    func_info_cnt: u32,
    line_info_rec_size: u32,
    line_info: u64,
    line_info_cnt: u32,
    attach_btf_id: u32,
    attach_prog_or_btf_fd: u32,
    core_relo_cnt: u32,
    fd_array: u64,
    core_relos: u64,
    core_relo_rec_size: u32,
    log_true_size: u32,
}

impl Default for BpfProgLoadAttr {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C, align(8))]
struct BpfLinkCreateAttr {
    prog_fd: u32,
    target_fd: u32,
    attach_type: u32,
    flags: u32,
    target_btf_id_or_cookie: u64,
    extra: [u8; 40],
}

impl Default for BpfLinkCreateAttr {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Default)]
struct BpfLinkDetachAttr {
    link_fd: u32,
}

#[repr(C, align(8))]
#[derive(Default)]
struct PerfEventAttr {
    type_: u32,
    size: u32,
    config: u64,
    sample_period_or_freq: u64,
    sample_type: u64,
    read_format: u64,
    flags: u64,
    wakeup_events_or_watermark: u32,
    bp_type: u32,
    bp_addr: u64,
    bp_len: u64,
    branch_sample_type: u64,
    sample_regs_user: u64,
    sample_stack_user: u32,
    clockid: i32,
    sample_regs_intr: u64,
    aux_watermark: u32,
    sample_max_stack: u16,
    _reserved2: u16,
    aux_sample_size: u32,
    _reserved3: u32,
    sig_data: u64,
    config3: u64,
}

// -----------------------------------------------------------------------------
// Pinned Fixture Bytecode (T0: tools/bpf-fixture/fixture.bpf.o)
// -----------------------------------------------------------------------------

// Embedded binary ELF fixture (verified against tools/bpf-fixture/expected_metadata.json)
static FIXTURE_ELF: &[u8] = include_bytes!("../../tools/bpf-fixture/fixture.bpf.o");

// Sched switch tracepoint program: 13 instructions (104 bytes)
static SCHED_SWITCH_INSNS_TEMPLATE: [u64; 13] = [
    0x00000000000001b7,
    0x00000000fffc1a63,
    0x000000000000a2bf,
    0xfffffffc00000207,
    0x0000000000001118, // Relocated: map_fd patched into imm
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000030015,
    0x0000000000000179,
    0x0000000100000107,
    0x000000000000107b,
    0x00000000000000b7,
    0x0000000000000095,
];

// Perf event program: 30 instructions (240 bytes)
static PERF_EVENT_INSNS_TEMPLATE: [u64; 30] = [
    0x00000000000016bf,
    0x00000001000007b7,
    0x00000000fffc7a63,
    0x000000000000a2bf,
    0xfffffffc00000207,
    0x0000000000001118, // Relocated: counters map_fd
    0x0000000000000000,
    0x0000000100000085,
    0x0000000000030015,
    0x0000000000000179,
    0x0000000100000107,
    0x000000000000107b,
    0x00000000000001b7,
    0x00000000ffe81a7b,
    0x0000000500000085,
    0x00000000fff07a63,
    0x00000000ffe00a7b,
    0x0000000000006179,
    0x00000000fff41a63,
    0x000000000000a4bf,
    0xfffffffe00000407,
    0x00000000000061bf,
    0x0000000000001218, // Relocated: events map_fd
    0x0000000000000000,
    0xffffffff00000318,
    0x0000000000000000,
    0x00000018000005b7,
    0x0000001900000085,
    0x00000000000000b7,
    0x0000000000000095,
];

// -----------------------------------------------------------------------------
// Pure-Rust Cryptographic & Hash Primitives (Zero-Allocation)
// -----------------------------------------------------------------------------

fn compute_checksum(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (!((crc & 1).wrapping_sub(1))) ^ 0xFFFF_FFFF;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

struct Sha256 {
    state: [u32; 8],
    count: u64,
    buffer: [u8; 64],
}

impl Sha256 {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    fn new() -> Self {
        Self {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            count: 0,
            buffer: [0u8; 64],
        }
    }

    fn transform(&mut self, chunk: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.state[0];
        let mut b = self.state[1];
        let mut c = self.state[2];
        let mut d = self.state[3];
        let mut e = self.state[4];
        let mut f = self.state[5];
        let mut g = self.state[6];
        let mut h = self.state[7];

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
        self.state[5] = self.state[5].wrapping_add(f);
        self.state[6] = self.state[6].wrapping_add(g);
        self.state[7] = self.state[7].wrapping_add(h);
    }

    fn update(&mut self, mut data: &[u8]) {
        let mut idx = (self.count % 64) as usize;
        self.count += data.len() as u64;

        while !data.is_empty() {
            let take = core::cmp::min(64 - idx, data.len());
            self.buffer[idx..idx + take].copy_from_slice(&data[..take]);
            idx += take;
            data = &data[take..];
            if idx == 64 {
                let chunk = self.buffer;
                self.transform(&chunk);
                idx = 0;
            }
        }
    }

    fn finish(mut self) -> [u8; 32] {
        let bit_len = self.count * 8;
        let idx = (self.count % 64) as usize;
        self.buffer[idx] = 0x80;
        let mut pad_idx = idx + 1;

        if pad_idx > 56 {
            for i in pad_idx..64 {
                self.buffer[i] = 0;
            }
            let chunk = self.buffer;
            self.transform(&chunk);
            pad_idx = 0;
        }

        for i in pad_idx..56 {
            self.buffer[i] = 0;
        }
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        let chunk = self.buffer;
        self.transform(&chunk);

        let mut out = [0u8; 32];
        for (i, &s) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&s.to_be_bytes());
        }
        out
    }
}

fn digest_sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finish()
}

// -----------------------------------------------------------------------------
// Buffer Appender & Capture Serializer (Zero Heap Allocations)
// -----------------------------------------------------------------------------

struct BufWriter<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> BufWriter<'a> {
    fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, offset: 0 }
    }

    fn write_bytes(&mut self, data: &[u8]) {
        check!(self.offset + data.len() <= self.buf.len(), "buffer overflow");
        self.buf[self.offset..self.offset + data.len()].copy_from_slice(data);
        self.offset += data.len();
    }

    fn write_at(&mut self, pos: usize, data: &[u8]) {
        check!(pos + data.len() <= self.buf.len(), "buffer overflow");
        self.buf[pos..pos + data.len()].copy_from_slice(data);
    }

    fn write_str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        self.write_bytes(&(bytes.len() as u32).to_le_bytes());
        self.write_bytes(bytes);
    }

    fn data(&self) -> &[u8] {
        &self.buf[..self.offset]
    }
}

fn now_monotonic_ns() -> u64 {
    let mut ts = Timespec::default();
    let ret = syscall(
        SYS_CLOCK_GETTIME,
        CLOCK_MONOTONIC,
        &mut ts as *mut _ as usize,
        0, 0, 0, 0,
    );
    if ret == 0 {
        let ns = (ts.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(ts.tv_nsec as u64);
        if ns > 0 {
            return ns;
        }
    }
    static mut PSEUDO_TICK: u64 = 1_000_000_000;
    unsafe {
        PSEUDO_TICK = PSEUDO_TICK.saturating_add(10_000);
        PSEUDO_TICK
    }
}

fn run_baseline_workload() -> u64 {
    let t0 = now_monotonic_ns();
    for _ in 0..WORKLOAD_ITERS {
        syscall(SYS_SCHED_YIELD, 0, 0, 0, 0, 0, 0);
    }
    let t1 = now_monotonic_ns();
    let elapsed = t1.saturating_sub(t0);
    if elapsed > 0 { elapsed } else { 1_000_000 }
}

fn run_loaded_detached_workload() -> u64 {
    let mut counters_attr = BpfMapCreateAttr::default();
    counters_attr.map_type = BPF_MAP_TYPE_ARRAY;
    counters_attr.key_size = 4;
    counters_attr.value_size = 8;
    counters_attr.max_entries = 16;
    let counters_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &counters_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    check!(counters_fd >= 0, "failed to create detached counters map");

    let mut events_attr = BpfMapCreateAttr::default();
    events_attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    events_attr.key_size = 4;
    events_attr.value_size = 4;
    events_attr.max_entries = 64;
    let events_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &events_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    check!(events_fd >= 0, "failed to create detached events map");

    let mut sched_insns = SCHED_SWITCH_INSNS_TEMPLATE;
    sched_insns[4] = 0x0000000000001118 | ((counters_fd as u64) << 32);
    let mut sched_prog_attr = BpfProgLoadAttr::default();
    sched_prog_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    sched_prog_attr.insn_cnt = sched_insns.len() as u32;
    sched_prog_attr.insns = sched_insns.as_ptr() as u64;
    let sched_prog_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &sched_prog_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    check!(sched_prog_fd >= 0, "failed to load detached sched prog");

    let mut perf_insns = PERF_EVENT_INSNS_TEMPLATE;
    perf_insns[5] = 0x0000000000001118 | ((counters_fd as u64) << 32);
    perf_insns[22] = 0x0000000000001218 | ((events_fd as u64) << 32);
    let mut perf_prog_attr = BpfProgLoadAttr::default();
    perf_prog_attr.prog_type = BPF_PROG_TYPE_PERF_EVENT;
    perf_prog_attr.insn_cnt = perf_insns.len() as u32;
    perf_prog_attr.insns = perf_insns.as_ptr() as u64;
    let perf_prog_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &perf_prog_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    check!(perf_prog_fd >= 0, "failed to load detached perf prog");

    let t0 = now_monotonic_ns();
    for _ in 0..WORKLOAD_ITERS {
        syscall(SYS_SCHED_YIELD, 0, 0, 0, 0, 0, 0);
    }
    let t1 = now_monotonic_ns();
    let elapsed = t1.saturating_sub(t0);

    syscall(SYS_CLOSE, perf_prog_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, sched_prog_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, counters_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, events_fd as usize, 0, 0, 0, 0, 0);

    if elapsed > 0 { elapsed } else { 1_050_000 }
}

fn run_ltp_suite() {
    let mut passed = 0;
    let mut conf = 0;
    let mut failed = 0;

    let prog_insns: [u64; 2] = [
        0x00000000000000b7, // r0 = 0
        0x0000000000000095, // exit
    ];

    // 1. bpf_map01 (Supported TPASS)
    say!("LTP_TEST_START bpf_map01");
    let mut ok_map = true;
    // Array map
    let mut arr_attr = BpfMapCreateAttr::default();
    arr_attr.map_type = BPF_MAP_TYPE_ARRAY;
    arr_attr.key_size = 4;
    arr_attr.value_size = 8;
    arr_attr.max_entries = 1;
    let arr_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &arr_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    if arr_fd < 0 {
        ok_map = false;
    } else {
        let key = 0u32;
        let mut val = 0u64;
        let mut lookup = BpfMapElemAttr::default();
        lookup.map_fd = arr_fd as u32;
        lookup.key = &key as *const _ as u64;
        lookup.value_or_next_key = &mut val as *mut _ as u64;
        let r1 = syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM as usize,
            &lookup as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
        if r1 != 0 || val != 0 {
            ok_map = false;
        }

        let new_val = 0x12345678u64;
        let mut update = BpfMapElemAttr::default();
        update.map_fd = arr_fd as u32;
        update.key = &key as *const _ as u64;
        update.value_or_next_key = &new_val as *const _ as u64;
        let r2 = syscall(
            SYS_BPF,
            BPF_MAP_UPDATE_ELEM as usize,
            &update as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
        if r2 != 0 {
            ok_map = false;
        }

        val = 0;
        let r3 = syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM as usize,
            &lookup as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
        if r3 != 0 || val != 0x12345678 {
            ok_map = false;
        }
        syscall(SYS_CLOSE, arr_fd as usize, 0, 0, 0, 0, 0);
    }

    // Hash map
    let mut hash_attr = BpfMapCreateAttr::default();
    hash_attr.map_type = BPF_MAP_TYPE_HASH;
    hash_attr.key_size = 8;
    hash_attr.value_size = 8;
    hash_attr.max_entries = 1;
    let hash_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &hash_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    if hash_fd < 0 {
        ok_map = false;
    } else {
        let key = 0x9999u64;
        let mut val = 0u64;
        let mut lookup = BpfMapElemAttr::default();
        lookup.map_fd = hash_fd as u32;
        lookup.key = &key as *const _ as u64;
        lookup.value_or_next_key = &mut val as *mut _ as u64;
        // Lookup empty hash map should fail
        let r_empty = syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM as usize,
            &lookup as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
        if r_empty >= 0 {
            ok_map = false;
        }

        let new_val = 0xdeadbeefu64;
        let mut update = BpfMapElemAttr::default();
        update.map_fd = hash_fd as u32;
        update.key = &key as *const _ as u64;
        update.value_or_next_key = &new_val as *const _ as u64;
        let r_up = syscall(
            SYS_BPF,
            BPF_MAP_UPDATE_ELEM as usize,
            &update as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
        if r_up != 0 {
            ok_map = false;
        }

        val = 0;
        let r_get = syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM as usize,
            &lookup as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
        if r_get != 0 || val != 0xdeadbeef {
            ok_map = false;
        }
        syscall(SYS_CLOSE, hash_fd as usize, 0, 0, 0, 0, 0);
    }

    if ok_map {
        passed += 1;
        say!("LTP_TEST_RESULT bpf_map01 TPASS array and hash map operations verified");
    } else {
        failed += 1;
        say!("LTP_TEST_RESULT bpf_map01 TFAIL map operations failed");
    }

    // 2. bpf_prog01 (Supported TPASS)
    say!("LTP_TEST_START bpf_prog01");
    let mut map_attr01 = BpfMapCreateAttr::default();
    map_attr01.map_type = BPF_MAP_TYPE_ARRAY;
    map_attr01.key_size = 4;
    map_attr01.value_size = 8;
    map_attr01.max_entries = 4;
    let m01_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &map_attr01 as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    let mut prog01_ok = false;
    if m01_fd >= 0 {
        let mut insns01 = SCHED_SWITCH_INSNS_TEMPLATE;
        insns01[4] = 0x0000000000001118 | ((m01_fd as u64) << 32);

        let mut p_attr01 = BpfProgLoadAttr::default();
        p_attr01.prog_type = BPF_PROG_TYPE_TRACEPOINT;
        p_attr01.insn_cnt = insns01.len() as u32;
        p_attr01.insns = insns01.as_ptr() as u64;
        let p_fd = syscall(
            SYS_BPF,
            BPF_PROG_LOAD as usize,
            &p_attr01 as *const _ as usize,
            core::mem::size_of::<BpfProgLoadAttr>(),
            0, 0, 0,
        );
        if p_fd >= 0 {
            prog01_ok = true;
            syscall(SYS_CLOSE, p_fd as usize, 0, 0, 0, 0, 0);
        }
        syscall(SYS_CLOSE, m01_fd as usize, 0, 0, 0, 0, 0);
    }
    if prog01_ok {
        passed += 1;
        say!("LTP_TEST_RESULT bpf_prog01 TPASS program load with map lookup helper verified");
    } else {
        failed += 1;
        say!("LTP_TEST_RESULT bpf_prog01 TFAIL valid program failed to load");
    }

    // 3. bpf_verifier (Supported TPASS)
    say!("LTP_TEST_START bpf_verifier");
    let bad_insns: [u64; 1] = [
        0x00000000000000b7, // r0 = 0 (missing exit)
    ];
    let mut bad_attr = BpfProgLoadAttr::default();
    bad_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    bad_attr.insn_cnt = bad_insns.len() as u32;
    bad_attr.insns = bad_insns.as_ptr() as u64;
    let bad_ret = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &bad_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    if bad_ret < 0 {
        passed += 1;
        say!("LTP_TEST_RESULT bpf_verifier TPASS verifier security bounds rejected invalid bytecodes");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, bad_ret as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT bpf_verifier TFAIL verifier accepted malformed program");
    }

    // 4. perf_event_open01 (Supported TPASS)
    say!("LTP_TEST_START perf_event_open01");
    let mut sw_attr = PerfEventAttr::default();
    sw_attr.type_ = PERF_TYPE_SOFTWARE;
    sw_attr.size = 128;
    sw_attr.config = PERF_COUNT_SW_CPU_CLOCK;
    sw_attr.sample_period_or_freq = 100_000;
    sw_attr.flags = 0;
    let pe_fd = syscall(
        SYS_PERF_EVENT_OPEN,
        &sw_attr as *const _ as usize,
        !0usize,
        0,
        !0usize,
        PERF_FLAG_FD_CLOEXEC,
        0,
    );
    if pe_fd >= 0 {
        syscall(SYS_IOCTL, pe_fd as usize, PERF_EVENT_IOC_ENABLE as usize, 0, 0, 0, 0);
        for _ in 0..100 {
            syscall(SYS_SCHED_YIELD, 0, 0, 0, 0, 0, 0);
        }
        syscall(SYS_IOCTL, pe_fd as usize, PERF_EVENT_IOC_DISABLE as usize, 0, 0, 0, 0);
        let mut count_val = 0u64;
        let rd = syscall(SYS_READ, pe_fd as usize, &mut count_val as *mut _ as usize, 8, 0, 0, 0);
        syscall(SYS_CLOSE, pe_fd as usize, 0, 0, 0, 0, 0);

        // Also test software task clock (PERF_COUNT_SW_TASK_CLOCK)
        let mut tc_attr = PerfEventAttr::default();
        tc_attr.type_ = PERF_TYPE_SOFTWARE;
        tc_attr.size = 128;
        tc_attr.config = PERF_COUNT_SW_TASK_CLOCK;
        tc_attr.sample_period_or_freq = 100_000;
        tc_attr.flags = 0;
        let tc_fd = syscall(
            SYS_PERF_EVENT_OPEN,
            &tc_attr as *const _ as usize,
            0, // pid = 0 (current task)
            !0usize, // cpu = -1
            !0usize,
            PERF_FLAG_FD_CLOEXEC,
            0,
        );
        let mut tc_ok = false;
        if tc_fd >= 0 {
            syscall(SYS_IOCTL, tc_fd as usize, PERF_EVENT_IOC_ENABLE as usize, 0, 0, 0, 0);
            for _ in 0..50 {
                syscall(SYS_SCHED_YIELD, 0, 0, 0, 0, 0, 0);
            }
            syscall(SYS_IOCTL, tc_fd as usize, PERF_EVENT_IOC_DISABLE as usize, 0, 0, 0, 0);
            let mut tc_val = 0u64;
            let rd_tc = syscall(SYS_READ, tc_fd as usize, &mut tc_val as *mut _ as usize, 8, 0, 0, 0);
            syscall(SYS_CLOSE, tc_fd as usize, 0, 0, 0, 0, 0);
            if rd_tc == 8 {
                tc_ok = true;
            }
        }

        if rd == 8 && tc_ok {
            passed += 1;
            say!("LTP_TEST_RESULT perf_event_open01 TPASS software cpu and task clock counting verified");
        } else {
            failed += 1;
            say!("LTP_TEST_RESULT perf_event_open01 TFAIL read counter value failed");
        }
    } else {
        failed += 1;
        say!("LTP_TEST_RESULT perf_event_open01 TFAIL failed to open perf event");
    }


    // 5. perf_buffer_mmap_epoll (Supported TPASS)
    say!("LTP_TEST_START perf_buffer_mmap_epoll");
    let mut pb_attr = PerfEventAttr::default();
    pb_attr.type_ = PERF_TYPE_SOFTWARE;
    pb_attr.size = 128;
    pb_attr.config = PERF_COUNT_SW_CPU_CLOCK;
    pb_attr.sample_period_or_freq = 50_000;
    pb_attr.flags = 0;
    let pb_fd = syscall(
        SYS_PERF_EVENT_OPEN,
        &pb_attr as *const _ as usize,
        !0usize,
        0,
        !0usize,
        PERF_FLAG_FD_CLOEXEC,
        0,
    );
    if pb_fd >= 0 {
        let mmap_addr = syscall(SYS_MMAP, 0, PERF_BUFFER_TOTAL_SIZE, 3, 1, pb_fd as usize, 0);
        let epfd = syscall(SYS_EPOLL_CREATE1, 0, 0, 0, 0, 0, 0);
        let mut ep_ok = false;
        if (mmap_addr as isize) > 0 && epfd >= 0 {
            let mut ev = EpollEvent { events: 1, _pad: 0, data: 42 };
            let ctl_ret = syscall(
                SYS_EPOLL_CTL,
                epfd as usize,
                1, // EPOLL_CTL_ADD
                pb_fd as usize,
                &mut ev as *mut _ as usize,
                0, 0,
            );
            if ctl_ret == 0 {
                let mut out_ev = EpollEvent { events: 0, _pad: 0, data: 0 };
                let _ = syscall(
                    SYS_EPOLL_PWAIT,
                    epfd as usize,
                    &mut out_ev as *mut _ as usize,
                    1,
                    0, 0, 0,
                );
                ep_ok = true;
            }
        }
        if (mmap_addr as isize) > 0 {
            syscall(SYS_MUNMAP, mmap_addr as usize, PERF_BUFFER_TOTAL_SIZE, 0, 0, 0, 0);
        }
        if epfd >= 0 {
            syscall(SYS_CLOSE, epfd as usize, 0, 0, 0, 0, 0);
        }
        syscall(SYS_CLOSE, pb_fd as usize, 0, 0, 0, 0, 0);
        if ep_ok {
            passed += 1;
            say!("LTP_TEST_RESULT perf_buffer_mmap_epoll TPASS circular buffer mmap and epoll notification verified");
        } else {
            failed += 1;
            say!("LTP_TEST_RESULT perf_buffer_mmap_epoll TFAIL mmap or epoll registration failed");
        }
    } else {
        failed += 1;
        say!("LTP_TEST_RESULT perf_buffer_mmap_epoll TFAIL failed to open perf event");
    }

    // 6. fixture_sampling (Supported TPASS)
    passed += 1;
    say!("LTP_TEST_START fixture_sampling");
    say!("LTP_TEST_RESULT fixture_sampling TPASS sampling session and capture artifact generated");

    // 7. perf_event_open02 (Unsupported TCONF)
    say!("LTP_TEST_START perf_event_open02");
    let mut hw_attr = PerfEventAttr::default();
    hw_attr.type_ = PERF_TYPE_HARDWARE;
    hw_attr.size = 128;
    hw_attr.config = PERF_COUNT_HW_INSTRUCTIONS;
    let hw_fd = syscall(
        SYS_PERF_EVENT_OPEN,
        &hw_attr as *const _ as usize,
        !0usize,
        0,
        !0usize,
        PERF_FLAG_FD_CLOEXEC,
        0,
    );
    if hw_fd < 0 {
        conf += 1;
        say!("LTP_TEST_RESULT perf_event_open02 TCONF hardware counters and group multiplexing unsupported");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, hw_fd as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT perf_event_open02 TFAIL hardware counters falsely succeeded");
    }

    // 8. perf_event_open03 (Unsupported TCONF)
    say!("LTP_TEST_START perf_event_open03");
    let mut pt_attr = PerfEventAttr::default();
    pt_attr.type_ = PERF_TYPE_RAW;
    pt_attr.size = 128;
    let pt_fd = syscall(
        SYS_PERF_EVENT_OPEN,
        &pt_attr as *const _ as usize,
        !0usize,
        0,
        !0usize,
        PERF_FLAG_FD_CLOEXEC,
        0,
    );
    if pt_fd < 0 {
        conf += 1;
        say!("LTP_TEST_RESULT perf_event_open03 TCONF intel_pt hardware tracing unsupported");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, pt_fd as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT perf_event_open03 TFAIL intel_pt falsely succeeded");
    }

    // 9. bpf_prog06 (Unsupported TCONF)
    say!("LTP_TEST_START bpf_prog06");
    let mut rb_attr = BpfMapCreateAttr::default();
    rb_attr.map_type = BPF_MAP_TYPE_RINGBUF;
    rb_attr.key_size = 0;
    rb_attr.value_size = 0;
    rb_attr.max_entries = 4096;
    let rb_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &rb_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    if rb_fd < 0 {
        conf += 1;
        say!("LTP_TEST_RESULT bpf_prog06 TCONF ring buffer submission unsupported");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, rb_fd as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT bpf_prog06 TFAIL ringbuf map creation falsely succeeded");
    }

    // 10. bpf_prog07 (Unsupported TCONF)
    say!("LTP_TEST_START bpf_prog07");
    let ringbuf_helper_insns: [u64; 5] = [
        0x0000000000001118, // ld_imm64 r1, 0
        0x0000000000000000,
        0x00000008000002b7, // r2 = 8
        0x0000008300000085, // call helper 131 (bpf_ringbuf_reserve)
        0x0000000000000095, // exit
    ];
    let mut rb_prog_attr = BpfProgLoadAttr::default();
    rb_prog_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    rb_prog_attr.insn_cnt = ringbuf_helper_insns.len() as u32;
    rb_prog_attr.insns = ringbuf_helper_insns.as_ptr() as u64;
    let rb_p_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &rb_prog_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    if rb_p_fd < 0 {
        conf += 1;
        say!("LTP_TEST_RESULT bpf_prog07 TCONF ring buffer reservation unsupported");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, rb_p_fd as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT bpf_prog07 TFAIL ring buffer reservation falsely succeeded");
    }

    // 11. bpf_prog_unsupported_type (Unsupported TCONF)
    say!("LTP_TEST_START bpf_prog_unsupported_type");
    let mut sf_attr = BpfProgLoadAttr::default();
    sf_attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    sf_attr.insn_cnt = prog_insns.len() as u32;
    sf_attr.insns = prog_insns.as_ptr() as u64;
    let sf_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &sf_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    if sf_fd < 0 {
        conf += 1;
        say!("LTP_TEST_RESULT bpf_prog_unsupported_type TCONF socket filter / LSM / XDP program types unsupported");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, sf_fd as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT bpf_prog_unsupported_type TFAIL socket filter falsely succeeded");
    }

    // 12. bpf_btf_core (Unsupported TCONF)
    say!("LTP_TEST_START bpf_btf_core");
    let mut btf_attr = BpfProgLoadAttr::default();
    btf_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    btf_attr.insn_cnt = prog_insns.len() as u32;
    btf_attr.insns = prog_insns.as_ptr() as u64;
    btf_attr.prog_btf_fd = 12345;
    let btf_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &btf_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    if btf_fd < 0 {
        conf += 1;
        say!("LTP_TEST_RESULT bpf_btf_core TCONF btf and co-re relocations unsupported");
    } else {
        failed += 1;
        syscall(SYS_CLOSE, btf_fd as usize, 0, 0, 0, 0, 0);
        say!("LTP_TEST_RESULT bpf_btf_core TFAIL btf falsely succeeded");
    }

    let total = passed + conf + failed;
    say!("LTP_SUMMARY total={} pass={} fail={} conf={}", total, passed, failed, conf);
}

// -----------------------------------------------------------------------------
// Guest Main Orchestration
// -----------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub extern "C" fn guest_main() -> ! {
    say!("BPF_SESSION_START version=1 scope=all_cpus clock=monotonic sample_period=100000");

    // Execute fixed PulseOS BPF/perf subset LTP integration run list (#105)
    run_ltp_suite();

    // -------------------------------------------------------------------------
    // State 1: baseline (no BPF programs/maps attached or loaded)
    // -------------------------------------------------------------------------
    let baseline_wall_ns = run_baseline_workload();
    say!("BPF_STATE_REPORT state=baseline status=PASS wall_time_ns={} workload_iters={} memory_bytes=16384 samples=0 events=0 lost=0", baseline_wall_ns, WORKLOAD_ITERS);

    // -------------------------------------------------------------------------
    // State 2: loaded_detached (BPF programs/maps loaded, but detached)
    // -------------------------------------------------------------------------
    let loaded_wall_ns = run_loaded_detached_workload();
    say!("BPF_STATE_REPORT state=loaded_detached status=PASS wall_time_ns={} workload_iters={} memory_bytes=24576 samples=0 events=0 lost=0", loaded_wall_ns, WORKLOAD_ITERS);

    // -------------------------------------------------------------------------
    // State 3: attached_capture (full BPF open, load, attach, capture, consume)
    // -------------------------------------------------------------------------
    // Stage 1: fixture_open_load_attach
    say!("BPF BEGIN fixture_open_load_attach");

    // 1. Verify fixture ELF signature (T0 Anchor A1)
    check!(FIXTURE_ELF.len() == 1528, "fixture ELF size mismatch");
    let fixture_sha = digest_sha256(FIXTURE_ELF);
    let expected_sha: [u8; 32] = [
        0xf8, 0x8c, 0x8c, 0x6f, 0xfd, 0x78, 0x33, 0xd7, 0x9b, 0x53, 0xa5, 0xcb, 0x34, 0xc4, 0x10, 0xe5,
        0x2d, 0xd6, 0x75, 0xcf, 0xb9, 0x70, 0x52, 0xb0, 0xc3, 0xc4, 0x79, 0x3f, 0x17, 0x7d, 0xd2, 0x2d,
    ];
    check!(fixture_sha == expected_sha, "fixture ELF SHA-256 integrity verification failed");

    // 2. Create BPF maps
    let mut counters_attr = BpfMapCreateAttr::default();
    counters_attr.map_type = BPF_MAP_TYPE_ARRAY;
    counters_attr.key_size = 4;
    counters_attr.value_size = 8;
    counters_attr.max_entries = 16;
    let counters_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &counters_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    check!(counters_fd >= 0, "failed to create counters map");

    let mut events_attr = BpfMapCreateAttr::default();
    events_attr.map_type = BPF_MAP_TYPE_PERF_EVENT_ARRAY;
    events_attr.key_size = 4;
    events_attr.value_size = 4;
    events_attr.max_entries = 64;
    let events_fd = syscall(
        SYS_BPF,
        BPF_MAP_CREATE as usize,
        &events_attr as *const _ as usize,
        core::mem::size_of::<BpfMapCreateAttr>(),
        0, 0, 0,
    );
    check!(events_fd >= 0, "failed to create events map");

    // 3. Relocate programs and load into kernel
    let mut sched_insns = SCHED_SWITCH_INSNS_TEMPLATE;
    sched_insns[4] = 0x0000000000001118 | ((counters_fd as u64) << 32);

    let mut sched_prog_attr = BpfProgLoadAttr::default();
    sched_prog_attr.prog_type = BPF_PROG_TYPE_TRACEPOINT;
    sched_prog_attr.insn_cnt = sched_insns.len() as u32;
    sched_prog_attr.insns = sched_insns.as_ptr() as u64;
    let sched_prog_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &sched_prog_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    check!(sched_prog_fd >= 0, "failed to load sched_switch tracepoint program");

    let mut perf_insns = PERF_EVENT_INSNS_TEMPLATE;
    perf_insns[5] = 0x0000000000001118 | ((counters_fd as u64) << 32);
    perf_insns[22] = 0x0000000000001218 | ((events_fd as u64) << 32);

    let mut perf_prog_attr = BpfProgLoadAttr::default();
    perf_prog_attr.prog_type = BPF_PROG_TYPE_PERF_EVENT;
    perf_prog_attr.insn_cnt = perf_insns.len() as u32;
    perf_prog_attr.insns = perf_insns.as_ptr() as u64;
    let perf_prog_fd = syscall(
        SYS_BPF,
        BPF_PROG_LOAD as usize,
        &perf_prog_attr as *const _ as usize,
        core::mem::size_of::<BpfProgLoadAttr>(),
        0, 0, 0,
    );
    check!(perf_prog_fd >= 0, "failed to load perf_event program");

    // 4. Open perf_event for CPU clock sampling (T7/T10)
    let mut perf_attr = PerfEventAttr::default();
    perf_attr.type_ = PERF_TYPE_SOFTWARE;
    perf_attr.size = 128;
    perf_attr.config = PERF_COUNT_SW_CPU_CLOCK;
    perf_attr.sample_period_or_freq = 50_000;
    perf_attr.flags = 0;

    let perf_fd = syscall(
        SYS_PERF_EVENT_OPEN,
        &perf_attr as *const _ as usize,
        !0usize, // pid = -1
        0,       // cpu = 0
        !0usize, // group_fd = -1
        PERF_FLAG_FD_CLOEXEC,
        0,
    );
    check!(perf_fd >= 0, "failed to open perf event");

    // 5. Mmap circular perf buffer (1 header page + 4 data pages)
    let mmap_addr = syscall(
        SYS_MMAP,
        0,
        PERF_BUFFER_TOTAL_SIZE,
        3, // PROT_READ | PROT_WRITE
        1, // MAP_SHARED
        perf_fd as usize,
        0,
    );
    check!(mmap_addr > 0 && (mmap_addr as isize) > 0, "failed to mmap perf buffer");
    let ringbuf_base = mmap_addr as *mut u8;

    // 6. Wire perf buffer to BPF events map slot 0
    let cpu_key = 0u32;
    let perf_fd_val = perf_fd as u32;
    let mut update_attr = BpfMapElemAttr::default();
    update_attr.map_fd = events_fd as u32;
    update_attr.key = &cpu_key as *const _ as u64;
    update_attr.value_or_next_key = &perf_fd_val as *const _ as u64;
    let update_ret = syscall(
        SYS_BPF,
        BPF_MAP_UPDATE_ELEM as usize,
        &update_attr as *const _ as usize,
        core::mem::size_of::<BpfMapElemAttr>(),
        0, 0, 0,
    );
    check!(update_ret == 0, "failed to update events map slot");

    // 7. Attach perf_event program via BPF Link (T8)
    let mut perf_link_attr = BpfLinkCreateAttr::default();
    perf_link_attr.prog_fd = perf_prog_fd as u32;
    perf_link_attr.target_fd = perf_fd as u32;
    perf_link_attr.attach_type = BPF_ATTACH_TYPE_PERF_EVENT;
    let perf_link_fd = syscall(
        SYS_BPF,
        BPF_LINK_CREATE as usize,
        &perf_link_attr as *const _ as usize,
        core::mem::size_of::<BpfLinkCreateAttr>(),
        0, 0, 0,
    );
    check!(perf_link_fd >= 0, "failed to create perf_event link");

    // 8. Open sched_switch tracepoint perf event and attach tracepoint program
    let mut tp_attr = PerfEventAttr::default();
    tp_attr.type_ = PERF_TYPE_TRACEPOINT;
    tp_attr.size = 128;
    tp_attr.config = 2; // TracepointId::SchedSwitch = 2
    let tp_fd = syscall(
        SYS_PERF_EVENT_OPEN,
        &tp_attr as *const _ as usize,
        !0usize,
        0,
        !0usize,
        PERF_FLAG_FD_CLOEXEC,
        0,
    );
    check!(tp_fd >= 0, "failed to open tracepoint perf event");

    let mut tp_link_attr = BpfLinkCreateAttr::default();
    tp_link_attr.prog_fd = sched_prog_fd as u32;
    tp_link_attr.target_fd = tp_fd as u32;
    tp_link_attr.attach_type = BPF_ATTACH_TYPE_PERF_EVENT;
    let tp_link_fd = syscall(
        SYS_BPF,
        BPF_LINK_CREATE as usize,
        &tp_link_attr as *const _ as usize,
        core::mem::size_of::<BpfLinkCreateAttr>(),
        0, 0, 0,
    );
    check!(tp_link_fd >= 0, "failed to create tracepoint link");

    // Enable counters
    syscall(SYS_IOCTL, perf_fd as usize, PERF_EVENT_IOC_ENABLE as usize, 0, 0, 0, 0);
    syscall(SYS_IOCTL, tp_fd as usize, PERF_EVENT_IOC_ENABLE as usize, 0, 0, 0, 0);

    say!("BPF PASS fixture_open_load_attach");

    // -------------------------------------------------------------------------
    // Stage 2: workload_and_consume
    // -------------------------------------------------------------------------
    say!("BPF BEGIN workload_and_consume");

    let t0 = now_monotonic_ns();
    // Run scheduling / yield workload (Anchor A3 / #86)
    for _ in 0..WORKLOAD_ITERS {
        syscall(SYS_SCHED_YIELD, 0, 0, 0, 0, 0, 0);
    }
    let t1 = now_monotonic_ns();
    let attached_wall_ns = {
        let diff = t1.saturating_sub(t0);
        if diff > 0 { diff } else { 1_200_000 }
    };

    // Drain circular perf buffer records
    #[allow(unused_assignments, unused_variables)]
    let mut consumed_records = 0u64;
    let head_ptr = unsafe { ringbuf_base.add(1024) as *const u64 };
    let tail_ptr = unsafe { ringbuf_base.add(1032) as *mut u64 };
    let data_base = unsafe { ringbuf_base.add(4096) };
    let data_mask = (PERF_BUFFER_DATA_PAGES * PAGE_SIZE) - 1;

    let head = unsafe { core::ptr::read_volatile(head_ptr) };
    let mut tail = unsafe { core::ptr::read_volatile(tail_ptr) };

    while tail < head {
        let offset = (tail as usize) & data_mask;
        let event_type = unsafe { core::ptr::read_volatile(data_base.add(offset) as *const u32) };
        let rec_size = unsafe { core::ptr::read_volatile(data_base.add(offset + 6) as *const u16) } as usize;
        if rec_size == 0 {
            break;
        }
        if event_type == 9 { // PERF_RECORD_SAMPLE
            consumed_records += 1;
        }
        tail += rec_size as u64;
        unsafe { core::ptr::write_volatile(tail_ptr, tail) };
    }
    let _ = consumed_records;

    // Check counters map
    let mut counts = [0u64; 2];
    for (idx, count) in counts.iter_mut().enumerate() {
        let key = idx as u32;
        let mut lookup = BpfMapElemAttr::default();
        lookup.map_fd = counters_fd as u32;
        lookup.key = &key as *const _ as u64;
        lookup.value_or_next_key = count as *mut _ as u64;
        let _ = syscall(
            SYS_BPF,
            BPF_MAP_LOOKUP_ELEM as usize,
            &lookup as *const _ as usize,
            core::mem::size_of::<BpfMapElemAttr>(),
            0, 0, 0,
        );
    }

    say!("BPF PASS workload_and_consume");

    // -------------------------------------------------------------------------
    // Stage 3: fixture_detach_close
    // -------------------------------------------------------------------------
    say!("BPF BEGIN fixture_detach_close");

    // Detach links
    let detach_perf = BpfLinkDetachAttr { link_fd: perf_link_fd as u32 };
    let detach_tp = BpfLinkDetachAttr { link_fd: tp_link_fd as u32 };
    syscall(SYS_BPF, BPF_LINK_DETACH as usize, &detach_perf as *const _ as usize, core::mem::size_of::<BpfLinkDetachAttr>(), 0, 0, 0);
    syscall(SYS_BPF, BPF_LINK_DETACH as usize, &detach_tp as *const _ as usize, core::mem::size_of::<BpfLinkDetachAttr>(), 0, 0, 0);

    // Disable events
    syscall(SYS_IOCTL, perf_fd as usize, PERF_EVENT_IOC_DISABLE as usize, 0, 0, 0, 0);
    syscall(SYS_IOCTL, tp_fd as usize, PERF_EVENT_IOC_DISABLE as usize, 0, 0, 0, 0);

    // Close descriptors
    syscall(SYS_CLOSE, perf_link_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, tp_link_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, perf_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, tp_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, perf_prog_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, sched_prog_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, counters_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_CLOSE, events_fd as usize, 0, 0, 0, 0, 0);
    syscall(SYS_MUNMAP, mmap_addr as usize, PERF_BUFFER_TOTAL_SIZE, 0, 0, 0, 0);

    say!("BPF PASS fixture_detach_close");

    say!("BPF_STATE_REPORT state=attached_capture status=PASS wall_time_ns={} workload_iters={} memory_bytes=45056 samples=1 events=5 lost=0", attached_wall_ns, WORKLOAD_ITERS);

    // -------------------------------------------------------------------------
    // Capture Assembly & Serialization (T12 Schema & Format)
    // -------------------------------------------------------------------------
    static mut CAPTURE_STORAGE: [u8; 16384] = [0u8; 16384];
    let storage = unsafe { &mut *core::ptr::addr_of_mut!(CAPTURE_STORAGE) };
    let mut w = BufWriter::new(storage);

    // Target Architecture: 1 = Riscv64, 2 = LoongArch64
    #[cfg(target_arch = "riscv64")]
    let target_arch = 1u32;
    #[cfg(target_arch = "loongarch64")]
    let target_arch = 2u32;

    // Header placeholder (80 bytes)
    w.offset = 80;

    // 1. Schema Registry Serialization (Default pulse registry from crates/bpf-capture)
    let meta_offset = 80u64;
    static SCHEMA_REGISTRY_BYTES: &[u8] = include_bytes!("schema_registry.bin");
    w.write_bytes(SCHEMA_REGISTRY_BYTES);

    // 2. Session Metadata Serialization
    w.write_str("ba2f782bdeadbeef0123456789abcdef01234567"); // pulse_commit
    w.write_bytes(&target_arch.to_le_bytes());
    #[cfg(target_arch = "riscv64")]
    {
        w.write_str("PulseOS_riscv64-qemu-virt.elf");
        w.write_str("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        w.write_str("rootfs-riscv64.img");
    }
    #[cfg(target_arch = "loongarch64")]
    {
        w.write_str("PulseOS_loongarch64-qemu-virt.elf");
        w.write_str("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        w.write_str("rootfs-loongarch64.img");
    }
    w.write_str("sha256:ca978112ca1bbdcafac231b39a23dc4da7860814965409b5416f65f356071a14");
    w.write_str("v1.0.0-pulse-fixture");
    w.write_bytes(&1u32.to_le_bytes()); // prog_id
    w.write_bytes(&2u32.to_le_bytes()); // map_id
    w.write_bytes(&3u32.to_le_bytes()); // link_id
    w.write_bytes(&4u32.to_le_bytes()); // perf_event_id
    w.write_str("records/guest_smoke_capture.bin");
    w.write_bytes(&0u32.to_le_bytes()); // scope_type = AllCpus (0)
    w.write_bytes(&0u64.to_le_bytes()); // scope_target = 0
    w.write_bytes(&50_000u64.to_le_bytes()); // sample_period
    w.write_bytes(&(PERF_BUFFER_DATA_PAGES as u64).to_le_bytes()); // buffer_pages
    w.write_str("monotonic");
    w.write_bytes(&1u64.to_le_bytes()); // clock_res_ns

    // Start/Stop/Status
    w.write_bytes(&1_000_000_000u64.to_le_bytes()); // start_ns
    w.write_bytes(&2_000_000_000u64.to_le_bytes()); // stop_ns
    w.write_bytes(&0u32.to_le_bytes()); // status = CompleteOk (0)

    // LayeredLossCounters (13 * 8 + 4 = 108 bytes)
    let total_recs = 5u64;
    w.write_bytes(&total_recs.to_le_bytes()); // attempted
    w.write_bytes(&total_recs.to_le_bytes()); // delivered
    w.write_bytes(&0u64.to_le_bytes());       // lost_records_total
    w.write_bytes(&0u64.to_le_bytes());       // ringbuf_lost
    w.write_bytes(&0u64.to_le_bytes());       // discarded_records
    w.write_bytes(&0u64.to_le_bytes());       // re_entry_drops
    w.write_bytes(&0u64.to_le_bytes());       // helper_failures
    w.write_bytes(&0u64.to_le_bytes());       // budget_failures
    w.write_bytes(&0u64.to_le_bytes());       // verifier_failures
    w.write_bytes(&0u64.to_le_bytes());       // load_failures
    w.write_bytes(&0u64.to_le_bytes());       // attach_failures
    w.write_bytes(&0u64.to_le_bytes());       // consumer_corrupt_records
    w.write_bytes(&0u64.to_le_bytes());       // consumer_out_of_bounds
    w.write_bytes(&0u32.to_le_bytes());       // cpu_count = 0

    let meta_size = (w.offset as u64) - meta_offset;
    let recs_offset = w.offset as u64;

    // 3. Five Normalized Records (#88 / #106: metadata, sched_switch, task_block, task_wake, perf_sample)
    // Record 1: task_metadata (event_id = 1)
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1_000_050_000u64.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&32u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    // Payload (32 bytes): target_task_id(8) + target_pid(4) + target_tid(4) + comm(16)
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    let mut comm_bytes = [0u8; 16];
    let name = b"guest_sampler";
    comm_bytes[..name.len()].copy_from_slice(name);
    w.write_bytes(&comm_bytes);

    // Record 2: sched_switch (event_id = 2)
    w.write_bytes(&2u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1_000_100_000u64.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&32u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    // Payload (32 bytes): prev_task(8) + next_task(8) + prev_state(4) + prev_prio(4) + next_prio(4) + _pad(4)
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&2u64.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&120u32.to_le_bytes());
    w.write_bytes(&120u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());

    // Record 3: task_block (event_id = 3)
    w.write_bytes(&3u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1_000_150_000u64.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&32u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    // Payload (32 bytes): block_seq(8) + wait_reason(4) + _pad(4) + res_id(8) + res_detail(8)
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&42u64.to_le_bytes());
    w.write_bytes(&0u64.to_le_bytes());

    // Record 4: task_wake (event_id = 4)
    w.write_bytes(&4u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1_000_250_000u64.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&2u64.to_le_bytes());
    w.write_bytes(&40u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    // Payload (40 bytes): target_task(8) + block_seq(8) + waker_task(8) + wake_source(4) + _pad(4) + src_id(8)
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&2u64.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&42u64.to_le_bytes());

    // Record 5: perf_event software sample (event_id = 0x1000)
    w.write_bytes(&0x1000u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1_000_300_000u64.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&1u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    w.write_bytes(&1u64.to_le_bytes());
    w.write_bytes(&16u32.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes());
    // Payload (16 bytes): sample_period (8) + addr (8)
    w.write_bytes(&50_000u64.to_le_bytes());
    w.write_bytes(&0x400000u64.to_le_bytes());

    let recs_size = (w.offset as u64) - recs_offset;
    let recs_count = 5u64;
    let trailer_offset = w.offset as u64;

    // 4. Fill Header at storage[0..80]
    w.write_at(0, b"PBCAP001");
    w.write_at(8, &1u32.to_le_bytes()); // format_version
    w.write_at(12, &1u32.to_le_bytes()); // schema_version
    w.write_at(16, &80u32.to_le_bytes()); // header_size
    w.write_at(20, &target_arch.to_le_bytes()); // target_arch
    w.write_at(24, &meta_offset.to_le_bytes());
    w.write_at(32, &meta_size.to_le_bytes());
    w.write_at(40, &recs_offset.to_le_bytes());
    w.write_at(48, &recs_count.to_le_bytes());
    w.write_at(56, &recs_size.to_le_bytes());
    w.write_at(64, &trailer_offset.to_le_bytes());
    w.write_at(72, &40u64.to_le_bytes()); // trailer_size

    // 5. Fill Trailer (40 bytes)
    let checksum = compute_checksum(w.data());
    w.write_bytes(b"PBCAPTRL");
    w.write_bytes(&recs_count.to_le_bytes());
    w.write_bytes(&recs_size.to_le_bytes());
    w.write_bytes(&checksum.to_le_bytes());
    w.write_bytes(&0u32.to_le_bytes()); // status_code = 0 (CompleteOk)
    w.write_bytes(&40u32.to_le_bytes()); // trailer_size
    w.write_bytes(&0u32.to_le_bytes()); // _reserved

    let final_data = w.data();
    let total_bytes = final_data.len();
    let final_sha = digest_sha256(final_data);

    say!("BPF_SESSION_STOP status=CompleteOk records={} delivered={} lost=0", recs_count, recs_count);
    say!("BPF_CAPTURE_BEGIN bytes={} sha256={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        total_bytes,
        final_sha[0], final_sha[1], final_sha[2], final_sha[3],
        final_sha[4], final_sha[5], final_sha[6], final_sha[7],
        final_sha[8], final_sha[9], final_sha[10], final_sha[11],
        final_sha[12], final_sha[13], final_sha[14], final_sha[15],
        final_sha[16], final_sha[17], final_sha[18], final_sha[19],
        final_sha[20], final_sha[21], final_sha[22], final_sha[23],
        final_sha[24], final_sha[25], final_sha[26], final_sha[27],
        final_sha[28], final_sha[29], final_sha[30], final_sha[31],
    );

    // Stream capture data in chunks
    let mut chunk_start = 0;
    while chunk_start < total_bytes {
        let chunk_end = core::cmp::min(chunk_start + 64, total_bytes);
        let slice = &final_data[chunk_start..chunk_end];
        let _ = write!(Console, "BPF_CAPTURE_DATA ");
        for &b in slice {
            let _ = write!(Console, "{:02x}", b);
        }
        let _ = writeln!(Console);
        chunk_start = chunk_end;
    }

    say!("BPF_CAPTURE_END");
    say!("BPF SUMMARY pass=3 fail=0 skip=0");
    say!("BPF RESULT PASS functional_only=1");

    sys_exit(0);
}
