//! Actual ring-frame archive for the single-threaded freestanding sampler.
//! Anonymous mappings are privately owned here until Drop; only initialized
//! prefixes are exposed, and no mapping/borrow is handed to a BPF program.
use super::*;

#[cfg(not(fault_export_overflow))]
// Combined mapping/stack workload emits sixteen sources at 640 bytes each.
// Retain the later mapping phases without dropping the already consumed RAW.
pub const MAPPED_BYTES: usize = if cfg!(all(stack_test, mapping_test)) {
    8 * 1024 * 1024
} else {
    4 * 1024 * 1024
};
#[cfg(fault_export_overflow)]
pub const MAPPED_BYTES: usize = 4096;
const CAPACITY: usize = MAPPED_BYTES;
const STATS_CAPACITY: usize = 64 * 1024;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 { crc = (crc >> 1) ^ (0xedb88320 & (0u32.wrapping_sub(crc & 1))); }
    }
    !crc
}
struct Memory { base: usize, capacity: usize, len: usize }
impl Memory {
    fn new(capacity: usize) -> Self {
        let base = ok("archive mmap", syscall(222, 0, capacity, 3, 0x22, usize::MAX, 0));
        check!(base != 0, "archive mmap returned null");
        Self { base, capacity, len: 0 }
    }
    fn bytes(&self) -> &[u8] {
        // SAFETY: mmap returned this nonnull readable/writable private range.
        // len is increased only after successful writes/read syscall, remains
        // <= capacity, and &self prevents append or Drop during this borrow.
        unsafe { core::slice::from_raw_parts(self.base as *const u8, self.len) }
    }
    fn append(&mut self, bytes: &[u8]) {
        check!(bytes.len() <= self.capacity - self.len, "archive append exceeds mapping");
        // SAFETY: checked destination lies in the exclusively owned mapping;
        // inputs are separate ring-copy/header stack buffers, not this mapping.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), (self.base + self.len) as *mut u8, bytes.len()); }
        self.len += bytes.len();
    }
}
impl Drop for Memory {
    fn drop(&mut self) { check!(syscall(215, self.base, self.capacity, 0, 0, 0, 0) == 0, "archive munmap"); }
}
fn hex_lines(kind: &str, point: &str, data: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut hex = [0u8; 512];
    for (index, chunk) in data.chunks(256).enumerate() {
        for (i, byte) in chunk.iter().enumerate() {
            hex[2*i] = HEX[(byte >> 4) as usize];
            hex[2*i+1] = HEX[(byte & 15) as usize];
        }
        say!("ARCHIVE {} point={} offset={} hex={}", kind, point, index*256,
             core::str::from_utf8(&hex[..chunk.len()*2]).unwrap());
    }
}

pub struct Buffer { memory: Memory, frames: u64, dropped: u64, dropped_samples: u64, dropped_notices: u64, start_ns: u64 }
impl Buffer {
    pub fn new(start_ns: u64) -> Self {
        Self { memory: Memory::new(CAPACITY), frames: 0, dropped: 0, dropped_samples: 0, dropped_notices: 0, start_ns }
    }
    pub fn push(&mut self, cpu: usize, raw: &[u8]) {
        if raw.len() + 24 > self.memory.capacity - self.memory.len {
            self.dropped += 1;
            if u32_at(raw, 0) == 9 { self.dropped_samples += 1; }
            else { self.dropped_notices += 1; }
            return;
        }
        let mut header = [0u8; 24];
        put64(&mut header, 0, self.frames);
        put32(&mut header, 8, cpu as u32);
        put32(&mut header, 12, raw.len() as u32);
        put32(&mut header, 16, crc32(raw));
        self.memory.append(&header);
        self.memory.append(raw);
        self.frames += 1;
    }
    pub fn emit(self, stop_ns: u64) {
        let data = self.memory.bytes();
        let crc = crc32(data);
        say!("ARCHIVE BEGIN version=1 mode={} start_ns={} stop_ns={} frames={} bytes={} crc={} dropped={} dropped_samples={} dropped_notices={} mapped_bytes={}",
             MODE, self.start_ns, stop_ns, self.frames, data.len(), crc, self.dropped, self.dropped_samples, self.dropped_notices, self.memory.capacity);
        hex_lines("DATA", "frames", data);
        #[cfg(fault_aborted)]
        { say!("ARCHIVE INJECTED_ABORT before_trailer=1"); syscall(93, 1, 0, 0, 0, 0, 0); loop { core::hint::spin_loop(); } }
        #[cfg(not(fault_aborted))]
        say!("ARCHIVE END frames={} bytes={} crc={}", self.frames, data.len(), crc);
    }
}

fn read_stats() -> Memory {
    let path = c"/proc/pulse_bpf_stats";
    let fd = ok("open BPF diagnostics", syscall(56, (-100isize) as usize, path.as_ptr() as usize, 0, 0, 0, 0));
    let mut memory = Memory::new(STATS_CAPACITY);
    let mut tiny = [0u8; 8];
    let first = ok("read diagnostic prefix", syscall(63, fd, tiny.as_mut_ptr() as usize, tiny.len(), 0, 0, 0));
    check!(first == tiny.len(), "diagnostics missing prefix");
    memory.append(&tiny);
    // Deliberately fragmented reads exercise stable per-open snapshots, even
    // when the syscall layer splits a larger buffer at physical page edges.
    while memory.len < memory.capacity {
        let length = (memory.capacity - memory.len).min(97);
        let n = ok("read BPF diagnostics", syscall(63, fd, memory.base + memory.len, length, 0, 0, 0));
        check!(n <= length, "invalid diagnostics length");
        if n == 0 { break; }
        memory.len += n;
    }
    check!(syscall(63, fd, tiny.as_mut_ptr() as usize, tiny.len(), 0, 0, 0) == 0,
           "diagnostics exceed bound or re-rendered instead of stable EOF");
    close(fd);
    let text = core::str::from_utf8(memory.bytes()).unwrap();
    check!(text.starts_with("PULSE_BPF_STATS version=1 ") && text.contains(" available=1\n"), "diagnostics unavailable");
    check!(text.lines().last().is_some_and(|line| line.starts_with("END events=")), "missing diagnostics terminator");
    memory
}

fn sources_quiescent(memory: &Memory, sources: &[usize]) -> bool {
    check!(!sources.is_empty(), "no sources at diagnostics boundary");
    let text = core::str::from_utf8(memory.bytes()).unwrap();
    let mut quiescent = true;
    for source in sources {
        let line = text.lines().find(|line| line.starts_with("EVENT ") && field(line, "fd") == Some(*source as u64));
        check!(line.is_some(), "missing source diagnostics");
        let line = line.unwrap();
        check!(field(line, "id").is_some_and(|id| id != 0), "unknown source identity");
        check!(field(line, "enabled") == Some(0), "source not disabled at diagnostics boundary");
        let inflight = field(line, "inflight");
        check!(inflight.is_some(), "missing source inflight diagnostic");
        quiescent &= inflight == Some(0);
    }
    quiescent
}

/// Wait for accepted invocations to publish their output/counters before the
/// final ring drain. Sources were disabled by this sole control thread and will
/// not be re-enabled during the wait, so once every inflight count reaches zero
/// no new invocation can race the subsequent drain and after snapshot. Reopen
/// proc on each attempt: re-reading an old per-open snapshot cannot make progress.
pub fn wait_quiescent(sources: &[usize]) {
    const TIMEOUT_NS: u64 = 2_000_000_000;
    let start = monotonic_ns();
    let mut polls = 0u64;
    loop {
        let memory = read_stats();
        let quiescent = sources_quiescent(&memory, sources);
        drop(memory);
        polls += 1;
        let elapsed = monotonic_ns().saturating_sub(start);
        if quiescent {
            say!("ARCHIVE QUIESCENT polls={} waited_ns={}", polls, elapsed);
            return;
        }
        check!(elapsed < TIMEOUT_NS, "timed out waiting for accepted sampling invocations");
        sleep_ms(1);
    }
}

pub fn stats(point: &str, sources: &[usize]) {
    let memory = read_stats();
    check!(sources_quiescent(&memory, sources), "source still has accepted invocations");
    say!("ARCHIVE STATS_BEGIN point={} bytes={} crc={}", point, memory.len, crc32(memory.bytes()));
    hex_lines("STATS_DATA", point, memory.bytes());
    say!("ARCHIVE STATS_END point={}", point);
}
#[cfg(mapping_test)]
pub fn mappings(point: &str) {
    let path = c"/proc/pulse_bpf_mappings";
    let fd = ok("open mapping journal", syscall(56, (-100isize) as usize, path.as_ptr() as usize, 0, 0, 0, 0));
    let mut memory = Memory::new(4 * 1024 * 1024);
    while memory.len < memory.capacity {
        let length = (memory.capacity - memory.len).min(4093);
        let n = ok("read mapping journal", syscall(63, fd, memory.base + memory.len, length, 0, 0, 0));
        check!(n <= length, "invalid mapping journal length");
        if n == 0 { break; }
        memory.len += n;
    }
    let mut tail = [0u8; 8];
    check!(syscall(63, fd, tail.as_mut_ptr() as usize, tail.len(), 0, 0, 0) == 0,
           "mapping journal exceeds bound or lacks stable EOF");
    close(fd);
    check!(memory.len > 0, "empty mapping journal");
    say!("ARCHIVE MAPPINGS_BEGIN point={} bytes={} crc={}", point, memory.len, crc32(memory.bytes()));
    hex_lines("MAPPINGS_DATA", point, memory.bytes());
    say!("ARCHIVE MAPPINGS_END point={}", point);
}

fn field(line: &str, name: &str) -> Option<u64> {
    line.split_whitespace().filter_map(|token| token.split_once('='))
        .find(|(key, _)| *key == name).and_then(|(_, value)| value.parse().ok())
}

pub fn object_id(fd: usize) -> u32 {
    let mut info = [0u8; 256];
    let mut attr = [0u8; 16];
    put32(&mut attr, 0, fd as u32);
    put32(&mut attr, 4, info.len() as u32);
    put64(&mut attr, 8, info.as_mut_ptr() as u64);
    // Both attr (info_len) and info are output buffers for this syscall; use
    // mutable pointers rather than the input-only bpf() helper's shared slice.
    check!(syscall(280, 15, attr.as_mut_ptr() as usize, attr.len(), 0, 0, 0) == 0,
           "BPF object identity query failed");
    let id = u32_at(&info, 4);
    check!(id != 0, "unknown BPF object identity");
    id
}
