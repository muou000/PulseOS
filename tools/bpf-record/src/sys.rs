//! Private RV64/LA64 Linux-shaped syscall boundary. All owned FDs and mappings
//! are released exactly once. The kernel ABI is the platform trust boundary.
//! Safety contracts: <https://doc.rust-lang.org/core/alloc/trait.GlobalAlloc.html>
//! and <https://doc.rust-lang.org/core/ptr/fn.read_volatile.html>.
use alloc::{format, string::String, vec::Vec};
use core::{
    alloc::{GlobalAlloc, Layout},
    arch::asm,
    sync::atomic::{AtomicUsize, Ordering},
};

pub type Result<T> = core::result::Result<T, String>;
static FDS: AtomicUsize = AtomicUsize::new(0);
static MAPPINGS: AtomicUsize = AtomicUsize::new(0);
pub fn resources() -> (usize, usize) {
    (
        FDS.load(Ordering::Relaxed),
        MAPPINGS.load(Ordering::Relaxed),
    )
}

/// # Safety
/// Arguments must obey the named syscall's pointer, extent and lifetime
/// contract; buffers it writes must be exclusively writable until return.
unsafe fn raw(n: usize, a: usize, b: usize, c: usize, d: usize, e: usize, f: usize) -> isize {
    let out;
    // SAFETY: caller supplies the syscall-specific buffer contract. Both target
    // ABIs use these registers; syscall preserves SP and other Rust registers.
    // No nomem/pure flag permits reordering memory across kernel accesses.
    unsafe {
        #[cfg(target_arch = "riscv64")]
        asm!("ecall", inlateout("a0") a => out, in("a1") b, in("a2") c,
             in("a3") d, in("a4") e, in("a5") f, in("a7") n, options(nostack));
        #[cfg(target_arch = "loongarch64")]
        asm!("syscall 0", inlateout("$r4") a => out, in("$r5") b, in("$r6") c,
             in("$r7") d, in("$r8") e, in("$r9") f, in("$r11") n, options(nostack));
    }
    out
}
fn checked(op: &str, value: isize) -> Result<usize> {
    if value < 0 {
        Err(format!("{op}: errno={}", -value))
    } else {
        Ok(value as usize)
    }
}
pub fn exit(code: usize) -> ! {
    // SAFETY: exit_group has only a scalar argument and never returns normally.
    unsafe {
        raw(94, code, 0, 0, 0, 0, 0);
    }
    loop {
        core::hint::spin_loop();
    }
}
pub fn print(text: &str) {
    let _ = write_fd(2, text.as_bytes());
}
fn write_fd(fd: usize, mut bytes: &[u8]) -> Result<()> {
    while !bytes.is_empty() {
        // SAFETY: the immutable initialized slice remains live for synchronous write.
        let n = unsafe { raw(64, fd, bytes.as_ptr() as usize, bytes.len(), 0, 0, 0) };
        if n == -4 {
            continue;
        }
        let n = checked("write", n)?;
        if n == 0 || n > bytes.len() {
            return Err("write made invalid progress".into());
        }
        bytes = &bytes[n..];
    }
    Ok(())
}

pub struct Fd(usize);
impl Fd {
    fn own(result: isize, op: &str) -> Result<Self> {
        let fd = checked(op, result)?;
        FDS.fetch_add(1, Ordering::Relaxed);
        Ok(Self(fd))
    }
    pub fn number(&self) -> usize {
        self.0
    }
    pub fn open(path: &str, write: bool) -> Result<Self> {
        if path.as_bytes().contains(&0) {
            return Err("NUL in path".into());
        }
        let mut path = path.as_bytes().to_vec();
        path.push(0);
        // SAFETY: path is NUL terminated and lives through openat; mode is scalar.
        let result = unsafe {
            raw(
                56,
                -100isize as usize,
                path.as_ptr() as usize,
                if write {
                    1 | 64 | 512 | 0x80000
                } else {
                    0x80000
                },
                0o644,
                0,
                0,
            )
        };
        Self::own(result, "openat")
    }
    pub fn read(&self, bytes: &mut [u8]) -> Result<usize> {
        // SAFETY: bytes grants exclusive initialized writable storage for its length.
        let n = unsafe {
            raw(
                63,
                self.0,
                bytes.as_mut_ptr() as usize,
                bytes.len(),
                0,
                0,
                0,
            )
        };
        let n = checked("read", n)?;
        if n > bytes.len() {
            return Err("read exceeded buffer".into());
        }
        Ok(n)
    }
    pub fn write_all(&self, bytes: &[u8]) -> Result<()> {
        write_fd(self.0, bytes)
    }
    pub fn sync(&self) -> Result<()> {
        // SAFETY: fsync takes only an owned descriptor.
        checked("fsync", unsafe { raw(82, self.0, 0, 0, 0, 0, 0) }).map(|_| ())
    }
    pub fn enable(&self, enabled: bool) -> Result<()> {
        // SAFETY: these perf ioctls take no pointer argument.
        checked("perf ioctl", unsafe {
            raw(
                29,
                self.0,
                if enabled { 0x2400 } else { 0x2401 },
                0,
                0,
                0,
                0,
            )
        })
        .map(|_| ())
    }
    pub fn duplicate(&self) -> Result<Self> {
        // SAFETY: dup takes only an owned descriptor and returns a new ownership.
        Self::own(unsafe { raw(23, self.0, 0, 0, 0, 0, 0) }, "dup")
    }
    pub fn detach_link(&self) -> Result<()> {
        let mut attr = (self.0 as u32).to_le_bytes();
        // SAFETY: LINK_DETACH reads only this initialized scalar link FD attr.
        unsafe { bpf_call(34, &mut attr) }
    }
    pub fn perf(attr: &[u8; 64], pid: isize, cpu: isize) -> Result<Self> {
        // SAFETY: the entire fixed attr is readable for the synchronous syscall.
        Self::own(
            unsafe {
                raw(
                    241,
                    attr.as_ptr() as usize,
                    pid as usize,
                    cpu as usize,
                    usize::MAX,
                    8,
                    0,
                )
            },
            "perf_event_open",
        )
    }
    /// # Safety
    /// All pointers encoded in attr must refer to valid live input or exclusive
    /// output buffers with the lengths prescribed by this BPF command.
    pub unsafe fn bpf(command: usize, attr: &[u8]) -> Result<Self> {
        // SAFETY: attr itself is readable; caller proves every embedded pointer.
        Self::own(
            unsafe { raw(280, command, attr.as_ptr() as usize, attr.len(), 0, 0, 0) },
            "bpf create/load",
        )
    }
    pub fn object_id(&self) -> Result<u32> {
        let mut info = [0u8; 256];
        let mut attr = [0u8; 16];
        attr[..4].copy_from_slice(&(self.0 as u32).to_le_bytes());
        attr[4..8].copy_from_slice(&(info.len() as u32).to_le_bytes());
        attr[8..].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
        // SAFETY: attr describes the exclusively borrowed info buffer exactly.
        unsafe {
            bpf_call(15, &mut attr)?;
        }
        Ok(u32::from_le_bytes(info[4..8].try_into().unwrap()))
    }
}
impl Drop for Fd {
    fn drop(&mut self) {
        // SAFETY: unique FD ownership; no wrapper exposes close or transfers it.
        unsafe {
            raw(57, self.0, 0, 0, 0, 0, 0);
        }
        FDS.fetch_sub(1, Ordering::Relaxed);
    }
}
/// # Safety
/// attr and any embedded pointer must obey the selected BPF command; encoded
/// writable ranges must remain exclusively borrowed until the call returns.
pub unsafe fn bpf_call(command: usize, attr: &mut [u8]) -> Result<()> {
    // SAFETY: exclusive attr covers top-level writeback, caller covers its pointers.
    checked("bpf", unsafe {
        raw(
            280,
            command,
            attr.as_mut_ptr() as usize,
            attr.len(),
            0,
            0,
            0,
        )
    })
    .map(|_| ())
}
pub fn read_file(path: &str, limit: usize) -> Result<String> {
    String::from_utf8(read_bytes(path, limit)?).map_err(|_| "invalid UTF-8 in proc snapshot".into())
}
/// Read an existing file through the owned descriptor boundary, with a hard
/// allocation bound. Binary ELF bytes must never pass through UTF-8 decoding.
pub fn read_bytes(path: &str, limit: usize) -> Result<Vec<u8>> {
    let fd = Fd::open(path, false)?;
    let mut result = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = fd.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        if result.len().saturating_add(n) > limit {
            return Err("file exceeds read limit".into());
        }
        result.extend_from_slice(&chunk[..n]);
    }
    Ok(result)
}
pub fn now() -> Result<u64> {
    let mut time = [0i64; 2];
    // SAFETY: timespec is two 64-bit fields; buffer is exclusive and initialized.
    checked("clock_gettime", unsafe {
        raw(113, 1, time.as_mut_ptr() as usize, 0, 0, 0, 0)
    })?;
    if time[0] < 0 || !(0..1_000_000_000).contains(&time[1]) {
        return Err("invalid monotonic time".into());
    }
    Ok(time[0] as u64 * 1_000_000_000 + time[1] as u64)
}
pub fn sleep_ms(ms: u64) -> Result<()> {
    let time = [(ms / 1000) as i64, ((ms % 1000) * 1_000_000) as i64];
    // SAFETY: initialized timespec remains readable, null remainder requests no write.
    let r = unsafe { raw(101, time.as_ptr() as usize, 0, 0, 0, 0, 0) };
    if r == -4 {
        Ok(())
    } else {
        checked("nanosleep", r).map(|_| ())
    }
}
pub fn target_exists(tid: u32) -> Result<bool> {
    // SAFETY: tkill(signal=0) probes identity without pointer arguments or delivery.
    let r = unsafe { raw(130, tid as usize, 0, 0, 0, 0, 0) };
    if r == -3 {
        Ok(false)
    } else {
        checked("target probe", r).map(|_| true)
    }
}
pub struct Signals {
    fd: Fd,
    previous: u64,
    actions: [[u64; 3]; 2],
}
fn signal_action(signal: usize, new: &[u64; 3], old: &mut [u64; 3]) -> Result<()> {
    // SAFETY: both supported targets use handler/flags/mask as three u64 words;
    // new is initialized and readable; distinct old is exclusively writable.
    checked("sigaction", unsafe {
        raw(
            134,
            signal,
            new.as_ptr() as usize,
            old.as_mut_ptr() as usize,
            8,
            0,
            0,
        )
    })
    .map(|_| ())
}
impl Signals {
    pub fn new() -> Result<Self> {
        let mask = (1u64 << 1) | (1u64 << 14);
        let mut previous = 0u64;
        // SAFETY: both masks have the ABI's 8-byte size and distinct live storage.
        checked("sigprocmask", unsafe {
            raw(
                135,
                0,
                &mask as *const u64 as usize,
                &mut previous as *mut u64 as usize,
                8,
                0,
                0,
            )
        })?;
        let mut actions = [[0u64; 3]; 2];
        for (index, signal) in [2, 15].into_iter().enumerate() {
            if let Err(error) = signal_action(signal, &[0; 3], &mut actions[index]) {
                for restored in 0..index {
                    let _ = signal_action([2, 15][restored], &actions[restored], &mut [0; 3]);
                }
                // SAFETY: previous is the prior valid mask returned above.
                unsafe {
                    raw(135, 2, &previous as *const u64 as usize, 0, 8, 0, 0);
                }
                return Err(error);
            }
        }
        // SAFETY: mask remains readable; signalfd creates a nonblocking owned FD.
        let fd = match Fd::own(
            unsafe {
                raw(
                    74,
                    usize::MAX,
                    &mask as *const u64 as usize,
                    8,
                    0x800 | 0x80000,
                    0,
                    0,
                )
            },
            "signalfd",
        ) {
            Ok(fd) => fd,
            Err(error) => {
                for (index, signal) in [2, 15].into_iter().enumerate() {
                    let _ = signal_action(signal, &actions[index], &mut [0; 3]);
                }
                // SAFETY: previous contains the successfully fetched prior mask.
                unsafe {
                    raw(135, 2, &previous as *const u64 as usize, 0, 8, 0, 0);
                }
                return Err(error);
            }
        };
        Ok(Self {
            fd,
            previous,
            actions,
        })
    }
    pub fn poll(&self) -> Result<Option<u32>> {
        let mut info = [0u8; 128];
        // SAFETY: complete signalfd_siginfo buffer is exclusively writable.
        let n = unsafe {
            raw(
                63,
                self.fd.0,
                info.as_mut_ptr() as usize,
                info.len(),
                0,
                0,
                0,
            )
        };
        if n == -11 || n == -4 {
            return Ok(None);
        }
        if checked("signalfd read", n)? != info.len() {
            return Err("short signal record".into());
        }
        Ok(Some(u32::from_le_bytes(info[..4].try_into().unwrap())))
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        for (index, signal) in [2, 15].into_iter().enumerate() {
            let _ = signal_action(signal, &self.actions[index], &mut [0; 3]);
        }
        // SAFETY: restore the original scalar mask from this live field.
        unsafe {
            raw(135, 2, &self.previous as *const u64 as usize, 0, 8, 0, 0);
        }
    }
}

/// Privately owns exactly one shared mmap. No borrowed reference to its bytes
/// escapes; users must observe the perf publication protocol before reads.
pub struct Mapping {
    // Safety invariant: base is nonzero and page-aligned, and [base,base+size)
    // is one live shared perf mmap uniquely owned by this value until Drop.
    // The mapping starts with initialized ABI metadata, including aligned atomic
    // head/tail fields. No constructor or method exposes the address for unmap.
    base: usize,
    // Safety invariant: 8192 <= size <= isize::MAX, page-multiple, and
    // base+size does not wrap. Bytes after the first page are perf ring storage;
    // only acquired published unread bytes may be copied by Session::drain.
    size: usize,
}
impl Mapping {
    pub fn ring(fd: &Fd, size: usize) -> Result<Self> {
        if size < 8192 || size > isize::MAX as usize || size % 4096 != 0 {
            return Err("invalid mmap size".into());
        }
        // SAFETY: null hint, shared owned file mapping; no fixed mappings replace Rust data.
        let base = checked("mmap ring", unsafe { raw(222, 0, size, 3, 1, fd.0, 0) })?;
        if base == 0 || base % 4096 != 0 || base.checked_add(size).is_none() {
            // SAFETY: mmap succeeded; this unpublished mapping is still uniquely
            // owned here and no pointer/reference into it has been constructed.
            unsafe {
                raw(215, base, size, 0, 0, 0, 0);
            }
            return Err("invalid mmap alignment".into());
        }
        MAPPINGS.fetch_add(size, Ordering::Relaxed);
        // Construction proof: the checked extent is aligned and nonwrapping.
        // The only caller supplies an owned BPF_OUTPUT FD; successful perf mmap
        // creates initialized metadata and storage (kernel PerfBuffer contract).
        // No mapping address escapes, so Self assumes sole unmap ownership.
        Ok(Self { base, size })
    }
    pub fn head(&self) -> u64 {
        // SAFETY: live mapping has initialized aligned u64 at perf offset 1024;
        // kernel publishes head atomically and acquire orders subsequent bytes.
        unsafe {
            core::sync::atomic::AtomicU64::from_ptr((self.base + 1024) as *mut u64)
                .load(Ordering::Acquire)
        }
    }
    pub fn tail(&self, tail: u64) {
        // SAFETY: live mapping contains aligned tail, exclusively written by this
        // sole consumer; release prevents producer reuse before preceding copies.
        unsafe {
            core::sync::atomic::AtomicU64::from_ptr((self.base + 1032) as *mut u64)
                .store(tail, Ordering::Release);
        }
    }
    /// Closed call invariant: only Session::drain calls this method, using this
    /// mapping's acquired head and its sole consumer's unpublished tail. It
    /// publishes a new tail only after copying the complete frame. Bounds alone
    /// would not prove publication or absence of concurrent producer reuse.
    pub fn copy_published(&self, tail: u64, head: u64, offset: u64, out: &mut [u8]) -> Result<()> {
        let size = self.size - 4096;
        if head.wrapping_sub(tail) > size as u64
            || offset.wrapping_sub(tail) > head.wrapping_sub(tail)
            || out.len() as u64 > head.wrapping_sub(offset)
        {
            return Err("unpublished perf bytes".into());
        }
        for (i, byte) in out.iter_mut().enumerate() {
            let at = offset.wrapping_add(i as u64) as usize % size;
            // SAFETY: the closed Session::drain call invariant supplies the
            // actual acquired head and unpublished tail for this mapping.
            // The checked range lies in acquired unread [tail,head); kernel
            // cannot reuse it until our later tail publication. at bounds each
            // initialized byte within the owned mapping, including ring wrap.
            *byte = unsafe { core::ptr::read_volatile((self.base + 4096 + at) as *const u8) };
        }
        Ok(())
    }
}
impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: unique mapping ownership and no references escape its methods.
        unsafe {
            raw(215, self.base, self.size, 0, 0, 0, 0);
        }
        MAPPINGS.fetch_sub(self.size, Ordering::Relaxed);
    }
}

// One process-lifetime reservation prevents allocator activity from generating
// thousands of VMA revisions in the very mapping journal being observed.
static HEAP: spin::Mutex<Option<bpf_record::arena::ArenaHeap>> = spin::Mutex::new(None);

pub fn heap_resources() -> bpf_record::arena::HeapStats {
    HEAP.lock()
        .as_ref()
        .map_or_else(Default::default, |heap| heap.stats())
}

pub struct ProcessAllocator;
// SAFETY: the private mutex serializes lazy initialization and all buddy state.
// Only one successfully initialized anonymous mapping enters HEAP, remains live
// until process exit, and is never exposed except through disjoint allocator
// blocks. ArenaHeap checks initialization/layout arithmetic and the opted-in
// buddy heap preserves free-list ownership; caller-owned allocated bytes are
// untouched until the matching dealloc. Failure returns null without a second
// backing region. The lock, raw scalar syscalls and bounded buddy operations
// allocate nothing, invoke no callbacks and have no reachable panic under these
// invariants. This binary installs no userspace signal handlers that could
// reenter the allocator; its signal handling uses blocked signals/signalfd.
unsafe impl GlobalAlloc for ProcessAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        use bpf_record::arena::{ArenaHeap, MAX_ARENA_BYTES};
        if layout.size() == 0
            || layout
                .size()
                .checked_next_power_of_two()
                .is_none_or(|size| size.max(layout.align()) > MAX_ARENA_BYTES)
        {
            return core::ptr::null_mut();
        }
        let mut guard = HEAP.lock();
        if guard.is_none() {
            // SAFETY: mmap uses a null hint, anonymous private RW storage, no
            // MAP_FIXED replacement and no input/output user-memory pointers.
            let address = unsafe { raw(222, 0, MAX_ARENA_BYTES, 3, 0x22, usize::MAX, 0) };
            if address < 0 {
                return core::ptr::null_mut();
            }
            // SAFETY: successful anonymous mmap exclusively owns one writable
            // MAX_ARENA_BYTES region. No pointer/reference to its bytes escaped.
            // Once installed in static HEAP it is never unmapped until kernel
            // process teardown, outliving every allocation on every thread.
            let arena = unsafe { ArenaHeap::from_region(address as *mut u8, MAX_ARENA_BYTES) };
            let Some(arena) = arena else {
                // SAFETY: the failed constructor retained no region or block;
                // this is precisely the still-exclusive successful mmap span.
                unsafe {
                    raw(215, address as usize, MAX_ARENA_BYTES, 0, 0, 0, 0);
                }
                return core::ptr::null_mut();
            };
            *guard = Some(arena);
        }
        guard
            .as_mut()
            .and_then(|heap| heap.allocate(layout))
            .map_or(core::ptr::null_mut(), |pointer| pointer.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let Some(pointer) = core::ptr::NonNull::new(ptr) else {
            return;
        };
        if let Some(heap) = HEAP.lock().as_mut() {
            // SAFETY: GlobalAlloc's caller supplies a currently live block from
            // this allocator and its exact original Layout, with all accesses
            // ended. The private arena is its unique owner and the mutex grants
            // exclusive free-list access; this call retires that block once.
            unsafe { heap.deallocate(pointer, layout) };
        }
    }
}
