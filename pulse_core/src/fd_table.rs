use alloc::{
    collections::VecDeque,
    sync::Arc,
};
use core::{
    any::Any,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    time::Duration,
};

use axerrno::{LinuxError, LinuxResult};
use axfs::{File, FileFlags as AxFileFlags, OpenResult};
use axfs_ng_vfs::{Location, Metadata, NodeType};
use axio::{BufReader, PollState, Read, Seek, SeekFrom, Write};
use kspin::SpinNoIrq;
use linux_raw_sys::general::*;
use spin::{Lazy, Mutex};

use crate::cpu_dma_latency::{CpuDmaLatencyRequest, effective_latency_us};

pub const FD_RESERVED: usize = 3;
pub const FD_LIMIT: usize = 1048576;

bitflags::bitflags! {
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub struct FdFlags: u32 {
        const CLOEXEC = 1 << 0;
        const NONBLOCK = 1 << 1;
        const PATH = 1 << 2;
    }
}

pub trait FdObject: Send + Sync {
    fn as_any(&self) -> &dyn Any;

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<stat>;

    fn poll(&self) -> LinuxResult<PollState>;

    /// Waits until this object is likely ready for `events`.
    ///
    /// Returns:
    /// - `Ok(true)`: awakened for readiness (or equivalent wake event).
    /// - `Ok(false)`: timed out before readiness.
    /// - `Err(EOPNOTSUPP)`: object does not support blocking-ready wait.
    fn wait_ready(&self, _events: i16, _deadline: Option<Duration>) -> LinuxResult<bool> {
        Err(LinuxError::EOPNOTSUPP)
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        None
    }

    fn seek(&self, _pos: SeekFrom) -> LinuxResult<u64> {
        Err(LinuxError::ESPIPE)
    }

    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> LinuxResult<usize> {
        Err(LinuxError::EINVAL)
    }

    fn mmap_file_flags(&self) -> Option<AxFileFlags> {
        None
    }

    fn read_dirents64(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::ENOTDIR)
    }

    fn truncate(&self, _len: u64) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }

    fn flush(&self) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }

    fn sync_data(&self) -> LinuxResult {
        Err(LinuxError::EINVAL)
    }

    fn allocate(&self, _mode: u32, _offset: u64, _len: u64) -> LinuxResult {
        Err(LinuxError::ENODEV)
    }

    fn is_write_open(&self) -> bool {
        false
    }
}

#[derive(Clone)]
pub struct FdEntry {
    pub object: Arc<dyn FdObject>,
    pub flags: FdFlags,
}

impl FdEntry {
    pub fn new(object: Arc<dyn FdObject>, flags: FdFlags) -> Self {
        Self { object, flags }
    }
}

fn empty_stat() -> stat {
    unsafe { core::mem::zeroed() }
}

fn metadata_to_stat(metadata: &Metadata) -> stat {
    let ty = metadata.node_type as u8;
    let perm = metadata.mode.bits() as u32;
    let st_mode = ((ty as u32) << 12) | perm;
    stat {
        st_ino: metadata.inode as _,
        st_nlink: metadata.nlink as _,
        st_mode,
        st_uid: metadata.uid as _,
        st_gid: metadata.gid as _,
        st_size: metadata.size as _,
        st_blocks: metadata.blocks as _,
        st_blksize: metadata.block_size as _,
        st_atime: metadata.atime.as_secs() as _,
        st_atime_nsec: metadata.atime.subsec_nanos() as _,
        st_mtime: metadata.mtime.as_secs() as _,
        st_mtime_nsec: metadata.mtime.subsec_nanos() as _,
        st_ctime: metadata.ctime.as_secs() as _,
        st_ctime_nsec: metadata.ctime.subsec_nanos() as _,
        ..empty_stat()
    }
}

pub fn location_to_stat(location: &Location) -> LinuxResult<stat> {
    Ok(metadata_to_stat(&location.metadata()?))
}

struct StdinRaw;
struct StdoutRaw;

fn console_read_bytes(buf: &mut [u8]) -> axio::Result<usize> {
    let len = axhal::console::read_bytes(buf);
    for c in &mut buf[..len] {
        if *c == b'\r' {
            *c = b'\n';
        }
    }
    Ok(len)
}

fn console_write_bytes(buf: &[u8]) -> axio::Result<usize> {
    axhal::console::write_bytes(buf);
    Ok(buf.len())
}

static STDIN_BUFFER: Lazy<SpinNoIrq<VecDeque<u8>>> = Lazy::new(|| SpinNoIrq::new(VecDeque::new()));
pub static STDIN_WAIT_QUEUE: axtask::WaitQueue = axtask::WaitQueue::new();

impl Read for StdinRaw {
    fn read(&mut self, buf: &mut [u8]) -> axio::Result<usize> {
        let mut stdin_buf = STDIN_BUFFER.lock();
        let len = core::cmp::min(buf.len(), stdin_buf.len());
        for i in 0..len {
            buf[i] = stdin_buf.pop_front().unwrap();
        }
        Ok(len)
    }
}

pub fn poll_stdin() {
    let mut temp_buf = [0u8; 64];
    if let Ok(len) = console_read_bytes(&mut temp_buf) {
        if len > 0 {
            let mut stdin_buf = STDIN_BUFFER.lock();
            for &c in &temp_buf[..len] {
                stdin_buf.push_back(c);
            }
            STDIN_WAIT_QUEUE.notify_all(true);
        }
    }
}

impl Write for StdoutRaw {
    fn write(&mut self, buf: &[u8]) -> axio::Result<usize> {
        console_write_bytes(buf)
    }

    fn flush(&mut self) -> axio::Result {
        Ok(())
    }
}

static STDIN_READER: Lazy<Mutex<BufReader<StdinRaw>>> =
    Lazy::new(|| Mutex::new(BufReader::new(StdinRaw)));
static STDOUT_WRITER: Lazy<Mutex<StdoutRaw>> = Lazy::new(|| Mutex::new(StdoutRaw));

pub struct StdinObject;

impl StdinObject {
    fn current_has_pending_signal() -> bool {
        crate::task::current_thread()
            .map(|thread| thread.has_pending_signal())
            .unwrap_or(false)
    }
}

impl FdObject for StdinObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let read_len = STDIN_READER.lock().read(buf)?;
        if buf.is_empty() || read_len > 0 {
            return Ok(read_len);
        }
        loop {
            let read_len = STDIN_READER.lock().read(buf)?;
            if read_len > 0 {
                return Ok(read_len);
            }
            if let Ok(thread) = crate::task::current_thread() {
                if thread.has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
            }
            STDIN_WAIT_QUEUE.wait_until(|| {
                !STDIN_BUFFER.lock().is_empty()
                    || Self::current_has_pending_signal()
            });
            if Self::current_has_pending_signal() {
                return Err(LinuxError::EINTR);
            }
        }
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EPERM)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o20000 | 0o440u32,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let has_data = !STDIN_BUFFER.lock().is_empty();
        Ok(PollState {
            readable: has_data,
            writable: true,
        })
    }
}

pub struct StdoutObject;

impl FdObject for StdoutObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EPERM)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        Ok(STDOUT_WRITER.lock().write(buf)?)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o20000 | 0o220u32,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }
}

pub struct FileObject {
    inner: File,
    nonblocking: AtomicBool,
}

impl FileObject {
    pub fn new(inner: File) -> Self {
        Self {
            inner,
            nonblocking: AtomicBool::new(false),
        }
    }

    pub fn is_write_open(&self) -> bool {
        self.inner.flags().intersects(AxFileFlags::WRITE | AxFileFlags::APPEND)
    }
}

impl FdObject for FileObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let file = &self.inner;
        Ok(file.read(buf)?)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let file = &self.inner;
        Ok(file.write(buf)?)
    }

    fn stat(&self) -> LinuxResult<stat> {
        location_to_stat(self.inner.location())
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let flags = self.inner.flags();
        Ok(PollState {
            readable: flags.contains(AxFileFlags::READ),
            writable: flags.intersects(AxFileFlags::WRITE | AxFileFlags::APPEND),
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        Some(self.inner.location().clone())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        if self
            .inner
            .location()
            .flags()
            .contains(axfs_ng_vfs::NodeFlags::STREAM)
        {
            return Err(LinuxError::ESPIPE);
        }
        let mut file = &self.inner;
        Ok(file.seek(pos)?)
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> LinuxResult<usize> {
        Ok(self.inner.read_at(buf, offset)?)
    }

    fn mmap_file_flags(&self) -> Option<AxFileFlags> {
        Some(self.inner.flags())
    }

    fn truncate(&self, len: u64) -> LinuxResult {
        self.inner.access(AxFileFlags::WRITE)?.set_len(len)?;
        Ok(())
    }

    fn flush(&self) -> LinuxResult {
        self.inner.sync(false).map_err(Into::into)
    }

    fn sync_data(&self) -> LinuxResult {
        self.inner.sync(true).map_err(Into::into)
    }

    fn allocate(&self, mode: u32, offset: u64, len: u64) -> LinuxResult {
        if !self.is_write_open() {
            return Err(LinuxError::EBADF);
        }
        if len == 0 {
            return Err(LinuxError::EINVAL);
        }
        let end = offset.checked_add(len).ok_or(LinuxError::EFBIG)?;

        let metadata = self.inner.location().metadata()?;
        if metadata.node_type != NodeType::RegularFile {
            if metadata.node_type == NodeType::Directory {
                return Err(LinuxError::EISDIR);
            } else {
                return Err(LinuxError::ENODEV);
            }
        }

        if (mode & !(FALLOC_FL_KEEP_SIZE as u32)) != 0 {
            axlog::warn!("sys_fallocate: unsupported mode flags (mode={:#x})", mode);
            return Err(LinuxError::EOPNOTSUPP);
        }

        if (mode & (FALLOC_FL_KEEP_SIZE as u32)) != 0 {
            axlog::warn!(
                "sys_fallocate: FALLOC_FL_KEEP_SIZE is stubbed (mode={:#x}, offset={}, len={}) \
                 due to lack of native preallocation support in filesystem stack",
                mode,
                offset,
                len
            );
        } else {
            let cur_size = metadata.size;
            if end > cur_size {
                axlog::warn!(
                    "sys_fallocate: physical space preallocation is not supported, falling back to set_len (new_len={})",
                    end
                );
                self.inner.access(AxFileFlags::WRITE)?.set_len(end)?;
            }
        }

        Ok(())
    }

    fn is_write_open(&self) -> bool {
        self.is_write_open()
    }
}

fn parse_cpu_dma_latency_value(buf: &[u8]) -> LinuxResult<i32> {
    if buf.len() != 4 {
        return Err(LinuxError::EINVAL);
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(buf);
    Ok(i32::from_ne_bytes(bytes))
}

fn is_cpu_dma_latency_device(location: &Location) -> bool {
    let Ok(metadata) = location.metadata() else {
        return false;
    };
    metadata.node_type == NodeType::CharacterDevice
        && metadata.rdev.major() == 10
        && metadata.rdev.minor() == 63
}

pub struct CpuDmaLatencyObject {
    location: Location,
    request: Arc<CpuDmaLatencyRequest>,
    nonblocking: AtomicBool,
}

impl CpuDmaLatencyObject {
    pub fn new(location: Location) -> Self {
        Self {
            location,
            request: CpuDmaLatencyRequest::new(),
            nonblocking: AtomicBool::new(false),
        }
    }
}

impl FdObject for CpuDmaLatencyObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let bytes = effective_latency_us().to_ne_bytes();
        let n = core::cmp::min(buf.len(), bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let value = parse_cpu_dma_latency_value(buf)?;
        self.request.set_target_us(value);
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<stat> {
        location_to_stat(&self.location)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        Some(self.location.clone())
    }
}

#[repr(C, packed)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
}

pub struct DirObject {
    inner: Location,
    offset: Mutex<u64>,
    nonblocking: AtomicBool,
}

impl DirObject {
    pub fn new(inner: Location) -> Self {
        Self {
            inner,
            offset: Mutex::new(0),
            nonblocking: AtomicBool::new(false),
        }
    }
}

impl FdObject for DirObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EISDIR)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn stat(&self) -> LinuxResult<stat> {
        location_to_stat(&self.inner)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        Some(self.inner.clone())
    }

    fn flush(&self) -> LinuxResult {
        self.inner.sync(false).map_err(Into::into)
    }

    fn sync_data(&self) -> LinuxResult {
        self.inner.sync(true).map_err(Into::into)
    }

    fn read_dirents64(&self, dirp: &mut [u8]) -> LinuxResult<usize> {
        let mut offset = self.offset.lock();
        let mut written = 0usize;
        let mut break_out = false;
        let res = self.inner.read_dir(*offset, &mut |name: &str,
                                                     ino: u64,
                                                     node_type: NodeType,
                                                     next_off: u64|
         -> bool {
            if break_out {
                return false;
            }
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len();
            let unpadded_len = core::mem::size_of::<LinuxDirent64>() + name_len + 1;
            let reclen = (unpadded_len + 7) & !7;
            if written + reclen > dirp.len() {
                break_out = true;
                return false;
            }
            let dirent = LinuxDirent64 {
                d_ino: ino,
                d_off: next_off as i64,
                d_reclen: reclen as u16,
                d_type: node_type as u8,
            };
            axlog::debug!(
                "read_dirents64: emit name={}, ino={}, type={:?}, next_off={}, reclen={}",
                name,
                ino,
                node_type,
                next_off,
                reclen
            );
            unsafe {
                let dst = dirp.as_mut_ptr().add(written);
                core::ptr::write_unaligned(dst.cast::<LinuxDirent64>(), dirent);
                let name_dst = dst.add(core::mem::size_of::<LinuxDirent64>());
                core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_dst, name_len);
                core::ptr::write_bytes(
                    name_dst.add(name_len),
                    0,
                    reclen - core::mem::size_of::<LinuxDirent64>() - name_len,
                );
            }
            written += reclen;
            *offset = next_off;
            true
        });
        if written == 0 {
            res?;
        }
        Ok(written)
    }
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum RingBufferStatus {
    Full,
    Empty,
    Normal,
}

// Keep per-pipe memory bounded so socketpair-heavy workloads (e.g. hackbench)
// don't exhaust kernel heap just by creating many endpoints.
const RING_BUFFER_SIZE: usize = 4096;

struct PipeRingBuffer {
    arr: [u8; RING_BUFFER_SIZE],
    head: usize,
    tail: usize,
    status: RingBufferStatus,
}

impl PipeRingBuffer {
    const fn new() -> Self {
        Self {
            arr: [0; RING_BUFFER_SIZE],
            head: 0,
            tail: 0,
            status: RingBufferStatus::Empty,
        }
    }

    fn write_byte(&mut self, byte: u8) {
        self.status = RingBufferStatus::Normal;
        self.arr[self.tail] = byte;
        self.tail = (self.tail + 1) % RING_BUFFER_SIZE;
        if self.tail == self.head {
            self.status = RingBufferStatus::Full;
        }
    }

    fn read_byte(&mut self) -> u8 {
        self.status = RingBufferStatus::Normal;
        let byte = self.arr[self.head];
        self.head = (self.head + 1) % RING_BUFFER_SIZE;
        if self.head == self.tail {
            self.status = RingBufferStatus::Empty;
        }
        byte
    }

    const fn available_read(&self) -> usize {
        if matches!(self.status, RingBufferStatus::Empty) {
            0
        } else if self.tail > self.head {
            self.tail - self.head
        } else {
            self.tail + RING_BUFFER_SIZE - self.head
        }
    }

    const fn available_write(&self) -> usize {
        if matches!(self.status, RingBufferStatus::Full) {
            0
        } else {
            RING_BUFFER_SIZE - self.available_read()
        }
    }
}

struct PipeShared {
    buffer: Mutex<PipeRingBuffer>,
    read_wait_queue: axtask::WaitQueue,
    write_wait_queue: axtask::WaitQueue,
    reader_count: AtomicUsize,
    writer_count: AtomicUsize,
}

impl PipeShared {
    fn new() -> Self {
        Self {
            buffer: Mutex::new(PipeRingBuffer::new()),
            read_wait_queue: axtask::WaitQueue::new(),
            write_wait_queue: axtask::WaitQueue::new(),
            reader_count: AtomicUsize::new(1),
            writer_count: AtomicUsize::new(1),
        }
    }
}

pub struct PipeObject {
    readable: bool,
    shared: Arc<PipeShared>,
    nonblocking: AtomicBool,
}

impl PipeObject {
    pub fn new_pair() -> (Self, Self) {
        let shared = Arc::new(PipeShared::new());
        (
            Self {
                readable: true,
                shared: shared.clone(),
                nonblocking: AtomicBool::new(false),
            },
            Self {
                readable: false,
                shared,
                nonblocking: AtomicBool::new(false),
            },
        )
    }

    const fn writable(&self) -> bool {
        !self.readable
    }

    fn write_end_closed(&self) -> bool {
        self.shared.writer_count.load(Ordering::Acquire) == 0
    }

    fn read_end_closed(&self) -> bool {
        self.shared.reader_count.load(Ordering::Acquire) == 0
    }

    fn ready_for(&self, wait_for_read: bool, wait_for_write: bool) -> bool {
        let buffer = self.shared.buffer.lock();
        (wait_for_read && (buffer.available_read() > 0 || self.write_end_closed()))
            || (wait_for_write && (buffer.available_write() > 0 || self.read_end_closed()))
    }

    fn current_has_pending_signal() -> bool {
        crate::task::current_thread()
            .map(|thread| thread.has_pending_signal())
            .unwrap_or(false)
    }
}

impl FdObject for PipeObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if !self.readable {
            return Err(LinuxError::EPERM);
        }
        let mut read_size = 0usize;
        while read_size < buf.len() {
            let mut ring_buffer = self.shared.buffer.lock();
            let available = ring_buffer.available_read();
            if available == 0 {
                if read_size > 0 {
                    self.shared.write_wait_queue.notify_all(true);
                    return Ok(read_size);
                }
                if self.write_end_closed() {
                    return Ok(read_size);
                }
                if self.nonblocking.load(Ordering::Acquire) {
                    return Err(LinuxError::EAGAIN);
                }
                axlog::debug!(
                    "pipe read wait: tid={} shared={:p} write_closed={} nonblocking={} \
                     read_size={} want={}",
                    axtask::current().id().as_u64(),
                    Arc::as_ptr(&self.shared),
                    self.write_end_closed(),
                    self.nonblocking.load(Ordering::Acquire),
                    read_size,
                    buf.len()
                );
                drop(ring_buffer);
                self.shared.read_wait_queue.wait_until(|| {
                    let buffer = self.shared.buffer.lock();
                    buffer.available_read() > 0
                        || self.write_end_closed()
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                continue;
            }
            for _ in 0..available {
                if read_size == buf.len() {
                    self.shared.write_wait_queue.notify_all(true);
                    return Ok(read_size);
                }
                buf[read_size] = ring_buffer.read_byte();
                read_size += 1;
            }
            drop(ring_buffer);
            self.shared.write_wait_queue.notify_all(true);
        }
        Ok(read_size)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        if !self.writable() {
            return Err(LinuxError::EPERM);
        }
        let mut write_size = 0usize;
        while write_size < buf.len() {
            if self.read_end_closed() {
                return if write_size > 0 {
                    Ok(write_size)
                } else {
                    Err(LinuxError::EPIPE)
                };
            }
            let mut ring_buffer = self.shared.buffer.lock();
            let available = ring_buffer.available_write();
            if available == 0 {
                if self.nonblocking.load(Ordering::Acquire) {
                    return if write_size > 0 {
                        Ok(write_size)
                    } else {
                        Err(LinuxError::EAGAIN)
                    };
                }
                axlog::info!(
                    "pipe write wait: tid={} shared={:p} read_closed={} nonblocking={} \
                     write_size={} want={}",
                    axtask::current().id().as_u64(),
                    Arc::as_ptr(&self.shared),
                    self.read_end_closed(),
                    self.nonblocking.load(Ordering::Acquire),
                    write_size,
                    buf.len()
                );
                drop(ring_buffer);
                self.shared.write_wait_queue.wait_until(|| {
                    let buffer = self.shared.buffer.lock();
                    buffer.available_write() > 0
                        || self.read_end_closed()
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return if write_size > 0 {
                        Ok(write_size)
                    } else {
                        Err(LinuxError::EINTR)
                    };
                }
                continue;
            }
            for _ in 0..available {
                if write_size == buf.len() {
                    self.shared.read_wait_queue.notify_all(true);
                    return Ok(write_size);
                }
                ring_buffer.write_byte(buf[write_size]);
                write_size += 1;
            }
            drop(ring_buffer);
            self.shared.read_wait_queue.notify_all(true);
        }
        Ok(write_size)
    }

    fn stat(&self) -> LinuxResult<stat> {
        Ok(stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode: 0o10000 | 0o600u32,
            st_uid: 1000,
            st_gid: 1000,
            st_blksize: 4096,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let buffer = self.shared.buffer.lock();
        Ok(PollState {
            readable: self.readable && (buffer.available_read() > 0 || self.write_end_closed()),
            writable: self.writable() && (buffer.available_write() > 0 || self.read_end_closed()),
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn wait_ready(&self, events: i16, deadline: Option<Duration>) -> LinuxResult<bool> {
        let wait_for_read = self.readable && (events & (POLLIN as i16)) != 0;
        let wait_for_write = self.writable() && (events & (POLLOUT as i16)) != 0;
        if !wait_for_read && !wait_for_write {
            return Err(LinuxError::EOPNOTSUPP);
        }

        if self.ready_for(wait_for_read, wait_for_write) {
            return Ok(true);
        }

        let wq = if wait_for_read {
            &self.shared.read_wait_queue
        } else {
            &self.shared.write_wait_queue
        };

        match deadline {
            Some(deadline) => {
                let now = axhal::time::monotonic_time();
                if now >= deadline {
                    return Ok(self.ready_for(wait_for_read, wait_for_write));
                }
                let remain = deadline - now;
                wq.wait_timeout_until(remain, || {
                    self.ready_for(wait_for_read, wait_for_write)
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                Ok(self.ready_for(wait_for_read, wait_for_write))
            }
            None => {
                wq.wait_until(|| {
                    self.ready_for(wait_for_read, wait_for_write)
                        || Self::current_has_pending_signal()
                });
                if Self::current_has_pending_signal() {
                    return Err(LinuxError::EINTR);
                }
                Ok(true)
            }
        }
    }

    fn allocate(&self, _mode: u32, _offset: u64, _len: u64) -> LinuxResult {
        Err(LinuxError::ESPIPE)
    }
}

impl Drop for PipeObject {
    fn drop(&mut self) {
        if self.readable {
            self.shared.reader_count.fetch_sub(1, Ordering::AcqRel);
            // Closing a pipe during process teardown should only wake waiters.
            // Let the scheduler decide when to reschedule instead of doing it
            // from inside `drop()`.
            self.shared.write_wait_queue.notify_all(false);
        } else {
            self.shared.writer_count.fetch_sub(1, Ordering::AcqRel);
            self.shared.read_wait_queue.notify_all(false);
        }
    }
}

pub fn stdio_entries() -> [FdEntry; 3] {
    [
        FdEntry::new(Arc::new(StdinObject), FdFlags::empty()),
        FdEntry::new(Arc::new(StdoutObject), FdFlags::empty()),
        FdEntry::new(Arc::new(StdoutObject), FdFlags::empty()),
    ]
}

pub fn open_result_to_entry(result: OpenResult, flags: FdFlags) -> FdEntry {
    let object: Arc<dyn FdObject> = match result {
        OpenResult::File(file) => {
            if is_cpu_dma_latency_device(file.location()) {
                Arc::new(CpuDmaLatencyObject::new(file.location().clone()))
            } else {
                Arc::new(FileObject::new(file))
            }
        }
        OpenResult::Dir(dir) => Arc::new(DirObject::new(dir)),
    };
    if flags.contains(FdFlags::NONBLOCK) {
        let _ = object.set_nonblocking(true);
    }
    FdEntry::new(object, flags)
}

pub fn pipe_entries(flags: FdFlags) -> (FdEntry, FdEntry) {
    let (read_end, write_end) = PipeObject::new_pair();
    let read_object: Arc<dyn FdObject> = Arc::new(read_end);
    let write_object: Arc<dyn FdObject> = Arc::new(write_end);
    if flags.contains(FdFlags::NONBLOCK) {
        let _ = read_object.set_nonblocking(true);
        let _ = write_object.set_nonblocking(true);
    }
    (
        FdEntry::new(read_object, flags),
        FdEntry::new(write_object, flags),
    )
}

#[derive(Default)]
pub struct FdTable {
    entries: alloc::vec::Vec<Option<FdEntry>>,
    count: usize,
}

impl FdTable {
    pub fn new() -> Self {
        Self {
            entries: alloc::vec::Vec::new(),
            count: 0,
        }
    }

    pub fn clone_for_fork(&self) -> LinuxResult<Self> {
        Ok(Self {
            entries: self.entries.clone(),
            count: self.count,
        })
    }

    pub fn take_cloexec_on_exec(&mut self) -> alloc::vec::Vec<FdEntry> {
        let mut removed = alloc::vec::Vec::new();
        for (fd, slot) in self.entries.iter_mut().enumerate() {
            if let Some(entry) = slot {
                if entry.flags.contains(FdFlags::CLOEXEC) {
                    axlog::info!(
                        "take_cloexec_on_exec: removing cloexec fd entry fd={}, flags={:?}, \
                         object={:p}",
                        fd,
                        entry.flags,
                        Arc::as_ptr(&entry.object)
                    );
                    if let Some(taken) = slot.take() {
                        removed.push(taken);
                        self.count = self.count.saturating_sub(1);
                    }
                }
            }
        }
        removed
    }

    pub fn drain_all(&mut self) -> alloc::vec::Vec<FdEntry> {
        let mut removed = alloc::vec::Vec::new();
        for slot in self.entries.iter_mut() {
            if let Some(entry) = slot.take() {
                removed.push(entry);
            }
        }
        self.count = 0;
        removed
    }

    pub fn clone_all_entries(&self) -> alloc::vec::Vec<FdEntry> {
        self.entries.iter().filter_map(|slot| slot.clone()).collect()
    }

    pub fn is_file_write_open(&self, path: &str) -> bool {
        for slot in &self.entries {
            if let Some(entry) = slot {
                if entry.object.is_write_open() {
                    if let Some(loc) = entry.object.location() {
                        if let Ok(abs_path) = loc.absolute_path() {
                            if abs_path.as_str() == path {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    pub fn get(&self, fd: usize) -> Option<&FdEntry> {
        self.entries.get(fd).and_then(|slot| slot.as_ref())
    }

    pub fn get_entry_cloned(&self, fd: usize) -> LinuxResult<FdEntry> {
        self.get(fd).cloned().ok_or(LinuxError::EBADF)
    }

    pub fn get_object(&self, fd: usize) -> LinuxResult<Arc<dyn FdObject>> {
        Ok(self.get_entry_cloned(fd)?.object)
    }

    pub fn get_location(&self, fd: usize) -> LinuxResult<Location> {
        self.get_object(fd)?.location().ok_or(LinuxError::EBADF)
    }

    pub fn get_mut(&mut self, fd: usize) -> Option<&mut FdEntry> {
        self.entries.get_mut(fd).and_then(|slot| slot.as_mut())
    }

    pub fn insert_at(&mut self, fd: usize, entry: FdEntry) -> LinuxResult {
        if fd >= FD_LIMIT {
            return Err(LinuxError::EBADF);
        }
        if fd >= self.entries.len() {
            let mut new_len = core::cmp::max(16, self.entries.len());
            while new_len <= fd {
                new_len = new_len.saturating_mul(2);
            }
            new_len = core::cmp::min(new_len, FD_LIMIT);
            if fd >= new_len {
                return Err(LinuxError::EMFILE);
            }
            self.entries.resize_with(new_len, || None);
        }
        if self.entries[fd].is_none() {
            self.count = self.count.saturating_add(1);
        }
        self.entries[fd] = Some(entry);
        Ok(())
    }

    pub fn insert_from(&mut self, min_fd: usize, entry: FdEntry) -> LinuxResult<usize> {
        let mut found_fd = None;
        if min_fd < self.entries.len() {
            for (fd, slot) in self.entries.iter().enumerate().skip(min_fd) {
                if slot.is_none() {
                    found_fd = Some(fd);
                    break;
                }
            }
        }

        let fd = match found_fd {
            Some(fd) => fd,
            None => {
                let next_fd = core::cmp::max(min_fd, self.entries.len());
                if next_fd >= FD_LIMIT {
                    return Err(LinuxError::EMFILE);
                }
                next_fd
            }
        };

        if fd >= self.entries.len() {
            let mut new_len = core::cmp::max(16, self.entries.len());
            while new_len <= fd {
                new_len = new_len.saturating_mul(2);
            }
            new_len = core::cmp::min(new_len, FD_LIMIT);
            if fd >= new_len {
                return Err(LinuxError::EMFILE);
            }
            self.entries.resize_with(new_len, || None);
        }

        if self.entries[fd].is_none() {
            self.count = self.count.saturating_add(1);
        }
        self.entries[fd] = Some(entry);
        Ok(fd)
    }

    pub fn insert_next(&mut self, entry: FdEntry) -> LinuxResult<usize> {
        self.insert_from(0, entry)
    }

    pub fn remove(&mut self, fd: usize) -> Option<FdEntry> {
        if fd < self.entries.len() {
            let res = self.entries[fd].take();
            if res.is_some() {
                self.count = self.count.saturating_sub(1);
            }
            res
        } else {
            None
        }
    }

    pub fn remove_or_err(&mut self, fd: usize) -> LinuxResult<FdEntry> {
        self.remove(fd).ok_or(LinuxError::EBADF)
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

pub type SharedFdTable = Arc<Mutex<FdTable>>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::any::Any;

    struct DummyObject;

    impl FdObject for DummyObject {
        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn test_fd_table_is_empty_and_state() {
        let mut table = FdTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        let entry1 = FdEntry::new(Arc::new(DummyObject), FdFlags::empty());
        let fd1 = table.insert_next(entry1.clone()).expect("Failed to insert");
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        let entry2 = FdEntry::new(Arc::new(DummyObject), FdFlags::empty());
        let fd2 = table.insert_next(entry2).expect("Failed to insert");
        assert!(!table.is_empty());
        assert_eq!(table.len(), 2);

        table.remove(fd1);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        table.remove(fd2);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_fd_table_out_of_bounds_insert_and_failed_removals() {
        let mut table = FdTable::new();
        assert!(table.is_empty());

        let entry = FdEntry::new(Arc::new(DummyObject), FdFlags::empty());
        table.insert_at(10, entry).expect("Failed to insert at 10");
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        assert!(table.remove(99).is_none());
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        assert!(table.remove(10).is_some());
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);

        assert!(table.remove(10).is_none());
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_fd_table_drain_all_and_take_cloexec() {
        let mut table = FdTable::new();

        let entry1 = FdEntry::new(Arc::new(DummyObject), FdFlags::CLOEXEC);
        table.insert_next(entry1).expect("Failed to insert");

        let entry2 = FdEntry::new(Arc::new(DummyObject), FdFlags::empty());
        table.insert_next(entry2).expect("Failed to insert");

        assert!(!table.is_empty());
        assert_eq!(table.len(), 2);

        let removed = table.take_cloexec_on_exec();
        assert_eq!(removed.len(), 1);
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);

        let drained = table.drain_all();
        assert_eq!(drained.len(), 1);
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
    }
}
