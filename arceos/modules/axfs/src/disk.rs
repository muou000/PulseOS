use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
};
use core::mem;

use async_trait::async_trait;
use axdriver::{AxBlockDevice, prelude::*};
use futures_util::{StreamExt, stream::FuturesUnordered};
use spin::Mutex;

fn take<'a>(buf: &mut &'a [u8], cnt: usize) -> &'a [u8] {
    let (first, rem) = buf.split_at(cnt);
    *buf = rem;
    first
}

fn take_mut<'a>(buf: &mut &'a mut [u8], cnt: usize) -> &'a mut [u8] {
    // use mem::take to circumvent lifetime issues
    let (first, rem) = mem::take(buf).split_at_mut(cnt);
    *buf = rem;
    first
}

/// A cheaply-cloneable handle around an async-capable block device.
///
/// Async operations use shared receivers, so independent requests can reach
/// the driver's queue concurrently. The synchronous trait surface remains as
/// a compatibility bridge and blocks only the calling task on the same future.
#[derive(Clone)]
pub struct SharedBlockDevice {
    name: String,
    dev: Arc<dyn DynAsyncBlockDriverOps + Send + Sync>,
}

impl SharedBlockDevice {
    /// Wraps a block device so the same underlying driver can be reused.
    pub fn new(dev: AxBlockDevice) -> Self {
        let name = dev.device_name().to_string();
        let dev: Arc<dyn DynAsyncBlockDriverOps + Send + Sync> = Arc::from(dev);
        Self { name, dev }
    }

    /// Builds a `SharedBlockDevice` from a pre-existing shared driver handle.
    pub fn from_arc(dev: Arc<dyn DynAsyncBlockDriverOps + Send + Sync>) -> Self {
        let name = dev.device_name().to_string();
        Self { name, dev }
    }

    /// Returns the total size of the device in bytes.
    pub fn size(&self) -> u64 {
        self.dev
            .num_blocks()
            .saturating_mul(self.dev.block_size() as u64)
    }

    /// Returns the device block size.
    pub fn block_size(&self) -> usize {
        self.dev.block_size()
    }
}

impl BaseDriverOps for SharedBlockDevice {
    fn device_name(&self) -> &str {
        &self.name
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for SharedBlockDevice {
    fn num_blocks(&self) -> u64 {
        self.dev.num_blocks()
    }

    fn block_size(&self) -> usize {
        self.dev.block_size()
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        axtask::future::block_on(self.dev.read_block_async_dyn(block_id, buf))
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        axtask::future::block_on(self.dev.write_block_async_dyn(block_id, buf))
    }

    fn flush(&mut self) -> DevResult {
        axtask::future::block_on(self.dev.flush_async_dyn())
    }
}

impl AsyncBlockDriverOps for SharedBlockDevice {
    type ReadFuture<'a>
        = core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>
    where
        Self: 'a;
    type WriteFuture<'a>
        = core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>
    where
        Self: 'a;
    type FlushFuture<'a>
        = core::pin::Pin<Box<dyn core::future::Future<Output = DevResult> + Send + 'a>>
    where
        Self: 'a;

    fn read_block_async<'a>(&'a self, block_id: u64, buf: &'a mut [u8]) -> Self::ReadFuture<'a> {
        self.dev.read_block_async_dyn(block_id, buf)
    }

    fn write_block_async<'a>(&'a self, block_id: u64, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        self.dev.write_block_async_dyn(block_id, buf)
    }

    fn flush_async(&self) -> Self::FlushFuture<'_> {
        self.dev.flush_async_dyn()
    }
}

/// Inner mutable state of a disk device.
pub struct SeekableDiskInner {
    block_id: u64,
    offset: usize,
    read_buffer: Box<[u8]>,
    write_buffer: Box<[u8]>,
    write_buffer_dirty: bool,
}

/// A trait for objects that can be flushed.
#[async_trait]
pub trait DiskFlushable: Send + Sync {
    async fn flush_disk(&self) -> DevResult<()>;

    async fn flush_owner(&self, _owner: u64) -> DevResult<()> {
        self.flush_disk().await
    }

    fn begin_write_scope(&self, _owners: &[u64]) -> u64 {
        0
    }

    fn enter_write_scope(&self, _scope_id: u64) {}

    fn include_write_owner(&self, _scope_id: u64, _owner: u64) {}

    fn leave_write_scope(&self, _scope_id: u64) {}

    fn end_write_scope(&self, _scope_id: u64) {}
}

pub(crate) struct DiskWriteScope<'a> {
    disk: &'a dyn DiskFlushable,
    scope_id: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct DiskWriteScopeHandle<'a> {
    disk: &'a dyn DiskFlushable,
    scope_id: u64,
}

struct DiskWritePollGuard<'a> {
    disk: &'a dyn DiskFlushable,
    scope_id: u64,
}

impl Drop for DiskWritePollGuard<'_> {
    fn drop(&mut self) {
        self.disk.leave_write_scope(self.scope_id);
    }
}

impl<'a> DiskWriteScope<'a> {
    pub(crate) fn new(disk: &'a dyn DiskFlushable, owners: &[u64]) -> Self {
        let scope_id = disk.begin_write_scope(owners);
        Self { disk, scope_id }
    }

    pub(crate) fn handle(&self) -> DiskWriteScopeHandle<'a> {
        DiskWriteScopeHandle {
            disk: self.disk,
            scope_id: self.scope_id,
        }
    }

    pub(crate) async fn run<F: core::future::Future>(&mut self, future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        core::future::poll_fn(|cx| {
            self.disk.enter_write_scope(self.scope_id);
            let _poll_guard = DiskWritePollGuard {
                disk: self.disk,
                scope_id: self.scope_id,
            };
            core::future::Future::poll(future.as_mut(), cx)
        })
        .await
    }
}

impl DiskWriteScopeHandle<'_> {
    pub(crate) fn include_owner(&self, owner: u64) {
        self.disk.include_write_owner(self.scope_id, owner);
    }
}

impl Drop for DiskWriteScope<'_> {
    fn drop(&mut self) {
        self.disk.end_write_scope(self.scope_id);
    }
}

/// Flusher for a specific disk device.
pub struct DiskFlusher<D: BlockDriverOps> {
    dev: Arc<Mutex<D>>,
    inner: Arc<Mutex<SeekableDiskInner>>,
    flush_lock: async_lock::Mutex<()>,
}

#[async_trait]
impl<D: AsyncBlockDriverOps + Clone + 'static> DiskFlushable for DiskFlusher<D> {
    async fn flush_disk(&self) -> DevResult<()> {
        let _flush_guard = self.flush_lock.lock().await;
        let pending = {
            let inner = self.inner.lock();
            inner
                .write_buffer_dirty
                .then(|| (inner.block_id, inner.write_buffer.to_vec()))
        };
        let dev = self.dev.lock().clone();
        if let Some((block_id, data)) = pending {
            dev.write_block_async(block_id, &data).await?;
            let mut inner = self.inner.lock();
            if inner.write_buffer_dirty
                && inner.block_id == block_id
                && inner.write_buffer.as_ref() == data.as_slice()
            {
                inner.write_buffer_dirty = false;
            }
        }
        dev.flush_async().await
    }
}

pub static DISK_FLUSHERS: spin::Lazy<Mutex<alloc::vec::Vec<alloc::sync::Weak<dyn DiskFlushable>>>> =
    spin::Lazy::new(|| Mutex::new(alloc::vec::Vec::new()));

pub static FLUSHING_TASKS: spin::Lazy<Mutex<alloc::collections::BTreeSet<u64>>> =
    spin::Lazy::new(|| Mutex::new(alloc::collections::BTreeSet::new()));

struct FlushingTaskGuard {
    task_id: u64,
}

impl Drop for FlushingTaskGuard {
    fn drop(&mut self) {
        FLUSHING_TASKS.lock().remove(&self.task_id);
    }
}

/// Flushes all registered disks.
pub fn flush_all_disks() -> DevResult<()> {
    axtask::future::block_on(flush_all_disks_async())
}

/// Asynchronously flushes all registered disks.
pub async fn flush_all_disks_async() -> DevResult<()> {
    let task_id = axtask::current().id().as_u64();
    {
        let mut guard = FLUSHING_TASKS.lock();
        if !guard.insert(task_id) {
            return Ok(());
        }
    }
    let _flushing_task = FlushingTaskGuard { task_id };

    let flushers: alloc::vec::Vec<Arc<dyn DiskFlushable>> = {
        let mut guard = DISK_FLUSHERS.lock();
        let mut active = alloc::vec::Vec::new();
        guard.retain(|weak| {
            if let Some(strong) = weak.upgrade() {
                active.push(strong);
                true
            } else {
                false
            }
        });
        active
    };
    let mut ret = Ok(());
    const DISK_FLUSH_CONCURRENCY: usize = 4;
    let mut flushers = flushers.into_iter();
    let mut pending = FuturesUnordered::new();
    loop {
        while pending.len() < DISK_FLUSH_CONCURRENCY {
            let Some(flusher) = flushers.next() else {
                break;
            };
            pending.push(async move { flusher.flush_disk().await });
        }
        let Some(result) = pending.next().await else {
            break;
        };
        if let Err(e) = result {
            log::error!("Failed to flush disk: {:?}", e);
            ret = Err(e);
        }
    }

    ret
}

/// A disk device with a cursor.
pub struct SeekableDisk<D: BlockDriverOps = SharedBlockDevice> {
    dev: Arc<Mutex<D>>,
    inner: Arc<Mutex<SeekableDiskInner>>,
    flusher: Arc<dyn DiskFlushable>,
    block_size_log2: u8,
}

impl<D: AsyncBlockDriverOps + Clone + 'static> SeekableDisk<D> {
    /// Create a new disk.
    pub fn new(dev: D) -> Self {
        assert!(dev.block_size().is_power_of_two());
        let block_size_log2 = dev.block_size().trailing_zeros() as u8;
        let read_buffer = vec![0u8; dev.block_size()].into_boxed_slice();
        let write_buffer = vec![0u8; dev.block_size()].into_boxed_slice();
        let inner = Arc::new(Mutex::new(SeekableDiskInner {
            block_id: 0,
            offset: 0,
            read_buffer,
            write_buffer,
            write_buffer_dirty: false,
        }));
        let dev_arc = Arc::new(Mutex::new(dev));
        let flusher = Arc::new(DiskFlusher {
            dev: dev_arc.clone(),
            inner: inner.clone(),
            flush_lock: async_lock::Mutex::new(()),
        });

        DISK_FLUSHERS.lock().push(Arc::downgrade(&flusher) as _);

        Self {
            dev: dev_arc,
            inner,
            flusher,
            block_size_log2,
        }
    }

    /// Get the size of the disk.
    pub fn size(&self) -> u64 {
        self.dev.lock().num_blocks() << self.block_size_log2
    }

    /// Get the block size.
    pub fn block_size(&self) -> usize {
        1 << self.block_size_log2
    }

    /// Set the position of the cursor.
    pub fn set_position(&mut self, pos: u64) -> DevResult<()> {
        self.flush()?;
        let mut inner = self.inner.lock();
        inner.block_id = pos >> self.block_size_log2;
        inner.offset = pos as usize & (self.block_size() - 1);
        Ok(())
    }

    /// Write all pending changes to the disk.
    pub fn flush(&mut self) -> DevResult<()> {
        axtask::future::block_on(self.flusher.flush_disk())
    }

    pub fn device(&self) -> Arc<Mutex<D>> {
        self.dev.clone()
    }

    fn read_partial(&mut self, buf: &mut &mut [u8]) -> DevResult<usize> {
        self.flush()?;
        let (block_id, mut read_buffer) = {
            let mut inner = self.inner.lock();
            (inner.block_id, mem::take(&mut inner.read_buffer))
        };
        let mut dev = self.dev.lock().clone();
        let read_result = dev.read_block(block_id, &mut read_buffer);
        let mut inner = self.inner.lock();
        inner.read_buffer = read_buffer;
        read_result?;
        debug_assert_eq!(inner.block_id, block_id);

        let offset = inner.offset;
        let data = &inner.read_buffer[offset..];
        let length = buf.len().min(data.len());
        take_mut(buf, length).copy_from_slice(&data[..length]);

        inner.offset += length;
        if inner.offset == self.block_size() {
            inner.block_id += 1;
            inner.offset = 0;
        }

        Ok(length)
    }

    /// Read from the disk, returns the number of bytes read.
    pub fn read(&mut self, mut buf: &mut [u8]) -> DevResult<usize> {
        let mut read = 0;
        let offset = self.inner.lock().offset;
        if offset != 0 {
            read += self.read_partial(&mut buf)?;
        }
        if buf.len() >= self.block_size() {
            let blocks = buf.len() >> self.block_size_log2;
            let length = blocks << self.block_size_log2;
            let block_id = self.inner.lock().block_id;
            let data = take_mut(&mut buf, length);
            let mut dev = self.dev.lock().clone();
            dev.read_block(block_id, data)?;
            let mut inner = self.inner.lock();
            debug_assert_eq!(inner.block_id, block_id);
            inner.block_id += blocks as u64;
            read += length;
        }
        if !buf.is_empty() {
            read += self.read_partial(&mut buf)?;
        }

        Ok(read)
    }

    fn write_partial(&mut self, buf: &mut &[u8]) -> DevResult<usize> {
        let pending_read = {
            let mut inner = self.inner.lock();
            (!inner.write_buffer_dirty)
                .then(|| (inner.block_id, mem::take(&mut inner.write_buffer)))
        };
        if let Some((block_id, mut write_buffer)) = pending_read {
            let mut dev = self.dev.lock().clone();
            let read_result = dev.read_block(block_id, &mut write_buffer);
            let mut inner = self.inner.lock();
            inner.write_buffer = write_buffer;
            read_result?;
            debug_assert_eq!(inner.block_id, block_id);
            inner.write_buffer_dirty = true;
        }

        let mut inner = self.inner.lock();
        let offset = inner.offset;
        let data = &mut inner.write_buffer[offset..];
        let length = buf.len().min(data.len());
        data[..length].copy_from_slice(take(buf, length));

        inner.offset += length;
        if inner.offset == self.block_size() {
            drop(inner);
            self.flush()?;
            let mut inner = self.inner.lock();
            inner.block_id += 1;
            inner.offset = 0;
        }

        Ok(length)
    }

    /// Write to the disk, returns the number of bytes written.
    pub fn write(&mut self, mut buf: &[u8]) -> DevResult<usize> {
        let mut written = 0;
        let offset = self.inner.lock().offset;
        if offset != 0 {
            written += self.write_partial(&mut buf)?;
        }
        if buf.len() >= self.block_size() {
            let blocks = buf.len() >> self.block_size_log2;
            let length = blocks << self.block_size_log2;
            let block_id = self.inner.lock().block_id;
            let data = take(&mut buf, length);
            let mut dev = self.dev.lock().clone();
            dev.write_block(block_id, data)?;
            let mut inner = self.inner.lock();
            debug_assert_eq!(inner.block_id, block_id);
            inner.block_id += blocks as u64;
            written += length;
        }
        if !buf.is_empty() {
            written += self.write_partial(&mut buf)?;
        }

        Ok(written)
    }
}
