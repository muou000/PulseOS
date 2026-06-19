use alloc::{
    boxed::Box,
    string::{String, ToString},
    sync::Arc,
    vec,
};
use core::mem;

use axdriver::{AxBlockDevice, prelude::*};
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

/// A block device wrapper that can be cloned and shared across subsystems.
#[derive(Clone)]
pub struct SharedBlockDevice {
    name: String,
    dev: Arc<Mutex<AxBlockDevice>>,
}

impl SharedBlockDevice {
    /// Wraps a block device so the same underlying driver can be reused.
    pub fn new(dev: AxBlockDevice) -> Self {
        let name = dev.device_name().to_string();
        Self { name, dev: Arc::new(Mutex::new(dev)) }
    }

    /// Returns the total size of the device in bytes.
    pub fn size(&self) -> u64 {
        let dev = self.dev.lock();
        dev.num_blocks().saturating_mul(dev.block_size() as u64)
    }

    /// Returns the device block size.
    pub fn block_size(&self) -> usize {
        let dev = self.dev.lock();
        dev.block_size()
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
        let dev = self.dev.lock();
        dev.num_blocks()
    }

    fn block_size(&self) -> usize {
        let dev = self.dev.lock();
        dev.block_size()
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        let mut dev = self.dev.lock();
        dev.read_block(block_id, buf)
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        let mut dev = self.dev.lock();
        dev.write_block(block_id, buf)
    }

    fn flush(&mut self) -> DevResult {
        let mut dev = self.dev.lock();
        dev.flush()
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
pub trait DiskFlushable: Send + Sync {
    fn flush_disk(&self) -> DevResult<()>;
}

/// Flusher for a specific disk device.
pub struct DiskFlusher<D: BlockDriverOps> {
    dev: Arc<Mutex<D>>,
    inner: Arc<Mutex<SeekableDiskInner>>,
}

impl<D: BlockDriverOps> DiskFlushable for DiskFlusher<D> {
    fn flush_disk(&self) -> DevResult<()> {
        let mut inner = self.inner.lock();
        let mut dev = self.dev.lock();
        if inner.write_buffer_dirty {
            dev.write_block(inner.block_id, &inner.write_buffer)?;
            inner.write_buffer_dirty = false;
        }
        dev.flush()?;
        Ok(())
    }
}

pub static DISK_FLUSHERS: spin::Lazy<Mutex<alloc::vec::Vec<alloc::sync::Weak<dyn DiskFlushable>>>> =
    spin::Lazy::new(|| Mutex::new(alloc::vec::Vec::new()));

/// Flushes all registered disks.
pub fn flush_all_disks() -> DevResult<()> {
    let mut flushers = DISK_FLUSHERS.lock();
    flushers.retain(|weak| {
        if let Some(flusher) = weak.upgrade() {
            let _ = flusher.flush_disk();
            true
        } else {
            false
        }
    });
    Ok(())
}

/// A disk device with a cursor.
pub struct SeekableDisk<D: BlockDriverOps = SharedBlockDevice> {
    dev: Arc<Mutex<D>>,
    inner: Arc<Mutex<SeekableDiskInner>>,
    flusher: Arc<dyn DiskFlushable>,
    block_size_log2: u8,
}

impl<D: BlockDriverOps + 'static> SeekableDisk<D> {
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
        self.flusher.flush_disk()
    }

    pub fn device(&self) -> Arc<Mutex<D>> {
        self.dev.clone()
    }

    fn read_partial(&mut self, buf: &mut &mut [u8]) -> DevResult<usize> {
        self.flush()?;
        let mut inner = self.inner.lock();
        self.dev.lock().read_block(inner.block_id, &mut inner.read_buffer)?;

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
            let mut inner = self.inner.lock();
            self.dev.lock().read_block(inner.block_id, take_mut(&mut buf, length))?;
            read += length;

            inner.block_id += blocks as u64;
        }
        if !buf.is_empty() {
            read += self.read_partial(&mut buf)?;
        }

        Ok(read)
    }

    fn write_partial(&mut self, buf: &mut &[u8]) -> DevResult<usize> {
        let mut inner = self.inner.lock();
        if !inner.write_buffer_dirty {
            self.dev.lock().read_block(inner.block_id, &mut inner.write_buffer)?;
            inner.write_buffer_dirty = true;
        }

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
            self.dev.lock().write_block(self.inner.lock().block_id, take(&mut buf, length))?;
            written += length;

            let mut inner = self.inner.lock();
            inner.block_id += blocks as u64;
        }
        if !buf.is_empty() {
            written += self.write_partial(&mut buf)?;
        }

        Ok(written)
    }
}

