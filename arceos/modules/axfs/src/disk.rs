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

/// A disk device with a cursor.
pub struct SeekableDisk<D: BlockDriverOps> {
    dev: D,

    block_id: u64,
    offset: usize,
    block_size_log2: u8,

    read_buffer: Box<[u8]>,
    write_buffer: Box<[u8]>,
    /// Whether we have unsaved changes in the write buffer.
    ///
    /// It's guaranteed that when `offset == 0`, write_buffer_dirty is false.
    write_buffer_dirty: bool,
}

impl<D: BlockDriverOps> SeekableDisk<D> {
    /// Create a new disk.
    pub fn new(dev: D) -> Self {
        assert!(dev.block_size().is_power_of_two());
        let block_size_log2 = dev.block_size().trailing_zeros() as u8;
        let read_buffer = vec![0u8; dev.block_size()].into_boxed_slice();
        let write_buffer = vec![0u8; dev.block_size()].into_boxed_slice();
        Self {
            dev,
            block_id: 0,
            offset: 0,
            block_size_log2,
            read_buffer,
            write_buffer,
            write_buffer_dirty: false,
        }
    }

    /// Get the size of the disk.
    pub fn size(&self) -> u64 {
        self.dev.num_blocks() << self.block_size_log2
    }

    /// Get the block size.
    pub fn block_size(&self) -> usize {
        1 << self.block_size_log2
    }

    /// Set the position of the cursor.
    pub fn set_position(&mut self, pos: u64) -> DevResult<()> {
        self.flush()?;
        self.block_id = pos >> self.block_size_log2;
        self.offset = pos as usize & (self.block_size() - 1);
        Ok(())
    }

    /// Write all pending changes to the disk.
    pub fn flush(&mut self) -> DevResult<()> {
        if self.write_buffer_dirty {
            self.dev.write_block(self.block_id, &self.write_buffer)?;
            self.write_buffer_dirty = false;
        }
        Ok(())
    }

    fn read_partial(&mut self, buf: &mut &mut [u8]) -> DevResult<usize> {
        self.flush()?;
        self.dev.read_block(self.block_id, &mut self.read_buffer)?;

        let data = &self.read_buffer[self.offset..];
        let length = buf.len().min(data.len());
        take_mut(buf, length).copy_from_slice(&data[..length]);

        self.offset += length;
        if self.offset == self.block_size() {
            self.block_id += 1;
            self.offset = 0;
        }

        Ok(length)
    }

    /// Read from the disk, returns the number of bytes read.
    pub fn read(&mut self, mut buf: &mut [u8]) -> DevResult<usize> {
        let mut read = 0;
        if self.offset != 0 {
            read += self.read_partial(&mut buf)?;
        }
        if buf.len() >= self.block_size() {
            let blocks = buf.len() >> self.block_size_log2;
            let length = blocks << self.block_size_log2;
            self.dev.read_block(self.block_id, take_mut(&mut buf, length))?;
            read += length;

            self.block_id += blocks as u64;
        }
        if !buf.is_empty() {
            read += self.read_partial(&mut buf)?;
        }

        Ok(read)
    }

    fn write_partial(&mut self, buf: &mut &[u8]) -> DevResult<usize> {
        if !self.write_buffer_dirty {
            self.dev.read_block(self.block_id, &mut self.write_buffer)?;
            self.write_buffer_dirty = true;
        }

        let data = &mut self.write_buffer[self.offset..];
        let length = buf.len().min(data.len());
        data[..length].copy_from_slice(take(buf, length));

        self.offset += length;
        if self.offset == self.block_size() {
            self.flush()?;
            self.block_id += 1;
            self.offset = 0;
        }

        Ok(length)
    }

    /// Write to the disk, returns the number of bytes written.
    pub fn write(&mut self, mut buf: &[u8]) -> DevResult<usize> {
        let mut written = 0;
        if self.offset != 0 {
            written += self.write_partial(&mut buf)?;
        }
        if buf.len() >= self.block_size() {
            let blocks = buf.len() >> self.block_size_log2;
            let length = blocks << self.block_size_log2;
            self.dev.write_block(self.block_id, take(&mut buf, length))?;
            written += length;

            self.block_id += blocks as u64;
        }
        if !buf.is_empty() {
            written += self.write_partial(&mut buf)?;
        }

        Ok(written)
    }
}
