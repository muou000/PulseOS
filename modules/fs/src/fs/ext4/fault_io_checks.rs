//! Deterministic block-driver boundary checks for target-window provenance.
//! The counted driver supplies bytes in memory; real virtio evidence is separate.

use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::{
    future::{Future, Ready, poll_fn, ready},
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use driver::prelude::{
    AsyncBlockDriverOps, BaseDriverOps, BlockDriverOps, DevError, DevResult, DeviceType,
};
use ext4plus::{Ext4, Ext4Read, Ext4Write};
use spin::Mutex;

use crate::disk::{DiskFlushable, DiskWriteScope};

#[derive(Clone, Default)]
struct CountedDisk(Arc<spin::Mutex<Vec<(u64, usize)>>>);

impl CountedDisk {
    fn read(&self, sector: u64, bytes: &mut [u8]) -> DevResult {
        if sector >= 128 || bytes.len() % 512 != 0 || bytes.len() / 512 > 128 - sector as usize {
            return Err(DevError::InvalidParam);
        }
        self.0.lock().push((sector, bytes.len()));
        bytes.fill(0x73);
        Ok(())
    }
}

impl BaseDriverOps for CountedDisk {
    fn device_name(&self) -> &str {
        "fault-io-check"
    }
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for CountedDisk {
    fn num_blocks(&self) -> u64 {
        128
    }
    fn block_size(&self) -> usize {
        512
    }
    fn read_block(&mut self, sector: u64, bytes: &mut [u8]) -> DevResult {
        self.read(sector, bytes)
    }
    fn write_block(&mut self, _sector: u64, _bytes: &[u8]) -> DevResult {
        Err(DevError::Unsupported)
    }
    fn flush(&mut self) -> DevResult {
        Ok(())
    }
}

impl AsyncBlockDriverOps for CountedDisk {
    type ReadFuture<'a> = Ready<DevResult>;
    type WriteFuture<'a> = Ready<DevResult>;
    type FlushFuture<'a> = Ready<DevResult>;

    fn read_block_async<'a>(&'a self, sector: u64, bytes: &'a mut [u8]) -> Self::ReadFuture<'a> {
        ready(self.read(sector, bytes))
    }
    fn write_block_async<'a>(&'a self, _sector: u64, _bytes: &'a [u8]) -> Self::WriteFuture<'a> {
        ready(Err(DevError::Unsupported))
    }
    fn flush_async(&self) -> Self::FlushFuture<'_> {
        ready(Ok(()))
    }
}

struct MockDiskState {
    data: Mutex<Vec<u8>>,
    writes: AtomicUsize,
    flushes: AtomicUsize,
    written_sectors: Mutex<Vec<(u64, usize)>>,
    fail_write: AtomicBool,
    fail_flush: AtomicBool,
    pause_write: AtomicBool,
}

#[derive(Clone)]
struct MockAsyncDisk(Arc<MockDiskState>);

impl MockAsyncDisk {
    fn new(size: usize) -> Self {
        Self(Arc::new(MockDiskState {
            data: Mutex::new(vec![0; size]),
            writes: AtomicUsize::new(0),
            flushes: AtomicUsize::new(0),
            written_sectors: Mutex::new(Vec::new()),
            fail_write: AtomicBool::new(false),
            fail_flush: AtomicBool::new(false),
            pause_write: AtomicBool::new(false),
        }))
    }
}

impl BaseDriverOps for MockAsyncDisk {
    fn device_name(&self) -> &str {
        "mock-async-disk"
    }
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for MockAsyncDisk {
    fn num_blocks(&self) -> u64 {
        (self.0.data.lock().len() / 512) as u64
    }
    fn block_size(&self) -> usize {
        512
    }
    fn read_block(&mut self, sector: u64, bytes: &mut [u8]) -> DevResult {
        let off = sector as usize * 512;
        let data = self.0.data.lock();
        if off + bytes.len() > data.len() {
            return Err(DevError::InvalidParam);
        }
        bytes.copy_from_slice(&data[off..off + bytes.len()]);
        Ok(())
    }
    fn write_block(&mut self, sector: u64, bytes: &[u8]) -> DevResult {
        let off = sector as usize * 512;
        let mut data = self.0.data.lock();
        if off + bytes.len() > data.len() {
            return Err(DevError::InvalidParam);
        }
        data[off..off + bytes.len()].copy_from_slice(bytes);
        Ok(())
    }
    fn flush(&mut self) -> DevResult {
        Ok(())
    }
}

impl AsyncBlockDriverOps for MockAsyncDisk {
    type ReadFuture<'a> = Ready<DevResult>;
    type WriteFuture<'a> = Pin<Box<dyn Future<Output = DevResult> + Send + 'a>>;
    type FlushFuture<'a> = Ready<DevResult>;

    fn read_block_async<'a>(&'a self, sector: u64, bytes: &'a mut [u8]) -> Self::ReadFuture<'a> {
        let mut copy = self.clone();
        ready(copy.read_block(sector, bytes))
    }

    fn write_block_async<'a>(&'a self, sector: u64, bytes: &'a [u8]) -> Self::WriteFuture<'a> {
        Box::pin(async move {
            self.0.writes.fetch_add(1, Ordering::Relaxed);
            poll_fn(|cx| {
                if self.0.pause_write.load(Ordering::Acquire) {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                } else {
                    Poll::Ready(())
                }
            })
            .await;
            if self.0.fail_write.load(Ordering::Acquire) {
                return Err(DevError::Io);
            }
            let off = sector as usize * 512;
            let mut data = self.0.data.lock();
            if off + bytes.len() > data.len() {
                return Err(DevError::InvalidParam);
            }
            data[off..off + bytes.len()].copy_from_slice(bytes);
            self.0.written_sectors.lock().push((sector, bytes.len()));
            Ok(())
        })
    }

    fn flush_async(&self) -> Self::FlushFuture<'_> {
        self.0.flushes.fetch_add(1, Ordering::Relaxed);
        if self.0.fail_flush.load(Ordering::Acquire) {
            ready(Err(DevError::Io))
        } else {
            ready(Ok(()))
        }
    }
}

struct MockNoopWake;
impl alloc::task::Wake for MockNoopWake {
    fn wake(self: Arc<Self>) {}
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = Waker::from(Arc::new(MockNoopWake));
    future.poll(&mut Context::from_waker(&waker))
}

#[inline(never)]
fn flush_owner_scopes_writes_and_skips_unrelated_owners() -> vfs::VfsResult<()> {
    let mock = MockAsyncDisk::new(64 * 4096);
    let disk = super::Ext4Disk::new(mock.clone());
    let b10 = vec![0x1Au8; 4096];
    let b20 = vec![0x2Bu8; 4096];
    let b30 = vec![0x3Cu8; 4096];

    task::future::block_on(async {
        let mut s10 = DiskWriteScope::new(&*disk, &[10]);
        s10.run(disk.write_offset(4096, &b10)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s10);

        let mut s20 = DiskWriteScope::new(&*disk, &[20]);
        s20.run(disk.write_offset(8192, &b20)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s20);

        let mut s30 = DiskWriteScope::new_retroactive(&*disk, &[30]);
        let s30_handle = s30.handle();
        s30.run(async {
            disk.write_offset(12288, &b30).await?;
            s30_handle.include_owner(31);
            Ok::<_, DevError>(())
        })
        .await
        .map_err(|_| vfs::VfsError::Io)?;
        drop(s30);

        disk.flush_owner(10).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.writes.load(Ordering::Acquire) != 1 || mock.0.flushes.load(Ordering::Acquire) != 1 {
            return Err(vfs::VfsError::BadState);
        }
        if &*mock.0.written_sectors.lock() != &[(8u64, 4096usize)] {
            return Err(vfs::VfsError::BadState);
        }

        // Second flush_owner on clean owner must do 0 writes and 0 device flushes.
        disk.flush_owner(10).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.writes.load(Ordering::Acquire) != 1 || mock.0.flushes.load(Ordering::Acquire) != 1 {
            return Err(vfs::VfsError::BadState);
        }

        disk.flush_owner(31).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.writes.load(Ordering::Acquire) != 2 || mock.0.flushes.load(Ordering::Acquire) != 2 {
            return Err(vfs::VfsError::BadState);
        }
        if mock.0.written_sectors.lock().last().copied() != Some((24u64, 4096usize)) {
            return Err(vfs::VfsError::BadState);
        }

        disk.flush_owner(20).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.writes.load(Ordering::Acquire) != 3 || mock.0.flushes.load(Ordering::Acquire) != 3 {
            return Err(vfs::VfsError::BadState);
        }
        if mock.0.data.lock()[4096..8192] != b10[..]
            || mock.0.data.lock()[8192..12288] != b20[..]
            || mock.0.data.lock()[12288..16384] != b30[..]
        {
            return Err(vfs::VfsError::BadState);
        }
        Ok(())
    })?;
    log::info!("MLC_KERNEL PASS flush_owner_scopes_writes_and_skips_unrelated_owners");
    Ok(())
}

#[inline(never)]
fn flush_owner_error_retry_redirty_cancel_and_bypass() -> vfs::VfsResult<()> {
    let mock = MockAsyncDisk::new(64 * 4096);
    let disk = super::Ext4Disk::new(mock.clone());
    let b1 = vec![0xA1u8; 4096];
    let b2_old = vec![0xB1u8; 4096];
    let b2_new = vec![0xB2u8; 4096];
    let bypass = vec![0x55u8; 8192];
    let b3 = vec![0xC3u8; 4096];

    // 1. Flush failure still triggers dev.flush_async on retry.
    task::future::block_on(async {
        let mut s = DiskWriteScope::new(&*disk, &[10]);
        s.run(disk.write_offset(16384, &b1)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s);

        mock.0.fail_flush.store(true, Ordering::Release);
        if disk.flush_owner(10).await.is_ok() {
            return Err(vfs::VfsError::BadState);
        }
        let flushes_after_err = mock.0.flushes.load(Ordering::Acquire);
        mock.0.fail_flush.store(false, Ordering::Release);
        disk.flush_owner(10).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.flushes.load(Ordering::Acquire) != flushes_after_err + 1 {
            return Err(vfs::VfsError::BadState);
        }
        Ok(())
    })?;

    // 2. Canceled flush cleans flushing state; re-dirty preserves dirty block.
    task::future::block_on(async {
        let mut s = DiskWriteScope::new(&*disk, &[20]);
        s.run(disk.write_offset(20480, &b2_old)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s);
        Ok::<_, vfs::VfsError>(())
    })?;
    mock.0.pause_write.store(true, Ordering::Release);
    let writes_before = mock.0.writes.load(Ordering::Acquire);
    let mut flush_fut = Box::pin(disk.flush_owner(20));
    if !matches!(poll_once(flush_fut.as_mut()), Poll::Pending) {
        return Err(vfs::VfsError::BadState);
    }
    if mock.0.writes.load(Ordering::Acquire) != writes_before + 1 {
        return Err(vfs::VfsError::BadState);
    }
    drop(flush_fut);
    mock.0.pause_write.store(false, Ordering::Release);
    task::future::block_on(async {
        disk.flush_owner(20).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.data.lock()[20480..24576] != b2_old[..] {
            return Err(vfs::VfsError::BadState);
        }
        let mut s = DiskWriteScope::new(&*disk, &[20]);
        s.run(disk.write_offset(20480, &b2_new)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s);
        disk.flush_owner(20).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.data.lock()[20480..24576] != b2_new[..] {
            return Err(vfs::VfsError::BadState);
        }
        Ok::<_, vfs::VfsError>(())
    })?;

    // 3. Aligned >4 KiB bypass write still forces dev.flush_async on flush_owner.
    task::future::block_on(async {
        let flushes_before = mock.0.flushes.load(Ordering::Acquire);
        let mut s = DiskWriteScope::new(&*disk, &[40]);
        s.run(disk.write_offset(24576, &bypass)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s);
        disk.flush_owner(40).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.flushes.load(Ordering::Acquire) != flushes_before + 1 {
            return Err(vfs::VfsError::BadState);
        }
        if mock.0.data.lock()[24576..32768] != bypass[..] {
            return Err(vfs::VfsError::BadState);
        }
        Ok::<_, vfs::VfsError>(())
    })?;

    // 4. Write-error retry preserves dirty block and flushes on next attempt.
    task::future::block_on(async {
        let mut s = DiskWriteScope::new(&*disk, &[50]);
        s.run(disk.write_offset(32768, &b3)).await.map_err(|_| vfs::VfsError::Io)?;
        drop(s);
        mock.0.fail_write.store(true, Ordering::Release);
        if disk.flush_owner(50).await.is_ok() {
            return Err(vfs::VfsError::BadState);
        }
        mock.0.fail_write.store(false, Ordering::Release);
        disk.flush_owner(50).await.map_err(|_| vfs::VfsError::Io)?;
        if mock.0.data.lock()[32768..36864] != b3[..] {
            return Err(vfs::VfsError::BadState);
        }
        Ok(())
    })?;

    log::info!("MLC_KERNEL PASS flush_owner_error_retry_redirty_cancel_and_bypass");
    Ok(())
}

struct RawExt4Image {
    data: Mutex<Vec<u8>>,
    reads: Mutex<Vec<(u64, usize)>>,
    writes: Mutex<Vec<(u64, usize)>>,
}

impl RawExt4Image {
    fn minimal_64_blocks() -> Arc<Self> {
        let mut buf = vec![0u8; 64 * 4096];
        let write_u16 = |b: &mut [u8], off: usize, v: u16| b[off..off + 2].copy_from_slice(&v.to_le_bytes());
        let write_u32 = |b: &mut [u8], off: usize, v: u32| b[off..off + 4].copy_from_slice(&v.to_le_bytes());

        // Superblock at byte 1024 (block size = 4096, 64 blocks, 1 group, 256B inodes, EXTENTS)
        let sb = 1024;
        write_u32(&mut buf, sb + 0x04, 64); // s_blocks_count_lo
        write_u32(&mut buf, sb + 0x0c, 43); // s_free_blocks_count_lo
        write_u32(&mut buf, sb + 0x10, 16); // s_free_inodes_count
        write_u32(&mut buf, sb + 0x14, 0);  // s_first_data_block
        write_u32(&mut buf, sb + 0x18, 2);  // s_log_block_size (4096)
        write_u32(&mut buf, sb + 0x20, 64); // s_blocks_per_group
        write_u32(&mut buf, sb + 0x28, 32); // s_inodes_per_group
        write_u16(&mut buf, sb + 0x38, 0xef53); // s_magic
        write_u16(&mut buf, sb + 0x58, 256); // s_inode_size
        write_u32(&mut buf, sb + 0x60, 0x42); // INCOMPAT_EXTENTS | INCOMPAT_FILETYPE

        // Group 0 descriptor at block 1
        let bg = 4096;
        write_u32(&mut buf, bg + 0x00, 2);  // bg_block_bitmap_lo
        write_u32(&mut buf, bg + 0x04, 3);  // bg_inode_bitmap_lo
        write_u32(&mut buf, bg + 0x08, 4);  // bg_inode_table_lo
        write_u16(&mut buf, bg + 0x0c, 43); // bg_free_blocks_count_lo
        write_u16(&mut buf, bg + 0x0e, 16); // bg_free_inodes_count_lo

        // Mark blocks 0..=20 allocated in block bitmap (block 2) and blocks >= 64 out of range
        buf[2 * 4096] = 0xff;
        buf[2 * 4096 + 1] = 0xff;
        buf[2 * 4096 + 2] = 0x1f;
        // Mark inodes 1..=16 allocated in inode bitmap (block 3)
        buf[3 * 4096] = 0xff;
        buf[3 * 4096 + 1] = 0xff;

        // Inode 11 at block 4 + 10 * 256: regular file, 4096B, 1 initialized extent [0..1) -> block 20
        let ino11 = 4 * 4096 + 10 * 256;
        write_u16(&mut buf, ino11 + 0x00, 0x81a4); // S_IFREG | 0644
        write_u32(&mut buf, ino11 + 0x04, 4096);   // i_size_lo
        write_u16(&mut buf, ino11 + 0x1a, 1);      // i_links_count
        write_u32(&mut buf, ino11 + 0x1c, 8);      // i_blocks_lo (512B units)
        write_u32(&mut buf, ino11 + 0x20, 0x80000); // EXTENTS flag
        let ib = ino11 + 0x28;
        write_u16(&mut buf, ib + 0x00, 0xf30a); // eh_magic
        write_u16(&mut buf, ib + 0x02, 1);      // eh_entries
        write_u16(&mut buf, ib + 0x04, 4);      // eh_max
        write_u16(&mut buf, ib + 0x06, 0);      // eh_depth
        write_u32(&mut buf, ib + 0x0c, 0);      // ee_block
        write_u16(&mut buf, ib + 0x10, 1);      // ee_len (initialized)
        write_u16(&mut buf, ib + 0x12, 0);      // ee_start_hi
        write_u32(&mut buf, ib + 0x14, 20);     // ee_start_lo (block 20)

        Arc::new(Self {
            data: Mutex::new(buf),
            reads: Mutex::new(Vec::new()),
            writes: Mutex::new(Vec::new()),
        })
    }
}

struct RawReader(Arc<RawExt4Image>);
struct RawWriter(Arc<RawExt4Image>);

#[async_trait::async_trait]
impl Ext4Read for RawReader {
    async fn read(
        &self,
        start_byte: u64,
        dst: &mut [u8],
    ) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.reads.lock().push((start_byte, dst.len()));
        let off = start_byte as usize;
        let data = self.0.data.lock();
        dst.copy_from_slice(&data[off..off + dst.len()]);
        Ok(())
    }
}

#[async_trait::async_trait]
impl Ext4Write for RawWriter {
    async fn write(
        &self,
        start_byte: u64,
        src: &[u8],
    ) -> Result<(), alloc::boxed::Box<dyn core::error::Error + Send + Sync + 'static>> {
        self.0.writes.lock().push((start_byte, src.len()));
        let off = start_byte as usize;
        let mut data = self.0.data.lock();
        data[off..off + src.len()].copy_from_slice(src);
        Ok(())
    }
}

#[inline(never)]
fn extent_tree_partial_overwrite_skips_preread_and_unchanged_inode() -> vfs::VfsResult<()> {
    let img = RawExt4Image::minimal_64_blocks();
    let payload = vec![0x5Au8; 288];
    let ext_payload = vec![0x6Bu8; 288];

    task::future::block_on(async {
        let ext4 = Ext4::load_with_writer(
            Box::new(RawReader(img.clone())),
            Some(Box::new(RawWriter(img.clone()))),
        )
        .await
        .map_err(|_| vfs::VfsError::Io)?;
        let mut inode = ext4plus::inode::Inode::read(&ext4, core::num::NonZeroU32::new(11).unwrap())
            .await
            .map_err(|_| vfs::VfsError::Io)?;

        img.reads.lock().clear();
        img.writes.lock().clear();

        // 1. Overwrite subrange [256..544) inside initialized block 20 with unchanged size=4096:
        // must NOT pre-read block 20 and must NOT write back unchanged inode.
        let written = ext4plus::file::write_at(&ext4, &mut inode, &payload, 256)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if written != 288 {
            return Err(vfs::VfsError::BadState);
        }
        if !img.reads.lock().is_empty() {
            return Err(vfs::VfsError::BadState);
        }
        if &*img.writes.lock() != &[(20 * 4096 + 256, 288usize)] {
            return Err(vfs::VfsError::BadState);
        }

        // 2. Shrink inside block 20 via truncate: MUST zero [1000..4096) on disk and update inode size.
        img.writes.lock().clear();
        ext4plus::file::truncate(&ext4, &mut inode, 1000)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if inode.size_in_bytes() != 1000 {
            return Err(vfs::VfsError::BadState);
        }
        if !img.data.lock()[20 * 4096 + 1000..21 * 4096]
            .iter()
            .all(|&b| b == 0)
        {
            return Err(vfs::VfsError::BadState);
        }

        // 3. Extend inode size within already-allocated block 20: must skip pre-read AND write updated inode.
        img.reads.lock().clear();
        img.writes.lock().clear();
        let written_in_extent = ext4plus::file::write_at(&ext4, &mut inode, &payload, 1024)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if written_in_extent != 288 || inode.size_in_bytes() != 1312 {
            return Err(vfs::VfsError::BadState);
        }
        if !img.reads.lock().is_empty() {
            return Err(vfs::VfsError::BadState);
        }
        let ino11_off = (4 * 4096 + 10 * 256) as u64;
        if !img.writes.lock().iter().any(|(off, _)| *off == (20 * 4096 + 1024) as u64)
            || !img.writes.lock().iter().any(|(off, _)| *off == ino11_off)
        {
            return Err(vfs::VfsError::BadState);
        }

        // 4. Extend past 4096: MUST allocate a new block and write back updated inode.
        img.writes.lock().clear();
        let written2 = ext4plus::file::write_at(&ext4, &mut inode, &ext_payload, 4096)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if written2 != 288 || inode.size_in_bytes() != 4384 {
            return Err(vfs::VfsError::BadState);
        }
        if !img.writes.lock().iter().any(|(off, _)| *off == ino11_off) {
            return Err(vfs::VfsError::BadState);
        }

        let mut verify = vec![0u8; 288];
        ext4plus::file::read_at(&ext4, &inode, &mut verify, 256)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if verify != payload {
            return Err(vfs::VfsError::BadState);
        }
        ext4plus::file::read_at(&ext4, &inode, &mut verify, 1024)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if verify != payload {
            return Err(vfs::VfsError::BadState);
        }
        ext4plus::file::read_at(&ext4, &inode, &mut verify, 4096)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if verify != ext_payload {
            return Err(vfs::VfsError::BadState);
        }
        Ok(())
    })?;

    log::info!("MLC_KERNEL PASS extent_tree_partial_overwrite_skips_preread_and_unchanged_inode");
    Ok(())
}

pub(super) fn run() -> vfs::VfsResult<()> {
    let device = CountedDisk::default();
    let reader = super::Ext4DiskWrapper(super::Ext4Disk::new(device.clone()));
    let mut page = alloc::vec![0; 4096];
    let mut batch = alloc::vec![0; 8192];
    task::future::block_on(async {
        let cold = reader
            .read_with_io(4096, &mut page, 0..4096)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if cold != Some(true) || &*device.0.lock() != &[(8, 4096)] {
            return Err(vfs::VfsError::BadState);
        }
        device.0.lock().clear();
        // First block is resident; the second block really invokes the driver.
        // The selected first-page window must still report no storage read.
        let neighbor = reader
            .read_with_io(4096, &mut batch, 0..4096)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if neighbor != Some(false) || &*device.0.lock() != &[(16, 4096)] {
            return Err(vfs::VfsError::BadState);
        }
        device.0.lock().clear();
        // Select the second page of a different mixed hit/miss run instead.
        let target = reader
            .read_with_io(8192, &mut batch, 4096..8192)
            .await
            .map_err(|_| vfs::VfsError::Io)?;
        if target != Some(true) || &*device.0.lock() != &[(24, 4096)] {
            return Err(vfs::VfsError::BadState);
        }
        if !batch.iter().all(|byte| *byte == 0x73) {
            return Err(vfs::VfsError::BadState);
        }
        Ok(())
    })?;
    log::info!("MLC_KERNEL PASS fault_io_block_cache_neighbor");
    flush_owner_scopes_writes_and_skips_unrelated_owners()?;
    flush_owner_error_retry_redirty_cancel_and_bypass()?;
    extent_tree_partial_overwrite_skips_preread_and_unchanged_inode()?;
    Ok(())
}
