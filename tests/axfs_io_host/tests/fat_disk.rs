//! Run the FAT adapter against the kernel block traits without linking platform drivers.
extern crate alloc;
extern crate self as axdriver;

pub mod prelude {
    pub use axdriver_block::{
        AsyncBlockDriverOps, BaseDriverOps, BlockDriverOps, DevError, DevResult, DeviceType,
    };
}

#[path = "../../../modules/fs/src/fs/fat/disk.rs"]
mod disk;

use core::{
    future::{Future, Ready, poll_fn, ready},
    pin::{Pin, pin},
    sync::atomic::{AtomicU8, Ordering},
    task::{Context, Poll, Waker},
};
use std::sync::Arc;

use axdriver::prelude::*;
use disk::{FatDisk, FatDiskError};
use hadris_storage::{BlockIndex, async_::BlockDevice};

#[derive(Default)]
struct TestDisk {
    written_byte: Option<Arc<AtomicU8>>,
}

impl BaseDriverOps for TestDisk {
    fn device_name(&self) -> &str {
        "test-disk"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for TestDisk {
    fn block_size(&self) -> usize {
        512
    }

    fn num_blocks(&self) -> u64 {
        8
    }

    fn read_block(&mut self, _: u64, _: &mut [u8]) -> DevResult {
        unreachable!("synchronous FAT read")
    }

    fn write_block(&mut self, _: u64, _: &[u8]) -> DevResult {
        unreachable!("synchronous FAT write")
    }

    fn flush(&mut self) -> DevResult {
        unreachable!("synchronous FAT flush")
    }
}

impl AsyncBlockDriverOps for TestDisk {
    type ReadFuture<'a> = Ready<DevResult>;
    type WriteFuture<'a> = Pin<Box<dyn Future<Output = DevResult> + Send + 'a>>;
    type FlushFuture<'a> = Ready<DevResult>;

    fn read_block_async<'a>(&'a self, _: u64, _: &'a mut [u8]) -> Self::ReadFuture<'a> {
        ready(Err(DevError::Io))
    }

    fn write_block_async<'a>(&'a self, _: u64, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        let Some(written_byte) = &self.written_byte else {
            return Box::pin(ready(Err(DevError::NoMemory)));
        };
        let mut started = false;
        Box::pin(poll_fn(move |cx| {
            if started {
                written_byte.store(buf[0], Ordering::Relaxed);
                Poll::Ready(Ok(()))
            } else {
                started = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }))
    }

    fn flush_async(&self) -> Self::FlushFuture<'_> {
        ready(
            self.written_byte
                .as_ref()
                .map(|_| ())
                .ok_or(DevError::Unsupported),
        )
    }
}

#[test]
fn driver_failures_reach_the_filesystem() {
    let mut disk = FatDisk::new(TestDisk::default()).unwrap();
    let mut cx = Context::from_waker(Waker::noop());
    let first = BlockIndex::new(0);
    let mut buf = [0; 512];

    let read = pin!(disk.read_blocks(first, &mut buf))
        .as_mut()
        .poll(&mut cx);
    assert!(
        matches!(read, Poll::Ready(Err(e)) if matches!(e.device_error(), Some(FatDiskError(DevError::Io))))
    );
    let write = pin!(disk.write_blocks(first, &buf)).as_mut().poll(&mut cx);
    assert!(
        matches!(write, Poll::Ready(Err(e)) if matches!(e.device_error(), Some(FatDiskError(DevError::NoMemory))))
    );
    let flush = pin!(disk.flush()).as_mut().poll(&mut cx);
    assert!(
        matches!(flush, Poll::Ready(Err(e)) if matches!(e.device_error(), Some(FatDiskError(DevError::Unsupported))))
    );
}

#[test]
fn flush_waits_for_cancelled_write_with_its_original_bytes() {
    let written_byte = Arc::new(AtomicU8::new(0));
    let mut disk = FatDisk::new(TestDisk {
        written_byte: Some(Arc::clone(&written_byte)),
    })
    .unwrap();
    let mut cx = Context::from_waker(Waker::noop());

    {
        let buf = [42; 512];
        let mut write = pin!(disk.write_blocks(BlockIndex::new(0), &buf));
        assert!(write.as_mut().poll(&mut cx).is_pending());
    }
    assert_eq!(written_byte.load(Ordering::Relaxed), 0);
    assert!(matches!(
        pin!(disk.flush()).as_mut().poll(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(written_byte.load(Ordering::Relaxed), 42);
}
