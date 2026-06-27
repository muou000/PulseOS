use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use axdriver::prelude::{BaseDriverOps, BlockDriverOps, DeviceType, DevResult, DevError};

pub struct LoopDeviceState {
    pub backing: Mutex<Option<Arc<crate::highlevel::File>>>,
    pub size: AtomicU64,
    pub flags: core::sync::atomic::AtomicU32,
}

impl LoopDeviceState {
    const fn new() -> Self {
        Self {
            backing: Mutex::new(None),
            size: AtomicU64::new(0),
            flags: core::sync::atomic::AtomicU32::new(0),
        }
    }
}

pub static LOOP_DEVICES: [LoopDeviceState; 8] = [
    LoopDeviceState::new(), LoopDeviceState::new(), LoopDeviceState::new(), LoopDeviceState::new(),
    LoopDeviceState::new(), LoopDeviceState::new(), LoopDeviceState::new(), LoopDeviceState::new(),
];

pub struct LoopBlockDevice {
    id: usize,
}

impl LoopBlockDevice {
    pub fn new(id: usize) -> Self {
        Self { id }
    }
}

impl BaseDriverOps for LoopBlockDevice {
    fn device_name(&self) -> &str {
        "loop"
    }
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }
}

impl BlockDriverOps for LoopBlockDevice {
    fn num_blocks(&self) -> u64 {
        LOOP_DEVICES[self.id].size.load(Ordering::Acquire) / self.block_size() as u64
    }

    fn block_size(&self) -> usize {
        512
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        let file = {
            let backing = LOOP_DEVICES[self.id].backing.lock();
            backing.as_ref().cloned()
        };
        if let Some(file) = file {
            let offset = block_id * self.block_size() as u64;
            file.read_at(buf, offset).map_err(|_| DevError::Io)?;
            Ok(())
        } else {
            Err(DevError::BadState)
        }
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        let file = {
            let backing = LOOP_DEVICES[self.id].backing.lock();
            backing.as_ref().cloned()
        };
        if let Some(file) = file {
            let offset = block_id * self.block_size() as u64;
            file.write_at(buf, offset).map_err(|_| DevError::Io)?;
            Ok(())
        } else {
            Err(DevError::BadState)
        }
    }

    fn flush(&mut self) -> DevResult {
        let backing = LOOP_DEVICES[self.id].backing.lock();
        if let Some(file) = backing.as_ref() {
            file.sync(false).map_err(|_| DevError::Io)?;
        }
        Ok(())
    }
}
