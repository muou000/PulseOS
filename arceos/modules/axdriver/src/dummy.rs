//! Dummy types used if no device of a certain category is selected.

use cfg_if::cfg_if;

#[cfg(any(net_dev = "dummy", block_dev = "dummy", display_dev = "dummy"))]
use super::prelude::*;

cfg_if! {
    if #[cfg(net_dev = "dummy")] {
        use axdriver_net::{EthernetAddress, NetBuf, NetBufBox, NetBufPool, NetBufPtr};

        pub struct DummyNetDev;
        register_net_driver!(DummyNetDev);

        impl BaseDriverOps for DummyNetDev {
            fn device_type(&self) -> DeviceType { DeviceType::Net }
            fn device_name(&self) -> &str { "dummy-net" }
        }

        impl NetDriverOps for DummyNetDev {
            fn mac_address(&self) -> EthernetAddress { unreachable!() }
            fn can_transmit(&self) -> bool { false }
            fn can_receive(&self) -> bool { false }
            fn rx_queue_size(&self) -> usize { 0 }
            fn tx_queue_size(&self) -> usize { 0 }
            fn recycle_rx_buffer(&mut self, _: NetBufPtr) -> DevResult { Err(DevError::Unsupported) }
            fn recycle_tx_buffers(&mut self) -> DevResult { Err(DevError::Unsupported) }
            fn transmit(&mut self, _: NetBufPtr) -> DevResult { Err(DevError::Unsupported) }
            fn receive(&mut self) -> DevResult<NetBufPtr> { Err(DevError::Unsupported) }
            fn alloc_tx_buffer(&mut self, _: usize) -> DevResult<NetBufPtr> { Err(DevError::Unsupported) }
        }
    }
}

cfg_if! {
    if #[cfg(block_dev = "dummy")] {
        pub struct DummyBlockDev;
        register_block_driver!(DummyBlockDev);

        impl BaseDriverOps for DummyBlockDev {
            fn device_type(&self) -> DeviceType {
                DeviceType::Block
            }
            fn device_name(&self) -> &str {
                "dummy-block"
            }
        }

        impl BlockDriverOps for DummyBlockDev {
            fn num_blocks(&self) -> u64 {
                0
            }
            fn block_size(&self) -> usize {
                0
            }
            fn read_block(&mut self, _: u64, _: &mut [u8]) -> DevResult {
                Err(DevError::Unsupported)
            }
            fn write_block(&mut self, _: u64, _: &[u8]) -> DevResult {
                Err(DevError::Unsupported)
            }
            fn flush(&mut self) -> DevResult {
                Err(DevError::Unsupported)
            }
        }
    }
}

cfg_if! {
    if #[cfg(display_dev = "dummy")] {
        pub struct DummyDisplayDev;
        register_display_driver!(DummyDisplayDev);

        impl BaseDriverOps for DummyDisplayDev {
            fn device_type(&self) -> DeviceType {
                DeviceType::Display
            }
            fn device_name(&self) -> &str {
                "dummy-display"
            }
        }

        impl DisplayDriverOps for DummyDisplayDev {
            fn info(&self) -> axdriver_display::DisplayInfo {
                unreachable!()
            }
            fn fb(&self) -> axdriver_display::FrameBuffer {
                unreachable!()
            }
            fn need_flush(&self) -> bool {
                false
            }
            fn flush(&mut self) -> DevResult {
                Err(DevError::Unsupported)
            }
        }
    }
}
