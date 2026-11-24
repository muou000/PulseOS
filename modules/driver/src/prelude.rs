//! Device driver prelude that includes some traits and types.

pub use driver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
#[cfg(all(feature = "block", feature = "async"))]
pub use driver_block::{
    AsyncBlockDriverOps, DynAsyncBlockDriverOps, OwnedReadBufferRegistration,
    OwnedWriteBufferRegistration, register_owned_read_buffer, register_owned_write_buffer,
    run_owned_dma_guest_checks,
};
#[cfg(feature = "block")]
pub use {crate::structs::AxBlockDevice, driver_block::BlockDriverOps};
#[cfg(feature = "display")]
pub use {crate::structs::AxDisplayDevice, driver_display::DisplayDriverOps};
#[cfg(feature = "net")]
pub use {crate::structs::AxNetDevice, driver_net::NetDriverOps};
