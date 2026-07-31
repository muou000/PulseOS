//! Device driver prelude that includes some traits and types.

pub use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
#[cfg(all(feature = "block", feature = "async"))]
pub use axdriver_block::{
    AsyncBlockDriverOps, DynAsyncBlockDriverOps, OwnedReadBufferRegistration,
    register_owned_read_buffer,
};
#[cfg(feature = "block")]
pub use {crate::structs::AxBlockDevice, axdriver_block::BlockDriverOps};
#[cfg(feature = "display")]
pub use {crate::structs::AxDisplayDevice, axdriver_display::DisplayDriverOps};
#[cfg(feature = "net")]
pub use {crate::structs::AxNetDevice, axdriver_net::NetDriverOps};
