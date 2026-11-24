//! Compatibility paths for kernel consumers migrating to the process subsystem.
#![no_std]

pub use process as task;
pub use process::fd::{cpu_dma_latency, flock, record_lock};
pub use process::{bpf, fd as fd_table, io_uring, socket as net, trap};

pub mod config {
    pub use axconfig::{KERNEL_STACK_SIZE, user::*};
}

pub mod mm {
    pub use axmm::copy_from_kernel;
    pub use elf_loader::{ExecCredentials, UserAppLoadInfo, check_elf_header, prefault_range};
    pub use process::exec::load_user_app;
    #[cfg(feature = "mapping-lifecycle-test")]
    pub use process::lifecycle_checks;
    pub use process::uaccess::{
        FixedBufferIo, FixedBufferPages, PinnedUserBuffers, UserBufferCursor, UserIoSegment,
        fits_single_pin_window, pin_fixed_buffer_pages, pinned_buffers, release_pinned_user_frame,
        release_pinned_user_frames, release_pinned_user_frames_slice,
    };
}
