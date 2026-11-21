mod loader;
pub mod pinned_buffers;
#[cfg(feature = "mapping-lifecycle-test")]
pub mod lifecycle_checks;

use axerrno::AxResult;
use axmm::AddrSpace;
pub use loader::{
    ExecCredentials, UserAppLoadInfo, check_elf_header, load_user_app, prefault_range,
};
pub use pinned_buffers::{
    FixedBufferIo, FixedBufferPages, PinnedUserBuffers, UserBufferCursor, UserIoSegment,
    fits_single_pin_window, pin_fixed_buffer_pages, release_pinned_user_frame,
    release_pinned_user_frames, release_pinned_user_frames_slice,
};

/// If the target architecture requires it, the kernel portion of the address
/// space will be copied to the user address space.
pub fn copy_from_kernel(_aspace: &mut AddrSpace) -> AxResult {
    #[cfg(not(any(target_arch = "aarch64", target_arch = "loongarch64")))]
    {
        // ARMv8 (aarch64) and LoongArch64 use separate page tables for user space
        // (aarch64: TTBR0_EL1, LoongArch64: PGDL), so there is no need to copy the
        // kernel portion to the user page table.
        _aspace.copy_mappings_from(&axmm::kernel_aspace().lock())?;
    }
    Ok(())
}
