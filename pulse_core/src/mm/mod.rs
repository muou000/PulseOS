pub mod pinned_buffers;
#[cfg(feature = "mapping-lifecycle-test")]
pub mod lifecycle_checks;

use axerrno::AxResult;
use axmm::AddrSpace;
pub use elf_loader::{ExecCredentials, UserAppLoadInfo, check_elf_header, prefault_range};
pub use pinned_buffers::{
    FixedBufferIo, FixedBufferPages, PinnedUserBuffers, UserBufferCursor, UserIoSegment,
    fits_single_pin_window, pin_fixed_buffer_pages, release_pinned_user_frame,
    release_pinned_user_frames, release_pinned_user_frames_slice,
};

/// Supplies the process-side mapping source for the executable and its interpreter.
pub fn load_user_app(
    aspace: &mut AddrSpace,
    fs: &axfs::FsContext,
    credentials: ExecCredentials,
    main_location: axfs_ng_vfs::Location,
    main_exec_access: axfs::ExecAccessGuard,
    path: &str,
    execfn_path: &str,
    args: &[&str],
    envs: &[&str],
) -> AxResult<UserAppLoadInfo> {
    elf_loader::load_user_app(
        aspace,
        fs,
        credentials,
        elf_loader::ExecImageInput {
            location: main_location,
            exec_access: main_exec_access,
            path,
            execfn_path,
            args,
            envs,
        },
        |file| {
            #[cfg(feature = "bpf-trace")]
            { crate::bpf::mappings::file_source(file, true) }
            #[cfg(not(feature = "bpf-trace"))]
            { alloc::sync::Arc::new(file) }
        },
    )
}

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
