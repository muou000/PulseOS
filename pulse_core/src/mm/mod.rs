mod loader;

pub use loader::load_user_app;

use axerrno::AxResult;
use axmm::AddrSpace;

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
