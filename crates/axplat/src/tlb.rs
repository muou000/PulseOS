//! Translation lookaside buffer policy.

/// Platform-specific TLB invalidation policy.
#[def_plat_interface]
pub trait TlbIf {
    /// Returns whether RISC-V TLB invalidations must use the global form.
    ///
    /// This is used for platforms with a hardware erratum that can make
    /// address- or ASID-scoped `sfence.vma` unreliable. Platforms without such
    /// a restriction should return `false` so ASID-scoped invalidation remains
    /// available.
    fn requires_global_sfence() -> bool;
}
