//! Power management.

use core::{convert::Infallible, fmt};

/// Error returned when a secondary CPU cannot be started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CpuBootError {
    /// The platform firmware does not support starting secondary CPUs.
    NotSupported,
    /// The logical CPU ID or firmware hart ID is invalid.
    InvalidParameter,
    /// The secondary entry address is not executable by the target CPU.
    InvalidAddress,
    /// The target CPU is already running.
    AlreadyOn,
    /// The firmware returned an unclassified error code.
    Firmware(isize),
}

impl fmt::Display for CpuBootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => f.write_str("secondary CPU boot is not supported"),
            Self::InvalidParameter => f.write_str("invalid secondary CPU boot parameter"),
            Self::InvalidAddress => f.write_str("invalid secondary CPU entry address"),
            Self::AlreadyOn => f.write_str("secondary CPU is already running"),
            Self::Firmware(error) => write!(f, "firmware CPU boot error {error}"),
        }
    }
}

impl core::error::Error for CpuBootError {}

/// Error returned when a platform cannot reset the whole system.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemResetError {
    /// The platform has no usable system reset mechanism.
    NotSupported,
    /// Firmware rejected the reset request with an implementation-defined code.
    Firmware(isize),
}

impl fmt::Display for SystemResetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotSupported => f.write_str("system reset is not supported"),
            Self::Firmware(error) => write!(f, "firmware system reset error {error}"),
        }
    }
}

impl core::error::Error for SystemResetError {}

/// Result of requesting a platform reset.
///
/// A successful system reset does not return to the caller.  The uninhabited
/// success type encodes that contract while allowing a platform to report an
/// unsupported or rejected reset request.
pub type SystemResetResult = Result<Infallible, SystemResetError>;

/// Power management interface.
#[def_plat_interface]
pub trait PowerIf {
    /// Bootstraps the given CPU core with the given initial stack (in physical
    /// address).
    ///
    /// Where `cpu_id` is the logical CPU ID (0, 1, ..., N-1, N is the number of
    /// CPU cores on the platform).
    ///
    /// # Errors
    ///
    /// Returns an error if the CPU ID cannot be resolved or the platform
    /// firmware rejects the boot request.
    #[cfg(feature = "smp")]
    fn cpu_boot(cpu_id: usize, stack_top_paddr: usize) -> Result<(), CpuBootError>;

    /// Shutdown the whole system.
    fn system_off() -> !;

    /// Reset the whole system.
    ///
    /// A successful reset does not return. Implementations must return an
    /// error when the platform cannot issue the request instead of silently
    /// turning it into a power-off or CPU halt.
    fn system_reset() -> SystemResetResult;

    /// Get the number of CPU cores available on this platform.
    ///
    /// The platform should either get this value statically from its
    /// configuration or dynamically by platform-specific methods.
    ///
    /// For statically configured platforms, by convention, this value should be
    /// the same as `MAX_CPU_NUM` defined in the platform configuration.
    fn cpu_num() -> usize;
}
