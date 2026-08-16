#[macro_use]
mod macros;

mod context;
mod trap;
#[cfg(feature = "ls2k1000")]
mod unaligned;

pub mod asm;
pub mod init;

#[cfg(feature = "uspace")]
pub mod uspace;

pub use self::context::{FpuState, GeneralRegisters, TaskContext, TrapFrame};
#[cfg(feature = "ls2k1000")]
pub use self::unaligned::{
    UnalignedAccess, UnalignedAccessType, UnalignedError, UnalignedPageFault,
};

core::arch::global_asm!(include_asm_macros!(), include_str!("user_copy.S"));

unsafe extern "C" {
    pub fn user_copy(dst: *mut u8, src: *const u8, size: usize) -> usize;
}
