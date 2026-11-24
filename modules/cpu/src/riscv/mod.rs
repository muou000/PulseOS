#[macro_use]
mod macros;

mod context;
mod trap;

pub mod asm;
pub mod init;

#[cfg(target_arch = "riscv64")]
pub mod riscv_vector;

#[cfg(feature = "uspace")]
pub mod uspace;

pub use self::context::{FpState, GeneralRegisters, TaskContext, TrapFrame};

core::arch::global_asm!(include_asm_macros!(), include_str!("user_copy.S"));

unsafe extern "C" {
    pub fn user_copy(dst: *mut u8, src: *const u8, size: usize) -> usize;
}
