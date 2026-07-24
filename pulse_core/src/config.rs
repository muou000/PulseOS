/// The size of the kernel stack.
pub const KERNEL_STACK_SIZE: usize = 0x4_0000;

/// The base address of the user space.
pub const USER_SPACE_BASE: usize = 0x1000;
/// The size of the user space.
pub const USER_SPACE_SIZE: usize = 0x3f_ffff_f000;

/// The highest address of the user stack.
pub const USER_STACK_TOP: usize = 0x4_0000_0000;
/// The size of the user stack.
pub const USER_STACK_SIZE: usize = 0x8_0000;

/// The minimum address selected for a process's initial program break.
pub const USER_HEAP_BASE: usize = 0x4000_0000;

/// The base address for user interpreter.
pub const USER_INTERP_BASE: usize = 0x400_0000;
