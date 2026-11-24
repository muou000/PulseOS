//! Structures and functions for user space.

use memory_addr::VirtAddr;
#[cfg(feature = "fp-simd")]
use riscv::register::sstatus::FS;
use riscv::register::sstatus::Sstatus;

use crate::{GeneralRegisters, TrapFrame};

/// Context to enter user space.
pub struct UspaceContext {
    frame: TrapFrame,
    #[cfg(target_arch = "riscv64")]
    fresh_image: bool,
}

impl UspaceContext {
    /// Creates an empty context with all registers set to zero.
    pub const fn empty() -> Self {
        unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
    }

    /// Creates a new context with the given entry point, user stack pointer,
    /// and the argument.
    pub fn new(entry: usize, ustack_top: VirtAddr, arg0: usize) -> Self {
        let mut sstatus = Sstatus::from_bits(0);
        sstatus.set_spie(true); // enable interrupts
        #[cfg(feature = "fp-simd")]
        {
            sstatus.set_fs(FS::Initial); // set the FPU to initial state
        }

        Self {
            frame: TrapFrame {
                regs: GeneralRegisters {
                    a0: arg0,
                    sp: ustack_top.as_usize(),
                    ..Default::default()
                },
                sepc: entry,
                sstatus,
            },
            #[cfg(target_arch = "riscv64")]
            fresh_image: true,
        }
    }

    /// Creates a new context from the given [`TrapFrame`].
    pub const fn from(trap_frame: &TrapFrame) -> Self {
        Self {
            frame: *trap_frame,
            #[cfg(target_arch = "riscv64")]
            fresh_image: false,
        }
    }

    /// Gets the instruction pointer.
    pub const fn get_ip(&self) -> usize {
        self.frame.sepc
    }

    /// Gets the stack pointer.
    pub const fn get_sp(&self) -> usize {
        self.frame.regs.sp
    }

    /// Sets the instruction pointer.
    pub const fn set_ip(&mut self, pc: usize) {
        self.frame.sepc = pc;
    }

    /// Sets the stack pointer.
    pub const fn set_sp(&mut self, sp: usize) {
        self.frame.regs.sp = sp;
    }

    /// Sets the return value register.
    pub const fn set_retval(&mut self, a0: usize) {
        self.frame.regs.a0 = a0;
    }

    /// Enters user space.
    ///
    /// It restores the user registers and jumps to the user entry point
    /// (saved in `sepc`).
    /// When an exception or syscall occurs, the kernel stack pointer is
    /// switched to `kstack_top`.
    ///
    /// # Safety
    ///
    /// This function is unsafe because it changes processor mode and the stack.
    pub unsafe fn enter_uspace(&self, kstack_top: VirtAddr) -> ! {
        use riscv::register::{sepc, sscratch};

        crate::asm::disable_irqs();
        #[cfg(target_arch = "riscv64")]
        if self.fresh_image {
            super::riscv_vector::reset_for_exec();
        }
        // Address of the top of the kernel stack after saving the trap frame.
        let kernel_trap_addr = kstack_top.as_usize() - core::mem::size_of::<TrapFrame>();
        unsafe {
            sscratch::write(kstack_top.as_usize());
            sepc::write(self.frame.sepc);
            core::arch::asm!(
                include_asm_macros!(),
                "
                mv      sp, {tf}

                STR     gp, {kernel_trap_addr}, 3
                LDR     gp, sp, 3

                STR     tp, {kernel_trap_addr}, 4
                LDR     tp, sp, 4

                LDR     t0, sp, 33
                RESTORE_SSTATUS t0, t1
                POP_GENERAL_REGS
                LDR     sp, sp, 2
                sret",
                tf = in(reg) &(self.frame),
                kernel_trap_addr = in(reg) kernel_trap_addr,
                options(noreturn),
            )
        }
    }
}

impl core::ops::Deref for UspaceContext {
    type Target = TrapFrame;
    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.frame
    }
}

impl core::ops::DerefMut for UspaceContext {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.frame
    }
}
