//! RISC-V user vector state. The platform publishes a common register width
//! before scheduling user tasks. The kernel itself is built for RV64GC.

use core::{
    arch::asm,
    sync::atomic::{AtomicUsize, Ordering},
};

static VLENB: AtomicUsize = AtomicUsize::new(0);
const VS_MASK: usize = 3 << 9;

/// Number of bytes per user vector register, or zero when the platform disables V.
pub fn vlenb() -> usize {
    VLENB.load(Ordering::Acquire)
}

/// Reads the width on a hart that the platform has identified as V-capable.
///
/// # Safety
///
/// Call in S-mode during hart bring-up with interrupts masked, before this hart
/// owns any task's vector state. The hart must implement the V 1.0 extension.
pub unsafe fn hardware_vlenb() -> usize {
    let width: usize;
    // SAFETY: The caller established V support and excluded interrupts. Enabling
    // VS permits the read-only CSR access. Restore the original status before
    // returning to the bootstrap code.
    unsafe {
        asm!(
            "csrrs {old}, sstatus, {mask}",
            "csrr {width}, 0xc22",
            "csrw sstatus, {old}",
            old = out(reg) _, width = out(reg) width, mask = in(reg) VS_MASK,
            options(nomem, nostack),
        );
    }
    width
}

/// Enables user V with the register width of the boot hart.
///
/// # Safety
///
/// The platform must guarantee that every hart admitted to scheduling user
/// tasks implements V 1.0 with the same register width and compatible vector
/// configuration. Call once in S-mode on the boot hart with interrupts masked,
/// before task creation or secondary startup.
pub unsafe fn initialize() {
    // SAFETY: primary platform initialization established V 1.0, owns this hart
    // before tasks can run and has not enabled interrupts.
    let width = unsafe { hardware_vlenb() };
    // V mandates a power-of-two VLEN from 128 to 65536 bits.
    assert!(width.is_power_of_two() && (16..=8192).contains(&width));
    VLENB
        .compare_exchange(0, width, Ordering::Release, Ordering::Relaxed)
        .expect("RVV already initialized");
}

#[cfg(feature = "uspace")]
pub use task_state::VectorState;
#[cfg(feature = "uspace")]
pub(crate) use task_state::{reset_for_exec, switch};

#[cfg(feature = "uspace")]
mod task_state {
    extern crate alloc;

    use core::mem::offset_of;

    use riscv::interrupt::supervisor;

    use self::alloc::{collections::TryReserveError, vec::Vec};
    use super::{VS_MASK, asm, vlenb};

    // Each transfer processes four groups of eight whole registers (RVV 1.0
    // § Vector Load/Store Whole Register Instructions), independent of vl/vtype.
    core::arch::global_asm!(
        include_str!("vector.S"),
        vstart = const offset_of!(Control, vstart),
        vl = const offset_of!(Control, vl),
        vtype = const offset_of!(Control, vtype),
        vcsr = const offset_of!(Control, vcsr),
    );

    #[repr(C)]
    #[derive(Debug, Default)]
    struct Control {
        vstart: usize,
        vl: usize,
        vtype: usize,
        vcsr: usize,
    }

    unsafe extern "C" {
        fn riscv_save_vectors(registers: *mut u64, control: &mut Control, stride: usize);
        fn riscv_restore_vectors(registers: *const u64, control: &Control, stride: usize);
        fn riscv_zero_vectors();
    }

    fn vs() -> usize {
        let status: usize;
        // SAFETY: PulseOS runs in S-mode. This reads only the status CSR.
        unsafe { asm!("csrr {}, sstatus", out(reg) status, options(nomem, nostack)) };
        status & VS_MASK
    }

    /// An owned snapshot of 32 full-width registers and their vector controls.
    #[derive(Debug)]
    pub struct VectorState {
        // Safety invariant: owns exactly 32 * vlenb() bytes of u64-aligned storage.
        // capture constructs it at the published width; no operation resizes it.
        registers: Vec<u64>,
        control: Control,
    }

    impl VectorState {
        /// Captures the current user task for fork or signal delivery. A kernel
        /// parent has VS off and supplies zero initial state to its first child.
        pub fn capture() -> Result<Option<Self>, TryReserveError> {
            let width = vlenb();
            if width == 0 {
                return Ok(None);
            }
            let words = 32 * width / size_of::<u64>();
            let mut registers = Vec::new();
            registers.try_reserve_exact(words)?;
            registers.resize(words, 0);
            let mut state = Self {
                registers,
                control: Control::default(),
            };
            supervisor::free(|| {
                if vs() != 0 {
                    state.save();
                }
            });
            Ok(Some(state))
        }

        fn save(&mut self) {
            // SAFETY: Called with interrupts masked and VS enabled. initialize's
            // scheduling invariant and capture's allocation give exactly 32
            // registers of writable, aligned storage, exclusively borrowed here.
            // Assembly saves and reinstates vstart around the whole-register stores.
            unsafe {
                riscv_save_vectors(self.registers.as_mut_ptr(), &mut self.control, 8 * vlenb());
            }
        }

        fn restore(&self) {
            // SAFETY: The constructor sized the immutable aligned buffer for all
            // 32 registers at the platform's immutable common width. Callers own
            // this hart with interrupts masked, so enabling VS and restoring all
            // registers, then vl/vtype, vcsr and finally vstart, is indivisible
            // with respect to scheduling. Kernel code uses the scalar ABI.
            unsafe {
                asm!("csrs sstatus, {}", in(reg) VS_MASK, options(nostack));
                riscv_restore_vectors(self.registers.as_ptr(), &self.control, 8 * vlenb());
            }
        }

        /// Reinstates interrupted user state after a signal handler. VS stays
        /// dirty so the next switch records this change to the live task.
        pub fn restore_after_signal(&self) {
            supervisor::free(|| self.restore());
        }
    }

    pub(crate) fn switch(current: Option<&mut VectorState>, next: Option<&VectorState>) {
        if let Some(current) = current {
            if vs() == VS_MASK {
                current.save();
            }
        }
        if let Some(next) = next {
            next.restore();
            // SAFETY: restore set VS=Dirty (11). Clear its low bit to mark the
            // live registers Clean (10) relative to next's saved image.
            unsafe { asm!("csrc sstatus, {}", in(reg) 1usize << 9, options(nostack)) };
        } else {
            // SAFETY: The scheduler owns the hart. Clear the standard sstatus
            // field even with V disabled so the next task cannot inherit VS
            // from firmware. Harts without V hardwire these bits to zero.
            unsafe { asm!("csrc sstatus, {}", in(reg) VS_MASK, options(nostack)) };
        }
    }

    pub(crate) fn reset_for_exec() {
        if vlenb() != 0 {
            // SAFETY: Called with interrupts disabled during the user entry
            // transition after the scheduler has restored this task's vectors.
            // Clear all register groups to VLMAX and reset the controls so the
            // new image cannot observe the previous image's vector state.
            unsafe { riscv_zero_vectors() };
        }
    }
}
