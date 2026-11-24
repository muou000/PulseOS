//! Two-load, non-faulting frame capture for the RV64/LA64 sampling observer.
//!
//! The platform trap adapter must call [`fixup_read_fault`] before any page
//! resolver for supervisor data faults. Only these two assembly load PCs match;
//! normal user copies retain their existing fault-in semantics.

use crate::TrapFrame;

#[cfg(target_arch = "riscv64")]
core::arch::global_asm!(
    r#"
    .section .text
    .balign 4
    .global pulse_sample_read_frame
pulse_sample_read_frame:
    .global pulse_sample_load_first
pulse_sample_load_first:
    ld t0, 0(a1)
    .global pulse_sample_load_second
pulse_sample_load_second:
    ld t1, 8(a1)
    sd t0, 0(a0)
    sd t1, 8(a0)
    li a0, 1
    ret
    .global pulse_sample_read_failed
pulse_sample_read_failed:
    li a0, 0
    ret
"#
);

#[cfg(target_arch = "loongarch64")]
core::arch::global_asm!(
    r#"
    .section .text
    .balign 4
    .global pulse_sample_read_frame
pulse_sample_read_frame:
    .global pulse_sample_load_first
pulse_sample_load_first:
    ld.d $t0, $a1, 0
    .global pulse_sample_load_second
pulse_sample_load_second:
    ld.d $t1, $a1, 8
    st.d $t0, $a0, 0
    st.d $t1, $a0, 8
    addi.d $a0, $zero, 1
    jr $ra
    .global pulse_sample_read_failed
pulse_sample_read_failed:
    move $a0, $zero
    jr $ra
"#
);

unsafe extern "C" {
    fn pulse_sample_read_frame(destination: *mut u64, address: usize) -> usize;
    fn pulse_sample_load_first();
    fn pulse_sample_load_second();
    fn pulse_sample_read_failed();
}

/// Redirect only a failed load from the dedicated sampling reader.
/// Caller must have classified the trap as a supervisor data-read fault.
pub fn fixup_read_fault(tf: &mut TrapFrame) -> bool {
    if tf.ip() == pulse_sample_load_first as *const () as usize
        || tf.ip() == pulse_sample_load_second as *const () as usize
    {
        tf.set_ip(pulse_sample_read_failed as *const () as usize);
        true
    } else {
        false
    }
}

/// Read one aligned FP record as opaque machine words, or report a data fault.
/// No Rust reference to the source memory is constructed.
///
/// # Safety
/// On RV64/LA64 the caller must keep IRQs disabled throughout this call, install
/// `fixup_read_fault` before the resolver, and enable supervisor user access when
/// needed. `address` must be 8-byte aligned, with a checked 16-byte extent in
/// either the current live kernel stack or the current process's user range.
/// The source must be ordinary RAM, never MMIO. Kernel stack lifetime must be
/// retained; user address-space replacement and VMA removal must be excluded.
/// Concurrent userspace writes may tear the two-word observation; callers must
/// validate both integers before treating them as a frame. Assembly reads of
/// machine stack/user RAM are a platform contract, not Rust typed dereferences.
pub unsafe fn read_frame_nofault(address: usize) -> Option<[u8; 16]> {
    let mut words = [0u64; 2];
    // SAFETY: `words` supplies a live, aligned, exclusive 16-byte destination.
    // The caller establishes the source/trap obligations above. The assembly
    // writes both words only after both loads succeed, preserves callee-saved
    // registers, and returns 0 via the exact fault continuation on either fault.
    if unsafe { pulse_sample_read_frame(words.as_mut_ptr(), address) } == 0 {
        return None;
    }
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&words[0].to_le_bytes());
    bytes[8..].copy_from_slice(&words[1].to_le_bytes());
    Some(bytes)
}
