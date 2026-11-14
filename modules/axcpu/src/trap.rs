//! Trap handling.

pub use linkme::{
    distributed_slice as def_trap_handler, distributed_slice as register_trap_handler,
};
use memory_addr::VirtAddr;
pub use page_table_entry::MappingFlags as PageFaultFlags;

pub use crate::TrapFrame;

/// The architectural class of an address exception.
///
/// Keep this distinction through the generic trap dispatch so user-space can
/// observe the Linux-compatible SIGBUS subcode for the underlying fault.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    BadAddress,
    Misaligned,
}

/// A slice of IRQ handler functions.
#[def_trap_handler]
pub static IRQ: [fn(usize) -> bool];

/// Read-only IRQ observers invoked before the normal platform IRQ handler.
///
/// An observer receives the interrupted register state, not a later worker's
/// registers. Observers run with local IRQs disabled and must remain bounded:
/// copy scalar state to preallocated storage without sleeping, waiting on locks,
/// enabling interrupts, or scheduling. No reference to `TrapFrame` may be kept
/// after the callback returns. Registration does not consume the interrupt.
#[def_trap_handler]
pub static IRQ_OBSERVER: [fn(usize, &TrapFrame, bool)];

/// Notify observers while the architecture trap frame is still current.
#[inline]
pub(crate) fn observe_irq(vector: usize, tf: &TrapFrame, from_user: bool) {
    for observer in IRQ_OBSERVER.iter() {
        observer(vector, tf, from_user);
    }
}

/// A slice of page fault handler functions.
#[def_trap_handler]
pub static PAGE_FAULT: [fn(&mut TrapFrame, VirtAddr, PageFaultFlags, bool) -> bool];

/// A slice of illegal instruction handler functions.
#[cfg(feature = "uspace")]
#[def_trap_handler]
pub static ILLEGAL_INSTRUCTION: [fn(&mut TrapFrame, usize, bool) -> bool];

/// A slice of address error handler functions.
#[cfg(feature = "uspace")]
#[def_trap_handler]
pub static ADDRESS_ERROR: [fn(&mut TrapFrame, usize, AddressError, bool) -> bool];

/// A slice of syscall handler functions.
#[cfg(feature = "uspace")]
#[cfg_attr(docsrs, doc(cfg(feature = "uspace")))]
#[def_trap_handler]
pub static SYSCALL: [fn(&mut TrapFrame, usize) -> isize];

/// A slice of handlers called before returning from a user trap.
#[cfg(feature = "uspace")]
#[cfg_attr(docsrs, doc(cfg(feature = "uspace")))]
#[def_trap_handler]
pub static USER_RETURN: [fn(&mut TrapFrame)];

#[allow(unused_macros)]
macro_rules! handle_trap {
    ($trap:ident, $($args:tt)*) => {{
        let mut iter = $crate::trap::$trap.iter();
        if let Some(func) = iter.next() {
            if iter.next().is_some() {
                warn!("Multiple handlers for trap {} are not currently supported", stringify!($trap));
            }
            func($($args)*)
        } else {
            warn!("No registered handler for trap {}", stringify!($trap));
            false
        }
    }}
}

/// Call the external syscall handler.
#[cfg(feature = "uspace")]
pub(crate) fn handle_syscall(tf: &mut TrapFrame, syscall_num: usize) -> isize {
    SYSCALL[0](tf, syscall_num)
}

/// Call the optional user-return handler.
#[cfg(feature = "uspace")]
pub(crate) fn handle_user_return(tf: &mut TrapFrame) {
    let mut iter = USER_RETURN.iter();
    if let Some(func) = iter.next() {
        if iter.next().is_some() {
            warn!("Multiple handlers for trap USER_RETURN are not currently supported");
        }
        func(tf);
    }
}
