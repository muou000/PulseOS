//! Trap handling.

use memory_addr::VirtAddr;

pub use crate::TrapFrame;
pub use linkme::distributed_slice as def_trap_handler;
pub use linkme::distributed_slice as register_trap_handler;
pub use page_table_entry::MappingFlags as PageFaultFlags;

/// A slice of IRQ handler functions.
#[def_trap_handler]
pub static IRQ: [fn(usize) -> bool];

/// A slice of page fault handler functions.
#[def_trap_handler]
pub static PAGE_FAULT: [fn(VirtAddr, PageFaultFlags, bool) -> bool];

/// A slice of illegal instruction handler functions.
#[cfg(feature = "uspace")]
#[def_trap_handler]
pub static ILLEGAL_INSTRUCTION: [fn(&mut TrapFrame, usize, bool) -> bool];

/// A slice of address error handler functions.
#[cfg(feature = "uspace")]
#[def_trap_handler]
pub static ADDRESS_ERROR: [fn(&mut TrapFrame, usize, bool) -> bool];

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
