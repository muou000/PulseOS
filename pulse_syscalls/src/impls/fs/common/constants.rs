use alloc::collections::BTreeSet;
use alloc::string::String;

use arceos_posix_api::ctypes;
use spin::Lazy;

pub(crate) const O_NONBLOCK: usize = ctypes::O_NONBLOCK as usize;
pub(crate) const O_CLOEXEC: usize = ctypes::O_CLOEXEC as usize;
pub(crate) const AT_FDCWD: i32 = -100;
pub(crate) const AT_SYMLINK_NOFOLLOW: usize = 0x100;
pub(crate) const AT_EACCESS: usize = 0x200;
pub(crate) const AT_REMOVEDIR: usize = 0x200;
pub(crate) const AT_EMPTY_PATH: usize = 0x1000;
pub(crate) const FACCESS_R_OK: usize = 4;
pub(crate) const FACCESS_W_OK: usize = 2;
pub(crate) const FACCESS_X_OK: usize = 1;
pub(crate) const FACCESS_MODE_MASK: usize = FACCESS_R_OK | FACCESS_W_OK | FACCESS_X_OK;

pub(crate) static MOUNTED_TARGETS: Lazy<spin::Mutex<BTreeSet<String>>> =
	Lazy::new(|| spin::Mutex::new(BTreeSet::new()));
