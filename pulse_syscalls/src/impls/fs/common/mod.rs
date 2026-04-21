use alloc::{collections::BTreeSet, string::String};

use spin::Lazy;

mod fd;
mod path_resolve;
mod permission;

pub(crate) use fd::*;
pub(crate) use path_resolve::*;
pub(crate) use permission::*;

pub(crate) static MOUNTED_TARGETS: Lazy<spin::Mutex<BTreeSet<String>>> =
    Lazy::new(|| spin::Mutex::new(BTreeSet::new()));
