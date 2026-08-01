//! System and process-adjacent syscalls that do not belong to a dedicated subsystem.

use core::sync::atomic::{AtomicBool, Ordering};

use axalloc::global_allocator;
use axfs::FS_CONTEXT;
use linux_raw_sys::general::{
    GRND_INSECURE, GRND_NONBLOCK, GRND_RANDOM, RLIMIT_AS, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_DATA,
    RLIMIT_FSIZE, RLIMIT_MEMLOCK, RLIMIT_MSGQUEUE, RLIMIT_NICE, RLIMIT_NOFILE, RLIMIT_NPROC,
    RLIMIT_RSS, RLIMIT_RTPRIO, RLIMIT_RTTIME, RLIMIT_SIGPENDING, RLIMIT_STACK, rlimit64,
};
use pulse_core::task::uaccess;

use crate::{LinuxError, impls::utils::alloc_zeroed_bytes};

mod process;
mod system;

pub(crate) use process::*;
pub(crate) use system::*;
