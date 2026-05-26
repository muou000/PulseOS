use alloc::sync::Arc;
use axerrno::LinuxError;
use crate::{impls::fs::common::get_fd_entry, net::Socket};

mod addr;
mod io;
mod name;
mod opt;
mod socket;

pub use self::{io::*, name::*, opt::*, socket::*};

pub(super) fn get_socket(fd: usize) -> Result<Arc<Socket>, LinuxError> {
    let entry = get_fd_entry(fd)?;
    Socket::from_fd_entry(&entry.object)
}
