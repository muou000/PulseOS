//! System V shared memory and semaphores.
#![no_std]

extern crate alloc;

pub mod sem;
pub mod shm;

pub const IPC_PRIVATE: i32 = 0;
pub const IPC_CREAT: i32 = 0o1000;
pub const IPC_EXCL: i32 = 0o2000;
pub const IPC_RMID: i32 = 0;
pub const IPC_SET: i32 = 1;
pub const IPC_STAT: i32 = 2;

/// Permission record in the PulseOS SysV IPC userspace ABI.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IpcPerm {
    /// IPC key
    pub key: i32,
    /// effective UID of owner
    pub uid: u32,
    /// effective GID of owner
    pub gid: u32,
    /// effective UID of creator
    pub cuid: u32,
    /// effective GID of creator
    pub cgid: u32,
    /// permission bits and object-specific flags
    pub mode: u16,
    _pad: [u8; 2],
    _seq: u16,
    _pad2: u16,
    _pad3: u32,
    _pad4: u32,
}

pulse_user_abi::impl_user_abi_struct! {
    for IpcPerm, size = 36 => {
        key: i32,
        uid: u32,
        gid: u32,
        cuid: u32,
        cgid: u32,
        mode: u16,
        _pad: [u8; 2],
        _seq: u16,
        _pad2: u16,
        _pad3: u32,
        _pad4: u32,
    }
}

impl IpcPerm {
    pub fn is_owner(&self, euid: u32) -> bool {
        euid == 0 || euid == self.uid || euid == self.cuid
    }
}
