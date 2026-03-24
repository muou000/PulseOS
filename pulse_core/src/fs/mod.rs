#![allow(unused_variables)]

mod fd_table;

pub use fd_table::{FdTable, FileDesc};

use axerrno::{AxError, AxResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Regular,
    Directory,
    SymLink,
    CharDevice,
    BlockDevice,
}

#[derive(Debug, Clone)]
pub struct FileStat {
    pub file_type: FileType,
    pub size: u64,
    pub inode: u64,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct OpenFlags(u32);

#[allow(dead_code)]
impl OpenFlags {
    pub const RDONLY: Self = Self(0o0);
    pub const WRONLY: Self = Self(0o1);
    pub const RDWR: Self = Self(0o2);
    pub const CREATE: Self = Self(0o100);
    pub const TRUNC: Self = Self(0o1000);
    pub const APPEND: Self = Self(0o2000);
}

/// 打开文件
pub fn open(path: &str, flags: OpenFlags) -> AxResult<usize> {
    // TODO: 实现文件打开
    Err(AxError::Unsupported)
}

pub fn close(fd: usize) -> AxResult<()> {
    // TODO: 实现文件关闭
    Err(AxError::Unsupported)
}

/// 读取文件
pub fn read(fd: usize, buf: &mut [u8]) -> AxResult<usize> {
    // TODO: 实现文件读取
    Err(AxError::Unsupported)
}

/// 写入文件
pub fn write(fd: usize, buf: &[u8]) -> AxResult<usize> {
    // TODO: 实现文件写入
    Err(AxError::Unsupported)
}

/// 获取文件信息
pub fn stat(path: &str) -> AxResult<FileStat> {
    // TODO: 实现文件状态获取
    Err(AxError::Unsupported)
}
