use alloc::sync::Arc;
use core::ffi::{c_char, c_int};

use axerrno::{LinuxError, LinuxResult};
use axfs::OpenOptions;
use axfs_ng_vfs::{NodePermission, VfsError};
use axio::PollState;
use axsync::Mutex;

use super::fd_ops::{FileLike, get_file_like};
use crate::{ctypes, utils::char_ptr_to_str};

pub struct File {
    inner: Mutex<axfs::File>,
    offset: Mutex<u64>,
}

impl File {
    fn new(inner: axfs::File) -> Self {
        Self { inner: Mutex::new(inner), offset: Mutex::new(0) }
    }

    fn add_to_fd_table(self) -> LinuxResult<c_int> {
        super::fd_ops::add_file_like(Arc::new(self))
    }

    fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        f.into_any().downcast::<Self>().map_err(|_| LinuxError::EINVAL)
    }
}

impl FileLike for File {
    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let inner = self.inner.lock();
        let mut offset = self.offset.lock();
        let n = inner.read_at(buf, *offset)?;
        *offset += n as u64;
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let inner = self.inner.lock();
        if inner.flags().contains(axfs::FileFlags::APPEND) {
            // In append mode, writes always go to the end regardless of fd offset.
            let n = inner.write(buf)?;
            *self.offset.lock() = inner.location().len()?;
            Ok(n)
        } else {
            let mut offset = self.offset.lock();
            let n = inner.write_at(buf, *offset)?;
            *offset += n as u64;
            Ok(n)
        }
    }

    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let metadata = self.inner.lock().location().metadata()?;
        let ty = metadata.node_type as u8;
        let perm = metadata.mode.bits() as u32;
        let st_mode = ((ty as u32) << 12) | perm;
        Ok(ctypes::stat {
            st_ino: 1,
            st_nlink: 1,
            st_mode,
            st_uid: 1000,
            st_gid: 1000,
            st_size: metadata.size as _,
            st_blocks: metadata.blocks as _,
            st_blksize: 512,
            ..Default::default()
        })
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState { readable: true, writable: true })
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

pub struct DirFile {
    inner: Mutex<axfs::OpenResult>,
    offset: Mutex<u64>,
}

impl DirFile {
    fn new(dir: axfs::OpenResult) -> Self {
        Self { inner: Mutex::new(dir), offset: Mutex::new(0) }
    }
    fn from_fd(fd: c_int) -> LinuxResult<Arc<Self>> {
        let f = super::fd_ops::get_file_like(fd)?;
        f.into_any().downcast::<Self>().map_err(|_| LinuxError::EBADF)
    }
}

impl FileLike for DirFile {
    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EISDIR)
    }
    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }
    fn stat(&self) -> LinuxResult<ctypes::stat> {
        let inner = self.inner.lock();
        if let axfs::OpenResult::Dir(dir) = &*inner {
            let metadata = dir.metadata()?;
            let ty = metadata.node_type as u8;
            let perm = metadata.mode.bits() as u32;
            let st_mode = ((ty as u32) << 12) | perm;
            Ok(ctypes::stat {
                st_ino: 1,
                st_nlink: 1,
                st_mode,
                st_uid: 1000,
                st_gid: 1000,
                st_size: metadata.size as _,
                st_blocks: metadata.blocks as _,
                st_blksize: 512,
                ..Default::default()
            })
        } else {
            Err(LinuxError::EBADF)
        }
    }
    fn into_any(self: Arc<Self>) -> Arc<dyn core::any::Any + Send + Sync> {
        self
    }
    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState { readable: true, writable: false })
    }
    fn set_nonblocking(&self, _nonblocking: bool) -> LinuxResult {
        Ok(())
    }
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct LinuxDirent64 {
    pub d_ino: u64,
    pub d_off: i64,
    pub d_reclen: u16,
    pub d_type: u8,
}

pub unsafe fn sys_getdents64(fd: c_int, dirp: *mut u8, count: usize) -> c_int {
    debug!("sys_getdents64 <= {} {:#x} {}", fd, dirp as usize, count);
    syscall_body!(sys_getdents64, {
        let dirfile = DirFile::from_fd(fd)?;
        let mut offset = dirfile.offset.lock();
        let mut written = 0;
        let inner = dirfile.inner.lock();
        if let axfs::OpenResult::Dir(dir) = &*inner {
            let mut break_out = false;
            let res = dir.read_dir(*offset, &mut |name: &str,
                                                  ino: u64,
                                                  node_type: axfs::NodeType,
                                                  next_off: u64|
             -> bool {
                if break_out {
                    return false;
                }
                let name_bytes = name.as_bytes();
                let name_len = name_bytes.len();
                let unpadded_len = core::mem::size_of::<LinuxDirent64>() + name_len + 1;
                let reclen = (unpadded_len + 7) & !7;
                if written + reclen > count {
                    break_out = true;
                    return false;
                }
                let d_type = node_type as u8;
                let dst = unsafe { dirp.add(written) };
                let dirent = LinuxDirent64 {
                    d_ino: ino,
                    d_off: next_off as i64,
                    d_reclen: reclen as u16,
                    d_type,
                };
                unsafe {
                    core::ptr::write_unaligned(dst as *mut LinuxDirent64, dirent);
                    let name_dst = dst.add(core::mem::size_of::<LinuxDirent64>());
                    core::ptr::copy_nonoverlapping(name_bytes.as_ptr(), name_dst, name_len);
                    core::ptr::write_bytes(
                        name_dst.add(name_len),
                        0,
                        reclen - core::mem::size_of::<LinuxDirent64>() - name_len,
                    );
                }
                written += reclen;
                *offset = next_off;
                true
            });
            if let Err(e) = res {
                if written == 0 {
                    return Err(e.into());
                }
            }
            Ok(written as c_int)
        } else {
            Err(LinuxError::EBADF)
        }
    })
}

/// Convert open flags to [`OpenOptions`].
fn flags_to_options(flags: c_int, _mode: ctypes::mode_t) -> OpenOptions {
    let flags = flags as u32;
    let mut options = OpenOptions::new();
    match flags & 0b11 {
        ctypes::O_RDONLY => {
            options.read(true);
        }
        ctypes::O_WRONLY => {
            options.write(true);
        }
        _ => {
            options.read(true);
            options.write(true);
        }
    };
    if flags & ctypes::O_APPEND != 0 {
        options.append(true);
    }
    if flags & ctypes::O_TRUNC != 0 {
        options.truncate(true);
    }
    if flags & ctypes::O_CREAT != 0 {
        options.create(true);
    }
    if flags & ctypes::O_EXEC != 0 {
        options.create_new(true);
    }
    options
}

/// Open a file by `filename` and insert it into the file descriptor table.
///
/// Return its index in the file table (`fd`). Return `EMFILE` if it already
/// has the maximum number of files open.
pub fn sys_open(filename: *const c_char, flags: c_int, mode: ctypes::mode_t) -> c_int {
    let filename = char_ptr_to_str(filename);
    debug!("sys_open <= {:?} {:#o} {:#o}", filename, flags, mode);
    syscall_body!(sys_open, {
        let options = flags_to_options(flags, mode);
        let filename = filename?;
        let result = options.open(&axfs::FS_CONTEXT.lock(), filename)?;
        let f: Arc<dyn FileLike> = match result {
            axfs::OpenResult::File(file) => Arc::new(File::new(file)),
            dir_res @ axfs::OpenResult::Dir(_) => Arc::new(DirFile::new(dir_res)),
        };
        super::fd_ops::add_file_like(f)
    })
}

/// Set the position of the file indicated by `fd`.
///
/// Return its position after seek.
pub fn sys_lseek(fd: c_int, offset: ctypes::off_t, whence: c_int) -> ctypes::off_t {
    debug!("sys_lseek <= {} {} {}", fd, offset, whence);
    syscall_body!(sys_lseek, {
        let file = File::from_fd(fd)?;
        let new_offset: u64 = match whence {
            0 => {
                if offset < 0 {
                    Err(LinuxError::EINVAL)
                } else {
                    Ok(offset as u64)
                }
            }
            1 => {
                let cur = *file.offset.lock();
                cur.checked_add_signed(offset).ok_or(LinuxError::EINVAL)
            }
            2 => {
                let end = file.inner.lock().location().len()?;
                end.checked_add_signed(offset).ok_or(LinuxError::EINVAL)
            }
            _ => Err(LinuxError::EINVAL),
        }?;
        *file.offset.lock() = new_offset;
        Ok(new_offset as ctypes::off_t)
    })
}

/// Get the file metadata by `path` and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_stat(path: *const c_char, buf: *mut ctypes::stat) -> c_int {
    let path = char_ptr_to_str(path);
    debug!("sys_stat <= {:?} {:#x}", path, buf as usize);
    syscall_body!(sys_stat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        let path = path?;
        let mut options = OpenOptions::new();
        options.read(true);
        let opened = options.open(&axfs::FS_CONTEXT.lock(), path)?;
        let st = match opened {
            axfs::OpenResult::File(file) => File::new(file).stat()?,
            axfs::OpenResult::Dir(dir) => DirFile::new(axfs::OpenResult::Dir(dir)).stat()?,
        };
        unsafe { *buf = st };
        Ok(0)
    })
}

/// Get file metadata by `fd` and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_fstat(fd: c_int, buf: *mut ctypes::stat) -> c_int {
    debug!("sys_fstat <= {} {:#x}", fd, buf as usize);
    syscall_body!(sys_fstat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }

        unsafe { *buf = get_file_like(fd)?.stat()? };
        Ok(0)
    })
}

/// Get the metadata of the symbolic link and write into `buf`.
///
/// Return 0 if success.
pub unsafe fn sys_lstat(path: *const c_char, buf: *mut ctypes::stat) -> ctypes::ssize_t {
    let path = char_ptr_to_str(path);
    debug!("sys_lstat <= {:?} {:#x}", path, buf as usize);
    syscall_body!(sys_lstat, {
        if buf.is_null() {
            return Err(LinuxError::EFAULT);
        }
        unsafe { *buf = Default::default() }; // TODO
        Ok(0)
    })
}

/// Get the path of the current directory.
#[allow(clippy::unnecessary_cast)] // `c_char` is either `i8` or `u8`
pub fn sys_getcwd(buf: *mut c_char, size: usize) -> *mut c_char {
    debug!("sys_getcwd <= {:#x} {}", buf as usize, size);
    syscall_body!(sys_getcwd, {
        if buf.is_null() {
            return Ok(core::ptr::null::<c_char>() as _);
        }
        let dst = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, size as _) };
        let cwd = axfs::FS_CONTEXT.lock().current_dir().absolute_path()?;
        let cwd = cwd.as_bytes();
        if cwd.len() < size {
            dst[..cwd.len()].copy_from_slice(cwd);
            dst[cwd.len()] = 0;
            Ok(buf)
        } else {
            Err(LinuxError::ERANGE)
        }
    })
}

/// Set the current working directory.
pub fn sys_chdir(path: *const c_char) -> c_int {
    let path = char_ptr_to_str(path);
    debug!("sys_chdir <= {:?}", path);
    syscall_body!(sys_chdir, {
        let path = path?;
        let mut fs = axfs::FS_CONTEXT.lock();
        let dir = fs.resolve(path)?;
        fs.set_current_dir(dir)?;
        Ok(0)
    })
}

/// Create a directory.
pub fn sys_mkdir(path: *const c_char, _mode: ctypes::mode_t) -> c_int {
    let path = char_ptr_to_str(path);
    debug!("sys_mkdir <= {:?}", path);
    syscall_body!(sys_mkdir, {
        let path = path?;
        let fs = axfs::FS_CONTEXT.lock();
        if fs.resolve(path).is_ok() {
            return Err(LinuxError::EEXIST);
        }
        let umask =
            pulse_core::task::current_process().map(|process| process.umask()).unwrap_or(0o022);
        let mode = (((_mode as u32) & !umask) & 0o777) as _;
        match fs.create_dir(path, NodePermission::from_bits_truncate(mode)) {
            Ok(_) => {}
            Err(VfsError::NotFound) => return Err(LinuxError::ENOENT),
            Err(err) => return Err(LinuxError::from(err.canonicalize())),
        }
        Ok(0)
    })
}

/// Rename `old` to `new`
/// If new exists, it is first removed.
///
/// Return 0 if the operation succeeds, otherwise return -1.
pub fn sys_rename(old: *const c_char, new: *const c_char) -> c_int {
    syscall_body!(sys_rename, {
        let old_path = char_ptr_to_str(old)?;
        let new_path = char_ptr_to_str(new)?;
        debug!("sys_rename <= old: {:?}, new: {:?}", old_path, new_path);
        axfs::FS_CONTEXT.lock().rename(old_path, new_path)?;
        Ok(0)
    })
}
