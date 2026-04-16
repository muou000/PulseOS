use alloc::collections::BTreeSet;
use alloc::ffi::CString;
use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use arceos_posix_api::ctypes;
use axfs::{FsContext, OpenOptions};
use axfs_ng_vfs::{Location, MetadataUpdate, NodePermission, NodeType};

use axerrno::LinuxError;
use axio::SeekFrom;
use core::time::Duration;
use spin::Lazy;

use pulse_core::fd_table::{
    FdEntry, FdFlags, FdObject, location_to_stat, open_result_to_entry, pipe_entries,
};
const O_NONBLOCK: usize = ctypes::O_NONBLOCK as usize;
const O_CLOEXEC: usize = ctypes::O_CLOEXEC as usize;
const O_NOFOLLOW: usize = ctypes::O_NOFOLLOW as usize;
const O_DIRECTORY: usize = ctypes::O_DIRECTORY as usize;
const O_DIRECT: usize = ctypes::O_DIRECT as usize;
const O_PATH: usize = ctypes::O_PATH as usize;
const O_APPEND: usize = ctypes::O_APPEND as usize;
const O_TRUNC: usize = ctypes::O_TRUNC as usize;
const O_CREAT: usize = ctypes::O_CREAT as usize;
const O_EXCL: usize = ctypes::O_EXCL as usize;
const O_ACCMODE: usize = ctypes::O_ACCMODE as usize;
const AT_FDCWD: i32 = -100;
const AT_SYMLINK_NOFOLLOW: usize = 0x100;
const AT_EACCESS: usize = 0x200;
const AT_REMOVEDIR: usize = 0x200;
const FACCESS_R_OK: usize = 4;
const FACCESS_W_OK: usize = 2;
const FACCESS_X_OK: usize = 1;
const FACCESS_MODE_MASK: usize = FACCESS_R_OK | FACCESS_W_OK | FACCESS_X_OK;
const UTIME_NOW: i64 = 0x3fff_ffff;
const UTIME_OMIT: i64 = 0x3fff_fffe;

static MOUNTED_TARGETS: Lazy<spin::Mutex<BTreeSet<String>>> =
    Lazy::new(|| spin::Mutex::new(BTreeSet::new()));

fn write_user_bytes(user_addr: usize, bytes: &[u8]) -> Result<(), LinuxError> {
    with_process(|process| process.write_user_bytes(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

fn read_user_bytes(user_addr: usize, bytes: &mut [u8]) -> Result<(), LinuxError> {
    with_process(|process| process.read_user_bytes(user_addr, bytes))?
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

fn read_user_cstring(user_addr: usize) -> Result<CString, LinuxError> {
    if user_addr == 0 {
        return Err(LinuxError::EFAULT);
    }
    const PATH_MAX: usize = 4096;
    const CHUNK_SIZE: usize = 128;
    const PAGE_SIZE: usize = 4096;
    with_process(|process| {
        let mut bytes = Vec::new();
        let mut offset = 0usize;
        let mut chunk = [0u8; CHUNK_SIZE];

        while offset < PATH_MAX {
            let addr = user_addr.checked_add(offset).ok_or(LinuxError::EFAULT)?;
            let page_left = PAGE_SIZE - (addr & (PAGE_SIZE - 1));
            let to_read = core::cmp::min(CHUNK_SIZE, core::cmp::min(PATH_MAX - offset, page_left));
            process
                .read_user_bytes(addr, &mut chunk[..to_read])
                .map_err(|e| LinuxError::from(e.canonicalize()))?;

            if let Some(pos) = chunk[..to_read].iter().position(|&b| b == 0) {
                bytes.extend_from_slice(&chunk[..pos]);
                return CString::new(bytes).map_err(|_| LinuxError::EINVAL);
            }

            bytes.extend_from_slice(&chunk[..to_read]);
            offset += to_read;
        }

        Err(LinuxError::ENAMETOOLONG)
    })?
}

fn read_user_iovec_array(
    user_addr: usize,
    iovcnt: usize,
) -> Result<Vec<ctypes::iovec>, LinuxError> {
    let mut iovecs = Vec::with_capacity(iovcnt);
    for i in 0..iovcnt {
        let mut iov = core::mem::MaybeUninit::<ctypes::iovec>::uninit();
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                iov.as_mut_ptr().cast::<u8>(),
                core::mem::size_of::<ctypes::iovec>(),
            )
        };
        read_user_bytes(user_addr + i * core::mem::size_of::<ctypes::iovec>(), bytes)?;
        iovecs.push(unsafe { iov.assume_init() });
    }
    Ok(iovecs)
}

fn with_process<R>(f: impl FnOnce(&pulse_core::task::Process) -> R) -> Result<R, LinuxError> {
    let process = pulse_core::task::current_process()?;
    Ok(f(process.as_ref()))
}

fn get_fd_entry(fd: usize) -> Result<FdEntry, LinuxError> {
    with_process(|process| {
        process
            .fd_table
            .lock()
            .get(fd)
            .cloned()
            .ok_or(LinuxError::EBADF)
    })?
}

fn get_fd_object(fd: usize) -> Result<Arc<dyn FdObject>, LinuxError> {
    Ok(get_fd_entry(fd)?.object)
}

fn get_fd_location(fd: usize) -> Result<Location, LinuxError> {
    get_fd_object(fd)?.location().ok_or(LinuxError::EBADF)
}

fn insert_fd_entry(entry: FdEntry) -> Result<usize, LinuxError> {
    with_process(|process| process.fd_table.lock().insert_next(entry))?
}

fn insert_fd_entry_from(min_fd: usize, entry: FdEntry) -> Result<usize, LinuxError> {
    with_process(|process| process.fd_table.lock().insert_from(min_fd, entry))?
}

fn set_fd_entry(fd: usize, entry: FdEntry) -> Result<(), LinuxError> {
    with_process(|process| process.fd_table.lock().insert_at(fd, entry))?
}

fn remove_fd_entry(fd: usize) -> Result<FdEntry, LinuxError> {
    with_process(|process| process.fd_table.lock().remove(fd).ok_or(LinuxError::EBADF))?
}

fn open_fd_flags(flags: usize) -> FdFlags {
    let mut fd_flags = FdFlags::empty();
    if (flags & O_CLOEXEC) != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    if (flags & O_NONBLOCK) != 0 {
        fd_flags.insert(FdFlags::NONBLOCK);
    }
    fd_flags
}

fn flags_to_options(flags: usize, mode: usize) -> OpenOptions {
    let mut options = OpenOptions::new();
    match flags & O_ACCMODE {
        x if x == ctypes::O_RDONLY as usize => {
            options.read(true);
        }
        x if x == ctypes::O_WRONLY as usize => {
            options.write(true);
        }
        _ => {
            options.read(true);
            options.write(true);
        }
    }
    if (flags & O_APPEND) != 0 {
        options.append(true);
    }
    if (flags & O_TRUNC) != 0 {
        options.truncate(true);
    }
    if (flags & O_CREAT) != 0 {
        options.create(true);
    }
    if (flags & O_EXCL) != 0 {
        options.create_new(true);
    }
    if (flags & O_DIRECTORY) != 0 {
        options.directory(true);
    }
    if (flags & O_NOFOLLOW) != 0 {
        options.no_follow(true);
    }
    if (flags & O_DIRECT) != 0 {
        options.direct(true);
    }
    if (flags & O_PATH) != 0 {
        options.path(true);
    }
    options.mode(mode as u32);
    options
}

fn context_for_dirfd(dirfd: i32) -> Result<FsContext, LinuxError> {
    let base = with_process(|process| process.fs_context.lock().clone())?;
    if dirfd == AT_FDCWD {
        return Ok(base);
    }
    if dirfd < 0 {
        return Err(LinuxError::EBADF);
    }
    let location = get_fd_location(dirfd as usize)?;
    if !location.is_dir() {
        return Err(LinuxError::ENOTDIR);
    }
    base.with_current_dir(location)
        .map_err(|e| LinuxError::from(e.canonicalize()))
}

fn resolve_location_at_ptr(
    dirfd: i32,
    pathname: usize,
    flags: usize,
) -> Result<Location, LinuxError> {
    if (flags & AT_EMPTY_PATH) != 0 {
        if pathname == 0 {
            if dirfd < 0 {
                return Err(LinuxError::EBADF);
            }
            return get_fd_location(dirfd as usize);
        }
        let path = read_user_cstring(pathname)?;
        if path.as_bytes().is_empty() {
            if dirfd < 0 {
                return Err(LinuxError::EBADF);
            }
            return get_fd_location(dirfd as usize);
        }
    }

    if pathname == 0 {
        return Err(LinuxError::EFAULT);
    }
    let path = read_user_cstring(pathname)?;
    // Linux paths are byte sequences; avoid rejecting non-UTF-8 paths here.
    let path = path.as_c_str().to_string_lossy();
    if let Some(result) = try_resolve_location_fast(dirfd, path.as_ref(), flags) {
        return result;
    }
    let ctx = context_for_dirfd(dirfd)?;
    if (flags & AT_SYMLINK_NOFOLLOW) != 0 {
        ctx.resolve_no_follow(path.as_ref())
            .map_err(|e| LinuxError::from(e.canonicalize()))
    } else {
        ctx.resolve(path.as_ref())
            .map_err(|e| LinuxError::from(e.canonicalize()))
    }
}

fn try_resolve_location_fast(
    dirfd: i32,
    path: &str,
    flags: usize,
) -> Option<Result<Location, LinuxError>> {
    // Fast path for directory traversal workloads (`du`): common pattern
    // is `fstatat(dirfd, "name", ..., AT_SYMLINK_NOFOLLOW)`.
    if dirfd == AT_FDCWD {
        return None;
    }
    if dirfd < 0 {
        return Some(Err(LinuxError::EBADF));
    }
    if flags != AT_SYMLINK_NOFOLLOW {
        return None;
    }
    if path.is_empty() || path.starts_with('/') || path.contains('/') {
        return None;
    }
    let base = match get_fd_location(dirfd as usize) {
        Ok(loc) => loc,
        Err(e) => return Some(Err(e)),
    };
    if !base.is_dir() {
        return Some(Err(LinuxError::ENOTDIR));
    }
    Some(
        base.lookup_no_follow(path)
            .map_err(|e| LinuxError::from(e.canonicalize())),
    )
}

fn stat_from_location(location: &Location) -> Result<ctypes::stat, LinuxError> {
    location_to_stat(location)
}

fn permission_mask_from_bits(
    mode: NodePermission,
    read: NodePermission,
    write: NodePermission,
    exec: NodePermission,
) -> usize {
    let mut mask = 0usize;
    if mode.contains(read) {
        mask |= FACCESS_R_OK;
    }
    if mode.contains(write) {
        mask |= FACCESS_W_OK;
    }
    if mode.contains(exec) {
        mask |= FACCESS_X_OK;
    }
    mask
}

fn allowed_access_mask(
    mode: NodePermission,
    uid: u32,
    gid: u32,
    owner_uid: u32,
    owner_gid: u32,
) -> usize {
    if uid == owner_uid {
        permission_mask_from_bits(
            mode,
            NodePermission::OWNER_READ,
            NodePermission::OWNER_WRITE,
            NodePermission::OWNER_EXEC,
        )
    } else if gid == owner_gid {
        permission_mask_from_bits(
            mode,
            NodePermission::GROUP_READ,
            NodePermission::GROUP_WRITE,
            NodePermission::GROUP_EXEC,
        )
    } else {
        permission_mask_from_bits(
            mode,
            NodePermission::OTHER_READ,
            NodePermission::OTHER_WRITE,
            NodePermission::OTHER_EXEC,
        )
    }
}

fn check_faccess_permission(
    location: &Location,
    mode: usize,
    uid: u32,
    gid: u32,
) -> Result<(), LinuxError> {
    if mode == 0 {
        return Ok(());
    }

    let meta = location
        .metadata()
        .map_err(|e| LinuxError::from(e.canonicalize()))?;

    // Linux-like behavior: privileged user bypasses read/write permission checks.
    // For X_OK, regular files still require at least one execute bit.
    if uid == 0 {
        if (mode & FACCESS_X_OK) == 0 {
            return Ok(());
        }
        if meta.node_type != NodeType::RegularFile {
            return Ok(());
        }
        let any_exec = meta.mode.intersects(
            NodePermission::OWNER_EXEC | NodePermission::GROUP_EXEC | NodePermission::OTHER_EXEC,
        );
        return if any_exec {
            Ok(())
        } else {
            Err(LinuxError::EACCES)
        };
    }

    let allowed = allowed_access_mask(meta.mode, uid, gid, meta.uid, meta.gid);
    if (mode & !allowed) == 0 {
        Ok(())
    } else {
        Err(LinuxError::EACCES)
    }
}

fn read_user_timespec(user_addr: usize) -> Result<ctypes::timespec, LinuxError> {
    let mut ts = core::mem::MaybeUninit::<ctypes::timespec>::uninit();
    let bytes = unsafe {
        core::slice::from_raw_parts_mut(
            ts.as_mut_ptr().cast::<u8>(),
            core::mem::size_of::<ctypes::timespec>(),
        )
    };
    read_user_bytes(user_addr, bytes)?;
    Ok(unsafe { ts.assume_init() })
}

fn read_user_i64(user_addr: usize) -> Result<i64, LinuxError> {
    let mut bytes = [0u8; core::mem::size_of::<i64>()];
    read_user_bytes(user_addr, &mut bytes)?;
    Ok(i64::from_ne_bytes(bytes))
}

fn write_user_i64(user_addr: usize, value: i64) -> Result<(), LinuxError> {
    write_user_bytes(user_addr, &value.to_ne_bytes())
}

fn timespec_to_update_time(
    ts: ctypes::timespec,
    now: Duration,
) -> Result<Option<Duration>, LinuxError> {
    match ts.tv_nsec {
        UTIME_OMIT => Ok(None),
        UTIME_NOW => Ok(Some(now)),
        nsec if !(0..1_000_000_000).contains(&nsec) => Err(LinuxError::EINVAL),
        _ if ts.tv_sec < 0 => Err(LinuxError::EINVAL),
        _ => Ok(Some(Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32))),
    }
}

pub fn sys_read(fd: usize, buf: usize, count: usize) -> isize {
    axlog::debug!("sys_read: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let object = match get_fd_object(fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };
    let mut tmp = vec![0u8; count];
    let ret = match object.read(&mut tmp) {
        Ok(ret) => ret as isize,
        Err(e) => return -e.code() as isize,
    };
    if ret <= 0 {
        return ret;
    }
    match write_user_bytes(buf, &tmp[..ret as usize]) {
        Ok(()) => ret,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_write(fd: usize, buf: usize, count: usize) -> isize {
    axlog::debug!("sys_write: fd={}, buf={:#x}, count={}", fd, buf, count);
    if buf == 0 && count != 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let object = match get_fd_object(fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };
    let mut tmp = vec![0u8; count];
    if let Err(e) = read_user_bytes(buf, &mut tmp) {
        return -e.code() as isize;
    }
    match object.write(&tmp) {
        Ok(ret) => ret as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_openat(dirfd: i32, pathname: usize, flags: usize, mode: usize) -> isize {
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let ctx = match context_for_dirfd(dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    let path = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };

    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let options = flags_to_options(flags, mode);
    let opened = match options.open(&ctx, path) {
        Ok(opened) => opened,
        Err(e) => {
            let err = LinuxError::from(e.canonicalize());
            return -err.code() as isize;
        }
    };
    let entry = open_result_to_entry(opened, open_fd_flags(flags));
    match insert_fd_entry(entry) {
        Ok(fd) => fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_mkdirat(dirfd: i32, pathname: usize, mode: usize) -> isize {
    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let ctx = match context_for_dirfd(dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };
    let path = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    match ctx.create_dir(path, NodePermission::from_bits_truncate(mode as _)) {
        Ok(_) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}

pub fn sys_mount(
    _source: usize,
    target: usize,
    _fstype: usize,
    _flags: usize,
    _data: usize,
) -> isize {
    axlog::debug!("sys_mount: target={:#x}, flags={:#x}", target, _flags);
    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let target = match read_user_cstring(target) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let target_path = match target.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    if let Err(e) = context_for_dirfd(AT_FDCWD).and_then(|ctx| {
        ctx.resolve(target_path)
            .map(|_| ())
            .map_err(|err| LinuxError::from(err.canonicalize()))
    }) {
        return -e.code() as isize;
    }

    let mut mounted = MOUNTED_TARGETS.lock();
    if mounted.contains(target_path) {
        return -LinuxError::EBUSY.code() as isize;
    }
    mounted.insert(target_path.to_string());
    0
}

pub fn sys_umount2(target: usize, _flags: usize) -> isize {
    axlog::debug!("sys_umount2: target={:#x}, flags={:#x}", target, _flags);
    if target == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }

    let target = match read_user_cstring(target) {
        Ok(target) => target,
        Err(e) => return -e.code() as isize,
    };
    let target_path = match target.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };

    let mut mounted = MOUNTED_TARGETS.lock();
    if mounted.remove(target_path) {
        0
    } else {
        -LinuxError::EINVAL.code() as isize
    }
}

pub fn sys_getdents64(fd: usize, dirp: usize, count: usize) -> isize {
    let object = match get_fd_object(fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };

    if count == 0 {
        return 0;
    }
    // Allow larger user-provided buffers to reduce syscall count during
    // directory-heavy workloads (e.g. `du`).
    let mut tmp = vec![0u8; count.min(64 * 1024)];
    let ret = match object.read_dirents64(&mut tmp) {
        Ok(ret) => ret as isize,
        Err(e) => return -e.code() as isize,
    };
    if ret <= 0 {
        return ret;
    }
    match write_user_bytes(dirp, &tmp[..ret as usize]) {
        Ok(()) => ret,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_close(fd: usize) -> isize {
    axlog::debug!("sys_close: fd={}", fd);
    match remove_fd_entry(fd) {
        Ok(_) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_fstat(fd: usize, statbuf: usize) -> isize {
    axlog::debug!("sys_fstat: fd={}, statbuf={:#x}", fd, statbuf);
    if statbuf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let stat = match get_fd_object(fd).and_then(|object| object.stat()) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&stat as *const ctypes::stat).cast::<u8>(),
            core::mem::size_of::<ctypes::stat>(),
        )
    };
    match write_user_bytes(statbuf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

#[cfg_attr(
    not(any(target_arch = "riscv64", target_arch = "loongarch64")),
    allow(dead_code)
)]
pub fn sys_fstatat(dirfd: i32, pathname: usize, statbuf: usize, flags: usize) -> isize {
    if statbuf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };
    let stat = match stat_from_location(&location) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&stat as *const ctypes::stat).cast::<u8>(),
            core::mem::size_of::<ctypes::stat>(),
        )
    };
    match write_user_bytes(statbuf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

const STATX_BASIC_STATS: u32 = 0x0000_07ff;
const STATX_MNT_ID: u32 = 0x0000_1000;
const AT_EMPTY_PATH: usize = 0x1000;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct StatxTimestamp {
    tv_sec: i64,
    tv_nsec: u32,
    __reserved: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Statx {
    stx_mask: u32,
    stx_blksize: u32,
    stx_attributes: u64,
    stx_nlink: u32,
    stx_uid: u32,
    stx_gid: u32,
    stx_mode: u16,
    __spare0: u16,
    stx_ino: u64,
    stx_size: u64,
    stx_blocks: u64,
    stx_attributes_mask: u64,
    stx_atime: StatxTimestamp,
    stx_btime: StatxTimestamp,
    stx_ctime: StatxTimestamp,
    stx_mtime: StatxTimestamp,
    stx_rdev_major: u32,
    stx_rdev_minor: u32,
    stx_dev_major: u32,
    stx_dev_minor: u32,
    stx_mnt_id: u64,
    stx_dio_mem_align: u32,
    stx_dio_offset_align: u32,
    __spare3: [u64; 12],
}

fn to_statx_timestamp(ts: arceos_posix_api::ctypes::timespec) -> StatxTimestamp {
    StatxTimestamp {
        tv_sec: ts.tv_sec,
        tv_nsec: ts.tv_nsec as u32,
        __reserved: 0,
    }
}

pub fn sys_statx(
    dirfd: i32,
    pathname: usize,
    flags: usize,
    _mask: usize,
    statxbuf: usize,
) -> isize {
    if statxbuf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(loc) => loc,
        Err(e) => return -e.code() as isize,
    };
    let stat = match stat_from_location(&location) {
        Ok(stat) => stat,
        Err(e) => return -e.code() as isize,
    };

    let statx = Statx {
        stx_mask: STATX_BASIC_STATS | STATX_MNT_ID,
        stx_blksize: stat.st_blksize as u32,
        stx_attributes: 0,
        stx_nlink: stat.st_nlink,
        stx_uid: stat.st_uid,
        stx_gid: stat.st_gid,
        stx_mode: stat.st_mode as u16,
        __spare0: 0,
        stx_ino: stat.st_ino,
        stx_size: stat.st_size as u64,
        stx_blocks: stat.st_blocks as u64,
        stx_attributes_mask: 0,
        stx_atime: to_statx_timestamp(stat.st_atime),
        stx_btime: StatxTimestamp::default(),
        stx_ctime: to_statx_timestamp(stat.st_ctime),
        stx_mtime: to_statx_timestamp(stat.st_mtime),
        stx_rdev_major: 0,
        stx_rdev_minor: 0,
        stx_dev_major: 0,
        stx_dev_minor: 0,
        stx_mnt_id: 0,
        stx_dio_mem_align: 0,
        stx_dio_offset_align: 0,
        __spare3: [0; 12],
    };

    let bytes = unsafe {
        core::slice::from_raw_parts(
            (&statx as *const Statx).cast::<u8>(),
            core::mem::size_of::<Statx>(),
        )
    };
    match write_user_bytes(statxbuf, bytes) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_writev(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let object = match get_fd_object(fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    let mut total = 0isize;
    for iov in iovecs {
        if iov.iov_len == 0 {
            continue;
        }
        let mut buf = vec![0u8; iov.iov_len];
        if let Err(e) = read_user_bytes(iov.iov_base as usize, &mut buf) {
            return -e.code() as isize;
        }
        let ret = match object.write(&buf) {
            Ok(ret) => ret as isize,
            Err(e) => return if total > 0 { total } else { -e.code() as isize },
        };
        if ret < 0 {
            return if total > 0 { total } else { ret };
        }
        total += ret;
        if ret as usize != buf.len() {
            break;
        }
    }
    total
}

pub fn sys_readv(fd: usize, iov: usize, iovcnt: usize) -> isize {
    let object = match get_fd_object(fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };
    let iovecs = match read_user_iovec_array(iov, iovcnt) {
        Ok(iovecs) => iovecs,
        Err(e) => return -e.code() as isize,
    };
    let mut total = 0isize;
    for iov in iovecs {
        if iov.iov_len == 0 {
            continue;
        }
        let mut buf = vec![0u8; iov.iov_len];
        let ret = match object.read(&mut buf) {
            Ok(ret) => ret as isize,
            Err(e) => return if total > 0 { total } else { -e.code() as isize },
        };
        if ret <= 0 {
            return total + ret;
        }
        if let Err(e) = write_user_bytes(iov.iov_base as usize, &buf[..ret as usize]) {
            return if total > 0 { total } else { -e.code() as isize };
        }
        total += ret;
        if ret as usize != iov.iov_len {
            break;
        }
    }
    total
}

pub fn sys_sendfile(out_fd: usize, in_fd: usize, offset: usize, count: usize) -> isize {
    axlog::debug!(
        "sys_sendfile: out_fd={}, in_fd={}, offset={:#x}, count={}",
        out_fd,
        in_fd,
        offset,
        count
    );
    if count == 0 {
        return 0;
    }

    let out = match get_fd_object(out_fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };
    let input = match get_fd_object(in_fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };

    let use_explicit_offset = offset != 0;
    let mut file_offset = if use_explicit_offset {
        let off = match read_user_i64(offset) {
            Ok(off) => off,
            Err(e) => return -e.code() as isize,
        };
        if off < 0 {
            return -LinuxError::EINVAL.code() as isize;
        }
        off as u64
    } else {
        0
    };

    let mut total = 0usize;
    let mut buf = vec![0u8; count.clamp(1, 64 * 1024)];
    while total < count {
        let chunk_len = core::cmp::min(buf.len(), count - total);
        let read_len = if use_explicit_offset {
            match input.read_at(&mut buf[..chunk_len], file_offset) {
                Ok(len) => len,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            }
        } else {
            match input.read(&mut buf[..chunk_len]) {
                Ok(len) => len,
                Err(e) => {
                    return if total > 0 {
                        total as isize
                    } else {
                        -e.code() as isize
                    };
                }
            }
        };
        if read_len == 0 {
            break;
        }
        if use_explicit_offset {
            file_offset = file_offset.saturating_add(read_len as u64);
        }

        let mut written = 0usize;
        while written < read_len {
            match out.write(&buf[written..read_len]) {
                Ok(0) => break,
                Ok(len) => written += len,
                Err(e) => {
                    let transferred = total + written;
                    return if transferred > 0 {
                        transferred as isize
                    } else {
                        -e.code() as isize
                    };
                }
            }
        }
        total += written;
        if written < read_len {
            break;
        }
    }

    if use_explicit_offset && let Err(e) = write_user_i64(offset, file_offset as i64) {
        return if total > 0 {
            total as isize
        } else {
            -e.code() as isize
        };
    }

    total as isize
}

pub fn sys_fcntl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_fcntl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    match cmd as u32 {
        ctypes::F_GETFD => match get_fd_entry(fd) {
            Ok(entry) => {
                if entry.flags.contains(FdFlags::CLOEXEC) {
                    ctypes::FD_CLOEXEC as isize
                } else {
                    0
                }
            }
            Err(e) => -e.code() as isize,
        },
        ctypes::F_GETFL => match get_fd_entry(fd) {
            Ok(entry) => {
                let mut status = 0usize;
                if entry.flags.contains(FdFlags::NONBLOCK) {
                    status |= O_NONBLOCK;
                }
                status as isize
            }
            Err(e) => -e.code() as isize,
        },
        ctypes::F_SETFD => match with_process(|process| -> Result<isize, LinuxError> {
            let mut table = process.fd_table.lock();
            let Some(entry) = table.get_mut(fd) else {
                return Err(LinuxError::EBADF);
            };
            entry
                .flags
                .set(FdFlags::CLOEXEC, (arg & (ctypes::FD_CLOEXEC as usize)) != 0);
            Ok(0)
        }) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) | Err(e) => -e.code() as isize,
        },
        ctypes::F_SETFL => match with_process(|process| -> Result<isize, LinuxError> {
            let mut table = process.fd_table.lock();
            let Some(entry) = table.get_mut(fd) else {
                return Err(LinuxError::EBADF);
            };
            let nonblocking = (arg & O_NONBLOCK) != 0;
            entry.flags.set(FdFlags::NONBLOCK, nonblocking);
            entry.object.set_nonblocking(nonblocking)?;
            Ok(0)
        }) {
            Ok(Ok(v)) => v,
            Ok(Err(e)) | Err(e) => -e.code() as isize,
        },
        ctypes::F_DUPFD | ctypes::F_DUPFD_CLOEXEC => {
            let entry = match get_fd_entry(fd) {
                Ok(entry) => entry,
                Err(e) => return -e.code() as isize,
            };
            let mut flags = entry.flags;
            flags.remove(FdFlags::CLOEXEC);
            if cmd as u32 == ctypes::F_DUPFD_CLOEXEC {
                flags.insert(FdFlags::CLOEXEC);
            }
            match insert_fd_entry_from(arg, FdEntry::new(entry.object, flags)) {
                Ok(new_fd) => new_fd as isize,
                Err(e) => -e.code() as isize,
            }
        }
        _ => {
            axlog::warn!("unsupported fcntl parameters: cmd {}", cmd);
            0
        }
    }
}

pub fn sys_dup(fd: usize) -> isize {
    let entry = match get_fd_entry(fd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let mut flags = entry.flags;
    flags.remove(FdFlags::CLOEXEC);
    match insert_fd_entry(FdEntry::new(entry.object, flags)) {
        Ok(new_fd) => new_fd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_dup3(oldfd: usize, newfd: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_dup3: oldfd={}, newfd={}, flags={:#x}",
        oldfd,
        newfd,
        flags
    );
    if oldfd == newfd {
        return -LinuxError::EINVAL.code() as isize;
    }
    if (flags & !O_CLOEXEC) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let entry = match get_fd_entry(oldfd) {
        Ok(entry) => entry,
        Err(e) => return -e.code() as isize,
    };
    let mut fd_flags = entry.flags;
    fd_flags.remove(FdFlags::CLOEXEC);
    if (flags & O_CLOEXEC) != 0 {
        fd_flags.insert(FdFlags::CLOEXEC);
    }
    match set_fd_entry(newfd, FdEntry::new(entry.object, fd_flags)) {
        Ok(()) => newfd as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_pipe2(fds: usize, flags: usize) -> isize {
    axlog::debug!("sys_pipe2: fds={:#x}, flags={:#x}", fds, flags);
    if fds == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    let allowed = O_NONBLOCK | O_CLOEXEC;
    if (flags & !allowed) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }
    let (read_entry, write_entry) = pipe_entries(open_fd_flags(flags));
    let new_fds = match with_process(|process| -> Result<[i32; 2], LinuxError> {
        let mut table = process.fd_table.lock();
        let read_fd = table.insert_next(read_entry)?;
        let write_fd = match table.insert_next(write_entry) {
            Ok(fd) => fd,
            Err(e) => {
                if table.remove(read_fd).is_none() {
                    axlog::warn!(
                        "sys_pipe2: rollback failed to remove read fd {} after write insert error",
                        read_fd
                    );
                }
                return Err(e);
            }
        };
        Ok([read_fd as i32, write_fd as i32])
    }) {
        Ok(Ok(new_fds)) => new_fds,
        Ok(Err(e)) | Err(e) => return -e.code() as isize,
    };
    let bytes = unsafe {
        core::slice::from_raw_parts(
            new_fds.as_ptr().cast::<u8>(),
            core::mem::size_of_val(&new_fds),
        )
    };
    if let Err(e) = write_user_bytes(fds, bytes) {
        if let Err(remove_e) = remove_fd_entry(new_fds[0] as usize) {
            axlog::warn!(
                "sys_pipe2: rollback failed to remove read fd {}: {:?}",
                new_fds[0],
                remove_e
            );
        }
        if let Err(remove_e) = remove_fd_entry(new_fds[1] as usize) {
            axlog::warn!(
                "sys_pipe2: rollback failed to remove write fd {}: {:?}",
                new_fds[1],
                remove_e
            );
        }
        return -e.code() as isize;
    }
    0
}

pub fn sys_lseek(fd: usize, offset: usize, whence: usize) -> isize {
    axlog::debug!(
        "sys_lseek: fd={}, offset={:#x}, whence={}",
        fd,
        offset,
        whence
    );
    let object = match get_fd_object(fd) {
        Ok(object) => object,
        Err(e) => return -e.code() as isize,
    };
    let offset = offset as isize as i64;
    let pos = match whence {
        0 => {
            if offset < 0 {
                return -LinuxError::EINVAL.code() as isize;
            }
            SeekFrom::Start(offset as u64)
        }
        1 => SeekFrom::Current(offset),
        2 => SeekFrom::End(offset),
        _ => return -LinuxError::EINVAL.code() as isize,
    };
    match object.seek(pos) {
        Ok(pos) => pos as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_getcwd(buf: usize, size: usize) -> isize {
    axlog::debug!("sys_getcwd: buf={:#x}, size={}", buf, size);
    if buf == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if size == 0 {
        return -LinuxError::ERANGE.code() as isize;
    }
    let cwd = match with_process(|process| process.fs_context.lock().current_dir().absolute_path())
    {
        Ok(Ok(path)) => path,
        Ok(Err(e)) => return -LinuxError::from(e.canonicalize()).code() as isize,
        Err(e) => return -e.code() as isize,
    };
    let cwd = cwd.as_bytes();
    if cwd.len() + 1 > size {
        return -LinuxError::ERANGE.code() as isize;
    }
    let mut tmp = alloc::vec![0u8; cwd.len() + 1];
    tmp[..cwd.len()].copy_from_slice(cwd);
    match write_user_bytes(buf, &tmp) {
        Ok(()) => buf as isize,
        Err(e) => -e.code() as isize,
    }
}

pub fn sys_chdir(path: usize) -> isize {
    axlog::debug!("sys_chdir: path={:#x}", path);
    let path = match read_user_cstring(path) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path.to_str() {
        Ok(path) => path,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    match with_process(|process| -> Result<(), LinuxError> {
        let dir = {
            let fs = process.fs_context.lock().clone();
            fs.resolve(path)
                .map_err(|e| LinuxError::from(e.canonicalize()))?
        };
        process
            .fs_context
            .lock()
            .set_current_dir(dir)
            .map_err(|e| LinuxError::from(e.canonicalize()))?;
        process.sync_fs_context();
        Ok(())
    }) {
        Ok(Ok(())) => 0,
        Ok(Err(e)) | Err(e) => -e.code() as isize,
    }
}

pub fn sys_unlinkat(dirfd: i32, pathname: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_unlinkat: dirfd={}, pathname={:#x}, flags={:#x}",
        dirfd,
        pathname,
        flags
    );

    if pathname == 0 {
        return -LinuxError::EFAULT.code() as isize;
    }
    if (flags & !AT_REMOVEDIR) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let path = match read_user_cstring(pathname) {
        Ok(path) => path,
        Err(e) => return -e.code() as isize,
    };
    let path = match path.to_str() {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return -LinuxError::EINVAL.code() as isize,
        Err(_) => return -LinuxError::EINVAL.code() as isize,
    };
    let ctx = match context_for_dirfd(dirfd) {
        Ok(ctx) => ctx,
        Err(e) => return -e.code() as isize,
    };

    if (flags & AT_REMOVEDIR) != 0 {
        return match ctx.remove_dir(path) {
            Ok(()) => 0,
            Err(e) => {
                let errno = LinuxError::from(e.canonicalize());
                -errno.code() as isize
            }
        };
    }

    match ctx.remove_file(path) {
        Ok(()) => 0,
        Err(e) => {
            let errno = LinuxError::from(e.canonicalize());
            -errno.code() as isize
        }
    }
}

pub fn sys_utimensat(dirfd: i32, pathname: usize, times: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_utimensat: dirfd={}, pathname={:#x}, times={:#x}, flags={:#x}",
        dirfd,
        pathname,
        times,
        flags
    );
    let supported_flags = AT_SYMLINK_NOFOLLOW | AT_EMPTY_PATH;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(location) => location,
        Err(e) => return -e.code() as isize,
    };

    let now = axhal::time::wall_time();
    let (atime, mtime) = if times == 0 {
        (Some(now), Some(now))
    } else {
        let atime = match read_user_timespec(times).and_then(|ts| timespec_to_update_time(ts, now))
        {
            Ok(atime) => atime,
            Err(e) => return -e.code() as isize,
        };
        let mtime_addr = times + core::mem::size_of::<ctypes::timespec>();
        let mtime =
            match read_user_timespec(mtime_addr).and_then(|ts| timespec_to_update_time(ts, now)) {
                Ok(mtime) => mtime,
                Err(e) => return -e.code() as isize,
            };
        (atime, mtime)
    };

    if atime.is_none() && mtime.is_none() {
        return 0;
    }

    let update = MetadataUpdate {
        atime,
        mtime,
        ..Default::default()
    };
    match location.update_metadata(update) {
        Ok(()) => 0,
        Err(e) => -LinuxError::from(e.canonicalize()).code() as isize,
    }
}

const TCGETS: usize = 0x5401;
const TIOCGPGRP: usize = 0x540f;
const TIOCSPGRP: usize = 0x5410;
const TIOCGWINSZ: usize = 0x5413;

#[repr(C)]
struct WinSize {
    ws_row: u16,
    ws_col: u16,
    ws_xpixel: u16,
    ws_ypixel: u16,
}

pub fn sys_ioctl(fd: usize, cmd: usize, arg: usize) -> isize {
    axlog::debug!("sys_ioctl: fd={}, cmd={:#x}, arg={:#x}", fd, cmd, arg);
    match cmd {
        TCGETS => {
            // It's a stub to tell musl it is a terminal
            0
        }
        TIOCGPGRP => {
            if arg != 0 {
                let value = 1i32.to_ne_bytes();
                if let Err(e) = write_user_bytes(arg, &value) {
                    return -e.code() as isize;
                }
            }
            0
        }
        TIOCSPGRP => 0,
        TIOCGWINSZ => {
            if arg != 0 {
                let ws = WinSize {
                    ws_row: 24,
                    ws_col: 80,
                    ws_xpixel: 0,
                    ws_ypixel: 0,
                };
                let bytes = unsafe {
                    core::slice::from_raw_parts(
                        (&ws as *const WinSize).cast::<u8>(),
                        core::mem::size_of::<WinSize>(),
                    )
                };
                if let Err(e) = write_user_bytes(arg, bytes) {
                    return -e.code() as isize;
                }
            }
            0
        }
        _ => {
            // ENOTTY
            -LinuxError::ENOTTY.code() as isize
        }
    }
}

pub fn sys_faccessat(dirfd: i32, pathname: usize, mode: usize, flags: usize) -> isize {
    axlog::debug!(
        "sys_faccessat: dirfd={}, pathname={:#x}, mode={:#o}, flags={:#x}",
        dirfd,
        pathname,
        mode,
        flags
    );

    if (mode & !FACCESS_MODE_MASK) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let supported_flags = AT_SYMLINK_NOFOLLOW | AT_EACCESS | AT_EMPTY_PATH;
    if (flags & !supported_flags) != 0 {
        return -LinuxError::EINVAL.code() as isize;
    }

    let location = match resolve_location_at_ptr(dirfd, pathname, flags) {
        Ok(location) => location,
        Err(e) => return -e.code() as isize,
    };

    let (uid, gid) = match with_process(|process| {
        if (flags & AT_EACCESS) != 0 {
            (process.euid(), process.egid())
        } else {
            (process.ruid(), process.rgid())
        }
    }) {
        Ok(ids) => ids,
        Err(e) => return -e.code() as isize,
    };

    match check_faccess_permission(&location, mode, uid, gid) {
        Ok(()) => 0,
        Err(e) => -e.code() as isize,
    }
}
