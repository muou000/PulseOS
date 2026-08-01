use super::*;

pub struct FileObject {
    inner: File,
    nonblocking: AtomicBool,
}

impl FileObject {
    pub fn new(inner: File) -> Self {
        Self {
            inner,
            nonblocking: AtomicBool::new(false),
        }
    }

    pub fn is_write_open(&self) -> bool {
        self.inner
            .flags()
            .intersects(AxFileFlags::WRITE | AxFileFlags::APPEND)
    }

    pub fn is_read_open(&self) -> bool {
        self.inner.flags().contains(AxFileFlags::READ)
    }

    pub fn inner(&self) -> &File {
        &self.inner
    }
}

pub struct NsFdObject {
    pub ns_type: u32,
    pub pid: u64,
}

impl FdObject for NsFdObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_ns_fd(&self) -> Option<(u64, u32)> {
        Some((self.pid, self.ns_type))
    }

    fn stat(&self) -> LinuxResult<stat> {
        let ns_ino = axfs::fs::procfs::PID_INODE_START
            + (self.pid << axfs::fs::procfs::PID_INODE_SHIFT)
            + match self.ns_type {
                CLONE_NEWUTS => axfs::fs::procfs::SUB_INO_NS_UTS,
                CLONE_NEWIPC => axfs::fs::procfs::SUB_INO_NS_IPC,
                CLONE_NEWNET => axfs::fs::procfs::SUB_INO_NS_NET,
                CLONE_NEWNS => axfs::fs::procfs::SUB_INO_NS_MNT,
                CLONE_NEWPID => axfs::fs::procfs::SUB_INO_NS_PID,
                CLONE_NEWUSER => axfs::fs::procfs::SUB_INO_NS_USER,
                CLONE_NEWCGROUP => axfs::fs::procfs::SUB_INO_NS_CGROUP,
                _ => 0,
            };

        Ok(stat {
            st_ino: ns_ino as _,
            st_nlink: 1,
            st_mode: S_IFLNK | 0o777,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 4096,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: false,
            writable: false,
        })
    }
}

pub struct PidfdObject {
    pid: AtomicU64,
    bind_wait_queue: axtask::WaitQueue,
}

impl PidfdObject {
    pub fn new(pid: u64) -> Self {
        Self {
            pid: AtomicU64::new(pid),
            bind_wait_queue: axtask::WaitQueue::new(),
        }
    }

    pub fn pid(&self) -> u64 {
        self.pid.load(Ordering::Acquire)
    }

    pub fn bind_pid(&self, pid: u64) {
        debug_assert_ne!(pid, 0);
        let previous = self.pid.swap(pid, Ordering::AcqRel);
        debug_assert_eq!(previous, 0);
        self.bind_wait_queue.notify_all(true);
    }
}

impl FdObject for PidfdObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn stat(&self) -> LinuxResult<stat> {
        let pid = self.pid();
        Ok(stat {
            st_ino: (20000 + pid) as _,
            st_nlink: 1,
            st_mode: S_IFREG | 0o600,
            st_uid: 0,
            st_gid: 0,
            st_blksize: 4096,
            ..empty_stat()
        })
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let pid = self.pid();
        let is_zombie = pid != 0
            && crate::task::process_by_pid(pid)
                .map(|p| p.is_zombie())
                .unwrap_or(true);
        Ok(PollState {
            readable: is_zombie,
            writable: false,
        })
    }

    /// 将当前 waker 注册到目标进程自身的 `pid_exit_event` 等待队列上。
    ///
    /// `pidfd` 只关心目标进程进入僵尸态这一事件；只要目标进程在生命周期内，
    /// `Process::finish_thread_exit` 会在完成退出资源清理并写入 `zombie = true`
    /// 之后立即通知，从而唤醒 epoll/poll 等待者。
    ///
    /// 如果目标进程已不存在（已被 reap 并从全局表中注销），`poll()` 视为
    /// 始终可读，调用方不会走到这里；为防御性目的，进程已消失时直接返回
    /// `Ok(())`，不注册任何 waker，让 poll 端的下一次轮询自行退出。
    fn register_poll(
        self: Arc<Self>,
        cx: &mut core::task::Context<'_>,
        _events: axpoll::IoEvents,
        registrations: &mut Vec<PollRegistration>,
    ) -> LinuxResult {
        let mut pid = self.pid();
        if pid == 0 {
            let registration = self.bind_wait_queue.register_owned_waker(cx.waker());
            let object = self.clone();
            registrations.push(PollRegistration::new(move || {
                object.bind_wait_queue.unregister_waker(registration);
            }));
            pid = self.pid();
            if pid == 0 {
                return Ok(());
            }
            // Binding raced with registration. Ensure the poll future checks
            // readiness again even if the bind notification happened first.
            cx.waker().wake_by_ref();
        }

        if let Some(process) = crate::task::process_by_pid(pid) {
            let registration = process.pid_exit_event.register_owned_waker(cx.waker());
            let exited = process.is_zombie();
            registrations.push(PollRegistration::new(move || {
                process.pid_exit_event.unregister_waker(registration);
            }));
            if exited {
                cx.waker().wake_by_ref();
            }
        } else {
            cx.waker().wake_by_ref();
        }
        Ok(())
    }
}

impl FdObject for FileObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn ioctl(&self, cmd: u32, arg: usize) -> LinuxResult<isize> {
        if cmd == FIONREAD {
            let metadata = location_to_stat(self.inner.location())?;
            let pos = self.inner.position().unwrap_or(0);
            let size = metadata.st_size as u64;
            let n = size.saturating_sub(pos) as i32;
            let process = crate::task::current_process()?;
            process.write_user_bytes(arg, &n.to_ne_bytes())?;
            return Ok(0);
        }
        Err(LinuxError::ENOTTY)
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        let file = &self.inner;
        Ok(axtask::future::block_on(file.read(buf))?)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let file = &self.inner;
        Ok(axtask::future::block_on(file.write(buf))?)
    }

    fn stat(&self) -> LinuxResult<stat> {
        location_to_stat(self.inner.location())
    }

    fn poll(&self) -> LinuxResult<PollState> {
        let flags = self.inner.flags();
        Ok(PollState {
            readable: flags.contains(AxFileFlags::READ),
            writable: flags.intersects(AxFileFlags::WRITE | AxFileFlags::APPEND),
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        Some(self.inner.location().clone())
    }

    fn seek(&self, pos: SeekFrom) -> LinuxResult<u64> {
        if self
            .inner
            .location()
            .flags()
            .contains(axfs_ng_vfs::NodeFlags::STREAM)
        {
            return Err(LinuxError::ESPIPE);
        }
        let mut file = &self.inner;
        Ok(file.seek(pos)?)
    }

    fn read_at(&self, buf: &mut [u8], offset: u64) -> LinuxResult<usize> {
        Ok(axtask::future::block_on(self.inner.read_at(buf, offset))?)
    }

    fn write_at(&self, buf: &[u8], offset: u64) -> LinuxResult<usize> {
        let file = &self.inner;
        if file.flags().contains(AxFileFlags::APPEND) {
            let backend = file.backend()?;
            let (written, _) = axtask::future::block_on(backend.append(buf))?;
            Ok(written)
        } else {
            Ok(axtask::future::block_on(file.write_at(buf, offset))?)
        }
    }

    fn mmap_file_flags(&self) -> Option<AxFileFlags> {
        Some(self.inner.flags())
    }

    fn mmap_write_access(&self) -> Option<axfs::WriteAccessGuard> {
        self.inner.write_access_guard()
    }

    fn truncate(&self, len: u64) -> LinuxResult {
        axtask::future::block_on(self.inner.access(AxFileFlags::WRITE)?.set_len(len))?;
        Ok(())
    }

    fn flush(&self) -> LinuxResult {
        axtask::future::block_on(self.inner.sync(false)).map_err(Into::into)
    }

    fn sync_data(&self) -> LinuxResult {
        axtask::future::block_on(self.inner.sync(true)).map_err(Into::into)
    }

    fn allocate(&self, mode: u32, offset: u64, len: u64) -> LinuxResult {
        if !self.is_write_open() {
            return Err(LinuxError::EBADF);
        }
        if len == 0 {
            return Err(LinuxError::EINVAL);
        }
        let end = offset.checked_add(len).ok_or(LinuxError::EFBIG)?;

        let metadata = axtask::future::block_on(self.inner.location().metadata())?;
        if metadata.node_type != NodeType::RegularFile {
            if metadata.node_type == NodeType::Directory {
                return Err(LinuxError::EISDIR);
            } else {
                return Err(LinuxError::ENODEV);
            }
        }

        if (mode & !(FALLOC_FL_KEEP_SIZE as u32)) != 0 {
            axlog::warn!("sys_fallocate: unsupported mode flags (mode={:#x})", mode);
            return Err(LinuxError::EOPNOTSUPP);
        }

        if (mode & (FALLOC_FL_KEEP_SIZE as u32)) != 0 {
            axlog::warn!(
                "sys_fallocate: FALLOC_FL_KEEP_SIZE is stubbed (mode={:#x}, offset={}, len={}) \
                 due to lack of native preallocation support in filesystem stack",
                mode,
                offset,
                len
            );
        } else {
            let cur_size = axfs::cached_file_size(self.inner.location()).unwrap_or(metadata.size);
            if end > cur_size {
                axlog::warn!(
                    "sys_fallocate: physical space preallocation is not supported, falling back \
                     to set_len (new_len={})",
                    end
                );
                axtask::future::block_on(self.inner.access(AxFileFlags::WRITE)?.set_len(end))?;
            }
        }

        Ok(())
    }

    fn is_write_open(&self) -> bool {
        self.is_write_open()
    }

    fn is_read_open(&self) -> bool {
        self.is_read_open()
    }
}

impl Drop for FileObject {
    fn drop(&mut self) {
        let owner = self as *const FileObject as *const () as usize;
        crate::flock::flock_release_owner(owner);
    }
}

fn parse_cpu_dma_latency_value(buf: &[u8]) -> LinuxResult<i32> {
    if buf.len() != 4 {
        return Err(LinuxError::EINVAL);
    }
    let mut bytes = [0u8; 4];
    bytes.copy_from_slice(buf);
    Ok(i32::from_ne_bytes(bytes))
}

pub(super) fn is_cpu_dma_latency_device(location: &Location) -> bool {
    let Ok(metadata) = axtask::future::block_on(location.metadata()) else {
        return false;
    };
    metadata.node_type == NodeType::CharacterDevice
        && metadata.rdev.major() == 10
        && metadata.rdev.minor() == 63
}

pub struct CpuDmaLatencyObject {
    location: Location,
    request: Arc<CpuDmaLatencyRequest>,
    nonblocking: AtomicBool,
}

impl CpuDmaLatencyObject {
    pub fn new(location: Location) -> Self {
        Self {
            location,
            request: CpuDmaLatencyRequest::new(),
            nonblocking: AtomicBool::new(false),
        }
    }
}

impl FdObject for CpuDmaLatencyObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, buf: &mut [u8]) -> LinuxResult<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let bytes = effective_latency_us().to_ne_bytes();
        let n = core::cmp::min(buf.len(), bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        Ok(n)
    }

    fn write(&self, buf: &[u8]) -> LinuxResult<usize> {
        let value = parse_cpu_dma_latency_value(buf)?;
        self.request.set_target_us(value);
        Ok(buf.len())
    }

    fn stat(&self) -> LinuxResult<stat> {
        location_to_stat(&self.location)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: true,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        Some(self.location.clone())
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        true
    }
}

#[repr(C, packed)]
struct LinuxDirent64 {
    d_ino: u64,
    d_off: i64,
    d_reclen: u16,
    d_type: u8,
}

pub struct DirObject {
    inner: Location,
    offset: Mutex<u64>,
    nonblocking: AtomicBool,
}

impl DirObject {
    pub fn new(inner: Location) -> Self {
        Self {
            inner,
            offset: Mutex::new(0),
            nonblocking: AtomicBool::new(false),
        }
    }
}

impl FdObject for DirObject {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn read(&self, _buf: &mut [u8]) -> LinuxResult<usize> {
        Err(LinuxError::EISDIR)
    }

    fn write(&self, _buf: &[u8]) -> LinuxResult<usize> {
        Err(LinuxError::EBADF)
    }

    fn read_at(&self, _buf: &mut [u8], _offset: u64) -> LinuxResult<usize> {
        Err(LinuxError::EISDIR)
    }

    fn write_at(&self, _buf: &[u8], _offset: u64) -> LinuxResult<usize> {
        Err(LinuxError::EISDIR)
    }

    fn stat(&self) -> LinuxResult<stat> {
        location_to_stat(&self.inner)
    }

    fn poll(&self) -> LinuxResult<PollState> {
        Ok(PollState {
            readable: true,
            writable: false,
        })
    }

    fn set_nonblocking(&self, nonblocking: bool) -> LinuxResult {
        self.nonblocking.store(nonblocking, Ordering::Release);
        Ok(())
    }

    fn location(&self) -> Option<Location> {
        Some(self.inner.clone())
    }

    fn flush(&self) -> LinuxResult {
        axtask::future::block_on(self.inner.sync(false)).map_err(Into::into)
    }

    fn sync_data(&self) -> LinuxResult {
        axtask::future::block_on(self.inner.sync(true)).map_err(Into::into)
    }

    fn is_read_open(&self) -> bool {
        true
    }

    fn is_write_open(&self) -> bool {
        false
    }

    fn read_dirents64(&self, dirp: &mut [u8]) -> LinuxResult<usize> {
        let mut offset = self.offset.lock();
        let mut written = 0usize;
        let mut break_out = false;
        let res =
            axtask::future::block_on(self.inner.read_dir(*offset, &mut |name: &str,
                                                                        ino: u64,
                                                                        node_type: NodeType,
                                                                        next_off: u64|
             -> bool {
                if break_out {
                    return false;
                }
                let name_bytes = name.as_bytes();
                let name_len = name_bytes.len();
                let unpadded_len = core::mem::size_of::<LinuxDirent64>() + name_len + 1;
                let reclen = (unpadded_len + 7) & !7;
                if written + reclen > dirp.len() {
                    break_out = true;
                    return false;
                }
                let dirent = LinuxDirent64 {
                    d_ino: ino,
                    d_off: next_off as i64,
                    d_reclen: reclen as u16,
                    d_type: node_type as u8,
                };
                axlog::debug!(
                    "read_dirents64: emit name={}, ino={}, type={:?}, next_off={}, reclen={}",
                    name,
                    ino,
                    node_type,
                    next_off,
                    reclen
                );
                unsafe {
                    let dst = dirp.as_mut_ptr().add(written);
                    core::ptr::write_unaligned(dst.cast::<LinuxDirent64>(), dirent);
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
            }));
        if written == 0 {
            res?;
        }
        Ok(written)
    }
}

impl Drop for DirObject {
    fn drop(&mut self) {
        let owner = self as *const DirObject as *const () as usize;
        crate::flock::flock_release_owner(owner);
    }
}
