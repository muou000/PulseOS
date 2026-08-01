use super::{
    cache::{append_source_async, shared_file_state_async, write_source_at_async},
    *,
};

/// Low-level interface for file operations.
#[derive(Clone)]
pub enum FileBackend {
    Cached(CachedFile),
    Direct(Location),
}

impl FileBackend {
    pub(crate) fn new_direct(location: Location) -> Self {
        Self::Direct(location)
    }

    pub(crate) async fn new_cached(location: Location) -> VfsResult<Self> {
        CachedFile::get_or_create_async(location)
            .await
            .map(Self::Cached)
    }

    pub async fn read_at(&self, mut dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.read_at_async(dst, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if node_allows_page_cache(node_flags) && !node_flags.contains(NodeFlags::STREAM) {
                    let shared = shared_file_state_async(loc).await?;
                    let _guard = shared.io_lock.write().await;
                    let cached_size = shared.size();
                    if file.len().await? != cached_size {
                        file.set_len(cached_size).await?;
                    }
                    shared.flush_dirty_pages_async(file).await?;

                    let mut tmp = alloc::vec![0u8; dst.remaining_mut().min(64 * 1024)];
                    let read = file.read_at(&mut tmp, offset).await?;
                    return dst.write(&tmp[..read]);
                }
                // Keep the adapter bounded for very large vectored/user buffers.
                let mut tmp = alloc::vec![0u8; dst.remaining_mut().min(64 * 1024)];
                let read = file.read_at(&mut tmp, offset).await?;
                dst.write(&tmp[..read])
            }
        }
    }

    pub async fn write_at(&self, mut src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.write_at_async(src, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if !node_allows_page_cache(node_flags) || node_flags.contains(NodeFlags::STREAM) {
                    write_source_at_async(file, &mut src, offset).await
                } else {
                    let shared = shared_file_state_async(loc).await?;
                    let _guard = shared.io_lock.write().await;
                    let cached_size = shared.size();
                    if file.len().await? != cached_size {
                        file.set_len(cached_size).await?;
                    }
                    shared.flush_dirty_pages_async(file).await?;
                    let result = write_source_at_async(file, &mut src, offset).await;
                    if let Ok(backend_size) = file.len().await {
                        shared.set_size(backend_size);
                    }
                    let invalidate = shared.discard_all_pages_without_writeback_async(file).await;
                    match (result, invalidate) {
                        (Ok(written), Ok(())) => Ok(written),
                        (Err(err), Ok(())) => Err(err),
                        (Ok(_), Err(err)) => Err(err),
                        (Err(err), Err(_)) => Err(err),
                    }
                }
            }
        }
    }

    pub async fn append(&self, mut src: impl Read + IoBuf) -> VfsResult<(usize, u64)> {
        match self {
            Self::Cached(cached) => cached.append_async(src).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return append_source_async(file, &mut src).await;
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                let cached_size = shared.size();
                if file.len().await? != cached_size {
                    file.set_len(cached_size).await?;
                }
                shared.flush_dirty_pages_async(file).await?;
                let result = append_source_async(file, &mut src).await;
                if let Ok(backend_size) = file.len().await {
                    shared.set_size(backend_size);
                }
                let invalidate = shared.discard_all_pages_without_writeback_async(file).await;
                match (result, invalidate) {
                    (Ok(result), Ok(())) => Ok(result),
                    (Err(err), Ok(())) => Err(err),
                    (Ok(_), Err(err)) => Err(err),
                    (Err(err), Err(_)) => Err(err),
                }
            }
        }
    }

    pub fn location(&self) -> &Location {
        match self {
            Self::Cached(cached) => cached.location(),
            Self::Direct(loc) => loc,
        }
    }

    pub async fn sync(&self, data_only: bool) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.sync_async(data_only).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.sync(data_only).await;
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                let cached_size = shared.size();
                if file.len().await? != cached_size {
                    file.set_len(cached_size).await?;
                }
                shared.flush_dirty_pages_async(file).await?;
                file.sync(data_only).await
            }
        }
    }

    pub async fn set_len(&self, len: u64) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.set_len_async(len).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.set_len(len).await;
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                shared.flush_dirty_pages_async(file).await?;
                file.set_len(len).await?;
                shared.set_size(len);
                shared.discard_all_pages_without_writeback_async(file).await
            }
        }
    }
}

/// Provides `std::fs::File`-like interface.
pub struct File {
    inner: FileBackend,
    flags: FileFlags,
    position: Option<async_lock::Mutex<u64>>,
    _write_access: Option<WriteAccessGuard>,
    #[cfg(feature = "times")]
    access_flags: AtomicU8,
}

impl File {
    fn new_with_position(
        inner: FileBackend,
        flags: FileFlags,
        write_access: Option<WriteAccessGuard>,
        append_position: u64,
    ) -> Self {
        let position = if inner.location().flags().contains(NodeFlags::STREAM) {
            None
        } else {
            Some(async_lock::Mutex::new(
                if flags.contains(FileFlags::APPEND) {
                    append_position
                } else {
                    0
                },
            ))
        };
        Self {
            inner,
            flags,
            position,
            _write_access: write_access,
            #[cfg(feature = "times")]
            access_flags: AtomicU8::new(0),
        }
    }

    fn new(inner: FileBackend, flags: FileFlags, write_access: Option<WriteAccessGuard>) -> Self {
        let append_position = if flags.contains(FileFlags::APPEND) {
            cached_file_size(inner.location()).unwrap_or_default()
        } else {
            0
        };
        Self::new_with_position(inner, flags, write_access, append_position)
    }

    pub(super) async fn new_async(
        inner: FileBackend,
        flags: FileFlags,
        write_access: Option<WriteAccessGuard>,
    ) -> Self {
        let append_position = if flags.contains(FileFlags::APPEND) {
            match cached_file_size_if_present(inner.location()) {
                Some(size) => size,
                None => inner.location().len().await.unwrap_or_default(),
            }
        } else {
            0
        };
        Self::new_with_position(inner, flags, write_access, append_position)
    }

    pub fn clone_with_new_position(&self) -> Self {
        Self::new(self.inner.clone(), self.flags, self._write_access.clone())
    }

    pub fn write_access_guard(&self) -> Option<WriteAccessGuard> {
        self._write_access.clone()
    }

    pub async fn open(context: &FsContext, path: impl AsRef<Path>) -> VfsResult<Self> {
        OpenOptions::new()
            .read(true)
            .open(context, path.as_ref())
            .await
            .and_then(OpenResult::into_file)
    }

    pub async fn create(context: &FsContext, path: impl AsRef<Path>) -> VfsResult<Self> {
        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(context, path.as_ref())
            .await
            .and_then(OpenResult::into_file)
    }

    pub fn access(&self, flags: FileFlags) -> VfsResult<&FileBackend> {
        if self.flags.contains(flags) && !self.is_path() {
            Ok(&self.inner)
        } else {
            Err(VfsError::BadFileDescriptor)
        }
    }

    pub fn is_path(&self) -> bool {
        self.flags.contains(FileFlags::PATH)
    }

    pub fn flags(&self) -> FileFlags {
        self.flags
    }

    pub fn backend(&self) -> VfsResult<&FileBackend> {
        self.access(FileFlags::empty())?;
        Ok(&self.inner)
    }

    pub fn location(&self) -> &Location {
        self.inner.location()
    }

    pub fn is_direct_regular_file(&self) -> bool {
        if matches!(self.inner, FileBackend::Direct(_)) {
            if let Ok(metadata) = axtask::future::block_on(self.inner.location().metadata()) {
                if metadata.node_type == NodeType::RegularFile {
                    let fs_name = self.inner.location().filesystem().name();
                    return fs_name != "proc" && fs_name != "devfs" && fs_name != "tmpfs";
                }
            }
        }
        false
    }

    pub fn block_size(&self) -> u64 {
        axtask::future::block_on(self.inner.location().metadata())
            .map(|m| m.block_size)
            .unwrap_or(512)
    }

    /// Reads a number of bytes starting from a given offset.
    pub async fn read_at(&self, dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        let result = self.access(FileFlags::READ)?.read_at(dst, offset).await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|read| *read != 0) {
            self.access_flags.fetch_or(1, Ordering::AcqRel);
        }
        result
    }

    /// Writes a number of bytes starting from a given offset.
    pub async fn write_at(&self, src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let result = self.access(FileFlags::WRITE)?.write_at(src, offset).await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags.fetch_or(2, Ordering::AcqRel);
        }
        result
    }

    /// Attempts to sync OS-internal file content and metadata to disk.
    ///
    /// If `data_only` is `true`, only the file data is synced, not the
    /// metadata.
    pub async fn sync(&self, data_only: bool) -> VfsResult<()> {
        self.access(FileFlags::empty())?;
        #[cfg(feature = "times")]
        let timestamp_flags = self.take_timestamp_updates().await?;

        let result = self.inner.sync(data_only).await;
        #[cfg(feature = "times")]
        if result.is_err() {
            self.access_flags
                .fetch_or(timestamp_flags, Ordering::AcqRel);
        }
        result
    }

    pub async fn read(&self, dst: impl Write + IoBufMut) -> axio::Result<usize> {
        if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock().await;
            self.read_at(dst, *pos).await.inspect(|n| {
                *pos += *n as u64;
            })
        } else {
            self.read_at(dst, 0).await
        }
    }

    pub async fn write(&self, src: impl Read + IoBuf) -> axio::Result<usize> {
        let result = if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock().await;
            if let Ok(f) = self.access(FileFlags::APPEND) {
                f.append(src).await.map(|(written, new_size)| {
                    *pos = new_size;
                    written
                })
            } else {
                self.write_at(src, *pos).await.inspect(|n| {
                    *pos += *n as u64;
                })
            }
        } else {
            self.write_at(src, 0).await
        };
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags.fetch_or(2, Ordering::AcqRel);
        }
        result
    }

    pub async fn flush(&self) -> axio::Result {
        self.sync(false).await
    }

    pub fn position(&self) -> Option<u64> {
        self.position
            .as_ref()
            .map(|pos| *axtask::future::block_on(pos.lock()))
    }

    #[cfg(feature = "times")]
    async fn take_timestamp_updates(&self) -> VfsResult<u8> {
        let flags = self.access_flags.swap(0, Ordering::AcqRel);
        if flags == 0 {
            return Ok(0);
        }

        let now = axhal::time::wall_time();
        let mut update = axfs_ng_vfs::MetadataUpdate::default();
        if flags & 1 != 0 {
            update.atime = Some(now);
        }
        if flags & 2 != 0 {
            update.mtime = Some(now);
        }

        if let Err(err) = self.inner.location().update_metadata(update).await {
            self.access_flags.fetch_or(flags, Ordering::AcqRel);
            return Err(err);
        }
        Ok(flags)
    }
}

impl Drop for File {
    fn drop(&mut self) {
        #[cfg(feature = "times")]
        if self.access_flags.load(Ordering::Acquire) != 0 {
            // Closing a file should publish deferred timestamps, but it must not
            // turn an ordinary close into fsync and a device-wide flush.
            let _ = axtask::future::block_on(self.take_timestamp_updates());
        }
    }
}

impl Read for &File {
    fn read(&mut self, buf: &mut [u8]) -> axio::Result<usize> {
        axtask::future::block_on((*self).read(buf))
    }
}

impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> axio::Result<usize> {
        axtask::future::block_on((*self).write(buf))
    }

    fn flush(&mut self) -> axio::Result {
        axtask::future::block_on((*self).flush())
    }
}

impl Seek for &File {
    fn seek(&mut self, pos: SeekFrom) -> axio::Result<u64> {
        self.access(FileFlags::empty())?;

        if let Some(guard) = self.position.as_ref() {
            let mut guard = axtask::future::block_on(guard.lock());
            let new_pos = match pos {
                SeekFrom::Start(pos) => pos,
                SeekFrom::End(off) => {
                    let size = cached_file_size(self.access(FileFlags::empty())?.location())?;
                    size.checked_add_signed(off).ok_or(VfsError::InvalidInput)?
                }
                SeekFrom::Current(off) => guard
                    .checked_add_signed(off)
                    .ok_or(VfsError::InvalidInput)?,
            };
            *guard = new_pos;
            Ok(new_pos)
        } else {
            Ok(0)
        }
    }
}

impl Pollable for File {
    fn poll(&self) -> IoEvents {
        self.inner.location().poll()
    }

    fn register(&self, context: &mut Context<'_>, events: IoEvents) {
        self.inner.location().register(context, events)
    }
}
