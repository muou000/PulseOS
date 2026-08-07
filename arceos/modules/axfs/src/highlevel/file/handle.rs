use super::{
    cache::{
        append_slice_source_async, append_source_async, shared_file_state_async,
        write_slice_source_at_async, write_source_at_async,
    },
    *,
};

const DIRECT_IO_STAGING_SIZE: usize = 64 * 1024;

#[cfg(feature = "times")]
const ACCESS_FLAG_ATIME: u8 = 1;
#[cfg(feature = "times")]
const ACCESS_FLAG_MTIME: u8 = 2;

#[cfg(feature = "times")]
#[inline]
fn has_pending_timestamp_updates(flags: u8) -> bool {
    flags != 0
}

/// A file position lock that leaves queued async operations ahead of the
/// resident-read fast path. The async mutex alone cannot expose its waiter
/// state to `try_lock` callers.
struct FilePosition {
    value: async_lock::Mutex<u64>,
    waiters: AtomicUsize,
}

struct PositionWaiter<'a>(&'a AtomicUsize);

impl Drop for PositionWaiter<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

impl FilePosition {
    fn new(value: u64) -> Self {
        Self {
            value: async_lock::Mutex::new(value),
            waiters: AtomicUsize::new(0),
        }
    }

    fn try_lock(&self) -> Option<async_lock::MutexGuard<'_, u64>> {
        if self.waiters.load(Ordering::Acquire) != 0 {
            return None;
        }
        let guard = self.value.try_lock()?;
        if self.waiters.load(Ordering::Acquire) != 0 {
            drop(guard);
            return None;
        }
        Some(guard)
    }

    async fn lock(&self) -> async_lock::MutexGuard<'_, u64> {
        if let Some(guard) = self.try_lock() {
            return guard;
        }

        self.waiters.fetch_add(1, Ordering::AcqRel);
        // The RAII token also decrements the count if an enclosing file future
        // is cancelled while this mutex acquisition is pending.
        let waiter = PositionWaiter(&self.waiters);
        let guard = self.value.lock().await;
        drop(waiter);
        guard
    }
}

async fn extend_backend_to_cached_size(file: &FileNode, cached_size: u64) -> VfsResult<()> {
    if file.len().await? < cached_size {
        file.set_len(cached_size).await?;
    }
    Ok(())
}

async fn read_source_at_async<W: Write + IoBufMut>(
    file: &FileNode,
    dst: &mut W,
    offset: u64,
) -> VfsResult<usize> {
    let total = dst.remaining_mut();
    if total == 0 {
        return Ok(0);
    }

    let mut staging = alloc::vec![0u8; total.min(DIRECT_IO_STAGING_SIZE)];
    let mut completed = 0usize;
    while completed < total {
        let wanted = (total - completed).min(staging.len());
        let current_offset = offset
            .checked_add(completed as u64)
            .ok_or(VfsError::InvalidInput)?;
        let read = file.read_at(&mut staging[..wanted], current_offset).await?;
        if read > wanted {
            return Err(VfsError::Io);
        }

        let mut copied = 0usize;
        while copied < read {
            let written = dst.write(&staging[copied..read])?;
            if written == 0 || written > read - copied {
                return Err(VfsError::Io);
            }
            copied += written;
        }
        completed += read;
        if read < wanted {
            break;
        }
    }
    Ok(completed)
}

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
                    let requested = dst.remaining_mut();
                    if requested == 0 {
                        return Ok(0);
                    }
                    let shared = shared_file_state_async(loc).await?;
                    let _guard = shared.io_lock.write().await;
                    extend_backend_to_cached_size(file, shared.size()).await?;
                    shared
                        .flush_dirty_range_async(file, offset, requested)
                        .await?;
                    return read_source_at_async(file, &mut dst, offset).await;
                }
                read_source_at_async(file, &mut dst, offset).await
            }
        }
    }

    /// Tries to serve a read without suspending. `None` preserves the normal
    /// async path for direct I/O, cache misses, and contended cache state.
    pub fn try_read_at_resident(
        &self,
        dst: impl Write + IoBufMut,
        offset: u64,
    ) -> Option<VfsResult<usize>> {
        match self {
            Self::Cached(cached) => cached.try_read_at_resident(dst, offset),
            Self::Direct(_) => None,
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
                    let requested = src.remaining();
                    let shared = shared_file_state_async(loc).await?;
                    let _guard = shared.io_lock.write().await;
                    extend_backend_to_cached_size(file, shared.size()).await?;
                    shared
                        .flush_dirty_range_async(file, offset, requested)
                        .await?;
                    let result = write_source_at_async(file, &mut src, offset).await;
                    if let Ok(written) = result.as_ref() {
                        if *written != 0 {
                            let end = offset
                                .checked_add(*written as u64)
                                .ok_or(VfsError::InvalidInput)?;
                            shared.set_size(shared.size().max(end));
                        }
                    } else if let Ok(backend_size) = file.len().await {
                        shared.set_size(shared.size().max(backend_size));
                    }
                    let invalidate = shared
                        .discard_direct_write_range_without_writeback_async(file, offset, requested)
                        .await;
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

    pub async fn write_at_slice(&self, src: &[u8], offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.write_at_slice_async(src, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if !node_allows_page_cache(node_flags) || node_flags.contains(NodeFlags::STREAM) {
                    return write_slice_source_at_async(file, src, offset).await;
                }

                let requested = src.len();
                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                extend_backend_to_cached_size(file, shared.size()).await?;
                shared
                    .flush_dirty_range_async(file, offset, requested)
                    .await?;
                let result = write_slice_source_at_async(file, src, offset).await;
                if let Ok(written) = result.as_ref() {
                    if *written != 0 {
                        let end = offset
                            .checked_add(*written as u64)
                            .ok_or(VfsError::InvalidInput)?;
                        shared.set_size(shared.size().max(end));
                    }
                } else if let Ok(backend_size) = file.len().await {
                    shared.set_size(shared.size().max(backend_size));
                }
                let invalidate = shared
                    .discard_direct_write_range_without_writeback_async(file, offset, requested)
                    .await;
                match (result, invalidate) {
                    (Ok(written), Ok(())) => Ok(written),
                    (Err(err), Ok(())) => Err(err),
                    (Ok(_), Err(err)) => Err(err),
                    (Err(err), Err(_)) => Err(err),
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

                let requested = src.remaining();
                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                let cached_size = shared.size();
                let backend_size = file.len().await?;
                let offset = backend_size.max(cached_size);
                if backend_size < cached_size {
                    file.set_len(cached_size).await?;
                }
                // An append can begin in the cached file's final partial page.
                // Flush that page before direct I/O so range invalidation cannot
                // discard dirty bytes preceding the append offset.
                shared
                    .flush_dirty_range_async(file, offset, requested)
                    .await?;
                let result = append_source_async(file, &mut src).await;
                if let Ok((_, end)) = result.as_ref() {
                    shared.set_size(shared.size().max(*end));
                } else if let Ok(backend_size) = file.len().await {
                    shared.set_size(shared.size().max(backend_size));
                }
                let invalidate = shared
                    .discard_direct_write_range_without_writeback_async(file, offset, requested)
                    .await;
                match (result, invalidate) {
                    (Ok(result), Ok(())) => Ok(result),
                    (Err(err), Ok(())) => Err(err),
                    (Ok(_), Err(err)) => Err(err),
                    (Err(err), Err(_)) => Err(err),
                }
            }
        }
    }

    pub async fn append_slice(&self, src: &[u8]) -> VfsResult<(usize, u64)> {
        match self {
            Self::Cached(cached) => cached.append_slice_async(src).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return append_slice_source_async(file, src).await;
                }

                let requested = src.len();
                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                let cached_size = shared.size();
                let backend_size = file.len().await?;
                let offset = backend_size.max(cached_size);
                if backend_size < cached_size {
                    file.set_len(cached_size).await?;
                }
                // See append above: an append may overlap the final partial
                // cached page even though its byte offset is the file end.
                shared
                    .flush_dirty_range_async(file, offset, requested)
                    .await?;
                let result = append_slice_source_async(file, src).await;
                if let Ok((_, end)) = result.as_ref() {
                    shared.set_size(shared.size().max(*end));
                } else if let Ok(backend_size) = file.len().await {
                    shared.set_size(shared.size().max(backend_size));
                }
                let invalidate = shared
                    .discard_direct_write_range_without_writeback_async(file, offset, requested)
                    .await;
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

    /// Starts a bounded, best-effort cache fill without changing a file
    /// handle's current offset.
    pub fn readahead(&self, offset: u64, len: usize) -> VfsResult<()> {
        match self {
            Self::Cached(cached) => cached.prefetch_range(offset, len),
            Self::Direct(loc) => {
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return Ok(());
                }
                let cached =
                    axtask::future::block_on(CachedFile::get_or_create_async(loc.clone()))?;
                cached.prefetch_range(offset, len)
            }
        }
    }
}

/// Provides `std::fs::File`-like interface.
pub struct File {
    inner: FileBackend,
    flags: FileFlags,
    position: Option<FilePosition>,
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
            Some(FilePosition::new(if flags.contains(FileFlags::APPEND) {
                append_position
            } else {
                0
            }))
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

    /// Starts a bounded, best-effort readahead operation without changing the
    /// shared file position or recording a read access timestamp.
    pub fn readahead(&self, offset: u64, len: usize) -> VfsResult<()> {
        self.access(FileFlags::READ)?.readahead(offset, len)
    }

    /// Reads a number of bytes starting from a given offset.
    pub async fn read_at(&self, dst: impl Write + IoBufMut, offset: u64) -> VfsResult<usize> {
        let result = self.access(FileFlags::READ)?.read_at(dst, offset).await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|read| *read != 0) {
            self.access_flags
                .fetch_or(ACCESS_FLAG_ATIME, Ordering::AcqRel);
        }
        result
    }

    /// Tries to read fully resident cache pages without constructing a future.
    /// A `None` result must be retried through [`Self::read_at`].
    pub fn try_read_at_resident(
        &self,
        dst: impl Write + IoBufMut,
        offset: u64,
    ) -> Option<VfsResult<usize>> {
        let backend = match self.access(FileFlags::READ) {
            Ok(backend) => backend,
            Err(err) => return Some(Err(err)),
        };
        let result = backend.try_read_at_resident(dst, offset);
        #[cfg(feature = "times")]
        if let Some(Ok(read)) = result.as_ref()
            && *read != 0
        {
            self.access_flags
                .fetch_or(ACCESS_FLAG_ATIME, Ordering::AcqRel);
        }
        result
    }

    /// Writes a number of bytes starting from a given offset.
    pub async fn write_at(&self, src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let result = self.access(FileFlags::WRITE)?.write_at(src, offset).await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags
                .fetch_or(ACCESS_FLAG_MTIME, Ordering::AcqRel);
        }
        result
    }

    /// Writes a contiguous, lifetime-stable byte slice at a given offset.
    ///
    /// Callers that may suspend while borrowing user memory must keep its
    /// backing frames pinned until this future completes.
    pub async fn write_at_slice(&self, src: &[u8], offset: u64) -> VfsResult<usize> {
        let result = self
            .access(FileFlags::WRITE)?
            .write_at_slice(src, offset)
            .await;
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags
                .fetch_or(ACCESS_FLAG_MTIME, Ordering::AcqRel);
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

    /// Tries to read from resident cache pages while preserving the shared file
    /// offset update as one non-suspending critical section.
    pub fn try_read_resident(&self, dst: impl Write + IoBufMut) -> Option<axio::Result<usize>> {
        if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.try_lock()?;
            let result = self.try_read_at_resident(dst, *pos)?;
            if let Ok(read) = result.as_ref() {
                *pos += *read as u64;
            }
            Some(result)
        } else {
            self.try_read_at_resident(dst, 0)
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
            self.access_flags
                .fetch_or(ACCESS_FLAG_MTIME, Ordering::AcqRel);
        }
        result
    }

    /// Writes a contiguous, lifetime-stable byte slice at the current offset.
    ///
    /// Callers that may suspend while borrowing user memory must keep its
    /// backing frames pinned until this future completes.
    pub async fn write_slice(&self, src: &[u8]) -> axio::Result<usize> {
        let result = if let Some(pos) = self.position.as_ref() {
            let mut pos = pos.lock().await;
            if let Ok(f) = self.access(FileFlags::APPEND) {
                f.append_slice(src).await.map(|(written, new_size)| {
                    *pos = new_size;
                    written
                })
            } else {
                self.write_at_slice(src, *pos).await.inspect(|n| {
                    *pos += *n as u64;
                })
            }
        } else {
            self.write_at_slice(src, 0).await
        };
        #[cfg(feature = "times")]
        if result.as_ref().is_ok_and(|written| *written != 0) {
            self.access_flags
                .fetch_or(ACCESS_FLAG_MTIME, Ordering::AcqRel);
        }
        result
    }

    pub async fn flush(&self) -> axio::Result {
        self.sync(false).await
    }

    pub fn position(&self) -> Option<u64> {
        self.position.as_ref().map(|pos| {
            let pos = pos
                .try_lock()
                .unwrap_or_else(|| axtask::future::block_on(pos.lock()));
            *pos
        })
    }

    #[cfg(feature = "times")]
    async fn take_timestamp_updates(&self) -> VfsResult<u8> {
        let flags = self.access_flags.swap(0, Ordering::AcqRel);
        if flags == 0 {
            return Ok(0);
        }

        let now = axhal::time::wall_time();
        let mut update = axfs_ng_vfs::MetadataUpdate::default();
        if flags & ACCESS_FLAG_ATIME != 0 {
            update.atime = Some(now);
        }
        if flags & ACCESS_FLAG_MTIME != 0 {
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
        if has_pending_timestamp_updates(self.access_flags.load(Ordering::Acquire)) {
            // Closing a file publishes every deferred timestamp, including atime
            // set by a successful read.
            let _ = axtask::future::block_on(self.take_timestamp_updates());
        }
    }
}

#[cfg(all(test, feature = "times"))]
mod timestamp_tests {
    use super::{ACCESS_FLAG_ATIME, ACCESS_FLAG_MTIME, has_pending_timestamp_updates};

    #[test]
    fn read_only_access_requires_a_deferred_timestamp_update() {
        assert!(!has_pending_timestamp_updates(0));
        assert!(has_pending_timestamp_updates(ACCESS_FLAG_ATIME));
        assert!(has_pending_timestamp_updates(ACCESS_FLAG_MTIME));
        assert!(has_pending_timestamp_updates(
            ACCESS_FLAG_ATIME | ACCESS_FLAG_MTIME
        ));
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
            let mut guard = guard
                .try_lock()
                .unwrap_or_else(|| axtask::future::block_on(guard.lock()));
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
