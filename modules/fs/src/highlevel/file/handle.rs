use super::{
    cache::{
        CachedFileShared, FileWriteGuard, append_slice_source_async, append_source_async,
        shared_file_state_async, write_slice_once_at_async, write_slice_source_at_async,
        write_source_at_async,
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

async fn extend_backend_to_cached_size(file: &FileNode, cached_size: u64) -> VfsResult<()> {
    if file.len().await? < cached_size {
        file.set_len(cached_size).await?;
    }
    Ok(())
}

async fn can_use_direct_read_fast_path(
    shared: &CachedFileShared,
    file: &FileNode,
    offset: u64,
    requested: usize,
) -> VfsResult<bool> {
    Ok(file.len().await? >= shared.size() && !shared.has_dirty_pages_in_range(offset, requested))
}

async fn can_use_direct_write_fast_path(
    shared: &CachedFileShared,
    file: &FileNode,
    offset: u64,
    requested: usize,
) -> VfsResult<bool> {
    let cached_size = shared.size();
    let end_fits = offset
        .checked_add(requested as u64)
        .is_some_and(|e| e <= cached_size);
    Ok(end_fits
        && file.len().await? >= cached_size
        && !shared.has_cached_pages_in_range(offset, requested))
}

async fn prepare_direct_write_slow(
    shared: &CachedFileShared,
    file: &FileNode,
    offset: u64,
    requested: usize,
) -> VfsResult<()> {
    extend_backend_to_cached_size(file, shared.size()).await?;
    shared.flush_dirty_range_async(file, offset, requested).await
}

async fn finish_direct_write(
    shared: &CachedFileShared,
    file: &FileNode,
    offset: u64,
    requested: usize,
    result: VfsResult<usize>,
) -> VfsResult<usize> {
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
        (Ok(written), Err(_)) if written != 0 => Ok(written),
        (Ok(_), Err(err)) => Err(err),
        (Err(err), Err(_)) => Err(err),
    }
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
        #[cfg(feature = "file-io-test")]
        super::io_test::staged_bytes(read);

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
    async fn begin_write_operation(&self, exclusive: bool) -> VfsResult<Option<FileWriteGuard>> {
        match self {
            Self::Cached(cached) => Ok(Some(cached.begin_write_operation(exclusive).await)),
            Self::Direct(loc) => {
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return Ok(None);
                }
                let shared = shared_file_state_async(loc).await?;
                Ok(Some(shared.begin_write_operation(exclusive).await))
            }
        }
    }

    async fn append_offset(&self) -> VfsResult<u64> {
        match self {
            Self::Cached(cached) => Ok(cached.append_offset()),
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let shared = shared_file_state_async(loc).await?;
                Ok(shared.size().max(file.len().await?))
            }
        }
    }

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
                    {
                        let _guard = shared.io_lock.read().await;
                        if can_use_direct_read_fast_path(&shared, file, offset, requested).await? {
                            return read_source_at_async(file, &mut dst, offset).await;
                        }
                    }
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

    /// Fills a stable kernel slice, avoiding a second staging allocation in
    /// direct I/O. Advancing the slice also retains cached-read partial progress
    /// when a later page fill fails.
    async fn read_at_slice_in_operation(
        &self,
        dst: &mut &mut [u8],
        offset: u64,
    ) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.read_at_async(dst, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let requested = dst.len();
                if requested == 0 {
                    return Ok(0);
                }
                let read = if node_allows_page_cache(loc.flags())
                    && !loc.flags().contains(NodeFlags::STREAM)
                {
                    let shared = shared_file_state_async(loc).await?;
                    let fast_read = {
                        let _guard = shared.io_lock.read().await;
                        if can_use_direct_read_fast_path(&shared, file, offset, requested).await? {
                            Some(file.read_at(dst, offset).await?)
                        } else {
                            None
                        }
                    };
                    match fast_read {
                        Some(read) => read,
                        None => {
                            let _guard = shared.io_lock.write().await;
                            extend_backend_to_cached_size(file, shared.size()).await?;
                            shared
                                .flush_dirty_range_async(file, offset, requested)
                                .await?;
                            file.read_at(dst, offset).await?
                        }
                    }
                } else {
                    file.read_at(dst, offset).await?
                };
                if read > requested {
                    return Err(VfsError::Io);
                }
                let remaining = core::mem::take(dst);
                *dst = &mut remaining[read..];
                Ok(read)
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

    pub async fn write_at(&self, src: impl Read + IoBuf, offset: u64) -> VfsResult<usize> {
        let _operation = self.begin_write_operation(false).await?;
        self.write_at_in_operation(src, offset).await
    }

    async fn write_at_in_operation(
        &self,
        mut src: impl Read + IoBuf,
        offset: u64,
    ) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.write_at_in_operation(src, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if !node_allows_page_cache(node_flags) || node_flags.contains(NodeFlags::STREAM) {
                    write_source_at_async(file, &mut src, offset).await
                } else {
                    let requested = src.remaining();
                    if requested == 0 {
                        return Ok(0);
                    }
                    let shared = shared_file_state_async(loc).await?;
                    let fast_result = {
                        let _guard = shared.io_lock.read().await;
                        if can_use_direct_write_fast_path(&shared, file, offset, requested).await? {
                            // Reject concurrent cache fills that started before this direct write.
                            shared.bump_cache_generation();
                            Some(write_source_at_async(file, &mut src, offset).await)
                        } else {
                            None
                        }
                    };
                    if let Some(result) = fast_result {
                        if !shared.has_cached_pages_in_range(offset, requested) {
                            return result;
                        }
                        let _guard = shared.io_lock.write().await;
                        return finish_direct_write(&shared, file, offset, requested, result).await;
                    }
                    let _guard = shared.io_lock.write().await;
                    prepare_direct_write_slow(&shared, file, offset, requested).await?;
                    let result = write_source_at_async(file, &mut src, offset).await;
                    finish_direct_write(&shared, file, offset, requested, result).await
                }
            }
        }
    }

    pub async fn write_at_slice(&self, src: &[u8], offset: u64) -> VfsResult<usize> {
        let _operation = self.begin_write_operation(false).await?;
        self.write_at_slice_in_operation(src, offset).await
    }

    async fn write_at_slice_in_operation(&self, src: &[u8], offset: u64) -> VfsResult<usize> {
        match self {
            Self::Cached(cached) => cached.write_at_slice_in_operation(src, offset).await,
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                let node_flags = loc.flags();
                if !node_allows_page_cache(node_flags) || node_flags.contains(NodeFlags::STREAM) {
                    return write_slice_source_at_async(file, src, offset).await;
                }

                let requested = src.len();
                if requested == 0 {
                    return Ok(0);
                }
                let shared = shared_file_state_async(loc).await?;
                let fast_result = {
                    let _guard = shared.io_lock.read().await;
                    if can_use_direct_write_fast_path(&shared, file, offset, requested).await? {
                        shared.bump_cache_generation();
                        let res = if loc.node_type() == NodeType::RegularFile {
                            write_slice_once_at_async(file, src, offset).await
                        } else {
                            write_slice_source_at_async(file, src, offset).await
                        };
                        Some(res)
                    } else {
                        None
                    }
                };
                if let Some(result) = fast_result {
                    if !shared.has_cached_pages_in_range(offset, requested) {
                        return result;
                    }
                    let _guard = shared.io_lock.write().await;
                    return finish_direct_write(&shared, file, offset, requested, result).await;
                }
                let _guard = shared.io_lock.write().await;
                prepare_direct_write_slow(&shared, file, offset, requested).await?;
                let result = if loc.node_type() == NodeType::RegularFile {
                    write_slice_once_at_async(file, src, offset).await
                } else {
                    write_slice_source_at_async(file, src, offset).await
                };
                finish_direct_write(&shared, file, offset, requested, result).await
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
                let _operation = shared.begin_write_operation(true).await;
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
                let _operation = shared.begin_write_operation(true).await;
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
        self.sync_for_description(data_only, None).await.map(|_| ())
    }

    /// A successful checkpoint can still acknowledge an earlier writeback error.
    async fn sync_for_description(
        &self,
        data_only: bool,
        cursor: Option<&WritebackErrorCursor>,
    ) -> VfsResult<Option<VfsError>> {
        let file = self.location().entry().as_file()?;
        let shared = match self {
            Self::Cached(cached) if cached.in_memory() => return Ok(None),
            Self::Cached(cached) => cached.shared.clone(),
            Self::Direct(loc) => {
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return file.sync(data_only).await.map(|()| None);
                }
                shared_file_state_async(loc).await?
            }
        };
        let _guard = shared.io_lock.write().await;
        let result = shared.sync_dirty_pages_async(file, data_only).await;
        let reported = cursor.and_then(|cursor| cursor.check_and_advance(result));
        result.map(|()| reported)
    }

    pub async fn sync_range(
        &self,
        offset: u64,
        len: u64,
        wait_before: bool,
        write: bool,
        wait_after: bool,
    ) -> VfsResult<()> {
        if !wait_before && !write && !wait_after {
            return Ok(());
        }
        match self {
            Self::Cached(cached) => {
                cached
                    .sync_range_async(offset, len, wait_before, write, wait_after)
                    .await
            }
            Self::Direct(loc) => {
                let file = loc.entry().as_file()?;
                if !node_allows_page_cache(loc.flags()) || loc.flags().contains(NodeFlags::STREAM) {
                    return if write || wait_after {
                        file.sync(true).await
                    } else {
                        Ok(())
                    };
                }

                let shared = shared_file_state_async(loc).await?;
                let _guard = shared.io_lock.write().await;
                shared
                    .sync_range_async(file, offset, len, wait_before, write, wait_after)
                    .await
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
                let _operation = shared.begin_write_operation(true).await;
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
                    task::future::block_on(CachedFile::get_or_create_async(loc.clone()))?;
                cached.prefetch_range(offset, len)
            }
        }
    }
}

/// Provides `std::fs::File`-like interface.
pub struct File {
    inner: FileBackend,
    writeback_errors: Option<WritebackErrorCursor>,
    flags: FileFlags,
    position: Option<Arc<FilePosition>>,
    _write_access: Option<WriteAccessGuard>,
    #[cfg(feature = "times")]
    access_flags: AtomicU8,
}

/// One regular-file I/O operation spanning bounded, separately prepared user
/// buffer windows. The position and write-operation guards remain held until
/// this value is dropped. Cache/page-access guards exist only inside each
/// transfer, so preparing a subsequent window can fault from the same file.
pub struct FileIo<'a> {
    file: &'a File,
    position: IoPosition<'a>,
    write: bool,
    _write_operation: Option<FileWriteGuard>,
    // Reused across bounded user windows. SG sources cannot expose Rust slice
    // references over memory that another user thread may concurrently change.
    staging: Vec<u8>,
}

impl<'a> FileIo<'a> {
    fn new(
        file: &'a File,
        position: IoPosition<'a>,
        write: bool,
        write_operation: Option<FileWriteGuard>,
    ) -> Self {
        #[cfg(feature = "file-io-test")]
        super::io_test::operation_started();
        Self {
            file,
            position,
            write,
            _write_operation: write_operation,
            staging: Vec::new(),
        }
    }

    /// Exchanges initialized staging storage with a caller-owned bounded cache.
    /// Oversized allocations are not retained by a file operation. Existing
    /// bytes remain initialized, but only bytes filled by the current backend
    /// or source transfer can be delivered to its destination.
    pub fn replace_staging(&mut self, buffer: Vec<u8>) -> Vec<u8> {
        let buffer = if buffer.capacity() <= DIRECT_IO_STAGING_SIZE {
            buffer
        } else {
            Vec::new()
        };
        core::mem::replace(&mut self.staging, buffer)
    }

    pub fn current_offset(&self) -> u64 {
        self.position.offset()
    }

    /// Offset used by existing direct-I/O validation: the original shared or
    /// explicit position, even when APPEND subsequently selects a different EOF.
    pub fn validation_offset(&self) -> u64 {
        self.position.validation_offset()
    }

    fn check_length(&self, requested: usize) -> VfsResult<()> {
        self.current_offset()
            .checked_add(requested as u64)
            .ok_or(VfsError::InvalidInput)?;
        Ok(())
    }

    fn completed(&mut self, count: usize) -> VfsResult<usize> {
        self.position.advance(count).ok_or(VfsError::InvalidInput)?;
        #[cfg(feature = "times")]
        if count != 0 {
            self.file.access_flags.fetch_or(
                if self.write {
                    ACCESS_FLAG_MTIME
                } else {
                    ACCESS_FLAG_ATIME
                },
                Ordering::AcqRel,
            );
        }
        Ok(count)
    }

    fn prepare_staging(&mut self, requested: usize) -> VfsResult<()> {
        let wanted = requested.min(DIRECT_IO_STAGING_SIZE);
        if self.staging.len() < wanted {
            self.staging
                .try_reserve_exact(wanted - self.staging.len())
                .map_err(|_| VfsError::NoMemory)?;
            self.staging.resize(wanted, 0);
        }
        Ok(())
    }

    /// Delivers bytes only after every page-cache reference and guard has been
    /// released. The destination can map the source file or overlap it.
    fn deliver_staged<W: Write + IoBufMut>(
        &mut self,
        dst: &mut W,
        staged: usize,
    ) -> VfsResult<usize> {
        #[cfg(feature = "file-io-test")]
        super::io_test::staged_bytes(staged);
        let mut delivered = 0;
        while delivered < staged {
            let before = dst.remaining_mut();
            let result = dst.write(&self.staging[delivered..staged]);
            let copied = match before.checked_sub(dst.remaining_mut()) {
                Some(copied) if copied <= staged - delivered => copied,
                _ if delivered != 0 => return Ok(delivered),
                _ => return Err(VfsError::Io),
            };
            self.completed(copied)?;
            delivered += copied;
            match result {
                Ok(count) if count == copied && copied != 0 => {}
                Ok(0) if copied == 0 => return Ok(delivered),
                Err(error) if delivered == 0 => return Err(error.into()),
                _ if delivered != 0 => return Ok(delivered),
                _ => return Err(VfsError::Io),
            }
        }
        Ok(delivered)
    }

    /// Tries one fully resident bounded window without constructing a future.
    /// `None` leaves the destination and position unchanged; retain this same
    /// operation and call `read` for cache misses, contention, or direct I/O.
    pub fn try_read<W: Write + IoBufMut>(&mut self, dst: &mut W) -> Option<VfsResult<usize>> {
        if self.write {
            return Some(Err(VfsError::BadFileDescriptor));
        }
        if let Err(error) = self.file.access(FileFlags::READ) {
            return Some(Err(error));
        }
        let requested = dst.remaining_mut();
        if let Err(error) = self.check_length(requested) {
            return Some(Err(error));
        }
        if requested == 0 {
            return Some(Ok(0));
        }
        if requested > DIRECT_IO_STAGING_SIZE || matches!(self.file.inner, FileBackend::Direct(_)) {
            return None;
        }
        if let Err(error) = self.prepare_staging(requested) {
            return Some(Err(error));
        }
        let offset = self.current_offset();
        let mut target = &mut self.staging[..requested];
        let result = self.file.inner.try_read_at_resident(&mut target, offset)?;
        let staged = requested - target.len();
        match result {
            Err(error) if staged == 0 => Some(Err(error)),
            Ok(count) if count != staged => Some(Err(VfsError::Io)),
            _ => Some(self.deliver_staged(dst, staged)),
        }
    }

    pub async fn read<W: Write + IoBufMut>(&mut self, dst: &mut W) -> VfsResult<usize> {
        if self.write {
            return Err(VfsError::BadFileDescriptor);
        }
        self.file.access(FileFlags::READ)?;
        let requested = dst.remaining_mut();
        self.check_length(requested)?;
        if requested == 0 {
            return Ok(0);
        }
        self.prepare_staging(requested)?;
        let mut completed = 0;
        while completed < requested {
            let wanted = (requested - completed).min(self.staging.len());
            let offset = self.current_offset();
            let mut target = &mut self.staging[..wanted];
            let backend = &self.file.inner;
            let result = match backend.try_read_at_resident(&mut target, offset) {
                Some(result) => result,
                None => {
                    backend
                        .read_at_slice_in_operation(&mut target, offset)
                        .await
                }
            };
            let staged = wanted - target.len();
            let stop = result.is_err() || staged < wanted;
            match result {
                Err(error) if staged == 0 && completed == 0 => return Err(error),
                Err(_) if staged == 0 => break,
                Ok(count) if count != staged && completed == 0 => return Err(VfsError::Io),
                Ok(count) if count != staged => break,
                _ => {}
            }
            match self.deliver_staged(dst, staged) {
                Ok(delivered) => {
                    completed += delivered;
                    if delivered < staged {
                        break;
                    }
                }
                Err(error) if completed == 0 => return Err(error),
                Err(_) => break,
            }
            if stop || staged == 0 {
                break;
            }
        }
        Ok(completed)
    }

    pub async fn write<R: Read + IoBuf>(&mut self, src: &mut R) -> VfsResult<usize> {
        self.write_observed(src, &mut |_| {}).await
    }

    /// Reports only committed bytes, from the same stable staging copy passed
    /// to the backend. The observer runs after cache guards are released but
    /// while the operation retains its position/write guard; it must not
    /// synchronously reenter operations requiring those guards for this file.
    pub async fn write_observed<R: Read + IoBuf>(
        &mut self,
        src: &mut R,
        on_written: &mut impl FnMut(&[u8]),
    ) -> VfsResult<usize> {
        if !self.write {
            return Err(VfsError::BadFileDescriptor);
        }
        self.file.access(FileFlags::WRITE)?;
        let requested = src.remaining();
        self.check_length(requested)?;
        if requested == 0 {
            return Ok(0);
        }
        self.prepare_staging(requested)?;
        let mut completed = 0;
        while completed < requested {
            let wanted = (requested - completed).min(self.staging.len());
            let read = match src.read(&mut self.staging[..wanted]) {
                Ok(0) => break,
                Ok(read) if read <= wanted => read,
                Ok(_) if completed == 0 => return Err(VfsError::Io),
                Err(error) if completed == 0 => return Err(error.into()),
                _ => break,
            };
            #[cfg(feature = "file-io-test")]
            super::io_test::staged_bytes(read);
            // Only the stable kernel staging slice enters the backend. This
            // preserves the slice fast path and avoids a second staging copy.
            let result = self
                .file
                .inner
                .write_at_slice_in_operation(&self.staging[..read], self.current_offset())
                .await;
            match result {
                Ok(written) if written <= read => {
                    self.completed(written)?;
                    completed += written;
                    if written != 0 {
                        on_written(&self.staging[..written]);
                    }
                    if written < read {
                        break;
                    }
                }
                Ok(_) if completed == 0 => return Err(VfsError::Io),
                Err(error) if completed == 0 => return Err(error),
                _ => break,
            }
        }
        Ok(completed)
    }

    /// Retains the existing stable contiguous-slice path without staging.
    pub async fn write_slice(&mut self, src: &[u8]) -> VfsResult<usize> {
        if !self.write {
            return Err(VfsError::BadFileDescriptor);
        }
        self.file.access(FileFlags::WRITE)?;
        self.check_length(src.len())?;
        let written = self
            .file
            .inner
            .write_at_slice_in_operation(src, self.current_offset())
            .await?;
        if written > src.len() {
            return Err(VfsError::Io);
        }
        self.completed(written)
    }
}

impl File {
    /// Only regular cacheable filesystem nodes participate in user-buffer
    /// streaming. proc/devfs and streams retain their descriptor semantics;
    /// direct disk files and tmpfs are included.
    pub fn supports_file_io(&self) -> bool {
        let location = self.location();
        let flags = location.flags();
        !self.is_path()
            && node_allows_page_cache(flags)
            && !flags.contains(NodeFlags::STREAM)
            && !matches!(location.filesystem().name(), "proc" | "devfs")
            && location.node_type() == NodeType::RegularFile
    }

    /// Reserves one FIFO turn on the shared file position for deferred worker execution.
    pub fn reserve_position_ticket(&self) -> Option<FilePositionTicket> {
        self.position.as_ref().map(FilePosition::reserve)
    }

    /// Publishes a deferred job in the same order as its shared-position ticket.
    /// The callback runs with the position lock held when a ticket exists. It
    /// must only transfer the ticket to the queue and return. In particular,
    /// dropping or using the ticket, waking tasks and running I/O must wait
    /// until this call returns and releases the lock.
    pub fn publish_position_ticket<R>(
        &self,
        publish: impl FnOnce(Option<FilePositionTicket>) -> R,
    ) -> R {
        match &self.position {
            Some(position) => position.reserve_with(|ticket| publish(Some(ticket))),
            None => publish(None),
        }
    }

    /// Begins position ownership. Transfer methods check the access mode,
    /// allowing syscall alignment and user-memory validation to retain their
    /// existing precedence before the first actual transfer.
    pub async fn begin_read_io(&self, offset: Option<u64>) -> VfsResult<FileIo<'_>> {
        self.begin_io(None, offset, false, false).await
    }

    /// Begins position ownership using a submission-time ticket.
    pub async fn begin_read_io_with_ticket(
        &self,
        ticket: Option<FilePositionTicket>,
        offset: Option<u64>,
    ) -> VfsResult<FileIo<'_>> {
        self.begin_io(ticket, offset, false, false).await
    }

    /// Tries to retain the position transaction without waiting. A successful
    /// acquisition is never discarded for a cache miss or a later waiter.
    pub fn try_begin_read_io(&self, offset: Option<u64>) -> Option<VfsResult<FileIo<'_>>> {
        if !self.supports_file_io() {
            return Some(Err(VfsError::InvalidInput));
        }
        let position = IoPosition::try_begin(self.position.as_ref(), offset)?;
        Some(Ok(FileIo::new(self, position, false, None)))
    }

    /// Begins position/append ownership; write access is checked at transfer.
    pub async fn begin_write_io(&self, offset: Option<u64>) -> VfsResult<FileIo<'_>> {
        self.begin_io(None, offset, true, false).await
    }

    /// Begins position/append ownership, forcing append semantics when `force_append` is set.
    pub async fn begin_write_io_with_append(
        &self,
        offset: Option<u64>,
        force_append: bool,
    ) -> VfsResult<FileIo<'_>> {
        self.begin_io(None, offset, true, force_append).await
    }

    /// Begins position/append ownership using a submission-time ticket.
    pub async fn begin_write_io_with_ticket(
        &self,
        ticket: Option<FilePositionTicket>,
        offset: Option<u64>,
        force_append: bool,
    ) -> VfsResult<FileIo<'_>> {
        self.begin_io(ticket, offset, true, force_append).await
    }

    async fn begin_io(
        &self,
        ticket: Option<FilePositionTicket>,
        offset: Option<u64>,
        write: bool,
        force_append: bool,
    ) -> VfsResult<FileIo<'_>> {
        if !self.supports_file_io() {
            return Err(VfsError::InvalidInput);
        }
        let mut position =
            IoPosition::begin_with_ticket(self.position.as_ref(), ticket, offset).await;
        let append = write && (self.flags.contains(FileFlags::APPEND) || force_append);
        let write_operation = if write {
            self.inner.begin_write_operation(append).await?
        } else {
            None
        };
        if append {
            position.select_append(self.inner.append_offset().await?);
        }
        Ok(FileIo::new(self, position, write, write_operation))
    }

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
        let writeback_errors = WritebackErrorCursor::for_open(inner.location(), flags);
        Self {
            inner,
            writeback_errors,
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
        matches!(self.inner, FileBackend::Direct(_))
            && self.location().node_type() == NodeType::RegularFile
            && !matches!(
                self.location().filesystem().name(),
                "proc" | "devfs" | "tmpfs"
            )
    }

    /// Whether I/O or sync on this file's backing node can perform blocking waits.
    pub fn is_blocking_node(&self) -> bool {
        self.location().flags().contains(vfs::NodeFlags::BLOCKING)
    }

    pub fn block_size(&self) -> u64 {
        task::future::block_on(self.block_size_async())
    }

    pub async fn block_size_async(&self) -> u64 {
        self.inner
            .location()
            .metadata()
            .await
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

        let result = self
            .inner
            .sync_for_description(data_only, self.writeback_errors.as_ref())
            .await;
        #[cfg(feature = "times")]
        if result.is_err() {
            self.access_flags
                .fetch_or(timestamp_flags, Ordering::AcqRel);
        }
        result?.map_or(Ok(()), Err)
    }

    /// Flushes any deferred atime/mtime updates without suspending via `block_on`.
    pub async fn flush_pending_timestamps(&self) -> VfsResult<()> {
        #[cfg(feature = "times")]
        let _ = self.take_timestamp_updates().await?;
        Ok(())
    }

    /// Asynchronously flushes dirty cache pages in `[offset, offset + len)` and syncs storage.
    pub async fn sync_range(
        &self,
        offset: u64,
        len: u64,
        wait_before: bool,
        write: bool,
        wait_after: bool,
    ) -> VfsResult<()> {
        self.access(FileFlags::empty())?
            .sync_range(offset, len, wait_before, write, wait_after)
            .await
    }


    pub async fn read(&self, dst: impl Write + IoBufMut) -> io::Result<usize> {
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
    pub fn try_read_resident(&self, dst: impl Write + IoBufMut) -> Option<io::Result<usize>> {
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

    pub async fn write(&self, src: impl Read + IoBuf) -> io::Result<usize> {
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
    pub async fn write_slice(&self, src: &[u8]) -> io::Result<usize> {
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


    pub async fn flush(&self) -> io::Result {
        self.sync(false).await
    }

    pub fn position(&self) -> Option<u64> {
        self.position.as_ref().map(|pos| {
            let pos = pos
                .try_lock()
                .unwrap_or_else(|| task::future::block_on(pos.lock()));
            *pos
        })
    }

    #[cfg(feature = "times")]
    async fn take_timestamp_updates(&self) -> VfsResult<u8> {
        let flags = self.access_flags.swap(0, Ordering::AcqRel);
        if flags == 0 {
            return Ok(0);
        }

        let now = hal::time::wall_time();
        let mut update = vfs::MetadataUpdate::default();
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
            let _ = task::future::block_on(self.take_timestamp_updates());
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
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        task::future::block_on((*self).read(buf))
    }
}

impl Write for &File {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        task::future::block_on((*self).write(buf))
    }

    fn flush(&mut self) -> io::Result {
        task::future::block_on((*self).flush())
    }
}

impl Seek for &File {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.access(FileFlags::empty())?;

        if let Some(guard) = self.position.as_ref() {
            let mut guard = guard
                .try_lock()
                .unwrap_or_else(|| task::future::block_on(guard.lock()));
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
