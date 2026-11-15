//! Opt-in guest checks at the real File/FileIo boundary. Only external storage
//! is replaced: cache pages, file positions, transaction guards, and staging
//! execute their production implementations. These are not physical-disk tests.

use alloc::{boxed::Box, collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    any::Any,
    sync::atomic::{AtomicU64, Ordering},
    task::Context,
    time::Duration,
};

use axfs_ng_vfs::{
    DeviceId, DirEntry, FileNode, FileNodeOps, Filesystem, FilesystemOps, Location, Metadata,
    MetadataUpdate, Mountpoint, NodeFlags, NodeOps, NodePermission, NodeType, Reference, StatFs,
    VfsError, VfsResult,
};
use axpoll::{IoEvents, Pollable};
use spin::Mutex;

use super::{CachedFile, File, FileBackend, FileFlags};

const PAGE: usize = 4096;
const WINDOW: usize = 64 * 1024;
static NEXT_INODE: AtomicU64 = AtomicU64::new(1);

macro_rules! check {
    ($condition:expr) => {
        if !$condition {
            error!(
                "[FILE_IO_GUEST] FAIL line={} {}",
                line!(),
                stringify!($condition)
            );
            return Err(VfsError::BadState);
        }
    };
}

struct TestFilesystem(Filesystem);

#[async_trait::async_trait]
impl FilesystemOps for TestFilesystem {
    fn name(&self) -> &str {
        // CachedFile must exercise storage reads, rather than tmpfs zero-fill.
        "file-io-checks"
    }

    fn root_dir(&self) -> DirEntry {
        self.0.root_dir()
    }

    fn stat(&self) -> VfsResult<StatFs> {
        self.0.stat()
    }
}

#[derive(Clone, Copy)]
enum WriteReply {
    Full,
    Short(usize),
    Zero,
    Error,
}

struct Storage {
    data: Vec<u8>,
    writes: usize,
    reads: usize,
    write_plan: VecDeque<WriteReply>,
    fail_read_from: Option<u64>,
}

struct TestFile {
    fs: Arc<TestFilesystem>,
    inode: u64,
    kind: NodeType,
    storage: Mutex<Storage>,
}

#[async_trait::async_trait]
impl NodeOps for TestFile {
    fn inode(&self) -> u64 {
        self.inode
    }

    async fn metadata(&self) -> VfsResult<Metadata> {
        let size = self.storage.lock().data.len() as u64;
        Ok(Metadata {
            device: 0,
            inode: self.inode,
            nlink: 1,
            mode: NodePermission::default(),
            node_type: self.kind,
            uid: 0,
            gid: 0,
            size,
            block_size: 512,
            blocks: size.div_ceil(512),
            rdev: DeviceId(0),
            atime: Duration::ZERO,
            mtime: Duration::ZERO,
            ctime: Duration::ZERO,
        })
    }

    async fn len(&self) -> VfsResult<u64> {
        Ok(self.storage.lock().data.len() as u64)
    }

    async fn update_metadata(&self, _update: MetadataUpdate) -> VfsResult<()> {
        Ok(())
    }

    fn filesystem(&self) -> &dyn FilesystemOps {
        self.fs.as_ref()
    }

    async fn sync(&self, _data_only: bool) -> VfsResult<()> {
        Ok(())
    }

    fn flags(&self) -> NodeFlags {
        if self.kind == NodeType::RegularFile {
            NodeFlags::empty()
        } else {
            NodeFlags::NON_CACHEABLE
        }
    }

    fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
        self
    }
}

impl Pollable for TestFile {
    fn poll(&self) -> IoEvents {
        IoEvents::IN | IoEvents::OUT
    }

    fn register(&self, _context: &mut Context<'_>, _events: IoEvents) {}
}

#[async_trait::async_trait]
impl FileNodeOps for TestFile {
    async fn read_at(&self, dst: &mut [u8], offset: u64) -> VfsResult<usize> {
        let mut storage = self.storage.lock();
        storage.reads += 1;
        if storage.fail_read_from.is_some_and(|start| offset >= start) {
            return Err(VfsError::Io);
        }
        let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidInput)?;
        let count = dst.len().min(storage.data.len().saturating_sub(offset));
        if count != 0 {
            dst[..count].copy_from_slice(&storage.data[offset..offset + count]);
        }
        Ok(count)
    }

    async fn write_at(&self, src: &[u8], offset: u64) -> VfsResult<usize> {
        let mut storage = self.storage.lock();
        storage.writes += 1;
        let count = match storage.write_plan.pop_front().unwrap_or(WriteReply::Full) {
            WriteReply::Full => src.len(),
            WriteReply::Short(limit) => src.len().min(limit),
            WriteReply::Zero => 0,
            WriteReply::Error => return Err(VfsError::Io),
        };
        if count != 0 {
            let offset = usize::try_from(offset).map_err(|_| VfsError::InvalidInput)?;
            let end = offset.checked_add(count).ok_or(VfsError::InvalidInput)?;
            if storage.data.len() < end {
                storage.data.resize(end, 0);
            }
            storage.data[offset..end].copy_from_slice(&src[..count]);
        }
        Ok(count)
    }

    async fn append(&self, _src: &[u8]) -> VfsResult<(usize, u64)> {
        Err(VfsError::Unsupported)
    }

    async fn set_len(&self, len: u64) -> VfsResult<()> {
        self.storage
            .lock()
            .data
            .resize(usize::try_from(len).map_err(|_| VfsError::InvalidInput)?, 0);
        Ok(())
    }

    async fn set_symlink(&self, _target: &str) -> VfsResult<()> {
        Err(VfsError::Unsupported)
    }
}

struct Fixture {
    file: File,
    backend: Arc<TestFile>,
    cache: Option<CachedFile>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // The active cache registry can retain this external backend after the
        // test handles disappear. Never leave an injected fault armed for
        // background writeback or the final shutdown flush, even on failure.
        let mut storage = self.backend.storage.lock();
        storage.fail_read_from = None;
        storage.write_plan.clear();
    }
}

impl Fixture {
    async fn new(
        cached: bool,
        kind: NodeType,
        data: Vec<u8>,
        plan: &[WriteReply],
    ) -> VfsResult<Self> {
        let fs = Arc::new(TestFilesystem(crate::fs::new_tmpfs()));
        let mount = Mountpoint::new_root(&Filesystem::new(fs.clone()));
        let backend = Arc::new(TestFile {
            fs,
            inode: NEXT_INODE.fetch_add(1, Ordering::Relaxed),
            kind,
            storage: Mutex::new(Storage {
                data,
                writes: 0,
                reads: 0,
                write_plan: plan.iter().copied().collect(),
                fail_read_from: None,
            }),
        });
        let entry = DirEntry::new_file(FileNode::new(backend.clone()), kind, Reference::root());
        let location = Location::new(mount, entry);
        let cache = if cached {
            Some(CachedFile::get_or_create_async(location.clone()).await?)
        } else {
            None
        };
        let file_backend = match &cache {
            Some(cache) => FileBackend::Cached(cache.clone()),
            None => FileBackend::Direct(location),
        };
        let file = File::new_async(file_backend, FileFlags::READ | FileFlags::WRITE, None).await;
        Ok(Self {
            file,
            backend,
            cache,
        })
    }
}

async fn cached_read_prefix() -> VfsResult<()> {
    let fixture = Fixture::new(true, NodeType::RegularFile, vec![0x31; 2 * PAGE], &[]).await?;
    check!(!fixture.cache.as_ref().unwrap().in_memory());
    let mut warm = vec![0; PAGE];
    check!(fixture.file.read_at(warm.as_mut_slice(), 0).await? == PAGE);
    check!(fixture.backend.storage.lock().reads == 1);
    fixture.backend.storage.lock().fail_read_from = Some(PAGE as u64);

    let mut destination = vec![0xcc; 2 * PAGE + 2];
    let mut target = &mut destination[1..2 * PAGE + 1];
    let mut operation = fixture.file.begin_read_io(None).await?;
    check!(operation.read(&mut target).await? == PAGE);
    check!(operation.current_offset() == PAGE as u64);
    drop(operation);
    check!(fixture.file.position() == Some(PAGE as u64));
    check!(destination[0] == 0xcc && destination[2 * PAGE + 1] == 0xcc);
    check!(destination[1..PAGE + 1].iter().all(|byte| *byte == 0x31));
    check!(
        destination[PAGE + 1..2 * PAGE + 1]
            .iter()
            .all(|byte| *byte == 0xcc)
    );
    check!(fixture.backend.storage.lock().reads == 2);
    check!(fixture.cache.as_ref().unwrap().size() == (2 * PAGE) as u64);
    Ok(())
}

async fn cached_write_prefix() -> VfsResult<()> {
    let fixture = Fixture::new(true, NodeType::RegularFile, vec![0x25; 2 * PAGE], &[]).await?;
    check!(!fixture.cache.as_ref().unwrap().in_memory());
    fixture.backend.storage.lock().fail_read_from = Some(PAGE as u64);
    let bytes = vec![0x8c; PAGE + 17];
    let mut source = bytes.as_slice();
    let mut observed = Vec::new();
    let mut operation = fixture.file.begin_write_io(None).await?;
    check!(
        operation
            .write_observed(&mut source, &mut |written| observed
                .extend_from_slice(written))
            .await?
            == PAGE
    );
    check!(operation.current_offset() == PAGE as u64);
    drop(operation);
    check!(fixture.file.position() == Some(PAGE as u64));
    check!(observed.len() == PAGE && observed.iter().all(|byte| *byte == 0x8c));
    check!(fixture.cache.as_ref().unwrap().size() == (2 * PAGE) as u64);
    check!(fixture.backend.storage.lock().reads == 1);
    let mut actual = vec![0; PAGE];
    check!(fixture.file.read_at(actual.as_mut_slice(), 0).await? == PAGE);
    check!(actual.iter().all(|byte| *byte == 0x8c));
    let mut tail = [0u8; 1];
    check!(
        fixture
            .file
            .try_read_at_resident(tail.as_mut_slice(), PAGE as u64)
            .is_none()
    );
    fixture.backend.storage.lock().fail_read_from = None;
    fixture.file.sync(false).await?;
    let storage = fixture.backend.storage.lock();
    check!(storage.data.len() == 2 * PAGE);
    check!(storage.data[..PAGE].iter().all(|byte| *byte == 0x8c));
    check!(storage.data[PAGE..].iter().all(|byte| *byte == 0x25));
    Ok(())
}

async fn direct_short_zero() -> VfsResult<()> {
    for (reply, expected) in [(WriteReply::Short(3), 3), (WriteReply::Zero, 0)] {
        let fixture = Fixture::new(false, NodeType::RegularFile, Vec::new(), &[reply]).await?;
        let mut source = &b"abcdefgh"[..];
        let mut operation = fixture.file.begin_write_io(None).await?;
        check!(operation.write(&mut source).await? == expected);
        check!(operation.current_offset() == expected as u64);
        drop(operation);
        check!(fixture.file.position() == Some(expected as u64));
        let storage = fixture.backend.storage.lock();
        check!(storage.writes == 1);
        check!(storage.data.as_slice() == &b"abcdefgh"[..expected]);
    }
    Ok(())
}

async fn direct_later_error() -> VfsResult<()> {
    let fixture = Fixture::new(
        false,
        NodeType::RegularFile,
        Vec::new(),
        &[WriteReply::Full, WriteReply::Error],
    )
    .await?;
    let bytes = vec![0x42; WINDOW + 17];
    let mut source = bytes.as_slice();
    let mut operation = fixture.file.begin_write_io(None).await?;
    check!(operation.write(&mut source).await? == WINDOW);
    check!(operation.current_offset() == WINDOW as u64);
    drop(operation);
    check!(fixture.file.position() == Some(WINDOW as u64));
    {
        let storage = fixture.backend.storage.lock();
        check!(storage.writes == 2 && storage.data.len() == WINDOW);
        check!(storage.data.iter().all(|byte| *byte == 0x42));
    }

    // Separate user-pin windows enter the same FileIo more than once.
    let fixture = Fixture::new(
        false,
        NodeType::RegularFile,
        Vec::new(),
        &[WriteReply::Full, WriteReply::Error],
    )
    .await?;
    let mut first = &bytes[..PAGE];
    let mut second = &bytes[PAGE..PAGE + 17];
    let mut operation = fixture.file.begin_write_io(None).await?;
    check!(operation.write(&mut first).await? == PAGE);
    check!(operation.write(&mut second).await == Err(VfsError::Io));
    check!(operation.current_offset() == PAGE as u64);
    drop(operation);
    check!(fixture.file.position() == Some(PAGE as u64));
    let storage = fixture.backend.storage.lock();
    check!(storage.writes == 2 && storage.data.len() == PAGE);
    Ok(())
}

async fn legacy_nonregular_writeall() -> VfsResult<()> {
    for slice in [true, false] {
        let fixture = Fixture::new(
            false,
            NodeType::BlockDevice,
            Vec::new(),
            &[WriteReply::Short(3), WriteReply::Zero],
        )
        .await?;
        check!(!fixture.file.supports_file_io());
        let result = if slice {
            fixture.file.write_slice(b"abcdefgh").await
        } else {
            fixture.file.write(&b"abcdefgh"[..]).await
        };
        check!(result == Err(VfsError::Io));
        check!(fixture.file.position() == Some(0));
        let storage = fixture.backend.storage.lock();
        check!(storage.writes == 2 && storage.data.as_slice() == b"abc");
    }
    Ok(())
}

/// Runs only when the explicit test-kernel control operation requests it.
pub fn run_file_io_checks() -> VfsResult<()> {
    axtask::future::block_on(async {
        macro_rules! run_check {
            ($case:ident) => {
                if let Err(error) = $case().await {
                    error!("[FILE_IO_GUEST] {} FAIL {:?}", stringify!($case), error);
                    return Err(error);
                }
                info!("[FILE_IO_GUEST] {} PASS", stringify!($case));
            };
        }
        run_check!(cached_read_prefix);
        run_check!(cached_write_prefix);
        run_check!(direct_short_zero);
        run_check!(direct_later_error);
        run_check!(legacy_nonregular_writeall);
        info!("[FILE_IO_GUEST] All file I/O checks PASSED!");
        Ok(())
    })
}
