use alloc::{collections::BTreeMap, string::String};
use core::cmp::Ordering;
use core::borrow::Borrow;
pub struct Mutex<T> {
    inner: spin::Mutex<T>,
}

impl<T: core::fmt::Debug> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.inner, f)
    }
}

impl<T> Mutex<T> {
    pub const fn new(t: T) -> Self {
        Self {
            inner: spin::Mutex::new(t),
        }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        let guard = kernel_guard::NoPreempt::new();
        MutexGuard {
            inner: core::mem::ManuallyDrop::new(self.inner.lock()),
            _guard: core::mem::ManuallyDrop::new(guard),
        }
    }
}

pub struct MutexGuard<'a, T> {
    inner: core::mem::ManuallyDrop<spin::MutexGuard<'a, T>>,
    _guard: core::mem::ManuallyDrop<kernel_guard::NoPreempt>,
}

impl<'a, T> core::ops::Deref for MutexGuard<'a, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        &**self.inner
    }
}

impl<'a, T> core::ops::DerefMut for MutexGuard<'a, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        &mut **self.inner
    }
}

impl<'a, T> Drop for MutexGuard<'a, T> {
    fn drop(&mut self) {
        unsafe {
            core::mem::ManuallyDrop::drop(&mut self.inner);
            core::mem::ManuallyDrop::drop(&mut self._guard);
        }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

use crate::{DirEntrySink, NodeType, Metadata, MetadataUpdate, VfsResult};

/// A file name wrapper that sorts '.' first, then '..', and then alphabetically.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
pub struct FileName(pub String);

/// Compare two filenames prioritizing '.' then '..', and then alphabetically.
pub fn cmp_file_name(a: &str, b: &str) -> Ordering {
    fn index(s: &str) -> u8 {
        match s {
            "." => 0,
            ".." => 1,
            _ => 2,
        }
    }
    (index(a), a).cmp(&(index(b), b))
}

impl PartialOrd for FileName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for FileName {
    fn cmp(&self, other: &Self) -> Ordering {
        cmp_file_name(&self.0, &other.0)
    }
}

impl<T> From<T> for FileName
where
    T: Into<String>,
{
    fn from(name: T) -> Self {
        Self(name.into())
    }
}

impl Borrow<str> for FileName {
    fn borrow(&self) -> &str {
        &self.0
    }
}



/// A generic in-memory directory container holding child entry maps.
#[derive(Default)]
pub struct InMemDir<E> {
    pub entries: Mutex<BTreeMap<FileName, E>>,
}

impl<E> InMemDir<E> {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
        }
    }
}

/// A generic in-memory inode representation containing metadata and dynamic node content.
pub struct InMemInode<C> {
    pub ino: u64,
    pub metadata: Mutex<Metadata>,
    pub content: C,
}

impl<C> InMemInode<C> {
    pub fn new(ino: u64, metadata: Metadata, content: C) -> Self {
        Self {
            ino,
            metadata: Mutex::new(metadata),
            content,
        }
    }
}

/// Standard helper to perform a directory read (for `read_dir`) from a locked entries map.
pub fn read_dir_impl<E, F>(
    entries: &Mutex<BTreeMap<FileName, E>>,
    offset: u64,
    sink: &mut dyn DirEntrySink,
    mut get_info: F,
) -> VfsResult<usize>
where
    F: FnMut(&E) -> (u64, NodeType),
{
    let entries_lock = entries.lock();
    let mut count = 0;
    for (idx, (name, entry)) in entries_lock.iter().enumerate().skip(offset as usize) {
        let (ino, node_type) = get_info(entry);
        if !sink.accept(&name.0, ino, node_type, (idx + 1) as u64) {
            break;
        }
        count += 1;
    }
    Ok(count)
}

/// Updates standard metadata fields from `MetadataUpdate`.
pub fn update_metadata_impl(metadata: &mut Metadata, update: MetadataUpdate) {
    if let Some(mode) = update.mode {
        metadata.mode = mode;
    }
    if let Some((uid, gid)) = update.owner {
        metadata.uid = uid;
        metadata.gid = gid;
    }
    if let Some(atime) = update.atime {
        metadata.atime = atime;
    }
    if let Some(mtime) = update.mtime {
        metadata.mtime = mtime;
    }
}
