use alloc::{collections::BTreeMap, string::String};
use core::{borrow::Borrow, cmp::Ordering};

use kspin::{SpinNoPreempt, SpinNoPreemptGuard};

use crate::{DirEntrySink, Metadata, MetadataUpdate, NodeType, VfsResult};

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

/// Exclusive, preemption-safe access to an in-memory directory's entries.
///
/// The old implementation exposed `spin::RwLock`, but directory operations
/// run in task context and can be preempted while a reader/writer is held.
/// On a one-CPU guest that lets the lock owner sleep while its successor spins
/// forever.  Keep the old `read`/`write` call sites source-compatible while
/// making both operations use the short, non-preemptible critical section.
pub struct InMemEntries<E>(SpinNoPreempt<BTreeMap<FileName, E>>);

impl<E> InMemEntries<E> {
    pub fn new() -> Self {
        Self(SpinNoPreempt::new(BTreeMap::new()))
    }

    pub fn read(&self) -> SpinNoPreemptGuard<'_, BTreeMap<FileName, E>> {
        self.0.lock()
    }

    pub fn write(&self) -> SpinNoPreemptGuard<'_, BTreeMap<FileName, E>> {
        self.0.lock()
    }
}

impl<E> Default for InMemEntries<E> {
    fn default() -> Self {
        Self::new()
    }
}

/// A generic in-memory directory container holding child entry maps.
#[derive(Default)]
pub struct InMemDir<E> {
    pub entries: InMemEntries<E>,
}

impl<E> InMemDir<E> {
    pub fn new() -> Self {
        Self {
            entries: InMemEntries::new(),
        }
    }
}

/// A generic in-memory inode representation containing metadata and dynamic node content.
pub struct InMemInode<C> {
    pub ino: u64,
    pub metadata: SpinNoPreempt<Metadata>,
    pub content: C,
}

impl<C> InMemInode<C> {
    pub fn new(ino: u64, metadata: Metadata, content: C) -> Self {
        Self {
            ino,
            metadata: SpinNoPreempt::new(metadata),
            content,
        }
    }
}

/// Standard helper to perform a directory read (for `read_dir`) from a locked entries map.
pub fn read_dir_impl<E, F>(
    entries: &InMemEntries<E>,
    offset: u64,
    sink: &mut dyn DirEntrySink,
    mut get_info: F,
) -> VfsResult<usize>
where
    F: FnMut(&E) -> (u64, NodeType),
{
    let entries_lock = entries.read();
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
