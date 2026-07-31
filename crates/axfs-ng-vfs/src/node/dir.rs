use alloc::{borrow::ToOwned, boxed::Box, string::String, sync::Arc, vec::Vec};
use core::{
    mem,
    ops::Deref,
    sync::atomic::{AtomicU64, Ordering},
};

use async_lock::{Mutex, MutexGuard};
use async_trait::async_trait;
use hashbrown::HashMap;

use super::DirEntry;
use crate::{
    MetadataUpdate, NodeOps, NodePermission, NodeType, VfsError, VfsResult,
    path::{DOT, DOTDOT, MAX_NAME_LEN, verify_entry_name},
};

/// A trait for a sink that can receive directory entries.
pub trait DirEntrySink {
    /// Accept a directory entry, returns `false` if the sink is full.
    ///
    /// `offset` is the offset of the next entry to be read.
    ///
    /// It's not recommended to operate on the node inside the `accept`
    /// function, since some filesystem may impose a lock while iterating the
    /// directory, and operating on the node may cause deadlock.
    fn accept(&mut self, name: &str, ino: u64, node_type: NodeType, offset: u64) -> bool;
}

impl<F: FnMut(&str, u64, NodeType, u64) -> bool> DirEntrySink for F {
    fn accept(&mut self, name: &str, ino: u64, node_type: NodeType, offset: u64) -> bool {
        self(name, ino, node_type, offset)
    }
}

type DirChildren = HashMap<String, DirEntry>;

#[async_trait]
pub trait DirNodeOps: NodeOps {
    /// Reads directory entries.
    ///
    /// Returns the number of entries read.
    ///
    /// Implementations should ensure that `.` and `..` are present in the
    /// result.
    async fn read_dir(&self, offset: u64, sink: &mut (dyn DirEntrySink + Send))
    -> VfsResult<usize>;

    /// Lookups a directory entry by name.
    async fn lookup(&self, name: &str) -> VfsResult<DirEntry>;

    /// Returns whether directory entries can be cached.
    ///
    /// Some filesystems (like '/proc') may not support caching directory
    /// entries, as they may change frequently or not be backed by persistent
    /// storage.
    ///
    /// If this returns `false`, the directory will not be cached in dentry and
    /// each call to [`DirNode::lookup`] will end up calling [`lookup`].
    /// Implementations should take care to handle cases where [`lookup`] is
    /// called multiple times for the same name.
    fn is_cacheable(&self) -> bool {
        true
    }

    /// Creates a directory entry.
    async fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry>;

    /// Creates a link to a node.
    async fn link(&self, name: &str, node: &DirEntry) -> VfsResult<DirEntry>;

    /// Unlinks a directory entry by name.
    ///
    /// If the entry is a non-empty directory, it should return `ENOTEMPTY`
    /// error.
    async fn unlink(&self, name: &str) -> VfsResult<()>;

    /// Renames a directory entry, replacing the original entry (dst) if it
    /// already exists.
    ///
    /// If src and dst link to the same file, this should do nothing and return
    /// `Ok(())`.
    ///
    /// The caller should ensure:
    /// - If `src` is a directory, `dst` must not exist or be an empty
    ///   directory.
    /// - If `src` is not a directory, `dst` must not exist or not be a
    ///   directory.
    async fn rename(&self, src_name: &str, dst_dir: &DirNode, dst_name: &str) -> VfsResult<()>;
}

/// Options for opening (or creating) a directory entry.
///
/// See [`DirNode::open_file`] for more details.
#[derive(Debug, Clone)]
pub struct OpenOptions {
    pub create: bool,
    pub create_new: bool,
    pub node_type: NodeType,
    pub permission: NodePermission,
    pub user: Option<(u32, u32)>, // (uid, gid)
}

impl Default for OpenOptions {
    fn default() -> Self {
        Self {
            create: false,
            create_new: false,
            node_type: NodeType::RegularFile,
            permission: NodePermission::default(),
            user: None,
        }
    }
}

pub struct DirNode {
    ops: Arc<dyn DirNodeOps>,
    cache: Mutex<DirChildren>,
    cache_generation: AtomicU64,
    mutation: Mutex<()>,
}

impl Deref for DirNode {
    type Target = dyn NodeOps;

    fn deref(&self) -> &Self::Target {
        &*self.ops
    }
}

impl From<DirNode> for Arc<dyn NodeOps> {
    fn from(node: DirNode) -> Self {
        node.ops.clone()
    }
}

impl DirNode {
    pub fn new(ops: Arc<dyn DirNodeOps>) -> Self {
        Self {
            ops,
            cache: Mutex::default(),
            cache_generation: AtomicU64::new(0),
            mutation: Mutex::new(()),
        }
    }

    pub fn inner(&self) -> &Arc<dyn DirNodeOps> {
        &self.ops
    }

    pub fn downcast<T: DirNodeOps>(&self) -> VfsResult<Arc<T>> {
        self.ops
            .clone()
            .into_any()
            .downcast()
            .map_err(|_| VfsError::InvalidInput)
    }

    async fn forget_entry(entry: Option<DirEntry>) {
        if let Some(entry) = entry
            && let Ok(dir) = entry.as_dir()
        {
            dir.forget().await;
        }
    }

    /// Looks up a directory entry by name.
    pub async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
        if name.len() > MAX_NAME_LEN {
            return Err(VfsError::NameTooLong);
        }
        if !self.ops.is_cacheable() {
            return self.ops.lookup(name).await;
        }

        let generation = {
            let children = self.cache.lock().await;
            if let Some(entry) = children.get(name) {
                return Ok(entry.clone());
            }
            self.cache_generation.load(Ordering::Acquire)
        };

        let entry = self.ops.lookup(name).await?;
        let mut children = self.cache.lock().await;
        if let Some(existing) = children.get(name) {
            return Ok(existing.clone());
        }
        if self.cache_generation.load(Ordering::Acquire) == generation {
            children.insert(name.to_owned(), entry.clone());
        }
        Ok(entry)
    }

    /// Looks up a directory entry by name in cache.
    pub async fn lookup_cache(&self, name: &str) -> Option<DirEntry> {
        if self.ops.is_cacheable() {
            self.cache.lock().await.get(name).cloned()
        } else {
            None
        }
    }

    /// Inserts a directory entry into the cache.
    pub async fn insert_cache(&self, name: String, entry: DirEntry) -> Option<DirEntry> {
        if self.ops.is_cacheable() {
            let mut children = self.cache.lock().await;
            self.cache_generation.fetch_add(1, Ordering::AcqRel);
            children.insert(name, entry)
        } else {
            None
        }
    }

    pub async fn read_dir(
        &self,
        offset: u64,
        sink: &mut (dyn DirEntrySink + Send),
    ) -> VfsResult<usize> {
        self.ops.read_dir(offset, sink).await
    }

    /// Creates a link to a node.
    pub async fn link(&self, name: &str, node: &DirEntry) -> VfsResult<DirEntry> {
        verify_entry_name(name)?;

        let _mutation = self.mutation.lock().await;
        let entry = self.ops.link(name, node).await?;
        let mut children = self.cache.lock().await;
        self.cache_generation.fetch_add(1, Ordering::AcqRel);
        children.insert(name.to_owned(), entry.clone());
        Ok(entry)
    }

    /// Unlinks a directory entry by name.
    pub async fn unlink(&self, name: &str, is_dir: bool) -> VfsResult<()> {
        verify_entry_name(name)?;

        let _mutation = self.mutation.lock().await;
        let entry = self.lookup(name).await?;
        match (entry.is_dir(), is_dir) {
            (true, false) => return Err(VfsError::IsADirectory),
            (false, true) => return Err(VfsError::NotADirectory),
            _ => {}
        }

        self.ops.unlink(name).await?;
        let mut children = self.cache.lock().await;
        self.cache_generation.fetch_add(1, Ordering::AcqRel);
        let removed = children.remove(name);
        drop(children);
        drop(_mutation);
        Self::forget_entry(removed).await;
        Ok(())
    }

    /// Returns whether the directory contains children.
    pub async fn has_children(&self) -> VfsResult<bool> {
        let mut has_children = false;
        self.read_dir(0, &mut |name: &str, _, _, _| {
            if name != DOT && name != DOTDOT {
                has_children = true;
                false
            } else {
                true
            }
        })
        .await?;
        Ok(has_children)
    }

    async fn create_unlocked(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        let entry = self.ops.create(name, node_type, permission).await?;
        let mut children = self.cache.lock().await;
        self.cache_generation.fetch_add(1, Ordering::AcqRel);
        children.insert(name.to_owned(), entry.clone());
        Ok(entry)
    }

    /// Creates a directory entry.
    pub async fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<DirEntry> {
        verify_entry_name(name)?;
        let _mutation = self.mutation.lock().await;
        self.create_unlocked(name, node_type, permission).await
    }

    async fn lock_both_mutations<'a>(
        &'a self,
        other: &'a Self,
    ) -> (MutexGuard<'a, ()>, Option<MutexGuard<'a, ()>>) {
        if core::ptr::eq(self, other) {
            return (self.mutation.lock().await, None);
        }

        if (self as *const Self as usize) < (other as *const Self as usize) {
            let first = self.mutation.lock().await;
            let second = other.mutation.lock().await;
            (first, Some(second))
        } else {
            let first = other.mutation.lock().await;
            let second = self.mutation.lock().await;
            (first, Some(second))
        }
    }

    /// Renames a directory entry.
    pub async fn rename(&self, src_name: &str, dst_dir: &Self, dst_name: &str) -> VfsResult<()> {
        verify_entry_name(src_name)?;
        verify_entry_name(dst_name)?;

        let (first_mutation, second_mutation) = self.lock_both_mutations(dst_dir).await;

        let src = self.lookup(src_name).await?;
        if let Ok(dst) = dst_dir.lookup(dst_name).await {
            if src.node_type() == NodeType::Directory {
                if let Ok(dir) = dst.as_dir()
                    && dir.has_children().await?
                {
                    return Err(VfsError::DirectoryNotEmpty);
                }
            } else if dst.node_type() == NodeType::Directory {
                return Err(VfsError::IsADirectory);
            }
        }
        self.ops.rename(src_name, dst_dir, dst_name).await?;
        let (src_entry, dst_entry) = if core::ptr::eq(self, dst_dir) {
            let mut children = self.cache.lock().await;
            self.cache_generation.fetch_add(1, Ordering::AcqRel);
            (children.remove(src_name), children.remove(dst_name))
        } else {
            let src_entry = {
                let mut children = self.cache.lock().await;
                self.cache_generation.fetch_add(1, Ordering::AcqRel);
                children.remove(src_name)
            };
            let dst_entry = {
                let mut children = dst_dir.cache.lock().await;
                dst_dir.cache_generation.fetch_add(1, Ordering::AcqRel);
                children.remove(dst_name)
            };
            (src_entry, dst_entry)
        };
        drop(second_mutation);
        drop(first_mutation);
        Self::forget_entry(src_entry).await;
        Self::forget_entry(dst_entry).await;
        Ok(())
    }

    /// Opens (or creates) a file in the directory.
    pub async fn open_file(&self, name: &str, options: &OpenOptions) -> VfsResult<DirEntry> {
        verify_entry_name(name)?;

        match self.lookup(name).await {
            Ok(val) => {
                if options.create_new {
                    return Err(VfsError::AlreadyExists);
                }
                return Ok(val);
            }
            Err(err) if err.canonicalize() == VfsError::NotFound && options.create => {}
            Err(err) => return Err(err),
        }
        let _mutation = self.mutation.lock().await;
        match self.lookup(name).await {
            Ok(val) => {
                if options.create_new {
                    return Err(VfsError::AlreadyExists);
                }
                return Ok(val);
            }
            Err(err) if err.canonicalize() == VfsError::NotFound => {}
            Err(err) => return Err(err),
        }
        let mut permission = options.permission;
        let mut user = options.user;
        if let Ok(parent_meta) = self.metadata().await {
            if parent_meta.mode.contains(NodePermission::SET_GID) {
                if options.node_type == NodeType::Directory {
                    permission |= NodePermission::SET_GID;
                }
                if let Some((uid, _)) = user {
                    user = Some((uid, parent_meta.gid));
                }
            }
        }
        let entry = self
            .create_unlocked(name, options.node_type, permission)
            .await?;
        if user.is_some() {
            entry
                .update_metadata(MetadataUpdate {
                    owner: user,
                    ..Default::default()
                })
                .await?;
        }
        Ok(entry)
    }

    /// Clears the cache of directory entries & user data, allowing them to be
    /// released.
    pub async fn forget(&self) {
        let mut pending: Vec<_> = {
            let mut guard = self.cache.lock().await;
            self.cache_generation.fetch_add(1, Ordering::AcqRel);
            mem::take(&mut *guard).into_values().collect()
        };

        while let Some(child) = pending.pop() {
            if let Ok(dir) = child.as_dir() {
                let descendants = {
                    let mut guard = dir.cache.lock().await;
                    dir.cache_generation.fetch_add(1, Ordering::AcqRel);
                    mem::take(&mut *guard)
                };
                pending.extend(descendants.into_values());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::task::Wake;
    use core::{
        any::Any,
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    use super::*;
    use crate::{FilesystemOps, Metadata, Reference};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
        let waker = Waker::from(Arc::new(NoopWake));
        future.poll(&mut Context::from_waker(&waker))
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = core::pin::pin!(future);
        loop {
            if let Poll::Ready(output) = poll_once(future.as_mut()) {
                return output;
            }
            core::hint::spin_loop();
        }
    }

    struct TestDir {
        inode: u64,
        pending_lookup: bool,
    }

    impl TestDir {
        fn ready(inode: u64) -> Self {
            Self {
                inode,
                pending_lookup: false,
            }
        }

        fn pending(inode: u64) -> Self {
            Self {
                inode,
                pending_lookup: true,
            }
        }
    }

    #[async_trait]
    impl NodeOps for TestDir {
        fn inode(&self) -> u64 {
            self.inode
        }

        async fn metadata(&self) -> VfsResult<Metadata> {
            Err(VfsError::Unsupported)
        }

        async fn update_metadata(&self, _update: MetadataUpdate) -> VfsResult<()> {
            Ok(())
        }

        fn filesystem(&self) -> &dyn FilesystemOps {
            panic!("not used by dentry cache tests")
        }

        async fn sync(&self, _data_only: bool) -> VfsResult<()> {
            Ok(())
        }

        fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    #[async_trait]
    impl DirNodeOps for TestDir {
        async fn read_dir(
            &self,
            _offset: u64,
            _sink: &mut (dyn DirEntrySink + Send),
        ) -> VfsResult<usize> {
            Err(VfsError::Unsupported)
        }

        async fn lookup(&self, _name: &str) -> VfsResult<DirEntry> {
            if self.pending_lookup {
                core::future::pending::<()>().await;
            }
            Err(VfsError::NotFound)
        }

        async fn create(
            &self,
            _name: &str,
            _node_type: NodeType,
            _permission: NodePermission,
        ) -> VfsResult<DirEntry> {
            Err(VfsError::Unsupported)
        }

        async fn link(&self, _name: &str, _node: &DirEntry) -> VfsResult<DirEntry> {
            Err(VfsError::Unsupported)
        }

        async fn unlink(&self, _name: &str) -> VfsResult<()> {
            Err(VfsError::Unsupported)
        }

        async fn rename(
            &self,
            _src_name: &str,
            _dst_dir: &DirNode,
            _dst_name: &str,
        ) -> VfsResult<()> {
            Err(VfsError::Unsupported)
        }
    }

    fn new_dir_entry(inode: u64) -> DirEntry {
        DirEntry::new_dir(
            |_| DirNode::new(Arc::new(TestDir::ready(inode))),
            Reference::root(),
        )
    }

    #[test]
    fn cache_access_waits_for_contended_lock() {
        let dir = DirNode::new(Arc::new(TestDir::ready(1)));
        let cached = new_dir_entry(2);
        let replacement = new_dir_entry(3);
        let mut guard = block_on(dir.cache.lock());
        guard.insert("child".into(), cached.clone());

        let mut lookup = core::pin::pin!(dir.lookup_cache("child"));
        assert!(poll_once(lookup.as_mut()).is_pending());
        drop(guard);
        assert_eq!(block_on(lookup.as_mut()), Some(cached.clone()));

        let guard = block_on(dir.cache.lock());
        let mut insert = core::pin::pin!(dir.insert_cache("child".into(), replacement));
        assert!(poll_once(insert.as_mut()).is_pending());
        drop(guard);
        assert_eq!(block_on(insert.as_mut()), Some(cached));
    }

    #[test]
    fn forget_waits_for_and_clears_contended_descendants() {
        let root = DirNode::new(Arc::new(TestDir::ready(1)));
        let child = new_dir_entry(2);
        let grandchild = new_dir_entry(3);
        block_on(root.insert_cache("child".into(), child.clone()));
        block_on(
            child
                .as_dir()
                .unwrap()
                .insert_cache("grandchild".into(), grandchild),
        );

        let child_dir = child.as_dir().unwrap();
        let child_guard = block_on(child_dir.cache.lock());
        let mut forget = core::pin::pin!(root.forget());
        assert!(poll_once(forget.as_mut()).is_pending());
        assert!(block_on(root.cache.lock()).is_empty());
        assert!(child_guard.contains_key("grandchild"));

        drop(child_guard);
        block_on(forget.as_mut());
        assert!(block_on(child_dir.cache.lock()).is_empty());
    }

    #[test]
    fn backend_lookup_does_not_hold_cache_lock_while_pending() {
        let dir = DirNode::new(Arc::new(TestDir::pending(1)));
        let mut lookup = core::pin::pin!(dir.lookup("slow"));
        assert!(poll_once(lookup.as_mut()).is_pending());

        let cached = new_dir_entry(2);
        let mut insert = core::pin::pin!(dir.insert_cache("other".into(), cached));
        assert!(matches!(poll_once(insert.as_mut()), Poll::Ready(None)));
    }
}
