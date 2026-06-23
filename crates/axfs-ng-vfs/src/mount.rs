use alloc::{
    string::String,
    sync::{Arc, Weak},
    vec,
    vec::Vec,
};
use core::{
    iter, mem,
    sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    task::Context,
};

use axpoll::{IoEvents, Pollable};
use hashbrown::HashMap;
use inherit_methods_macro::inherit_methods;

use crate::{
    DirEntry, DirEntrySink, Filesystem, FilesystemOps, Metadata, MetadataUpdate, Mutex, MutexGuard,
    NodeFlags, NodePermission, NodeType, OpenOptions, TypeMap, VfsError, VfsResult,
    path::{DOT, DOTDOT, PathBuf},
};

static DEVICE_COUNTER: AtomicU64 = AtomicU64::new(1);
static MOUNT_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
static PEER_GROUP_COUNTER: AtomicU64 = AtomicU64::new(1);

// ---------------------------------------------------------------------------
// Propagation types
// ---------------------------------------------------------------------------

/// Propagation mode of a mountpoint (mirrors Linux MS_SHARED/MS_SLAVE/…).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropagationMode {
    /// Default – no propagation.
    Private,
    /// Shared with a peer group.  New mounts under this mountpoint are cloned
    /// to all other members of `peer_group`.
    Shared { peer_group: u64 },
    /// Receives propagation from `master_group` but does not propagate back.
    Slave { master_group: u64 },
    /// Shared and also a slave (receives from master, propagates to own peer group).
    SharedAndSlave { peer_group: u64, master_group: u64 },
    /// Cannot be bind-mounted.
    Unbindable,
}

impl PropagationMode {
    pub fn is_shared(self) -> bool {
        matches!(self, PropagationMode::Shared { .. } | PropagationMode::SharedAndSlave { .. })
    }

    pub fn is_slave(self) -> bool {
        matches!(self, PropagationMode::Slave { .. } | PropagationMode::SharedAndSlave { .. })
    }

    pub fn peer_group(self) -> Option<u64> {
        match self {
            PropagationMode::Shared { peer_group } => Some(peer_group),
            PropagationMode::SharedAndSlave { peer_group, .. } => Some(peer_group),
            _ => None,
        }
    }

    pub fn master_group(self) -> Option<u64> {
        match self {
            PropagationMode::Slave { master_group } => Some(master_group),
            PropagationMode::SharedAndSlave { master_group, .. } => Some(master_group),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Global peer-group registry
// peer_group_id -> list of weak refs to all Mountpoints in that group
// ---------------------------------------------------------------------------

static PEER_GROUPS: Mutex<Option<HashMap<u64, Vec<Weak<Mountpoint>>>>> = Mutex::new(None);

fn with_peer_groups<R>(f: impl FnOnce(&mut HashMap<u64, Vec<Weak<Mountpoint>>>) -> R) -> R {
    let mut guard = PEER_GROUPS.lock();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn peer_group_add(peer_group: u64, mp: &Arc<Mountpoint>) {
    with_peer_groups(|groups| {
        let list = groups.entry(peer_group).or_default();
        if !list.iter().any(|w| w.upgrade().map_or(false, |m| Arc::ptr_eq(&m, mp))) {
            list.push(Arc::downgrade(mp));
        }
    });
}

fn peer_group_remove(peer_group: u64, mp: &Arc<Mountpoint>) {
    with_peer_groups(|groups| {
        if let Some(members) = groups.get_mut(&peer_group) {
            members.retain(|w| {
                w.upgrade()
                    .map_or(false, |m| !Arc::ptr_eq(&m, mp))
            });
            if members.is_empty() {
                groups.remove(&peer_group);
            }
        }
    });
}

fn add_to_registry(mp: &Arc<Mountpoint>, mode: PropagationMode) {
    match mode {
        PropagationMode::Shared { peer_group } => {
            peer_group_add(peer_group, mp);
        }
        PropagationMode::Slave { master_group } => {
            peer_group_add(master_group, mp);
        }
        PropagationMode::SharedAndSlave { peer_group, master_group } => {
            peer_group_add(peer_group, mp);
            if peer_group != master_group {
                peer_group_add(master_group, mp);
            }
        }
        _ => {}
    }
}

fn remove_from_registry(mp: &Arc<Mountpoint>, mode: PropagationMode) {
    match mode {
        PropagationMode::Shared { peer_group } => {
            peer_group_remove(peer_group, mp);
        }
        PropagationMode::Slave { master_group } => {
            peer_group_remove(master_group, mp);
        }
        PropagationMode::SharedAndSlave { peer_group, master_group } => {
            peer_group_remove(peer_group, mp);
            if peer_group != master_group {
                peer_group_remove(master_group, mp);
            }
        }
        _ => {}
    }
}

/// Collect all live Mountpoints in a peer group (excluding `exclude`).
fn peer_group_members(peer_group: u64, exclude: &Arc<Mountpoint>) -> Vec<Arc<Mountpoint>> {
    with_peer_groups(|groups| {
        groups
            .get(&peer_group)
            .map(|members| {
                members
                    .iter()
                    .filter_map(Weak::upgrade)
                    .filter(|m| {
                        !Arc::ptr_eq(m, exclude) &&
                        m.propagation().peer_group() == Some(peer_group)
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
}

fn collect_slaves_of_group_rec(
    groups: &HashMap<u64, Vec<Weak<Mountpoint>>>,
    peer_group: u64,
    result: &mut Vec<Arc<Mountpoint>>,
) {
    let direct_slaves: Vec<Arc<Mountpoint>> = groups
        .get(&peer_group)
        .map(|members| {
            members
                .iter()
                .filter_map(Weak::upgrade)
                .filter(|m| {
                    m.propagation().master_group() == Some(peer_group)
                })
                .collect()
        })
        .unwrap_or_default();

    for slave in direct_slaves {
        if !result.iter().any(|m| Arc::ptr_eq(m, &slave)) {
            result.push(slave.clone());
            if let Some(slave_pg) = slave.propagation().peer_group() {
                collect_slaves_of_group_rec(groups, slave_pg, result);
            }
        }
    }
}

/// All slave Mountpoints whose master_group == `peer_group` (including transitive slaves).
fn slaves_of_group(peer_group: u64) -> Vec<Arc<Mountpoint>> {
    let mut result = Vec::new();
    with_peer_groups(|groups| {
        collect_slaves_of_group_rec(groups, peer_group, &mut result);
    });
    result
}

fn peer_group_master(groups: &HashMap<u64, Vec<Weak<Mountpoint>>>, pg: u64) -> Option<u64> {
    groups.get(&pg).and_then(|members| {
        members.iter().filter_map(Weak::upgrade).find_map(|m| {
            m.propagation().master_group()
        })
    })
}

fn is_slave_of(peer_mp: &Arc<Mountpoint>, parent_pg: u64) -> bool {
    with_peer_groups(|groups| {
        let mut cur_master = peer_mp.propagation().master_group();
        let mut visited = Vec::new();
        while let Some(m_pg) = cur_master {
            if m_pg == parent_pg {
                return true;
            }
            if visited.contains(&m_pg) {
                break;
            }
            visited.push(m_pg);
            cur_master = peer_group_master(groups, m_pg);
        }
        false
    })
}

// ---------------------------------------------------------------------------
// Mountpoint
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Mountpoint {
    /// Root dir entry in the mountpoint.
    pub(crate) root: DirEntry,
    /// Location in the parent mountpoint.
    location: core::cell::UnsafeCell<Option<Location>>,
    /// Children of the mountpoint. (inode, fs_ptr) -> Mountpoint
    children: Mutex<HashMap<(u64, usize), Weak<Self>>>,
    /// Device ID
    device: u64,
    /// Unique mount ID (used for propagation bookkeeping)
    pub id: u64,
    /// Propagation mode
    pub(crate) propagation: Mutex<PropagationMode>,
    /// Read-only status
    pub(crate) read_only: AtomicBool,
    /// Mount flags
    pub(crate) flags: AtomicUsize,
}

unsafe impl Sync for Mountpoint {}
unsafe impl Send for Mountpoint {}

impl Mountpoint {
    pub fn new(fs: &Filesystem, location_in_parent: Option<Location>) -> Arc<Self> {
        let root = fs.root_dir();
        Arc::new(Self {
            root,
            location: core::cell::UnsafeCell::new(location_in_parent),
            children: Mutex::default(),
            device: DEVICE_COUNTER.fetch_add(1, Ordering::Relaxed),
            id: MOUNT_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            propagation: Mutex::new(PropagationMode::Private),
            read_only: AtomicBool::new(false),
            flags: AtomicUsize::new(0),
        })
    }

    pub fn new_root(fs: &Filesystem) -> Arc<Self> {
        Self::new(fs, None)
    }

    pub fn new_bind(source: Location, location_in_parent: Option<Location>) -> Arc<Self> {
        let root = source.entry().clone();
        let ro = source.mountpoint().is_readonly();
        let f = source.mountpoint().get_flags();
        Arc::new(Self {
            root,
            location: core::cell::UnsafeCell::new(location_in_parent),
            children: Mutex::default(),
            device: source.mountpoint().device(),
            id: MOUNT_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            propagation: Mutex::new(PropagationMode::Private),
            read_only: AtomicBool::new(ro),
            flags: AtomicUsize::new(f),
        })
    }

    pub fn root_location(self: &Arc<Self>) -> Location {
        Location::new(self.clone(), self.root.clone())
    }

    pub fn location(&self) -> Option<Location> {
        unsafe { &*self.location.get() }.clone()
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn is_root(&self) -> bool {
        unsafe { &*self.location.get() }.is_none()
    }

    pub fn propagation(&self) -> PropagationMode {
        *self.propagation.lock()
    }

    pub fn is_readonly(&self) -> bool {
        self.read_only.load(Ordering::Acquire)
    }

    pub fn set_readonly(&self, ro: bool) {
        self.read_only.store(ro, Ordering::Release);
    }

    pub fn get_flags(&self) -> usize {
        self.flags.load(Ordering::Acquire)
    }

    pub fn set_flags(&self, flags: usize) {
        self.flags.store(flags, Ordering::Release);
    }

    /// See [`Location::resolve_mountpoint`].
    pub(crate) fn effective_mountpoint(self: &Arc<Self>) -> Arc<Self> {
        let mut current = self.clone();
        let mut visited = vec![self.id];
        loop {
            let next = {
                let children = current.children.lock();
                children.get(&Location::entry_key(&current.root)).and_then(Weak::upgrade)
            };
            if let Some(mount) = next {
                if visited.contains(&mount.id) {
                    break;
                }
                visited.push(mount.id);
                current = mount;
            } else {
                break;
            }
        }
        current
    }



    /// Make this mountpoint shared (allocate new peer group).
    /// Returns the new peer_group id.
    pub fn make_shared(self: &Arc<Self>) -> u64 {
        let mut prop = self.propagation.lock();
        let old_mode = *prop;
        match old_mode {
            PropagationMode::Shared { peer_group } => {
                peer_group
            }
            PropagationMode::SharedAndSlave { peer_group, .. } => {
                peer_group
            }
            PropagationMode::Slave { master_group } => {
                let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let new_mode = PropagationMode::SharedAndSlave { peer_group: pg, master_group };
                *prop = new_mode;
                drop(prop);
                remove_from_registry(self, old_mode);
                add_to_registry(self, new_mode);
                pg
            }
            _ => {
                let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                let new_mode = PropagationMode::Shared { peer_group: pg };
                *prop = new_mode;
                drop(prop);
                remove_from_registry(self, old_mode);
                add_to_registry(self, new_mode);
                pg
            }
        }
    }

    /// Safely changes the propagation mode and updates the global PEER_GROUPS registry.
    pub fn change_propagation(self: &Arc<Self>, new_mode: PropagationMode) {
        let mut prop = self.propagation.lock();
        let old_mode = *prop;
        if old_mode == new_mode {
            return;
        }
        *prop = new_mode;
        drop(prop);

        remove_from_registry(self, old_mode);
        add_to_registry(self, new_mode);
    }

    /// Make this mountpoint a slave of its current peer group.
    pub fn make_slave(self: &Arc<Self>) {
        let mut prop = self.propagation.lock();
        let old_mode = *prop;
        match old_mode {
            PropagationMode::Shared { peer_group } => {
                let new_mode = PropagationMode::Slave { master_group: peer_group };
                *prop = new_mode;
                drop(prop);
                remove_from_registry(self, old_mode);
                add_to_registry(self, new_mode);
            }
            PropagationMode::SharedAndSlave { peer_group, master_group } => {
                let _ = master_group;
                let new_mode = PropagationMode::Slave { master_group: peer_group };
                *prop = new_mode;
                drop(prop);
                remove_from_registry(self, old_mode);
                add_to_registry(self, new_mode);
            }
            PropagationMode::Slave { .. } => {}
            _ => {
                let new_mode = PropagationMode::Private;
                *prop = new_mode;
                drop(prop);
                remove_from_registry(self, old_mode);
                add_to_registry(self, new_mode);
            }
        }
    }

    /// Make this mountpoint private.
    pub fn make_private(self: &Arc<Self>) {
        self.change_propagation(PropagationMode::Private);
    }

    /// Make this mountpoint unbindable.
    pub fn make_unbindable(self: &Arc<Self>) {
        self.change_propagation(PropagationMode::Unbindable);
    }

    /// Apply `make_shared` recursively to this mountpoint and all descendants.
    pub fn make_rshared(self: &Arc<Self>) {
        self.make_shared();
        let children: Vec<_> = self
            .children
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for child in children {
            child.make_rshared();
        }
    }

    /// Apply `make_slave` recursively to this mountpoint and all descendants.
    pub fn make_rslave(self: &Arc<Self>) {
        self.make_slave();
        let children: Vec<_> = self
            .children
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for child in children {
            child.make_rslave();
        }
    }

    /// Apply `make_private` recursively.
    pub fn make_rprivate(self: &Arc<Self>) {
        self.make_private();
        let children: Vec<_> = self
            .children
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for child in children {
            child.make_rprivate();
        }
    }

    /// Apply `make_unbindable` recursively.
    pub fn make_runbindable(self: &Arc<Self>) {
        self.make_unbindable();
        let children: Vec<_> = self
            .children
            .lock()
            .values()
            .filter_map(Weak::upgrade)
            .collect();
        for child in children {
            child.make_runbindable();
        }
    }
}

fn is_mount_ancestor_of(mp1: &Arc<Mountpoint>, mp2: &Arc<Mountpoint>) -> bool {
    if Arc::ptr_eq(mp1, mp2) {
        return false;
    }
    let mut cur = mp2.clone();
    let mut visited = vec![mp2.id];
    loop {
        let next = cur.location().map(|loc| loc.mountpoint().clone());
        if let Some(next_mp) = next {
            if Arc::ptr_eq(mp1, &next_mp) {
                return true;
            }
            if visited.contains(&next_mp.id) {
                break;
            }
            visited.push(next_mp.id);
            cur = next_mp;
        } else {
            break;
        }
    }
    false
}


// ---------------------------------------------------------------------------
// Location
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Location {
    mountpoint: Arc<Mountpoint>,
    entry: DirEntry,
}

impl PartialEq for Location {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.mountpoint, &other.mountpoint) && self.entry == other.entry
    }
}

impl Eq for Location {}

#[inherit_methods(from = "self.entry")]
impl Location {
    pub fn inode(&self) -> u64;

    pub fn filesystem(&self) -> &dyn FilesystemOps;

    pub fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()>;

    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> VfsResult<u64>;

    pub fn sync(&self, data_only: bool) -> VfsResult<()>;

    pub fn is_file(&self) -> bool;

    pub fn is_dir(&self) -> bool;

    pub fn node_type(&self) -> NodeType;

    pub fn read_link(&self) -> VfsResult<String>;

    pub fn ioctl(&self, cmd: u32, arg: usize) -> VfsResult<usize>;

    pub fn flags(&self) -> NodeFlags;

    pub fn user_data(&self) -> MutexGuard<'_, TypeMap>;
}

impl Location {
    pub fn new(mountpoint: Arc<Mountpoint>, entry: DirEntry) -> Self {
        Self { mountpoint, entry }
    }

    fn wrap(&self, entry: DirEntry) -> Self {
        Self::new(self.mountpoint.clone(), entry)
    }

    pub fn mountpoint(&self) -> &Arc<Mountpoint> {
        &self.mountpoint
    }

    pub fn entry(&self) -> &DirEntry {
        &self.entry
    }

    pub fn name(&self) -> &str {
        if self.is_root_of_mount() {
            unsafe { &*self.mountpoint.location.get() }
                .as_ref()
                .map_or("", Location::name)
        } else {
            self.entry.name()
        }
    }

    pub fn parent(&self) -> Option<Self> {
        if !self.is_root_of_mount() {
            return self.entry.parent().map(|parent| self.wrap(parent));
        }
        self.mountpoint.location()?.parent()
    }

    pub fn is_root(&self) -> bool {
        self.mountpoint.is_root() && self.is_root_of_mount()
    }

    pub fn is_root_of_mount(&self) -> bool {
        self.entry.inode() == self.mountpoint.root.inode() &&
            core::ptr::eq(
                self.entry.filesystem() as *const _ as *const (),
                self.mountpoint.root.filesystem() as *const _ as *const ()
            )
    }

    pub fn check_is_dir(&self) -> VfsResult<()> {
        self.entry.as_dir().map(|_| ())
    }

    pub fn check_is_file(&self) -> VfsResult<()> {
        self.entry.as_file().map(|_| ())
    }

    pub fn metadata(&self) -> VfsResult<Metadata> {
        let mut metadata = self.entry.metadata()?;
        metadata.device = self.mountpoint.device();
        Ok(metadata)
    }

    pub fn absolute_path(&self) -> VfsResult<PathBuf> {
        let mut components = vec![];
        let mut cur = self.clone();
        loop {
            let mut entry = cur.entry.clone();
            while !entry.ptr_eq(&cur.mountpoint.root) {
                components.push(String::from(entry.name()));
                if let Some(parent) = entry.parent() {
                    entry = parent;
                } else {
                    break;
                }
            }
            cur = match cur.mountpoint.location() {
                Some(loc) => loc,
                None => break,
            }
        }
        Ok(iter::once("/")
            .chain(components.iter().map(String::as_str).rev())
            .collect())
    }

    pub(crate) fn entry_key(entry: &DirEntry) -> (u64, usize) {
        (
            entry.inode(),
            entry.filesystem() as *const _ as *const () as usize,
        )
    }

    /// Public alias of `entry_key` for use from other crates.
    pub fn pub_entry_key(entry: &DirEntry) -> (u64, usize) {
        Self::entry_key(entry)
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.mountpoint, &other.mountpoint) && self.entry.ptr_eq(&other.entry)
    }

    pub fn is_mountpoint(&self) -> bool {
        self.mountpoint
            .children
            .lock()
            .contains_key(&Self::entry_key(&self.entry))
    }

    /// See [`Mountpoint::effective_mountpoint`].
    fn resolve_mountpoint(self) -> Self {
        self
    }

    fn resolve_mounted_child(&self, entry: &DirEntry) -> Option<Self> {
        let mountpoint = self
            .mountpoint
            .children
            .lock()
            .get(&Self::entry_key(entry))
            .and_then(Weak::upgrade)?;
        let mountpoint = mountpoint.effective_mountpoint();
        let entry = mountpoint.root.clone();
        Some(Self::new(mountpoint, entry))
    }

    fn resolve_mounted_location(self) -> Self {
        if let Some(mount) = self.resolve_mounted_child(&self.entry) {
            return mount;
        }
        self.resolve_mountpoint()
    }

    pub fn lookup_no_follow(&self, name: &str) -> VfsResult<Self> {
        Ok(match name {
            DOT => self.clone(),
            DOTDOT => self.parent().unwrap_or_else(|| self.clone()),
            _ => {
                let loc = Self::new(self.mountpoint.clone(), self.entry.as_dir()?.lookup(name)?);
                loc.resolve_mounted_location()
            }
        })
    }

    pub fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<Self> {
        self.entry
            .as_dir()?
            .create(name, node_type, permission)
            .map(|entry| self.wrap(entry))
    }

    pub fn link(&self, name: &str, node: &Self) -> VfsResult<Self> {
        if !Arc::ptr_eq(&self.mountpoint, &node.mountpoint) {
            return Err(VfsError::CrossesDevices);
        }
        self.entry
            .as_dir()?
            .link(name, &node.entry)
            .map(|entry| self.wrap(entry))
    }

    pub fn rename(&self, src_name: &str, dst_dir: &Self, dst_name: &str) -> VfsResult<()> {
        if !Arc::ptr_eq(&self.mountpoint, &dst_dir.mountpoint) {
            return Err(VfsError::CrossesDevices);
        }
        if !self.ptr_eq(dst_dir) && self.entry.is_ancestor_of(&dst_dir.entry)? {
            return Err(VfsError::InvalidInput);
        }
        self.entry
            .as_dir()?
            .rename(src_name, dst_dir.entry.as_dir()?, dst_name)
    }

    pub fn unlink(&self, name: &str, is_dir: bool) -> VfsResult<()> {
        self.entry.as_dir()?.unlink(name, is_dir)
    }

    pub fn open_file(&self, name: &str, options: &OpenOptions) -> VfsResult<Location> {
        self.entry
            .as_dir()?
            .open_file(name, options)
            .map(|entry| self.wrap(entry).resolve_mounted_location())
    }

    pub fn read_dir(&self, offset: u64, sink: &mut dyn DirEntrySink) -> VfsResult<usize> {
        let loc = self.clone().resolve_mounted_location();
        loc.entry.as_dir()?.read_dir(offset, sink)
    }

    // -----------------------------------------------------------------------
    // Mount / unmount
    // -----------------------------------------------------------------------

    pub fn mount(&self, fs: &Filesystem) -> VfsResult<Arc<Mountpoint>> {
        self.entry.as_dir()?;
        let entry_key = Self::entry_key(&self.entry);
        let mut children = self.mountpoint.children.lock();
        if let Some(weak) = children.get(&entry_key) {
            if weak.upgrade().is_some() {
                return Err(VfsError::ResourceBusy);
            }
        }
        let result = Mountpoint::new(fs, Some(self.clone()));

        let dst_parent_prop = *self.mountpoint().propagation.lock();
        if dst_parent_prop.is_shared() {
            let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
            *result.propagation.lock() = PropagationMode::Shared { peer_group: pg };
            peer_group_add(pg, &result);
        }

        children.insert(entry_key, Arc::downgrade(&result));
        Ok(result)
    }

    /// Bind-mount `source` onto this location.
    ///
    /// Returns `Err(VfsError::PermissionDenied)` if `source` is Unbindable.
    pub fn mount_bind(&self, source: Location) -> VfsResult<Arc<Mountpoint>> {
        // Check unbindable: walk up to the effective root of source's mountpoint.
        {
            let src_root_mp = source.mountpoint().clone();
            let prop = *src_root_mp.propagation.lock();
            if prop == PropagationMode::Unbindable {
                return Err(VfsError::PermissionDenied);
            }
        }

        self.entry.as_dir()?;

        let src_prop = if source.is_root_of_mount() {
            *source.mountpoint().propagation.lock()
        } else {
            if let Some(_pg) = source.mountpoint().propagation().peer_group() {
                let is_descendant = self.entry.ptr_eq(&source.entry)
                    || (self.entry.inode() == source.entry.inode() && core::ptr::eq(
                        self.entry.filesystem() as *const _ as *const (),
                        source.entry.filesystem() as *const _ as *const ()
                    ))
                    || self.entry.is_ancestor_of(&source.entry).unwrap_or(false)
                    || source.entry.is_ancestor_of(&self.entry).unwrap_or(false);
                if is_descendant {
                    PropagationMode::Private
                } else {
                    *source.mountpoint().propagation.lock()
                }
            } else {
                PropagationMode::Private
            }
        };
        let dst_parent_prop = *self.mountpoint().propagation.lock();
        let final_prop = match src_prop {
            PropagationMode::Shared { peer_group } => PropagationMode::Shared { peer_group },
            PropagationMode::SharedAndSlave { peer_group, master_group } => {
                PropagationMode::SharedAndSlave { peer_group, master_group }
            }
            PropagationMode::Slave { master_group } => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::SharedAndSlave { peer_group: pg, master_group }
                } else {
                    PropagationMode::Slave { master_group }
                }
            }
            _ => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::Shared { peer_group: pg }
                } else {
                    src_prop
                }
            }
        };

        let entry_key = Self::entry_key(&self.entry);
        let mut children = self.mountpoint.children.lock();
        if let Some(weak) = children.get(&entry_key) {
            if weak.upgrade().is_some() {
                return Err(VfsError::ResourceBusy);
            }
        }

        let result = Mountpoint::new_bind(source, Some(self.clone()));

        result.change_propagation(final_prop);

        children.insert(entry_key, Arc::downgrade(&result));
        Ok(result)
    }

    pub fn unmount(&self) -> VfsResult<()> {
        if !self.is_root_of_mount() {
            return Err(VfsError::InvalidInput);
        }
        let children = self.mountpoint.children.lock();
        if !children.is_empty() {
            log::warn!("unmount: mount ID {} at {:?} is busy. Children keys: {:?}", self.mountpoint.id, self.entry, children.keys());
            return Err(VfsError::ResourceBusy);
        }
        drop(children);
        // Clean up peer group registration.
        {
            let prop = *self.mountpoint.propagation.lock();
            remove_from_registry(&self.mountpoint, prop);
        }
        self.entry.as_dir()?.forget();
        if let Some(parent_loc) = self.mountpoint.location() {
            parent_loc
                .mountpoint
                .children
                .lock()
                .remove(&Self::entry_key(&parent_loc.entry));
        }
        Ok(())
    }

    pub fn unmount_all(&self) -> VfsResult<()> {
        if !self.is_root_of_mount() {
            return Err(VfsError::InvalidInput);
        }
        let children = mem::take(&mut *self.mountpoint.children.lock());
        for (_, child) in children {
            if let Some(child) = child.upgrade() {
                child.root_location().unmount_all()?;
            }
        }
        self.unmount()
    }

    // -----------------------------------------------------------------------
    // Move mount: detach from current parent, reattach under new_parent/name.
    // -----------------------------------------------------------------------

    /// Move this mount (which must be a mountpoint root) to `new_parent`.
    /// The directory `new_parent` must be empty of any existing mount.
    pub fn move_mount(&self, new_parent: &Location) -> VfsResult<Arc<Mountpoint>> {
        if !self.is_root_of_mount() {
            return Err(VfsError::InvalidInput);
        }
        new_parent.entry.as_dir()?;
        let mp = &self.mountpoint;

        // Check target is not already a mount
        let new_entry_key = Self::entry_key(&new_parent.entry);
        {
            let new_parent_children = new_parent.mountpoint.children.lock();
            if let Some(weak) = new_parent_children.get(&new_entry_key) {
                if weak.upgrade().is_some() {
                    return Err(VfsError::ResourceBusy);
                }
            }
        }

        // Detach from old parent.
        if let Some(old_parent_loc) = mp.location() {
            old_parent_loc
                .mountpoint
                .children
                .lock()
                .remove(&Self::entry_key(&old_parent_loc.entry));
        }

        // Update location of the original mountpoint in-place.
        unsafe {
            *mp.location.get() = Some(new_parent.clone());
        }

        // Attach to new parent.
        new_parent
            .mountpoint
            .children
            .lock()
            .insert(new_entry_key, Arc::downgrade(mp));

        // Update propagation mode after move.
        let dst_parent_prop = *new_parent.mountpoint.propagation.lock();
        let src_prop = *mp.propagation.lock();
        let final_prop = match src_prop {
            PropagationMode::Shared { peer_group } => PropagationMode::Shared { peer_group },
            PropagationMode::SharedAndSlave { peer_group, master_group } => {
                PropagationMode::SharedAndSlave { peer_group, master_group }
            }
            _ => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::Shared { peer_group: pg }
                } else {
                    src_prop
                }
            }
        };
        mp.change_propagation(final_prop);

        Ok(mp.clone())
    }
}

// ---------------------------------------------------------------------------
// Propagation helper used by sys_mount
// ---------------------------------------------------------------------------

/// Find all peer parent mountpoints of `mp`'s parent mountpoint and collect
/// child mountpoints mounted at the same location.
fn propagated_propagation_mode(
    parent_mp: &Arc<Mountpoint>,
    peer_mp: &Arc<Mountpoint>,
    new_mp: &Arc<Mountpoint>,
) -> PropagationMode {
    let parent_pg = parent_mp.propagation().peer_group();

    let is_peer = parent_pg.is_some() && parent_pg == peer_mp.propagation().peer_group();
    let is_slave = parent_pg.map_or(false, |pg| is_slave_of(peer_mp, pg));

    if is_peer {
        // Peer: copy propagation mode exactly.
        *new_mp.propagation.lock()
    } else if is_slave {
        // Slave: master group of shadow_mp is new_mp's peer group (if new_mp is shared).
        if let Some(new_pg) = new_mp.propagation().peer_group() {
            if peer_mp.propagation().is_shared() {
                let shadow_pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                PropagationMode::SharedAndSlave {
                    peer_group: shadow_pg,
                    master_group: new_pg,
                }
            } else {
                PropagationMode::Slave { master_group: new_pg }
            }
        } else {
            // If new_mp is not shared, it has no peer group to be a master of.
            if peer_mp.propagation().is_shared() {
                let shadow_pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                PropagationMode::Shared { peer_group: shadow_pg }
            } else {
                PropagationMode::Private
            }
        }
    } else {
        // Fallback
        *new_mp.propagation.lock()
    }
}

fn collect_propagate_unmount_rec(
    parent_mp: &Arc<Mountpoint>,
    entry_key: &(u64, usize),
    result: &mut Vec<Arc<Mountpoint>>,
) {
    let mut targets = Vec::new();
    let prop = *parent_mp.propagation.lock();
    if let Some(peer_group) = prop.peer_group() {
        targets.extend(peer_group_members(peer_group, parent_mp));
        targets.extend(slaves_of_group(peer_group));
    }

    for peer_parent_mp in targets {
        let peer_child = {
            let children = peer_parent_mp.children.lock();
            children.get(entry_key).and_then(Weak::upgrade)
        };
        if let Some(peer_child_mp) = peer_child {
            if !result.iter().any(|m| Arc::ptr_eq(m, &peer_child_mp)) {
                result.push(peer_child_mp);
                collect_propagate_unmount_rec(&peer_parent_mp, entry_key, result);
            }
        }
    }
}

pub fn collect_propagate_unmount(mp: &Arc<Mountpoint>) -> Vec<Arc<Mountpoint>> {
    let mut result = Vec::new();
    let Some(loc) = mp.location() else {
        return result;
    };
    let parent_mp = loc.mountpoint();
    let entry_key = Location::entry_key(loc.entry());
    collect_propagate_unmount_rec(parent_mp, &entry_key, &mut result);

    // Exclude the target mountpoint itself from peer unmount propagation
    result.retain(|m| !Arc::ptr_eq(m, mp));

    // Sort so that descendant/child mounts are unmounted before their ancestors/parents
    result.sort_by(|a, b| {
        if is_mount_ancestor_of(a, b) {
            core::cmp::Ordering::Greater
        } else if is_mount_ancestor_of(b, a) {
            core::cmp::Ordering::Less
        } else {
            core::cmp::Ordering::Equal
        }
    });

    result
}

fn propagate_to_slaves(
    parent_mp: &Arc<Mountpoint>,
    mount_loc_entry: &DirEntry,
    source: Option<Location>,
    new_mp: &Arc<Mountpoint>,
    created: &mut Vec<(Arc<Mountpoint>, Arc<Mountpoint>)>,
) {
    let prop = *parent_mp.propagation.lock();
    let Some(peer_group) = prop.peer_group() else {
        return;
    };

    let slaves = slaves_of_group(peer_group);
    for slave_mp in slaves {
        if Arc::ptr_eq(&slave_mp, new_mp)
            || is_mount_ancestor_of(&slave_mp, new_mp)
            || is_mount_ancestor_of(new_mp, &slave_mp)
        {
            continue;
        }

        if created.iter().any(|(p, _)| Arc::ptr_eq(p, &slave_mp)) {
            continue;
        }

        let is_reachable = slave_mp.root == *mount_loc_entry
            || slave_mp.root.is_ancestor_of(mount_loc_entry).unwrap_or(false);

        if !is_reachable {
            continue;
        }

        let peer_loc = Location::new(slave_mp.clone(), mount_loc_entry.clone()).resolve_mounted_location();

        let shadow_mp = match &source {
            Some(src_loc) => {
                match peer_loc.mount_bind_silent(src_loc.clone()) {
                    Ok(mp) => mp,
                    Err(_) => continue,
                }
            }
            None => {
                let root_loc = new_mp.root_location();
                match peer_loc.mount_bind_silent(root_loc) {
                    Ok(mp) => mp,
                    Err(_) => continue,
                }
            }
        };

        if Arc::ptr_eq(&shadow_mp, new_mp) {
            continue;
        }

        let shadow_prop = propagated_propagation_mode(parent_mp, &slave_mp, new_mp);
        shadow_mp.change_propagation(shadow_prop);

        let mut sub_created = Vec::new();
        propagate_subtree(new_mp, &shadow_mp, &mut sub_created);

        created.push((slave_mp.clone(), shadow_mp.clone()));
        created.extend(sub_created);

        // Recursively propagate to the slaves of slave_mp
        let source_to_use = source.clone().unwrap_or_else(|| new_mp.root_location());
        propagate_to_slaves(
            &slave_mp,
            mount_loc_entry,
            Some(source_to_use),
            &shadow_mp,
            created,
        );
    }
}

// ---------------------------------------------------------------------------

pub fn propagate_subtree(
    src_mp: &Arc<Mountpoint>,
    dst_mp: &Arc<Mountpoint>,
    collected: &mut Vec<(Arc<Mountpoint>, Arc<Mountpoint>)>,
) {
    let children: Vec<((u64, usize), Arc<Mountpoint>)> = {
        let guard = src_mp.children.lock();
        guard
            .iter()
            .filter_map(|(key, weak)| weak.upgrade().map(|mp| (*key, mp)))
            .collect()
    };

    for (_key, child_mp) in children {
        if Arc::ptr_eq(&child_mp, dst_mp)
            || is_mount_ancestor_of(&child_mp, dst_mp)
            || is_mount_ancestor_of(dst_mp, &child_mp)
        {
            continue;
        }

        let Some(child_loc) = child_mp.location() else {
            continue;
        };

        let is_reachable = dst_mp.root == child_loc.entry
            || dst_mp.root.is_ancestor_of(&child_loc.entry).unwrap_or(false);
        if !is_reachable {
            continue;
        }

        let dst_child_loc = Location::new(dst_mp.clone(), child_loc.entry.clone()).resolve_mounted_location();

        let Ok(shadow_child_mp) = dst_child_loc.mount_bind_silent(child_mp.root_location()) else {
            continue;
        };

        if Arc::ptr_eq(&shadow_child_mp, &child_mp) {
            continue;
        }

        // Calculate correct propagation mode
        let shadow_prop = propagated_propagation_mode(src_mp, dst_mp, &child_mp);
        shadow_child_mp.change_propagation(shadow_prop);

        collected.push((dst_mp.clone(), shadow_child_mp.clone()));

        propagate_subtree(&child_mp, &shadow_child_mp, collected);

        // Propagate recursively to all slaves of dst_mp
        propagate_to_slaves(
            dst_mp,
            &child_loc.entry,
            Some(child_mp.root_location()),
            &shadow_child_mp,
            collected,
        );
    }
}

pub fn propagate_new_mount(
    parent_mp: &Arc<Mountpoint>,
    _mount_entry_key: (u64, usize),
    source: Option<Location>,
    new_mp: &Arc<Mountpoint>,
) -> Vec<(Arc<Mountpoint>, Arc<Mountpoint>)> {
    // Peers / slaves to propagate to.
    let mut targets: Vec<Arc<Mountpoint>> = Vec::new();

    let prop = *parent_mp.propagation.lock();
    if let Some(peer_group) = prop.peer_group() {
        // Propagate to all other peers.
        targets.extend(peer_group_members(peer_group, parent_mp));
        // Also propagate to slaves of this group.
        targets.extend(slaves_of_group(peer_group));
    }

    let mut created: Vec<(Arc<Mountpoint>, Arc<Mountpoint>)> = Vec::new();

    for peer_mp in targets {
        if Arc::ptr_eq(&peer_mp, new_mp)
            || is_mount_ancestor_of(&peer_mp, new_mp)
            || is_mount_ancestor_of(new_mp, &peer_mp)
        {
            continue;
        }

        if created.iter().any(|(p, _)| Arc::ptr_eq(p, &peer_mp)) {
            continue;
        }

        // Find the destination entry (mount_loc.entry) reachable within the peer.
        let mount_loc = match new_mp.location() {
            Some(loc) => loc,
            None => continue,
        };

        let is_reachable = peer_mp.root == mount_loc.entry
            || peer_mp.root.is_ancestor_of(&mount_loc.entry).unwrap_or(false);

        if !is_reachable {
            continue;
        }

        let peer_loc = Location::new(peer_mp.clone(), mount_loc.entry.clone()).resolve_mounted_location();

        // Create a shadow mount at peer_loc.
        let shadow_mp = match &source {
            Some(src_loc) => {
                // Bind: clone the source location.
                match peer_loc.mount_bind_silent(src_loc.clone()) {
                    Ok(mp) => mp,
                    Err(_) => continue,
                }
            }
            None => {
                // Real FS: share the same filesystem.
                // Create a new bind pointing to new_mp's root.
                let root_loc = new_mp.root_location();
                match peer_loc.mount_bind_silent(root_loc) {
                    Ok(mp) => mp,
                    Err(_) => continue,
                }
            }
        };

        if Arc::ptr_eq(&shadow_mp, new_mp) {
            continue;
        }

        // Calculate correct propagation mode
        let shadow_prop = propagated_propagation_mode(parent_mp, &peer_mp, new_mp);
        shadow_mp.change_propagation(shadow_prop);

        let mut sub_created = Vec::new();
        propagate_subtree(new_mp, &shadow_mp, &mut sub_created);

        created.push((peer_mp.clone(), shadow_mp.clone()));
        created.extend(sub_created);

        // Propagate recursively to all slaves of peer_mp
        let source_to_use = source.clone().unwrap_or_else(|| new_mp.root_location());
        propagate_to_slaves(
            &peer_mp,
            &mount_loc.entry,
            Some(source_to_use),
            &shadow_mp,
            &mut created,
        );
    }

    created
}

impl Location {
    /// Like `mount_bind` but skips the unbindable check (for internal propagation).
    fn mount_bind_silent(&self, source: Location) -> VfsResult<Arc<Mountpoint>> {
        let entry_key = Self::entry_key(&self.entry);
        let mut children = self.mountpoint.children.lock();
        if let Some(weak) = children.get(&entry_key) {
            if let Some(existing) = weak.upgrade() {
                return Ok(existing);
            }
        }
        let src_prop = if source.is_root_of_mount() {
            *source.mountpoint().propagation.lock()
        } else {
            if let Some(_pg) = source.mountpoint().propagation().peer_group() {
                let is_descendant = self.entry.ptr_eq(&source.entry)
                    || (self.entry.inode() == source.entry.inode() && core::ptr::eq(
                        self.entry.filesystem() as *const _ as *const (),
                        source.entry.filesystem() as *const _ as *const ()
                    ))
                    || self.entry.is_ancestor_of(&source.entry).unwrap_or(false)
                    || source.entry.is_ancestor_of(&self.entry).unwrap_or(false);
                if is_descendant {
                    PropagationMode::Private
                } else {
                    *source.mountpoint().propagation.lock()
                }
            } else {
                PropagationMode::Private
            }
        };
        let dst_parent_prop = *self.mountpoint().propagation.lock();
        let final_prop = match src_prop {
            PropagationMode::Shared { peer_group } => PropagationMode::Shared { peer_group },
            PropagationMode::SharedAndSlave { peer_group, master_group } => {
                PropagationMode::SharedAndSlave { peer_group, master_group }
            }
            PropagationMode::Slave { master_group } => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::SharedAndSlave { peer_group: pg, master_group }
                } else {
                    PropagationMode::Slave { master_group }
                }
            }
            _ => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::Shared { peer_group: pg }
                } else {
                    src_prop
                }
            }
        };

        let result = Mountpoint::new_bind(source, Some(self.clone()));

        result.change_propagation(final_prop);

        children.insert(entry_key, Arc::downgrade(&result));
        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Pollable impl
// ---------------------------------------------------------------------------

#[inherit_methods(from = "self.entry")]
impl Pollable for Location {
    fn poll(&self) -> IoEvents;

    fn register(&self, context: &mut Context<'_>, events: IoEvents);
}
