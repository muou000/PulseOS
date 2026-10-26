use alloc::{
    borrow::Cow,
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
use hashbrown::{HashMap, HashSet};
use inherit_methods_macro::inherit_methods;
use kspin::SpinNoPreempt;

use crate::{
    DirEntry, DirEntrySink, Filesystem, FilesystemOps, Metadata, MetadataUpdate,
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

static PEER_GROUPS: SpinNoPreempt<Option<HashMap<u64, Vec<Weak<Mountpoint>>>>> =
    SpinNoPreempt::new(None);

fn with_peer_groups_read<R>(f: impl FnOnce(&HashMap<u64, Vec<Weak<Mountpoint>>>) -> R) -> R {
    let guard = PEER_GROUPS.lock();
    if let Some(map) = guard.as_ref() {
        f(map)
    } else {
        let empty = HashMap::new();
        f(&empty)
    }
}

fn with_peer_groups_write<R>(f: impl FnOnce(&mut HashMap<u64, Vec<Weak<Mountpoint>>>) -> R) -> R {
    let mut guard = PEER_GROUPS.lock();
    let map = guard.get_or_insert_with(HashMap::new);
    f(map)
}

fn peer_group_add(peer_group: u64, mp: &Arc<Mountpoint>) {
    with_peer_groups_write(|groups| {
        let list = groups.entry(peer_group).or_default();
        if !list.iter().any(|w| w.upgrade().map_or(false, |m| Arc::ptr_eq(&m, mp))) {
            list.push(Arc::downgrade(mp));
        }
    });
}

fn peer_group_remove(peer_group: u64, mp: &Arc<Mountpoint>) {
    with_peer_groups_write(|groups| {
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
    with_peer_groups_read(|groups| {
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
    with_peer_groups_read(|groups| {
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
    with_peer_groups_read(|groups| {
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
// Unified mount-topology synchronization protocol
// ---------------------------------------------------------------------------
//
// Protocol summary:
// 1. All reads and writes of per-mountpoint topology state (`Mountpoint::topology`:
//    parent attachment link and mounted-children registry) are mediated by a
//    single preemption-safe reader-writer lock (`topology_sync::MOUNT_TOPOLOGY_LOCK`).
// 2. Readers acquire `TopologyReadGuard` via `topology_sync::lock_topology_read()`,
//    allowing concurrent multi-CPU path resolution, root checks, parent/path
//    traversals, and subtree snapshots to observe an atomic topology state.
// 3. Writers (`mount`, `mount_bind`, `mount_bind_silent`, `unmount`,
//    `unmount_all`, `move_mount`) acquire `TopologyWriteGuard` via
//    `topology_sync::lock_topology_write()`, updating parent links and child
//    registries together as a single indivisible topology transition.
// 4. Lock-ordering & non-reentrancy rule: `MOUNT_TOPOLOGY_LOCK` is a strict leaf
//    lock. Callers must never acquire `MOUNT_TOPOLOGY_LOCK` reentrantly, must
//    never acquire `Mountpoint::propagation`, `PEER_GROUPS`, or filesystem node
//    locks while holding it, must compute `NodeOps`-derived entry keys outside
//    it, and must defer dropping detached `Location` / `Mountpoint` values until
//    after the topology guard is released.
// 5. `Mountpoint::has_children` provides a lock-free negative fast path: writers
//    update `has_children` under `TopologyWriteGuard` with `Ordering::Release`
//    (setting `new_parent` to `true` before clearing `old_parent` to `false` on
//    moves), and lock-free probes read it with `Ordering::Acquire` before
//    falling back to `TopologyReadGuard` when `true`.

mod topology_sync {
    use core::{cell::UnsafeCell, fmt, marker::PhantomData};

    use kernel_guard::NoPreempt;
    use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};

    static MOUNT_TOPOLOGY_LOCK: RwLock<()> = RwLock::new(());

    /// Interior-mutable cell whose contents may only be accessed while holding a
    /// [`TopologyReadGuard`] or [`TopologyWriteGuard`] for `MOUNT_TOPOLOGY_LOCK`.
    pub(super) struct TopologyCell<T> {
        // Safety invariant: `value` is initialized at construction and valid for
        // the lifetime of `self`. Shared access (`&T`) occurs only while
        // `MOUNT_TOPOLOGY_LOCK` is held in read or write mode with no active
        // `&mut TopologyWriteGuard` borrow; exclusive access (`&mut T`) occurs
        // only while `MOUNT_TOPOLOGY_LOCK` is held in write mode via an
        // exclusive `&mut TopologyWriteGuard` borrow.
        value: UnsafeCell<T>,
    }

    impl<T> TopologyCell<T> {
        pub(super) const fn new(value: T) -> Self {
            Self {
                value: UnsafeCell::new(value),
            }
        }
    }

    impl<T> fmt::Debug for TopologyCell<T> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("TopologyCell").finish_non_exhaustive()
        }
    }

    /// Preemption-disabled shared read token for [`MOUNT_TOPOLOGY_LOCK`].
    pub(super) struct TopologyReadGuard {
        // Safety invariant: `_guard` holds a shared read lock on
        // `MOUNT_TOPOLOGY_LOCK` for the lifetime of `self`. Fields drop in
        // declaration order, releasing `_guard` before re-enabling preemption.
        _guard: RwLockReadGuard<'static, ()>,
        _preempt: NoPreempt,
        _not_send_sync: PhantomData<*const ()>,
    }

    /// Preemption-disabled exclusive write token for [`MOUNT_TOPOLOGY_LOCK`].
    pub(super) struct TopologyWriteGuard {
        // Safety invariant: `_guard` holds the unique write lock on
        // `MOUNT_TOPOLOGY_LOCK` for the lifetime of `self`. Fields drop in
        // declaration order, releasing `_guard` before re-enabling preemption.
        _guard: RwLockWriteGuard<'static, ()>,
        _preempt: NoPreempt,
        _not_send_sync: PhantomData<*const ()>,
    }

    pub(super) fn lock_topology_read() -> TopologyReadGuard {
        let preempt = NoPreempt::new();
        let guard = MOUNT_TOPOLOGY_LOCK.read();
        TopologyReadGuard {
            _guard: guard,
            _preempt: preempt,
            _not_send_sync: PhantomData,
        }
    }

    pub(super) fn lock_topology_write() -> TopologyWriteGuard {
        let preempt = NoPreempt::new();
        let guard = MOUNT_TOPOLOGY_LOCK.write();
        TopologyWriteGuard {
            _guard: guard,
            _preempt: preempt,
            _not_send_sync: PhantomData,
        }
    }

    impl TopologyReadGuard {
        pub(super) fn get<'a, T>(&'a self, cell: &'a TopologyCell<T>) -> &'a T {
            // SAFETY:
            // Operation: shared-reference dereference `&*cell.value.get()`.
            // Required contract (Rust Reference, pointer-to-reference conversion
            // and `UnsafeCell::get`): `cell.value.get()` must be non-null,
            // aligned, dereferenceable for `size_of::<T>()`, point to an
            // initialized `T`, and have no concurrent write or live `&mut T`
            // alias for the entire lifetime `'a`.
            // Evidence:
            // - Type/initialization fact: `cell: &'a TopologyCell<T>` borrows a
            //   live, initialized `TopologyCell<T>` for `'a`, so `cell.value.get()`
            //   is non-null, aligned, dereferenceable, and initialized for `'a`.
            // - Dependency lemma (`spin::RwLock::read`) + `TopologyReadGuard`
            //   field invariant: while `self._guard` is alive (at least `'a`
            //   because `self` is borrowed for `'a`, or forever if forgotten),
            //   no thread can hold `RwLockWriteGuard` on `MOUNT_TOPOLOGY_LOCK`.
            // - Module invariant (`TopologyCell::value`): exclusive `&mut T`
            //   references and writes to `*cell.value.get()` are created solely
            //   through `TopologyWriteGuard::get_mut`, which cannot exist while
            //   `self._guard` is held.
            unsafe { &*cell.value.get() }
        }
    }

    impl TopologyWriteGuard {
        pub(super) fn get<'a, T>(&'a self, cell: &'a TopologyCell<T>) -> &'a T {
            // SAFETY:
            // Operation: shared-reference dereference `&*cell.value.get()`.
            // Required contract: `cell.value.get()` must be non-null, aligned,
            // dereferenceable, point to an initialized `T`, and have no
            // concurrent write or live `&mut T` alias for `'a`.
            // Evidence:
            // - Type/initialization fact: `cell: &'a TopologyCell<T>` guarantees
            //   liveness, alignment, and initialization of `T` for `'a`.
            // - Dependency lemma (`spin::RwLock::write`) + `TopologyWriteGuard`
            //   field invariant: `self._guard` holds the unique write lock on
            //   `MOUNT_TOPOLOGY_LOCK`, excluding all other `TopologyReadGuard`
            //   and `TopologyWriteGuard` instances across all threads for `'a`.
            // - Borrow-checker fact: `&'a self` prevents calling
            //   `TopologyWriteGuard::get_mut(&mut self, ...)` for the entire
            //   lifetime `'a`, so no `&mut T` alias exists on this thread either.
            unsafe { &*cell.value.get() }
        }

        pub(super) fn get_mut<'a, T>(&'a mut self, cell: &'a TopologyCell<T>) -> &'a mut T {
            // SAFETY:
            // Operation: mutable-reference dereference `&mut *cell.value.get()`.
            // Required contract: `cell.value.get()` must be non-null, aligned,
            // dereferenceable, point to an initialized `T`, and have unique,
            // unaliased access (no other `&T`, `&mut T`, or raw-pointer access)
            // for the entire lifetime `'a`.
            // Evidence:
            // - Type/initialization fact: `cell: &'a TopologyCell<T>` guarantees
            //   liveness, alignment, and initialization of `T` for `'a`.
            // - Dependency lemma (`spin::RwLock::write`) + `TopologyWriteGuard`
            //   field invariant: `self._guard` holds the unique write lock on
            //   `MOUNT_TOPOLOGY_LOCK`, excluding all other `TopologyReadGuard`
            //   and `TopologyWriteGuard` instances across all threads for `'a`.
            // - Borrow-checker fact: `&'a mut self` exclusively borrows this
            //   sole `TopologyWriteGuard` for `'a`, statically preventing any
            //   overlapping `self.get(...)` or `self.get_mut(...)` call (even on
            //   the same `TopologyCell<T>`) for the entire lifetime `'a`.
            unsafe { &mut *cell.value.get() }
        }
    }
}

#[derive(Debug)]
struct ParentLink {
    location: Location,
    entry_key: (u64, usize),
}

#[derive(Debug)]
enum MountAttachment {
    /// Root of a mount tree (created without a parent mount location).
    Root,
    /// Attached at `ParentLink` inside `ParentLink::location.mountpoint`.
    Attached(ParentLink),
    /// Unmounted and detached from the mount tree.
    Detached,
}

#[derive(Debug)]
struct MountTopology {
    attachment: MountAttachment,
    children: HashMap<(u64, usize), Weak<Mountpoint>>,
}

impl MountTopology {
    fn from_initial_parent(location_in_parent: Option<Location>) -> Self {
        let attachment = match location_in_parent {
            Some(location) => {
                let entry_key = Location::entry_key(&location.entry);
                MountAttachment::Attached(ParentLink {
                    location,
                    entry_key,
                })
            }
            None => MountAttachment::Root,
        };
        Self {
            attachment,
            children: HashMap::new(),
        }
    }

    fn parent_link(&self) -> Option<&ParentLink> {
        match &self.attachment {
            MountAttachment::Attached(link) => Some(link),
            MountAttachment::Root | MountAttachment::Detached => None,
        }
    }

    fn parent_location(&self) -> Option<&Location> {
        self.parent_link().map(|link| &link.location)
    }
}

// ---------------------------------------------------------------------------
// Mountpoint
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct Mountpoint {
    /// Root dir entry in the mountpoint.
    pub(crate) root: DirEntry,
    /// Cached `Location::entry_key(&self.root)` so topology lock holders never
    /// invoke `NodeOps` trait methods on `root`.
    root_key: (u64, usize),
    // Safety invariant: `topology` (holding `MountTopology { attachment, children }`)
    // is accessed exclusively via `topology_sync::{TopologyReadGuard, TopologyWriteGuard}`
    // under `MOUNT_TOPOLOGY_LOCK`. All topology transitions maintain:
    // (a) bidirectional parent/child consistency: for every mount registered in
    //     a parent's `children[&k]` with `strong_count() > 0`, its `attachment`
    //     is `Attached(ParentLink { location, entry_key: k })` with
    //     `Arc::ptr_eq(&location.mountpoint, &parent)` and `parent` is not
    //     `Detached`; `Root` and `Detached` mounts have no live parent entry;
    // (b) acyclicity: following `ParentLink` pointers never visits the same
    //     `Mountpoint` twice.
    topology: topology_sync::TopologyCell<MountTopology>,
    // Safety invariant: `has_children` is mutated only while holding
    // `TopologyWriteGuard` using `Ordering::Release`, and is `true` whenever
    // `topology.children` contains at least one live child (`strong_count() > 0`).
    // Lock-free negative probes read `has_children` with `Ordering::Acquire`.
    pub(crate) has_children: AtomicBool,
    /// Device ID
    device: u64,
    /// Unique mount ID (used for propagation bookkeeping)
    pub id: u64,
    /// Propagation mode
    pub(crate) propagation: SpinNoPreempt<PropagationMode>,
    /// Read-only status
    pub(crate) read_only: AtomicBool,
    /// Mount flags
    pub(crate) flags: AtomicUsize,
}

const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn verify_constituent_fields() {
        assert_send_sync::<DirEntry>();
        assert_send_sync::<(u64, usize)>();
        assert_send_sync::<MountTopology>();
        assert_send_sync::<AtomicBool>();
        assert_send_sync::<u64>();
        assert_send_sync::<SpinNoPreempt<PropagationMode>>();
        assert_send_sync::<AtomicUsize>();
    }
    let _ = verify_constituent_fields;
};

// SAFETY:
// Operation: manual `Send` implementation for `Mountpoint`.
// Required contract (`core::marker::Send`): transferring ownership of a
// `Mountpoint` (or dropping it via the last `Arc<Mountpoint>` on another thread)
// must not cause data races or violate thread-locality invariants of its fields.
// Evidence:
// - Protected state: `Mountpoint::topology` (`TopologyCell<MountTopology>`) and
//   its companion fast-path flag `Mountpoint::has_children` (`AtomicBool`).
// - Compile-time type fact (`verify_constituent_fields` above): `MountTopology`
//   and every sibling field (`DirEntry`, `(u64, usize)`, `AtomicBool`, `u64`,
//   `SpinNoPreempt<PropagationMode>`, `AtomicUsize`) implement `Send + Sync`.
// - Ownership/synchronization fact: moving or dropping an owned `Mountpoint`
//   requires unique ownership (`Arc::drop` runs `Mountpoint`'s destructor only
//   after an `Acquire`/`Release` atomic decrement from the last strong owner
//   with no live `&Mountpoint` references), so no concurrent `TopologyReadGuard`
//   or `TopologyWriteGuard` access to `self.topology` can race with transfer or
//   destruction.
unsafe impl Send for Mountpoint {}

// SAFETY:
// Operation: manual `Sync` implementation for `Mountpoint`.
// Required contract (`core::marker::Sync`): concurrent shared-reference
// (`&Mountpoint`) access across multiple threads must not cause data races or
// create aliasing violations on any field.
// Evidence:
// - Protected state & invariant: `Mountpoint::topology` (`TopologyCell<MountTopology>`,
//   containing parent `MountAttachment` and child `HashMap<(u64, usize), Weak<Mountpoint>>`)
//   is only read via `TopologyReadGuard::get` / `TopologyWriteGuard::get` and
//   only mutated via `TopologyWriteGuard::get_mut`, all synchronized by the
//   single `MOUNT_TOPOLOGY_LOCK` (`spin::RwLock<()>` with `NoPreempt`).
// - Dependency lemma (`spin::RwLock`): `RwLock::read` and `RwLock::write`
//   establish happens-before (`Acquire`/`Release`) ordering between exclusive
//   writers and shared readers, preventing read/write and write/write data races
//   on `MountTopology`.
// - Compile-time type fact (`verify_constituent_fields` above): `MountTopology`
//   implements `Send + Sync` (so concurrent `&MountTopology` reads across
//   multiple `TopologyReadGuard` holders are data-race-free), and every other
//   field of `Mountpoint` (`root`, `root_key`, `has_children`, `device`, `id`,
//   `propagation`, `read_only`, `flags`) implements `Sync`.
unsafe impl Sync for Mountpoint {}

fn effective_mountpoint_locked(
    start: Arc<Mountpoint>,
    guard: &topology_sync::TopologyReadGuard,
    deferred_drops: &mut Vec<Arc<Mountpoint>>,
) -> Arc<Mountpoint> {
    let mut current = start;
    let mut visited = vec![current.id];
    while let Some(next) = guard
        .get(&current.topology)
        .children
        .get(&current.root_key)
        .and_then(Weak::upgrade)
    {
        if visited.contains(&next.id) {
            deferred_drops.push(next);
            break;
        }
        visited.push(next.id);
        let prev = mem::replace(&mut current, next);
        deferred_drops.push(prev);
    }
    current
}

impl Mountpoint {
    pub fn new(fs: &Filesystem, location_in_parent: Option<Location>) -> Arc<Self> {
        Self::new_with_propagation(fs, location_in_parent, PropagationMode::Private)
    }

    fn new_with_propagation(
        fs: &Filesystem,
        location_in_parent: Option<Location>,
        propagation: PropagationMode,
    ) -> Arc<Self> {
        let root = fs.root_dir();
        let root_key = Location::entry_key(&root);
        Arc::new(Self {
            root,
            root_key,
            topology: topology_sync::TopologyCell::new(MountTopology::from_initial_parent(
                location_in_parent,
            )),
            has_children: AtomicBool::new(false),
            device: DEVICE_COUNTER.fetch_add(1, Ordering::Relaxed),
            id: MOUNT_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            propagation: SpinNoPreempt::new(propagation),
            read_only: AtomicBool::new(false),
            flags: AtomicUsize::new(0),
        })
    }

    pub fn new_root(fs: &Filesystem) -> Arc<Self> {
        Self::new(fs, None)
    }

    pub fn new_bind(source: Location, location_in_parent: Option<Location>) -> Arc<Self> {
        Self::new_bind_with_propagation(source, location_in_parent, PropagationMode::Private)
    }

    fn new_bind_with_propagation(
        source: Location,
        location_in_parent: Option<Location>,
        propagation: PropagationMode,
    ) -> Arc<Self> {
        let root = source.entry().clone();
        let root_key = Location::entry_key(&root);
        let ro = source.mountpoint().is_readonly();
        let f = source.mountpoint().get_flags();
        let device = source.mountpoint().device();
        Arc::new(Self {
            root,
            root_key,
            topology: topology_sync::TopologyCell::new(MountTopology::from_initial_parent(
                location_in_parent,
            )),
            has_children: AtomicBool::new(false),
            device,
            id: MOUNT_ID_COUNTER.fetch_add(1, Ordering::Relaxed),
            propagation: SpinNoPreempt::new(propagation),
            read_only: AtomicBool::new(ro),
            flags: AtomicUsize::new(f),
        })
    }

    pub fn root_location(self: &Arc<Self>) -> Location {
        Location::new(self.clone(), self.root.clone())
    }

    /// Snapshot this mountpoint and all currently attached descendants.
    ///
    /// `unmount_all` detaches children before recursively unmounting them, so
    /// callers that maintain a parallel registry must take this snapshot
    /// before starting that operation.  Mount topology is expected to be a
    /// tree; the visited set keeps a malformed/stale graph from looping.
    pub fn collect_subtree(self: &Arc<Self>) -> Vec<Arc<Self>> {
        let mut result = Vec::new();
        let mut stack = Vec::new();
        let mut batch = Vec::new();
        let mut visited = HashSet::new();
        let mut deferred_drops = Vec::new();
        {
            let guard = topology_sync::lock_topology_read();
            visited.insert(self.id);
            result.push(self.clone());
            stack.push(0usize);
            while let Some(idx) = stack.pop() {
                for weak in guard.get(&result[idx].topology).children.values() {
                    if let Some(child) = weak.upgrade() {
                        if visited.insert(child.id) {
                            batch.push(child);
                        } else {
                            deferred_drops.push(child);
                        }
                    }
                }
                let start_len = result.len();
                result.append(&mut batch);
                for child_idx in start_len..result.len() {
                    stack.push(child_idx);
                }
            }
        }
        drop(deferred_drops);
        result
    }

    pub fn location(&self) -> Option<Location> {
        let guard = topology_sync::lock_topology_read();
        let loc = guard.get(&self.topology).parent_location().cloned();
        drop(guard);
        loc
    }

    pub fn device(&self) -> u64 {
        self.device
    }

    pub fn is_root(&self) -> bool {
        let guard = topology_sync::lock_topology_read();
        matches!(guard.get(&self.topology).attachment, MountAttachment::Root)
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
        for mp in self.collect_subtree() {
            mp.make_shared();
        }
    }

    /// Apply `make_slave` recursively to this mountpoint and all descendants.
    pub fn make_rslave(self: &Arc<Self>) {
        for mp in self.collect_subtree() {
            mp.make_slave();
        }
    }

    /// Apply `make_private` recursively.
    pub fn make_rprivate(self: &Arc<Self>) {
        for mp in self.collect_subtree() {
            mp.make_private();
        }
    }

    /// Apply `make_unbindable` recursively.
    pub fn make_runbindable(self: &Arc<Self>) {
        for mp in self.collect_subtree() {
            mp.make_unbindable();
        }
    }
}

fn is_mount_ancestor_of_with<'a>(
    mp1: &Arc<Mountpoint>,
    mp2: &'a Arc<Mountpoint>,
    mut get_topology: impl FnMut(&'a Mountpoint) -> &'a MountTopology,
) -> bool {
    if Arc::ptr_eq(mp1, mp2) {
        return false;
    }
    let mut cur: &'a Mountpoint = mp2;
    let mut slow: &'a Mountpoint = mp2;
    let mut advance_slow = false;
    while let Some(parent_link) = get_topology(cur).parent_link() {
        let next_mp = &parent_link.location.mountpoint;
        if Arc::ptr_eq(mp1, next_mp) {
            return true;
        }
        cur = next_mp;
        if advance_slow {
            if let Some(slow_link) = get_topology(slow).parent_link() {
                slow = &slow_link.location.mountpoint;
            }
            if core::ptr::eq(cur, slow) {
                break;
            }
        }
        advance_slow = !advance_slow;
    }
    false
}

fn is_mount_ancestor_of(mp1: &Arc<Mountpoint>, mp2: &Arc<Mountpoint>) -> bool {
    let guard = topology_sync::lock_topology_read();
    is_mount_ancestor_of_with(mp1, mp2, |mp| guard.get(&mp.topology))
}

/// Walk up through any mount-root stacking chain under `guard` until reaching
/// the underlying non-root mountpoint [`Location`], or `None` if `mp` is a
/// root or detached mount.
fn underlying_mount_location<'a>(
    mp: &'a Mountpoint,
    guard: &'a topology_sync::TopologyReadGuard,
) -> Option<&'a Location> {
    let mut cur = mp;
    let mut slow = mp;
    let mut advance_slow = false;
    loop {
        let parent = guard.get(&cur.topology).parent_link()?;
        let loc = &parent.location;
        if parent.entry_key != loc.mountpoint.root_key {
            return Some(loc);
        }
        cur = &loc.mountpoint;
        if advance_slow {
            if let Some(slow_parent) = guard.get(&slow.topology).parent_link() {
                slow = &slow_parent.location.mountpoint;
            }
            if core::ptr::eq(cur, slow) {
                return None;
            }
        }
        advance_slow = !advance_slow;
    }
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

impl Location {
    pub fn inode(&self) -> u64 {
        self.entry.inode()
    }

    pub fn filesystem(&self) -> &dyn FilesystemOps {
        self.entry.filesystem()
    }

    pub async fn update_metadata(&self, update: MetadataUpdate) -> VfsResult<()> {
        self.entry.update_metadata(update).await
    }

    #[allow(clippy::len_without_is_empty)]
    pub async fn len(&self) -> VfsResult<u64> {
        self.entry.len().await
    }

    pub async fn sync(&self, data_only: bool) -> VfsResult<()> {
        self.entry.sync(data_only).await
    }

    pub fn is_file(&self) -> bool {
        self.entry.is_file()
    }

    pub fn is_dir(&self) -> bool {
        self.entry.is_dir()
    }

    pub fn node_type(&self) -> NodeType {
        self.entry.node_type()
    }

    pub async fn read_link(&self) -> VfsResult<String> {
        self.entry.read_link().await
    }

    pub async fn ioctl(&self, cmd: u32, arg: usize) -> VfsResult<usize> {
        self.entry.ioctl(cmd, arg).await
    }

    pub fn flags(&self) -> NodeFlags {
        self.entry.flags()
    }

    pub fn user_data(&self) -> kspin::SpinNoPreemptGuard<'_, TypeMap> {
        self.entry.user_data()
    }
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

    pub fn name(&self) -> Cow<'_, str> {
        if !self.is_root_of_mount() {
            return Cow::Borrowed(self.entry.name());
        }
        let guard = topology_sync::lock_topology_read();
        let name = underlying_mount_location(&self.mountpoint, &guard)
            .map(|loc| String::from(loc.entry.name()));
        drop(guard);
        match name {
            Some(owned) => Cow::Owned(owned),
            None => Cow::Borrowed(""),
        }
    }

    pub fn parent(&self) -> Option<Self> {
        if !self.is_root_of_mount() {
            return self.entry.parent().map(|parent| self.wrap(parent));
        }
        let guard = topology_sync::lock_topology_read();
        let parent = underlying_mount_location(&self.mountpoint, &guard)
            .and_then(|loc| loc.entry.parent().map(|parent| loc.wrap(parent)));
        drop(guard);
        parent
    }

    /// Atomically snapshot both the parent [`Location`] and this entry's name
    /// in that parent directory under one topology read critical section.
    pub fn parent_and_name(&self) -> Option<(Self, Cow<'_, str>)> {
        if !self.is_root_of_mount() {
            let parent = self.entry.parent().map(|parent| self.wrap(parent))?;
            return Some((parent, Cow::Borrowed(self.entry.name())));
        }
        let guard = topology_sync::lock_topology_read();
        let snapshot = underlying_mount_location(&self.mountpoint, &guard).and_then(|loc| {
            let parent = loc.entry.parent().map(|parent| loc.wrap(parent))?;
            let name = Cow::Owned(String::from(loc.entry.name()));
            Some((parent, name))
        });
        drop(guard);
        snapshot
    }

    pub fn is_root(&self) -> bool {
        self.is_root_of_mount() && self.mountpoint.is_root()
    }

    pub fn is_root_of_mount(&self) -> bool {
        Self::entry_key(&self.entry) == self.mountpoint.root_key
    }

    pub fn check_is_dir(&self) -> VfsResult<()> {
        self.entry.as_dir().map(|_| ())
    }

    pub fn check_is_file(&self) -> VfsResult<()> {
        self.entry.as_file().map(|_| ())
    }

    pub async fn metadata(&self) -> VfsResult<Metadata> {
        let mut metadata = self.entry.metadata().await?;
        metadata.device = self.mountpoint.device();
        Ok(metadata)
    }

    pub fn absolute_path(&self) -> VfsResult<PathBuf> {
        let mut components = vec![];
        let mut kept_entries: Vec<DirEntry> = Vec::new();
        {
            let guard = topology_sync::lock_topology_read();
            let mut cur_mp: &Mountpoint = &self.mountpoint;
            let mut cur_entry: &DirEntry = &self.entry;
            let mut slow_mp: &Mountpoint = &self.mountpoint;
            let mut advance_slow = false;
            loop {
                let mut entry: &DirEntry = cur_entry;
                while !entry.ptr_eq(&cur_mp.root) {
                    components.push(String::from(entry.name()));
                    if let Some(parent) = entry.parent() {
                        kept_entries.push(parent);
                        entry = kept_entries.last().unwrap();
                    } else {
                        break;
                    }
                }
                let Some(parent_link) = guard.get(&cur_mp.topology).parent_link() else {
                    break;
                };
                cur_mp = &parent_link.location.mountpoint;
                cur_entry = &parent_link.location.entry;
                if advance_slow {
                    if let Some(slow_link) = guard.get(&slow_mp.topology).parent_link() {
                        slow_mp = &slow_link.location.mountpoint;
                    }
                    if core::ptr::eq(cur_mp, slow_mp) {
                        break;
                    }
                }
                advance_slow = !advance_slow;
            }
        }
        drop(kept_entries);
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
        if !self.mountpoint.has_children.load(Ordering::Acquire) {
            return false;
        }
        let key = Self::entry_key(&self.entry);
        let guard = topology_sync::lock_topology_read();
        guard
            .get(&self.mountpoint.topology)
            .children
            .get(&key)
            .is_some_and(|weak| weak.strong_count() > 0)
    }

    /// Identity pass-through; stacked mount resolution happens in
    /// [`Location::resolve_mounted_child`] via [`effective_mountpoint_locked`].
    fn resolve_mountpoint(self) -> Self {
        self
    }

    fn resolve_mounted_child(&self, entry: &DirEntry) -> Option<Self> {
        if !self.mountpoint.has_children.load(Ordering::Acquire) {
            return None;
        }
        let entry_key = Self::entry_key(entry);
        let mut deferred_drops = Vec::new();
        let effective = {
            let guard = topology_sync::lock_topology_read();
            let first = guard
                .get(&self.mountpoint.topology)
                .children
                .get(&entry_key)
                .and_then(Weak::upgrade);
            first.map(|mp| effective_mountpoint_locked(mp, &guard, &mut deferred_drops))
        };
        drop(deferred_drops);
        let mountpoint = effective?;
        let root_entry = mountpoint.root.clone();
        Some(Self::new(mountpoint, root_entry))
    }

    fn resolve_mounted_location(self) -> Self {
        if let Some(mount) = self.resolve_mounted_child(&self.entry) {
            return mount;
        }
        self.resolve_mountpoint()
    }

    pub async fn lookup_no_follow(&self, name: &str) -> VfsResult<Self> {
        Ok(match name {
            DOT => self.clone(),
            DOTDOT => self.parent().unwrap_or_else(|| self.clone()),
            _ => {
                let loc = Self::new(self.mountpoint.clone(), self.entry.as_dir()?.lookup(name).await?);
                loc.resolve_mounted_location()
            }
        })
    }

    pub async fn create(
        &self,
        name: &str,
        node_type: NodeType,
        permission: NodePermission,
    ) -> VfsResult<Self> {
        self.entry
            .as_dir()?
            .create(name, node_type, permission)
            .await
            .map(|entry| self.wrap(entry))
    }

    pub async fn link(&self, name: &str, node: &Self) -> VfsResult<Self> {
        if !Arc::ptr_eq(&self.mountpoint, &node.mountpoint) {
            return Err(VfsError::CrossesDevices);
        }
        self.entry
            .as_dir()?
            .link(name, &node.entry)
            .await
            .map(|entry| self.wrap(entry))
    }

    pub async fn rename(&self, src_name: &str, dst_dir: &Self, dst_name: &str) -> VfsResult<()> {
        if !Arc::ptr_eq(&self.mountpoint, &dst_dir.mountpoint) {
            return Err(VfsError::CrossesDevices);
        }
        if !self.ptr_eq(dst_dir) && self.entry.is_ancestor_of(&dst_dir.entry)? {
            return Err(VfsError::InvalidInput);
        }
        self.entry
            .as_dir()?
            .rename(src_name, dst_dir.entry.as_dir()?, dst_name)
            .await
    }

    pub async fn unlink(&self, name: &str, is_dir: bool) -> VfsResult<()> {
        self.entry.as_dir()?.unlink(name, is_dir).await
    }

    pub async fn open_file(&self, name: &str, options: &OpenOptions) -> VfsResult<Location> {
        let dir = self.entry.as_dir()?;
        dir.open_file(name, options)
            .await
            .map(|entry| self.wrap(entry).resolve_mounted_location())
    }

    pub async fn read_dir(&self, offset: u64, sink: &mut (dyn DirEntrySink + Send)) -> VfsResult<usize> {
        let loc = self.clone().resolve_mounted_location();
        loc.entry.as_dir()?.read_dir(offset, sink).await
    }

    // -----------------------------------------------------------------------
    // Mount / unmount
    // -----------------------------------------------------------------------

    pub fn mount(&self, fs: &Filesystem) -> VfsResult<Arc<Mountpoint>> {
        self.entry.as_dir()?;
        let entry_key = Self::entry_key(&self.entry);
        let dst_parent_prop = *self.mountpoint().propagation.lock();
        let initial_prop = if dst_parent_prop.is_shared() {
            let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
            PropagationMode::Shared { peer_group: pg }
        } else {
            PropagationMode::Private
        };

        let candidate = Mountpoint::new_with_propagation(fs, Some(self.clone()), initial_prop);
        let candidate_weak = Arc::downgrade(&candidate);
        let mut stale_weak = None;
        let attach_result = {
            let mut guard = topology_sync::lock_topology_write();
            if matches!(
                guard.get(&self.mountpoint.topology).attachment,
                MountAttachment::Detached
            ) {
                Err(VfsError::InvalidInput)
            } else if guard
                .get(&self.mountpoint.topology)
                .children
                .get(&entry_key)
                .is_some_and(|weak| weak.strong_count() > 0)
            {
                Err(VfsError::ResourceBusy)
            } else {
                let children = &mut guard.get_mut(&self.mountpoint.topology).children;
                children.reserve(1);
                stale_weak = children.insert(entry_key, candidate_weak);
                self.mountpoint.has_children.store(true, Ordering::Release);
                Ok(())
            }
        };
        drop(stale_weak);
        if let Err(err) = attach_result {
            drop(candidate);
            return Err(err);
        }
        add_to_registry(&candidate, initial_prop);
        Ok(candidate)
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
        } else if source.mountpoint().propagation().peer_group().is_some() {
            let is_descendant = self.entry.ptr_eq(&source.entry)
                || Self::entry_key(&self.entry) == Self::entry_key(&source.entry)
                || self.entry.is_ancestor_of(&source.entry).unwrap_or(false)
                || source.entry.is_ancestor_of(&self.entry).unwrap_or(false);
            if is_descendant {
                PropagationMode::Private
            } else {
                *source.mountpoint().propagation.lock()
            }
        } else {
            PropagationMode::Private
        };
        let dst_parent_prop = *self.mountpoint().propagation.lock();
        let final_prop = match src_prop {
            PropagationMode::Shared { peer_group } => PropagationMode::Shared { peer_group },
            PropagationMode::SharedAndSlave {
                peer_group,
                master_group,
            } => PropagationMode::SharedAndSlave {
                peer_group,
                master_group,
            },
            PropagationMode::Slave { master_group } => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::SharedAndSlave {
                        peer_group: pg,
                        master_group,
                    }
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
        let candidate = Mountpoint::new_bind_with_propagation(source, Some(self.clone()), final_prop);
        let candidate_weak = Arc::downgrade(&candidate);
        let mut stale_weak = None;
        let attach_result = {
            let mut guard = topology_sync::lock_topology_write();
            if matches!(
                guard.get(&self.mountpoint.topology).attachment,
                MountAttachment::Detached
            ) {
                Err(VfsError::InvalidInput)
            } else if guard
                .get(&self.mountpoint.topology)
                .children
                .get(&entry_key)
                .is_some_and(|weak| weak.strong_count() > 0)
            {
                Err(VfsError::ResourceBusy)
            } else {
                let children = &mut guard.get_mut(&self.mountpoint.topology).children;
                children.reserve(1);
                stale_weak = children.insert(entry_key, candidate_weak);
                self.mountpoint.has_children.store(true, Ordering::Release);
                Ok(())
            }
        };
        drop(stale_weak);
        if let Err(err) = attach_result {
            drop(candidate);
            return Err(err);
        }
        add_to_registry(&candidate, final_prop);
        Ok(candidate)
    }

    pub fn unmount(&self) -> VfsResult<()> {
        if !self.is_root_of_mount() {
            return Err(VfsError::InvalidInput);
        }
        let mp = &self.mountpoint;
        let mut stale_self_children = HashMap::new();
        let mut old_attachment = MountAttachment::Detached;
        let mut removed_parent_weak = None;
        let mut busy_keys = Vec::new();
        {
            let mut guard = topology_sync::lock_topology_write();
            let has_live_child = guard
                .get(&mp.topology)
                .children
                .values()
                .any(|weak| weak.strong_count() > 0);
            if has_live_child {
                busy_keys.extend(guard.get(&mp.topology).children.keys().copied());
            } else {
                stale_self_children = mem::take(&mut guard.get_mut(&mp.topology).children);
                mp.has_children.store(false, Ordering::Release);
                old_attachment = mem::replace(
                    &mut guard.get_mut(&mp.topology).attachment,
                    MountAttachment::Detached,
                );
                if let MountAttachment::Attached(ref parent_link) = old_attachment {
                    let parent_mp = &parent_link.location.mountpoint;
                    let entry_key = parent_link.entry_key;
                    let parent_children = &mut guard.get_mut(&parent_mp.topology).children;
                    let should_remove = parent_children.get(&entry_key).is_some_and(|weak| {
                        core::ptr::eq(Weak::as_ptr(weak), Arc::as_ptr(mp))
                            || weak.strong_count() == 0
                    });
                    if should_remove {
                        removed_parent_weak = parent_children.remove(&entry_key);
                    }
                    if !parent_children.values().any(|weak| weak.strong_count() > 0) {
                        parent_mp.has_children.store(false, Ordering::Release);
                    }
                }
            }
        }
        if !busy_keys.is_empty() {
            log::warn!(
                "unmount: mount ID {} at {:?} is busy. Children keys: {:?}",
                mp.id,
                self.entry,
                busy_keys
            );
            return Err(VfsError::ResourceBusy);
        }
        drop((stale_self_children, old_attachment, removed_parent_weak));
        let prop = *mp.propagation.lock();
        remove_from_registry(mp, prop);
        Ok(())
    }

    pub fn unmount_all(&self) -> VfsResult<()> {
        if !self.is_root_of_mount() {
            return Err(VfsError::InvalidInput);
        }
        let mut detached_mps = Vec::new();
        let mut detached_attachments = Vec::new();
        let mut detached_maps = Vec::new();
        let mut removed_root_weak = None;
        let mut duplicate_arcs = Vec::new();
        {
            let mut guard = topology_sync::lock_topology_write();
            let root_mp = &self.mountpoint;
            let root_attachment = mem::replace(
                &mut guard.get_mut(&root_mp.topology).attachment,
                MountAttachment::Detached,
            );
            if let MountAttachment::Attached(ref parent_link) = root_attachment {
                let parent_mp = &parent_link.location.mountpoint;
                let entry_key = parent_link.entry_key;
                let parent_children = &mut guard.get_mut(&parent_mp.topology).children;
                let should_remove = parent_children.get(&entry_key).is_some_and(|weak| {
                    core::ptr::eq(Weak::as_ptr(weak), Arc::as_ptr(root_mp))
                        || weak.strong_count() == 0
                });
                if should_remove {
                    removed_root_weak = parent_children.remove(&entry_key);
                }
                if !parent_children.values().any(|weak| weak.strong_count() > 0) {
                    parent_mp.has_children.store(false, Ordering::Release);
                }
            }
            detached_attachments.push(root_attachment);

            let mut visited = HashSet::new();
            visited.insert(root_mp.id);
            detached_mps.push(root_mp.clone());
            let mut stack = vec![0usize];
            while let Some(idx) = stack.pop() {
                let node_attachment = mem::replace(
                    &mut guard.get_mut(&detached_mps[idx].topology).attachment,
                    MountAttachment::Detached,
                );
                detached_attachments.push(node_attachment);
                let node_children =
                    mem::take(&mut guard.get_mut(&detached_mps[idx].topology).children);
                detached_mps[idx]
                    .has_children
                    .store(false, Ordering::Release);

                let start_len = detached_mps.len();
                for weak in node_children.values() {
                    if let Some(child_mp) = weak.upgrade() {
                        if visited.insert(child_mp.id) {
                            detached_mps.push(child_mp);
                        } else {
                            duplicate_arcs.push(child_mp);
                        }
                    }
                }
                detached_maps.push(node_children);
                for child_idx in start_len..detached_mps.len() {
                    stack.push(child_idx);
                }
            }
        }
        drop((
            detached_attachments,
            detached_maps,
            removed_root_weak,
            duplicate_arcs,
        ));
        for node in &detached_mps {
            let prop = *node.propagation.lock();
            remove_from_registry(node, prop);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Move mount: detach from current parent, reattach under new_parent/name.
    // -----------------------------------------------------------------------

    /// Move this mount (which must be an attached mountpoint root) to `new_parent`.
    /// The directory `new_parent` must not already host a mount or lie inside `self`.
    pub fn move_mount(&self, new_parent: &Location) -> VfsResult<Arc<Mountpoint>> {
        if !self.is_root_of_mount() {
            return Err(VfsError::InvalidInput);
        }
        new_parent.entry.as_dir()?;
        let mp = &self.mountpoint;
        let new_parent_mp = &new_parent.mountpoint;
        let new_entry_key = Self::entry_key(&new_parent.entry);
        let new_parent_loc = new_parent.clone();
        let mp_weak = Arc::downgrade(mp);

        let mut old_parent_keep = None;
        let mut removed_old_weak = None;
        let mut stale_target_weak = None;
        let mut old_attachment = MountAttachment::Detached;
        let move_result = {
            let mut guard = topology_sync::lock_topology_write();
            let old_info = guard
                .get(&mp.topology)
                .parent_link()
                .map(|link| (link.location.mountpoint.clone(), link.entry_key));
            if let Some((old_parent_mp, old_entry_key)) = old_info {
                old_parent_keep = Some(old_parent_mp);
                let old_parent_mp = old_parent_keep.as_ref().unwrap();

                // Verify parent-child link consistency on old parent.
                let is_registered = guard
                    .get(&old_parent_mp.topology)
                    .children
                    .get(&old_entry_key)
                    .is_some_and(|weak| core::ptr::eq(Weak::as_ptr(weak), Arc::as_ptr(mp)));
                if !is_registered {
                    Err(VfsError::InvalidInput)
                } else if matches!(
                    guard.get(&new_parent_mp.topology).attachment,
                    MountAttachment::Detached
                ) {
                    Err(VfsError::InvalidInput)
                } else if Arc::ptr_eq(mp, new_parent_mp)
                    || is_mount_ancestor_of_with(mp, new_parent_mp, |m| guard.get(&m.topology))
                {
                    // Reject moving a mount into itself or any of its descendants.
                    Err(VfsError::InvalidInput)
                } else if guard
                    .get(&new_parent_mp.topology)
                    .children
                    .get(&new_entry_key)
                    .is_some_and(|weak| weak.strong_count() > 0)
                {
                    Err(VfsError::ResourceBusy)
                } else {
                    guard
                        .get_mut(&new_parent_mp.topology)
                        .children
                        .reserve(1);
                    removed_old_weak = guard
                        .get_mut(&old_parent_mp.topology)
                        .children
                        .remove(&old_entry_key);
                    stale_target_weak = guard
                        .get_mut(&new_parent_mp.topology)
                        .children
                        .insert(new_entry_key, mp_weak);
                    old_attachment = mem::replace(
                        &mut guard.get_mut(&mp.topology).attachment,
                        MountAttachment::Attached(ParentLink {
                            location: new_parent_loc,
                            entry_key: new_entry_key,
                        }),
                    );
                    // Publish `true` on `new_parent_mp` before potentially clearing
                    // `old_parent_mp` so lock-free negative fast-path probes never
                    // observe both parents empty across the move boundary.
                    new_parent_mp.has_children.store(true, Ordering::Release);
                    if !Arc::ptr_eq(old_parent_mp, new_parent_mp)
                        && !guard
                            .get(&old_parent_mp.topology)
                            .children
                            .values()
                            .any(|weak| weak.strong_count() > 0)
                    {
                        old_parent_mp.has_children.store(false, Ordering::Release);
                    }
                    Ok(())
                }
            } else {
                // Reject moving root mounts and already-unmounted mounts.
                Err(VfsError::InvalidInput)
            }
        };
        drop((
            old_parent_keep,
            removed_old_weak,
            stale_target_weak,
            old_attachment,
        ));
        move_result?;

        // Update propagation mode after move.
        let dst_parent_prop = *new_parent.mountpoint.propagation.lock();
        let src_prop = *mp.propagation.lock();
        let final_prop = match src_prop {
            PropagationMode::Shared { peer_group } => PropagationMode::Shared { peer_group },
            PropagationMode::SharedAndSlave {
                peer_group,
                master_group,
            } => PropagationMode::SharedAndSlave {
                peer_group,
                master_group,
            },
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
    visited: &mut HashSet<u64>,
) {
    if !visited.insert(parent_mp.id) {
        return;
    }
    let mut targets = Vec::new();
    let prop = *parent_mp.propagation.lock();
    if let Some(peer_group) = prop.peer_group() {
        targets.extend(peer_group_members(peer_group, parent_mp));
        targets.extend(slaves_of_group(peer_group));
    }

    for peer_parent_mp in targets {
        let peer_child = {
            let guard = topology_sync::lock_topology_read();
            guard
                .get(&peer_parent_mp.topology)
                .children
                .get(entry_key)
                .and_then(Weak::upgrade)
        };
        if let Some(peer_child_mp) = peer_child {
            if !result.iter().any(|m| Arc::ptr_eq(m, &peer_child_mp)) {
                result.push(peer_child_mp);
                collect_propagate_unmount_rec(&peer_parent_mp, entry_key, result, visited);
            }
        }
    }
}

pub fn collect_propagate_unmount(mp: &Arc<Mountpoint>) -> Vec<Arc<Mountpoint>> {
    let mut result = Vec::new();
    let parent_snapshot = {
        let guard = topology_sync::lock_topology_read();
        guard
            .get(&mp.topology)
            .parent_link()
            .map(|link| (link.location.mountpoint.clone(), link.entry_key))
    };
    let Some((parent_mp, entry_key)) = parent_snapshot else {
        return result;
    };
    let mut visited = HashSet::new();
    collect_propagate_unmount_rec(&parent_mp, &entry_key, &mut result, &mut visited);

    // Exclude the target mountpoint itself from peer unmount propagation
    result.retain(|m| !Arc::ptr_eq(m, mp));

    // Sort so that descendant/child mounts are unmounted before their ancestors/parents
    {
        let guard = topology_sync::lock_topology_read();
        result.sort_by(|a, b| {
            if is_mount_ancestor_of_with(a, b, |m| guard.get(&m.topology)) {
                core::cmp::Ordering::Greater
            } else if is_mount_ancestor_of_with(b, a, |m| guard.get(&m.topology)) {
                core::cmp::Ordering::Less
            } else {
                core::cmp::Ordering::Equal
            }
        });
    }

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
    let mut deferred_drops = Vec::new();
    let children: Vec<(Arc<Mountpoint>, Location)> = {
        let guard = topology_sync::lock_topology_read();
        guard
            .get(&src_mp.topology)
            .children
            .values()
            .filter_map(|weak| {
                let child_mp = weak.upgrade()?;
                let Some(loc) = guard.get(&child_mp.topology).parent_location().cloned() else {
                    deferred_drops.push(child_mp);
                    return None;
                };
                Some((child_mp, loc))
            })
            .collect()
    };
    drop(deferred_drops);

    for (child_mp, child_loc) in children {
        if Arc::ptr_eq(&child_mp, dst_mp)
            || is_mount_ancestor_of(&child_mp, dst_mp)
            || is_mount_ancestor_of(dst_mp, &child_mp)
        {
            continue;
        }

        let is_reachable = dst_mp.root == child_loc.entry
            || dst_mp.root.is_ancestor_of(&child_loc.entry).unwrap_or(false);
        if !is_reachable {
            continue;
        }

        let dst_child_loc =
            Location::new(dst_mp.clone(), child_loc.entry.clone()).resolve_mounted_location();

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
        {
            let guard = topology_sync::lock_topology_read();
            if let Some(existing) = guard
                .get(&self.mountpoint.topology)
                .children
                .get(&entry_key)
                .and_then(Weak::upgrade)
            {
                drop(guard);
                return Ok(existing);
            }
        }
        let src_prop = if source.is_root_of_mount() {
            *source.mountpoint().propagation.lock()
        } else if source.mountpoint().propagation().peer_group().is_some() {
            let is_descendant = self.entry.ptr_eq(&source.entry)
                || entry_key == Self::entry_key(&source.entry)
                || self.entry.is_ancestor_of(&source.entry).unwrap_or(false)
                || source.entry.is_ancestor_of(&self.entry).unwrap_or(false);
            if is_descendant {
                PropagationMode::Private
            } else {
                *source.mountpoint().propagation.lock()
            }
        } else {
            PropagationMode::Private
        };
        let dst_parent_prop = *self.mountpoint().propagation.lock();
        let final_prop = match src_prop {
            PropagationMode::Shared { peer_group } => PropagationMode::Shared { peer_group },
            PropagationMode::SharedAndSlave {
                peer_group,
                master_group,
            } => PropagationMode::SharedAndSlave {
                peer_group,
                master_group,
            },
            PropagationMode::Slave { master_group } => {
                if dst_parent_prop.is_shared() {
                    let pg = PEER_GROUP_COUNTER.fetch_add(1, Ordering::Relaxed);
                    PropagationMode::SharedAndSlave {
                        peer_group: pg,
                        master_group,
                    }
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

        let candidate =
            Mountpoint::new_bind_with_propagation(source, Some(self.clone()), final_prop);
        let candidate_weak = Arc::downgrade(&candidate);
        let mut stale_weak = None;
        let outcome = {
            let mut guard = topology_sync::lock_topology_write();
            if matches!(
                guard.get(&self.mountpoint.topology).attachment,
                MountAttachment::Detached
            ) {
                Err(VfsError::InvalidInput)
            } else if let Some(existing) = guard
                .get(&self.mountpoint.topology)
                .children
                .get(&entry_key)
                .and_then(Weak::upgrade)
            {
                Ok(Some(existing))
            } else {
                let children = &mut guard.get_mut(&self.mountpoint.topology).children;
                children.reserve(1);
                stale_weak = children.insert(entry_key, candidate_weak);
                self.mountpoint.has_children.store(true, Ordering::Release);
                Ok(None)
            }
        };
        drop(stale_weak);
        match outcome {
            Ok(Some(existing)) => {
                drop(candidate);
                Ok(existing)
            }
            Ok(None) => {
                add_to_registry(&candidate, final_prop);
                Ok(candidate)
            }
            Err(err) => {
                drop(candidate);
                Err(err)
            }
        }
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

#[cfg(test)]
mod tests {
    use alloc::{
        borrow::ToOwned, boxed::Box, collections::BTreeMap, string::ToString, task::Wake,
    };
    use core::{
        any::Any,
        future::Future,
        sync::atomic::AtomicU64,
        task::{Context, Poll, Waker},
    };
    use std::{sync::Barrier, thread};

    use async_trait::async_trait;

    use super::*;
    use crate::{DirNode, DirNodeOps, NodeOps, Reference, StatFs, WeakDirEntry};

    struct NoopWake;

    impl Wake for NoopWake {
        fn wake(self: Arc<Self>) {}
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let waker = Waker::from(Arc::new(NoopWake));
        let mut cx = Context::from_waker(&waker);
        let mut future = core::pin::pin!(future);
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return output;
            }
            core::hint::spin_loop();
        }
    }

    struct MemFs {
        name: &'static str,
        next_ino: AtomicU64,
        root: SpinNoPreempt<Option<WeakDirEntry>>,
    }

    struct MemDir {
        ino: u64,
        fs: Arc<MemFs>,
        this: WeakDirEntry,
        entries: SpinNoPreempt<BTreeMap<String, DirEntry>>,
    }

    impl MemFs {
        fn create(name: &'static str) -> Filesystem {
            let fs = Arc::new(Self {
                name,
                next_ino: AtomicU64::new(2),
                root: SpinNoPreempt::new(None),
            });
            let fs_for_root = fs.clone();
            let root = DirEntry::new_dir(
                move |this| {
                    DirNode::new(Arc::new(MemDir {
                        ino: 1,
                        fs: fs_for_root,
                        this,
                        entries: SpinNoPreempt::new(BTreeMap::new()),
                    }))
                },
                Reference::root(),
            );
            *fs.root.lock() = Some(root.downgrade());
            let filesystem = Filesystem::new(fs);
            drop(root);
            filesystem
        }
    }

    #[async_trait]
    impl FilesystemOps for MemFs {
        fn name(&self) -> &str {
            self.name
        }

        fn root_dir(&self) -> DirEntry {
            self.root.lock().as_ref().unwrap().upgrade().unwrap()
        }

        fn stat(&self) -> VfsResult<StatFs> {
            Err(VfsError::Unsupported)
        }
    }

    #[async_trait]
    impl NodeOps for MemDir {
        fn inode(&self) -> u64 {
            self.ino
        }

        async fn metadata(&self) -> VfsResult<Metadata> {
            Err(VfsError::Unsupported)
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

        fn into_any(self: Arc<Self>) -> Arc<dyn Any + Send + Sync> {
            self
        }
    }

    #[async_trait]
    impl DirNodeOps for MemDir {
        async fn read_dir(
            &self,
            _offset: u64,
            _sink: &mut (dyn DirEntrySink + Send),
        ) -> VfsResult<usize> {
            Err(VfsError::Unsupported)
        }

        async fn lookup(&self, name: &str) -> VfsResult<DirEntry> {
            self.entries
                .lock()
                .get(name)
                .cloned()
                .ok_or(VfsError::NotFound)
        }

        async fn create(
            &self,
            name: &str,
            node_type: NodeType,
            _permission: NodePermission,
        ) -> VfsResult<DirEntry> {
            if node_type != NodeType::Directory {
                return Err(VfsError::Unsupported);
            }
            let mut entries = self.entries.lock();
            if entries.contains_key(name) {
                return Err(VfsError::AlreadyExists);
            }
            let ino = self.fs.next_ino.fetch_add(1, Ordering::Relaxed);
            let fs = self.fs.clone();
            let entry = DirEntry::new_dir(
                move |this| {
                    DirNode::new(Arc::new(MemDir {
                        ino,
                        fs,
                        this,
                        entries: SpinNoPreempt::new(BTreeMap::new()),
                    }))
                },
                Reference::new(Some(self.this.clone()), name.to_owned()),
            );
            entries.insert(name.to_owned(), entry.clone());
            Ok(entry)
        }

        async fn link(&self, _name: &str, _node: &DirEntry) -> VfsResult<DirEntry> {
            Err(VfsError::Unsupported)
        }

        async fn unlink(&self, name: &str) -> VfsResult<()> {
            self.entries
                .lock()
                .remove(name)
                .map(|_| ())
                .ok_or(VfsError::NotFound)
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

    fn mkdir(parent: &Location, name: &str) -> Location {
        block_on(parent.create(name, NodeType::Directory, NodePermission::default())).unwrap()
    }

    #[test]
    fn concurrent_move_mount_versus_resolve_preserves_topology_invariants() {
        let root_fs = MemFs::create("root");
        let left_fs = MemFs::create("left");
        let right_fs = MemFs::create("right");
        let moving_fs = MemFs::create("moving");
        let leaf_fs = MemFs::create("leaf");

        let root_mp = Mountpoint::new_root(&root_fs);
        let root_loc = root_mp.root_location();
        let left_dir = mkdir(&root_loc, "left");
        let right_dir = mkdir(&root_loc, "right");

        let left_mp = left_dir.mount(&left_fs).unwrap();
        let right_mp = right_dir.mount(&right_fs).unwrap();
        let left_root = left_mp.root_location();
        let right_root = right_mp.root_location();

        // Use distinct slot names per parent so any torn `(parent, name)` or
        // cross-parent path stitch (e.g. `/left/rs0/...`) fails immediately.
        let left_s0 = mkdir(&left_root, "ls0");
        let left_s1 = mkdir(&left_root, "ls1");
        let right_s0 = mkdir(&right_root, "rs0");
        let right_s1 = mkdir(&right_root, "rs1");

        let moving_mp = left_s0.mount(&moving_fs).unwrap();
        let moving_root = moving_mp.root_location();
        let inner_loc = mkdir(&moving_root, "inner");
        let leaf_dir = mkdir(&inner_loc, "leaf");
        let leaf_mp = leaf_dir.mount(&leaf_fs).unwrap();
        let leaf_root = leaf_mp.root_location();

        let slots = Arc::new([
            left_s0.clone(),
            right_s0.clone(),
            left_s1.clone(),
            right_s1.clone(),
        ]);

        let iterations = if cfg!(miri) { 12 } else { 2_000 };
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for mover_idx in 0..2usize {
            let barrier = barrier.clone();
            let slots = slots.clone();
            let moving_root = moving_root.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                for step in 0..iterations {
                    let target = &slots[(step * 2 + mover_idx + 1) % slots.len()];
                    let _ = moving_root.move_mount(target);
                }
            }));
        }

        for _ in 0..2 {
            let barrier = barrier.clone();
            let moving_mp = moving_mp.clone();
            let moving_root = moving_root.clone();
            let inner_loc = inner_loc.clone();
            let leaf_root = leaf_root.clone();
            let left_mp = left_mp.clone();
            let left_root = left_root.clone();
            let right_root = right_root.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                for _ in 0..iterations {
                    assert!(!moving_mp.is_root());
                    assert!(!moving_root.is_root());
                    let loc = moving_mp.location().expect("moving mount stays attached");
                    let loc_name = loc.name();
                    assert!(
                        matches!(&*loc_name, "ls0" | "ls1" | "rs0" | "rs1"),
                        "unexpected parent slot name: {loc_name}"
                    );

                    let name = moving_root.name();
                    assert!(
                        matches!(&*name, "ls0" | "ls1" | "rs0" | "rs1"),
                        "unexpected moving mount name: {name}"
                    );

                    let (parent, atomic_name) = moving_root
                        .parent_and_name()
                        .expect("moving mount has parent and name");
                    if parent == left_root {
                        assert!(
                            matches!(&*atomic_name, "ls0" | "ls1"),
                            "torn parent/name snapshot: left_root with {atomic_name}"
                        );
                    } else if parent == right_root {
                        assert!(
                            matches!(&*atomic_name, "rs0" | "rs1"),
                            "torn parent/name snapshot: right_root with {atomic_name}"
                        );
                    } else {
                        panic!("unexpected parent location: {parent:?}");
                    }

                    let parent_only = moving_root.parent().expect("moving mount has parent");
                    assert!(
                        parent_only == left_root || parent_only == right_root,
                        "unexpected parent location: {parent_only:?}"
                    );

                    let inner_path = inner_loc.absolute_path().unwrap().to_string();
                    assert!(
                        matches!(
                            inner_path.as_str(),
                            "/left/ls0/inner"
                                | "/right/rs0/inner"
                                | "/left/ls1/inner"
                                | "/right/rs1/inner"
                        ),
                        "inconsistent inner path: {inner_path}"
                    );

                    let leaf_path = leaf_root.absolute_path().unwrap().to_string();
                    assert!(
                        matches!(
                            leaf_path.as_str(),
                            "/left/ls0/inner/leaf"
                                | "/right/rs0/inner/leaf"
                                | "/left/ls1/inner/leaf"
                                | "/right/rs1/inner/leaf"
                        ),
                        "inconsistent leaf path: {leaf_path}"
                    );

                    let resolved = block_on(left_root.lookup_no_follow("ls0")).unwrap();
                    assert!(
                        Arc::ptr_eq(resolved.mountpoint(), &left_mp)
                            || Arc::ptr_eq(resolved.mountpoint(), &moving_mp)
                    );
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let mounted_slots: Vec<&Location> = slots
            .iter()
            .filter(|slot| slot.is_mountpoint())
            .collect();
        assert_eq!(
            mounted_slots.len(),
            1,
            "expected exactly one active child entry, found {}: {mounted_slots:?}",
            mounted_slots.len()
        );
        let active_slot = mounted_slots[0];
        assert_eq!(moving_mp.location().as_ref(), Some(active_slot));

        for slot in slots.iter() {
            let parent_root = if Arc::ptr_eq(slot.mountpoint(), &left_mp) {
                &left_root
            } else {
                &right_root
            };
            let resolved = block_on(parent_root.lookup_no_follow(&slot.name())).unwrap();
            if slot == active_slot {
                assert!(Arc::ptr_eq(resolved.mountpoint(), &moving_mp));
            } else {
                assert!(Arc::ptr_eq(resolved.mountpoint(), slot.mountpoint()));
            }
        }
    }

    #[test]
    fn move_mount_rejects_invalid_and_busy_transitions_without_partial_mutation() {
        let root_fs = MemFs::create("root");
        let fs_a = MemFs::create("a");
        let fs_a_child = MemFs::create("a_child");
        let fs_b = MemFs::create("b");
        let fs_replacement = MemFs::create("replacement");

        let root_mp = Mountpoint::new_root(&root_fs);
        let root_loc = root_mp.root_location();
        assert!(root_mp.is_root());
        assert!(root_loc.is_root());
        assert_eq!(&*root_loc.name(), "");
        assert!(root_loc.parent().is_none());
        assert!(root_loc.parent_and_name().is_none());

        let dir_a = mkdir(&root_loc, "a");
        let dir_b = mkdir(&root_loc, "b");
        let dir_free = mkdir(&root_loc, "free");

        // Reject moving global root mount.
        assert_eq!(
            root_loc.move_mount(&dir_free).unwrap_err(),
            VfsError::InvalidInput
        );
        assert!(root_mp.is_root());
        assert!(!dir_free.is_mountpoint());

        let mp_a = dir_a.mount(&fs_a).unwrap();
        let a_root = mp_a.root_location();
        let a_sub = mkdir(&a_root, "sub");
        let a_nested_slot = mkdir(&a_sub, "nested");
        let mp_a_child = a_nested_slot.mount(&fs_a_child).unwrap();
        let a_child_sub = mkdir(&mp_a_child.root_location(), "inside");

        // Reject moving non-mount-root directory.
        assert_eq!(
            a_sub.move_mount(&dir_free).unwrap_err(),
            VfsError::InvalidInput
        );

        // Reject moving a mount into itself or into a descendant mount.
        assert_eq!(
            a_root.move_mount(&a_sub).unwrap_err(),
            VfsError::InvalidInput
        );
        assert_eq!(
            a_root.move_mount(&a_child_sub).unwrap_err(),
            VfsError::InvalidInput
        );
        assert_eq!(mp_a.location().as_ref(), Some(&dir_a));
        assert_eq!(
            a_child_sub.absolute_path().unwrap().to_string(),
            "/a/sub/nested/inside"
        );

        // Reject moving onto an already-occupied mountpoint.
        let mp_b = dir_b.mount(&fs_b).unwrap();
        let b_root = mp_b.root_location();
        let b_sub = mkdir(&b_root, "sub");
        assert_eq!(
            a_root.move_mount(&dir_b).unwrap_err(),
            VfsError::ResourceBusy
        );
        assert_eq!(mp_a.location().as_ref(), Some(&dir_a));
        assert_eq!(mp_b.location().as_ref(), Some(&dir_b));

        // Concurrent cross-subtree moves (`a` -> `/b/sub` vs `b` -> `/a/sub`) must
        // serialize cleanly without ever forming a detached cycle.
        let barrier = Arc::new(Barrier::new(2));
        let h1 = {
            let barrier = barrier.clone();
            let a_root = a_root.clone();
            let b_sub = b_sub.clone();
            thread::spawn(move || {
                barrier.wait();
                a_root.move_mount(&b_sub)
            })
        };
        let h2 = {
            let barrier = barrier.clone();
            let b_root = b_root.clone();
            let a_sub = a_sub.clone();
            thread::spawn(move || {
                barrier.wait();
                b_root.move_mount(&a_sub)
            })
        };
        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();
        assert!(
            !(r1.is_ok() && r2.is_ok()),
            "cross-subtree moves cannot both succeed into a cycle"
        );
        let a_path = a_root.absolute_path().unwrap().to_string();
        let b_path = b_root.absolute_path().unwrap().to_string();
        assert!(a_path == "/a" || a_path == "/b/sub", "unexpected a_path: {a_path}");
        assert!(b_path == "/b" || b_path == "/a/sub", "unexpected b_path: {b_path}");

        // Detach `mp_a` subtree and verify detached mounts cannot move or evict replacements.
        a_root.unmount_all().unwrap();
        if mp_b.location().is_some() {
            b_root.unmount_all().unwrap();
        }
        assert!(!mp_a.is_root());
        assert!(mp_a.location().is_none());
        assert_eq!(
            a_root.move_mount(&dir_free).unwrap_err(),
            VfsError::InvalidInput
        );

        let replacement_mp = dir_a.mount(&fs_replacement).unwrap();
        assert!(dir_a.is_mountpoint());
        // Repeated unmount or move on stale `a_root` must not evict `replacement_mp`.
        assert_eq!(a_root.unmount(), Ok(()));
        assert_eq!(
            a_root.move_mount(&dir_free).unwrap_err(),
            VfsError::InvalidInput
        );
        let resolved_a = block_on(root_loc.lookup_no_follow("a")).unwrap();
        assert!(Arc::ptr_eq(resolved_a.mountpoint(), &replacement_mp));
    }

    #[test]
    fn stacked_mounts_and_unmount_all_preserve_consistent_topology() {
        let root_fs = MemFs::create("root");
        let lower_fs = MemFs::create("lower");
        let upper_fs = MemFs::create("upper");
        let child_fs = MemFs::create("child");

        let root_mp = Mountpoint::new_root(&root_fs);
        let root_loc = root_mp.root_location();
        let mnt_dir = mkdir(&root_loc, "mnt");
        let alt_dir = mkdir(&root_loc, "alt");

        let lower_mp = mnt_dir.mount(&lower_fs).unwrap();
        let lower_root = lower_mp.root_location();
        let lower_sub = mkdir(&lower_root, "lower_sub");

        // Stack `upper_fs` directly on top of `lower_root`.
        let upper_mp = lower_root.mount(&upper_fs).unwrap();
        let upper_root = upper_mp.root_location();
        let upper_child = mkdir(&upper_root, "upper_child");

        let resolved = block_on(root_loc.lookup_no_follow("mnt")).unwrap();
        assert!(Arc::ptr_eq(resolved.mountpoint(), &upper_mp));
        assert_eq!(&*upper_root.name(), "mnt");
        assert_eq!(upper_root.parent(), Some(root_loc.clone()));
        let (p, n) = upper_root.parent_and_name().unwrap();
        assert_eq!(p, root_loc);
        assert_eq!(&*n, "mnt");
        assert_eq!(
            upper_child.absolute_path().unwrap().to_string(),
            "/mnt/upper_child"
        );

        // Moving `upper_mp` off the stack to `/alt` exposes `lower_mp` at `/mnt`.
        upper_root.move_mount(&alt_dir).unwrap();
        let resolved_mnt = block_on(root_loc.lookup_no_follow("mnt")).unwrap();
        assert!(Arc::ptr_eq(resolved_mnt.mountpoint(), &lower_mp));
        let resolved_alt = block_on(root_loc.lookup_no_follow("alt")).unwrap();
        assert!(Arc::ptr_eq(resolved_alt.mountpoint(), &upper_mp));
        assert_eq!(
            upper_child.absolute_path().unwrap().to_string(),
            "/alt/upper_child"
        );

        // Mount a child under `lower_sub`; `unmount` must report ResourceBusy, while
        // `collect_subtree` + `unmount_all` detaches both atomically.
        let child_mp = lower_sub.mount(&child_fs).unwrap();
        assert_eq!(lower_root.unmount(), Err(VfsError::ResourceBusy));
        let subtree = lower_mp.collect_subtree();
        assert_eq!(subtree.len(), 2);
        assert!(subtree.iter().any(|mp| Arc::ptr_eq(mp, &lower_mp)));
        assert!(subtree.iter().any(|mp| Arc::ptr_eq(mp, &child_mp)));

        lower_root.unmount_all().unwrap();
        assert!(!mnt_dir.is_mountpoint());
        assert!(lower_mp.location().is_none());
        assert!(child_mp.location().is_none());
        assert!(!lower_mp.is_root());
        assert!(!child_mp.is_root());
    }

    #[test]
    fn mount_bind_and_shared_slave_propagation_remain_intact() {
        let root_fs = MemFs::create("root");
        let shared_fs = MemFs::create("shared");
        let sub_fs = MemFs::create("sub");
        let nested_fs = MemFs::create("nested");
        let slave_local_fs = MemFs::create("slave_local");

        let root_mp = Mountpoint::new_root(&root_fs);
        let root_loc = root_mp.root_location();
        let dir_a = mkdir(&root_loc, "peer_a");
        let dir_b = mkdir(&root_loc, "peer_b");
        let dir_c = mkdir(&root_loc, "slave_c");
        let dir_unbind = mkdir(&root_loc, "unbind");

        // Unbindable mount rejects `mount_bind` with PermissionDenied.
        let unbind_mp = dir_unbind.mount(&slave_local_fs).unwrap();
        unbind_mp.make_unbindable();
        assert_eq!(
            dir_b.mount_bind(unbind_mp.root_location()).unwrap_err(),
            VfsError::PermissionDenied
        );
        unbind_mp.root_location().unmount().unwrap();

        // Setup shared peer `peer_a` <-> `peer_b`, and one-way slave `slave_c`.
        let peer_a_mp = dir_a.mount(&shared_fs).unwrap();
        let peer_a_root = peer_a_mp.root_location();
        let sub_slot_a = mkdir(&peer_a_root, "sub");
        let slave_only_slot = mkdir(&peer_a_root, "only_slave");

        let pg = peer_a_mp.make_shared();
        assert_eq!(peer_a_mp.propagation(), PropagationMode::Shared { peer_group: pg });

        let peer_b_mp = dir_b.mount_bind(peer_a_root.clone()).unwrap();
        assert_eq!(peer_b_mp.propagation(), PropagationMode::Shared { peer_group: pg });

        let slave_c_mp = dir_c.mount_bind(peer_b_mp.root_location()).unwrap();
        slave_c_mp.make_slave();
        assert_eq!(
            slave_c_mp.propagation(),
            PropagationMode::Slave { master_group: pg }
        );

        // Mount `sub_fs` (with an already-attached nested mount) at `/peer_a/sub` and propagate.
        let sub_mp = sub_slot_a.mount(&sub_fs).unwrap();
        let nested_slot = mkdir(&sub_mp.root_location(), "nested");
        let _nested_mp = nested_slot.mount(&nested_fs).unwrap();

        let shadows = propagate_new_mount(
            &peer_a_mp,
            Location::entry_key(sub_slot_a.entry()),
            None,
            &sub_mp,
        );
        assert!(!shadows.is_empty());

        let peer_b_sub = block_on(peer_b_mp.root_location().lookup_no_follow("sub")).unwrap();
        assert!(peer_b_sub.is_root_of_mount());
        assert!(!Arc::ptr_eq(peer_b_sub.mountpoint(), &peer_b_mp));
        assert!(peer_b_sub.mountpoint().propagation().is_shared());
        let peer_b_nested = block_on(peer_b_sub.lookup_no_follow("nested")).unwrap();
        assert!(peer_b_nested.is_root_of_mount());

        let slave_c_sub = block_on(slave_c_mp.root_location().lookup_no_follow("sub")).unwrap();
        assert!(slave_c_sub.is_root_of_mount());
        assert!(slave_c_sub.mountpoint().propagation().is_slave());
        let slave_c_nested = block_on(slave_c_sub.lookup_no_follow("nested")).unwrap();
        assert!(slave_c_nested.is_root_of_mount());

        // Mounting under slave `slave_c` does NOT propagate back to master `peer_a`.
        let c_only_loc = Location::new(slave_c_mp.clone(), slave_only_slot.entry().clone());
        let c_local_mp = c_only_loc.mount(&slave_local_fs).unwrap();
        let back_shadows = propagate_new_mount(
            &slave_c_mp,
            Location::entry_key(c_only_loc.entry()),
            None,
            &c_local_mp,
        );
        assert!(back_shadows.is_empty());
        let a_only_resolved = block_on(peer_a_root.lookup_no_follow("only_slave")).unwrap();
        assert!(Arc::ptr_eq(a_only_resolved.mountpoint(), &peer_a_mp));

        // Verify propagated unmount collection includes peer & slave shadow mounts.
        let prop_unmounts = collect_propagate_unmount(&sub_mp);
        assert!(prop_unmounts.iter().any(|m| Arc::ptr_eq(m, peer_b_sub.mountpoint())));
        assert!(prop_unmounts.iter().any(|m| Arc::ptr_eq(m, slave_c_sub.mountpoint())));

        // Cleanly detach everything and verify `make_rprivate` clears peer groups.
        for target in prop_unmounts {
            target.root_location().unmount_all().unwrap();
        }
        root_loc.unmount_all().unwrap();
        root_mp.make_rprivate();
    }
}
