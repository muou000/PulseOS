//! BPF Map metadata, validation and bounded storage.
//!
//! This file is the pure part of the BPF object model: it only depends on
//! `core`, `alloc`, `spin` and `axerrno`, so `pulse_syscalls` host tests can compile it
//! directly. Kernel-only glue (the descriptor object) lives in `object.rs`.

use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};
use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use axerrno::LinuxError;
use spin::RwLock;

pub const BPF_OBJ_NAME_LEN: usize = 16;

pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
pub const BPF_MAP_TYPE_PERF_EVENT_ARRAY: u32 = 4;
/// Last Linux map type known to this ABI (`BPF_MAP_TYPE_ARENA`).
const BPF_MAP_TYPE_LINUX_MAX: u32 = 33;

pub const BPF_F_NO_PREALLOC: u32 = 1 << 0;
pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;
pub const BPF_F_WRONLY_PROG: u32 = 1 << 8;

pub const BPF_ANY: u64 = 0;
pub const BPF_NOEXIST: u64 = 1;
pub const BPF_EXIST: u64 = 2;

/// Linux bounds hash keys by the BPF stack size.
pub const BPF_MAP_MAX_KEY_SIZE: u32 = 512;
pub const BPF_MAP_MAX_VALUE_SIZE: u32 = 64 * 1024;
/// Upper bound for the storage of a single Map.
pub const BPF_MAP_MAX_BYTES: usize = 16 * 1024 * 1024;
/// Upper bound for the storage of all live Maps in the kernel.
pub const BPF_MAP_TOTAL_BYTES: usize = 64 * 1024 * 1024;

/// Kernel-wide Map memory budget.
pub static KERNEL_BPF_MAP_BUDGET: BpfMemoryBudget = BpfMemoryBudget::new(BPF_MAP_TOTAL_BYTES);

static NEXT_MAP_ID: AtomicU32 = AtomicU32::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BpfMapType {
    Hash,
    Array,
    PerfEventArray,
}

impl BpfMapType {
    pub fn from_raw(raw: u32) -> Result<Self, LinuxError> {
        match raw {
            BPF_MAP_TYPE_HASH => Ok(Self::Hash),
            BPF_MAP_TYPE_ARRAY => Ok(Self::Array),
            BPF_MAP_TYPE_PERF_EVENT_ARRAY => Ok(Self::PerfEventArray),
            0 => Err(LinuxError::EINVAL),
            raw if raw <= BPF_MAP_TYPE_LINUX_MAX => Err(LinuxError::EOPNOTSUPP),
            _ => Err(LinuxError::EINVAL),
        }
    }

    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Hash => BPF_MAP_TYPE_HASH,
            Self::Array => BPF_MAP_TYPE_ARRAY,
            Self::PerfEventArray => BPF_MAP_TYPE_PERF_EVENT_ARRAY,
        }
    }

    const fn allowed_flags(self) -> u32 {
        match self {
            Self::Hash => BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG,
            Self::Array => BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG,
            Self::PerfEventArray => 0,
        }
    }
}

/// Raw `BPF_MAP_CREATE` fields after ABI decoding.
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfMapCreateRequest {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: u32,
    pub numa_node: u32,
    pub map_name: [u8; BPF_OBJ_NAME_LEN],
    pub map_ifindex: u32,
    pub btf_fd: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub map_extra: u64,
}

/// Validated, immutable Map attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BpfMapSpec {
    map_type: BpfMapType,
    key_size: u32,
    value_size: u32,
    max_entries: u32,
    map_flags: u32,
    name: [u8; BPF_OBJ_NAME_LEN],
    storage_bytes: usize,
}

impl BpfMapSpec {
    /// Validates every attribute before any allocation happens.
    pub fn validate(req: &BpfMapCreateRequest) -> Result<Self, LinuxError> {
        // Map-in-map, bloom filters, NUMA nodes, and BTF are outside the compatibility tier.
        // libbpf retries without BTF type IDs when this fails.
        if req.inner_map_fd != 0
            || req.numa_node != 0
            || req.map_extra != 0
            || req.btf_fd != 0
            || req.btf_key_type_id != 0
            || req.btf_value_type_id != 0
            || req.btf_vmlinux_value_type_id != 0
        {
            return Err(LinuxError::EINVAL);
        }
        if req.map_ifindex != 0 {
            return Err(LinuxError::EOPNOTSUPP);
        }
        let name = validate_obj_name(&req.map_name)?;
        let map_type = BpfMapType::from_raw(req.map_type)?;

        let flags = req.map_flags;
        if flags & !map_type.allowed_flags() != 0
            || flags & (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)
                == (BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG)
        {
            return Err(LinuxError::EINVAL);
        }

        let key_ok = match map_type {
            BpfMapType::Array | BpfMapType::PerfEventArray => req.key_size == 4,
            BpfMapType::Hash => req.key_size != 0,
        };
        let val_ok = match map_type {
            BpfMapType::PerfEventArray => req.value_size == 4,
            _ => req.value_size != 0,
        };
        if !key_ok || !val_ok || req.value_size == 0 || req.max_entries == 0 {
            return Err(LinuxError::EINVAL);
        }
        if req.key_size > BPF_MAP_MAX_KEY_SIZE || req.value_size > BPF_MAP_MAX_VALUE_SIZE {
            return Err(LinuxError::E2BIG);
        }

        let entry_bytes = match map_type {
            BpfMapType::Array | BpfMapType::PerfEventArray => req.value_size as usize,
            BpfMapType::Hash => req.key_size as usize + req.value_size as usize,
        };
        let storage_bytes = entry_bytes
            .checked_mul(req.max_entries as usize)
            .filter(|&bytes| bytes <= BPF_MAP_MAX_BYTES)
            .ok_or(LinuxError::E2BIG)?;

        Ok(Self {
            map_type,
            key_size: req.key_size,
            value_size: req.value_size,
            max_entries: req.max_entries,
            map_flags: flags,
            name,
            storage_bytes,
        })
    }

    pub fn map_type(&self) -> BpfMapType {
        self.map_type
    }

    pub fn key_size(&self) -> u32 {
        self.key_size
    }

    pub fn value_size(&self) -> u32 {
        self.value_size
    }

    pub fn max_entries(&self) -> u32 {
        self.max_entries
    }

    pub fn map_flags(&self) -> u32 {
        self.map_flags
    }

    pub fn name_bytes(&self) -> &[u8; BPF_OBJ_NAME_LEN] {
        &self.name
    }

    /// Worst-case storage charged against the Map memory budget.
    pub fn storage_bytes(&self) -> usize {
        self.storage_bytes
    }
}

/// Linux `bpf_obj_name_cpy`: NUL-terminated, `[A-Za-z0-9_.]` only.
fn validate_obj_name(raw: &[u8; BPF_OBJ_NAME_LEN]) -> Result<[u8; BPF_OBJ_NAME_LEN], LinuxError> {
    let len = raw
        .iter()
        .position(|&b| b == 0)
        .ok_or(LinuxError::EINVAL)?;
    if !raw[..len]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return Err(LinuxError::EINVAL);
    }
    let mut name = [0u8; BPF_OBJ_NAME_LEN];
    name[..len].copy_from_slice(&raw[..len]);
    Ok(name)
}

/// Bounded accounting for Map storage and live Map objects.
pub struct BpfMemoryBudget {
    limit: usize,
    charged: AtomicUsize,
    live_maps: AtomicUsize,
}

impl BpfMemoryBudget {
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            charged: AtomicUsize::new(0),
            live_maps: AtomicUsize::new(0),
        }
    }

    pub fn charged_bytes(&self) -> usize {
        self.charged.load(Ordering::Acquire)
    }

    pub fn live_maps(&self) -> usize {
        self.live_maps.load(Ordering::Acquire)
    }

    fn charge(&'static self, bytes: usize) -> Result<BpfMemoryCharge, LinuxError> {
        let mut cur = self.charged.load(Ordering::Acquire);
        loop {
            let next = cur
                .checked_add(bytes)
                .filter(|&next| next <= self.limit)
                .ok_or(LinuxError::ENOMEM)?;
            match self
                .charged
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }
        self.live_maps.fetch_add(1, Ordering::AcqRel);
        Ok(BpfMemoryCharge {
            budget: self,
            bytes,
        })
    }
}

/// Releases its budget charge when the owning Map is destroyed.
struct BpfMemoryCharge {
    budget: &'static BpfMemoryBudget,
    bytes: usize,
}

impl Drop for BpfMemoryCharge {
    fn drop(&mut self) {
        self.budget.charged.fetch_sub(self.bytes, Ordering::AcqRel);
        self.budget.live_maps.fetch_sub(1, Ordering::AcqRel);
    }
}

pub trait PerfEventOutputSink: Send + Sync {
    fn output_sample(&self, data: &[u8]) -> Result<(), LinuxError>;
    fn as_any(&self) -> &dyn Any;
}

enum BpfMapStorage {
    /// Preallocated, zero-initialized `max_entries * value_size` bytes.
    Array(Vec<u8>),
    /// Holds at most `max_entries` elements; element operations land with the
    /// Map element control plane.
    #[allow(dead_code)]
    Hash(BTreeMap<Vec<u8>, Vec<u8>>),
    /// Slots holding CPU -> perf event objects and raw fd descriptors.
    PerfEventArray {
        fds: Vec<Option<u32>>,
        slots: Vec<Option<Arc<dyn PerfEventOutputSink>>>,
    },
}

impl BpfMapStorage {
    fn capacity(&self, val_size: usize, max_entries: usize) -> usize {
        match self {
            Self::Array(values) => values.len() / val_size,
            Self::Hash(_) => max_entries,
            Self::PerfEventArray { slots, .. } => slots.len(),
        }
    }

    fn lookup(
        &self,
        key: &[u8],
        val_size: usize,
        max_entries: usize,
        out: &mut [u8],
    ) -> Result<(), LinuxError> {
        match self {
            Self::Array(values) => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::ENOENT);
                }
                let start = index * val_size;
                let end = start + val_size;
                out.copy_from_slice(&values[start..end]);
                Ok(())
            }
            Self::Hash(map) => {
                let val = map.get(key).ok_or(LinuxError::ENOENT)?;
                out.copy_from_slice(val);
                Ok(())
            }
            Self::PerfEventArray { fds, .. } => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::ENOENT);
                }
                let fd = fds.get(index).copied().flatten().ok_or(LinuxError::ENOENT)?;
                out.copy_from_slice(&fd.to_ne_bytes());
                Ok(())
            }
        }
    }

    fn read_value(
        &self,
        key: &[u8],
        offset: usize,
        val_size: usize,
        max_entries: usize,
        out: &mut [u8],
    ) -> Result<(), LinuxError> {
        if offset.checked_add(out.len()).map_or(true, |end| end > val_size) {
            return Err(LinuxError::EINVAL);
        }
        match self {
            Self::Array(values) => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::ENOENT);
                }
                let start = index * val_size + offset;
                let end = start + out.len();
                out.copy_from_slice(&values[start..end]);
                Ok(())
            }
            Self::Hash(map) => {
                let val = map.get(key).ok_or(LinuxError::ENOENT)?;
                out.copy_from_slice(&val[offset..offset + out.len()]);
                Ok(())
            }
            Self::PerfEventArray { fds, .. } => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::ENOENT);
                }
                let fd = fds.get(index).copied().flatten().ok_or(LinuxError::ENOENT)?;
                let fd_bytes = fd.to_ne_bytes();
                let end = offset.checked_add(out.len()).ok_or(LinuxError::EINVAL)?;
                if end > fd_bytes.len() {
                    return Err(LinuxError::EINVAL);
                }
                out.copy_from_slice(&fd_bytes[offset..end]);
                Ok(())
            }
        }
    }

    fn write_value(
        &mut self,
        key: &[u8],
        offset: usize,
        val_size: usize,
        max_entries: usize,
        data: &[u8],
    ) -> Result<(), LinuxError> {
        if offset.checked_add(data.len()).map_or(true, |end| end > val_size) {
            return Err(LinuxError::EINVAL);
        }
        match self {
            Self::Array(values) => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::ENOENT);
                }
                let start = index * val_size + offset;
                let end = start + data.len();
                values[start..end].copy_from_slice(data);
                Ok(())
            }
            Self::Hash(map) => {
                let val = map.get_mut(key).ok_or(LinuxError::ENOENT)?;
                val[offset..offset + data.len()].copy_from_slice(data);
                Ok(())
            }
            Self::PerfEventArray { fds, .. } => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::ENOENT);
                }
                if offset == 0 && data.len() == 4 {
                    let fd = u32::from_ne_bytes(data.try_into().map_err(|_| LinuxError::EINVAL)?);
                    fds[index] = Some(fd);
                    Ok(())
                } else {
                    Err(LinuxError::EINVAL)
                }
            }
        }
    }

    fn update(
        &mut self,
        key: &[u8],
        value: &[u8],
        flags: u64,
        val_size: usize,
        max_entries: usize,
    ) -> Result<(), LinuxError> {
        match self {
            Self::Array(values) => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::E2BIG);
                }
                if flags == BPF_NOEXIST {
                    return Err(LinuxError::EEXIST);
                }
                let start = index * val_size;
                let end = start + val_size;
                values[start..end].copy_from_slice(value);
                Ok(())
            }
            Self::Hash(map) => match map.get_mut(key) {
                Some(existing_val) => {
                    if flags == BPF_NOEXIST {
                        return Err(LinuxError::EEXIST);
                    }
                    existing_val.copy_from_slice(value);
                    Ok(())
                }
                None => {
                    if flags == BPF_EXIST {
                        return Err(LinuxError::ENOENT);
                    }
                    if map.len() >= max_entries {
                        return Err(LinuxError::E2BIG);
                    }
                    map.insert(key.to_vec(), value.to_vec());
                    Ok(())
                }
            },
            Self::PerfEventArray { fds, .. } => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= max_entries {
                    return Err(LinuxError::E2BIG);
                }
                if flags == BPF_NOEXIST && fds[index].is_some() {
                    return Err(LinuxError::EEXIST);
                }
                if flags == BPF_EXIST && fds[index].is_none() {
                    return Err(LinuxError::ENOENT);
                }
                let fd = u32::from_ne_bytes(value.try_into().map_err(|_| LinuxError::EINVAL)?);
                fds[index] = Some(fd);
                Ok(())
            }
        }
    }

    fn delete(&mut self, key: &[u8]) -> Result<(), LinuxError> {
        match self {
            Self::Array(_) => Err(LinuxError::EINVAL),
            Self::Hash(map) => map.remove(key).ok_or(LinuxError::ENOENT).map(|_| ()),
            Self::PerfEventArray { fds, slots } => {
                let index = u32::from_ne_bytes(key.try_into().map_err(|_| LinuxError::EINVAL)?) as usize;
                if index >= fds.len() {
                    return Err(LinuxError::EINVAL);
                }
                if fds[index].is_none() {
                    return Err(LinuxError::ENOENT);
                }
                fds[index] = None;
                slots[index] = None;
                Ok(())
            }
        }
    }

    fn get_next_key(
        &self,
        key: Option<&[u8]>,
        max_entries: usize,
        next_key_out: &mut [u8],
    ) -> Result<(), LinuxError> {
        match self {
            Self::Array(_) | Self::PerfEventArray { .. } => {
                if max_entries == 0 {
                    return Err(LinuxError::ENOENT);
                }
                let next_idx = match key {
                    None => 0u32,
                    Some(k) => {
                        let idx = u32::from_ne_bytes(k.try_into().map_err(|_| LinuxError::EINVAL)?);
                        if idx >= max_entries as u32 {
                            0u32
                        } else if idx >= (max_entries as u32) - 1 {
                            return Err(LinuxError::ENOENT);
                        } else {
                            idx + 1
                        }
                    }
                };
                next_key_out.copy_from_slice(&next_idx.to_ne_bytes());
                Ok(())
            }
            Self::Hash(map) => {
                if map.is_empty() {
                    return Err(LinuxError::ENOENT);
                }
                match key {
                    None => {
                        let first = map.keys().next().ok_or(LinuxError::ENOENT)?;
                        next_key_out.copy_from_slice(first);
                        Ok(())
                    }
                    Some(k) => {
                        if !map.contains_key(k) {
                            let first = map.keys().next().ok_or(LinuxError::ENOENT)?;
                            next_key_out.copy_from_slice(first);
                            Ok(())
                        } else {
                            use core::ops::Bound;
                            let mut range = map.range((Bound::Excluded(k.to_vec()), Bound::Unbounded));
                            let next = range.next().ok_or(LinuxError::ENOENT)?;
                            next_key_out.copy_from_slice(next.0);
                            Ok(())
                        }
                    }
                }
            }
        }
    }
}

/// A BPF Map object. Its lifetime is owned by `Arc` references held by
/// descriptors (and, later, Programs); dropping the last one frees storage
/// and releases the budget charge.
pub struct BpfMap {
    id: u32,
    spec: BpfMapSpec,
    storage: RwLock<BpfMapStorage>,
    // Declared last: storage is freed before the charge is released.
    _charge: BpfMemoryCharge,
}

impl BpfMap {
    pub fn create(spec: BpfMapSpec) -> Result<Self, LinuxError> {
        Self::create_in(spec, &KERNEL_BPF_MAP_BUDGET)
    }

    pub fn create_in(spec: BpfMapSpec, budget: &'static BpfMemoryBudget) -> Result<Self, LinuxError> {
        let charge = budget.charge(spec.storage_bytes)?;
        let storage = match spec.map_type {
            BpfMapType::Array => {
                let mut values = Vec::new();
                values
                    .try_reserve_exact(spec.storage_bytes)
                    .map_err(|_| LinuxError::ENOMEM)?;
                values.resize(spec.storage_bytes, 0);
                BpfMapStorage::Array(values)
            }
            BpfMapType::Hash => BpfMapStorage::Hash(BTreeMap::new()),
            BpfMapType::PerfEventArray => {
                let max = spec.max_entries as usize;
                BpfMapStorage::PerfEventArray {
                    fds: alloc::vec![None; max],
                    slots: alloc::vec![None; max],
                }
            }
        };
        Ok(Self {
            id: alloc_map_id(),
            spec,
            storage: RwLock::new(storage),
            _charge: charge,
        })
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn spec(&self) -> &BpfMapSpec {
        &self.spec
    }

    /// Number of element slots currently backed by storage.
    pub fn storage_capacity(&self) -> usize {
        self.storage
            .read()
            .capacity(self.spec.value_size as usize, self.spec.max_entries as usize)
    }

    pub fn lookup(&self, key: &[u8], value_out: &mut [u8]) -> Result<(), LinuxError> {
        if key.len() != self.spec.key_size as usize || value_out.len() != self.spec.value_size as usize {
            return Err(LinuxError::EINVAL);
        }
        self.storage.read().lookup(
            key,
            self.spec.value_size as usize,
            self.spec.max_entries as usize,
            value_out,
        )
    }

    pub fn read_value_bytes(&self, key: &[u8], offset: usize, out: &mut [u8]) -> Result<(), LinuxError> {
        if key.len() != self.spec.key_size as usize {
            return Err(LinuxError::EINVAL);
        }
        self.storage.read().read_value(
            key,
            offset,
            self.spec.value_size as usize,
            self.spec.max_entries as usize,
            out,
        )
    }

    pub fn write_value_bytes(&self, key: &[u8], offset: usize, data: &[u8]) -> Result<(), LinuxError> {
        if key.len() != self.spec.key_size as usize {
            return Err(LinuxError::EINVAL);
        }
        self.storage.write().write_value(
            key,
            offset,
            self.spec.value_size as usize,
            self.spec.max_entries as usize,
            data,
        )
    }

    pub fn update(&self, key: &[u8], value: &[u8], flags: u64) -> Result<(), LinuxError> {
        if key.len() != self.spec.key_size as usize || value.len() != self.spec.value_size as usize {
            return Err(LinuxError::EINVAL);
        }
        if flags > BPF_EXIST {
            return Err(LinuxError::EINVAL);
        }
        self.storage.write().update(
            key,
            value,
            flags,
            self.spec.value_size as usize,
            self.spec.max_entries as usize,
        )
    }

    pub fn delete(&self, key: &[u8]) -> Result<(), LinuxError> {
        if key.len() != self.spec.key_size as usize {
            return Err(LinuxError::EINVAL);
        }
        self.storage.write().delete(key)
    }

    pub fn get_next_key(&self, key: Option<&[u8]>, next_key_out: &mut [u8]) -> Result<(), LinuxError> {
        if next_key_out.len() != self.spec.key_size as usize {
            return Err(LinuxError::EINVAL);
        }
        if let Some(k) = key {
            if k.len() != self.spec.key_size as usize {
                return Err(LinuxError::EINVAL);
            }
        }
        self.storage
            .read()
            .get_next_key(key, self.spec.max_entries as usize, next_key_out)
    }

    pub fn output_perf_event(&self, index: u32, data: &[u8]) -> Result<(), LinuxError> {
        if let BpfMapStorage::PerfEventArray { slots, .. } = &*self.storage.read() {
            let slot = slots.get(index as usize).and_then(|s| s.as_ref()).ok_or(LinuxError::ENOENT)?;
            slot.output_sample(data)
        } else {
            Err(LinuxError::EINVAL)
        }
    }

    pub fn get_slot(&self, index: u32) -> Option<Arc<dyn PerfEventOutputSink>> {
        if let BpfMapStorage::PerfEventArray { slots, .. } = &*self.storage.read() {
            slots.get(index as usize).cloned().flatten()
        } else {
            None
        }
    }

    pub fn set_slot(
        &self,
        index: u32,
        fd: Option<u32>,
        slot: Option<Arc<dyn PerfEventOutputSink>>,
    ) -> Result<(), LinuxError> {
        if let BpfMapStorage::PerfEventArray { slots, fds } = &mut *self.storage.write() {
            let idx = index as usize;
            if idx >= self.spec.max_entries as usize {
                return Err(LinuxError::E2BIG);
            }
            fds[idx] = fd;
            slots[idx] = slot;
            Ok(())
        } else {
            Err(LinuxError::EINVAL)
        }
    }

    pub fn info(&self) -> BpfMapInfo {
        BpfMapInfo {
            map_type: self.spec.map_type.as_raw(),
            id: self.id,
            key_size: self.spec.key_size,
            value_size: self.spec.value_size,
            max_entries: self.spec.max_entries,
            map_flags: self.spec.map_flags,
            name: self.spec.name,
            ..BpfMapInfo::default()
        }
    }
}

fn alloc_map_id() -> u32 {
    loop {
        let id = NEXT_MAP_ID.fetch_add(1, Ordering::Relaxed);
        if id != 0 {
            return id;
        }
    }
}

/// Linux `struct bpf_map_info`.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BpfMapInfo {
    pub map_type: u32,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub ifindex: u32,
    pub btf_vmlinux_value_type_id: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub btf_id: u32,
    pub btf_key_type_id: u32,
    pub btf_value_type_id: u32,
    pub _pad: u32,
    pub map_extra: u64,
}

const _: () = assert!(core::mem::size_of::<BpfMapInfo>() == 88);

impl BpfMapInfo {
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: `BpfMapInfo` is `repr(C)` with only integer fields and an
        // explicit padding field, so every byte is initialized.
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
