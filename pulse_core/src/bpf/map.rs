//! BPF Map metadata, validation and bounded storage.
//!
//! This file is the pure part of the BPF object model: it only depends on
//! `core`, `alloc` and `axerrno`, so `pulse_syscalls` host tests can compile it
//! directly. Kernel-only glue (the descriptor object) lives in `object.rs`.

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use axerrno::LinuxError;

pub const BPF_OBJ_NAME_LEN: usize = 16;

pub const BPF_MAP_TYPE_HASH: u32 = 1;
pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
/// Last Linux map type known to this ABI (`BPF_MAP_TYPE_ARENA`).
const BPF_MAP_TYPE_LINUX_MAX: u32 = 33;

pub const BPF_F_NO_PREALLOC: u32 = 1 << 0;
pub const BPF_F_RDONLY_PROG: u32 = 1 << 7;
pub const BPF_F_WRONLY_PROG: u32 = 1 << 8;

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
}

impl BpfMapType {
    pub fn from_raw(raw: u32) -> Result<Self, LinuxError> {
        match raw {
            BPF_MAP_TYPE_HASH => Ok(Self::Hash),
            BPF_MAP_TYPE_ARRAY => Ok(Self::Array),
            0 => Err(LinuxError::EINVAL),
            raw if raw <= BPF_MAP_TYPE_LINUX_MAX => Err(LinuxError::EOPNOTSUPP),
            _ => Err(LinuxError::EINVAL),
        }
    }

    pub const fn as_raw(self) -> u32 {
        match self {
            Self::Hash => BPF_MAP_TYPE_HASH,
            Self::Array => BPF_MAP_TYPE_ARRAY,
        }
    }

    const fn allowed_flags(self) -> u32 {
        match self {
            Self::Hash => BPF_F_NO_PREALLOC | BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG,
            Self::Array => BPF_F_RDONLY_PROG | BPF_F_WRONLY_PROG,
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
            BpfMapType::Array => req.key_size == 4,
            BpfMapType::Hash => req.key_size != 0,
        };
        if !key_ok || req.value_size == 0 || req.max_entries == 0 {
            return Err(LinuxError::EINVAL);
        }
        if req.key_size > BPF_MAP_MAX_KEY_SIZE || req.value_size > BPF_MAP_MAX_VALUE_SIZE {
            return Err(LinuxError::E2BIG);
        }

        let entry_bytes = match map_type {
            BpfMapType::Array => req.value_size as usize,
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

enum BpfMapStorage {
    /// Preallocated, zero-initialized `max_entries * value_size` bytes.
    Array(Vec<u8>),
    /// Holds at most `max_entries` elements; element operations land with the
    /// Map element control plane.
    #[allow(dead_code)]
    Hash(BTreeMap<Vec<u8>, Vec<u8>>),
}

/// A BPF Map object. Its lifetime is owned by `Arc` references held by
/// descriptors (and, later, Programs); dropping the last one frees storage
/// and releases the budget charge.
pub struct BpfMap {
    id: u32,
    spec: BpfMapSpec,
    storage: BpfMapStorage,
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
        };
        Ok(Self {
            id: alloc_map_id(),
            spec,
            storage,
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
        match &self.storage {
            BpfMapStorage::Array(values) => values.len() / self.spec.value_size as usize,
            BpfMapStorage::Hash(_) => self.spec.max_entries as usize,
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
