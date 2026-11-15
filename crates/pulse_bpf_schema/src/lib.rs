#![no_std]

pub mod stack;
pub use stack::{
    DEFAULT_STACK_BYTE_LIMIT, DEFAULT_STACK_DEPTH, FrozenStack, MAX_STACK_DEPTH,
    PerfStackSampleContext, StackDecodeError, StackLimits, StackRegisters, StackStatus,
    walk_frame_pointers,
};

/// Epoch shared by IRQ snapshots, tracepoint producers and event control.
static OBSERVATION_GENERATION: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(1);

pub fn observation_generation() -> u64 {
    OBSERVATION_GENERATION.load(core::sync::atomic::Ordering::Acquire)
}

/// Epoch exhaustion fails closed: consumers must reject u64::MAX.
pub fn advance_observation_generation() -> u64 {
    use core::sync::atomic::Ordering;
    match OBSERVATION_GENERATION.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| value.checked_add(1)) {
        Ok(previous) => previous + 1,
        Err(_) => u64::MAX,
    }
}

/// Tracepoint identifier for BPF v1 semantic events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u32)]
pub enum TracepointId {
    TaskMetadata = 1,
    SchedSwitch  = 2,
    TaskBlock    = 3,
    TaskWake     = 4,
    TaskExit     = 5,
    TaskEnqueue  = 6,
    PhaseMarker  = 7,
    PageFault    = 8,
}

impl TracepointId {
    pub const ALL: [TracepointId; 8] = [
        TracepointId::TaskMetadata,
        TracepointId::SchedSwitch,
        TracepointId::TaskBlock,
        TracepointId::TaskWake,
        TracepointId::TaskExit,
        TracepointId::TaskEnqueue,
        TracepointId::PhaseMarker,
        TracepointId::PageFault,
    ];

    #[inline]
    pub const fn as_u32(self) -> u32 {
        self as u32
    }

    pub const fn from_u32(raw: u32) -> Result<Self, TracepointError> {
        match raw {
            1 => Ok(Self::TaskMetadata),
            2 => Ok(Self::SchedSwitch),
            3 => Ok(Self::TaskBlock),
            4 => Ok(Self::TaskWake),
            5 => Ok(Self::TaskExit),
            6 => Ok(Self::TaskEnqueue),
            7 => Ok(Self::PhaseMarker),
            8 => Ok(Self::PageFault),
            100..=105 => Err(TracepointError::DeferredId(raw)),
            _ => Err(TracepointError::UnknownId(raw)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PhaseBoundary {
    Begin = 1,
    End   = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum EnqueueReason {
    Spawn             = 1,
    Wake              = 2,
    Preempt           = 3,
    Yield             = 4,
    AffinityMigration = 5,
    DeferredWake      = 6,
    WorkSteal         = 7,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldType {
    U8,
    U16,
    U32,
    U64,
    I32,
    I64,
    ByteArray(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldMetadata {
    pub name: &'static str,
    pub offset: usize,
    pub size: usize,
    pub field_type: FieldType,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TracepointMetadata {
    pub id: TracepointId,
    pub category: &'static str,
    pub name: &'static str,
    pub version: u32,
    pub endianness: Endianness,
    pub context_size: usize,
    pub fields: &'static [FieldMetadata],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TracepointError {
    UnknownId(u32),
    UnknownName,
    DeferredId(u32),
}

// -----------------------------------------------------------------------------
// Versioned Context Structs (repr(C), scalar-only, no internal pointers)
// -----------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContextCommon {
    pub event_id: u32,
    pub version: u32,
    pub timestamp_ns: u64,
    pub cpu_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub _reserved: u32,
    pub task_id: u64,
}

impl ContextCommon {
    pub const fn new(event_id: TracepointId, timestamp_ns: u64, cpu_id: u32, pid: u32, tid: u32, task_id: u64) -> Self {
        Self {
            event_id: event_id as u32,
            version: 1,
            timestamp_ns,
            cpu_id,
            pid,
            tid,
            _reserved: 0,
            task_id,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskMetadataContext {
    pub common: ContextCommon,
    pub target_task_id: u64,
    pub target_pid: u32,
    pub target_tid: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SchedSwitchContext {
    pub common: ContextCommon,
    pub prev_task_id: u64,
    pub next_task_id: u64,
    pub prev_state: u32,
    pub prev_prio: u32,
    pub next_prio: u32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskBlockContext {
    pub common: ContextCommon,
    pub block_sequence: u64,
    pub wait_reason: u32,
    pub _pad: u32,
    pub resource_id: u64,
    pub resource_detail: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskWakeContext {
    pub common: ContextCommon,
    pub target_task_id: u64,
    pub block_sequence: u64,
    pub waker_task_id: u64,
    pub wake_source: u32,
    pub _pad: u32,
    pub source_id: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskExitContext {
    pub common: ContextCommon,
    pub exit_task_id: u64,
    pub exit_code: i32,
    pub _pad: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TaskEnqueueContext {
    pub common: ContextCommon,
    pub enqueue_task_id: u64,
    pub enqueue_cpu: u32,
    pub target_cpu: u32,
    pub queue_depth: u32,
    pub enqueue_reason: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PhaseMarkerContext {
    pub common: ContextCommon,
    pub phase_boundary: u32,
    pub phase_len: u32,
    pub phase_name: [u8; 16],
}

/// Access bits are an independent observation ABI, not raw MappingFlags bits.
pub struct PageFaultAccess;
impl PageFaultAccess {
    /// Architecture did not identify READ/WRITE/EXECUTE (e.g. LA privilege fault).
    pub const UNKNOWN: u32 = 0;
    pub const READ: u32 = 1;
    pub const WRITE: u32 = 2;
    pub const EXECUTE: u32 = 4;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PageFaultOrigin {
    Kernel = 1,
    User   = 2,
}

/// Result of the address-space resolver, before trap signal/fixup handling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PageFaultOutcome {
    Resolved      = 1,
    NotHandled    = 2,
    NoMemory      = 3,
    ResolverError = 4,
}

/// Linux-style minor/major classification requires actual I/O provenance.
/// Current PulseOS producers always emit Unknown; the other tags reserve an
/// explicit extension that cannot be inferred from latency or backing type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PageFaultClassification {
    Unknown = 0,
    Minor   = 1,
    Major   = 2,
}

/// One returned resolver call. `common` identifies the faulting task and the
/// completion CPU/time. Wall duration includes any waits or descheduling.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageFaultContext {
    pub common: ContextCommon,
    pub fault_address: u64,
    pub start_ns: u64,
    pub elapsed_ns: u64,
    pub access: u32,
    pub origin: u32,
    pub outcome: u32,
    pub classification: u32,
}

impl PageFaultContext {
    /// Construct an unknown-I/O-classification completion from measured times.
    /// A regressed clock cannot be represented as a zero-duration success.
    pub fn from_completion(
        common: ContextCommon,
        fault_address: u64,
        start_ns: u64,
        access: u32,
        origin: PageFaultOrigin,
        outcome: PageFaultOutcome,
    ) -> Option<Self> {
        let elapsed_ns = common.timestamp_ns.checked_sub(start_ns)?;
        Some(Self {
            common,
            fault_address,
            start_ns,
            elapsed_ns,
            access,
            origin: origin as u32,
            outcome: outcome as u32,
            classification: PageFaultClassification::Unknown as u32,
        })
    }

    /// Explicit little-endian encoding; does not inspect struct padding.
    pub fn to_bytes(&self) -> [u8; 80] {
        let mut bytes = [0u8; 80];
        bytes[0..4].copy_from_slice(&self.common.event_id.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.common.version.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.common.timestamp_ns.to_le_bytes());
        bytes[16..20].copy_from_slice(&self.common.cpu_id.to_le_bytes());
        bytes[20..24].copy_from_slice(&self.common.pid.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.common.tid.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.common._reserved.to_le_bytes());
        bytes[32..40].copy_from_slice(&self.common.task_id.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.fault_address.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.start_ns.to_le_bytes());
        bytes[56..64].copy_from_slice(&self.elapsed_ns.to_le_bytes());
        bytes[64..68].copy_from_slice(&self.access.to_le_bytes());
        bytes[68..72].copy_from_slice(&self.origin.to_le_bytes());
        bytes[72..76].copy_from_slice(&self.outcome.to_le_bytes());
        bytes[76..80].copy_from_slice(&self.classification.to_le_bytes());
        bytes
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfEventContext {
    pub sample_period: u64,
    pub addr: u64,
    pub timestamp_ns: u64,
    pub cpu_id: u32,
    pub pid: u32,
    pub tid: u32,
    pub _reserved: u32,
    pub task_id: u64,
}

impl PerfEventContext {
    pub const fn new(
        sample_period: u64,
        addr: u64,
        timestamp_ns: u64,
        cpu_id: u32,
        pid: u32,
        tid: u32,
        task_id: u64,
    ) -> Self {
        Self {
            sample_period,
            addr,
            timestamp_ns,
            cpu_id,
            pid,
            tid,
            _reserved: 0,
            task_id,
        }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

/// PulseOS software-sample v2; the first 48 bytes preserve the v1 context.
/// IP and perf KERNEL=1/USER=2 mode are appended; version=2 is at byte 60.
/// The data-address field in the v1 prefix is never repurposed as an IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfSampleContext {
    pub base: PerfEventContext,
    pub ip: u64,
    pub mode: u32,
    pub version: u32,
}

impl PerfSampleContext {
    pub const SIZE: usize = 64;

    /// Explicit little-endian encoding without Rust layout or padding bytes.
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..8].copy_from_slice(&self.base.sample_period.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.base.addr.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.base.timestamp_ns.to_le_bytes());
        bytes[24..28].copy_from_slice(&self.base.cpu_id.to_le_bytes());
        bytes[28..32].copy_from_slice(&self.base.pid.to_le_bytes());
        bytes[32..36].copy_from_slice(&self.base.tid.to_le_bytes());
        bytes[40..48].copy_from_slice(&self.base.task_id.to_le_bytes());
        bytes[48..56].copy_from_slice(&self.ip.to_le_bytes());
        bytes[56..60].copy_from_slice(&self.mode.to_le_bytes());
        bytes[60..64].copy_from_slice(&self.version.to_le_bytes());
        bytes
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PerfEventSampleCounters {
    pub delivered_samples: u64,
    pub re_entry_drops: u64,
    pub helper_failures: u64,
    pub budget_failures: u64,
}


// -----------------------------------------------------------------------------
// Field Metadata Tables
// -----------------------------------------------------------------------------

macro_rules! define_tp_fields {
    ($name:ident, $len:expr, [ $($extra:expr),* $(,)? ]) => {
        static $name: [FieldMetadata; $len] = [
            FieldMetadata { name: "event_id", offset: 0, size: 4, field_type: FieldType::U32 },
            FieldMetadata { name: "version", offset: 4, size: 4, field_type: FieldType::U32 },
            FieldMetadata { name: "timestamp_ns", offset: 8, size: 8, field_type: FieldType::U64 },
            FieldMetadata { name: "cpu_id", offset: 16, size: 4, field_type: FieldType::U32 },
            FieldMetadata { name: "pid", offset: 20, size: 4, field_type: FieldType::U32 },
            FieldMetadata { name: "tid", offset: 24, size: 4, field_type: FieldType::U32 },
            FieldMetadata { name: "_reserved", offset: 28, size: 4, field_type: FieldType::U32 },
            FieldMetadata { name: "task_id", offset: 32, size: 8, field_type: FieldType::U64 },
            $($extra),*
        ];
    };
}

define_tp_fields!(
    TASK_METADATA_FIELDS,
    12,
    [
        FieldMetadata { name: "target_task_id", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "target_pid", offset: 48, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "target_tid", offset: 52, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "comm", offset: 56, size: 16, field_type: FieldType::ByteArray(16) },
    ]
);

define_tp_fields!(
    SCHED_SWITCH_FIELDS,
    14,
    [
        FieldMetadata { name: "prev_task_id", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "next_task_id", offset: 48, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "prev_state", offset: 56, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "prev_prio", offset: 60, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "next_prio", offset: 64, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "_pad", offset: 68, size: 4, field_type: FieldType::U32 },
    ]
);

define_tp_fields!(
    TASK_BLOCK_FIELDS,
    13,
    [
        FieldMetadata { name: "block_sequence", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "wait_reason", offset: 48, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "_pad", offset: 52, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "resource_id", offset: 56, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "resource_detail", offset: 64, size: 8, field_type: FieldType::U64 },
    ]
);

define_tp_fields!(
    TASK_WAKE_FIELDS,
    14,
    [
        FieldMetadata { name: "target_task_id", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "block_sequence", offset: 48, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "waker_task_id", offset: 56, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "wake_source", offset: 64, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "_pad", offset: 68, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "source_id", offset: 72, size: 8, field_type: FieldType::U64 },
    ]
);

define_tp_fields!(
    TASK_EXIT_FIELDS,
    11,
    [
        FieldMetadata { name: "exit_task_id", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "exit_code", offset: 48, size: 4, field_type: FieldType::I32 },
        FieldMetadata { name: "_pad", offset: 52, size: 4, field_type: FieldType::U32 },
    ]
);

define_tp_fields!(
    TASK_ENQUEUE_FIELDS,
    13,
    [
        FieldMetadata { name: "enqueue_task_id", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "enqueue_cpu", offset: 48, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "target_cpu", offset: 52, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "queue_depth", offset: 56, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "enqueue_reason", offset: 60, size: 4, field_type: FieldType::U32 },
    ]
);

define_tp_fields!(
    PHASE_MARKER_FIELDS,
    11,
    [
        FieldMetadata { name: "phase_boundary", offset: 40, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "phase_len", offset: 44, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "phase_name", offset: 48, size: 16, field_type: FieldType::ByteArray(16) },
    ]
);

define_tp_fields!(
    PAGE_FAULT_FIELDS,
    15,
    [
        FieldMetadata { name: "fault_address", offset: 40, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "start_ns", offset: 48, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "elapsed_ns", offset: 56, size: 8, field_type: FieldType::U64 },
        FieldMetadata { name: "access", offset: 64, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "origin", offset: 68, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "outcome", offset: 72, size: 4, field_type: FieldType::U32 },
        FieldMetadata { name: "classification", offset: 76, size: 4, field_type: FieldType::U32 },
    ]
);

// -----------------------------------------------------------------------------
// Tracepoint Registry
// -----------------------------------------------------------------------------

static TRACEPOINTS: [TracepointMetadata; 8] = [
    TracepointMetadata {
        id: TracepointId::TaskMetadata,
        category: "task",
        name: "task_metadata",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<TaskMetadataContext>(),
        fields: &TASK_METADATA_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::SchedSwitch,
        category: "sched",
        name: "sched_switch",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<SchedSwitchContext>(),
        fields: &SCHED_SWITCH_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::TaskBlock,
        category: "sched",
        name: "task_block",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<TaskBlockContext>(),
        fields: &TASK_BLOCK_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::TaskWake,
        category: "sched",
        name: "task_wake",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<TaskWakeContext>(),
        fields: &TASK_WAKE_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::TaskExit,
        category: "task",
        name: "task_exit",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<TaskExitContext>(),
        fields: &TASK_EXIT_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::TaskEnqueue,
        category: "sched",
        name: "task_enqueue",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<TaskEnqueueContext>(),
        fields: &TASK_ENQUEUE_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::PhaseMarker,
        category: "pulse",
        name: "phase_marker",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<PhaseMarkerContext>(),
        fields: &PHASE_MARKER_FIELDS,
    },
    TracepointMetadata {
        id: TracepointId::PageFault,
        category: "mm",
        name: "page_fault",
        version: 1,
        endianness: Endianness::Little,
        context_size: core::mem::size_of::<PageFaultContext>(),
        fields: &PAGE_FAULT_FIELDS,
    },
];

/// Look up tracepoint metadata by numeric ID.
pub fn lookup_by_id(id: u32) -> Result<&'static TracepointMetadata, TracepointError> {
    let tp_id = TracepointId::from_u32(id)?;
    let idx = (tp_id as usize) - 1;
    if idx < TRACEPOINTS.len() {
        Ok(&TRACEPOINTS[idx])
    } else {
        Err(TracepointError::UnknownId(id))
    }
}

/// Look up tracepoint metadata by category and event name.
pub fn lookup_by_name(category: &str, name: &str) -> Result<&'static TracepointMetadata, TracepointError> {
    for tp in &TRACEPOINTS {
        if tp.category == category && tp.name == name {
            return Ok(tp);
        }
    }
    Err(TracepointError::UnknownName)
}

/// Enumerate all supported tracepoints in the registry.
pub fn all_tracepoints() -> &'static [TracepointMetadata] {
    &TRACEPOINTS
}

/// Check if a tracepoint ID is deferred (reserved for future release / hardware PMU).
pub fn is_deferred_id(id: u32) -> bool {
    matches!(id, 100..=105)
}

/// Check if a tracepoint ID is supported in BPF v1.
pub fn is_supported_id(id: u32) -> bool {
    TracepointId::from_u32(id).is_ok()
}

// -----------------------------------------------------------------------------
// Bounded Event Record and Lock-Free Handoff Buffer
// -----------------------------------------------------------------------------

/// Maximum serialized context size across all supported tracepoints (TaskWakeContext is 80 bytes).
pub const MAX_CONTEXT_SIZE: usize = 80;

/// Bounded record representing a captured tracepoint event.
#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EventRecord {
    pub id: TracepointId,
    pub len: u32,
    /// Internal handoff metadata; not part of the BPF context byte slice.
    pub generation: u64,
    pub data: [u8; MAX_CONTEXT_SIZE],
}

impl EventRecord {
    pub const fn empty() -> Self {
        Self {
            id: TracepointId::TaskMetadata,
            len: 0,
            generation: 0,
            data: [0u8; MAX_CONTEXT_SIZE],
        }
    }

    pub fn new(id: TracepointId, slice: &[u8]) -> Self {
        let mut rec = Self::empty();
        rec.id = id;
        rec.generation = observation_generation();
        let copy_len = slice.len().min(MAX_CONTEXT_SIZE);
        rec.len = copy_len as u32;
        rec.data[..copy_len].copy_from_slice(&slice[..copy_len]);
        rec
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
}

/// Reason for dropping an event during nonblocking handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueueDropReason {
    /// Bounded queue was saturated (overflow).
    Full,
    /// Recursive or re-entrant tracepoint invocation detected on the same execution context.
    Recursive,
}

/// Drop and enqueue accounting statistics for bounded tracepoint delivery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DropStats {
    /// Count of events dropped because the buffer was full.
    pub dropped_full: u64,
    /// Count of events dropped because of re-entrant tracepoint execution.
    pub dropped_recursive: u64,
    /// Total count of events successfully enqueued.
    pub total_enqueued: u64,
}

/// Bounded, allocation-free, lock-free handoff queue for critical tracepoint paths.
pub struct BoundedTraceQueue<const CAP: usize> {
    head: core::sync::atomic::AtomicUsize,
    tail: core::sync::atomic::AtomicUsize,
    in_trace: core::sync::atomic::AtomicBool,
    in_drain: core::sync::atomic::AtomicBool,
    dropped_full: core::sync::atomic::AtomicU64,
    dropped_recursive: core::sync::atomic::AtomicU64,
    total_enqueued: core::sync::atomic::AtomicU64,
    slots: [core::cell::UnsafeCell<EventRecord>; CAP],
}

// SAFETY: `in_trace` serializes producers and `in_drain` serializes consumers.
// Release publication of head/tail and matching Acquire loads keep each slot's
// initialized record and reuse ordered; callbacks receive a local copy.
unsafe impl<const CAP: usize> Sync for BoundedTraceQueue<CAP> {}

struct DrainGuard<'a>(&'a core::sync::atomic::AtomicBool);

impl Drop for DrainGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, core::sync::atomic::Ordering::Release);
    }
}

impl<const CAP: usize> BoundedTraceQueue<CAP> {
    pub const fn new() -> Self {
        assert!(CAP.is_power_of_two(), "capacity must be a nonzero power of two");
        Self {
            head: core::sync::atomic::AtomicUsize::new(0),
            tail: core::sync::atomic::AtomicUsize::new(0),
            in_trace: core::sync::atomic::AtomicBool::new(false),
            in_drain: core::sync::atomic::AtomicBool::new(false),
            dropped_full: core::sync::atomic::AtomicU64::new(0),
            dropped_recursive: core::sync::atomic::AtomicU64::new(0),
            total_enqueued: core::sync::atomic::AtomicU64::new(0),
            slots: [const { core::cell::UnsafeCell::new(EventRecord::empty()) }; CAP],
        }
    }

    /// Enqueue an event in an allocation-free, nonblocking, non-recursive manner.
    #[inline]
    pub fn enqueue_bytes(&self, id: TracepointId, slice: &[u8]) -> Result<(), QueueDropReason> {
        self.enqueue_with_generation(id, slice, observation_generation())
    }

    /// Enqueue with the epoch captured before source fields were observed.
    pub fn enqueue_with_generation(&self, id: TracepointId, slice: &[u8], generation: u64) -> Result<(), QueueDropReason> {
        // Reentrancy guard: strictly bounded and non-recursive
        if self
            .in_trace
            .compare_exchange(
                false,
                true,
                core::sync::atomic::Ordering::Acquire,
                core::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            self.dropped_recursive
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return Err(QueueDropReason::Recursive);
        }

        let head = self.head.load(core::sync::atomic::Ordering::Relaxed);
        let tail = self.tail.load(core::sync::atomic::Ordering::Acquire);

        let res = if head.wrapping_sub(tail) >= CAP {
            self.dropped_full
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Err(QueueDropReason::Full)
        } else {
            let copy_len = slice.len().min(MAX_CONTEXT_SIZE);
            let mask = CAP - 1;
            let slot = &self.slots[head & mask];
            let record = unsafe { &mut *slot.get() };
            record.id = id;
            record.generation = generation;
            record.len = copy_len as u32;
            record.data[..copy_len].copy_from_slice(&slice[..copy_len]);
            self.head
                .store(head.wrapping_add(1), core::sync::atomic::Ordering::Release);
            self.total_enqueued
                .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            Ok(())
        };

        self.in_trace
            .store(false, core::sync::atomic::Ordering::Release);
        res
    }

    /// Drain up to `max_count` events, invoking `consumer` for each.
    pub fn drain<F: FnMut(TracepointId, &[u8])>(&self, max_count: usize, mut consumer: F) -> usize {
        self.drain_with_generation(max_count, |id, bytes, _generation| consumer(id, bytes))
    }

    /// Drain preserved context bytes together with their original epoch.
    pub fn drain_with_generation<F: FnMut(TracepointId, &[u8], u64)>(&self, max_count: usize, mut consumer: F) -> usize {
        use core::sync::atomic::Ordering;
        if self.in_drain.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            return 0;
        }
        let _guard = DrainGuard(&self.in_drain);
        let mut drained = 0;
        let mut tail = self.tail.load(Ordering::Relaxed);
        let head = self.head.load(Ordering::Acquire);
        let mask = CAP - 1;

        while tail != head && drained < max_count {
            let slot = &self.slots[tail & mask];
            let record = unsafe { *slot.get() };
            tail = tail.wrapping_add(1);
            self.tail.store(tail, Ordering::Release);
            drained += 1;
            consumer(record.id, record.as_bytes(), record.generation);
        }
        drained
    }

    /// Query drop and enqueue statistics.
    pub fn drop_stats(&self) -> DropStats {
        DropStats {
            dropped_full: self.dropped_full.load(core::sync::atomic::Ordering::Relaxed),
            dropped_recursive: self
                .dropped_recursive
                .load(core::sync::atomic::Ordering::Relaxed),
            total_enqueued: self
                .total_enqueued
                .load(core::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Reset drop statistics.
    pub fn reset_drop_stats(&self) {
        self.dropped_full
            .store(0, core::sync::atomic::Ordering::Relaxed);
        self.dropped_recursive
            .store(0, core::sync::atomic::Ordering::Relaxed);
        self.total_enqueued
            .store(0, core::sync::atomic::Ordering::Relaxed);
    }

    /// Check if reentrancy flag is currently set (for testing / diagnostics).
    #[doc(hidden)]
    pub fn is_in_trace(&self) -> bool {
        self.in_trace.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Simulate setting the reentrancy flag (for testing).
    #[doc(hidden)]
    pub fn set_in_trace_for_test(&mut self, val: bool) {
        self.in_trace
            .store(val, core::sync::atomic::Ordering::Relaxed);
    }
}

// -----------------------------------------------------------------------------
// Static Assertions for Critical Path Guarantees
// -----------------------------------------------------------------------------

const _: () = {
    assert!(core::mem::size_of::<ContextCommon>() == 40);
    assert!(core::mem::align_of::<ContextCommon>() == 8);

    assert!(core::mem::size_of::<TaskMetadataContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<SchedSwitchContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskBlockContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskWakeContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskExitContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<TaskEnqueueContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<PhaseMarkerContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<PageFaultContext>() == 80);
    assert!(core::mem::size_of::<PageFaultContext>() <= MAX_CONTEXT_SIZE);
    assert!(core::mem::size_of::<PerfEventContext>() == 48);
    assert!(core::mem::align_of::<PerfEventContext>() == 8);
    assert!(core::mem::size_of::<PerfEventContext>() <= MAX_CONTEXT_SIZE);

    assert!(core::mem::size_of::<EventRecord>() == 96);
    assert!(core::mem::align_of::<EventRecord>() == 8);
};
