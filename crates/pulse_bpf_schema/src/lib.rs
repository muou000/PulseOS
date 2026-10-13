#![no_std]

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
}

impl TracepointId {
    pub const ALL: [TracepointId; 7] = [
        TracepointId::TaskMetadata,
        TracepointId::SchedSwitch,
        TracepointId::TaskBlock,
        TracepointId::TaskWake,
        TracepointId::TaskExit,
        TracepointId::TaskEnqueue,
        TracepointId::PhaseMarker,
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

// -----------------------------------------------------------------------------
// Tracepoint Registry
// -----------------------------------------------------------------------------

static TRACEPOINTS: [TracepointMetadata; 7] = [
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
