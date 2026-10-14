//! BPF Link model and link metadata (#98).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use axerrno::LinuxError;

use super::{
    perf_event::{
        register_active_perf_event, unregister_active_perf_event, PerfEvent, PerfEventClock,
        PERF_COUNT_SW_CPU_CLOCK, PERF_COUNT_SW_TASK_CLOCK, PERF_COUNT_SW_BPF_OUTPUT,
        PERF_TYPE_SOFTWARE, PERF_TYPE_TRACEPOINT,
    },
    program::BpfProgram,
};

static NEXT_LINK_ID: AtomicU32 = AtomicU32::new(1);

pub const BPF_LINK_TYPE_PERF_EVENT: u32 = 7;

pub const BPF_PERF_EVENT_TRACEPOINT: u32 = 5;
pub const BPF_PERF_EVENT_EVENT: u32 = 6;

pub const BPF_PERF_EVENT: u32 = 41;

/// Discover a tracepoint ID from a category/name pair (e.g. "sched/sched_switch") or event name (#98).
pub fn discover_tracepoint(category_or_name: &str) -> Result<pulse_bpf_schema::TracepointId, LinuxError> {
    if let Some((cat, name)) = category_or_name.split_once('/') {
        pulse_bpf_schema::lookup_by_name(cat, name)
            .map(|meta| meta.id)
            .map_err(|_| LinuxError::ENOENT)
    } else {
        for tp in pulse_bpf_schema::all_tracepoints() {
            if tp.name == category_or_name {
                return Ok(tp.id);
            }
        }
        Err(LinuxError::ENOENT)
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BpfLinkInfo {
    pub link_type: u32,
    pub id: u32,
    pub prog_id: u32,
    pub _pad: u32,
    pub perf_event_type: u32,
    pub _pad2: u32,
    pub config: u64,
    pub event_type: u32,
    pub _pad3: u32,
    pub extra: [u8; 24],
}

impl BpfLinkInfo {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}

pub struct BpfLink {
    id: u32,
    link_type: u32,
    prog: Arc<BpfProgram>,
    target: Arc<PerfEvent>,
    detached: AtomicBool,
}

impl BpfLink {
    pub fn new(prog: Arc<BpfProgram>, target: Arc<PerfEvent>) -> Result<Arc<Self>, LinuxError> {
        target.attach_program(prog.clone())?;
        register_active_perf_event(&target);
        let id = NEXT_LINK_ID.fetch_add(1, Ordering::Relaxed);
        Ok(Arc::new(Self {
            id,
            link_type: BPF_LINK_TYPE_PERF_EVENT,
            prog,
            target,
            detached: AtomicBool::new(false),
        }))
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn link_type(&self) -> u32 {
        self.link_type
    }

    pub fn prog(&self) -> &Arc<BpfProgram> {
        &self.prog
    }

    pub fn target(&self) -> &Arc<PerfEvent> {
        &self.target
    }

    pub fn is_detached(&self) -> bool {
        self.detached.load(Ordering::Acquire)
    }

    pub fn detach(&self) -> Result<(), LinuxError> {
        if self.detached.swap(true, Ordering::AcqRel) {
            return Err(LinuxError::EINVAL);
        }
        unregister_active_perf_event(&self.target);
        self.target.detach_program(&self.prog)?;
        Ok(())
    }

    pub fn info(&self) -> BpfLinkInfo {
        let (perf_event_type, config, event_type) = match self.target.spec().clock {
            PerfEventClock::CpuClock => (
                BPF_PERF_EVENT_EVENT,
                PERF_COUNT_SW_CPU_CLOCK,
                PERF_TYPE_SOFTWARE,
            ),
            PerfEventClock::TaskClock => (
                BPF_PERF_EVENT_EVENT,
                PERF_COUNT_SW_TASK_CLOCK,
                PERF_TYPE_SOFTWARE,
            ),
            PerfEventClock::Tracepoint(tp_id) => (
                BPF_PERF_EVENT_TRACEPOINT,
                tp_id.as_u32() as u64,
                PERF_TYPE_TRACEPOINT,
            ),
            PerfEventClock::BpfOutput => (
                BPF_PERF_EVENT_EVENT,
                PERF_COUNT_SW_BPF_OUTPUT,
                PERF_TYPE_SOFTWARE,
            ),
        };
        let mut info = BpfLinkInfo::default();
        info.link_type = self.link_type;
        info.id = self.id;
        info.prog_id = self.prog.id();
        info.perf_event_type = perf_event_type;
        info.config = config;
        info.event_type = event_type;
        info
    }
}

impl Drop for BpfLink {
    fn drop(&mut self) {
        let _ = self.detach();
    }
}
