//! BPF Program model and immutable instruction storage.

use alloc::{sync::Arc, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use axerrno::LinuxError;

use super::{
    insn::BpfInsn,
    interpreter::{self, BpfEnv, BpfVmError, DefaultBpfEnv},
    map::BpfMap,
    BPF_OBJ_NAME_LEN,
};

static NEXT_PROG_ID: AtomicU32 = AtomicU32::new(1);

pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 5;
pub const BPF_PROG_TYPE_PERF_EVENT: u32 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum BpfProgType {
    Tracepoint = BPF_PROG_TYPE_TRACEPOINT,
    PerfEvent = BPF_PROG_TYPE_PERF_EVENT,
}

impl BpfProgType {
    pub fn from_raw(raw: u32) -> Result<Self, LinuxError> {
        match raw {
            BPF_PROG_TYPE_TRACEPOINT => Ok(Self::Tracepoint),
            BPF_PROG_TYPE_PERF_EVENT => Ok(Self::PerfEvent),
            _ => Err(LinuxError::EINVAL),
        }
    }

    pub const fn as_raw(self) -> u32 {
        self as u32
    }
}

pub struct BpfProgram {
    id: u32,
    prog_type: BpfProgType,
    name: [u8; BPF_OBJ_NAME_LEN],
    insns: Arc<[BpfInsn]>,
    referenced_maps: Vec<Arc<BpfMap>>,
    run_cnt: AtomicU64,
    runtime_errors: AtomicU64,
}

impl BpfProgram {
    pub fn new(
        prog_type: BpfProgType,
        name: [u8; BPF_OBJ_NAME_LEN],
        insns: Arc<[BpfInsn]>,
        referenced_maps: Vec<Arc<BpfMap>>,
    ) -> Self {
        let id = NEXT_PROG_ID.fetch_add(1, Ordering::Relaxed);
        Self {
            id,
            prog_type,
            name,
            insns,
            referenced_maps,
            run_cnt: AtomicU64::new(0),
            runtime_errors: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    pub fn id(&self) -> u32 {
        self.id
    }

    #[inline(always)]
    pub fn prog_type(&self) -> BpfProgType {
        self.prog_type
    }

    #[inline(always)]
    pub fn name(&self) -> &[u8; BPF_OBJ_NAME_LEN] {
        &self.name
    }

    #[inline(always)]
    pub fn insns(&self) -> &Arc<[BpfInsn]> {
        &self.insns
    }

    #[inline(always)]
    pub fn referenced_maps(&self) -> &[Arc<BpfMap>] {
        &self.referenced_maps
    }

    #[inline(always)]
    pub fn run_cnt(&self) -> u64 {
        self.run_cnt.load(Ordering::Relaxed)
    }

    #[inline(always)]
    pub fn runtime_errors(&self) -> u64 {
        self.runtime_errors.load(Ordering::Relaxed)
    }

    pub fn run(&self, context: &[u8]) -> Result<u64, BpfVmError> {
        self.run_with_env(context, &DefaultBpfEnv)
    }

    pub fn run_with_env(&self, context: &[u8], env: &dyn BpfEnv) -> Result<u64, BpfVmError> {
        self.run_cnt.fetch_add(1, Ordering::Relaxed);
        match interpreter::execute(&self.insns, &self.referenced_maps, context, env) {
            Ok(ret) => Ok(ret),
            Err(e) => {
                self.runtime_errors.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    pub fn info(&self) -> BpfProgInfo {
        let mut info = BpfProgInfo::default();
        info.prog_type = self.prog_type.as_raw();
        info.id = self.id;
        info.name = self.name;
        info.xlated_prog_len = (self.insns.len() * core::mem::size_of::<BpfInsn>()) as u32;
        info.nr_map_ids = self.referenced_maps.len() as u32;
        info.run_cnt = self.run_cnt.load(Ordering::Relaxed);
        info
    }
}

#[repr(C, align(8))]
#[derive(Clone, Copy, Debug, Default)]
pub struct BpfProgInfo {
    pub prog_type: u32,
    pub id: u32,
    pub tag: [u8; 8],
    pub jited_prog_len: u32,
    pub xlated_prog_len: u32,
    pub jited_prog_insns: u64,
    pub xlated_prog_insns: u64,
    pub load_time: u64,
    pub created_by_uid: u32,
    pub nr_map_ids: u32,
    pub map_ids: u64,
    pub name: [u8; BPF_OBJ_NAME_LEN],
    pub ifindex: u32,
    pub gpl_compatible: u32,
    pub netns_dev: u64,
    pub netns_ino: u64,
    pub nr_jited_ksyms: u32,
    pub nr_jited_func_lens: u32,
    pub jited_ksyms: u64,
    pub jited_func_lens: u64,
    pub btf_id: u32,
    pub func_info_rec_size: u32,
    pub func_info: u64,
    pub nr_func_info: u32,
    pub nr_line_info: u32,
    pub line_info: u64,
    pub jited_line_info: u64,
    pub nr_jited_line_info: u32,
    pub line_info_rec_size: u32,
    pub jited_line_info_rec_size: u32,
    pub nr_prog_tags: u32,
    pub prog_tags: u64,
    pub run_time_ns: u64,
    pub run_cnt: u64,
    pub recursion_misses: u64,
    pub count: u32,
    pub verified_insns: u32,
}

impl BpfProgInfo {
    pub fn as_bytes(&self) -> &[u8] {
        unsafe {
            core::slice::from_raw_parts(
                self as *const Self as *const u8,
                core::mem::size_of::<Self>(),
            )
        }
    }
}
