use alloc::{collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicI32, Ordering};

use spin::Lazy;
use crate::sync::Mutex;

const UNCONSTRAINED_LATENCY_US: i32 = i32::MAX;

#[derive(Default)]
struct CpuDmaLatencyState {
    next_id: u64,
    requests: BTreeMap<u64, i32>,
}

impl CpuDmaLatencyState {
    fn effective_value(&self) -> i32 {
        self.requests
            .values()
            .copied()
            .min()
            .unwrap_or(UNCONSTRAINED_LATENCY_US)
    }
}

static CPU_DMA_LATENCY_STATE: Lazy<Mutex<CpuDmaLatencyState>> =
    Lazy::new(|| Mutex::new(CpuDmaLatencyState::default()));
static CPU_DMA_LATENCY_EFFECTIVE: AtomicI32 = AtomicI32::new(UNCONSTRAINED_LATENCY_US);

fn apply_effective_latency(value: i32) {
    CPU_DMA_LATENCY_EFFECTIVE.store(value, Ordering::Release);
}

pub fn effective_latency_us() -> i32 {
    CPU_DMA_LATENCY_EFFECTIVE.load(Ordering::Acquire)
}

pub struct CpuDmaLatencyRequest {
    id: u64,
}

impl CpuDmaLatencyRequest {
    pub fn new() -> Arc<Self> {
        let (id, effective) = {
            let mut state = CPU_DMA_LATENCY_STATE.lock();
            let id = state.next_id;
            state.next_id = state.next_id.wrapping_add(1);
            state.requests.insert(id, UNCONSTRAINED_LATENCY_US);
            (id, state.effective_value())
        };
        apply_effective_latency(effective);
        Arc::new(Self { id })
    }

    pub fn set_target_us(&self, value: i32) {
        let effective = {
            let mut state = CPU_DMA_LATENCY_STATE.lock();
            if let Some(slot) = state.requests.get_mut(&self.id) {
                *slot = value;
            } else {
                return;
            }
            state.effective_value()
        };
        apply_effective_latency(effective);
    }
}

impl Drop for CpuDmaLatencyRequest {
    fn drop(&mut self) {
        let effective = {
            let mut state = CPU_DMA_LATENCY_STATE.lock();
            state.requests.remove(&self.id);
            state.effective_value()
        };
        apply_effective_latency(effective);
    }
}
