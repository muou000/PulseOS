//! Perf Event core model, metadata and accounting lifecycle (#97).
//!
//! This file is the pure part of the PerfEvent subsystem: it only depends on
//! `core`, `alloc`, `spin` and `axerrno`, so `pulse_syscalls` host tests can compile
//! it directly. Descriptor wrapping (`PerfEventObject: FdObject`) lives in `object.rs`.

use axerrno::LinuxError;

pub const PERF_EVENT_IOC_ENABLE: u32 = 0x2400;
pub const PERF_EVENT_IOC_DISABLE: u32 = 0x2401;
pub const PERF_EVENT_IOC_REFRESH: u32 = 0x2402;
pub const PERF_EVENT_IOC_RESET: u32 = 0x2403;
pub const PERF_EVENT_IOC_PERIOD: u32 = 0x40082404;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerfEventClock {
    CpuClock,
    TaskClock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PerfEventScope {
    PerCpu { cpu: usize },
    Task { pid: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PerfEventSpec {
    pub clock: PerfEventClock,
    pub scope: PerfEventScope,
    pub sample_period: u64,
    pub disabled: bool,
    pub cloexec: bool,
}

#[derive(Debug)]
struct PerfEventState {
    enabled: bool,
    accumulated_ns: u64,
    last_enabled_ns: u64,
    sample_period: u64,
}

pub struct PerfEvent {
    spec: PerfEventSpec,
    state: spin::Mutex<PerfEventState>,
}

impl PerfEvent {
    pub fn new(spec: PerfEventSpec, now_ns: u64) -> Self {
        let enabled = !spec.disabled;
        let last_enabled_ns = if enabled { now_ns } else { 0 };
        Self {
            spec,
            state: spin::Mutex::new(PerfEventState {
                enabled,
                accumulated_ns: 0,
                last_enabled_ns,
                sample_period: spec.sample_period,
            }),
        }
    }

    pub fn spec(&self) -> &PerfEventSpec {
        &self.spec
    }

    pub fn is_enabled(&self) -> bool {
        self.state.lock().enabled
    }

    pub fn sample_period(&self) -> u64 {
        self.state.lock().sample_period
    }

    pub fn enable_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        if !state.enabled {
            state.enabled = true;
            state.last_enabled_ns = now_ns;
        }
    }

    pub fn disable_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        if state.enabled {
            let elapsed = now_ns.saturating_sub(state.last_enabled_ns);
            state.accumulated_ns = state.accumulated_ns.saturating_add(elapsed);
            state.enabled = false;
        }
    }

    pub fn reset_at(&self, now_ns: u64) {
        let mut state = self.state.lock();
        state.accumulated_ns = 0;
        state.last_enabled_ns = now_ns;
    }

    pub fn set_period(&self, period: u64) {
        self.state.lock().sample_period = period;
    }

    pub fn read_counter_at(&self, now_ns: u64) -> u64 {
        let state = self.state.lock();
        if state.enabled {
            let elapsed = now_ns.saturating_sub(state.last_enabled_ns);
            state.accumulated_ns.saturating_add(elapsed)
        } else {
            state.accumulated_ns
        }
    }

    pub fn read_into_at(&self, buf: &mut [u8], now_ns: u64) -> Result<usize, LinuxError> {
        if buf.len() < 8 {
            return Err(LinuxError::EINVAL);
        }
        let val = self.read_counter_at(now_ns);
        buf[..8].copy_from_slice(&val.to_ne_bytes());
        Ok(8)
    }

    pub fn ioctl_at(&self, cmd: u32, arg: usize, now_ns: u64) -> Result<isize, LinuxError> {
        match cmd {
            PERF_EVENT_IOC_ENABLE => {
                self.enable_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_DISABLE => {
                self.disable_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_RESET => {
                self.reset_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_REFRESH => {
                self.enable_at(now_ns);
                Ok(0)
            }
            PERF_EVENT_IOC_PERIOD => {
                self.set_period(arg as u64);
                Ok(0)
            }
            _ => Err(LinuxError::ENOTTY),
        }
    }
}
