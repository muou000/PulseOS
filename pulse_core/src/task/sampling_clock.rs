//! Accumulated running time for one thread, independent of user/kernel mode.
//!
//! The scheduler supplies enter/leave timestamps while transferring CPU
//! ownership. The owner serializes these transitions and queries; this value
//! contains no wall-clock credit for intervals in which the thread is asleep.

#[derive(Debug)]
pub struct OnCpuClock {
    accumulated_ns: u64,
    entered_ns: Option<u64>,
}

impl OnCpuClock {
    pub const fn new() -> Self {
        Self { accumulated_ns: 0, entered_ns: None }
    }

    pub fn enter(&mut self, now_ns: u64) {
        if self.entered_ns.is_none() {
            self.entered_ns = Some(now_ns);
        }
    }

    pub fn leave(&mut self, now_ns: u64) {
        if let Some(start) = self.entered_ns.take() {
            self.accumulated_ns = self.accumulated_ns.saturating_add(now_ns.saturating_sub(start));
        }
    }

    pub fn read(&self, now_ns: u64) -> u64 {
        self.accumulated_ns.saturating_add(
            self.entered_ns.map_or(0, |start| now_ns.saturating_sub(start)),
        )
    }
}
