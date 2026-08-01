use super::*;
use crate::task;

impl Process {
    pub fn mark_user_resume_at(&self, now_ns: u64) {
        if let Ok(thread) = task::current_thread() {
            thread.mark_user_resume_at(now_ns);
        }
    }

    pub fn mark_user_resume(&self) {
        if let Ok(thread) = task::current_thread() {
            thread.mark_user_resume();
        }
    }

    pub fn on_kernel_entry_from_user(&self, now_ns: u64) {
        if let Ok(thread) = task::current_thread() {
            thread.on_kernel_entry_from_user(now_ns);
        }
    }

    pub fn add_sys_time_ns(&self, delta_ns: u64) {
        if let Ok(thread) = task::current_thread() {
            thread.add_sys_time_ns(delta_ns);
        }
    }

    pub fn add_child_time_ns(&self, child_user_ns: u64, child_sys_ns: u64) {
        self.time_context
            .child_user_time_ns
            .fetch_add(child_user_ns, Ordering::Relaxed);
        self.time_context
            .child_sys_time_ns
            .fetch_add(child_sys_ns, Ordering::Relaxed);
    }

    pub fn snapshot_cpu_time_ns(&self, now_ns: u64) -> (u64, u64) {
        let mut total_user = self.time_context.user_time_ns.load(Ordering::Relaxed);
        let mut total_sys = self.time_context.sys_time_ns.load(Ordering::Relaxed);
        let registry = self.threads.lock();
        for state in registry.values() {
            if let ThreadState::Active(task) = state {
                if let Some(handle) = task::thread_handle_from_task(task) {
                    let (u, s) = handle.snapshot_cpu_time_ns(now_ns);
                    total_user = total_user.saturating_add(u);
                    total_sys = total_sys.saturating_add(s);
                }
            }
        }
        (total_user, total_sys)
    }

    pub fn snapshot_children_cpu_time_ns(&self) -> (u64, u64) {
        (
            self.time_context.child_user_time_ns.load(Ordering::Relaxed),
            self.time_context.child_sys_time_ns.load(Ordering::Relaxed),
        )
    }

    pub fn read_sys_time_ns(&self) -> u64 {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        self.snapshot_cpu_time_ns(now_ns).1
    }

    /// Set ITIMER_REAL. Returns the previous (remaining_ns, interval_ns).
    /// `value_ns` is the initial timeout in nanoseconds (0 = disarm).
    /// `interval_ns` is the repeat interval (0 = one-shot).
    pub fn set_itimer_real(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let old_deadline = self
            .time_context
            .itimer_real_deadline_ns
            .load(Ordering::Acquire);
        let old_interval = self
            .time_context
            .itimer_real_interval_ns
            .load(Ordering::Acquire);
        let old_remaining = if old_deadline == 0 {
            0
        } else if now_ns >= old_deadline {
            0
        } else {
            old_deadline - now_ns
        };

        if value_ns == 0 {
            // Disarm
            self.time_context
                .itimer_real_deadline_ns
                .store(0, Ordering::Release);
            self.time_context
                .itimer_real_interval_ns
                .store(0, Ordering::Release);
        } else {
            let deadline = now_ns.saturating_add(value_ns);
            self.time_context
                .itimer_real_deadline_ns
                .store(deadline, Ordering::Release);
            self.time_context
                .itimer_real_interval_ns
                .store(interval_ns, Ordering::Release);
            task::schedule_itimer_event(self.pid(), deadline);
        }
        (old_remaining, old_interval)
    }

    /// Get ITIMER_REAL. Returns (remaining_ns, interval_ns).
    pub fn get_itimer_real(&self) -> (u64, u64) {
        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        let deadline = self
            .time_context
            .itimer_real_deadline_ns
            .load(Ordering::Acquire);
        let interval = self
            .time_context
            .itimer_real_interval_ns
            .load(Ordering::Acquire);
        let remaining = if deadline == 0 {
            0
        } else if now_ns >= deadline {
            0
        } else {
            deadline - now_ns
        };
        (remaining, interval)
    }

    pub fn set_itimer_virt(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let old_remaining = self
            .time_context
            .itimer_virt_remaining_ns
            .swap(value_ns, Ordering::AcqRel);
        let old_interval = self
            .time_context
            .itimer_virt_interval_ns
            .swap(interval_ns, Ordering::AcqRel);
        (old_remaining, old_interval)
    }

    pub fn get_itimer_virt(&self) -> (u64, u64) {
        let remaining = self
            .time_context
            .itimer_virt_remaining_ns
            .load(Ordering::Acquire);
        let interval = self
            .time_context
            .itimer_virt_interval_ns
            .load(Ordering::Acquire);
        (remaining, interval)
    }

    pub fn set_itimer_prof(&self, value_ns: u64, interval_ns: u64) -> (u64, u64) {
        let old_remaining = self
            .time_context
            .itimer_prof_remaining_ns
            .swap(value_ns, Ordering::AcqRel);
        let old_interval = self
            .time_context
            .itimer_prof_interval_ns
            .swap(interval_ns, Ordering::AcqRel);
        (old_remaining, old_interval)
    }

    pub fn get_itimer_prof(&self) -> (u64, u64) {
        let remaining = self
            .time_context
            .itimer_prof_remaining_ns
            .load(Ordering::Acquire);
        let interval = self
            .time_context
            .itimer_prof_interval_ns
            .load(Ordering::Acquire);
        (remaining, interval)
    }

    /// Called from timer tick hook (interrupt context). Checks if ITIMER_REAL

    pub fn check_itimer_virt_tick(&self, elapsed_ns: u64) {
        let mut remaining = self
            .time_context
            .itimer_virt_remaining_ns
            .load(Ordering::Acquire);
        if remaining == 0 {
            return;
        }

        if remaining <= elapsed_ns {
            // Expired. Send SIGVTALRM (signal 26).
            let _ = queue_signal_to_process(self, 26 /* SIGVTALRM */);
            let interval = self
                .time_context
                .itimer_virt_interval_ns
                .load(Ordering::Acquire);
            remaining = interval; // might be 0, which disarms it
        } else {
            remaining -= elapsed_ns;
        }
        self.time_context
            .itimer_virt_remaining_ns
            .store(remaining, Ordering::Release);
    }

    pub fn check_itimer_prof_tick(&self, elapsed_ns: u64) {
        let mut remaining = self
            .time_context
            .itimer_prof_remaining_ns
            .load(Ordering::Acquire);
        if remaining == 0 {
            return;
        }

        if remaining <= elapsed_ns {
            // Expired. Send SIGPROF (signal 27).
            let _ = queue_signal_to_process(self, 27 /* SIGPROF */);
            let interval = self
                .time_context
                .itimer_prof_interval_ns
                .load(Ordering::Acquire);
            remaining = interval; // might be 0, which disarms it
        } else {
            remaining -= elapsed_ns;
        }
        self.time_context
            .itimer_prof_remaining_ns
            .store(remaining, Ordering::Release);
    }

    pub fn complete_vfork(&self) {
        if let Some(ref ctx) = self.vfork_context {
            if !ctx.wait_enabled {
                return;
            }
            if !ctx.done.swap(true, Ordering::AcqRel) {
                // Keep vfork completion notification side-effect free with respect
                // to scheduling while the child is still unwinding its exit path.
                ctx.event
                    .notify_all_with_context(false, WakeContext::task());
            }
        }
    }

    pub fn wait_for_vfork_completion(&self) {
        if let Some(ref ctx) = self.vfork_context {
            if !ctx.wait_enabled {
                return;
            }
            let current_thread = task::current_thread().ok();
            let wait_context = WaitContext::new(|| (WaitReason::Vfork, self.pid(), 0));
            ctx.event.wait_until_with_context(wait_context, || {
                ctx.done.load(Ordering::Acquire)
                    || current_thread
                        .as_ref()
                        .map(|thread| {
                            thread.exec_exit_requested() || thread.process().group_exiting()
                        })
                        .unwrap_or(false)
            });
        }
    }
}

impl Process {
    pub fn alloc_posix_timer(
        &self,
        clock_id: i32,
        event: sigevent,
    ) -> Result<i32, axerrno::LinuxError> {
        match clock_id {
            0 | 1 | 2 | 3 | 7 => {}
            _ => return Err(axerrno::LinuxError::EINVAL),
        }

        let mut timers = self.posix_timers.lock();
        for (i, slot) in timers.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(PosixTimer {
                    id: i,
                    generation: self.next_posix_timer_generation(),
                    clock_id,
                    event,
                    itimer_spec: unsafe { core::mem::zeroed() },
                    overrun: 0,
                    next_deadline_ns: 0,
                    interval_ns: 0,
                    is_absolute: false,
                    first_expired: false,
                });
                return Ok(i as i32);
            }
        }
        Err(axerrno::LinuxError::ENOSPC)
    }

    pub fn next_posix_timer_generation(&self) -> u64 {
        self.posix_timer_generation.fetch_add(1, Ordering::AcqRel)
    }

    pub fn clear_posix_timers_on_exec(&self) {
        self.posix_timers.lock().fill(None);
    }
}
