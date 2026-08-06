use super::*;
use crate::task;

const TIMER_WORK_ITIMER_REAL: u32 = 1 << 0;
const TIMER_WORK_ITIMER_VIRT: u32 = 1 << 1;
const TIMER_WORK_ITIMER_PROF: u32 = 1 << 2;
const TIMER_WORK_POSIX_SHIFT: usize = 8;

fn posix_timer_work_bit(timer_id: usize) -> Option<u32> {
    (timer_id < MAX_POSIX_TIMER_COUNT).then(|| 1u32 << (TIMER_WORK_POSIX_SHIFT + timer_id))
}

fn tick_interval_timer(
    remaining: &core::sync::atomic::AtomicU64,
    interval: &core::sync::atomic::AtomicU64,
    timer_work: &core::sync::atomic::AtomicU32,
    work_bit: u32,
    elapsed_ns: u64,
) -> bool {
    let mut current = remaining.load(Ordering::Acquire);
    loop {
        if current == 0 {
            return false;
        }
        let (next, expired) = if current <= elapsed_ns {
            (interval.load(Ordering::Acquire), true)
        } else {
            (current - elapsed_ns, false)
        };
        match remaining.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => {
                if expired {
                    timer_work.fetch_or(work_bit, Ordering::Release);
                }
                return expired;
            }
            Err(actual) => current = actual,
        }
    }
}

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

    /// Runs in the timer IRQ hook. It only advances the counter and records
    /// expiry; the signal queue operation itself is completed by the timer
    /// worker in regular task context.
    pub(crate) fn check_itimer_virt_tick(&self, elapsed_ns: u64) -> bool {
        tick_interval_timer(
            &self.time_context.itimer_virt_remaining_ns,
            &self.time_context.itimer_virt_interval_ns,
            &self.time_context.timer_work,
            TIMER_WORK_ITIMER_VIRT,
            elapsed_ns,
        )
    }

    /// See `check_itimer_virt_tick`.
    pub(crate) fn check_itimer_prof_tick(&self, elapsed_ns: u64) -> bool {
        tick_interval_timer(
            &self.time_context.itimer_prof_remaining_ns,
            &self.time_context.itimer_prof_interval_ns,
            &self.time_context.timer_work,
            TIMER_WORK_ITIMER_PROF,
            elapsed_ns,
        )
    }

    /// Marks a real-time itimer expiry from a generic timer callback. This is
    /// intentionally limited to atomics so the callback remains IRQ-safe.
    pub(crate) fn mark_itimer_real_expired_from_irq(&self, deadline: u64) -> bool {
        if deadline == 0
            || self
                .time_context
                .itimer_real_deadline_ns
                .load(Ordering::Acquire)
                != deadline
        {
            return false;
        }
        self.time_context
            .timer_work
            .fetch_or(TIMER_WORK_ITIMER_REAL, Ordering::Release);
        true
    }

    /// Marks a POSIX timer slot for task-context processing. The worker checks
    /// its generation/deadline state before producing a signal, so an expired
    /// callback from a replaced timer cannot fire the replacement early.
    pub(crate) fn mark_posix_timer_expired_from_irq(
        &self,
        timer_id: usize,
        deadline: u64,
        generation: u64,
    ) -> bool {
        let Some(bit) = posix_timer_work_bit(timer_id) else {
            return false;
        };
        self.time_context.posix_timer_work_deadlines[timer_id].store(deadline, Ordering::Relaxed);
        self.time_context.posix_timer_work_generations[timer_id]
            .store(generation, Ordering::Relaxed);
        self.time_context
            .timer_work
            .fetch_or(bit, Ordering::Release);
        true
    }

    /// Completes timer work deferred from interrupt context. The caller is a
    /// dedicated kernel task, so queue locks, task wakeups, and generic timer
    /// allocation cannot extend timer IRQ latency.
    pub(crate) fn drain_deferred_timer_work(&self) {
        let work = self.time_context.timer_work.swap(0, Ordering::AcqRel);
        if work == 0 || self.is_zombie() {
            return;
        }

        if (work & TIMER_WORK_ITIMER_VIRT) != 0 {
            let _ = queue_signal_to_process(self, 26 /* SIGVTALRM */);
        }
        if (work & TIMER_WORK_ITIMER_PROF) != 0 {
            let _ = queue_signal_to_process(self, 27 /* SIGPROF */);
        }

        let now_ns = axhal::time::monotonic_time_nanos() as u64;
        if (work & TIMER_WORK_ITIMER_REAL) != 0 {
            self.drain_itimer_real_expiry(now_ns);
        }
        for timer_id in 0..MAX_POSIX_TIMER_COUNT {
            if (work & posix_timer_work_bit(timer_id).unwrap_or(0)) != 0 {
                let deadline =
                    self.time_context.posix_timer_work_deadlines[timer_id].load(Ordering::Relaxed);
                let generation = self.time_context.posix_timer_work_generations[timer_id]
                    .load(Ordering::Relaxed);
                self.drain_posix_timer_expiry(timer_id, deadline, generation, now_ns);
            }
        }
    }

    fn drain_itimer_real_expiry(&self, now_ns: u64) {
        let deadline = self
            .time_context
            .itimer_real_deadline_ns
            .load(Ordering::Acquire);
        if deadline == 0 || deadline > now_ns {
            return;
        }
        let interval = self
            .time_context
            .itimer_real_interval_ns
            .load(Ordering::Acquire);
        let next_deadline = if interval == 0 {
            0
        } else {
            let mut next = deadline.saturating_add(interval);
            while next <= now_ns {
                let advanced = next.saturating_add(interval);
                if advanced == next {
                    break;
                }
                next = advanced;
            }
            next
        };
        if self
            .time_context
            .itimer_real_deadline_ns
            .compare_exchange(deadline, next_deadline, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }

        let _ = queue_signal_to_process(self, 14 /* SIGALRM */);
        if next_deadline != 0 {
            task::schedule_itimer_event(self.pid(), next_deadline);
        }
    }

    fn drain_posix_timer_expiry(
        &self,
        timer_id: usize,
        expected_deadline: u64,
        expected_generation: u64,
        now_ns: u64,
    ) {
        let (signal, rearm) = {
            let mut timers = self.posix_timers.lock();
            let Some(Some(timer)) = timers.get_mut(timer_id) else {
                return;
            };
            if timer.generation != expected_generation
                || timer.next_deadline_ns != expected_deadline
                || timer.next_deadline_ns == 0
                || timer.next_deadline_ns > now_ns
            {
                return;
            }

            let signal = if timer.event.sigev_notify == 0 {
                Some(timer.event.sigev_signo as usize)
            } else {
                None
            };
            timer.first_expired = true;
            let rearm = if timer.interval_ns == 0 {
                timer.next_deadline_ns = 0;
                None
            } else {
                let mut next = timer.next_deadline_ns.saturating_add(timer.interval_ns);
                while next <= now_ns {
                    let advanced = next.saturating_add(timer.interval_ns);
                    if advanced == next {
                        break;
                    }
                    timer.overrun = timer.overrun.saturating_add(1);
                    next = advanced;
                }
                timer.next_deadline_ns = next;
                Some((next, timer.generation))
            };
            (signal, rearm)
        };

        if let Some(sig) = signal {
            let _ = queue_signal_to_process(self, sig);
        }
        if let Some((deadline, generation)) = rearm {
            task::schedule_posix_timer_event(self.pid(), timer_id, deadline, generation);
        }
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
