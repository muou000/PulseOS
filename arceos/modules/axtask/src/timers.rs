use core::sync::atomic::{AtomicU64, Ordering};

use kernel_guard::NoOp;
use lazyinit::LazyInit;
use timer_list::{TimeValue, TimerEvent, TimerList};

use axhal::time::monotonic_time;

use crate::{AxTaskRef, select_run_queue};

static TIMER_TICKET_ID: AtomicU64 = AtomicU64::new(1);

percpu_static! {
    TIMER_LIST: LazyInit<TimerList<TaskWakeupEvent>> = LazyInit::new(),
}

struct TaskWakeupEvent {
    ticket_id: u64,
    task: AxTaskRef,
}

impl TimerEvent for TaskWakeupEvent {
    fn callback(self, _now: TimeValue) {
        // Ignore the timer event if timeout was set but not triggered
        // (wake up by `WaitQueue::notify()`).
        // Judge if this timer event is still valid by checking the ticket ID.
        if self.task.timer_ticket() != self.ticket_id {
            // Timer ticket ID is not matched.
            // Just ignore this timer event and return.
            return;
        }

        // Timer ticket match.
        select_run_queue::<NoOp>(&self.task).unblock_task(self.task, true)
    }
}

percpu_static! {
    NEXT_TICK_DEADLINE: u64 = 0,
}

pub fn reprogram_timer() {
    reprogram_timer_internal(false);
}

pub(crate) fn reprogram_timer_from_tick() {
    reprogram_timer_internal(true);
}

fn reprogram_timer_internal(from_tick: bool) {
    let now_ns = axhal::time::monotonic_time_nanos();
    let mut tick_deadline = unsafe { NEXT_TICK_DEADLINE.read_current_raw() };
    let periodic_interval_nanos = axhal::time::NANOS_PER_SEC / axconfig::TICKS_PER_SEC as u64;

    if from_tick {
        if now_ns >= tick_deadline {
            tick_deadline = now_ns + periodic_interval_nanos;
            unsafe { NEXT_TICK_DEADLINE.write_current_raw(tick_deadline) };
        }
    }

    let mut final_deadline = tick_deadline;
    if let Some(event_deadline) = unsafe {
        let tl = TIMER_LIST.current_ref_raw();
        if tl.is_inited() {
            tl.next_deadline()
        } else {
            None
        }
    } {
        let event_mono_ns = event_deadline.as_nanos() as u64;
        if event_mono_ns < final_deadline {
            final_deadline = event_mono_ns;
        }
    }

    if final_deadline < now_ns {
        final_deadline = now_ns;
    }

    axhal::time::set_oneshot_timer(final_deadline);
}

pub fn next_deadline() -> Option<TimeValue> {
    unsafe {
        let tl = TIMER_LIST.current_ref_raw();
        if tl.is_inited() {
            tl.next_deadline()
        } else {
            None
        }
    }
}

pub fn set_alarm_wakeup(deadline: TimeValue, task: AxTaskRef) {
    TIMER_LIST.with_current(|timer_list| {
        let ticket_id = TIMER_TICKET_ID.fetch_add(1, Ordering::AcqRel);
        task.set_timer_ticket(ticket_id);
        timer_list.set(deadline, TaskWakeupEvent { ticket_id, task });
    });
    reprogram_timer();
}

pub fn check_events() {
    loop {
        let now = monotonic_time();
        let event = unsafe {
            // Safety: IRQs are disabled at this time.
            TIMER_LIST.current_ref_mut_raw()
        }
        .expire_one(now);
        if let Some((_deadline, event)) = event {
            event.callback(now);
        } else {
            break;
        }
    }
}

pub fn init() {
    TIMER_LIST.with_current(|timer_list| {
        timer_list.init_once(TimerList::new());
    });
}
