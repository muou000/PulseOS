use core::sync::atomic::{AtomicU64, Ordering};

use kernel_guard::NoOp;
use lazyinit::LazyInit;
use timer_list::{TimeValue, TimerEvent, TimerList};

use axhal::time::monotonic_time;

use crate::{AxTaskRef, AxTaskWeak, select_run_queue};

static TIMER_TICKET_ID: AtomicU64 = AtomicU64::new(1);

pub enum AxTimerEvent {
    TaskWakeup {
        ticket_id: u64,
        task: AxTaskWeak,
    },
    Generic {
        callback: alloc::boxed::Box<dyn FnOnce(TimeValue) + Send + Sync>,
    },
}

percpu_static! {
    TIMER_LIST: LazyInit<TimerList<AxTimerEvent>> = LazyInit::new(),
}

impl TimerEvent for AxTimerEvent {
    fn callback(self, _now: TimeValue) {
        match self {
            Self::TaskWakeup { ticket_id, task } => {
                if let Some(task) = task.upgrade() {
                    if task.timer_ticket() != ticket_id {
                        return;
                    }
                    select_run_queue::<NoOp>(&task).unblock_task(task, true);
                }
            }
            Self::Generic { callback } => {
                callback(_now);
            }
        }
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
            let missed_ticks = (now_ns - tick_deadline) / periodic_interval_nanos + 1;
            tick_deadline += missed_ticks * periodic_interval_nanos;
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

    if final_deadline != u64::MAX {
        if final_deadline < now_ns {
            final_deadline = now_ns;
        }
        axhal::time::set_oneshot_timer(final_deadline);
    }
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
        timer_list.set(
            deadline,
            AxTimerEvent::TaskWakeup {
                ticket_id,
                task: alloc::sync::Arc::downgrade(&task),
            },
        );
    });
    reprogram_timer();
}

pub fn set_generic_timer(deadline: TimeValue, callback: alloc::boxed::Box<dyn FnOnce(TimeValue) + Send + Sync>) {
    TIMER_LIST.with_current(|timer_list| {
        timer_list.set(deadline, AxTimerEvent::Generic { callback });
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
    let first_deadline = axhal::time::monotonic_time_nanos() + axhal::time::NANOS_PER_SEC / axconfig::TICKS_PER_SEC as u64;
    unsafe { NEXT_TICK_DEADLINE.write_current_raw(first_deadline) };
}
