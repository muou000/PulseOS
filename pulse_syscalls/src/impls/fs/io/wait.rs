use alloc::{sync::Arc, vec::Vec};
use core::time::Duration;

use axerrno::LinuxError;
use linux_raw_sys::general::{POLLERR, POLLNVAL, pollfd};
use pulse_core::{fd_table::FdObject, task::Thread};

use super::requested_poll_revents;
use crate::impls::fs::common::get_fd_objects;

const ACTIVE_YIELD_ROUNDS: usize = 64;
const SLEEP_QUANTUM: Duration = Duration::from_micros(100);

pub(super) type PollObject = Arc<dyn FdObject>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadinessWaitResult {
    Ready(usize),
    Interrupted,
    TimedOut,
}

pub(super) fn snapshot_poll_objects(
    pollfds: &[pollfd],
) -> Result<Vec<Option<PollObject>>, LinuxError> {
    get_fd_objects(pollfds.iter().map(|pfd| pfd.fd as usize))
}

fn object_revents(object: &PollObject, events: i16) -> i16 {
    match object.poll() {
        Ok(state) => requested_poll_revents(events, state),
        Err(_) => POLLERR as i16,
    }
}

fn object_may_be_ready(object: &PollObject, events: i16) -> bool {
    object_revents(object, events) != 0
}

pub(super) fn readiness_scan_once(pollfds: &mut [pollfd], objects: &[Option<PollObject>]) -> usize {
    let mut ready = 0usize;
    for (index, pfd) in pollfds.iter_mut().enumerate() {
        pfd.revents = 0;
        if pfd.fd < 0 {
            continue;
        }

        match objects.get(index).and_then(Option::as_ref) {
            Some(object) => {
                pfd.revents = object_revents(object, pfd.events);
                if pfd.revents != 0 {
                    ready += 1;
                }
            }
            None => {
                pfd.revents = POLLNVAL as i16;
                ready += 1;
            }
        }
    }
    ready
}

fn remaining_duration(deadline: Option<axhal::time::TimeValue>) -> Option<Duration> {
    deadline.map(|deadline| {
        let now = axhal::time::monotonic_time();
        if now >= deadline {
            Duration::ZERO
        } else {
            deadline - now
        }
    })
}

fn collect_readiness_wait_objects(
    pollfds: &[pollfd],
    objects: &[Option<PollObject>],
) -> Option<Vec<(PollObject, i16)>> {
    let mut wait_objects = Vec::with_capacity(pollfds.len().min(128));

    for (pfd, object) in pollfds.iter().zip(objects.iter()) {
        if pfd.fd < 0 {
            continue;
        }

        let object = object.as_ref()?;
        let mut queue_probe = Vec::new();
        match object.get_wait_queues(pfd.events, &mut queue_probe) {
            Ok(true) => wait_objects.push((object.clone(), pfd.events)),
            _ => return None,
        }
    }

    (!wait_objects.is_empty()).then_some(wait_objects)
}

fn objects_may_be_ready(wait_objects: &[(PollObject, i16)], thread: &Thread) -> bool {
    for (object, events) in wait_objects {
        if object_may_be_ready(object, *events) {
            return true;
        }
    }
    thread.has_pending_signal()
}

fn refresh_readiness_wait_queues<'a>(
    wait_objects: &'a [(PollObject, i16)],
    thread: &'a Thread,
    queues: &mut Vec<&'a axtask::WaitQueue>,
) -> bool {
    queues.clear();
    for (object, events) in wait_objects {
        match object.get_wait_queues(*events, queues) {
            Ok(true) => {}
            Ok(false) | Err(_) => return false,
        }
    }
    queues.push(thread.signal_wait_queue());
    true
}

fn wait_event_driven(
    thread: &Thread,
    pollfds: &mut [pollfd],
    objects: &[Option<PollObject>],
    deadline: Option<axhal::time::TimeValue>,
) -> Option<ReadinessWaitResult> {
    let wait_objects = collect_readiness_wait_objects(pollfds, objects)?;
    let mut queues = Vec::with_capacity(wait_objects.len().saturating_add(1).min(128));
    if !refresh_readiness_wait_queues(&wait_objects, thread, &mut queues) {
        return None;
    }
    let mut check_ready = || objects_may_be_ready(&wait_objects, thread);

    let mut yielded_ready = false;
    for _ in 0..ACTIVE_YIELD_ROUNDS {
        if check_ready() {
            yielded_ready = true;
            break;
        }
        if let Some(Duration::ZERO) = remaining_duration(deadline) {
            break;
        }
        axtask::yield_now();
    }

    if !yielded_ready {
        loop {
            if check_ready() {
                break;
            }

            let remain = remaining_duration(deadline);
            if matches!(remain, Some(Duration::ZERO)) {
                break;
            }

            if !refresh_readiness_wait_queues(&wait_objects, thread, &mut queues) {
                return None;
            }
            let wait_result =
                axtask::WaitQueue::wait_multiple_timeout_until(&queues, remain, &mut check_ready);
            if matches!(wait_result, Err(true)) {
                break;
            }
        }
    }

    Some(finalize_wait(pollfds, objects, thread))
}

fn wait_fallback(
    thread: &Thread,
    pollfds: &mut [pollfd],
    objects: &[Option<PollObject>],
    deadline: Option<axhal::time::TimeValue>,
) -> ReadinessWaitResult {
    let mut idle_rounds = 0usize;

    loop {
        let ready = readiness_scan_once(pollfds, objects);
        if ready > 0 {
            return ReadinessWaitResult::Ready(ready);
        }
        if thread.has_pending_signal() {
            return ReadinessWaitResult::Interrupted;
        }

        if let Some(deadline) = deadline {
            let now = axhal::time::monotonic_time();
            if now >= deadline {
                return ReadinessWaitResult::TimedOut;
            }
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                let sleep_dur = core::cmp::min(deadline - now, SLEEP_QUANTUM);
                if sleep_dur > Duration::ZERO {
                    thread
                        .signal_wait_queue()
                        .wait_timeout_until(sleep_dur, || thread.has_pending_signal());
                } else {
                    axtask::yield_now();
                }
            }
        } else {
            idle_rounds = idle_rounds.saturating_add(1);
            if idle_rounds <= ACTIVE_YIELD_ROUNDS {
                axtask::yield_now();
            } else {
                thread
                    .signal_wait_queue()
                    .wait_timeout_until(SLEEP_QUANTUM, || thread.has_pending_signal());
            }
        }
    }
}

fn finalize_wait(
    pollfds: &mut [pollfd],
    objects: &[Option<PollObject>],
    thread: &Thread,
) -> ReadinessWaitResult {
    let ready = readiness_scan_once(pollfds, objects);
    if ready > 0 {
        return ReadinessWaitResult::Ready(ready);
    }
    if thread.has_pending_signal() {
        ReadinessWaitResult::Interrupted
    } else {
        ReadinessWaitResult::TimedOut
    }
}

pub(super) fn wait_for_readiness(
    thread: &Thread,
    pollfds: &mut [pollfd],
    objects: &[Option<PollObject>],
    deadline: Option<axhal::time::TimeValue>,
) -> ReadinessWaitResult {
    let ready = readiness_scan_once(pollfds, objects);
    if ready > 0 {
        return ReadinessWaitResult::Ready(ready);
    }

    wait_event_driven(thread, pollfds, objects, deadline)
        .unwrap_or_else(|| wait_fallback(thread, pollfds, objects, deadline))
}
