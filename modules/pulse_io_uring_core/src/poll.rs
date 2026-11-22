//! Pure `no_std` `io_uring` `POLL_ADD` 32-bit mask translation and four-step
//! one-shot poll readiness state machine (closing the check/enroll race).

use axerrno::LinuxError;
use axpoll::IoEvents;
use linux_raw_sys::general::{
    POLLERR, POLLHUP, POLLIN, POLLOUT, POLLPRI, POLLRDBAND, POLLRDHUP, POLLRDNORM, POLLWRBAND,
    POLLWRNORM,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollReadiness {
    pub readable: bool,
    pub writable: bool,
    pub rdhup: bool,
    pub hup: bool,
    pub err: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OneShotPollStep {
    Ready(u32),
    Pending,
}

/// Translates Linux 32-bit `poll32_events` mask into [`axpoll::IoEvents`],
/// always retaining [`IoEvents::ALWAYS_POLL`] (`POLLERR | POLLHUP`).
#[inline]
pub fn poll_mask_to_io_events(mask: u32) -> IoEvents {
    let mut events = IoEvents::ALWAYS_POLL;
    if (mask & (POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI)) != 0 {
        events |= IoEvents::IN;
    }
    if (mask & POLLPRI) != 0 {
        events |= IoEvents::PRI;
    }
    if (mask & (POLLOUT | POLLWRNORM | POLLWRBAND)) != 0 {
        events |= IoEvents::OUT;
    }
    if (mask & POLLRDHUP) != 0 {
        events |= IoEvents::RDHUP;
    }
    events
}

/// Translates [`axpoll::IoEvents`] readiness flags back to a Linux poll event mask.
#[inline]
pub fn io_events_to_poll_mask(events: IoEvents) -> u32 {
    let mut mask = 0u32;
    if events.contains(IoEvents::IN) {
        mask |= POLLIN;
    }
    if events.contains(IoEvents::PRI) {
        mask |= POLLPRI;
    }
    if events.contains(IoEvents::OUT) {
        mask |= POLLOUT;
    }
    if events.contains(IoEvents::RDHUP) {
        mask |= POLLRDHUP;
    }
    if events.contains(IoEvents::ERR) {
        mask |= POLLERR;
    }
    if events.contains(IoEvents::HUP) {
        mask |= POLLHUP;
    }
    mask
}

/// Computes the 32-bit `revents` mask from [`PollReadiness`] and the requested
/// `poll32_events` mask (`POLLERR` and `POLLHUP` are always reported when set).
#[inline]
pub fn compute_poll_revents(mask: u32, readiness: PollReadiness) -> u32 {
    let mut rev = 0u32;
    if readiness.readable {
        rev |= mask & (POLLIN | POLLRDNORM);
    }
    if readiness.writable {
        rev |= mask & (POLLOUT | POLLWRNORM);
    }
    if readiness.rdhup {
        rev |= mask & POLLRDHUP;
    }
    if readiness.err {
        rev |= POLLERR;
    }
    if readiness.hup {
        rev |= POLLHUP;
    }
    rev
}

/// Executes one poll step of the four-step race-free one-shot poll state machine:
/// clear stale registrations -> initial check -> register wakers -> post-enroll recheck.
pub fn drive_one_shot_poll_step<C, R, U>(
    mut check: C,
    mut register: R,
    mut clear_registrations: U,
) -> Result<OneShotPollStep, LinuxError>
where
    C: FnMut() -> Option<u32>,
    R: FnMut() -> Result<(), LinuxError>,
    U: FnMut(),
{
    clear_registrations();
    if let Some(rev) = check() {
        return Ok(OneShotPollStep::Ready(rev));
    }
    register()?;
    if let Some(rev) = check() {
        clear_registrations();
        return Ok(OneShotPollStep::Ready(rev));
    }
    Ok(OneShotPollStep::Pending)
}

#[cfg(test)]
mod tests {
    use core::cell::Cell;

    use super::*;

    #[test]
    fn poll_mask_translates_32bit_events_and_always_includes_err_hup() {
        let ev_in = poll_mask_to_io_events(POLLRDNORM | POLLRDBAND | POLLPRI);
        assert!(ev_in.contains(IoEvents::IN));
        assert!(ev_in.contains(IoEvents::PRI));
        assert!(ev_in.contains(IoEvents::ERR));
        assert!(ev_in.contains(IoEvents::HUP));
        assert!(!ev_in.contains(IoEvents::OUT));

        let ev_out = poll_mask_to_io_events(POLLWRNORM | POLLWRBAND);
        assert!(ev_out.contains(IoEvents::OUT));
        assert!(ev_out.contains(IoEvents::ERR));
        assert!(ev_out.contains(IoEvents::HUP));
        assert!(!ev_out.contains(IoEvents::IN));

        let ev_rdhup = poll_mask_to_io_events(POLLRDHUP);
        assert!(ev_rdhup.contains(IoEvents::RDHUP));
        assert!(ev_rdhup.contains(IoEvents::ERR));
        assert!(ev_rdhup.contains(IoEvents::HUP));

        let ev_zero = poll_mask_to_io_events(0);
        assert_eq!(ev_zero.bits(), IoEvents::ALWAYS_POLL.bits());
    }

    #[test]
    fn compute_poll_revents_respects_mask_and_unmasked_err_hup() {
        let rev = compute_poll_revents(
            POLLIN | POLLRDNORM | POLLRDHUP,
            PollReadiness {
                readable: true,
                writable: true,
                rdhup: true,
                hup: true,
                err: true,
            },
        );
        assert_eq!(rev, POLLIN | POLLRDNORM | POLLRDHUP | POLLERR | POLLHUP);

        let rev_zero_mask = compute_poll_revents(
            0,
            PollReadiness {
                readable: true,
                writable: true,
                rdhup: true,
                hup: true,
                err: false,
            },
        );
        assert_eq!(rev_zero_mask, POLLHUP);

        let rev_none = compute_poll_revents(
            POLLOUT | POLLWRNORM,
            PollReadiness {
                readable: true,
                writable: false,
                rdhup: false,
                hup: false,
                err: false,
            },
        );
        assert_eq!(rev_none, 0);

        let rt_mask = io_events_to_poll_mask(
            IoEvents::IN | IoEvents::PRI | IoEvents::OUT | IoEvents::RDHUP | IoEvents::ERR | IoEvents::HUP,
        );
        assert_eq!(
            rt_mask,
            POLLIN | POLLPRI | POLLOUT | POLLRDHUP | POLLERR | POLLHUP
        );
        assert_eq!(
            poll_mask_to_io_events(rt_mask).bits(),
            (IoEvents::IN | IoEvents::PRI | IoEvents::OUT | IoEvents::RDHUP | IoEvents::ALWAYS_POLL).bits()
        );
    }

    #[test]
    fn one_shot_poll_step_closes_check_enroll_race_via_post_enroll_recheck() {
        // Case 1: already ready on initial check -> skips registration.
        let cleared = Cell::new(0usize);
        let registered = Cell::new(0usize);
        let res = drive_one_shot_poll_step(
            || Some(POLLIN),
            || {
                registered.set(registered.get() + 1);
                Ok(())
            },
            || cleared.set(cleared.get() + 1),
        );
        assert_eq!(res, Ok(OneShotPollStep::Ready(POLLIN)));
        assert_eq!(cleared.get(), 1);
        assert_eq!(registered.get(), 0);

        // Case 2: readiness flips concurrently during register -> post-enroll recheck catches it and clears.
        let cleared2 = Cell::new(0usize);
        let checks = Cell::new(0usize);
        let became_ready = Cell::new(false);
        let res2 = drive_one_shot_poll_step(
            || {
                checks.set(checks.get() + 1);
                became_ready.get().then_some(POLLOUT | POLLERR)
            },
            || {
                became_ready.set(true);
                Ok(())
            },
            || cleared2.set(cleared2.get() + 1),
        );
        assert_eq!(res2, Ok(OneShotPollStep::Ready(POLLOUT | POLLERR)));
        assert_eq!(checks.get(), 2);
        assert_eq!(cleared2.get(), 2);

        // Case 3: still unready after register -> remains Pending with 1 clear & 1 register.
        let cleared3 = Cell::new(0usize);
        let registered3 = Cell::new(0usize);
        let res3 = drive_one_shot_poll_step(
            || None,
            || {
                registered3.set(registered3.get() + 1);
                Ok(())
            },
            || cleared3.set(cleared3.get() + 1),
        );
        assert_eq!(res3, Ok(OneShotPollStep::Pending));
        assert_eq!(cleared3.get(), 1);
        assert_eq!(registered3.get(), 1);

        // Case 4: register fails -> propagates error without recheck.
        let checks4 = Cell::new(0usize);
        let res4 = drive_one_shot_poll_step(
            || {
                checks4.set(checks4.get() + 1);
                None
            },
            || Err(LinuxError::EOPNOTSUPP),
            || {},
        );
        assert_eq!(res4, Err(LinuxError::EOPNOTSUPP));
        assert_eq!(checks4.get(), 1);
    }
}
