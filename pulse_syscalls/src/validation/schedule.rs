use axerrno::LinuxError;
use linux_raw_sys::general::{
    SCHED_BATCH, SCHED_DEADLINE, SCHED_FIFO, SCHED_IDLE, SCHED_NORMAL, SCHED_RR,
};

pub(crate) const RT_PRIORITY_MIN: isize = 1;
pub(crate) const RT_PRIORITY_MAX: isize = 99;
pub(crate) const MIN_NICE: i32 = -20;
pub(crate) const MAX_NICE: i32 = 19;
pub(crate) const SCHED_ATTR_SIZE_VER0: u32 = core::mem::size_of::<SchedAttr>() as u32;
pub(crate) const SCHED_ATTR_MAX_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SchedAttr {
    pub size: u32,
    pub sched_policy: u32,
    pub sched_flags: u64,
    pub sched_nice: i32,
    pub sched_priority: u32,
    pub sched_runtime: u64,
    pub sched_deadline: u64,
    pub sched_period: u64,
}

pulse_user_abi::impl_user_abi_struct! {
    for SchedAttr, size = 48 => {
        size: u32,
        sched_policy: u32,
        sched_flags: u64,
        sched_nice: i32,
        sched_priority: u32,
        sched_runtime: u64,
        sched_deadline: u64,
        sched_period: u64,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SchedChangeRequest {
    pub policy: u32,
    pub rt_priority: u32,
    pub nice: i32,
    pub update_nice: bool,
    pub flags: u64,
    pub runtime: u64,
    pub deadline: u64,
    pub period: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TargetSchedSnapshot {
    pub policy: u32,
    pub rt_priority: u32,
    pub nice: i32,
    pub ruid: u32,
    pub euid: u32,
    pub rlim_nice: u64,
    pub rlim_rtprio: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CallerCreds {
    pub euid: u32,
    pub has_cap_sys_nice: bool,
}

pub(crate) fn is_fair_policy(policy: u32) -> bool {
    matches!(policy, SCHED_NORMAL | SCHED_BATCH)
}

pub(crate) fn is_rt_policy(policy: u32) -> bool {
    matches!(policy, SCHED_FIFO | SCHED_RR)
}

pub(crate) fn is_idle_policy(policy: u32) -> bool {
    policy == SCHED_IDLE
}

pub(crate) fn is_dl_policy(policy: u32) -> bool {
    policy == SCHED_DEADLINE
}

pub(crate) fn sched_priority_max(raw_policy: usize) -> Result<isize, LinuxError> {
    let policy = raw_policy as i32;
    if policy < 0 {
        return Err(LinuxError::EINVAL);
    }
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => Ok(RT_PRIORITY_MAX),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(0),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn sched_priority_min(raw_policy: usize) -> Result<isize, LinuxError> {
    let policy = raw_policy as i32;
    if policy < 0 {
        return Err(LinuxError::EINVAL);
    }
    match policy as u32 {
        SCHED_FIFO | SCHED_RR => Ok(RT_PRIORITY_MIN),
        SCHED_NORMAL | SCHED_BATCH | SCHED_IDLE | SCHED_DEADLINE => Ok(0),
        _ => Err(LinuxError::EINVAL),
    }
}

pub(crate) fn validate_sched_getattr_args(
    pid: usize,
    attr_ptr: usize,
    size: usize,
    flags: usize,
) -> Result<usize, LinuxError> {
    if attr_ptr == 0
        || (pid as i32) < 0
        || flags != 0
        || size < SCHED_ATTR_SIZE_VER0 as usize
        || size > SCHED_ATTR_MAX_SIZE
    {
        return Err(LinuxError::EINVAL);
    }
    Ok(size)
}

pub(crate) fn validate_sched_setattr_args(
    pid: usize,
    attr_ptr: usize,
    flags: usize,
) -> Result<(), LinuxError> {
    if attr_ptr == 0 || (pid as i32) < 0 || flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub(crate) fn decode_sched_setattr_size(raw_size: u32) -> Result<usize, LinuxError> {
    let effective = if raw_size == 0 {
        SCHED_ATTR_SIZE_VER0
    } else {
        raw_size
    };
    if effective < SCHED_ATTR_SIZE_VER0 || effective as usize > SCHED_ATTR_MAX_SIZE {
        return Err(LinuxError::E2BIG);
    }
    Ok(effective as usize)
}

pub(crate) fn check_zeroed_extension_bytes(trailing: &[u8]) -> Result<(), LinuxError> {
    if trailing.iter().any(|&b| b != 0) {
        Err(LinuxError::E2BIG)
    } else {
        Ok(())
    }
}

fn validate_rt_or_zero_priority(policy: u32, priority: u32) -> Result<u32, LinuxError> {
    if is_rt_policy(policy) {
        if (RT_PRIORITY_MIN as u32..=RT_PRIORITY_MAX as u32).contains(&priority) {
            Ok(priority)
        } else {
            Err(LinuxError::EINVAL)
        }
    } else if priority == 0 {
        Ok(0)
    } else {
        Err(LinuxError::EINVAL)
    }
}

fn validate_signed_policy_priority(policy: u32, sched_priority: i32) -> Result<u32, LinuxError> {
    if sched_priority < 0 {
        return Err(LinuxError::EINVAL);
    }
    validate_rt_or_zero_priority(policy, sched_priority as u32)
}

pub(crate) fn validate_sched_setparam(
    current_policy: u32,
    current_nice: i32,
    sched_priority: i32,
) -> Result<SchedChangeRequest, LinuxError> {
    if !is_rt_policy(current_policy)
        && !is_fair_policy(current_policy)
        && !is_idle_policy(current_policy)
    {
        return Err(LinuxError::EINVAL);
    }
    let rt_priority = validate_signed_policy_priority(current_policy, sched_priority)?;
    Ok(SchedChangeRequest {
        policy: current_policy,
        rt_priority,
        nice: current_nice,
        update_nice: false,
        flags: 0,
        runtime: 0,
        deadline: 0,
        period: 0,
    })
}

pub(crate) fn validate_sched_setscheduler(
    raw_policy: usize,
    sched_priority: i32,
    current_nice: i32,
) -> Result<SchedChangeRequest, LinuxError> {
    let signed_policy = raw_policy as i32;
    if signed_policy < 0 {
        return Err(LinuxError::EINVAL);
    }
    let policy = signed_policy as u32;
    if !is_rt_policy(policy) && !is_fair_policy(policy) && !is_idle_policy(policy) {
        return Err(LinuxError::EINVAL);
    }
    let rt_priority = validate_signed_policy_priority(policy, sched_priority)?;
    Ok(SchedChangeRequest {
        policy,
        rt_priority,
        nice: current_nice,
        update_nice: false,
        flags: 0,
        runtime: 0,
        deadline: 0,
        period: 0,
    })
}

pub(crate) fn validate_sched_setattr(
    mut attr: SchedAttr,
    current_nice: i32,
) -> Result<SchedChangeRequest, LinuxError> {
    if (attr.sched_policy as i32) < 0 || attr.sched_flags != 0 {
        return Err(LinuxError::EINVAL);
    }
    attr.sched_nice = attr.sched_nice.clamp(MIN_NICE, MAX_NICE);

    let policy = attr.sched_policy;
    if !is_rt_policy(policy)
        && !is_fair_policy(policy)
        && !is_idle_policy(policy)
        && !is_dl_policy(policy)
    {
        return Err(LinuxError::EINVAL);
    }

    let rt_priority = validate_rt_or_zero_priority(policy, attr.sched_priority)?;
    if is_dl_policy(policy) {
        if attr.sched_runtime == 0
            || attr.sched_deadline == 0
            || attr.sched_period == 0
            || attr.sched_runtime > attr.sched_deadline
            || attr.sched_deadline > attr.sched_period
        {
            return Err(LinuxError::EINVAL);
        }
        return Ok(SchedChangeRequest {
            policy,
            rt_priority: 0,
            nice: current_nice,
            update_nice: false,
            flags: 0,
            runtime: attr.sched_runtime,
            deadline: attr.sched_deadline,
            period: attr.sched_period,
        });
    }

    let (nice, update_nice) = if is_fair_policy(policy) {
        (attr.sched_nice, true)
    } else {
        (current_nice, false)
    };

    Ok(SchedChangeRequest {
        policy,
        rt_priority,
        nice,
        update_nice,
        flags: 0,
        runtime: 0,
        deadline: 0,
        period: 0,
    })
}

pub(crate) fn nice_to_rlimit(nice: i32) -> u64 {
    (MAX_NICE - nice.clamp(MIN_NICE, MAX_NICE) + 1) as u64
}

pub(crate) fn is_nice_reduction(rlim_nice: u64, nice: i32) -> bool {
    nice_to_rlimit(nice) <= rlim_nice
}

pub(crate) fn authorize_sched_change(
    caller: CallerCreds,
    target: &TargetSchedSnapshot,
    req: &SchedChangeRequest,
) -> Result<(), LinuxError> {
    let mut needs_priv = false;

    if is_fair_policy(req.policy)
        && req.nice < target.nice
        && !is_nice_reduction(target.rlim_nice, req.nice)
    {
        needs_priv = true;
    }

    if is_rt_policy(req.policy) {
        if req.policy != target.policy && target.rlim_rtprio == 0 {
            needs_priv = true;
        }
        if req.rt_priority > target.rt_priority
            && u64::from(req.rt_priority) > target.rlim_rtprio
        {
            needs_priv = true;
        }
    }

    if is_dl_policy(req.policy) {
        needs_priv = true;
    }

    if is_idle_policy(target.policy)
        && !is_idle_policy(req.policy)
        && !is_nice_reduction(target.rlim_nice, target.nice)
    {
        needs_priv = true;
    }

    if caller.euid != target.euid && caller.euid != target.ruid {
        needs_priv = true;
    }

    if needs_priv && !caller.has_cap_sys_nice {
        return Err(LinuxError::EPERM);
    }
    Ok(())
}

pub(crate) fn eevdf_priority_for_request(req: &SchedChangeRequest) -> isize {
    if is_rt_policy(req.policy) {
        req.rt_priority as isize
    } else if is_fair_policy(req.policy) {
        req.nice.clamp(MIN_NICE, MAX_NICE) as isize - 100
    } else if is_idle_policy(req.policy) {
        MAX_NICE as isize - 100
    } else {
        // PulseOS records SCHED_DEADLINE metadata without CBS/EDF scheduling;
        // keep it in the ordinary EEVDF class.
        -100
    }
}

pub(crate) fn format_sched_attr_for_policy(
    policy: u32,
    flags: u64,
    nice: i32,
    rt_priority: u32,
    runtime: u64,
    deadline: u64,
    period: u64,
) -> SchedAttr {
    if is_dl_policy(policy) {
        SchedAttr {
            size: SCHED_ATTR_SIZE_VER0,
            sched_policy: policy,
            sched_flags: flags,
            sched_nice: 0,
            sched_priority: 0,
            sched_runtime: runtime,
            sched_deadline: deadline,
            sched_period: period,
        }
    } else if is_rt_policy(policy) {
        SchedAttr {
            size: SCHED_ATTR_SIZE_VER0,
            sched_policy: policy,
            sched_flags: flags,
            sched_nice: 0,
            sched_priority: rt_priority,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
        }
    } else {
        SchedAttr {
            size: SCHED_ATTR_SIZE_VER0,
            sched_policy: policy,
            sched_flags: flags,
            sched_nice: nice,
            sched_priority: 0,
            sched_runtime: 0,
            sched_deadline: 0,
            sched_period: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(policy: u32, rt_priority: u32, nice: i32) -> TargetSchedSnapshot {
        TargetSchedSnapshot {
            policy,
            rt_priority,
            nice,
            ruid: 1000,
            euid: 1000,
            rlim_nice: 0,
            rlim_rtprio: 0,
        }
    }

    fn unpriv(euid: u32) -> CallerCreds {
        CallerCreds {
            euid,
            has_cap_sys_nice: false,
        }
    }

    #[test]
    fn ltp_sched_get_priority_min_max_deadline_and_ranges() {
        assert_eq!(sched_priority_min(SCHED_NORMAL as usize), Ok(0));
        assert_eq!(sched_priority_max(SCHED_NORMAL as usize), Ok(0));
        assert_eq!(sched_priority_min(SCHED_BATCH as usize), Ok(0));
        assert_eq!(sched_priority_max(SCHED_BATCH as usize), Ok(0));
        assert_eq!(sched_priority_min(SCHED_IDLE as usize), Ok(0));
        assert_eq!(sched_priority_max(SCHED_IDLE as usize), Ok(0));
        assert_eq!(sched_priority_min(SCHED_DEADLINE as usize), Ok(0));
        assert_eq!(sched_priority_max(SCHED_DEADLINE as usize), Ok(0));
        assert_eq!(sched_priority_min(SCHED_FIFO as usize), Ok(1));
        assert_eq!(sched_priority_max(SCHED_FIFO as usize), Ok(99));
        assert_eq!(sched_priority_min(SCHED_RR as usize), Ok(1));
        assert_eq!(sched_priority_max(SCHED_RR as usize), Ok(99));

        assert_eq!(sched_priority_min(999), Err(LinuxError::EINVAL));
        assert_eq!(sched_priority_max(999), Err(LinuxError::EINVAL));
        assert_eq!(sched_priority_min((-1i32) as usize), Err(LinuxError::EINVAL));
        assert_eq!(sched_priority_max((-1i32) as usize), Err(LinuxError::EINVAL));
    }

    #[test]
    fn ltp_sched_setparam04_validates_against_current_policy() {
        assert_eq!(
            validate_sched_setparam(SCHED_NORMAL, -5, 1),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setparam(SCHED_BATCH, 0, 1),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setparam(SCHED_IDLE, 0, 1),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setparam(SCHED_NORMAL, -5, 0),
            Ok(SchedChangeRequest {
                policy: SCHED_NORMAL,
                rt_priority: 0,
                nice: -5,
                update_nice: false,
                flags: 0,
                runtime: 0,
                deadline: 0,
                period: 0,
            })
        );
        assert_eq!(
            validate_sched_setparam(SCHED_FIFO, 3, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setparam(SCHED_RR, 3, 100),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setparam(SCHED_FIFO, 3, -1),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setparam(SCHED_RR, 3, 50),
            Ok(SchedChangeRequest {
                policy: SCHED_RR,
                rt_priority: 50,
                nice: 3,
                update_nice: false,
                flags: 0,
                runtime: 0,
                deadline: 0,
                period: 0,
            })
        );
        assert_eq!(
            validate_sched_setparam(SCHED_DEADLINE, 0, 0),
            Err(LinuxError::EINVAL)
        );
    }

    #[test]
    fn ltp_sched_getattr02_rejects_null_bad_size_negative_pid_and_flags() {
        assert_eq!(
            validate_sched_getattr_args(0, 0, 48, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_getattr_args((-1i32) as usize, 0x1000, 48, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_getattr_args(0, 0x1000, 47, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_getattr_args(0, 0x1000, 4097, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_getattr_args(0, 0x1000, 48, 1000),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(validate_sched_getattr_args(0, 0x1000, 48, 0), Ok(48));
        assert_eq!(validate_sched_getattr_args(0, 0x1000, 56, 0), Ok(56));
    }

    #[test]
    fn ltp_sched_setattr02_validates_args_sizes_and_policy_params() {
        assert_eq!(
            validate_sched_setattr_args(0, 0, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setattr_args((-1i32) as usize, 0x1000, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setattr_args(0, 0x1000, 1000),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(validate_sched_setattr_args(0, 0x1000, 0), Ok(()));

        assert_eq!(decode_sched_setattr_size(0), Ok(48));
        assert_eq!(decode_sched_setattr_size(48), Ok(48));
        assert_eq!(decode_sched_setattr_size(56), Ok(56));
        assert_eq!(decode_sched_setattr_size(47), Err(LinuxError::E2BIG));
        assert_eq!(decode_sched_setattr_size(4097), Err(LinuxError::E2BIG));

        assert_eq!(check_zeroed_extension_bytes(&[0; 8]), Ok(()));
        assert_eq!(
            check_zeroed_extension_bytes(&[0, 0, 1, 0]),
            Err(LinuxError::E2BIG)
        );

        let invalid_policy = SchedAttr {
            size: 48,
            sched_policy: 999,
            ..Default::default()
        };
        assert_eq!(
            validate_sched_setattr(invalid_policy, 0),
            Err(LinuxError::EINVAL)
        );

        let neg_policy = SchedAttr {
            size: 48,
            sched_policy: (-1i32) as u32,
            ..Default::default()
        };
        assert_eq!(
            validate_sched_setattr(neg_policy, 0),
            Err(LinuxError::EINVAL)
        );

        let unsupported_flags = SchedAttr {
            size: 48,
            sched_policy: SCHED_NORMAL,
            sched_flags: 1,
            ..Default::default()
        };
        assert_eq!(
            validate_sched_setattr(unsupported_flags, 0),
            Err(LinuxError::EINVAL)
        );

        let bad_dl = SchedAttr {
            size: 48,
            sched_policy: SCHED_DEADLINE,
            sched_runtime: 30_000_000,
            sched_deadline: 10_000_000,
            sched_period: 30_000_000,
            ..Default::default()
        };
        assert_eq!(validate_sched_setattr(bad_dl, 0), Err(LinuxError::EINVAL));

        let good_dl = SchedAttr {
            size: 48,
            sched_policy: SCHED_DEADLINE,
            sched_runtime: 10_000_000,
            sched_deadline: 30_000_000,
            sched_period: 30_000_000,
            ..Default::default()
        };
        assert_eq!(
            validate_sched_setattr(good_dl, 7),
            Ok(SchedChangeRequest {
                policy: SCHED_DEADLINE,
                rt_priority: 0,
                nice: 7,
                update_nice: false,
                flags: 0,
                runtime: 10_000_000,
                deadline: 30_000_000,
                period: 30_000_000,
            })
        );

        let clamped_nice = SchedAttr {
            size: 48,
            sched_policy: SCHED_NORMAL,
            sched_nice: -50,
            ..Default::default()
        };
        assert_eq!(
            validate_sched_setattr(clamped_nice, 0),
            Ok(SchedChangeRequest {
                policy: SCHED_NORMAL,
                rt_priority: 0,
                nice: -20,
                update_nice: true,
                flags: 0,
                runtime: 0,
                deadline: 0,
                period: 0,
            })
        );
    }

    #[test]
    fn sched_setscheduler_validation_rejects_deadline_and_bad_priorities() {
        assert_eq!(
            validate_sched_setscheduler(SCHED_DEADLINE as usize, 0, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setscheduler((-1i32) as usize, 0, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setscheduler(SCHED_NORMAL as usize, 1, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setscheduler(SCHED_FIFO as usize, 0, 0),
            Err(LinuxError::EINVAL)
        );
        assert_eq!(
            validate_sched_setscheduler(SCHED_RR as usize, 99, -4),
            Ok(SchedChangeRequest {
                policy: SCHED_RR,
                rt_priority: 99,
                nice: -4,
                update_nice: false,
                flags: 0,
                runtime: 0,
                deadline: 0,
                period: 0,
            })
        );
    }

    #[test]
    fn ltp_sched_setscheduler02_and_03_credentials_and_rlimits() {
        // sched_setscheduler02: unprivileged FIFO denied when RLIMIT_RTPRIO == 0
        let req_fifo_1 = validate_sched_setscheduler(SCHED_FIFO as usize, 1, 0).unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &target(SCHED_NORMAL, 0, 0), &req_fifo_1),
            Err(LinuxError::EPERM)
        );

        // sched_setscheduler03: RLIMIT_NICE = 19, current nice = 0, setting OTHER/BATCH/IDLE succeeds
        let mut snap = target(SCHED_NORMAL, 0, 0);
        snap.rlim_nice = 19;
        for pol in [SCHED_NORMAL, SCHED_BATCH, SCHED_IDLE] {
            let req = validate_sched_setscheduler(pol as usize, 0, 0).unwrap();
            assert_eq!(authorize_sched_change(unpriv(1000), &snap, &req), Ok(()));
        }

        // Leaving SCHED_IDLE requires RLIMIT_NICE >= nice_to_rlimit(current_nice)
        let mut idle_snap = target(SCHED_IDLE, 0, 0);
        idle_snap.rlim_nice = 19;
        let req_other = validate_sched_setscheduler(SCHED_NORMAL as usize, 0, 0).unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &idle_snap, &req_other),
            Err(LinuxError::EPERM)
        );
        idle_snap.rlim_nice = 20;
        assert_eq!(
            authorize_sched_change(unpriv(1000), &idle_snap, &req_other),
            Ok(())
        );

        // RT priority changes under RLIMIT_RTPRIO
        let mut rt_snap = target(SCHED_FIFO, 10, 0);
        rt_snap.rlim_rtprio = 0;
        let lower_fifo = validate_sched_setparam(SCHED_FIFO, 0, 5).unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &rt_snap, &lower_fifo),
            Ok(())
        );
        let switch_to_rr = validate_sched_setscheduler(SCHED_RR as usize, 5, 0).unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &rt_snap, &switch_to_rr),
            Err(LinuxError::EPERM)
        );
        let raise_fifo = validate_sched_setparam(SCHED_FIFO, 0, 11).unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &rt_snap, &raise_fifo),
            Err(LinuxError::EPERM)
        );
        rt_snap.rlim_rtprio = 11;
        assert_eq!(
            authorize_sched_change(unpriv(1000), &rt_snap, &raise_fifo),
            Ok(())
        );
        assert_eq!(
            authorize_sched_change(unpriv(1000), &rt_snap, &switch_to_rr),
            Ok(())
        );

        // sched_setattr lowering nice against RLIMIT_NICE
        let mut nice_snap = target(SCHED_NORMAL, 0, 0);
        nice_snap.rlim_nice = 25; // allows down to nice -5
        let req_nice_m5 = validate_sched_setattr(
            SchedAttr {
                size: 48,
                sched_policy: SCHED_NORMAL,
                sched_nice: -5,
                ..Default::default()
            },
            0,
        )
        .unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &nice_snap, &req_nice_m5),
            Ok(())
        );
        let req_nice_m6 = validate_sched_setattr(
            SchedAttr {
                size: 48,
                sched_policy: SCHED_NORMAL,
                sched_nice: -6,
                ..Default::default()
            },
            0,
        )
        .unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &nice_snap, &req_nice_m6),
            Err(LinuxError::EPERM)
        );

        // Cross-owner and SCHED_DEADLINE checks
        assert_eq!(
            authorize_sched_change(unpriv(2000), &target(SCHED_NORMAL, 0, 0), &req_other),
            Err(LinuxError::EPERM)
        );
        let req_dl = validate_sched_setattr(
            SchedAttr {
                size: 48,
                sched_policy: SCHED_DEADLINE,
                sched_runtime: 1000,
                sched_deadline: 2000,
                sched_period: 3000,
                ..Default::default()
            },
            0,
        )
        .unwrap();
        assert_eq!(
            authorize_sched_change(unpriv(1000), &target(SCHED_NORMAL, 0, 0), &req_dl),
            Err(LinuxError::EPERM)
        );

        // CAP_SYS_NICE overrides all restrictions
        let priv_caller = CallerCreds {
            euid: 2000,
            has_cap_sys_nice: true,
        };
        assert_eq!(
            authorize_sched_change(priv_caller, &target(SCHED_NORMAL, 0, 0), &req_dl),
            Ok(())
        );
        assert_eq!(
            authorize_sched_change(priv_caller, &target(SCHED_NORMAL, 0, 0), &req_fifo_1),
            Ok(())
        );
    }

    #[test]
    fn format_sched_attr_and_eevdf_priority_match_policy() {
        let dl_attr = format_sched_attr_for_policy(
            SCHED_DEADLINE,
            0,
            -5,
            12,
            10_000_000,
            30_000_000,
            30_000_000,
        );
        assert_eq!(dl_attr.size, 48);
        assert_eq!(dl_attr.sched_nice, 0);
        assert_eq!(dl_attr.sched_priority, 0);
        assert_eq!(dl_attr.sched_runtime, 10_000_000);
        assert_eq!(dl_attr.sched_deadline, 30_000_000);
        assert_eq!(dl_attr.sched_period, 30_000_000);

        let rt_attr = format_sched_attr_for_policy(SCHED_FIFO, 0, -5, 42, 100, 200, 300);
        assert_eq!(rt_attr.sched_nice, 0);
        assert_eq!(rt_attr.sched_priority, 42);
        assert_eq!(rt_attr.sched_runtime, 0);
        assert_eq!(rt_attr.sched_deadline, 0);
        assert_eq!(rt_attr.sched_period, 0);

        let fair_attr = format_sched_attr_for_policy(SCHED_NORMAL, 0, -5, 42, 100, 200, 300);
        assert_eq!(fair_attr.sched_nice, -5);
        assert_eq!(fair_attr.sched_priority, 0);
        assert_eq!(fair_attr.sched_runtime, 0);
        assert_eq!(fair_attr.sched_deadline, 0);
        assert_eq!(fair_attr.sched_period, 0);

        let req_idle = validate_sched_setscheduler(SCHED_IDLE as usize, 0, -5).unwrap();
        assert_eq!(eevdf_priority_for_request(&req_idle), -81);
        let req_fair = validate_sched_setscheduler(SCHED_NORMAL as usize, 0, -5).unwrap();
        assert_eq!(eevdf_priority_for_request(&req_fair), -105);
        let req_rt = validate_sched_setscheduler(SCHED_RR as usize, 25, -5).unwrap();
        assert_eq!(eevdf_priority_for_request(&req_rt), 25);
    }
}
