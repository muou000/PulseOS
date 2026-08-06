use alloc::{collections::VecDeque, sync::Arc, vec::Vec};
use core::{
    array,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
};

use axerrno::{AxError, AxResult};
use axhal::context::TrapFrame;
use axtask::WaitQueue;
use hashbrown::HashMap;
use kspin::SpinNoIrq;
use linux_raw_sys::general::{
    _NSIG, CAP_KILL, MINSIGSTKSZ, SA_NODEFER, SA_ONSTACK, SA_RESETHAND, SI_KERNEL, SIGBUS, SIGCHLD,
    SIGCONT, SIGFPE, SIGILL, SIGKILL, SIGSEGV, SIGSTOP, SIGSYS, SIGTRAP, SIGTSTP, SIGTTIN, SIGTTOU,
    SIGURG, SIGWINCH, SS_AUTODISARM, SS_DISABLE, SS_FLAG_BITS, SS_ONSTACK, siginfo,
};
use spin::{Lazy, Mutex};

use super::{Process, Thread};

pub const SIG_DFL: usize = 0;
pub const SIG_IGN: usize = 1;

const SIGINFO_FRAME_SIZE: usize = 128;
pub const SIGRTMIN: usize = 32;
const STANDARD_SIGNAL_MAX: usize = SIGRTMIN - 1;
const REALTIME_SIGNAL_COUNT: usize = (_NSIG as usize) - SIGRTMIN + 1;

const _: () = assert!(SIGINFO_FRAME_SIZE == core::mem::size_of::<siginfo>());

#[inline]
fn sig_bit(sig: usize) -> Option<u64> {
    if (1..=(_NSIG as usize)).contains(&sig) {
        Some(1u64 << (sig - 1))
    } else {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SigAction {
    pub handler: usize,
    pub flags: usize,
    pub mask: u64,
}

impl SigAction {
    pub const fn dfl() -> Self {
        Self {
            handler: SIG_DFL,
            flags: 0,
            mask: 0,
        }
    }

    pub const fn from_parts(handler: usize, flags: usize, mask: u64) -> Self {
        Self {
            handler,
            flags,
            mask,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum DefaultSignalAction {
    Ignore,
    Terminate,
    /// 终止进程并设置 core dump 标志位（不需要实际写文件）
    CoreDump,
    Stop,
    Continue,
}

#[derive(Clone, Copy, Debug)]
pub enum SignalAction {
    Ignore,
    Default(DefaultSignalAction),
    Handler(SigAction),
}

#[derive(Clone, Copy, Debug)]
pub struct SignalDelivery {
    pub sig: usize,
    pub action: SignalAction,
}

#[derive(Clone, Copy, Debug)]
pub struct SignalAltStack {
    pub sp: usize,
    pub size: usize,
    pub flags: usize,
}

impl SignalAltStack {
    const fn disabled() -> Self {
        Self {
            sp: 0,
            size: 0,
            flags: SS_DISABLE as usize,
        }
    }

    fn is_disabled(self) -> bool {
        (self.flags & SS_DISABLE as usize) != 0
    }

    fn is_active(self) -> bool {
        (self.flags & SS_ONSTACK as usize) != 0
    }

    fn is_autodisarm(self) -> bool {
        (self.flags & SS_AUTODISARM as usize) != 0
    }

    fn contains(self, sp: usize) -> bool {
        !self.is_disabled() && sp.wrapping_sub(self.sp) < self.size
    }

    fn without_runtime_flags(mut self) -> Self {
        self.flags &= !(SS_ONSTACK as usize);
        self
    }

    fn set_active_for_sp(&mut self, sp: usize) {
        self.flags &= !(SS_ONSTACK as usize);
        if self.contains(sp) {
            self.flags |= SS_ONSTACK as usize;
        }
    }

    /// Normalizes the subset of `stack_t` flags accepted by Linux.  `SS_ONSTACK`
    /// is a compatibility input value, not persistent configuration; runtime
    /// activity is derived from the restored user stack pointer instead.
    pub fn from_user_parts(sp: usize, size: usize, flags: u32) -> Option<Self> {
        let mode = flags & !SS_FLAG_BITS;
        match mode {
            SS_DISABLE => Some(Self {
                sp: 0,
                size: 0,
                flags: (SS_DISABLE | (flags & SS_FLAG_BITS)) as usize,
            }),
            0 | SS_ONSTACK => Some(Self {
                sp,
                size,
                flags: (flags & SS_FLAG_BITS) as usize,
            }),
            _ => None,
        }
    }
}

#[cfg(target_arch = "riscv64")]
type SignalFpState = axcpu::FpState;
#[cfg(target_arch = "loongarch64")]
type SignalFpState = axcpu::FpuState;

#[derive(Clone, Copy, Debug)]
struct SavedSignalContext {
    tf: TrapFrame,
    old_mask: u64,
    user_ucontext: Option<usize>,
    fp: SignalFpState,
}

/// The Linux limit is a per-real-UID count, while each queued record keeps the
/// UID it charged. Keeping the UID in the record means a later credential
/// change cannot release the wrong account.
///
/// The counter is sharded because unrelated UIDs must not serialize real-time
/// signal admission on one global spin lock. A single UID still maps to one
/// shard, which preserves the required per-UID limit.
const SIGPENDING_COUNT_SHARDS: usize = 16;
static SIGPENDING_COUNTS: Lazy<[SpinNoIrq<HashMap<u32, u64>>; SIGPENDING_COUNT_SHARDS]> =
    Lazy::new(|| array::from_fn(|_| SpinNoIrq::new(HashMap::new())));

#[inline]
fn sigpending_count_shard(ruid: u32) -> &'static SpinNoIrq<HashMap<u32, u64>> {
    &SIGPENDING_COUNTS[ruid as usize % SIGPENDING_COUNT_SHARDS]
}

#[derive(Debug)]
struct PendingSignalReservation {
    ruid: u32,
}

impl PendingSignalReservation {
    fn try_acquire(ruid: u32, limit: u64) -> Option<Self> {
        let mut counts = sigpending_count_shard(ruid).lock();
        match counts.get_mut(&ruid) {
            Some(count) => {
                if *count >= limit || *count == u64::MAX {
                    return None;
                }
                *count += 1;
            }
            None => {
                if limit == 0 || counts.try_reserve(1).is_err() {
                    return None;
                }
                counts.insert(ruid, 1);
            }
        }
        Some(Self { ruid })
    }

    fn release(self) {
        let mut counts = sigpending_count_shard(self.ruid).lock();
        let remove = match counts.get_mut(&self.ruid) {
            Some(count) => {
                debug_assert!(*count != 0, "signal pending count underflow");
                *count = count.saturating_sub(1);
                *count == 0
            }
            None => {
                debug_assert!(false, "signal pending reservation released twice");
                return;
            }
        };
        if remove {
            counts.remove(&self.ruid);
        }
    }
}

#[cfg(test)]
fn sigpending_count(ruid: u32) -> u64 {
    sigpending_count_shard(ruid)
        .lock()
        .get(&ruid)
        .copied()
        .unwrap_or(0)
}

#[derive(Clone, Copy)]
enum QueueAdmission {
    Untracked,
    BestEffort { ruid: u32, limit: u64 },
    Required { ruid: u32, limit: u64 },
}

impl QueueAdmission {
    fn best_effort(process: &Process) -> Self {
        Self::BestEffort {
            ruid: process.ruid(),
            limit: process.sigpending_limit(),
        }
    }

    fn required(process: &Process) -> Self {
        Self::Required {
            ruid: process.ruid(),
            limit: process.sigpending_limit(),
        }
    }

    fn reserve(self, sig: usize) -> Result<Option<PendingSignalReservation>, QueuePutResult> {
        if matches!(self, Self::Untracked) || sig == SIGKILL as usize {
            return Ok(None);
        }
        let (ruid, limit) = match self {
            Self::BestEffort { ruid, limit } | Self::Required { ruid, limit } => (ruid, limit),
            Self::Untracked => unreachable!(),
        };
        PendingSignalReservation::try_acquire(ruid, limit)
            .map(Some)
            .ok_or_else(|| self.exhaustion_result())
    }

    fn exhaustion_result(self) -> QueuePutResult {
        match self {
            Self::Required { .. } => QueuePutResult::LimitExceeded,
            Self::Untracked | Self::BestEffort { .. } => QueuePutResult::Fallback,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum QueuePutResult {
    Queued,
    Coalesced,
    /// Linux still sets the pending bit after best-effort allocation failure,
    /// but it has no queue record from which to recover the original siginfo.
    Fallback,
    LimitExceeded,
    Invalid,
}

impl QueuePutResult {
    fn is_pending(self) -> bool {
        matches!(self, Self::Queued | Self::Fallback)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SignalQueueError {
    Limit,
}

/// One queued signal together with the ABI data that must remain associated
/// with that delivery.  Keeping this object in the same queue as its signal
/// bit avoids the old bitmap/map race and preserves Linux's first-info rule
/// for standard signals.
#[derive(Debug)]
struct PendingSignal {
    sig: usize,
    info: [u8; SIGINFO_FRAME_SIZE],
    reservation: Option<PendingSignalReservation>,
}

impl PendingSignal {
    fn new(
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
        reservation: Option<PendingSignalReservation>,
    ) -> Self {
        Self {
            sig,
            info: info.unwrap_or_else(|| default_siginfo(sig)),
            reservation,
        }
    }

    fn fallback(sig: usize) -> Self {
        Self::new(sig, None, None)
    }

    fn release_reservation(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            reservation.release();
        }
    }
}

/// Pending signals for one thread or one process-directed queue.
///
/// Standard signals coalesce into one slot and retain the first siginfo.
/// Real-time signals remain queued FIFO per signal number.  The bitmap is an
/// index into the queues, not the authoritative storage, so signal number and
/// siginfo are always consumed atomically under the same lock.  `fallback_mask`
/// represents a set pending bit without a queue record after Linux's
/// best-effort allocation fallback.
struct PendingSignals {
    mask: u64,
    synchronous_mask: u64,
    fallback_mask: u64,
    // Standard signals need at most one record per number. Keep those records
    // in small, lazily allocated queues rather than reserving a siginfo-sized
    // slot for every signal in every thread and process.
    standard: VecDeque<PendingSignal>,
    synchronous: VecDeque<PendingSignal>,
    realtime: [VecDeque<PendingSignal>; REALTIME_SIGNAL_COUNT],
}

impl Default for PendingSignals {
    fn default() -> Self {
        Self {
            mask: 0,
            synchronous_mask: 0,
            fallback_mask: 0,
            standard: VecDeque::new(),
            synchronous: VecDeque::new(),
            realtime: array::from_fn(|_| VecDeque::new()),
        }
    }
}

impl PendingSignals {
    fn contains_standard(queue: &VecDeque<PendingSignal>, sig: usize) -> bool {
        queue.iter().any(|pending| pending.sig == sig)
    }

    fn take_standard(queue: &mut VecDeque<PendingSignal>, sig: usize) -> Option<PendingSignal> {
        let index = queue.iter().position(|pending| pending.sig == sig)?;
        queue.remove(index)
    }

    fn push_standard(
        queue: &mut VecDeque<PendingSignal>,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
        mut reservation: Option<PendingSignalReservation>,
    ) -> Result<(), ()> {
        if queue.try_reserve(1).is_err() {
            if let Some(reservation) = reservation.take() {
                reservation.release();
            }
            return Err(());
        }
        queue.push_back(PendingSignal::new(sig, info, reservation));
        Ok(())
    }

    fn put(&mut self, sig: usize, info: Option<[u8; SIGINFO_FRAME_SIZE]>) -> bool {
        self.put_with_admission(sig, info, QueueAdmission::Untracked)
            .is_pending()
    }

    fn put_with_admission(
        &mut self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
        admission: QueueAdmission,
    ) -> QueuePutResult {
        self.put_with_priority_and_admission(sig, info, false, admission)
    }

    /// Faults caused by the current instruction must be selected before an
    /// unrelated asynchronous signal.  Linux gives thread-private synchronous
    /// faults a dedicated dequeue pass for this reason.
    fn put_synchronous(&mut self, sig: usize, info: Option<[u8; SIGINFO_FRAME_SIZE]>) -> bool {
        self.put_with_priority_and_admission(sig, info, true, QueueAdmission::Untracked)
            .is_pending()
    }

    fn put_with_priority_and_admission(
        &mut self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
        synchronous: bool,
        admission: QueueAdmission,
    ) -> QueuePutResult {
        let Some(bit) = sig_bit(sig) else {
            return QueuePutResult::Invalid;
        };

        if sig <= STANDARD_SIGNAL_MAX {
            if synchronous && is_synchronous_fault_signal(sig) {
                if Self::contains_standard(&self.synchronous, sig) {
                    return QueuePutResult::Coalesced;
                }
                let reservation = match admission.reserve(sig) {
                    Ok(reservation) => reservation,
                    Err(result) => return self.record_fallback(bit, result),
                };
                if Self::push_standard(&mut self.synchronous, sig, info, reservation).is_err() {
                    return self.record_fallback(bit, admission.exhaustion_result());
                }
                self.synchronous_mask |= bit;
                self.mask |= bit;
                return QueuePutResult::Queued;
            }

            if Self::contains_standard(&self.standard, sig)
                || Self::contains_standard(&self.synchronous, sig)
                || (self.fallback_mask & bit) != 0
            {
                // Linux coalesces ordinary standard signals and preserves
                // the first siginfo supplied while the signal is pending.
                return QueuePutResult::Coalesced;
            }
            let reservation = match admission.reserve(sig) {
                Ok(reservation) => reservation,
                Err(result) => return self.record_fallback(bit, result),
            };
            if Self::push_standard(&mut self.standard, sig, info, reservation).is_err() {
                return self.record_fallback(bit, admission.exhaustion_result());
            }
            self.mask |= bit;
            return QueuePutResult::Queued;
        }

        let mut reservation = match admission.reserve(sig) {
            Ok(reservation) => reservation,
            Err(result) => return self.record_fallback(bit, result),
        };
        let queue = &mut self.realtime[sig - SIGRTMIN];
        if queue.try_reserve(1).is_err() {
            if let Some(reservation) = reservation.take() {
                reservation.release();
            }
            return self.record_fallback(bit, admission.exhaustion_result());
        }
        queue.push_back(PendingSignal::new(sig, info, reservation));
        self.mask |= bit;
        QueuePutResult::Queued
    }

    fn record_fallback(&mut self, bit: u64, result: QueuePutResult) -> QueuePutResult {
        if result == QueuePutResult::Fallback {
            self.fallback_mask |= bit;
            self.mask |= bit;
        }
        result
    }

    fn select_signal(&self, eligible: u64) -> Option<usize> {
        let ready = self.mask & eligible;
        if ready == 0 {
            return None;
        }
        let synchronous = ready & self.synchronous_mask;
        Some(if synchronous != 0 {
            synchronous.trailing_zeros() as usize + 1
        } else {
            ready.trailing_zeros() as usize + 1
        })
    }

    /// Returns the two signal sets in the order `dequeue` considers them.
    /// A caller can inspect dispositions after releasing the pending-queue
    /// lock, which avoids inverting the pending/sighand lock order.
    fn delivery_masks(&self, eligible: u64) -> [u64; 2] {
        let ready = self.mask & eligible;
        [
            ready & self.synchronous_mask,
            ready & !self.synchronous_mask,
        ]
    }

    fn dequeue(&mut self, eligible: u64) -> Option<PendingSignal> {
        let sig = self.select_signal(eligible)?;
        let bit = sig_bit(sig)?;

        if sig <= STANDARD_SIGNAL_MAX {
            if (self.synchronous_mask & bit) != 0 {
                let mut pending = Self::take_standard(&mut self.synchronous, sig)?;
                pending.release_reservation();
                self.synchronous_mask &= !bit;
                if !Self::contains_standard(&self.standard, sig) && (self.fallback_mask & bit) == 0
                {
                    self.mask &= !bit;
                }
                return Some(pending);
            }

            if let Some(mut pending) = Self::take_standard(&mut self.standard, sig) {
                pending.release_reservation();
                if !Self::contains_standard(&self.synchronous, sig)
                    && (self.fallback_mask & bit) == 0
                {
                    self.mask &= !bit;
                }
                return Some(pending);
            }
            if (self.fallback_mask & bit) != 0 {
                self.fallback_mask &= !bit;
                if !Self::contains_standard(&self.synchronous, sig) {
                    self.mask &= !bit;
                }
                return Some(PendingSignal::fallback(sig));
            }
            self.mask &= !bit;
            return None;
        }

        let queue = &mut self.realtime[sig - SIGRTMIN];
        if let Some(mut pending) = queue.pop_front() {
            pending.release_reservation();
            if queue.is_empty() {
                // A real queue record supersedes a previously fallback-only
                // pending bit when it is the last record for this signal.
                self.mask &= !bit;
                self.fallback_mask &= !bit;
            }
            return Some(pending);
        }
        if (self.fallback_mask & bit) != 0 {
            self.fallback_mask &= !bit;
            self.mask &= !bit;
            return Some(PendingSignal::fallback(sig));
        }
        self.mask &= !bit;
        None
    }

    fn mask(&self) -> u64 {
        self.mask
    }

    fn clear(&mut self, sig: usize) {
        let Some(bit) = sig_bit(sig) else {
            return;
        };
        if sig <= STANDARD_SIGNAL_MAX {
            while let Some(mut pending) = Self::take_standard(&mut self.standard, sig) {
                pending.release_reservation();
            }
            while let Some(mut pending) = Self::take_standard(&mut self.synchronous, sig) {
                pending.release_reservation();
            }
        } else {
            while let Some(mut pending) = self.realtime[sig - SIGRTMIN].pop_front() {
                pending.release_reservation();
            }
        }
        self.mask &= !bit;
        self.synchronous_mask &= !bit;
        self.fallback_mask &= !bit;
    }

    fn clear_mask(&mut self, mut mask: u64) {
        while mask != 0 {
            let sig = mask.trailing_zeros() as usize + 1;
            mask &= mask - 1;
            self.clear(sig);
        }
    }
}

impl Drop for PendingSignals {
    fn drop(&mut self) {
        if self.mask == 0 {
            return;
        }
        for sig in 1..=(_NSIG as usize) {
            self.clear(sig);
        }
    }
}

fn is_synchronous_fault_signal(sig: usize) -> bool {
    matches!(
        sig as u32,
        SIGSEGV | SIGBUS | SIGILL | SIGTRAP | SIGFPE | SIGSYS
    )
}

fn default_siginfo(sig: usize) -> [u8; SIGINFO_FRAME_SIZE] {
    let mut info: siginfo = unsafe { core::mem::zeroed() };
    info.__bindgen_anon_1.__bindgen_anon_1.si_signo = sig as linux_raw_sys::ctypes::c_int;
    unsafe { core::mem::transmute(info) }
}

fn forced_siginfo(sig: usize) -> [u8; SIGINFO_FRAME_SIZE] {
    let mut info: siginfo = unsafe { core::mem::zeroed() };
    unsafe {
        let header = &mut info.__bindgen_anon_1.__bindgen_anon_1;
        header.si_signo = sig as linux_raw_sys::ctypes::c_int;
        header.si_errno = 0;
        header.si_code = SI_KERNEL as i32;
    }
    unsafe { core::mem::transmute::<siginfo, [u8; SIGINFO_FRAME_SIZE]>(info) }
}

/// Constructs the `siginfo_t` payload for a synchronous instruction or
/// memory fault.  The fault union is zeroed before selecting its `si_addr`
/// member, matching the kernel ABI layout used by userspace signal handlers.
pub fn signal_info_for_fault(sig: usize, code: i32, fault_addr: usize) -> [u8; 128] {
    let mut info: siginfo = unsafe { core::mem::zeroed() };
    unsafe {
        let header = &mut info.__bindgen_anon_1.__bindgen_anon_1;
        header.si_signo = sig as linux_raw_sys::ctypes::c_int;
        header.si_errno = 0;
        header.si_code = code;
        header._sifields._sigfault._addr = fault_addr as *mut linux_raw_sys::ctypes::c_void;
    }
    unsafe { core::mem::transmute::<siginfo, [u8; SIGINFO_FRAME_SIZE]>(info) }
}

/// Constructs the `SIGCHLD` payload for a child state transition.
pub fn signal_info_for_child(child_pid: u64, child_uid: u32, code: i32, status: i32) -> [u8; 128] {
    let mut info: siginfo = unsafe { core::mem::zeroed() };
    unsafe {
        let header = &mut info.__bindgen_anon_1.__bindgen_anon_1;
        header.si_signo = SIGCHLD as linux_raw_sys::ctypes::c_int;
        header.si_errno = 0;
        header.si_code = code;
        let child = &mut header._sifields._sigchld;
        child._pid = child_pid as _;
        child._uid = child_uid as _;
        child._status = status;
    }
    unsafe { core::mem::transmute::<siginfo, [u8; SIGINFO_FRAME_SIZE]>(info) }
}

pub struct SignalHandlers {
    actions: SpinNoIrq<[SigAction; (_NSIG as usize) + 1]>,
    /// Mirrors dispositions that discard a pending signal. This is maintained
    /// under `actions` so hot pending predicates can skip a per-signal sighand
    /// lock without risking a false negative during a disposition change.
    ignored_mask: AtomicU64,
}

pub struct SignalShared {
    handlers: Arc<SignalHandlers>,
    process_pending: SpinNoIrq<PendingSignals>,
    /// Lock-free mirror of `process_pending.mask`. It is an advisory snapshot:
    /// a stale set bit merely makes a later exact dequeue recheck the queue.
    pending_bits: AtomicU64,
}

impl SignalShared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            handlers: Arc::new(SignalHandlers {
                actions: SpinNoIrq::new([SigAction::dfl(); (_NSIG as usize) + 1]),
                ignored_mask: AtomicU64::new(default_ignored_mask()),
            }),
            process_pending: SpinNoIrq::new(PendingSignals::default()),
            pending_bits: AtomicU64::new(0),
        })
    }

    pub fn clone_sighand_only(from: &Arc<Self>) -> Arc<Self> {
        Arc::new(Self {
            handlers: from.handlers.clone(),
            process_pending: SpinNoIrq::new(PendingSignals::default()),
            pending_bits: AtomicU64::new(0),
        })
    }

    pub fn clone_actions_only(from: &Arc<Self>) -> Arc<Self> {
        let actions = *from.handlers.actions.lock();
        Arc::new(Self {
            handlers: Arc::new(SignalHandlers {
                actions: SpinNoIrq::new(actions),
                ignored_mask: AtomicU64::new(ignored_mask_for_actions(&actions)),
            }),
            process_pending: SpinNoIrq::new(PendingSignals::default()),
            pending_bits: AtomicU64::new(0),
        })
    }

    pub fn action(&self, sig: usize) -> SigAction {
        self.handlers.actions.lock()[sig]
    }

    pub fn set_action(&self, sig: usize, act: SigAction) {
        let mut actions = self.handlers.actions.lock();
        let old = actions[sig];
        let old_ignored = sigaction_is_ignored(sig, old);
        let new_ignored = sigaction_is_ignored(sig, act);
        let bit = sig_bit(sig).unwrap_or(0);
        if old_ignored && !new_ignored {
            // Clear before publishing a newly catchable action. A concurrent
            // predicate can only produce a harmless false positive here.
            self.handlers
                .ignored_mask
                .fetch_and(!bit, Ordering::Release);
        }
        actions[sig] = act;
        if !old_ignored && new_ignored {
            // Set after publishing an ignored action. A concurrent predicate
            // can only produce a harmless extra wake before this store.
            self.handlers.ignored_mask.fetch_or(bit, Ordering::Release);
        }
    }

    /// Returns the previous disposition and, when supplied, installs the new
    /// one while holding the same sighand lock.  `rt_sigaction` needs this
    /// combined operation so its old-action result cannot be paired with a
    /// disposition installed by a concurrent caller.
    pub fn replace_action(&self, sig: usize, new: Option<SigAction>) -> SigAction {
        let mut actions = self.handlers.actions.lock();
        let old = actions[sig];
        if let Some(new) = new {
            let old_ignored = sigaction_is_ignored(sig, old);
            let new_ignored = sigaction_is_ignored(sig, new);
            let bit = sig_bit(sig).unwrap_or(0);
            if old_ignored && !new_ignored {
                self.handlers
                    .ignored_mask
                    .fetch_and(!bit, Ordering::Release);
            }
            actions[sig] = new;
            if !old_ignored && new_ignored {
                self.handlers.ignored_mask.fetch_or(bit, Ordering::Release);
            }
        }
        old
    }

    pub fn reset_dispositions_on_exec(&self) {
        let mut actions = self.handlers.actions.lock();
        let mut ignored = 0;
        for sig in 1..=(_NSIG as usize) {
            let old_ignored = sigaction_is_ignored(sig, actions[sig]);
            let handler = if actions[sig].handler == SIG_IGN {
                SIG_IGN
            } else {
                SIG_DFL
            };
            let new_action = SigAction::from_parts(handler, 0, 0);
            let new_ignored = sigaction_is_ignored(sig, new_action);
            let bit = sig_bit(sig).unwrap_or(0);
            if old_ignored && !new_ignored {
                // Keep the hot predicate free of false negatives while the
                // action table is being reset during exec.
                self.handlers
                    .ignored_mask
                    .fetch_and(!bit, Ordering::Release);
            }
            actions[sig] = new_action;
            if !old_ignored && new_ignored {
                self.handlers.ignored_mask.fetch_or(bit, Ordering::Release);
            }
            if new_ignored {
                ignored |= sig_bit(sig).unwrap_or(0);
            }
        }
        self.handlers.ignored_mask.store(ignored, Ordering::Release);
    }

    pub fn queue_process_signal(&self, sig: usize) -> bool {
        self.queue_process_signal_with_info(sig, None)
    }

    pub fn queue_process_signal_with_info(
        &self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
    ) -> bool {
        let mut pending = self.process_pending.lock();
        let queued = pending.put(sig, info);
        if queued {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        queued
    }

    fn queue_process_signal_with_info_admission(
        &self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
        admission: QueueAdmission,
    ) -> QueuePutResult {
        let mut pending = self.process_pending.lock();
        let result = pending.put_with_admission(sig, info, admission);
        if matches!(result, QueuePutResult::Queued | QueuePutResult::Fallback) {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        result
    }

    fn dequeue_process_unblocked(&self, blocked: u64) -> Option<PendingSignal> {
        let mut pending = self.process_pending.lock();
        let result = pending.dequeue(!blocked);
        if result.is_some() {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        result
    }

    fn dequeue_process_from_mask(&self, mask: u64) -> Option<PendingSignal> {
        let mut pending = self.process_pending.lock();
        let result = pending.dequeue(mask);
        if result.is_some() {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        result
    }

    fn process_delivery_masks(&self, blocked: u64) -> [u64; 2] {
        self.process_pending.lock().delivery_masks(!blocked)
    }

    fn pending_mask(&self) -> u64 {
        self.pending_bits.load(Ordering::Acquire)
    }

    fn clear_pending_mask(&self, mask: u64) {
        if mask == 0 {
            return;
        }
        let mut pending = self.process_pending.lock();
        let old_mask = pending.mask();
        pending.clear_mask(mask);
        if pending.mask() != old_mask {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
    }

    #[inline]
    fn ignored_mask(&self) -> u64 {
        self.handlers.ignored_mask.load(Ordering::Acquire)
    }

    pub fn choose_target_tid(
        &self,
        process: &Process,
        blocked: impl Fn(u64) -> bool,
    ) -> Option<u64> {
        let tids = process.thread_ids_snapshot();
        tids.into_iter()
            .find(|tid| !blocked(*tid))
            .or_else(|| process.thread_ids_snapshot().into_iter().next())
    }
}

pub struct ThreadSignal {
    shared: Arc<SignalShared>,
    thread_pending: SpinNoIrq<PendingSignals>,
    /// Lock-free mirror of `thread_pending.mask`; see `SignalShared`.
    pending_bits: AtomicU64,
    blocked: AtomicU64,
    in_handler: AtomicBool,
    skip_once: AtomicBool,
    signal_wait: WaitQueue,
    saved_ctx: Mutex<Vec<SavedSignalContext>>,
    altstack: Mutex<SignalAltStack>,
    sigsuspend_restore: Mutex<Option<u64>>,
}

impl ThreadSignal {
    pub fn new(shared: Arc<SignalShared>) -> Arc<Self> {
        Arc::new(Self {
            shared,
            thread_pending: SpinNoIrq::new(PendingSignals::default()),
            pending_bits: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            in_handler: AtomicBool::new(false),
            skip_once: AtomicBool::new(false),
            signal_wait: WaitQueue::new(),
            saved_ctx: Mutex::new(Vec::new()),
            altstack: Mutex::new(SignalAltStack::disabled()),
            sigsuspend_restore: Mutex::new(None),
        })
    }

    pub fn shared(&self) -> Arc<SignalShared> {
        self.shared.clone()
    }

    pub fn blocked_mask(&self) -> u64 {
        self.blocked.load(Ordering::Acquire)
    }

    pub fn set_blocked_mask(&self, mask: u64) -> u64 {
        let sanitized = sanitize_mask(mask);
        self.blocked.swap(sanitized, Ordering::AcqRel)
    }

    pub fn queue_thread_signal(&self, sig: usize) -> bool {
        self.queue_thread_signal_with_info(sig, None)
    }

    pub fn queue_thread_signal_with_info(
        &self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
    ) -> bool {
        let mut pending = self.thread_pending.lock();
        let queued = pending.put(sig, info);
        if queued {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        queued
    }

    fn queue_thread_signal_with_info_admission(
        &self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
        admission: QueueAdmission,
    ) -> QueuePutResult {
        let mut pending = self.thread_pending.lock();
        let result = pending.put_with_admission(sig, info, admission);
        if matches!(result, QueuePutResult::Queued | QueuePutResult::Fallback) {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        result
    }

    fn queue_synchronous_signal_with_info(
        &self,
        sig: usize,
        info: Option<[u8; SIGINFO_FRAME_SIZE]>,
    ) -> bool {
        let mut pending = self.thread_pending.lock();
        let queued = pending.put_synchronous(sig, info);
        if queued {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        queued
    }

    fn clear_pending_mask(&self, mask: u64) {
        if mask == 0 {
            return;
        }
        let mut pending = self.thread_pending.lock();
        let old_mask = pending.mask();
        pending.clear_mask(mask);
        if pending.mask() != old_mask {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
    }

    fn dequeue_thread_with_mask(&self, mask: u64) -> Option<PendingSignal> {
        let mut pending = self.thread_pending.lock();
        let result = pending.dequeue(mask);
        if result.is_some() {
            self.pending_bits.store(pending.mask(), Ordering::Release);
        }
        result
    }

    pub fn queue_process_signal(&self, sig: usize) -> bool {
        self.shared.queue_process_signal(sig)
    }

    pub fn wait_queue(&self) -> &WaitQueue {
        &self.signal_wait
    }

    pub fn notify_waiters(&self) {
        self.signal_wait.notify_all(true);
    }

    pub fn reset_runtime_on_exec(&self) {
        self.in_handler.store(false, Ordering::Release);
        self.skip_once.store(false, Ordering::Release);
        self.saved_ctx.lock().clear();
        *self.sigsuspend_restore.lock() = None;
        *self.altstack.lock() = SignalAltStack::disabled();
    }

    pub fn set_altstack(&self, ss: SignalAltStack) {
        *self.altstack.lock() = ss.without_runtime_flags();
    }

    pub fn altstack(&self) -> SignalAltStack {
        *self.altstack.lock()
    }

    fn enter_altstack(&self) {
        let mut altstack = self.altstack.lock();
        if altstack.is_disabled() {
            return;
        }
        if altstack.is_autodisarm() {
            // Linux resets an autodisarmed stack after the frame has been
            // installed.  Nested handlers therefore use the current stack,
            // and sigaltstack() inside the handler may install a new one.
            *altstack = SignalAltStack::disabled();
        } else {
            altstack.flags |= SS_ONSTACK as usize;
        }
    }

    fn restore_altstack_from_frame(
        &self,
        frame_altstack: Option<SignalAltStack>,
        restored_sp: usize,
    ) {
        let mut altstack = self.altstack.lock();
        // Linux ignores invalid stack settings from a valid signal frame, but
        // still re-evaluates whether the restored SP lies on the old stack.
        let mut restored = frame_altstack.unwrap_or_else(|| (*altstack).without_runtime_flags());
        restored.set_active_for_sp(restored_sp);
        *altstack = restored;
    }

    pub fn begin_sigsuspend(&self, new_mask: u64) {
        let old = self.set_blocked_mask(new_mask);
        *self.sigsuspend_restore.lock() = Some(old);
    }

    fn take_sigsuspend_restore(&self) -> Option<u64> {
        self.sigsuspend_restore.lock().take()
    }

    fn maybe_restore_sigsuspend_mask(&self) {
        if let Some(old) = self.take_sigsuspend_restore() {
            self.set_blocked_mask(old);
        }
    }

    pub fn has_pending_unblocked(&self) -> bool {
        let blocked = self.blocked_mask();
        (self.pending_mask() & !blocked) != 0
    }

    pub fn has_pending_or_skip_once(&self) -> bool {
        if self.skip_once.load(Ordering::Acquire) {
            return true;
        }
        if !self.may_have_pending() {
            return false;
        }
        self.has_pending_unblocked()
    }

    pub fn is_in_handler(&self) -> bool {
        self.in_handler.load(Ordering::Acquire)
    }

    fn prepare_for_forced_signal(&self, sig: usize) -> bool {
        let Some(bit) = sig_bit(sig) else {
            return false;
        };
        let action = resolve_action(&self.shared, sig);
        let was_blocked = (self.blocked.load(Ordering::Acquire) & bit) != 0;
        let was_ignored = is_ignored_action(action);

        if was_blocked || was_ignored {
            self.shared.set_action(sig, SigAction::dfl());
        }
        if was_blocked {
            self.blocked.fetch_and(!bit, Ordering::AcqRel);
        }

        // A synchronous fault is a new delivery point, even immediately after
        // rt_sigreturn consumed the normal one-shot delivery suppression.
        self.skip_once.store(false, Ordering::Release);
        true
    }

    pub fn pending_mask(&self) -> u64 {
        self.pending_bits.load(Ordering::Acquire) | self.shared.pending_mask()
    }

    pub fn has_pending_unblocked_not_in_set(&self, set: u64) -> bool {
        let set = sanitize_mask(set);
        let blocked = self.blocked_mask();
        let pending = self.pending_mask() & !blocked & !set;
        (pending & !self.shared.ignored_mask()) != 0
    }

    pub fn has_waitset_signal(&self, waitset: u64) -> bool {
        let waitset = sanitize_mask(waitset);
        (self.pending_mask() & waitset) != 0
    }

    pub fn has_deliverable_pending_signal(&self) -> bool {
        let blocked = self.blocked_mask();
        let pending = self.pending_mask() & !blocked;
        (pending & !self.shared.ignored_mask()) != 0
    }

    #[inline]
    fn may_have_pending(&self) -> bool {
        self.pending_mask() != 0
    }

    pub fn dequeue_waitset_with_info(
        &self,
        waitset: u64,
    ) -> Option<(usize, Option<[u8; SIGINFO_FRAME_SIZE]>)> {
        let waitset = sanitize_mask(waitset);
        // Never hold the thread and process pending-queue locks together.
        // Dequeue the thread-directed record first, then inspect the shared
        // queue only after its guard has been dropped.
        let pending = self
            .dequeue_thread_with_mask(waitset)
            .or_else(|| self.shared.dequeue_process_from_mask(waitset))?;
        Some((pending.sig, Some(pending.info)))
    }

    pub fn clear_skip_once(&self) -> bool {
        self.skip_once.swap(false, Ordering::AcqRel)
    }

    pub fn restore_from_sigreturn(&self, process: &Process, tf: &mut TrapFrame) -> AxResult<usize> {
        let saved = {
            let frames = self.saved_ctx.lock();
            *frames.last().ok_or(AxError::InvalidInput)?
        };
        let (restored_tf, restored_mask, restored_altstack) =
            restore_user_signal_context(process, saved)?;
        let restored_fp = restore_user_signal_fp_state(process, saved)?;

        // Do not consume the frame until all user reads and address validation
        // have succeeded.  In particular, an invalid inner frame must not make
        // its outer handler frame unrecoverable.
        let still_in_handler = {
            let mut frames = self.saved_ctx.lock();
            frames.pop().ok_or(AxError::InvalidInput)?;
            !frames.is_empty()
        };

        *tf = restored_tf;
        restore_signal_fp_state(&restored_fp);
        self.blocked
            .store(sanitize_mask(restored_mask), Ordering::Release);
        self.restore_altstack_from_frame(restored_altstack, current_sp(tf));
        self.in_handler.store(still_in_handler, Ordering::Release);
        self.skip_once.store(true, Ordering::Release);
        axlog::debug!(
            "restore_from_sigreturn complete: ip={:#x}, sp={:#x}, nested={}",
            current_ip(tf),
            current_sp(tf),
            still_in_handler
        );
        Ok(signal_return_value(tf))
    }

    fn first_deliverable_signal(&self, masks: [u64; 2]) -> Option<usize> {
        let shared = self.shared();
        for mut pending in masks {
            while pending != 0 {
                let sig = pending.trailing_zeros() as usize + 1;
                pending &= pending - 1;
                if !is_ignored_action(resolve_action(&shared, sig)) {
                    return Some(sig);
                }
            }
        }
        None
    }

    /// Peeks the first signal that can actually affect the current thread.
    ///
    /// Linux discards ignored pending signals while searching for a deliverable
    /// one.  Restart decisions need the same ordering without consuming the
    /// queue, otherwise a lower-numbered ignored signal can hide a following
    /// handler that lacks `SA_RESTART`.
    pub fn peek_unblocked_deliverable(&self) -> Option<usize> {
        let blocked = self.blocked_mask();

        let thread_masks = self.thread_pending.lock().delivery_masks(!blocked);
        if let Some(sig) = self.first_deliverable_signal(thread_masks) {
            return Some(sig);
        }

        self.first_deliverable_signal(self.shared.process_delivery_masks(blocked))
    }

    /// Dequeues pending signals until one has a non-ignored disposition.
    ///
    /// An ignored signal is not a user-visible delivery point and must not
    /// postpone a later catchable or default-action signal to a future trap.
    fn dequeue_unblocked_deliverable_with_info(
        &self,
    ) -> Option<(usize, [u8; SIGINFO_FRAME_SIZE], SignalAction)> {
        loop {
            let blocked = self.blocked_mask();
            let pending = { self.dequeue_thread_with_mask(!blocked) }
                .or_else(|| self.shared.dequeue_process_unblocked(blocked))?;
            let action = resolve_action(&self.shared, pending.sig);
            if !is_ignored_action(action) {
                return Some((pending.sig, pending.info, action));
            }
        }
    }

    fn save_context(
        &self,
        tf: &TrapFrame,
        old_mask: u64,
        user_ucontext: Option<usize>,
        fp: SignalFpState,
    ) {
        self.saved_ctx.lock().push(SavedSignalContext {
            tf: *tf,
            old_mask,
            user_ucontext,
            fp,
        });
    }
}

#[cfg(target_arch = "riscv64")]
fn capture_signal_fp_state() -> SignalFpState {
    let mut fp = SignalFpState::default();
    fp.save();
    fp
}

#[cfg(target_arch = "loongarch64")]
fn capture_signal_fp_state() -> SignalFpState {
    let mut fp = SignalFpState::default();
    fp.save();
    fp
}

#[cfg(target_arch = "riscv64")]
fn restore_signal_fp_state(fp: &SignalFpState) {
    fp.restore();
}

#[cfg(target_arch = "loongarch64")]
fn restore_signal_fp_state(fp: &SignalFpState) {
    fp.restore();
}

fn restore_user_signal_context(
    process: &Process,
    saved: SavedSignalContext,
) -> AxResult<(TrapFrame, u64, Option<SignalAltStack>)> {
    let mut tf = saved.tf;
    let mut restored_mask = saved.old_mask;
    let Some(user_ucontext) = saved.user_ucontext else {
        return Ok((tf, restored_mask, None));
    };

    #[cfg(target_arch = "riscv64")]
    {
        let gregs_addr = user_ucontext.checked_add(176).ok_or(AxError::BadAddress)?;
        let mut gregs = [0u64; 32];
        process.read_user_bytes(gregs_addr, unsafe {
            core::slice::from_raw_parts_mut(
                gregs.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&gregs),
            )
        })?;
        tf.regs.ra = gregs[1] as usize;
        tf.regs.sp = gregs[2] as usize;
        tf.regs.gp = gregs[3] as usize;
        tf.regs.tp = gregs[4] as usize;
        tf.regs.t0 = gregs[5] as usize;
        tf.regs.t1 = gregs[6] as usize;
        tf.regs.t2 = gregs[7] as usize;
        tf.regs.s0 = gregs[8] as usize;
        tf.regs.s1 = gregs[9] as usize;
        tf.regs.a0 = gregs[10] as usize;
        tf.regs.a1 = gregs[11] as usize;
        tf.regs.a2 = gregs[12] as usize;
        tf.regs.a3 = gregs[13] as usize;
        tf.regs.a4 = gregs[14] as usize;
        tf.regs.a5 = gregs[15] as usize;
        tf.regs.a6 = gregs[16] as usize;
        tf.regs.a7 = gregs[17] as usize;
        tf.regs.s2 = gregs[18] as usize;
        tf.regs.s3 = gregs[19] as usize;
        tf.regs.s4 = gregs[20] as usize;
        tf.regs.s5 = gregs[21] as usize;
        tf.regs.s6 = gregs[22] as usize;
        tf.regs.s7 = gregs[23] as usize;
        tf.regs.s8 = gregs[24] as usize;
        tf.regs.s9 = gregs[25] as usize;
        tf.regs.s10 = gregs[26] as usize;
        tf.regs.s11 = gregs[27] as usize;
        tf.regs.t3 = gregs[28] as usize;
        tf.regs.t4 = gregs[29] as usize;
        tf.regs.t5 = gregs[30] as usize;
        tf.regs.t6 = gregs[31] as usize;
    }
    #[cfg(target_arch = "loongarch64")]
    {
        let gregs_addr = user_ucontext.checked_add(184).ok_or(AxError::BadAddress)?;
        let mut gregs = [0u64; 32];
        process.read_user_bytes(gregs_addr, unsafe {
            core::slice::from_raw_parts_mut(
                gregs.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&gregs),
            )
        })?;
        tf.regs.ra = gregs[1] as usize;
        tf.regs.tp = gregs[2] as usize;
        tf.regs.sp = gregs[3] as usize;
        tf.regs.a0 = gregs[4] as usize;
        tf.regs.a1 = gregs[5] as usize;
        tf.regs.a2 = gregs[6] as usize;
        tf.regs.a3 = gregs[7] as usize;
        tf.regs.a4 = gregs[8] as usize;
        tf.regs.a5 = gregs[9] as usize;
        tf.regs.a6 = gregs[10] as usize;
        tf.regs.a7 = gregs[11] as usize;
        tf.regs.t0 = gregs[12] as usize;
        tf.regs.t1 = gregs[13] as usize;
        tf.regs.t2 = gregs[14] as usize;
        tf.regs.t3 = gregs[15] as usize;
        tf.regs.t4 = gregs[16] as usize;
        tf.regs.t5 = gregs[17] as usize;
        tf.regs.t6 = gregs[18] as usize;
        tf.regs.t7 = gregs[19] as usize;
        tf.regs.t8 = gregs[20] as usize;
        tf.regs.u0 = gregs[21] as usize;
        tf.regs.fp = gregs[22] as usize;
        tf.regs.s0 = gregs[23] as usize;
        tf.regs.s1 = gregs[24] as usize;
        tf.regs.s2 = gregs[25] as usize;
        tf.regs.s3 = gregs[26] as usize;
        tf.regs.s4 = gregs[27] as usize;
        tf.regs.s5 = gregs[28] as usize;
        tf.regs.s6 = gregs[29] as usize;
        tf.regs.s7 = gregs[30] as usize;
        tf.regs.s8 = gregs[31] as usize;
    }

    if current_sp(&tf) >= axconfig::plat::KERNEL_ASPACE_BASE {
        return Err(AxError::BadAddress);
    }
    let pc = read_user_signal_pc(process, user_ucontext)?;
    if pc >= axconfig::plat::KERNEL_ASPACE_BASE {
        return Err(AxError::BadAddress);
    }
    set_ip(&mut tf, pc);
    restored_mask = read_user_signal_mask(process, user_ucontext)?;
    let restored_altstack = read_user_signal_altstack(process, user_ucontext)?
        .filter(|stack| stack.is_disabled() || stack.size >= MINSIGSTKSZ as usize);
    Ok((tf, restored_mask, restored_altstack))
}

fn sanitize_mask(mask: u64) -> u64 {
    let mut mask = mask;
    if let Some(bit) = sig_bit(SIGKILL as usize) {
        mask &= !bit;
    }
    if let Some(bit) = sig_bit(SIGSTOP as usize) {
        mask &= !bit;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_siginfo_preserves_signal_code_and_address() {
        let raw = signal_info_for_fault(SIGSEGV as usize, 2, 0xdead_beef);
        let info: siginfo = unsafe { core::mem::transmute(raw) };
        unsafe {
            let header = info.__bindgen_anon_1.__bindgen_anon_1;
            assert_eq!(header.si_signo, SIGSEGV as i32);
            assert_eq!(header.si_errno, 0);
            assert_eq!(header.si_code, 2);
            assert_eq!(header._sifields._sigfault._addr as usize, 0xdead_beef);
        }
    }

    #[test]
    fn child_siginfo_preserves_child_transition_fields() {
        let raw = signal_info_for_child(42, 1000, 1, 7);
        let info: siginfo = unsafe { core::mem::transmute(raw) };
        unsafe {
            let header = info.__bindgen_anon_1.__bindgen_anon_1;
            let child = header._sifields._sigchld;
            assert_eq!(header.si_signo, SIGCHLD as i32);
            assert_eq!(header.si_errno, 0);
            assert_eq!(header.si_code, 1);
            assert_eq!(child._pid, 42);
            assert_eq!(child._uid, 1000);
            assert_eq!(child._status, 7);
        }
    }

    #[test]
    fn standard_pending_signal_coalesces_and_preserves_first_siginfo() {
        let mut pending = PendingSignals::default();
        let signal = 10;

        assert!(pending.put(signal, Some([0x11; SIGINFO_FRAME_SIZE])));
        assert!(!pending.put(signal, Some([0x22; SIGINFO_FRAME_SIZE])));
        assert_eq!(pending.mask(), sig_bit(signal).unwrap());

        let delivered = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(delivered.sig, signal);
        assert_eq!(delivered.info, [0x11; SIGINFO_FRAME_SIZE]);
        assert_eq!(pending.mask(), 0);
    }

    #[test]
    fn synchronous_fault_precedes_a_lower_numbered_async_signal() {
        let mut pending = PendingSignals::default();

        assert!(pending.put(2, Some([0x11; SIGINFO_FRAME_SIZE])));
        assert!(pending.put_synchronous(SIGSEGV as usize, Some([0x22; SIGINFO_FRAME_SIZE])));

        let first = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (first.sig, first.info),
            (SIGSEGV as usize, [0x22; SIGINFO_FRAME_SIZE])
        );
        let second = pending.dequeue(u64::MAX).unwrap();
        assert_eq!((second.sig, second.info), (2, [0x11; SIGINFO_FRAME_SIZE]));
    }

    #[test]
    fn synchronous_fault_is_not_coalesced_with_an_async_signal_of_the_same_number() {
        let mut pending = PendingSignals::default();
        let signal = SIGSEGV as usize;

        assert!(pending.put(signal, Some([0x11; SIGINFO_FRAME_SIZE])));
        assert!(pending.put_synchronous(signal, Some([0x22; SIGINFO_FRAME_SIZE])));

        let first = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (first.sig, first.info),
            (signal, [0x22; SIGINFO_FRAME_SIZE])
        );
        assert_eq!(pending.mask(), sig_bit(signal).unwrap());
        let second = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (second.sig, second.info),
            (signal, [0x11; SIGINFO_FRAME_SIZE])
        );
        assert_eq!(pending.mask(), 0);
    }

    #[test]
    fn forced_signal_uses_kernel_siginfo_code() {
        let raw = forced_siginfo(SIGSEGV as usize);
        let info: siginfo = unsafe { core::mem::transmute(raw) };
        unsafe {
            let header = info.__bindgen_anon_1.__bindgen_anon_1;
            assert_eq!(header.si_signo, SIGSEGV as i32);
            assert_eq!(header.si_code, SI_KERNEL as i32);
        }
    }

    #[test]
    fn ignored_signals_are_only_retained_while_blocked() {
        let bit = sig_bit(10).unwrap();

        assert!(is_ignored_unblocked(SignalAction::Ignore, 0, 10));
        assert!(!is_ignored_unblocked(SignalAction::Ignore, bit, 10));
        assert!(!is_ignored_unblocked(
            SignalAction::Default(DefaultSignalAction::Terminate),
            0,
            10
        ));
    }

    #[test]
    fn ignored_signal_is_skipped_before_the_next_deliverable_signal() {
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared);
        let catchable = SIGRTMIN;

        // SIGCHLD has the default-ignore disposition and sorts ahead of the
        // real-time signal. It must not hide the later delivery.
        assert!(signal.queue_thread_signal(SIGCHLD as usize));
        assert!(signal.queue_thread_signal(catchable));
        assert_eq!(signal.peek_unblocked_deliverable(), Some(catchable));

        let (sig, _, action) = signal.dequeue_unblocked_deliverable_with_info().unwrap();
        assert_eq!(sig, catchable);
        assert!(matches!(
            action,
            SignalAction::Default(DefaultSignalAction::Terminate)
        ));
        assert_eq!(signal.pending_mask(), 0);
    }

    #[test]
    fn signal_permission_uses_effective_cap_kill() {
        let cap_kill = 1_u64 << CAP_KILL;

        assert!(!can_signal_credentials(0, 0, 0, 1000, 1000, 0, false));
        assert!(can_signal_credentials(
            1000, 1000, cap_kill, 2000, 2000, 0, false
        ));
    }

    #[test]
    fn signal_permission_accepts_real_or_effective_uid_matches() {
        assert!(can_signal_credentials(1000, 2000, 0, 1000, 3000, 0, false));
        assert!(can_signal_credentials(1000, 2000, 0, 3000, 1000, 0, false));
        assert!(can_signal_credentials(2000, 1000, 0, 1000, 3000, 0, false));
        assert!(can_signal_credentials(2000, 1000, 0, 3000, 1000, 0, false));
        assert!(!can_signal_credentials(1000, 2000, 0, 3000, 4000, 0, false));
    }

    #[test]
    fn signal_permission_allows_sigcont_within_one_session_only() {
        assert!(can_signal_credentials(
            1000,
            1000,
            0,
            2000,
            2000,
            SIGCONT as usize,
            true,
        ));
        assert!(!can_signal_credentials(
            1000,
            1000,
            0,
            2000,
            2000,
            SIGCONT as usize,
            false,
        ));
        assert!(!can_signal_credentials(1000, 1000, 0, 2000, 2000, 15, true));
    }

    #[test]
    fn realtime_pending_signals_are_fifo_per_number_and_lowest_number_wins() {
        let mut pending = PendingSignals::default();
        let first_rt = SIGRTMIN;
        let second_rt = SIGRTMIN + 1;

        assert!(pending.put(second_rt, Some([0x33; SIGINFO_FRAME_SIZE])));
        assert!(pending.put(first_rt, Some([0x11; SIGINFO_FRAME_SIZE])));
        assert!(pending.put(first_rt, Some([0x22; SIGINFO_FRAME_SIZE])));

        let first = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (first.sig, first.info),
            (first_rt, [0x11; SIGINFO_FRAME_SIZE])
        );
        let second = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (second.sig, second.info),
            (first_rt, [0x22; SIGINFO_FRAME_SIZE])
        );
        let third = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (third.sig, third.info),
            (second_rt, [0x33; SIGINFO_FRAME_SIZE])
        );
        assert_eq!(pending.mask(), 0);
    }

    #[test]
    fn sigpending_limit_is_shared_by_real_uid_and_released_on_dequeue_and_clear() {
        const RUID: u32 = u32::MAX - 101;
        let admission = QueueAdmission::Required {
            ruid: RUID,
            limit: 1,
        };
        let mut first_queue = PendingSignals::default();
        let mut second_queue = PendingSignals::default();

        assert_eq!(sigpending_count(RUID), 0);
        assert_eq!(
            first_queue.put_with_admission(SIGRTMIN, Some([0x11; SIGINFO_FRAME_SIZE]), admission,),
            QueuePutResult::Queued
        );
        assert_eq!(sigpending_count(RUID), 1);
        assert_eq!(
            second_queue.put_with_admission(SIGRTMIN, Some([0x22; SIGINFO_FRAME_SIZE]), admission,),
            QueuePutResult::LimitExceeded
        );
        assert_eq!(sigpending_count(RUID), 1);

        let delivered = first_queue.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (delivered.sig, delivered.info),
            (SIGRTMIN, [0x11; SIGINFO_FRAME_SIZE])
        );
        assert_eq!(sigpending_count(RUID), 0);

        assert_eq!(
            second_queue.put_with_admission(SIGRTMIN, Some([0x22; SIGINFO_FRAME_SIZE]), admission,),
            QueuePutResult::Queued
        );
        assert_eq!(sigpending_count(RUID), 1);
        second_queue.clear(SIGRTMIN);
        assert_eq!(sigpending_count(RUID), 0);
    }

    #[test]
    fn best_effort_queue_exhaustion_keeps_a_fallback_pending_signal() {
        const RUID: u32 = u32::MAX - 102;
        let mut pending = PendingSignals::default();

        assert_eq!(
            pending.put_with_admission(
                SIGRTMIN,
                Some([0x33; SIGINFO_FRAME_SIZE]),
                QueueAdmission::BestEffort {
                    ruid: RUID,
                    limit: 0,
                },
            ),
            QueuePutResult::Fallback
        );
        assert_eq!(sigpending_count(RUID), 0);
        assert_eq!(pending.mask(), sig_bit(SIGRTMIN).unwrap());

        let delivered = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (delivered.sig, delivered.info),
            (SIGRTMIN, default_siginfo(SIGRTMIN))
        );
        assert_eq!(pending.mask(), 0);
    }

    #[test]
    fn realtime_queue_record_supersedes_an_older_fallback_pending_bit() {
        const RUID: u32 = u32::MAX - 103;
        let mut pending = PendingSignals::default();

        assert_eq!(
            pending.put_with_admission(
                SIGRTMIN,
                Some([0x11; SIGINFO_FRAME_SIZE]),
                QueueAdmission::BestEffort {
                    ruid: RUID,
                    limit: 0,
                },
            ),
            QueuePutResult::Fallback
        );
        assert_eq!(
            pending.put_with_admission(
                SIGRTMIN,
                Some([0x22; SIGINFO_FRAME_SIZE]),
                QueueAdmission::Required {
                    ruid: RUID,
                    limit: 1,
                },
            ),
            QueuePutResult::Queued
        );
        assert_eq!(sigpending_count(RUID), 1);

        let delivered = pending.dequeue(u64::MAX).unwrap();
        assert_eq!(
            (delivered.sig, delivered.info),
            (SIGRTMIN, [0x22; SIGINFO_FRAME_SIZE])
        );
        assert_eq!(sigpending_count(RUID), 0);
        assert!(pending.dequeue(u64::MAX).is_none());
    }

    #[test]
    fn exec_reset_preserves_pending_signals_and_blocked_mask() {
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        signal.set_blocked_mask(0b1010);
        signal.queue_thread_signal_with_info(1, Some([1; 128]));
        shared.queue_process_signal_with_info(3, Some([3; 128]));
        shared.set_action(10, SigAction::from_parts(0x1234, 7, 0x55));
        shared.set_action(12, SigAction::from_parts(SIG_IGN, 9, 0xaa));
        signal.set_altstack(SignalAltStack {
            sp: 0x1000,
            size: 0x2000,
            flags: 0,
        });
        signal.in_handler.store(true, Ordering::Release);
        signal.skip_once.store(true, Ordering::Release);
        *signal.sigsuspend_restore.lock() = Some(0x44);

        shared.reset_dispositions_on_exec();
        signal.reset_runtime_on_exec();

        assert_eq!(signal.blocked_mask(), 0b1010);
        assert_ne!(signal.thread_pending.lock().mask(), 0);
        assert_ne!(shared.process_pending.lock().mask(), 0);
        assert_eq!(signal.pending_mask(), 0b0101);
        assert_eq!(shared.action(10).handler, SIG_DFL);
        assert_eq!(shared.action(12).handler, SIG_IGN);
        assert!(!signal.in_handler.load(Ordering::Acquire));
        assert!(!signal.skip_once.load(Ordering::Acquire));
        assert!(signal.sigsuspend_restore.lock().is_none());
        let altstack = signal.altstack();
        assert_eq!(
            (altstack.sp, altstack.size, altstack.flags),
            (0, 0, SS_DISABLE as usize)
        );
        assert_eq!(
            signal.dequeue_waitset_with_info(1),
            Some((1, Some([1; 128])))
        );
        assert_eq!(
            signal.dequeue_waitset_with_info(1 << 2),
            Some((3, Some([3; 128])))
        );
    }

    #[test]
    fn pending_bit_mirror_preserves_precise_pending_checks() {
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());
        let thread_bit = sig_bit(1).unwrap();
        let process_bit = sig_bit(2).unwrap();

        assert!(!signal.has_pending_or_skip_once());

        signal.set_blocked_mask(thread_bit);
        assert!(signal.queue_thread_signal(1));
        assert!(!signal.has_pending_or_skip_once());

        signal.set_blocked_mask(0);
        assert!(signal.has_pending_or_skip_once());
        assert_eq!(
            signal.dequeue_waitset_with_info(thread_bit),
            Some((1, Some(default_siginfo(1))))
        );
        assert_eq!(signal.pending_bits.load(Ordering::Acquire), 0);
        assert!(!signal.has_pending_or_skip_once());

        assert!(shared.queue_process_signal(2));
        assert!(signal.has_pending_or_skip_once());
        assert_eq!(
            signal.dequeue_waitset_with_info(process_bit),
            Some((2, Some(default_siginfo(2))))
        );
        assert_eq!(shared.pending_bits.load(Ordering::Acquire), 0);
        assert!(!signal.has_pending_or_skip_once());
    }

    #[test]
    fn ignored_disposition_mask_tracks_shared_sighand_changes() {
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        // SIGCHLD is default-ignored, while signal 10 is catchable by default.
        assert!((shared.ignored_mask() & sig_bit(SIGCHLD as usize).unwrap()) != 0);
        assert!((shared.ignored_mask() & sig_bit(10).unwrap()) == 0);

        shared.queue_process_signal(SIGCHLD as usize);
        assert!(!signal.has_deliverable_pending_signal());
        shared.set_action(SIGCHLD as usize, SigAction::from_parts(0x1234, 0, 0));
        assert!(signal.has_deliverable_pending_signal());
        assert_eq!(
            signal.dequeue_waitset_with_info(sig_bit(SIGCHLD as usize).unwrap()),
            Some((SIGCHLD as usize, Some(default_siginfo(SIGCHLD as usize))))
        );

        shared.set_action(10, SigAction::from_parts(SIG_IGN, 0, 0));
        assert!((shared.ignored_mask() & sig_bit(10).unwrap()) != 0);
        shared.queue_process_signal(10);
        assert!(!signal.has_deliverable_pending_signal());
    }

    #[test]
    fn clear_sighand_resets_only_the_private_child_actions() {
        let parent = SignalShared::new();
        parent.set_action(10, SigAction::from_parts(0x1234, 7, 0x55));
        parent.set_action(12, SigAction::from_parts(SIG_IGN, 9, 0xaa));

        let child = SignalShared::clone_actions_only(&parent);
        child.reset_dispositions_on_exec();

        assert_eq!(parent.action(10).handler, 0x1234);
        let parent_ignored = parent.action(12);
        assert_eq!(
            (
                parent_ignored.handler,
                parent_ignored.flags,
                parent_ignored.mask
            ),
            (SIG_IGN, 9, 0xaa)
        );
        let reset = child.action(10);
        assert_eq!((reset.handler, reset.flags, reset.mask), (SIG_DFL, 0, 0));
        let ignored = child.action(12);
        assert_eq!(
            (ignored.handler, ignored.flags, ignored.mask),
            (SIG_IGN, 0, 0)
        );
    }

    #[test]
    fn forced_signal_unblocks_and_resets_a_blocked_handler() {
        const SIGSEGV: usize = 11;
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());
        let sigsegv_bit = sig_bit(SIGSEGV).unwrap();

        shared.set_action(SIGSEGV, SigAction::from_parts(0x1234, 0, 0));
        signal.set_blocked_mask(sigsegv_bit);
        signal.skip_once.store(true, Ordering::Release);

        assert!(signal.prepare_for_forced_signal(SIGSEGV));
        assert_eq!(signal.blocked_mask() & sigsegv_bit, 0);
        assert!(!signal.skip_once.load(Ordering::Acquire));
        assert_eq!(shared.action(SIGSEGV).handler, SIG_DFL);
        assert!(matches!(
            resolve_action(&shared, SIGSEGV),
            SignalAction::Default(DefaultSignalAction::CoreDump)
        ));

        signal.queue_thread_signal(SIGSEGV);
        assert!(signal.has_pending_unblocked());
    }

    #[test]
    fn forced_signal_preserves_an_unblocked_handler() {
        const SIGSEGV: usize = 11;
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        shared.set_action(SIGSEGV, SigAction::from_parts(0x1234, 0, 0));

        assert!(signal.prepare_for_forced_signal(SIGSEGV));
        assert_eq!(shared.action(SIGSEGV).handler, 0x1234);
    }

    #[test]
    fn forced_signal_resets_an_ignored_disposition() {
        const SIGSEGV: usize = 11;
        let shared = SignalShared::new();
        let signal = ThreadSignal::new(shared.clone());

        shared.set_action(SIGSEGV, SigAction::from_parts(SIG_IGN, 0, 0));

        assert!(signal.prepare_for_forced_signal(SIGSEGV));
        assert_eq!(shared.action(SIGSEGV).handler, SIG_DFL);
        assert!(matches!(
            resolve_action(&shared, SIGSEGV),
            SignalAction::Default(DefaultSignalAction::CoreDump)
        ));
    }

    #[test]
    fn alternate_signal_stack_tracks_active_delivery() {
        let signal = ThreadSignal::new(SignalShared::new());
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: SS_ONSTACK as usize,
        };
        signal.set_altstack(altstack);

        assert!(!signal.altstack().is_active());
        signal.enter_altstack();
        assert!(signal.altstack().is_active());
        signal.restore_altstack_from_frame(Some(altstack), 0x80_000);
        assert!(!signal.altstack().is_active());
    }

    #[test]
    fn altstack_accepts_linux_compatible_flag_combinations() {
        let stack =
            SignalAltStack::from_user_parts(0x10_000, 0x4_000, SS_ONSTACK | SS_AUTODISARM).unwrap();
        assert_eq!(stack.flags, SS_AUTODISARM as usize);

        let disabled =
            SignalAltStack::from_user_parts(0x10_000, 0x4_000, SS_DISABLE | SS_AUTODISARM).unwrap();
        assert_eq!(disabled.sp, 0);
        assert_eq!(disabled.size, 0);
        assert_eq!(disabled.flags, (SS_DISABLE | SS_AUTODISARM) as usize);

        assert!(SignalAltStack::from_user_parts(0, 0, SS_DISABLE | SS_ONSTACK).is_none());
        assert!(SignalAltStack::from_user_parts(0, 0, 0x4000_0000).is_none());
    }

    #[test]
    fn autodisarm_disables_during_handler_and_restores_from_signal_frame() {
        let signal = ThreadSignal::new(SignalShared::new());
        let stack = SignalAltStack::from_user_parts(0x10_000, 0x4_000, SS_AUTODISARM).unwrap();
        signal.set_altstack(stack);

        signal.enter_altstack();
        let during_handler = signal.altstack();
        assert!(during_handler.is_disabled());
        assert_eq!(during_handler.flags, SS_DISABLE as usize);

        signal.restore_altstack_from_frame(Some(stack), 0x80_000);
        let restored = signal.altstack();
        assert_eq!((restored.sp, restored.size), (stack.sp, stack.size));
        assert_eq!(restored.flags, SS_AUTODISARM as usize);
    }

    #[test]
    fn altstack_restore_keeps_nested_handler_active_when_sp_is_in_range() {
        let signal = ThreadSignal::new(SignalShared::new());
        let stack = SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: 0,
        };
        signal.set_altstack(stack);
        signal.enter_altstack();

        signal.restore_altstack_from_frame(Some(stack), stack.sp + 0x100);
        assert!(signal.altstack().is_active());
    }

    #[test]
    fn signal_frame_uses_enabled_alternate_stack() {
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: 0,
        };

        let (frame_base, used_altstack) =
            signal_frame_base(0x80_000, SA_ONSTACK as usize, altstack, 0x480).unwrap();

        assert_eq!(frame_base, 0x13_b80);
        assert!(used_altstack);
    }

    #[test]
    fn signal_frame_stays_on_an_active_alternate_stack() {
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x4_000,
            flags: SS_ONSTACK as usize,
        };

        let (frame_base, used_altstack) =
            signal_frame_base(0x13_c00, SA_ONSTACK as usize, altstack, 0x480).unwrap();

        assert_eq!(frame_base, 0x13_780);
        assert!(!used_altstack);
    }

    #[test]
    fn signal_frame_rejects_an_undersized_alternate_stack() {
        let altstack = SignalAltStack {
            sp: 0x10_000,
            size: 0x100,
            flags: 0,
        };

        assert!(signal_frame_base(0x80_000, SA_ONSTACK as usize, altstack, 0x480).is_err());
    }
}

fn default_action(sig: usize) -> DefaultSignalAction {
    match sig as u32 {
        SIGCHLD | SIGURG | SIGWINCH => DefaultSignalAction::Ignore,
        SIGCONT => DefaultSignalAction::Continue,
        SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU => DefaultSignalAction::Stop,
        // POSIX 定义：以下信号的默认动作是终止并产生 core dump
        // SIGQUIT=3, SIGILL=4, SIGTRAP=5, SIGABRT=6, SIGBUS=7,
        // SIGFPE=8, SIGSEGV=11, SIGXCPU=24, SIGXFSZ=25, SIGSYS=31
        3 | 4 | 5 | 6 | 7 | 8 | 11 | 24 | 25 | 31 => DefaultSignalAction::CoreDump,
        _ => DefaultSignalAction::Terminate,
    }
}

fn sigaction_is_ignored(sig: usize, action: SigAction) -> bool {
    action.handler == SIG_IGN
        || (action.handler == SIG_DFL && matches!(default_action(sig), DefaultSignalAction::Ignore))
}

fn ignored_mask_for_actions(actions: &[SigAction; (_NSIG as usize) + 1]) -> u64 {
    let mut mask = 0;
    for sig in 1..=(_NSIG as usize) {
        if sigaction_is_ignored(sig, actions[sig]) {
            mask |= sig_bit(sig).unwrap_or(0);
        }
    }
    mask
}

fn default_ignored_mask() -> u64 {
    let actions = [SigAction::dfl(); (_NSIG as usize) + 1];
    ignored_mask_for_actions(&actions)
}

pub fn resolve_action(shared: &SignalShared, sig: usize) -> SignalAction {
    let act = shared.action(sig);
    match act.handler {
        SIG_IGN => SignalAction::Ignore,
        SIG_DFL => SignalAction::Default(default_action(sig)),
        _ => SignalAction::Handler(act),
    }
}

fn is_ignored_action(action: SignalAction) -> bool {
    matches!(
        action,
        SignalAction::Ignore | SignalAction::Default(DefaultSignalAction::Ignore)
    )
}

#[cfg(target_arch = "riscv64")]
fn set_ip(tf: &mut TrapFrame, ip: usize) {
    tf.sepc = ip;
}
#[cfg(target_arch = "loongarch64")]
fn set_ip(tf: &mut TrapFrame, ip: usize) {
    tf.era = ip;
}

#[cfg(target_arch = "riscv64")]
fn set_ra(tf: &mut TrapFrame, ra: usize) {
    tf.regs.ra = ra;
}
#[cfg(target_arch = "loongarch64")]
fn set_ra(tf: &mut TrapFrame, ra: usize) {
    tf.regs.ra = ra;
}

#[cfg(target_arch = "riscv64")]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a0 = arg;
}
#[cfg(target_arch = "riscv64")]
fn set_arg1(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a1 = arg;
}
#[cfg(target_arch = "riscv64")]
fn set_arg2(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a2 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a0 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg1(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a1 = arg;
}
#[cfg(target_arch = "loongarch64")]
fn set_arg2(tf: &mut TrapFrame, arg: usize) {
    tf.regs.a2 = arg;
}

#[cfg(target_arch = "riscv64")]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.sepc
}
#[cfg(target_arch = "loongarch64")]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.era
}
#[cfg(target_arch = "riscv64")]
fn current_sp(tf: &TrapFrame) -> usize {
    tf.regs.sp
}
#[cfg(target_arch = "loongarch64")]
fn current_sp(tf: &TrapFrame) -> usize {
    tf.regs.sp
}
#[cfg(target_arch = "riscv64")]
fn set_sp(tf: &mut TrapFrame, sp: usize) {
    tf.regs.sp = sp;
}
#[cfg(target_arch = "loongarch64")]
fn set_sp(tf: &mut TrapFrame, sp: usize) {
    tf.regs.sp = sp;
}

#[cfg(target_arch = "riscv64")]
fn signal_return_value(tf: &TrapFrame) -> usize {
    tf.regs.a0
}
#[cfg(target_arch = "loongarch64")]
fn signal_return_value(tf: &TrapFrame) -> usize {
    tf.regs.a0
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn signal_return_value(tf: &TrapFrame) -> usize {
    tf.rax as usize
}

#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_ip(tf: &mut TrapFrame, ip: usize) {
    tf.rip = ip as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_ra(_tf: &mut TrapFrame, _ra: usize) {}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_arg0(tf: &mut TrapFrame, arg: usize) {
    tf.rdi = arg as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_arg1(tf: &mut TrapFrame, arg: usize) {
    tf.rsi = arg as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_arg2(tf: &mut TrapFrame, arg: usize) {
    tf.rdx = arg as u64;
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn current_ip(tf: &TrapFrame) -> usize {
    tf.rip as usize
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn current_sp(tf: &TrapFrame) -> usize {
    tf.rsp as usize
}
#[cfg(not(any(target_arch = "riscv64", target_arch = "loongarch64")))]
fn set_sp(tf: &mut TrapFrame, sp: usize) {
    tf.rsp = sp as u64;
}

const UCONTEXT_FRAME_SIZE: usize = 1024;
const UCONTEXT_STACK_OFFSET: usize = 16;
const UCONTEXT_STACK_FLAGS_OFFSET: usize = UCONTEXT_STACK_OFFSET + core::mem::size_of::<usize>();
const UCONTEXT_STACK_SIZE_OFFSET: usize = UCONTEXT_STACK_OFFSET + 2 * core::mem::size_of::<usize>();
const UCONTEXT_SIGMASK_OFFSET: usize = 40;
const UCONTEXT_PC_OFFSET: usize = 176;

// The fixed ucontext header reserves 128 bytes for sigset_t at offset 40,
// ending at offset 168. Both supported 64-bit ABIs insert eight bytes of
// alignment padding before uc_mcontext begins at offset 176.
#[cfg(target_arch = "riscv64")]
const RISCV_D_FPU_OFFSET: usize = UCONTEXT_PC_OFFSET + 32 * core::mem::size_of::<u64>();
#[cfg(target_arch = "riscv64")]
const RISCV_D_FCSR_OFFSET: usize = RISCV_D_FPU_OFFSET + 32 * core::mem::size_of::<u64>();
#[cfg(target_arch = "riscv64")]
const RISCV_EXT_RESERVED_OFFSET: usize = RISCV_D_FPU_OFFSET + 129 * core::mem::size_of::<u32>();
#[cfg(target_arch = "riscv64")]
const RISCV_EXT_HEADER_OFFSET: usize = RISCV_EXT_RESERVED_OFFSET + core::mem::size_of::<u32>();

#[cfg(target_arch = "loongarch64")]
const LOONGARCH_SC_FLAGS_OFFSET: usize = UCONTEXT_PC_OFFSET + 8 + 32 * core::mem::size_of::<u64>();
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_SC_EXTCONTEXT_OFFSET: usize = LOONGARCH_SC_FLAGS_OFFSET + 8;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_SCTX_INFO_SIZE: usize = 16;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_CONTEXT_SIZE: usize = 32 * core::mem::size_of::<u128>() + 8 + 8;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_CONTEXT_OFFSET: usize =
    LOONGARCH_SC_EXTCONTEXT_OFFSET + LOONGARCH_SCTX_INFO_SIZE;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_HEADER_SIZE_OFFSET: usize =
    LOONGARCH_SC_EXTCONTEXT_OFFSET + core::mem::size_of::<u32>();
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_FCC_OFFSET: usize =
    LOONGARCH_LSX_CONTEXT_OFFSET + 32 * core::mem::size_of::<u128>();
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_FCSR_OFFSET: usize = LOONGARCH_LSX_FCC_OFFSET + 8;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_FRAME_SIZE: usize = LOONGARCH_SCTX_INFO_SIZE + LOONGARCH_LSX_CONTEXT_SIZE;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_END_OFFSET: usize = LOONGARCH_SC_EXTCONTEXT_OFFSET + LOONGARCH_LSX_FRAME_SIZE;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_SC_USED_FP: u32 = 1;
#[cfg(target_arch = "loongarch64")]
const LOONGARCH_LSX_CTX_MAGIC: u32 = 0x5358_0001;

#[cfg(target_arch = "riscv64")]
const _: () =
    assert!(RISCV_EXT_HEADER_OFFSET + 2 * core::mem::size_of::<u32>() <= UCONTEXT_FRAME_SIZE);
#[cfg(target_arch = "loongarch64")]
const _: () = assert!(LOONGARCH_LSX_END_OFFSET + LOONGARCH_SCTX_INFO_SIZE <= UCONTEXT_FRAME_SIZE);

fn signal_frame_base(
    current_sp: usize,
    action_flags: usize,
    altstack: SignalAltStack,
    frame_size: usize,
) -> AxResult<(usize, bool)> {
    let use_altstack = (action_flags & SA_ONSTACK as usize) != 0
        && !altstack.is_disabled()
        && !altstack.is_active()
        && !altstack.contains(current_sp);
    let stack_top = if use_altstack {
        altstack
            .sp
            .checked_add(altstack.size)
            .ok_or(AxError::BadAddress)?
    } else {
        current_sp
    };
    let frame_base = stack_top
        .checked_sub(frame_size)
        .ok_or(AxError::BadAddress)?
        & !15;
    if use_altstack && frame_base < altstack.sp {
        return Err(AxError::BadAddress);
    }
    Ok((frame_base, use_altstack))
}

fn write_user_signal_frame(
    thread: &Thread,
    tf: &TrapFrame,
    old_mask: u64,
    siginfo: Option<[u8; 128]>,
    action_flags: usize,
    fp: &SignalFpState,
) -> AxResult<(usize, usize, bool)> {
    let frame_size = SIGINFO_FRAME_SIZE + UCONTEXT_FRAME_SIZE;
    let altstack = thread.signal_altstack();
    let (frame_base, used_altstack) =
        signal_frame_base(current_sp(tf), action_flags, altstack, frame_size)?;
    let siginfo_addr = frame_base;
    let ucontext_addr = frame_base + SIGINFO_FRAME_SIZE;

    let mut siginfo_bytes = [0u8; SIGINFO_FRAME_SIZE];
    if let Some(info) = siginfo {
        siginfo_bytes.copy_from_slice(&info);
    }
    let process = thread.process();
    process.write_user_bytes(siginfo_addr, &siginfo_bytes)?;

    let zeroes = [0u8; UCONTEXT_FRAME_SIZE];
    process.write_user_bytes(ucontext_addr, &zeroes)?;

    write_user_signal_altstack(process.as_ref(), ucontext_addr, altstack)?;
    process.write_user_usize(ucontext_addr + UCONTEXT_SIGMASK_OFFSET, old_mask as usize)?;
    #[cfg(target_arch = "riscv64")]
    {
        // `__gregs[0]` is PC in the RISC-V ABI. `TrapFrame::regs` starts
        // with x0, so writing it here and then overwriting slot zero with PC
        // produces the ABI's PC, x1..x31 sequence.
        let gregs_addr = ucontext_addr + UCONTEXT_PC_OFFSET;
        let gregs_bytes =
            unsafe { core::slice::from_raw_parts(&tf.regs as *const _ as *const u8, 32 * 8) };
        process.write_user_bytes(gregs_addr, gregs_bytes)?;
    }

    process.write_user_usize(ucontext_addr + UCONTEXT_PC_OFFSET, current_ip(tf))?;
    #[cfg(target_arch = "loongarch64")]
    {
        // On loongarch64, sc_regs starts at offset 184 in ucontext_t.
        let gregs_addr = ucontext_addr + 184;
        let gregs_bytes =
            unsafe { core::slice::from_raw_parts(&tf.regs as *const _ as *const u8, 32 * 8) };
        process.write_user_bytes(gregs_addr, gregs_bytes)?;
    }

    write_user_signal_fp_state(process.as_ref(), ucontext_addr, fp)?;

    Ok((siginfo_addr, ucontext_addr, used_altstack))
}

fn write_user_signal_altstack(
    process: &Process,
    user_ucontext: usize,
    altstack: SignalAltStack,
) -> AxResult<()> {
    let altstack = altstack.without_runtime_flags();
    process.write_user_usize(user_ucontext + UCONTEXT_STACK_OFFSET, altstack.sp)?;
    process.write_user_bytes(
        user_ucontext + UCONTEXT_STACK_FLAGS_OFFSET,
        &(altstack.flags as i32).to_ne_bytes(),
    )?;
    process.write_user_usize(user_ucontext + UCONTEXT_STACK_SIZE_OFFSET, altstack.size)
}

fn read_user_signal_pc(process: &Process, user_ucontext: usize) -> AxResult<usize> {
    let addr = user_ucontext
        .checked_add(UCONTEXT_PC_OFFSET)
        .ok_or(AxError::BadAddress)?;
    process.read_user_usize(addr)
}

fn read_user_signal_mask(process: &Process, user_ucontext: usize) -> AxResult<u64> {
    let addr = user_ucontext
        .checked_add(UCONTEXT_SIGMASK_OFFSET)
        .ok_or(AxError::BadAddress)?;
    process.read_user_usize(addr).map(|mask| mask as u64)
}

fn read_user_signal_altstack(
    process: &Process,
    user_ucontext: usize,
) -> AxResult<Option<SignalAltStack>> {
    let stack_addr = user_ucontext
        .checked_add(UCONTEXT_STACK_OFFSET)
        .ok_or(AxError::BadAddress)?;
    let flags_addr = user_ucontext
        .checked_add(UCONTEXT_STACK_FLAGS_OFFSET)
        .ok_or(AxError::BadAddress)?;
    let size_addr = user_ucontext
        .checked_add(UCONTEXT_STACK_SIZE_OFFSET)
        .ok_or(AxError::BadAddress)?;
    let sp = process.read_user_usize(stack_addr)?;
    let mut flags = [0u8; core::mem::size_of::<i32>()];
    process.read_user_bytes(flags_addr, &mut flags)?;
    let size = process.read_user_usize(size_addr)?;
    Ok(SignalAltStack::from_user_parts(
        sp,
        size,
        i32::from_ne_bytes(flags) as u32,
    ))
}

fn signal_context_addr(user_ucontext: usize, offset: usize) -> AxResult<usize> {
    user_ucontext.checked_add(offset).ok_or(AxError::BadAddress)
}

fn read_user_signal_u32(process: &Process, addr: usize) -> AxResult<u32> {
    let mut bytes = [0u8; core::mem::size_of::<u32>()];
    process.read_user_bytes(addr, &mut bytes)?;
    Ok(u32::from_ne_bytes(bytes))
}

#[cfg(target_arch = "riscv64")]
fn write_user_signal_fp_state(
    process: &Process,
    user_ucontext: usize,
    fp: &SignalFpState,
) -> AxResult<()> {
    let fp_bytes = unsafe {
        core::slice::from_raw_parts(fp.fp.as_ptr().cast::<u8>(), core::mem::size_of_val(&fp.fp))
    };
    process.write_user_bytes(
        signal_context_addr(user_ucontext, RISCV_D_FPU_OFFSET)?,
        fp_bytes,
    )?;
    process.write_user_bytes(
        signal_context_addr(user_ucontext, RISCV_D_FCSR_OFFSET)?,
        &(fp.fcsr as u32).to_ne_bytes(),
    )?;
    // The D-extension state and the extension descriptor share a union.  A
    // zero reserved word plus END header advertises that PulseOS emitted no
    // variable-length RISC-V extension records.
    process.write_user_bytes(
        signal_context_addr(user_ucontext, RISCV_EXT_RESERVED_OFFSET)?,
        &[0u8; 12],
    )
}

#[cfg(target_arch = "loongarch64")]
fn write_user_signal_fp_state(
    process: &Process,
    user_ucontext: usize,
    fp: &SignalFpState,
) -> AxResult<()> {
    let fp_bytes = unsafe {
        core::slice::from_raw_parts(fp.fp.as_ptr().cast::<u8>(), core::mem::size_of_val(&fp.fp))
    };
    let extcontext = signal_context_addr(user_ucontext, LOONGARCH_SC_EXTCONTEXT_OFFSET)?;
    let lsx_context = signal_context_addr(user_ucontext, LOONGARCH_LSX_CONTEXT_OFFSET)?;

    process.write_user_bytes(
        signal_context_addr(user_ucontext, LOONGARCH_SC_FLAGS_OFFSET)?,
        &LOONGARCH_SC_USED_FP.to_ne_bytes(),
    )?;
    process.write_user_bytes(extcontext, &LOONGARCH_LSX_CTX_MAGIC.to_ne_bytes())?;
    process.write_user_bytes(
        signal_context_addr(user_ucontext, LOONGARCH_LSX_HEADER_SIZE_OFFSET)?,
        &(LOONGARCH_LSX_FRAME_SIZE as u32).to_ne_bytes(),
    )?;
    process.write_user_bytes(lsx_context, fp_bytes)?;
    process.write_user_bytes(
        signal_context_addr(user_ucontext, LOONGARCH_LSX_FCC_OFFSET)?,
        &fp.fcc,
    )?;
    process.write_user_bytes(
        signal_context_addr(user_ucontext, LOONGARCH_LSX_FCSR_OFFSET)?,
        &fp.fcsr.to_ne_bytes(),
    )?;
    // `ucontext` was zeroed before this point. Write the terminator explicitly
    // so the frame remains valid if its construction order changes later.
    process.write_user_bytes(
        signal_context_addr(user_ucontext, LOONGARCH_LSX_END_OFFSET)?,
        &[0u8; LOONGARCH_SCTX_INFO_SIZE],
    )
}

#[cfg(target_arch = "riscv64")]
fn restore_user_signal_fp_state(
    process: &Process,
    saved: SavedSignalContext,
) -> AxResult<axcpu::FpState> {
    let Some(user_ucontext) = saved.user_ucontext else {
        return Ok(saved.fp);
    };

    let reserved = read_user_signal_u32(
        process,
        signal_context_addr(user_ucontext, RISCV_EXT_RESERVED_OFFSET)?,
    )?;
    let ext_magic = read_user_signal_u32(
        process,
        signal_context_addr(user_ucontext, RISCV_EXT_HEADER_OFFSET)?,
    )?;
    let ext_size = read_user_signal_u32(
        process,
        signal_context_addr(
            user_ucontext,
            RISCV_EXT_HEADER_OFFSET + core::mem::size_of::<u32>(),
        )?,
    )?;
    if reserved != 0 || ext_magic != 0 || ext_size != 0 {
        return Err(AxError::InvalidInput);
    }

    let mut fp = saved.fp;
    process.read_user_bytes(
        signal_context_addr(user_ucontext, RISCV_D_FPU_OFFSET)?,
        unsafe {
            core::slice::from_raw_parts_mut(
                fp.fp.as_mut_ptr().cast::<u8>(),
                core::mem::size_of_val(&fp.fp),
            )
        },
    )?;
    fp.fcsr = read_user_signal_u32(
        process,
        signal_context_addr(user_ucontext, RISCV_D_FCSR_OFFSET)?,
    )? as usize;
    Ok(fp)
}

#[cfg(target_arch = "loongarch64")]
fn restore_user_signal_fp_state(
    process: &Process,
    saved: SavedSignalContext,
) -> AxResult<axcpu::FpuState> {
    let Some(user_ucontext) = saved.user_ucontext else {
        return Ok(saved.fp);
    };

    let flags = read_user_signal_u32(
        process,
        signal_context_addr(user_ucontext, LOONGARCH_SC_FLAGS_OFFSET)?,
    )?;
    if flags & LOONGARCH_SC_USED_FP == 0 {
        return Ok(axcpu::FpuState::default());
    }

    let extcontext = signal_context_addr(user_ucontext, LOONGARCH_SC_EXTCONTEXT_OFFSET)?;
    let magic = read_user_signal_u32(process, extcontext)?;
    let size = read_user_signal_u32(
        process,
        signal_context_addr(user_ucontext, LOONGARCH_LSX_HEADER_SIZE_OFFSET)?,
    )?;
    if magic != LOONGARCH_LSX_CTX_MAGIC || size < LOONGARCH_LSX_FRAME_SIZE as u32 {
        return Err(AxError::InvalidInput);
    }

    let mut fp = saved.fp;
    let lsx_context = signal_context_addr(user_ucontext, LOONGARCH_LSX_CONTEXT_OFFSET)?;
    process.read_user_bytes(lsx_context, unsafe {
        core::slice::from_raw_parts_mut(
            fp.fp.as_mut_ptr().cast::<u8>(),
            core::mem::size_of_val(&fp.fp),
        )
    })?;
    process.read_user_bytes(
        signal_context_addr(user_ucontext, LOONGARCH_LSX_FCC_OFFSET)?,
        &mut fp.fcc,
    )?;
    fp.fcsr = read_user_signal_u32(
        process,
        signal_context_addr(user_ucontext, LOONGARCH_LSX_FCSR_OFFSET)?,
    )?;
    Ok(fp)
}

pub fn can_signal(caller: &Process, target: &Process, sig: usize) -> bool {
    can_signal_credentials(
        caller.ruid(),
        caller.euid(),
        caller.capabilities().1,
        target.ruid(),
        target.suid(),
        sig,
        caller.sid() == target.sid(),
    )
}

/// Linux's signal permission rule in PulseOS's single user namespace.
fn can_signal_credentials(
    caller_ruid: u32,
    caller_euid: u32,
    caller_cap_effective: u64,
    target_ruid: u32,
    target_suid: u32,
    sig: usize,
    same_session: bool,
) -> bool {
    (caller_cap_effective & (1_u64 << CAP_KILL)) != 0
        || caller_euid == target_ruid
        || caller_euid == target_suid
        || caller_ruid == target_ruid
        || caller_ruid == target_suid
        || (sig == SIGCONT as usize && same_session)
}

pub fn queue_signal_to_process(process: &Process, sig: usize) -> bool {
    queue_signal_to_process_with_info(process, sig, None)
}

pub fn queue_signal_to_thread(thread: &Thread, sig: usize) -> bool {
    queue_signal_to_thread_with_info(thread, sig, None)
}

/// Queues a signal caused synchronously by the current thread's execution.
///
/// A blocked or ignored synchronous fault cannot remain pending while the
/// faulting instruction is retried. Match Linux force-signal behavior by
/// restoring the default disposition and unblocking it before queuing.
pub fn force_signal_to_thread(thread: &Thread, sig: usize) -> bool {
    force_signal_to_thread_with_info(thread, sig, forced_siginfo(sig))
}

/// Queues a synchronous signal while preserving its `siginfo_t` payload.
///
/// A blocked or ignored synchronous fault cannot remain pending while the
/// faulting instruction is retried. Match Linux force-signal behavior by
/// restoring the default disposition and unblocking it before queuing.
pub fn force_signal_to_thread_with_info(thread: &Thread, sig: usize, info: [u8; 128]) -> bool {
    if !thread.signal().prepare_for_forced_signal(sig) {
        return false;
    }
    let queued = thread
        .signal()
        .queue_synchronous_signal_with_info(sig, Some(info));
    thread.notify_signal_pending(sig);
    queued
}

pub fn queue_signal_to_process_with_info(
    process: &Process,
    sig: usize,
    info: Option<[u8; 128]>,
) -> bool {
    queue_signal_to_process_with_admission(process, sig, info, QueueAdmission::best_effort(process))
        .unwrap_or(false)
}

/// Queues a signal for an ABI that must report `EAGAIN` when a real-time
/// sigqueue record cannot be allocated under `RLIMIT_SIGPENDING`.
pub fn queue_signal_to_process_with_info_strict(
    process: &Process,
    sig: usize,
    info: Option<[u8; 128]>,
) -> Result<bool, SignalQueueError> {
    queue_signal_to_process_with_admission(process, sig, info, QueueAdmission::required(process))
}

fn queue_signal_to_process_with_admission(
    process: &Process,
    sig: usize,
    info: Option<[u8; 128]>,
    admission: QueueAdmission,
) -> Result<bool, SignalQueueError> {
    if sig_bit(sig).is_none() {
        return Ok(false);
    }
    prepare_job_control_enqueue(process, sig);
    let shared = process.signal_shared();
    let action = resolve_action(&shared, sig);
    let mut threads = None;
    if is_ignored_action(action) {
        let snapshot = list_threads_for_signal(process);
        if should_discard_ignored_process_signal(sig, &snapshot) {
            return Ok(false);
        }
        threads = Some(snapshot);
    }
    let result = shared.queue_process_signal_with_info_admission(sig, info, admission);
    if matches!(result, QueuePutResult::Queued | QueuePutResult::Fallback) {
        let threads = threads.unwrap_or_else(|| list_threads_for_signal(process));
        notify_process_signal_pending(&threads, sig);
    }
    match result {
        QueuePutResult::LimitExceeded => Err(SignalQueueError::Limit),
        result => Ok(result.is_pending()),
    }
}

fn notify_process_signal_pending(threads: &[Arc<Thread>], sig: usize) {
    let Some(bit) = sig_bit(sig) else {
        return;
    };

    // Process-directed signals have one shared pending record. Interrupt one
    // thread that can consume it instead of waking every member of a large
    // thread group. The retry over all currently eligible threads covers a
    // concurrent mask change between selection and notification.
    for thread in threads {
        if (thread.signal_blocked_mask() & bit) == 0 && thread.notify_signal_pending(sig) {
            return;
        }
    }

    // If every member masks the signal, it may be consumed by signalfd or a
    // synchronous signal wait. Those users register on the per-thread wait
    // queue, so only inspect the queues in this all-blocked fallback instead
    // of taking a wait-queue lock on every ordinary process signal.
    for thread in threads {
        if !thread.signal_wait_queue().is_empty() {
            thread.notify_signal_pending(sig);
        }
    }
}

fn should_discard_ignored_process_signal(sig: usize, threads: &[Arc<Thread>]) -> bool {
    let Some(bit) = sig_bit(sig) else {
        return false;
    };
    threads
        .iter()
        .any(|thread| (thread.signal_blocked_mask() & bit) == 0)
}

pub fn queue_signal_to_thread_with_info(
    thread: &Thread,
    sig: usize,
    info: Option<[u8; 128]>,
) -> bool {
    let process = thread.process();
    queue_signal_to_thread_with_admission(
        thread,
        process.as_ref(),
        sig,
        info,
        QueueAdmission::best_effort(process.as_ref()),
    )
    .unwrap_or(false)
}

/// Queues a thread-directed signal for an ABI that must report `EAGAIN` on a
/// real-time queue allocation failure.
pub fn queue_signal_to_thread_with_info_strict(
    thread: &Thread,
    sig: usize,
    info: Option<[u8; 128]>,
) -> Result<bool, SignalQueueError> {
    let process = thread.process();
    queue_signal_to_thread_with_admission(
        thread,
        process.as_ref(),
        sig,
        info,
        QueueAdmission::required(process.as_ref()),
    )
}

fn queue_signal_to_thread_with_admission(
    thread: &Thread,
    process: &Process,
    sig: usize,
    info: Option<[u8; 128]>,
    admission: QueueAdmission,
) -> Result<bool, SignalQueueError> {
    if sig_bit(sig).is_none() {
        return Ok(false);
    }
    prepare_job_control_enqueue(process, sig);
    let action = resolve_action(&thread.signal().shared(), sig);
    if is_ignored_unblocked(action, thread.signal_blocked_mask(), sig) {
        return Ok(false);
    }
    let result = thread
        .signal()
        .queue_thread_signal_with_info_admission(sig, info, admission);
    if matches!(result, QueuePutResult::Queued | QueuePutResult::Fallback) {
        thread.notify_signal_pending(sig);
    }
    match result {
        QueuePutResult::LimitExceeded => Err(SignalQueueError::Limit),
        result => Ok(result.is_pending()),
    }
}

fn is_ignored_unblocked(action: SignalAction, blocked: u64, sig: usize) -> bool {
    let Some(bit) = sig_bit(sig) else {
        return false;
    };
    is_ignored_action(action) && (blocked & bit) == 0
}

fn is_job_control_stop_signal(sig: usize) -> bool {
    matches!(sig as u32, SIGSTOP | SIGTSTP | SIGTTIN | SIGTTOU)
}

/// Arrival of SIGCONT discards pending stop signals and resumes a stopped
/// group immediately.  Arrival of a stop signal discards a pending SIGCONT.
/// This is an enqueue-time rule, independent of masks and dispositions.
fn prepare_job_control_enqueue(process: &Process, sig: usize) {
    if sig == SIGCONT as usize {
        let stop_signals = [
            SIGSTOP as usize,
            SIGTSTP as usize,
            SIGTTIN as usize,
            SIGTTOU as usize,
        ];
        clear_signals_from_all_queues(process, signal_set_mask(&stop_signals));
        process.continue_group();
    } else if is_job_control_stop_signal(sig) {
        clear_signals_from_all_queues(process, sig_bit(SIGCONT as usize).unwrap_or(0));
    }
}

fn signal_set_mask(signals: &[usize]) -> u64 {
    signals
        .iter()
        .fold(0, |mask, sig| mask | sig_bit(*sig).unwrap_or(0))
}

fn clear_signals_from_all_queues(process: &Process, mask: u64) {
    process.signal_shared().clear_pending_mask(mask);
    for thread in list_threads_for_signal(process) {
        thread.signal().clear_pending_mask(mask);
    }
}

/// POSIX requires a pending signal to be discarded when its disposition
/// changes to ignore.  The default disposition of SIGCHLD, SIGURG, and
/// SIGWINCH is ignore as well, so this helper deliberately resolves the full
/// action rather than checking only for `SIG_IGN`.
pub fn discard_pending_if_ignored(process: &Process, sig: usize) {
    if is_ignored_action(resolve_action(&process.signal_shared(), sig)) {
        clear_signals_from_all_queues(process, sig_bit(sig).unwrap_or(0));
    }
}

pub fn check_signals_and_deliver(thread: &Thread, tf: &mut TrapFrame) -> Option<SignalDelivery> {
    let sig_state = thread.signal();
    if sig_state.clear_skip_once() {
        return None;
    }

    let (sig, siginfo, action) = sig_state.dequeue_unblocked_deliverable_with_info()?;

    match action {
        SignalAction::Ignore | SignalAction::Default(DefaultSignalAction::Ignore) => {
            unreachable!("ignored signals are skipped before delivery")
        }
        SignalAction::Default(DefaultSignalAction::Terminate)
        | SignalAction::Default(DefaultSignalAction::CoreDump)
        | SignalAction::Default(DefaultSignalAction::Stop)
        | SignalAction::Default(DefaultSignalAction::Continue) => {
            sig_state.maybe_restore_sigsuspend_mask();
            Some(SignalDelivery { sig, action })
        }
        SignalAction::Handler(act) => {
            let old_mask = sig_state.blocked_mask();
            // sigsuspend installs a temporary mask only until the signal
            // handler returns.  Save the caller's original mask in this frame,
            // while keeping the temporary mask as the base for handler-time
            // blocking below.
            let restore_mask = sig_state.take_sigsuspend_restore().unwrap_or(old_mask);
            let mut new_mask = old_mask | act.mask;
            if (act.flags & (SA_NODEFER as usize)) == 0
                && let Some(bit) = sig_bit(sig)
            {
                new_mask |= bit;
            }
            new_mask = sanitize_mask(new_mask);
            let fp = capture_signal_fp_state();
            match write_user_signal_frame(thread, tf, restore_mask, Some(siginfo), act.flags, &fp) {
                Ok((siginfo_addr, ucontext_addr, used_altstack)) => {
                    sig_state.save_context(tf, restore_mask, Some(ucontext_addr), fp);
                    if used_altstack {
                        sig_state.enter_altstack();
                    }
                    set_arg1(tf, siginfo_addr);
                    set_arg2(tf, ucontext_addr);
                    set_sp(tf, siginfo_addr);
                }
                Err(e) => {
                    axlog::warn!("failed to build signal frame for sig {}: {:?}", sig, e);
                    sig_state.set_blocked_mask(restore_mask);
                    return Some(SignalDelivery {
                        sig: SIGSEGV as usize,
                        action: SignalAction::Default(DefaultSignalAction::CoreDump),
                    });
                }
            }
            sig_state.set_blocked_mask(new_mask);
            sig_state.in_handler.store(true, Ordering::Release);

            if (act.flags & (SA_RESETHAND as usize)) != 0 {
                sig_state.shared().set_action(sig, SigAction::dfl());
            }

            set_arg0(tf, sig);
            set_ra(tf, thread.process().signal_trampoline());
            set_ip(tf, act.handler);
            Some(SignalDelivery { sig, action })
        }
    }
}

pub fn pending_mask(thread: &Thread) -> u64 {
    thread.signal().pending_mask()
}

pub fn blocked_mask(thread: &Thread) -> u64 {
    thread.signal().blocked_mask()
}

fn list_threads_for_signal(process: &Process) -> Vec<Arc<Thread>> {
    process.active_threads_snapshot()
}
