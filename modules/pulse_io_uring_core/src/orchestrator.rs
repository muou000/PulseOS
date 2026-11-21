//! Pure `no_std` io_uring request lifecycle, 1:1 completion ownership (`try_claim_completion`),
//! timeout/cancel coordination, same-batch link/hardlink chains, and `IOSQE_IO_DRAIN` barriers.

use alloc::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    vec::Vec,
};

use axerrno::LinuxError;
use pulse_user_abi::io_uring::{
    IORING_ASYNC_CANCEL_ALL, IORING_ASYNC_CANCEL_ANY, IORING_ASYNC_CANCEL_FD,
    IORING_ASYNC_CANCEL_FD_FIXED, IORING_TIMEOUT_ABS, IORING_TIMEOUT_BOOTTIME,
    IORING_TIMEOUT_CLOCK_MASK, IORING_TIMEOUT_ETIME_SUCCESS, IORING_TIMEOUT_LINK,
    IORING_TIMEOUT_REALTIME, IOSQE_IO_DRAIN, IOSQE_IO_HARDLINK, IOSQE_IO_LINK, IoUringCqe,
    IoUringSqe,
};

pub type RequestId = u64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestPhase {
    Created,
    Queued,
    Running,
    Completing,
    Completed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutClock {
    Monotonic,
    Boottime,
    Realtime,
}

impl TimeoutClock {
    #[inline]
    pub const fn from_op_flags(op_flags: u32) -> Self {
        match op_flags & IORING_TIMEOUT_CLOCK_MASK {
            IORING_TIMEOUT_BOOTTIME => Self::Boottime,
            IORING_TIMEOUT_REALTIME => Self::Realtime,
            _ => Self::Monotonic,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RequestKind {
    Normal {
        opcode: u8,
        fd: Option<i32>,
        expected_min_bytes: Option<usize>,
    },
    Timeout {
        clock: TimeoutClock,
        abs: bool,
        etime_success: bool,
        target_completions: Option<u64>,
        generation: u64,
    },
    LinkTimeout {
        predecessor: RequestId,
        clock: TimeoutClock,
        abs: bool,
        generation: u64,
    },
}

#[derive(Clone, Debug)]
struct RequestEntry {
    id: RequestId,
    submit_seq: u64,
    user_data: u64,
    owner_pid: u64,
    in_chain: bool,
    phase: RequestPhase,
    claimed: bool,
    kind: RequestKind,
    has_link: bool,
    has_hardlink: bool,
    barrier_seq: Option<u64>,
    next_in_chain: Option<RequestId>,
    attached_link_timeout: Option<RequestId>,
}

impl RequestEntry {
    fn breaks_soft_link(&self, res: i32) -> bool {
        if let RequestKind::Timeout {
            etime_success: true,
            ..
        } = self.kind
        {
            if res == -LinuxError::ETIME.code() {
                return false;
            }
        }
        if res < 0 {
            return true;
        }
        if let RequestKind::Normal {
            expected_min_bytes: Some(expected),
            ..
        } = self.kind
        {
            if (res as usize) < expected {
                return true;
            }
        }
        false
    }
}

#[derive(Clone, Debug)]
pub struct QueuedChainHead {
    pub id: RequestId,
    pub submit_seq: u64,
    pub barrier_seq: Option<u64>,
}

#[derive(Default, Debug)]
pub struct OrchestratorEffects {
    /// CQEs ready to emit into `CompletionRingState`.
    pub cqes: Vec<IoUringCqe>,
    /// Requests that transitioned to `Running` and must now be executed.
    pub start_requests: Vec<RequestId>,
    /// Running/queued requests whose underlying timer/future/worker handle must be cancelled.
    pub cancel_requests: Vec<RequestId>,
    /// `(request_id, new_generation)` for updated active timers whose deadline changed.
    pub reschedule_timeouts: Vec<(RequestId, u64)>,
}

/// Prepared per-SQE metadata passed into batch assembly after prep validation.
#[derive(Clone, Copy, Debug)]
pub struct PreparedRequest {
    pub user_data: u64,
    pub sqe_flags: u8,
    pub owner_pid: u64,
    pub kind: RequestKind,
}

impl PreparedRequest {
    #[inline]
    pub const fn with_owner_pid(mut self, owner_pid: u64) -> Self {
        self.owner_pid = owner_pid;
        self
    }

    pub fn from_normal(sqe: &IoUringSqe, fd: Option<i32>, expected_min_bytes: Option<usize>) -> Self {
        Self {
            user_data: sqe.user_data,
            sqe_flags: sqe.flags,
            owner_pid: 0,
            kind: RequestKind::Normal {
                opcode: sqe.opcode,
                fd,
                expected_min_bytes,
            },
        }
    }

    pub fn from_timeout(sqe: &IoUringSqe, current_cqe_seq: u64) -> Self {
        let target_completions = if sqe.off > 0 {
            Some(current_cqe_seq.saturating_add(sqe.off))
        } else {
            None
        };
        Self {
            user_data: sqe.user_data,
            sqe_flags: sqe.flags,
            owner_pid: 0,
            kind: RequestKind::Timeout {
                clock: TimeoutClock::from_op_flags(sqe.op_flags),
                abs: (sqe.op_flags & IORING_TIMEOUT_ABS) != 0,
                etime_success: (sqe.op_flags & IORING_TIMEOUT_ETIME_SUCCESS) != 0,
                target_completions,
                generation: 1,
            },
        }
    }

    pub fn from_link_timeout(sqe: &IoUringSqe) -> Self {
        Self {
            user_data: sqe.user_data,
            sqe_flags: sqe.flags,
            owner_pid: 0,
            kind: RequestKind::LinkTimeout {
                predecessor: 0,
                clock: TimeoutClock::from_op_flags(sqe.op_flags),
                abs: (sqe.op_flags & IORING_TIMEOUT_ABS) != 0,
                generation: 1,
            },
        }
    }
}

/// Pure `no_std` orchestrator owning request lifecycles, link/hardlink chains,
/// drain barriers, completion-count timeouts, and unique CQE completion tokens.
pub struct RequestOrchestrator {
    next_id: RequestId,
    next_submit_seq: u64,
    completion_seq: u64,
    drain_next: bool,
    requests: BTreeMap<RequestId, RequestEntry>,
    /// Ordered set of incomplete `(submit_seq, RequestId)` for O(1) lowest-seq watermark check.
    incomplete_seqs: BTreeSet<(u64, RequestId)>,
    /// FIFO queue of deferred chain heads waiting behind an active drain barrier.
    drain_queue: VecDeque<QueuedChainHead>,
}

impl Default for RequestOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl RequestOrchestrator {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_submit_seq: 1,
            completion_seq: 0,
            drain_next: false,
            requests: BTreeMap::new(),
            incomplete_seqs: BTreeSet::new(),
            drain_queue: VecDeque::new(),
        }
    }

    #[inline]
    pub fn completion_seq(&self) -> u64 {
        self.completion_seq
    }

    #[inline]
    pub fn inflight_len(&self) -> usize {
        self.requests.len()
    }

    #[inline]
    pub fn min_incomplete_seq(&self) -> u64 {
        self.incomplete_seqs
            .first()
            .map(|(seq, _)| *seq)
            .unwrap_or(self.next_submit_seq)
    }

    #[inline]
    pub fn drain_queue_len(&self) -> usize {
        self.drain_queue.len()
    }

    #[inline]
    pub fn request_phase(&self, id: RequestId) -> Option<RequestPhase> {
        self.requests.get(&id).map(|r| r.phase)
    }

    pub fn active_request_ids(&self) -> Vec<RequestId> {
        self.requests.keys().copied().collect()
    }

    fn alloc_id_and_seq(&mut self) -> (RequestId, u64) {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        let seq = self.next_submit_seq;
        self.next_submit_seq = self.next_submit_seq.wrapping_add(1).max(1);
        (id, seq)
    }

    /// Commits one completed chain of already-prepared requests (assembled within one batch).
    ///
    /// Returns `(head_id, OrchestratorEffects)` starting either immediately or queueing behind an
    /// active `IOSQE_IO_DRAIN` barrier.
    pub fn commit_chain(
        &mut self,
        chain: &mut [PreparedRequest],
    ) -> Result<(RequestId, OrchestratorEffects), LinuxError> {
        let (ids, eff) = self.commit_chain_with_ids(chain)?;
        Ok((ids[0], eff))
    }

    /// Commits one completed chain and returns `(allocated_ids_in_chain_order, OrchestratorEffects)`.
    pub fn commit_chain_with_ids(
        &mut self,
        chain: &mut [PreparedRequest],
    ) -> Result<(Vec<RequestId>, OrchestratorEffects), LinuxError> {
        if chain.is_empty() {
            return Err(LinuxError::EINVAL);
        }

        // Validate LINK_TIMEOUT placement inside the assembled chain first:
        // - Cannot be the head (no predecessor).
        // - Cannot immediately follow another LINK_TIMEOUT.
        let mut prev_was_lt = false;
        for (idx, item) in chain.iter().enumerate() {
            let is_lt = matches!(item.kind, RequestKind::LinkTimeout { .. });
            if is_lt {
                if idx == 0 || prev_was_lt {
                    return Err(LinuxError::EINVAL);
                }
                prev_was_lt = true;
            } else {
                prev_was_lt = false;
            }
        }

        // Clear trailing link bits on the final node of a finished chain.
        if let Some(last) = chain.last_mut() {
            last.sqe_flags &= !(IOSQE_IO_LINK | IOSQE_IO_HARDLINK);
        }

        let mut effects = OrchestratorEffects::default();
        let mut ids: Vec<RequestId> = Vec::with_capacity(chain.len());

        let in_chain = chain.len() > 1;
        let mut head_seq = 0u64;
        for (idx, item) in chain.iter().enumerate() {
            let (id, seq) = self.alloc_id_and_seq();
            if idx == 0 {
                head_seq = seq;
            }
            let has_drain = (item.sqe_flags & IOSQE_IO_DRAIN) != 0;
            let has_hardlink = (item.sqe_flags & IOSQE_IO_HARDLINK) != 0;
            let has_link = (item.sqe_flags & IOSQE_IO_LINK) != 0 && !has_hardlink;

            let barrier_seq = if idx == 0 && (has_drain || self.drain_next) {
                Some(head_seq)
            } else {
                None
            };
            if idx == 0 && !has_drain {
                self.drain_next = false;
            }

            self.incomplete_seqs.insert((seq, id));
            self.requests.insert(
                id,
                RequestEntry {
                    id,
                    submit_seq: seq,
                    user_data: item.user_data,
                    owner_pid: item.owner_pid,
                    in_chain,
                    phase: RequestPhase::Queued,
                    claimed: false,
                    kind: item.kind,
                    has_link,
                    has_hardlink,
                    barrier_seq,
                    next_in_chain: None,
                    attached_link_timeout: None,
                },
            );
            ids.push(id);
        }

        // If any node in this chain had IOSQE_IO_DRAIN, the next request submitted after
        // this chain must also wait until this chain drains.
        if chain
            .iter()
            .any(|item| (item.sqe_flags & IOSQE_IO_DRAIN) != 0)
        {
            self.drain_next = true;
        }

        // Wire chain edges and attach `LINK_TIMEOUT` nodes to their direct predecessor.
        let mut i = 0;
        let mut head_id = ids[0];
        let mut prev_exec_id: Option<RequestId> = None;
        while i < ids.len() {
            let cur_id = ids[i];
            let is_lt = self
                .requests
                .get(&cur_id)
                .is_some_and(|r| matches!(r.kind, RequestKind::LinkTimeout { .. }));
            if is_lt {
                let pred_id = prev_exec_id.expect("validated non-head LinkTimeout");
                let (lt_link, lt_hardlink) = {
                    let lt = self.requests.get_mut(&cur_id).unwrap();
                    if let RequestKind::LinkTimeout {
                        ref mut predecessor,
                        ..
                    } = lt.kind
                    {
                        *predecessor = pred_id;
                    }
                    let l = lt.has_link;
                    let h = lt.has_hardlink;
                    lt.has_link = false;
                    lt.has_hardlink = false;
                    (l, h)
                };
                if let Some(pred) = self.requests.get_mut(&pred_id) {
                    pred.attached_link_timeout = Some(cur_id);
                    pred.has_link = lt_link;
                    pred.has_hardlink = lt_hardlink;
                }
            } else {
                if let Some(prev) = prev_exec_id {
                    if let Some(prev_req) = self.requests.get_mut(&prev) {
                        prev_req.next_in_chain = Some(cur_id);
                    }
                } else {
                    head_id = cur_id;
                }
                prev_exec_id = Some(cur_id);
            }
            i += 1;
        }

        // Check whether this chain head must wait in `drain_queue`.
        let head_entry = self.requests.get(&head_id).unwrap();
        let must_defer = !self.drain_queue.is_empty()
            || head_entry
                .barrier_seq
                .is_some_and(|b| self.min_incomplete_seq() < b);

        if must_defer {
            self.drain_queue.push_back(QueuedChainHead {
                id: head_id,
                submit_seq: head_entry.submit_seq,
                barrier_seq: head_entry.barrier_seq,
            });
        } else {
            self.activate_request_with_timeout(head_id, &mut effects);
        }

        Ok((ids, effects))
    }

    fn activate_request_with_timeout(&mut self, id: RequestId, effects: &mut OrchestratorEffects) {
        let attached_lt = {
            let Some(req) = self.requests.get_mut(&id) else {
                return;
            };
            if req.claimed || req.phase != RequestPhase::Queued {
                return;
            }
            req.phase = RequestPhase::Running;
            effects.start_requests.push(id);
            req.attached_link_timeout
        };
        if let Some(lt_id) = attached_lt {
            if let Some(lt) = self.requests.get_mut(&lt_id) {
                if !lt.claimed && lt.phase == RequestPhase::Queued {
                    lt.phase = RequestPhase::Running;
                    effects.start_requests.push(lt_id);
                }
            }
        }
    }

    fn release_drain_waiters(&mut self, effects: &mut OrchestratorEffects) {
        loop {
            let Some(front) = self.drain_queue.front() else {
                break;
            };
            let id = front.id;
            let barrier = front.barrier_seq.unwrap_or(0);
            let min_seq = self.min_incomplete_seq();
            // Once all earlier requests (`submit_seq < barrier`) completed, this entry may start.
            // Note: if `front` was already completed/cancelled, `requests.get(&id)` is None -> pop.
            if self.requests.get(&id).is_none() {
                self.drain_queue.pop_front();
                continue;
            }
            if min_seq < barrier {
                break;
            }
            let head = self.drain_queue.pop_front().unwrap();
            self.activate_request_with_timeout(head.id, effects);
            // If `head` has `IOSQE_IO_DRAIN` and just entered `Running`, and the *next* entry in
            // `drain_queue` has `barrier_seq >= next.submit_seq` (from `drain_next`), the loop check
            // `min_incomplete_seq() < next.barrier` will automatically pause until `head` completes!
        }
    }

    /// Marks a request as irreversibly committing its completion result (`Completing`).
    ///
    /// Once in `Completing`, concurrent `ASYNC_CANCEL`, `TIMEOUT_REMOVE`, `LINK_TIMEOUT`, or
    /// ring teardown cannot claim or steal this request (`-EALREADY` / `-EBUSY` on cancel).
    pub fn try_begin_completing(&mut self, id: RequestId) -> bool {
        let Some(req) = self.requests.get_mut(&id) else {
            return false;
        };
        if req.claimed {
            return false;
        }
        match req.phase {
            RequestPhase::Queued | RequestPhase::Running => {
                req.phase = RequestPhase::Completing;
                req.claimed = true;
                true
            }
            RequestPhase::Created | RequestPhase::Completing | RequestPhase::Completed => false,
        }
    }

    /// Finishes a request previously transitioned via [`Self::try_begin_completing`].
    pub fn finish_completing(
        &mut self,
        id: RequestId,
        res: i32,
        cqe_flags: u32,
    ) -> OrchestratorEffects {
        let mut effects = OrchestratorEffects::default();
        self.finalize_claimed_request(id, res, cqe_flags, &mut effects);
        self.release_drain_waiters(&mut effects);
        self.check_timeout_count_triggers(&mut effects);
        effects
    }

    /// Atomically claims completion ownership of `id` (`1:1` CQE guarantee) and processes
    /// link cascades, attached `LINK_TIMEOUT` cancellation, drain barriers, and timeout count
    /// triggers.
    ///
    /// Returns `None` if `id` was already claimed/completed/cancelled.
    pub fn try_claim_completion(
        &mut self,
        id: RequestId,
        res: i32,
        cqe_flags: u32,
    ) -> Option<OrchestratorEffects> {
        let req = self.requests.get_mut(&id)?;
        if req.claimed
            || matches!(
                req.phase,
                RequestPhase::Completing | RequestPhase::Completed | RequestPhase::Created
            )
        {
            return None;
        }
        req.claimed = true;
        req.phase = RequestPhase::Completing;

        let mut effects = OrchestratorEffects::default();
        self.finalize_claimed_request(id, res, cqe_flags, &mut effects);
        self.release_drain_waiters(&mut effects);
        self.check_timeout_count_triggers(&mut effects);
        Some(effects)
    }

    fn finalize_claimed_request(
        &mut self,
        id: RequestId,
        res: i32,
        cqe_flags: u32,
        effects: &mut OrchestratorEffects,
    ) {
        let Some(mut entry) = self.requests.remove(&id) else {
            return;
        };
        entry.phase = RequestPhase::Completed;
        self.incomplete_seqs.remove(&(entry.submit_seq, entry.id));

        // Cancel attached LINK_TIMEOUT if predecessor completed before timer expiry.
        if let Some(lt_id) = entry.attached_link_timeout.take() {
            if let Some(lt_entry) = self.requests.get_mut(&lt_id) {
                if !lt_entry.claimed {
                    lt_entry.claimed = true;
                    lt_entry.phase = RequestPhase::Completed;
                    let lt_removed = self.requests.remove(&lt_id).unwrap();
                    self.incomplete_seqs
                        .remove(&(lt_removed.submit_seq, lt_removed.id));
                    effects.cancel_requests.push(lt_id);
                    self.push_cqe_and_advance(
                        IoUringCqe {
                            user_data: lt_removed.user_data,
                            res: -LinuxError::ECANCELED.code(),
                            flags: 0,
                        },
                        false,
                        effects,
                    );
                }
            }
        }

        let is_timeout_kind = matches!(
            entry.kind,
            RequestKind::Timeout { .. } | RequestKind::LinkTimeout { .. }
        );
        self.push_cqe_and_advance(
            IoUringCqe {
                user_data: entry.user_data,
                res,
                flags: cqe_flags,
            },
            !is_timeout_kind,
            effects,
        );

        // Process successor chain edge (either normal failure/success or link cascade).
        if let Some(next_id) = entry.next_in_chain {
            let broken = entry.breaks_soft_link(res);
            if entry.has_hardlink || !broken {
                self.activate_request_with_timeout(next_id, effects);
            } else {
                self.cascade_cancel_chain(next_id, effects);
            }
        }
    }

    fn cascade_cancel_chain(&mut self, start_id: RequestId, effects: &mut OrchestratorEffects) {
        let mut cursor = Some(start_id);
        while let Some(id) = cursor {
            let Some(req) = self.requests.get_mut(&id) else {
                break;
            };
            if req.claimed {
                break;
            }
            req.claimed = true;
            req.phase = RequestPhase::Completed;
            let removed = self.requests.remove(&id).unwrap();
            self.incomplete_seqs
                .remove(&(removed.submit_seq, removed.id));
            effects.cancel_requests.push(id);

            if let Some(lt_id) = removed.attached_link_timeout {
                if let Some(lt_req) = self.requests.get_mut(&lt_id) {
                    if !lt_req.claimed {
                        lt_req.claimed = true;
                        let lt_removed = self.requests.remove(&lt_id).unwrap();
                        self.incomplete_seqs
                            .remove(&(lt_removed.submit_seq, lt_removed.id));
                        effects.cancel_requests.push(lt_id);
                        self.push_cqe_and_advance(
                            IoUringCqe {
                                user_data: lt_removed.user_data,
                                res: -LinuxError::ECANCELED.code(),
                                flags: 0,
                            },
                            false,
                            effects,
                        );
                    }
                }
            }

            self.push_cqe_and_advance(
                IoUringCqe {
                    user_data: removed.user_data,
                    res: -LinuxError::ECANCELED.code(),
                    flags: 0,
                },
                true,
                effects,
            );

            cursor = removed.next_in_chain;
            if removed.has_hardlink {
                // Hardlink continues executing the successor even after `-ECANCELED` on predecessor.
                if let Some(next_id) = cursor {
                    self.activate_request_with_timeout(next_id, effects);
                }
                break;
            }
        }
    }

    fn push_cqe_and_advance(
        &mut self,
        cqe: IoUringCqe,
        counts_for_timeout: bool,
        effects: &mut OrchestratorEffects,
    ) {
        effects.cqes.push(cqe);
        if counts_for_timeout {
            self.completion_seq = self.completion_seq.wrapping_add(1);
        }
    }

    fn check_timeout_count_triggers(&mut self, effects: &mut OrchestratorEffects) {
        loop {
            let triggered_id = self.requests.iter().find_map(|(&id, req)| {
                if req.claimed {
                    return None;
                }
                if let RequestKind::Timeout {
                    target_completions: Some(target),
                    ..
                } = req.kind
                {
                    if self.completion_seq >= target {
                        return Some(id);
                    }
                }
                None
            });
            let Some(id) = triggered_id else {
                break;
            };
            if let Some(req) = self.requests.get_mut(&id) {
                req.claimed = true;
                req.phase = RequestPhase::Completing;
                effects.cancel_requests.push(id);
                self.finalize_claimed_request(id, 0, 0, effects);
                self.release_drain_waiters(effects);
            }
        }
    }

    /// Invoked when an `IORING_OP_TIMEOUT` timer fires with matching `generation`.
    pub fn expire_timeout(&mut self, id: RequestId, generation: u64) -> OrchestratorEffects {
        let Some(req) = self.requests.get(&id) else {
            return OrchestratorEffects::default();
        };
        if req.claimed {
            return OrchestratorEffects::default();
        }
        let RequestKind::Timeout {
            generation: cur_gen,
            ..
        } = req.kind
        else {
            return OrchestratorEffects::default();
        };
        if cur_gen != generation {
            return OrchestratorEffects::default();
        }
        // `IORING_TIMEOUT_ETIME_SUCCESS` still emits `-ETIME` as the CQE result;
        // it only prevents `-ETIME` from breaking an `IOSQE_IO_LINK` chain.
        self.try_claim_completion(id, -LinuxError::ETIME.code(), 0)
            .unwrap_or_default()
    }

    /// Invoked when an `IORING_OP_LINK_TIMEOUT` timer fires with matching `generation`.
    ///
    /// Resolves the bidirectional race between the linked predecessor and the link timeout:
    /// - If predecessor is still claimable, claims predecessor with `-ECANCELED` and completes
    ///   `LINK_TIMEOUT` with `-ETIME`.
    /// - Otherwise predecessor already won completion, so completes `LINK_TIMEOUT` with `-ECANCELED`.
    pub fn expire_link_timeout(
        &mut self,
        lt_id: RequestId,
        generation: u64,
    ) -> OrchestratorEffects {
        let Some(lt_req) = self.requests.get(&lt_id) else {
            return OrchestratorEffects::default();
        };
        if lt_req.claimed {
            return OrchestratorEffects::default();
        }
        let RequestKind::LinkTimeout {
            predecessor,
            generation: cur_gen,
            ..
        } = lt_req.kind
        else {
            return OrchestratorEffects::default();
        };
        if cur_gen != generation {
            return OrchestratorEffects::default();
        }

        let mut effects = OrchestratorEffects::default();
        // Detach from predecessor first so `finalize_claimed_request(predecessor)` does not
        // auto-cancel `lt_id` before we emit `lt_id`'s own `-ETIME`.
        let pred_claimed_by_us = if let Some(pred) = self.requests.get_mut(&predecessor) {
            if !pred.claimed
                && matches!(pred.phase, RequestPhase::Queued | RequestPhase::Running)
            {
                pred.attached_link_timeout = None;
                true
            } else {
                false
            }
        } else {
            false
        };

        if pred_claimed_by_us {
            effects.cancel_requests.push(predecessor);
            if let Some(sub_eff) =
                self.try_claim_completion(predecessor, -LinuxError::ECANCELED.code(), 0)
            {
                effects.cqes.extend(sub_eff.cqes);
                effects.start_requests.extend(sub_eff.start_requests);
                effects.cancel_requests.extend(sub_eff.cancel_requests);
                effects
                    .reschedule_timeouts
                    .extend(sub_eff.reschedule_timeouts);
            }
            if let Some(lt_eff) = self.try_claim_completion(lt_id, -LinuxError::ETIME.code(), 0) {
                effects.cqes.extend(lt_eff.cqes);
                effects.start_requests.extend(lt_eff.start_requests);
                effects.cancel_requests.extend(lt_eff.cancel_requests);
                effects
                    .reschedule_timeouts
                    .extend(lt_eff.reschedule_timeouts);
            }
        } else if let Some(lt_eff) =
            self.try_claim_completion(lt_id, -LinuxError::ECANCELED.code(), 0)
        {
            effects.cqes.extend(lt_eff.cqes);
            effects.start_requests.extend(lt_eff.start_requests);
            effects.cancel_requests.extend(lt_eff.cancel_requests);
            effects
                .reschedule_timeouts
                .extend(lt_eff.reschedule_timeouts);
        }

        effects
    }

    /// Executes `IORING_OP_TIMEOUT_REMOVE` (`flags == 0`) against active regular `TIMEOUT`s.
    pub fn timeout_remove(
        &mut self,
        target_user_data: u64,
    ) -> (i32, OrchestratorEffects) {
        let mut saw_completing = false;
        let target_id = self.requests.iter().find_map(|(&id, req)| {
            if req.user_data != target_user_data {
                return None;
            }
            if !matches!(req.kind, RequestKind::Timeout { .. }) {
                return None;
            }
            if req.claimed || req.phase == RequestPhase::Completing {
                saw_completing = true;
                return None;
            }
            Some(id)
        });

        let Some(id) = target_id else {
            return (
                if saw_completing {
                    -LinuxError::EBUSY.code()
                } else {
                    -LinuxError::ENOENT.code()
                },
                OrchestratorEffects::default(),
            );
        };

        let mut effects = self
            .try_claim_completion(id, -LinuxError::ECANCELED.code(), 0)
            .unwrap_or_default();
        effects.cancel_requests.push(id);
        (0, effects)
    }

    /// Executes `IORING_OP_TIMEOUT_REMOVE` with `IORING_TIMEOUT_UPDATE`.
    pub fn timeout_update(
        &mut self,
        target_user_data: u64,
        op_flags: u32,
    ) -> (i32, Option<(RequestId, u64, TimeoutClock, bool)>) {
        let match_link = (op_flags & IORING_TIMEOUT_LINK) != 0;
        let abs = (op_flags & IORING_TIMEOUT_ABS) != 0;
        let explicit_clock = (op_flags & IORING_TIMEOUT_CLOCK_MASK) != 0;

        let mut saw_completing = false;
        let mut matched: Option<(RequestId, u64, TimeoutClock)> = None;

        for (&id, req) in self.requests.iter() {
            if req.user_data != target_user_data {
                continue;
            }
            let clock = match req.kind {
                RequestKind::Timeout { clock, .. } if !match_link => clock,
                RequestKind::LinkTimeout { clock, .. } if match_link => clock,
                _ => continue,
            };
            if req.claimed || req.phase == RequestPhase::Completing {
                saw_completing = true;
                continue;
            }
            let next_clock = if explicit_clock {
                TimeoutClock::from_op_flags(op_flags)
            } else {
                clock
            };
            let new_gen = match req.kind {
                RequestKind::Timeout { generation, .. }
                | RequestKind::LinkTimeout { generation, .. } => generation.wrapping_add(1),
                RequestKind::Normal { .. } => 1,
            };
            matched = Some((id, new_gen, next_clock));
            break;
        }

        let Some((id, new_gen, next_clock)) = matched else {
            let code = if saw_completing {
                -LinuxError::EBUSY.code()
            } else {
                -LinuxError::ENOENT.code()
            };
            return (code, None);
        };

        if let Some(req) = self.requests.get_mut(&id) {
            match req.kind {
                RequestKind::Timeout {
                    ref mut clock,
                    abs: ref mut ref_abs,
                    ref mut generation,
                    ..
                } => {
                    *clock = next_clock;
                    *ref_abs = abs;
                    *generation = new_gen;
                }
                RequestKind::LinkTimeout {
                    ref mut clock,
                    abs: ref mut ref_abs,
                    ref mut generation,
                    ..
                } => {
                    *clock = next_clock;
                    *ref_abs = abs;
                    *generation = new_gen;
                }
                RequestKind::Normal { .. } => {}
            }
        }

        (0, Some((id, new_gen, next_clock, abs)))
    }

    /// Executes `IORING_OP_ASYNC_CANCEL` against active requests in this ring only.
    pub fn async_cancel(
        &mut self,
        target_user_data: u64,
        target_fd: i32,
        cancel_flags: u32,
    ) -> (i32, OrchestratorEffects) {
        let all = (cancel_flags & IORING_ASYNC_CANCEL_ALL) != 0;
        let by_fd = (cancel_flags & IORING_ASYNC_CANCEL_FD) != 0;
        let any = (cancel_flags & IORING_ASYNC_CANCEL_ANY) != 0;
        let fixed_fd = (cancel_flags & IORING_ASYNC_CANCEL_FD_FIXED) != 0;

        if fixed_fd {
            return (-LinuxError::ENOENT.code(), OrchestratorEffects::default());
        }

        let mut matched_ids = Vec::new();
        let mut saw_completing = false;

        for (&id, req) in self.requests.iter() {
            let is_match = if by_fd {
                match req.kind {
                    RequestKind::Normal { fd: Some(fd), .. } => fd == target_fd,
                    _ => false,
                }
            } else if any {
                true
            } else {
                req.user_data == target_user_data
            };

            if !is_match {
                continue;
            }

            if req.claimed || req.phase == RequestPhase::Completing {
                saw_completing = true;
                continue;
            }
            matched_ids.push(id);
            if !all {
                break;
            }
        }

        if matched_ids.is_empty() {
            let code = if saw_completing {
                -LinuxError::EALREADY.code()
            } else {
                -LinuxError::ENOENT.code()
            };
            return (code, OrchestratorEffects::default());
        }

        let mut combined = OrchestratorEffects::default();
        let mut cancelled_count = 0i32;

        for id in matched_ids {
            // Skip any target that was already cascade-cancelled by a prior item in the same `ALL` pass.
            let is_still_claimable = self
                .requests
                .get(&id)
                .is_some_and(|r| !r.claimed && r.phase != RequestPhase::Completing);
            if !is_still_claimable {
                continue;
            }
            combined.cancel_requests.push(id);
            if let Some(eff) =
                self.try_claim_completion(id, -LinuxError::ECANCELED.code(), 0)
            {
                cancelled_count += 1;
                combined.cqes.extend(eff.cqes);
                combined.start_requests.extend(eff.start_requests);
                combined.cancel_requests.extend(eff.cancel_requests);
                combined.reschedule_timeouts.extend(eff.reschedule_timeouts);
            }
        }

        let res = if cancelled_count == 0 {
            if saw_completing {
                -LinuxError::EALREADY.code()
            } else {
                -LinuxError::ENOENT.code()
            }
        } else if all {
            cancelled_count
        } else {
            0
        };

        (res, combined)
    }

    /// Cancels all active/queued requests owned by `owner_pid` on process exit/`execve`,
    /// except unlinked standalone `TIMEOUT`s which Linux detaches cleanly into the shared ring.
    pub fn cancel_requests_for_owner(&mut self, owner_pid: u64) -> OrchestratorEffects {
        let mut combined = OrchestratorEffects::default();
        loop {
            let next_id = self.requests.iter().find_map(|(&id, req)| {
                if req.owner_pid != owner_pid
                    || req.claimed
                    || req.phase == RequestPhase::Completing
                {
                    return None;
                }
                if matches!(req.kind, RequestKind::LinkTimeout { .. }) {
                    return None;
                }
                if matches!(req.kind, RequestKind::Timeout { .. }) && !req.in_chain {
                    return None;
                }
                Some(id)
            });
            let Some(id) = next_id else {
                break;
            };
            combined.cancel_requests.push(id);
            if let Some(eff) = self.try_claim_completion(id, -LinuxError::ECANCELED.code(), 0) {
                combined.cqes.extend(eff.cqes);
                combined.start_requests.extend(eff.start_requests);
                combined.cancel_requests.extend(eff.cancel_requests);
                combined
                    .reschedule_timeouts
                    .extend(eff.reschedule_timeouts);
            }
        }
        combined
            .start_requests
            .retain(|id| self.requests.contains_key(id));
        combined
    }

    /// Cancels all remaining active/queued requests during ring teardown (`IoUringObject::drop`).
    pub fn cancel_all_for_teardown(&mut self) -> OrchestratorEffects {
        let mut combined = OrchestratorEffects::default();
        let ids: Vec<RequestId> = self.requests.keys().copied().collect();
        for id in ids {
            let claimable = self
                .requests
                .get(&id)
                .is_some_and(|r| !r.claimed && r.phase != RequestPhase::Completing);
            if claimable {
                combined.cancel_requests.push(id);
                if let Some(eff) =
                    self.try_claim_completion(id, -LinuxError::ECANCELED.code(), 0)
                {
                    combined.cqes.extend(eff.cqes);
                    combined.start_requests.extend(eff.start_requests);
                    combined.cancel_requests.extend(eff.cancel_requests);
                }
            }
        }
        self.drain_queue.clear();
        combined
    }
}

/// Evaluates whether a batch submission callback should stop early (`!IORING_SETUP_SUBMIT_ALL`).
#[inline]
pub const fn should_stop_submit_batch(submit_all: bool, had_prep_error: bool, in_link: bool) -> bool {
    !submit_all && had_prep_error && !in_link
}

/// Host-testable executor slot state machine mirror matching `axtask::future::executor::TaskSlot`.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState {
    Idle,
    Queued,
    Polling,
    PollingNotified,
    Cancelled,
    Completed,
}

#[cfg(test)]
mod tests {
    use linux_raw_sys::io_uring::io_uring_op;
    use pulse_user_abi::io_uring::IORING_TIMEOUT_UPDATE;

    use super::*;

    #[derive(Debug)]
    struct TestSlotModel {
        state: SlotState,
        cancelled: bool,
        has_future: bool,
        queue_pushes: usize,
        drops: usize,
    }

    impl TestSlotModel {
        fn new_polling() -> Self {
            Self {
                state: SlotState::Polling,
                cancelled: false,
                has_future: false,
                queue_pushes: 0,
                drops: 0,
            }
        }

        fn wake(&mut self) -> bool {
            match self.state {
                SlotState::Idle => {
                    self.state = SlotState::Queued;
                    self.queue_pushes += 1;
                    true
                }
                SlotState::Polling => {
                    self.state = SlotState::PollingNotified;
                    false
                }
                SlotState::Queued
                | SlotState::PollingNotified
                | SlotState::Cancelled
                | SlotState::Completed => false,
            }
        }

        fn finish_poll_pending(&mut self) -> bool {
            if self.state == SlotState::Cancelled {
                self.state = SlotState::Completed;
                self.drops += 1;
                return false;
            }
            self.has_future = true;
            match self.state {
                SlotState::Polling => {
                    self.state = SlotState::Idle;
                    true
                }
                SlotState::PollingNotified => {
                    self.state = SlotState::Queued;
                    self.queue_pushes += 1;
                    true
                }
                SlotState::Cancelled => {
                    self.has_future = false;
                    self.state = SlotState::Completed;
                    self.drops += 1;
                    false
                }
                _ => false,
            }
        }

        fn cancel(&mut self) {
            self.cancelled = true;
            match self.state {
                SlotState::Idle | SlotState::Queued => {
                    self.state = SlotState::Completed;
                    if self.has_future {
                        self.has_future = false;
                        self.drops += 1;
                    }
                }
                SlotState::Polling | SlotState::PollingNotified => {
                    self.state = SlotState::Cancelled;
                }
                SlotState::Cancelled | SlotState::Completed => {}
            }
        }
    }

    fn normal_prep(user_data: u64, flags: u8, fd: Option<i32>, min_bytes: Option<usize>) -> PreparedRequest {
        PreparedRequest {
            user_data,
            sqe_flags: flags,
            owner_pid: 0,
            kind: RequestKind::Normal {
                opcode: io_uring_op::IORING_OP_NOP as u8,
                fd,
                expected_min_bytes: min_bytes,
            },
        }
    }

    #[test]
    fn executor_slot_state_dedup_wake_during_poll_and_cancel_drop() {
        let mut slot = TestSlotModel::new_polling();
        assert!(slot.finish_poll_pending());
        assert_eq!(slot.state, SlotState::Idle);
        // Repeated wakes while queued deduplicate to 1 queue push.
        assert!(slot.wake());
        assert!(!slot.wake());
        assert!(!slot.wake());
        assert_eq!(slot.queue_pushes, 1);

        // Wake during active poll triggers re-queue without losing wakeup.
        let mut slot2 = TestSlotModel::new_polling();
        assert!(!slot2.wake());
        assert_eq!(slot2.state, SlotState::PollingNotified);
        assert!(slot2.finish_poll_pending());
        assert_eq!(slot2.state, SlotState::Queued);
        assert_eq!(slot2.queue_pushes, 1);

        // Cancel during active poll defers future drop until poll finishes cleanly.
        let mut slot3 = TestSlotModel::new_polling();
        slot3.cancel();
        assert!(slot3.cancelled);
        assert_eq!(slot3.drops, 0);
        assert!(!slot3.finish_poll_pending());
        assert_eq!(slot3.state, SlotState::Completed);
        assert_eq!(slot3.drops, 1);
    }

    #[test]
    fn try_claim_completion_is_strictly_single_winner() {
        let mut orch = RequestOrchestrator::new();
        let (id, eff) = orch
            .commit_chain(&mut [normal_prep(0x11, 0, Some(3), None)])
            .unwrap();
        assert_eq!(eff.start_requests, alloc::vec![id]);
        assert_eq!(orch.request_phase(id), Some(RequestPhase::Running));

        let c1 = orch.try_claim_completion(id, 42, 0).unwrap();
        assert_eq!(c1.cqes.len(), 1);
        assert_eq!(c1.cqes[0].user_data, 0x11);
        assert_eq!(c1.cqes[0].res, 42);

        // Competing completion, cancel, or timeout claims must all lose cleanly.
        assert!(orch.try_claim_completion(id, -125, 0).is_none());
        let (cancel_res, _) = orch.async_cancel(0x11, -1, 0);
        assert_eq!(cancel_res, -LinuxError::ENOENT.code());
        assert_eq!(orch.inflight_len(), 0);
    }

    #[test]
    fn io_link_cascades_on_error_and_short_io_while_hardlink_and_etime_success_continue() {
        let mut orch = RequestOrchestrator::new();

        // 1. Soft link with unexpected short read (`res = 4 < 16`) cancels successor.
        let mut chain1 = [
            normal_prep(1, IOSQE_IO_LINK, None, Some(16)),
            normal_prep(2, IOSQE_IO_LINK, None, None),
            normal_prep(3, 0, None, None),
        ];
        let (id1, start1) = orch.commit_chain(&mut chain1).unwrap();
        assert_eq!(start1.start_requests, alloc::vec![id1]);
        let short = orch.try_claim_completion(id1, 4, 0).unwrap();
        assert_eq!(short.cqes.len(), 3);
        assert_eq!((short.cqes[0].user_data, short.cqes[0].res), (1, 4));
        assert_eq!(
            (short.cqes[1].user_data, short.cqes[1].res),
            (2, -LinuxError::ECANCELED.code())
        );
        assert_eq!(
            (short.cqes[2].user_data, short.cqes[2].res),
            (3, -LinuxError::ECANCELED.code())
        );

        // 2. Hardlink continues even on error.
        let mut chain2 = [
            normal_prep(10, IOSQE_IO_HARDLINK, None, None),
            normal_prep(11, 0, None, None),
        ];
        let (h1, _) = orch.commit_chain(&mut chain2).unwrap();
        let eff2 = orch.try_claim_completion(h1, -LinuxError::EIO.code(), 0).unwrap();
        assert_eq!(eff2.cqes.len(), 1);
        assert_eq!(eff2.start_requests.len(), 1);
        let h2 = eff2.start_requests[0];
        let eff2_b = orch.try_claim_completion(h2, 0, 0).unwrap();
        assert_eq!((eff2_b.cqes[0].user_data, eff2_b.cqes[0].res), (11, 0));

        // 3. TIMEOUT with `IORING_TIMEOUT_ETIME_SUCCESS` does NOT break soft `IOSQE_IO_LINK`.
        let mut chain3 = [
            PreparedRequest {
                user_data: 20,
                sqe_flags: IOSQE_IO_LINK,
                owner_pid: 0,
                kind: RequestKind::Timeout {
                    clock: TimeoutClock::Monotonic,
                    abs: false,
                    etime_success: true,
                    target_completions: None,
                    generation: 1,
                },
            },
            normal_prep(21, 0, None, None),
        ];
        let (t1, _) = orch.commit_chain(&mut chain3).unwrap();
        let eff3 = orch
            .try_claim_completion(t1, -LinuxError::ETIME.code(), 0)
            .unwrap();
        assert_eq!(eff3.cqes.len(), 1);
        assert_eq!(
            (eff3.cqes[0].user_data, eff3.cqes[0].res),
            (20, -LinuxError::ETIME.code())
        );
        assert_eq!(eff3.start_requests.len(), 1);
        let t2 = eff3.start_requests[0];
        let eff3_b = orch.try_claim_completion(t2, 0, 0).unwrap();
        assert_eq!((eff3_b.cqes[0].user_data, eff3_b.cqes[0].res), (21, 0));
    }

    #[test]
    fn link_timeout_race_emits_exact_non_duplicating_outcomes() {
        let mut orch = RequestOrchestrator::new();

        // A. Predecessor wins: LinkTimeout gets `-ECANCELED`.
        let mut chain_a = [
            normal_prep(100, IOSQE_IO_LINK, Some(5), None),
            PreparedRequest {
                user_data: 101,
                sqe_flags: 0,
                owner_pid: 0,
                kind: RequestKind::LinkTimeout {
                    predecessor: 0,
                    clock: TimeoutClock::Monotonic,
                    abs: false,
                    generation: 1,
                },
            },
        ];
        let (p_a, eff_a) = orch.commit_chain(&mut chain_a).unwrap();
        assert_eq!(eff_a.start_requests.len(), 2);
        let lt_a = eff_a.start_requests[1];
        let done_a = orch.try_claim_completion(p_a, 12, 0).unwrap();
        assert_eq!(done_a.cancel_requests, alloc::vec![lt_a]);
        assert_eq!(
            done_a
                .cqes
                .iter()
                .map(|c| (c.user_data, c.res))
                .collect::<Vec<_>>(),
            alloc::vec![(101, -LinuxError::ECANCELED.code()), (100, 12)]
        );
        assert!(orch.expire_link_timeout(lt_a, 1).cqes.is_empty());

        // B. LinkTimeout wins: Predecessor gets `-ECANCELED`, LinkTimeout gets `-ETIME`,
        //    and trailing linked request also cancels.
        let mut chain_b = [
            normal_prep(200, IOSQE_IO_LINK, Some(5), None),
            PreparedRequest {
                user_data: 201,
                sqe_flags: IOSQE_IO_LINK,
                owner_pid: 0,
                kind: RequestKind::LinkTimeout {
                    predecessor: 0,
                    clock: TimeoutClock::Monotonic,
                    abs: false,
                    generation: 1,
                },
            },
            normal_prep(202, 0, None, None),
        ];
        let (p_b, eff_b) = orch.commit_chain(&mut chain_b).unwrap();
        let lt_b = eff_b.start_requests[1];
        let expired = orch.expire_link_timeout(lt_b, 1);
        assert!(expired.cancel_requests.contains(&p_b));
        assert_eq!(
            expired
                .cqes
                .iter()
                .map(|c| (c.user_data, c.res))
                .collect::<Vec<_>>(),
            alloc::vec![
                (200, -LinuxError::ECANCELED.code()),
                (202, -LinuxError::ECANCELED.code()),
                (201, -LinuxError::ETIME.code()),
            ]
        );
        assert!(orch.try_claim_completion(p_b, 0, 0).is_none());
    }

    #[test]
    fn drain_barrier_blocks_subsequent_requests_until_prior_seq_completes() {
        let mut orch = RequestOrchestrator::new();
        let (r1, e1) = orch.commit_chain(&mut [normal_prep(1, 0, None, None)]).unwrap();
        assert_eq!(e1.start_requests, alloc::vec![r1]);

        let (r2, e2) = orch
            .commit_chain(&mut [normal_prep(2, IOSQE_IO_DRAIN, None, None)])
            .unwrap();
        assert!(e2.start_requests.is_empty());

        let (r3, e3) = orch.commit_chain(&mut [normal_prep(3, 0, None, None)]).unwrap();
        assert!(e3.start_requests.is_empty());
        assert_eq!(orch.drain_queue_len(), 2);

        // Finishing r1 releases r2 (the drain request), while r3 still waits until r2 completes.
        let d1 = orch.try_claim_completion(r1, 0, 0).unwrap();
        assert_eq!(d1.start_requests, alloc::vec![r2]);
        assert_eq!(orch.drain_queue_len(), 1);

        let d2 = orch.try_claim_completion(r2, 0, 0).unwrap();
        assert_eq!(d2.start_requests, alloc::vec![r3]);
        assert_eq!(orch.drain_queue_len(), 0);
    }

    #[test]
    fn timeout_count_remove_update_and_async_cancel_cover_ealready_ebusy_and_enoent() {
        let mut orch = RequestOrchestrator::new();
        let (t1, _) = orch
            .commit_chain(&mut [PreparedRequest {
                user_data: 50,
                sqe_flags: 0,
                owner_pid: 0,
                kind: RequestKind::Timeout {
                    clock: TimeoutClock::Monotonic,
                    abs: false,
                    etime_success: false,
                    target_completions: Some(orch.completion_seq() + 2),
                    generation: 1,
                },
            }])
            .unwrap();

        // Update valid timeout bumps generation.
        let (upd_res, upd_info) = orch.timeout_update(50, IORING_TIMEOUT_UPDATE | IORING_TIMEOUT_ABS);
        assert_eq!(upd_res, 0);
        assert_eq!(upd_info.unwrap().1, 2);
        // Stale generation expiry is ignored.
        assert!(orch.expire_timeout(t1, 1).cqes.is_empty());

        // Emitting 2 non-timeout completions satisfies `off = 2`.
        let (n1, _) = orch.commit_chain(&mut [normal_prep(1, 0, None, None)]).unwrap();
        let (n2, _) = orch.commit_chain(&mut [normal_prep(2, 0, None, None)]).unwrap();
        assert!(orch.try_claim_completion(n1, 0, 0).unwrap().cqes.len() == 1);
        let eff_n2 = orch.try_claim_completion(n2, 0, 0).unwrap();
        assert!(eff_n2.cancel_requests.contains(&t1));
        assert!(eff_n2.cqes.iter().any(|c| c.user_data == 50 && c.res == 0));

        // Remove missing / Completing -> `-ENOENT` / `-EBUSY`.
        assert_eq!(orch.timeout_remove(50).0, -LinuxError::ENOENT.code());

        // Async cancel: FD filter & Completing (`-EALREADY`).
        let (r_fd, _) = orch
            .commit_chain(&mut [normal_prep(77, 0, Some(9), None)])
            .unwrap();
        assert!(orch.try_begin_completing(r_fd));
        assert_eq!(
            orch.async_cancel(0, 9, IORING_ASYNC_CANCEL_FD).0,
            -LinuxError::EALREADY.code()
        );
        let fin = orch.finish_completing(r_fd, 64, 0);
        assert_eq!((fin.cqes[0].user_data, fin.cqes[0].res), (77, 64));
    }

    #[test]
    fn cancel_requests_for_owner_cancels_links_and_keeps_standalone_timeouts() {
        let mut orch = RequestOrchestrator::new();

        // Linked POLL_ADD -> TIMEOUT owned by exiting child pid 42.
        let (_, _) = orch
            .commit_chain(&mut [
                normal_prep(1, IOSQE_IO_LINK, Some(3), None).with_owner_pid(42),
                PreparedRequest {
                    user_data: 2,
                    sqe_flags: 0,
                    owner_pid: 42,
                    kind: RequestKind::Timeout {
                        clock: TimeoutClock::Monotonic,
                        abs: false,
                        etime_success: false,
                        target_completions: None,
                        generation: 1,
                    },
                },
            ])
            .unwrap();

        // Standalone unlinked TIMEOUT owned by exiting child pid 42 (must survive exit).
        let (standalone_to, _) = orch
            .commit_chain(&mut [PreparedRequest {
                user_data: 3,
                sqe_flags: 0,
                owner_pid: 42,
                kind: RequestKind::Timeout {
                    clock: TimeoutClock::Monotonic,
                    abs: false,
                    etime_success: false,
                    target_completions: None,
                    generation: 1,
                },
            }])
            .unwrap();

        // Linked TIMEOUT -> NOP owned by pid 43 (must survive pid 42 exit, cancel on pid 43 exit).
        let _ = orch
            .commit_chain(&mut [
                PreparedRequest {
                    user_data: 10,
                    sqe_flags: IOSQE_IO_LINK,
                    owner_pid: 43,
                    kind: RequestKind::Timeout {
                        clock: TimeoutClock::Monotonic,
                        abs: false,
                        etime_success: false,
                        target_completions: None,
                        generation: 1,
                    },
                },
                normal_prep(11, 0, None, None).with_owner_pid(43),
            ])
            .unwrap();

        let eff_42 = orch.cancel_requests_for_owner(42);
        assert_eq!(
            eff_42
                .cqes
                .iter()
                .map(|c| (c.user_data, c.res))
                .collect::<Vec<_>>(),
            alloc::vec![
                (1, -LinuxError::ECANCELED.code()),
                (2, -LinuxError::ECANCELED.code()),
            ]
        );
        // Standalone timeout (user_data 3) expires cleanly later.
        let exp_3 = orch.expire_timeout(standalone_to, 1);
        assert_eq!(exp_3.cqes.len(), 1);
        assert_eq!((exp_3.cqes[0].user_data, exp_3.cqes[0].res), (3, -LinuxError::ETIME.code()));

        let eff_43 = orch.cancel_requests_for_owner(43);
        assert_eq!(
            eff_43
                .cqes
                .iter()
                .map(|c| (c.user_data, c.res))
                .collect::<Vec<_>>(),
            alloc::vec![
                (10, -LinuxError::ECANCELED.code()),
                (11, -LinuxError::ECANCELED.code()),
            ]
        );
        assert_eq!(orch.inflight_len(), 0);
    }
}
