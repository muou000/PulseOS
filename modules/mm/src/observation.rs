//! Optional observation of deferred TLB visibility, separate from ownership.
//!
//! A begin has no matching completion when a shootdown is abandoned or cannot
//! establish visibility. Consumers must retain that uncertainty indefinitely.

use core::sync::atomic::{AtomicU64, Ordering};

type Observer = fn(space_id: usize, token: u64, complete: bool);

static OBSERVER: spin::Once<Observer> = spin::Once::new();
static NEXT_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Installs the boot-time observer once. The callback receives only scalar
/// facts (a never-reused address-space identity, not a hardware ASID) and must not acquire an address-space lock or wait for a shootdown.
/// Begin can run under an address-space write lock; completion runs unlocked.
/// The callback does not participate in the memory ownership protocol.
pub fn register_tlb_observer(observer: Observer) {
    OBSERVER.call_once(|| observer);
}

pub(crate) struct Observation {
    observer: Observer,
    space_id: usize,
    token: u64,
}

impl Observation {
    pub(crate) fn begin(space_id: usize) -> Option<Self> {
        let observer = *OBSERVER.get()?;
        let token = NEXT_TOKEN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .expect("TLB observation identity exhausted");
        observer(space_id, token, false);
        Some(Self {
            observer,
            space_id,
            token,
        })
    }

    pub(crate) fn complete(self) {
        (self.observer)(self.space_id, self.token, true);
    }
}
