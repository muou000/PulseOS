use alloc::{boxed::Box, sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, Ordering};

use log::warn;
use rdif_block::{BIrqHandler, IQueue, Interface, QueueHandle};

use crate::{
    block::OperationPoll,
    error::{Error, ErrorContext, Phase},
    rdif::{
        config::{BlockConfig, device_info, queue_limits},
        host::BlockHost,
        irq::BlockIrqHandler,
        queue::BlockQueue,
        shared_core::SharedCore,
    },
    sdio::{
        card::SdioSdmmc,
        host::{SdioHost, SdioIrqHost},
    },
    response::CardState,
};

// A data command can leave an SD card in Programming while the controller has
// already reported the transfer complete.  CMD13 is the portable SD/MMC
// completion barrier; bound retries so a missing card/IRQ cannot spin forever.
const MAX_FLUSH_STATUS_POLLS: usize = 128;
const MAX_FLUSH_COMMAND_POLLS: usize = 1_000_000;

fn flush_card_state(state: CardState) -> Result<bool, Error> {
    match state {
        CardState::Transfer => Ok(true),
        CardState::Programming => Ok(false),
        _ => Err(Error::BadResponse(ErrorContext::for_cmd(
            Phase::BusyWait,
            13,
        ))),
    }
}

pub struct BlockDevice<H>
where
    H: BlockHost,
{
    pub(super) control: Arc<BlockControl<H>>,
    irq_handler: Option<BIrqHandler>,
}

pub struct BlockControl<H>
where
    H: BlockHost,
{
    pub(super) raw: SharedCore<SdioSdmmc<H>>,
    pub(super) config: BlockConfig,
    pub(super) irq_enabled: AtomicBool,
    pub(super) queue_taken: AtomicBool,
}

impl<H> BlockDevice<H>
where
    H: BlockHost,
{
    pub fn new(mut card: SdioSdmmc<H>, config: BlockConfig) -> Self {
        let irq_handler = config.irq_driven.then(|| {
            Box::new(BlockIrqHandler::<H> {
                irq: SdioIrqHost::irq_handle(card.host_mut()),
            }) as BIrqHandler
        });
        let raw = SharedCore::new(card);
        Self {
            control: Arc::new(BlockControl {
                raw,
                config,
                irq_enabled: AtomicBool::new(false),
                queue_taken: AtomicBool::new(false),
            }),
            irq_handler,
        }
    }

    pub fn config(&self) -> &BlockConfig {
        &self.control.config
    }

    /// Completes the card-side programming phase after queued writes.
    ///
    /// RDIF's queue has no generic media-cache flush command.  For SD/MMC,
    /// CMD13/SEND_STATUS is the protocol-defined barrier: once the card
    /// reports `Transfer`, the preceding write is no longer in its internal
    /// programming state. Callers must serialize this method with the queue
    /// (the JH7110 adapter does so with its queue mutex).
    pub fn flush(&self) -> Result<(), Error> {
        let mut polls = 0usize;
        self.flush_with(|| {
            polls = polls.saturating_add(1);
            polls > MAX_FLUSH_COMMAND_POLLS
        })
    }

    /// Variant of [`Self::flush`] with a caller-supplied abort predicate.
    ///
    /// Controller drivers can use their monotonic clock here so a lost IRQ or
    /// a card that never leaves Programming cannot strand an async writeback
    /// task while the shared card core is borrowed.
    pub fn flush_with(&self, mut should_abort: impl FnMut() -> bool) -> Result<(), Error> {
        self.control.raw.with_mut(|card| {
            for _ in 0..MAX_FLUSH_STATUS_POLLS {
                if should_abort() {
                    return Err(Error::Timeout(ErrorContext::for_cmd(
                        Phase::BusyWait,
                        13,
                    )));
                }
                let mut request = card.submit_status()?;
                loop {
                    if should_abort() {
                        return Err(Error::Timeout(ErrorContext::for_cmd(
                            Phase::BusyWait,
                            13,
                        )));
                    }
                    match card.poll_status_request(&mut request)? {
                        OperationPoll::Pending => core::hint::spin_loop(),
                        OperationPoll::Complete(state) => {
                            if flush_card_state(state)? {
                                return Ok(());
                            }
                            break;
                        }
                    }
                }
            }
            Err(Error::Timeout(ErrorContext::for_cmd(
                Phase::BusyWait,
                13,
            )))
        })
    }

    fn queue_limits_with_mask(&self, dma_mask: u64) -> rdif_block::QueueLimits {
        queue_limits(&self.control.config, dma_mask)
    }
}

impl<H> BlockControl<H>
where
    H: BlockHost,
{
    pub(super) fn claim_queue(&self) -> bool {
        self.queue_taken
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
    }

    pub(super) fn release_queue(&self) {
        self.queue_taken.store(false, Ordering::Release);
    }
}

impl<H> rdif_block::DriverGeneric for BlockDevice<H>
where
    H: BlockHost,
{
    fn name(&self) -> &str {
        self.control.config.name
    }
}

impl<H> Interface for BlockDevice<H>
where
    H: BlockHost,
{
    fn device_info(&self) -> rdif_block::DeviceInfo {
        device_info(&self.control.config)
    }

    fn queue_limits(&self) -> rdif_block::QueueLimits {
        self.queue_limits_with_mask(self.control.config.dma_mask)
    }

    fn create_queue(&mut self) -> Option<Box<dyn IQueue>> {
        if self.control.config.uses_dma() || !self.control.claim_queue() {
            return None;
        }
        Some(Box::new(BlockQueue::<H>::new(Arc::clone(&self.control), 0)) as _)
    }

    fn create_owned_queue(&mut self) -> Option<QueueHandle> {
        if self.control.config.dma.is_none() || !self.control.claim_queue() {
            return None;
        }
        Some(QueueHandle::new(Box::new(BlockQueue::<H>::new(
            Arc::clone(&self.control),
            0,
        ))))
    }

    fn enable_irq(&self) {
        if !self.control.config.irq_driven {
            self.control.irq_enabled.store(false, Ordering::Release);
            return;
        }
        let mut enabled = false;
        self.control.raw.with_mut(|raw| {
            if let Err(err) = SdioHost::enable_completion_irq(raw.host_mut()) {
                warn!(
                    "{}: enable completion IRQ failed: {:?}",
                    self.control.config.name, err
                );
                return;
            }
            enabled = raw.host().completion_irq_enabled();
        });
        self.control.irq_enabled.store(enabled, Ordering::Release);
    }

    fn disable_irq(&self) {
        self.control.raw.with_mut(|raw| {
            if let Err(err) = SdioHost::disable_completion_irq(raw.host_mut()) {
                warn!(
                    "{}: disable completion IRQ failed: {:?}",
                    self.control.config.name, err
                );
            }
        });
        self.control.irq_enabled.store(false, Ordering::Release);
    }

    fn is_irq_enabled(&self) -> bool {
        self.control.irq_enabled.load(Ordering::Acquire)
    }

    fn irq_sources(&self) -> rdif_block::IrqSourceList {
        if !self.control.config.irq_driven {
            return Vec::new();
        }
        vec![rdif_block::IrqSourceInfo::legacy(
            rdif_block::IdList::from_bits(1),
        )]
    }

    fn take_irq_handler(&mut self, source_id: usize) -> Option<Box<dyn rdif_block::IrqHandler>> {
        if !self.control.config.irq_driven || source_id != 0 {
            return None;
        }
        self.irq_handler.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn card_status_barrier_accepts_transfer_only() {
        assert_eq!(flush_card_state(CardState::Transfer), Ok(true));
        assert_eq!(flush_card_state(CardState::Programming), Ok(false));
        assert!(flush_card_state(CardState::Standby).is_err());
    }
}
