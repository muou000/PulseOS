//! StarFive JH7110 SD/MMC block device adapter.

use core::{
    future::{Ready, ready},
    ptr::NonNull,
    time::Duration,
};

use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use sdmmc_protocol::{
    DataCommandPoll, OperationPoll,
    error::Error,
    sdio::{CardInfo, CardInitPreference, SdioHost2Adapter, SdioInitScratch, SdioSdmmc},
};
use spin::Mutex;
use starfive_jh7110_dwmmc::{JH7110_STABLE_REFERENCE_CLOCK_HZ, Jh7110DwMmc, Jh7110DwMmcConfig};

use crate::BlockDriverOps;

const BLOCK_SIZE: usize = 512;
const INIT_TIMEOUT: Duration = Duration::from_secs(5);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const INIT_PACE: Duration = Duration::from_millis(10);
const JH7110_PIO_TRANSFER_CLOCK_HZ: u32 = 6_250_000;

const CLKDIV_OFFSET: usize = 0x08;
const CLKENA_OFFSET: usize = 0x10;
const TMOUT_OFFSET: usize = 0x14;
const CTYPE_OFFSET: usize = 0x18;
const RINTSTS_OFFSET: usize = 0x44;
const STATUS_OFFSET: usize = 0x48;
const FIFOTH_OFFSET: usize = 0x4c;
const UHS_OFFSET: usize = 0x74;
const UHS_REG_EXT_OFFSET: usize = 0x108;
const JH7110_FIFO_DEPTH_WORDS: u32 = 32;
const JH7110_FIFOTH: u32 =
    (2 << 28) | ((JH7110_FIFO_DEPTH_WORDS / 2 - 1) << 16) | (JH7110_FIFO_DEPTH_WORDS / 2);

type Card = SdioSdmmc<SdioHost2Adapter<Jh7110DwMmc>>;

/// A serialized JH7110 SD/MMC block device using the controller's PIO FIFO.
pub struct Jh7110SdMmc {
    card: Mutex<Card>,
    capacity_blocks: u64,
    base: usize,
}

impl Jh7110SdMmc {
    /// Initializes the SD card attached to a JH7110 DW MMC controller.
    ///
    /// # Safety
    ///
    /// `base` must be the mapped controller register address and this instance
    /// must have exclusive ownership of the controller.
    pub unsafe fn try_new(base: usize) -> DevResult<Self> {
        let mmio = NonNull::new(base as *mut u8).ok_or(DevError::InvalidParam)?;
        log_controller_state(base);

        let config =
            Jh7110DwMmcConfig::default().with_reference_clock_hz(JH7110_STABLE_REFERENCE_CLOCK_HZ);
        let mut host = unsafe { Jh7110DwMmc::new(mmio, config) };
        log::debug!(
            "JH7110 SD/MMC: reset controller, CIU reference={} Hz",
            JH7110_STABLE_REFERENCE_CLOCK_HZ
        );
        host.reset_and_init().map_err(|error| {
            log::error!("JH7110 SD/MMC controller reset failed: {error}");
            map_error(error)
        })?;
        // dwmmc-host 0.3.3 defaults to a 256-word FIFO. JH7110 exposes a
        // 32-word FIFO, and card initialization already issues data commands.
        program_jh7110_fifo(base);

        let mut card = SdioSdmmc::new_host2(host);
        // The board path deliberately stays at legacy/default timing until the
        // pinctrl, clock and 1.8 V regulator controls are owned by PulseOS.
        card.set_sd_speed_selection_enabled(false);
        let info = initialize_card(&mut card, base).map_err(|error| {
            log::error!("JH7110 SD/MMC card initialization failed: {error}");
            map_error(error)
        })?;
        set_pio_transfer_clock(&mut card).map_err(|error| {
            log::error!("JH7110 SD/MMC transfer clock setup failed: {error}");
            map_error(error)
        })?;
        program_jh7110_fifo(base);
        log::debug!(
            "JH7110 SD/MMC: polling PIO clock capped at {} Hz",
            JH7110_PIO_TRANSFER_CLOCK_HZ
        );
        log_transfer_state(base, "post-init");
        let capacity_blocks = info.capacity_blocks.ok_or_else(|| {
            log::error!("JH7110 SD/MMC card did not report a supported capacity");
            DevError::Unsupported
        })?;
        if capacity_blocks == 0 {
            return Err(DevError::Io);
        }

        log::info!(
            "JH7110 SD/MMC card ready: kind={:?}, high_capacity={}, rca={:#x}",
            info.kind,
            info.high_capacity,
            info.rca
        );
        log::info!(
            "JH7110 SD/MMC capacity: {} blocks ({} MiB), polling PIO",
            capacity_blocks,
            capacity_blocks.saturating_mul(BLOCK_SIZE as u64) / (1024 * 1024)
        );
        Ok(Self {
            card: Mutex::new(card),
            capacity_blocks,
            base,
        })
    }

    fn read_blocks(&self, block_id: u64, buf: &mut [u8]) -> DevResult {
        validate_request(block_id, buf.len(), self.capacity_blocks)?;
        let first_block = block_id as u32;
        let mut card = self.card.lock();
        program_jh7110_fifo(self.base);
        for (index, block) in buf.chunks_exact_mut(BLOCK_SIZE).enumerate() {
            let block_id = first_block
                .checked_add(index as u32)
                .ok_or(DevError::InvalidParam)?;
            read_one_block(&mut card, block_id, block).map_err(|error| {
                log_transfer_error_state(self.base, "read-recovery");
                log::error!("JH7110 SD/MMC read block {block_id} failed: {error}");
                map_error(error)
            })?;
        }
        Ok(())
    }

    fn write_blocks(&self, block_id: u64, buf: &[u8]) -> DevResult {
        validate_request(block_id, buf.len(), self.capacity_blocks)?;
        let first_block = block_id as u32;
        let mut card = self.card.lock();
        program_jh7110_fifo(self.base);
        for (index, block) in buf.chunks_exact(BLOCK_SIZE).enumerate() {
            let block_id = first_block
                .checked_add(index as u32)
                .ok_or(DevError::InvalidParam)?;
            write_one_block(&mut card, block_id, block).map_err(|error| {
                log_transfer_error_state(self.base, "write-recovery");
                log::error!("JH7110 SD/MMC write block {block_id} failed: {error}");
                map_error(error)
            })?;
        }
        Ok(())
    }
}

impl BaseDriverOps for Jh7110SdMmc {
    fn device_type(&self) -> DeviceType {
        DeviceType::Block
    }

    fn device_name(&self) -> &str {
        "starfive-jh7110-sdmmc"
    }
}

impl BlockDriverOps for Jh7110SdMmc {
    fn num_blocks(&self) -> u64 {
        self.capacity_blocks
    }

    fn block_size(&self) -> usize {
        BLOCK_SIZE
    }

    fn read_block(&mut self, block_id: u64, buf: &mut [u8]) -> DevResult {
        self.read_blocks(block_id, buf)
    }

    fn write_block(&mut self, block_id: u64, buf: &[u8]) -> DevResult {
        self.write_blocks(block_id, buf)
    }

    fn flush(&mut self) -> DevResult {
        Ok(())
    }
}

#[cfg(feature = "async")]
impl crate::AsyncBlockDriverOps for Jh7110SdMmc {
    type ReadFuture<'a>
        = Ready<DevResult>
    where
        Self: 'a;
    type WriteFuture<'a>
        = Ready<DevResult>
    where
        Self: 'a;
    type FlushFuture<'a>
        = Ready<DevResult>
    where
        Self: 'a;

    fn read_block_async<'a>(&'a self, block_id: u64, buf: &'a mut [u8]) -> Self::ReadFuture<'a> {
        ready(self.read_blocks(block_id, buf))
    }

    fn write_block_async<'a>(&'a self, block_id: u64, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        ready(self.write_blocks(block_id, buf))
    }

    fn flush_async(&self) -> Self::FlushFuture<'_> {
        ready(Ok(()))
    }
}

fn initialize_card(card: &mut Card, base: usize) -> Result<CardInfo, Error> {
    let mut scratch = SdioInitScratch::new();
    let mut request = card.submit_init_with_preference(CardInitPreference::SdOnly, &mut scratch)?;
    let deadline = axhal::time::monotonic_time() + INIT_TIMEOUT;
    loop {
        if axhal::time::monotonic_time() >= deadline {
            return Err(Error::Timeout(sdmmc_protocol::error::ErrorContext::new(
                sdmmc_protocol::error::Phase::Init,
            )));
        }
        let progress = card.poll_init_request(&mut request);
        // ResetAll and PowerOn both reset the controller and restore the
        // upstream 256-word default. Re-apply the JH7110 threshold after each
        // state transition, before the next command can be submitted.
        program_jh7110_fifo(base);
        match progress? {
            OperationPoll::Pending => {
                if request.take_needs_pace() {
                    axhal::time::busy_wait(INIT_PACE);
                } else {
                    core::hint::spin_loop();
                }
            }
            OperationPoll::Complete(info) => return Ok(info),
            _ => return Err(Error::UnsupportedCommand),
        }
    }
}

fn set_pio_transfer_clock(card: &mut Card) -> Result<(), Error> {
    card.host_mut()
        .with_host_mut(|host| host.inner_mut().program_clock(JH7110_PIO_TRANSFER_CLOCK_HZ))
}

fn read_one_block(card: &mut Card, block_id: u32, buf: &mut [u8]) -> Result<(), Error> {
    pio_transfer_fence();
    let mut request = card.submit_read_blocks_into(block_id, buf)?;
    pio_transfer_fence();
    let deadline = axhal::time::monotonic_time() + IO_TIMEOUT;
    loop {
        if axhal::time::monotonic_time() >= deadline {
            return Err(Error::Timeout(
                sdmmc_protocol::error::ErrorContext::for_cmd(
                    sdmmc_protocol::error::Phase::DataRead,
                    17,
                ),
            ));
        }
        let poll = card.poll_data_request(&mut request);
        pio_transfer_fence();
        match poll? {
            DataCommandPoll::Pending => core::hint::spin_loop(),
            DataCommandPoll::Complete(_) => return Ok(()),
            _ => return Err(Error::UnsupportedCommand),
        }
    }
}

fn write_one_block(card: &mut Card, block_id: u32, buf: &[u8]) -> Result<(), Error> {
    pio_transfer_fence();
    let mut request = card.submit_write_blocks_from(block_id, buf)?;
    pio_transfer_fence();
    let deadline = axhal::time::monotonic_time() + IO_TIMEOUT;
    loop {
        if axhal::time::monotonic_time() >= deadline {
            return Err(Error::Timeout(
                sdmmc_protocol::error::ErrorContext::for_cmd(
                    sdmmc_protocol::error::Phase::DataWrite,
                    24,
                ),
            ));
        }
        let poll = card.poll_data_request(&mut request);
        pio_transfer_fence();
        match poll? {
            DataCommandPoll::Pending => core::hint::spin_loop(),
            DataCommandPoll::Complete(_) => return Ok(()),
            _ => return Err(Error::UnsupportedCommand),
        }
    }
}

#[inline]
fn pio_transfer_fence() {
    // Linux uses ordered MMIO accessors for DW-MMC PIO and drains stores
    // before it publishes transfer completion. dwmmc-host exposes raw
    // volatile FIFO accesses, so retain the required RAM/I-O ordering at the
    // serialized adapter boundary.
    #[cfg(target_arch = "riscv64")]
    unsafe {
        core::arch::asm!("fence iorw, iorw", options(nostack, preserves_flags));
    }
    #[cfg(not(target_arch = "riscv64"))]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

fn validate_request(block_id: u64, len: usize, capacity_blocks: u64) -> DevResult {
    if len == 0 || len % BLOCK_SIZE != 0 || u32::try_from(block_id).is_err() {
        return Err(DevError::InvalidParam);
    }
    let blocks = u64::try_from(len / BLOCK_SIZE).map_err(|_| DevError::InvalidParam)?;
    if block_id
        .checked_add(blocks)
        .is_none_or(|end| end > capacity_blocks)
    {
        return Err(DevError::InvalidParam);
    }
    Ok(())
}

fn map_error(error: Error) -> DevError {
    match error {
        Error::Busy => DevError::ResourceBusy,
        Error::InvalidArgument | Error::Misaligned => DevError::InvalidParam,
        Error::UnsupportedCommand => DevError::Unsupported,
        _ => DevError::Io,
    }
}

fn program_jh7110_fifo(base: usize) {
    unsafe { ((base + FIFOTH_OFFSET) as *mut u32).write_volatile(JH7110_FIFOTH) };
}

fn read_controller_register(base: usize, offset: usize) -> u32 {
    unsafe { ((base + offset) as *const u32).read_volatile() }
}

fn log_transfer_state(base: usize, stage: &str) {
    log::debug!(
        "SDMMC {stage} clock: DIV={:#010x} ENA={:#010x}",
        read_controller_register(base, CLKDIV_OFFSET),
        read_controller_register(base, CLKENA_OFFSET),
    );
    log::debug!(
        "SDMMC {stage} bus: CTYPE={:#010x} TMOUT={:#010x}",
        read_controller_register(base, CTYPE_OFFSET),
        read_controller_register(base, TMOUT_OFFSET),
    );
    log::debug!(
        "SDMMC {stage} fifo: FIFOTH={:#010x} STATUS={:#010x}",
        read_controller_register(base, FIFOTH_OFFSET),
        read_controller_register(base, STATUS_OFFSET),
    );
    log::debug!(
        "SDMMC {stage} timing: UHS={:#010x} EXT={:#010x}",
        read_controller_register(base, UHS_OFFSET),
        read_controller_register(base, UHS_REG_EXT_OFFSET),
    );
}

fn log_transfer_error_state(base: usize, stage: &str) {
    log::error!(
        "SDMMC {stage}: RAW={:#010x} STATUS={:#010x}",
        read_controller_register(base, RINTSTS_OFFSET),
        read_controller_register(base, STATUS_OFFSET),
    );
    log::error!(
        "SDMMC {stage}: DIV={:#010x} ENA={:#010x}",
        read_controller_register(base, CLKDIV_OFFSET),
        read_controller_register(base, CLKENA_OFFSET),
    );
    log::error!(
        "SDMMC {stage}: CTYPE={:#010x} FIFOTH={:#010x}",
        read_controller_register(base, CTYPE_OFFSET),
        read_controller_register(base, FIFOTH_OFFSET),
    );
    log::error!(
        "SDMMC {stage}: UHS={:#010x} EXT={:#010x}",
        read_controller_register(base, UHS_OFFSET),
        read_controller_register(base, UHS_REG_EXT_OFFSET),
    );
}

fn log_controller_state(base: usize) {
    // These fixed offsets are part of the Synopsys DW_mshc register layout.
    log::debug!("JH7110 SD/MMC controller MMIO at {base:#x}");
    log::debug!(
        "JH7110 SD/MMC ID: VERID={:#010x}, HCON={:#010x}",
        read_controller_register(base, 0x6c),
        read_controller_register(base, 0x70),
    );
    log::debug!(
        "JH7110 SD/MMC state: CTRL={:#010x}, PWREN={:#010x}",
        read_controller_register(base, 0x00),
        read_controller_register(base, 0x04),
    );
    log::debug!(
        "JH7110 SD/MMC clock/status: CLKENA={:#010x}, STATUS={:#010x}",
        read_controller_register(base, CLKENA_OFFSET),
        read_controller_register(base, STATUS_OFFSET),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jh7110_fifo_threshold_matches_32_word_slot() {
        assert_eq!(JH7110_FIFOTH, 0x200f_0010);
    }

    #[test]
    fn conservative_pio_clock_uses_divider_four() {
        assert_eq!(
            JH7110_STABLE_REFERENCE_CLOCK_HZ / (2 * JH7110_PIO_TRANSFER_CLOCK_HZ),
            4
        );
    }

    #[test]
    fn request_must_fit_card_capacity() {
        assert!(validate_request(7, 512, 8).is_ok());
        assert!(validate_request(7, 1024, 8).is_err());
        assert!(validate_request(0, 0, 8).is_err());
    }
}
