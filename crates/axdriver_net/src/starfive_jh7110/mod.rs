//! Minimal single-queue DWMAC 5.20 driver for the StarFive JH7110.

extern crate alloc;

mod desc;
mod regs;

use alloc::sync::Arc;
use core::{
    marker::PhantomData,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering, fence},
    time::Duration,
};

use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use desc::{DESC_SIZE, DmaDesc};
use regs::*;

use crate::{EthernetAddress, NetBuf, NetBufPool, NetBufPtr, NetDriverOps};

// JH7110 exposes only a combined clean+invalidate cache operation. The rings
// contain enough entries for DWMAC's ring mode, but only one entry per ring is
// DMA-owned at a time. Thus flushing a descriptor's cache line cannot write
// back stale state over another descriptor that DMA is updating.
const RX_DESC_COUNT: usize = 4;
const TX_DESC_COUNT: usize = 4;
const CACHE_LINE_SIZE: usize = 64;
const DMA_BUFFER_SIZE: usize = 2048;
const PAGE_SIZE: usize = 4096;
const DMA_ADDR_LIMIT: u64 = 1 << 40;
const RESET_SPINS: usize = 1_000_000;
const MDIO_SPINS: usize = 100_000;
const PHY_BMCR: u8 = 0;
const PHY_BMSR: u8 = 1;
const YT8531_PHY_ID: u32 = 0x4f51_e91b;
const YT8531_EXT_PAGE_SELECT: u8 = 0x1e;
const YT8531_EXT_PAGE_DATA: u8 = 0x1f;
const YT8531_EXT_CHIP_CONFIG: u16 = 0xa001;
const YT8531_EXT_RGMII_CONFIG1: u16 = 0xa003;
const YT8531_EXT_PAD_DRIVE_STRENGTH: u16 = 0xa010;
const YT8531_EXT_SYNCE_CONFIG: u16 = 0xa012;
const FALLBACK_POLL_INTERVAL: Duration = Duration::from_millis(10);

const RX_RING_OFFSET: usize = 0;
const TX_RING_OFFSET: usize = align_up(RX_RING_OFFSET + RX_DESC_COUNT * DESC_SIZE, CACHE_LINE_SIZE);
const RX_BUFFER_OFFSET: usize =
    align_up(TX_RING_OFFSET + TX_DESC_COUNT * DESC_SIZE, CACHE_LINE_SIZE);
const TX_BUFFER_OFFSET: usize = RX_BUFFER_OFFSET + RX_DESC_COUNT * DMA_BUFFER_SIZE;
const DMA_REGION_SIZE: usize = TX_BUFFER_OFFSET + TX_DESC_COUNT * DMA_BUFFER_SIZE;
const DMA_REGION_PAGES: usize = DMA_REGION_SIZE.div_ceil(PAGE_SIZE);

const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// DMA services supplied by the owning kernel.
///
/// # Safety
///
/// Allocations must be physically contiguous, page aligned, and accessible by
/// the device at the returned physical address. `dma_sync` must complete all
/// cache maintenance before it returns.
pub unsafe trait DmaOps: Send + Sync + 'static {
    /// Allocates physically contiguous DMA pages.
    fn alloc_pages(num_pages: usize) -> DevResult<(NonNull<u8>, u64)>;

    /// Releases pages returned by `alloc_pages`.
    unsafe fn dealloc_pages(vaddr: NonNull<u8>, dma_addr: u64, num_pages: usize);

    /// Writes back and invalidates cache lines covering a DMA range.
    fn dma_sync(paddr: u64, size: usize);
}

/// DWMAC AXI bus settings encoded from the firmware device tree.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Jh7110AxiConfig {
    /// Maximum outstanding AXI write requests, in the controller encoding.
    pub write_outstanding_limit: u8,
    /// Maximum outstanding AXI read requests, in the controller encoding.
    pub read_outstanding_limit: u8,
    /// Supported burst lengths using DWMAC's BLEN4..BLEN256 bit map.
    pub burst_length_mask: u8,
    /// Allows the AXI master to enter low-power idle.
    pub low_power_idle: bool,
    /// Exits low-power idle when a frame becomes available.
    pub exit_on_frame: bool,
}

impl Default for Jh7110AxiConfig {
    fn default() -> Self {
        Self {
            write_outstanding_limit: 1,
            read_outstanding_limit: 1,
            burst_length_mask: 0xfe,
            low_power_idle: false,
            exit_on_frame: false,
        }
    }
}

/// Board data obtained from the firmware device tree.
#[derive(Clone, Copy, Debug)]
pub struct Jh7110Config {
    /// MAC address supplied by firmware, or `None` to use the controller value.
    pub mac_address: Option<[u8; 6]>,
    /// Clause 22 PHY address on the MDIO bus.
    pub phy_addr: u8,
    /// Preferred GMAC4 CSR clock selector. Values above 7 reuse the selector
    /// left by firmware. PHY-ID probing may refine the selected value.
    pub mdio_clock_range: u8,
    /// AXI outstanding-request and burst-length settings.
    pub axi: Jh7110AxiConfig,
    /// Uses the 64-byte RX/TX threshold selected by the board device tree.
    pub force_threshold_dma_mode: bool,
    /// Enables the DWMAC descriptor cache after DMA reset.
    pub descriptor_cache_enable: bool,
    /// Accepts all destination addresses in hardware so the network stack can filter them.
    pub promiscuous_mode: bool,
}

/// Raw status captured while acknowledging a DWMAC interrupt.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Jh7110InterruptStatus {
    /// DMA channel 0 status before write-one-to-clear acknowledgement.
    pub dma: u32,
    /// MAC interrupt status sampled at the same time.
    pub mac: u32,
}

/// YT8531 extended registers relevant to the RGMII board wiring.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Jh7110PhyExtendedStatus {
    /// Chip configuration, including RX clock delay enable.
    pub chip_config: u16,
    /// RGMII delay and TX clock inversion configuration.
    pub rgmii_config1: u16,
    /// RGMII RX clock/data pad drive-strength configuration.
    pub pad_drive_strength: u16,
    /// PHY synchronous-clock output configuration.
    pub synce_config: u16,
}

/// Clause 22 PHY registers that determine whether the MAC data path is active.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Jh7110PhyBasicStatus {
    /// Basic mode control register (BMCR).
    pub control: u16,
    /// Basic mode status register (BMSR).
    pub status: u16,
}

impl Jh7110InterruptStatus {
    /// Returns whether the status contains a DMA event handled by this driver.
    pub const fn has_work(self) -> bool {
        self.dma & (DMA_STATUS_RX | DMA_STATUS_TX | DMA_STATUS_COMMON) != 0
    }

    /// Returns whether a receive or transmit completion was reported.
    pub const fn has_completion(self) -> bool {
        self.dma & (DMA_STATUS_RX_INTERRUPT | DMA_STATUS_TX_INTERRUPT) != 0
    }

    /// Returns whether the DMA channel reported an abnormal condition.
    pub const fn has_abnormal(self) -> bool {
        self.dma & DMA_INT_ABNORMAL != 0
    }
}

/// Minimal live state used to diagnose board-level DMA bring-up.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Jh7110Diagnostics {
    /// Global DMA mode, including descriptor cache enablement.
    pub dma_mode: u32,
    /// Global DMA AXI system-bus configuration.
    pub dma_sys_bus_mode: u32,
    /// Current DMA channel 0 TX control register.
    pub dma_tx_control: u32,
    /// Current DMA channel 0 RX control register.
    pub dma_rx_control: u32,
    /// Current DMA channel 0 status register.
    pub dma_status: u32,
    /// Current TX descriptor pointer reported by DMA.
    pub dma_current_tx_descriptor: u32,
    /// Current RX descriptor pointer reported by DMA.
    pub dma_current_rx_descriptor: u32,
    /// High word of the current TX buffer address reported by DMA.
    pub dma_current_tx_buffer_high: u32,
    /// Low word of the current TX buffer address reported by DMA.
    pub dma_current_tx_buffer_low: u32,
    /// Exclusive TX descriptor tail pointer.
    pub dma_tx_tail: u32,
    /// Exclusive RX descriptor tail pointer.
    pub dma_rx_tail: u32,
    /// MAC operating mode after link-speed adjustment.
    pub mac_config: u32,
    /// Active MAC destination-address filtering policy.
    pub mac_packet_filter: u32,
    /// MAC transmit/receive protocol-engine state.
    pub mac_debug: u32,
    /// Multicast/broadcast receive-queue routing policy.
    pub mac_rx_queue_control1: u32,
    /// Primary MAC address high word, including address enable.
    pub mac_address_high: u32,
    /// Primary MAC address low word.
    pub mac_address_low: u32,
    /// MTL transmit queue 0 operating mode.
    pub mtl_tx_operation_mode: u32,
    /// MTL transmit queue 0 FIFO and read-controller state.
    pub mtl_tx_debug: u32,
    /// Transmit frames counted by MAC, including errored frames.
    pub mmc_tx_frame_count_good_bad: u32,
    /// Successfully transmitted frames counted by MAC.
    pub mmc_tx_frame_count_good: u32,
    /// Transmit FIFO underflow errors counted by MAC.
    pub mmc_tx_underflow_error: u32,
    /// Frames successfully transmitted after a single collision.
    pub mmc_tx_single_collision_good: u32,
    /// Frames successfully transmitted after multiple collisions.
    pub mmc_tx_multi_collision_good: u32,
    /// Frames whose transmission was deferred because the medium was busy.
    pub mmc_tx_deferred: u32,
    /// Late-collision errors counted by MAC.
    pub mmc_tx_late_collision: u32,
    /// Excessive-collision errors counted by MAC.
    pub mmc_tx_excessive_collision: u32,
    /// Carrier-sense errors counted by MAC.
    pub mmc_tx_carrier_error: u32,
    /// Frames dropped after excessive carrier deferral.
    pub mmc_tx_excessive_deferral: u32,
    /// MTL receive queue 0 operating mode.
    pub mtl_rx_operation_mode: u32,
    /// Status word of the descriptor currently expected to receive a frame.
    pub rx_descriptor_status: u32,
    /// Status word of the descriptor currently available for transmission.
    pub tx_descriptor_status: u32,
    /// Length/control word of the descriptor currently available for transmission.
    pub tx_descriptor_control: u32,
    /// Status word of the most recently submitted transmit descriptor.
    pub last_tx_descriptor_status: u32,
    /// Length/control word of the most recently submitted transmit descriptor.
    pub last_tx_descriptor_control: u32,
    /// Software index of the next TX descriptor to fill.
    pub tx_index: usize,
}

impl Default for Jh7110Config {
    fn default() -> Self {
        Self {
            mac_address: None,
            phy_addr: 0,
            mdio_clock_range: 0xf,
            axi: Jh7110AxiConfig::default(),
            force_threshold_dma_mode: false,
            descriptor_cache_enable: true,
            promiscuous_mode: false,
        }
    }
}

struct DmaRegion<H: DmaOps> {
    vaddr: NonNull<u8>,
    paddr: u64,
    _hal: PhantomData<H>,
}

unsafe impl<H: DmaOps> Send for DmaRegion<H> {}
unsafe impl<H: DmaOps> Sync for DmaRegion<H> {}

impl<H: DmaOps> DmaRegion<H> {
    fn allocate() -> DevResult<Self> {
        let (vaddr, paddr) = H::alloc_pages(DMA_REGION_PAGES)?;
        let end = paddr
            .checked_add(DMA_REGION_SIZE as u64)
            .ok_or(DevError::InvalidParam)?;
        if end > DMA_ADDR_LIMIT {
            unsafe { H::dealloc_pages(vaddr, paddr, DMA_REGION_PAGES) };
            return Err(DevError::Unsupported);
        }
        unsafe { core::ptr::write_bytes(vaddr.as_ptr(), 0, DMA_REGION_PAGES * PAGE_SIZE) };
        H::dma_sync(paddr, DMA_REGION_PAGES * PAGE_SIZE);
        Ok(Self {
            vaddr,
            paddr,
            _hal: PhantomData,
        })
    }

    fn vaddr_at(&self, offset: usize) -> *mut u8 {
        debug_assert!(offset < DMA_REGION_SIZE);
        unsafe { self.vaddr.as_ptr().add(offset) }
    }

    const fn paddr_at(&self, offset: usize) -> u64 {
        self.paddr + offset as u64
    }
}

impl<H: DmaOps> Drop for DmaRegion<H> {
    fn drop(&mut self) {
        unsafe { H::dealloc_pages(self.vaddr, self.paddr, DMA_REGION_PAGES) };
    }
}

/// A single-queue JH7110 DWMAC network device.
pub struct Jh7110Dwmac<H: DmaOps> {
    mmio: NonNull<u8>,
    dma: DmaRegion<H>,
    buffer_pool: Arc<NetBufPool>,
    mac_address: [u8; 6],
    phy_addr: u8,
    mdio_clock_range: u8,
    phy_id: u32,
    axi: Jh7110AxiConfig,
    force_threshold_dma_mode: bool,
    descriptor_cache_enable: bool,
    promiscuous_mode: bool,
    rx_index: usize,
    tx_index: usize,
    rx_ready: AtomicBool,
    tx_busy: AtomicBool,
}

unsafe impl<H: DmaOps> Send for Jh7110Dwmac<H> {}
unsafe impl<H: DmaOps> Sync for Jh7110Dwmac<H> {}

impl<H: DmaOps> Jh7110Dwmac<H> {
    /// Creates and starts a JH7110 DWMAC device.
    ///
    /// # Safety
    ///
    /// `mmio_base` must be the mapped base of an enabled DWMAC 5.20 instance,
    /// and no other software may access that instance concurrently.
    pub unsafe fn try_new(mmio_base: usize, config: Jh7110Config) -> DevResult<Self> {
        let mmio = NonNull::new(mmio_base as *mut u8).ok_or(DevError::InvalidParam)?;
        let dma = DmaRegion::<H>::allocate()?;
        let buffer_pool = NetBufPool::new(RX_DESC_COUNT + TX_DESC_COUNT, DMA_BUFFER_SIZE)?;
        let mut this = Self {
            mmio,
            dma,
            buffer_pool,
            mac_address: [0; 6],
            phy_addr: config.phy_addr,
            mdio_clock_range: 0,
            phy_id: 0,
            axi: config.axi,
            force_threshold_dma_mode: config.force_threshold_dma_mode,
            descriptor_cache_enable: config.descriptor_cache_enable,
            promiscuous_mode: config.promiscuous_mode,
            rx_index: 0,
            tx_index: 0,
            rx_ready: AtomicBool::new(false),
            tx_busy: AtomicBool::new(false),
        };

        let controller_mac = this.read_mac_address();
        let firmware_mdio_clock_range =
            ((this.read(GMAC_MDIO_ADDR) >> MDIO_CLOCK_SHIFT) & 0xf) as u8;
        this.mdio_clock_range = if config.mdio_clock_range <= 7 {
            config.mdio_clock_range
        } else {
            firmware_mdio_clock_range.min(7)
        };
        this.mac_address =
            select_mac_address(config.mac_address, controller_mac).ok_or(DevError::BadState)?;
        this.reset()?;
        let _ = this.detect_phy();
        let dma_width = this.dma_address_width();
        let dma_end = this.dma.paddr + DMA_REGION_SIZE as u64;
        if dma_width == 0 || dma_width < 64 && dma_end > (1_u64 << dma_width) {
            return Err(DevError::Unsupported);
        }
        this.initialize_rings();
        this.configure_dma();
        this.configure_mac();
        let _ = this.refresh_link();
        this.start();
        Ok(this)
    }

    fn read(&self, offset: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.mmio.as_ptr().add(offset).cast::<u32>()) }
    }

    fn write(&self, offset: usize, value: u32) {
        unsafe { core::ptr::write_volatile(self.mmio.as_ptr().add(offset).cast::<u32>(), value) };
    }

    fn modify(&self, offset: usize, clear: u32, set: u32) {
        self.write(offset, (self.read(offset) & !clear) | set);
    }

    fn reset(&self) -> DevResult {
        self.modify(DMA_MODE, 0, DMA_MODE_SOFT_RESET);
        for _ in 0..RESET_SPINS {
            if self.read(DMA_MODE) & DMA_MODE_SOFT_RESET == 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err(DevError::Io)
    }

    fn rx_desc_ptr(&self, index: usize) -> *mut DmaDesc {
        self.dma.vaddr_at(RX_RING_OFFSET + index * DESC_SIZE).cast()
    }

    fn tx_desc_ptr(&self, index: usize) -> *mut DmaDesc {
        self.dma.vaddr_at(TX_RING_OFFSET + index * DESC_SIZE).cast()
    }

    const fn rx_desc_paddr(&self, index: usize) -> u64 {
        self.dma.paddr_at(RX_RING_OFFSET + index * DESC_SIZE)
    }

    const fn tx_desc_paddr(&self, index: usize) -> u64 {
        self.dma.paddr_at(TX_RING_OFFSET + index * DESC_SIZE)
    }

    const fn rx_buffer_paddr(&self, index: usize) -> u64 {
        self.dma
            .paddr_at(RX_BUFFER_OFFSET + index * DMA_BUFFER_SIZE)
    }

    const fn tx_buffer_paddr(&self, index: usize) -> u64 {
        self.dma
            .paddr_at(TX_BUFFER_OFFSET + index * DMA_BUFFER_SIZE)
    }

    fn initialize_rings(&self) {
        for index in 0..RX_DESC_COUNT {
            let desc = if index == 0 {
                DmaDesc::rx(self.rx_buffer_paddr(index))
            } else {
                DmaDesc::empty()
            };
            unsafe { desc.write(self.rx_desc_ptr(index)) };
        }
        for index in 0..TX_DESC_COUNT {
            unsafe { DmaDesc::empty().write(self.tx_desc_ptr(index)) };
        }
        fence(Ordering::Release);
        H::dma_sync(self.dma.paddr, RX_BUFFER_OFFSET);
    }

    fn configure_dma(&self) {
        self.modify(
            DMA_MODE,
            DMA_MODE_DESCRIPTOR_CACHE_ENABLE,
            if self.descriptor_cache_enable {
                DMA_MODE_DESCRIPTOR_CACHE_ENABLE
            } else {
                0
            },
        );
        self.write(
            DMA_SYS_BUS_MODE,
            dma_sys_bus_mode(self.dma_address_width() > 32, self.axi),
        );
        self.write(DMA_CH0_CONTROL, 0);
        self.write(DMA_CH0_TX_BASE_HIGH, (self.tx_desc_paddr(0) >> 32) as u32);
        self.write(DMA_CH0_TX_BASE_LOW, self.tx_desc_paddr(0) as u32);
        self.write(DMA_CH0_RX_BASE_HIGH, (self.rx_desc_paddr(0) >> 32) as u32);
        self.write(DMA_CH0_RX_BASE_LOW, self.rx_desc_paddr(0) as u32);
        self.write(DMA_CH0_TX_RING_LEN, (TX_DESC_COUNT - 1) as u32);
        self.write(DMA_CH0_RX_RING_LEN, (RX_DESC_COUNT - 1) as u32);
        self.write(
            DMA_CH0_TX_CONTROL,
            DMA_TX_PBL_16 | DMA_TX_OPERATE_SECOND_PACKET,
        );
        self.write(
            DMA_CH0_RX_CONTROL,
            DMA_RX_PBL_16 | ((DMA_BUFFER_SIZE as u32) << DMA_RX_BUFFER_SIZE_SHIFT),
        );
        self.write(DMA_CH0_INT_ENABLE, 0);
        self.write(DMA_CH0_TX_TAIL, self.tx_desc_paddr(0) as u32);
        self.write(DMA_CH0_RX_TAIL, self.rx_desc_paddr(1) as u32);
    }

    fn configure_mac(&self) {
        for (register, value) in primary_mac_register_writes(self.mac_address) {
            self.write(register, value);
        }
        let mut packet_filter = GMAC_PACKET_FILTER_HASH_OR_PERFECT;
        if self.promiscuous_mode {
            packet_filter |= GMAC_PACKET_FILTER_PROMISCUOUS | GMAC_PACKET_FILTER_PASS_CONTROL;
        }
        self.write(GMAC_PACKET_FILTER, packet_filter);
        self.modify(GMAC_RXQ_CTRL0, 0x3, GMAC_RX_DCB_QUEUE0_ENABLE);
        self.modify(
            GMAC_RXQ_CTRL1,
            GMAC_RX_MCBC_QUEUE_MASK,
            GMAC_RX_MCBC_QUEUE_ENABLE,
        );
        let (tx_clear, tx_set, rx_clear, rx_set) = if self.force_threshold_dma_mode {
            (
                MTL_TX_QUEUE_SIZE_MASK | MTL_TX_STORE_FORWARD | MTL_TX_THRESHOLD_MASK,
                MTL_TXQ_ENABLE | MTL_TX_QUEUE_SIZE_2K | MTL_TX_THRESHOLD_64,
                MTL_RX_QUEUE_SIZE_MASK | MTL_RX_STORE_FORWARD | MTL_RX_THRESHOLD_MASK,
                MTL_RX_QUEUE_SIZE_2K | MTL_RX_DISABLE_TCP_ERROR_FORWARD | MTL_RX_THRESHOLD_64,
            )
        } else {
            (
                MTL_TX_QUEUE_SIZE_MASK | MTL_TX_THRESHOLD_MASK,
                MTL_TX_STORE_FORWARD | MTL_TXQ_ENABLE | MTL_TX_QUEUE_SIZE_2K,
                MTL_RX_QUEUE_SIZE_MASK | MTL_RX_THRESHOLD_MASK,
                MTL_RX_STORE_FORWARD | MTL_RX_QUEUE_SIZE_2K | MTL_RX_DISABLE_TCP_ERROR_FORWARD,
            )
        };
        self.modify(MTL_TXQ0_OPERATION_MODE, tx_clear, tx_set);
        self.modify(MTL_RXQ0_OPERATION_MODE, rx_clear, rx_set);
        self.write(GMAC_INT_ENABLE, 0);
        self.modify(
            GMAC_CONFIG,
            GMAC_CONFIG_PS | GMAC_CONFIG_FES,
            GMAC_CONFIG_DM
                | GMAC_CONFIG_ACS
                | GMAC_CONFIG_IPC
                | GMAC_CONFIG_BE
                | GMAC_CONFIG_JD
                | GMAC_CONFIG_JE
                | GMAC_CONFIG_DCRS,
        );
    }

    fn start(&self) {
        self.modify(DMA_CH0_TX_CONTROL, 0, DMA_TX_START);
        self.modify(DMA_CH0_RX_CONTROL, 0, DMA_RX_START);
        self.modify(GMAC_CONFIG, 0, GMAC_CONFIG_TE | GMAC_CONFIG_RE);
    }

    fn read_mac_address(&self) -> [u8; 6] {
        let low = self.read(GMAC_ADDR_LOW0).to_le_bytes();
        let high = self.read(GMAC_ADDR_HIGH0).to_le_bytes();
        [low[0], low[1], low[2], low[3], high[0], high[1]]
    }

    fn mdio_wait_idle(&self) -> bool {
        for _ in 0..MDIO_SPINS {
            if self.read(GMAC_MDIO_ADDR) & MDIO_BUSY == 0 {
                return true;
            }
            core::hint::spin_loop();
        }
        false
    }

    fn mdio_read(&self, register: u8) -> Option<u16> {
        if !self.mdio_wait_idle() {
            return None;
        }
        let command = ((self.phy_addr as u32) << MDIO_PHY_SHIFT)
            | ((register as u32) << MDIO_REG_SHIFT)
            | ((self.mdio_clock_range as u32) << MDIO_CLOCK_SHIFT)
            | MDIO_READ
            | MDIO_BUSY;
        self.write(GMAC_MDIO_DATA, 0);
        self.write(GMAC_MDIO_ADDR, command);
        self.mdio_wait_idle()
            .then(|| (self.read(GMAC_MDIO_DATA) & 0xffff) as u16)
    }

    fn mdio_write(&self, register: u8, value: u16) -> bool {
        if !self.mdio_wait_idle() {
            return false;
        }
        let command = ((self.phy_addr as u32) << MDIO_PHY_SHIFT)
            | ((register as u32) << MDIO_REG_SHIFT)
            | ((self.mdio_clock_range as u32) << MDIO_CLOCK_SHIFT)
            | MDIO_WRITE
            | MDIO_BUSY;
        self.write(GMAC_MDIO_DATA, value as u32);
        self.write(GMAC_MDIO_ADDR, command);
        self.mdio_wait_idle()
    }

    fn mdio_read_ext(&self, register: u16) -> Option<u16> {
        self.mdio_write(YT8531_EXT_PAGE_SELECT, register)
            .then(|| self.mdio_read(YT8531_EXT_PAGE_DATA))?
    }

    fn detect_phy(&mut self) -> DevResult {
        let preferred = self.mdio_clock_range.min(7);
        for offset in 0..8 {
            let range = (preferred + offset) & 7;
            self.mdio_clock_range = range;
            let Some(id_high) = self.mdio_read(2) else {
                continue;
            };
            let Some(id_low) = self.mdio_read(3) else {
                continue;
            };
            let phy_id = ((id_high as u32) << 16) | id_low as u32;
            if valid_phy_id(phy_id) {
                self.phy_id = phy_id;
                return Ok(());
            }
        }
        self.mdio_clock_range = preferred;
        Err(DevError::Io)
    }

    /// Refreshes the MAC speed and duplex from the YT8531 link status.
    ///
    /// Unavailable, down, or unresolved link state leaves the last valid MAC
    /// configuration intact. The raw PHY status is returned for link-change
    /// diagnostics.
    pub fn refresh_link(&self) -> Option<u16> {
        // YT8531/compatible PHY specific status: link=10, duplex=13,
        // speed=15:14 (0=10M, 1=100M, 2=1000M).
        let status = self.mdio_read(0x11)?;
        if let Some(set) = mac_link_config(status) {
            self.modify(
                GMAC_CONFIG,
                GMAC_CONFIG_DM | GMAC_CONFIG_PS | GMAC_CONFIG_FES,
                set,
            );
        }
        Some(status)
    }

    /// Reads the YT8531-compatible PHY status register for diagnostics.
    pub fn phy_status(&self) -> Option<u16> {
        self.mdio_read(0x11)
    }

    /// Reads Clause 22 PHY control and current status for board diagnostics.
    pub fn phy_basic_status(&self) -> Option<Jh7110PhyBasicStatus> {
        let control = self.mdio_read(PHY_BMCR)?;
        // BMSR link state is latched-low, so discard the first read.
        let _ = self.mdio_read(PHY_BMSR)?;
        let status = self.mdio_read(PHY_BMSR)?;
        Some(Jh7110PhyBasicStatus { control, status })
    }

    /// Reads YT8531 extended RGMII configuration without changing it.
    pub fn phy_extended_status(&self) -> Option<Jh7110PhyExtendedStatus> {
        if self.phy_id & !0xf != YT8531_PHY_ID & !0xf {
            return None;
        }
        Some(Jh7110PhyExtendedStatus {
            chip_config: self.mdio_read_ext(YT8531_EXT_CHIP_CONFIG)?,
            rgmii_config1: self.mdio_read_ext(YT8531_EXT_RGMII_CONFIG1)?,
            pad_drive_strength: self.mdio_read_ext(YT8531_EXT_PAD_DRIVE_STRENGTH)?,
            synce_config: self.mdio_read_ext(YT8531_EXT_SYNCE_CONFIG)?,
        })
    }

    /// Returns the detected Clause 22 PHY identifier.
    pub const fn phy_id(&self) -> u32 {
        self.phy_id
    }

    /// Returns the working CSR clock selector found during PHY probing.
    pub const fn mdio_clock_range(&self) -> u8 {
        self.mdio_clock_range
    }

    /// Acknowledges channel interrupts and returns the raw pre-acknowledgement status.
    pub fn handle_interrupt(&self) -> Jh7110InterruptStatus {
        let status = self.read(DMA_CH0_STATUS);
        let handled = status & (DMA_STATUS_RX | DMA_STATUS_TX | DMA_STATUS_COMMON);
        if status & DMA_STATUS_RX_INTERRUPT != 0 {
            self.rx_ready.store(true, Ordering::Release);
        }
        if status & DMA_STATUS_TX_INTERRUPT != 0 {
            self.tx_busy.store(false, Ordering::Release);
        }
        if handled != 0 {
            self.write(DMA_CH0_STATUS, handled);
        }
        let mac_status = self.read(GMAC_INT_STATUS);
        Jh7110InterruptStatus {
            dma: status,
            mac: mac_status,
        }
    }

    /// Enables completion and error interrupts after the kernel handler exists.
    pub fn enable_interrupts(&self) -> Jh7110InterruptStatus {
        let pending = self.handle_interrupt();
        self.write(DMA_CH0_INT_ENABLE, DMA_INT_NORMAL | DMA_INT_ABNORMAL);
        pending
    }

    /// Masks all channel interrupts.
    pub fn disable_interrupts(&self) {
        self.write(DMA_CH0_INT_ENABLE, 0);
    }

    /// Returns the DMA address width advertised by the controller.
    pub fn dma_address_width(&self) -> u8 {
        match (self.read(GMAC_HW_FEATURE1) & GMAC_HW_ADDR64_MASK) >> 14 {
            0 => 32,
            1 => 40,
            2 => 48,
            _ => 0,
        }
    }

    /// Captures DMA and current descriptor state without changing ownership.
    pub fn diagnostics(&self) -> Jh7110Diagnostics {
        let rx_desc_paddr = self.rx_desc_paddr(self.rx_index);
        let tx_desc_paddr = self.tx_desc_paddr(self.tx_index);
        let last_tx_index = (self.tx_index + TX_DESC_COUNT - 1) % TX_DESC_COUNT;
        let last_tx_desc_paddr = self.tx_desc_paddr(last_tx_index);
        H::dma_sync(rx_desc_paddr, DESC_SIZE);
        H::dma_sync(tx_desc_paddr, DESC_SIZE);
        H::dma_sync(last_tx_desc_paddr, DESC_SIZE);
        fence(Ordering::Acquire);
        let rx_desc = unsafe { DmaDesc::read(self.rx_desc_ptr(self.rx_index)) };
        let tx_desc = unsafe { DmaDesc::read(self.tx_desc_ptr(self.tx_index)) };
        let last_tx_desc = unsafe { DmaDesc::read(self.tx_desc_ptr(last_tx_index)) };
        Jh7110Diagnostics {
            dma_mode: self.read(DMA_MODE),
            dma_sys_bus_mode: self.read(DMA_SYS_BUS_MODE),
            dma_tx_control: self.read(DMA_CH0_TX_CONTROL),
            dma_rx_control: self.read(DMA_CH0_RX_CONTROL),
            dma_status: self.read(DMA_CH0_STATUS),
            dma_current_tx_descriptor: self.read(DMA_CH0_CURRENT_TX_DESC),
            dma_current_rx_descriptor: self.read(DMA_CH0_CURRENT_RX_DESC),
            dma_current_tx_buffer_high: self.read(DMA_CH0_CURRENT_TX_BUFFER_HIGH),
            dma_current_tx_buffer_low: self.read(DMA_CH0_CURRENT_TX_BUFFER_LOW),
            dma_tx_tail: self.read(DMA_CH0_TX_TAIL),
            dma_rx_tail: self.read(DMA_CH0_RX_TAIL),
            mac_config: self.read(GMAC_CONFIG),
            mac_packet_filter: self.read(GMAC_PACKET_FILTER),
            mac_debug: self.read(GMAC_DEBUG),
            mac_rx_queue_control1: self.read(GMAC_RXQ_CTRL1),
            mac_address_high: self.read(GMAC_ADDR_HIGH0),
            mac_address_low: self.read(GMAC_ADDR_LOW0),
            mtl_tx_operation_mode: self.read(MTL_TXQ0_OPERATION_MODE),
            mtl_tx_debug: self.read(MTL_TXQ0_DEBUG),
            mmc_tx_frame_count_good_bad: self.read(MMC_TX_FRAME_COUNT_GOOD_BAD),
            mmc_tx_frame_count_good: self.read(MMC_TX_FRAME_COUNT_GOOD),
            mmc_tx_underflow_error: self.read(MMC_TX_UNDERFLOW_ERROR),
            mmc_tx_single_collision_good: self.read(MMC_TX_SINGLE_COLLISION_GOOD),
            mmc_tx_multi_collision_good: self.read(MMC_TX_MULTI_COLLISION_GOOD),
            mmc_tx_deferred: self.read(MMC_TX_DEFERRED),
            mmc_tx_late_collision: self.read(MMC_TX_LATE_COLLISION),
            mmc_tx_excessive_collision: self.read(MMC_TX_EXCESSIVE_COLLISION),
            mmc_tx_carrier_error: self.read(MMC_TX_CARRIER_ERROR),
            mmc_tx_excessive_deferral: self.read(MMC_TX_EXCESSIVE_DEFERRAL),
            mtl_rx_operation_mode: self.read(MTL_RXQ0_OPERATION_MODE),
            rx_descriptor_status: rx_desc.status_word(),
            tx_descriptor_status: tx_desc.status_word(),
            tx_descriptor_control: tx_desc.control_word(),
            last_tx_descriptor_status: last_tx_desc.status_word(),
            last_tx_descriptor_control: last_tx_desc.control_word(),
            tx_index: self.tx_index,
        }
    }
}

impl<H: DmaOps> BaseDriverOps for Jh7110Dwmac<H> {
    fn device_name(&self) -> &str {
        "starfive-jh7110-dwmac"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Net
    }
}

impl<H: DmaOps> NetDriverOps for Jh7110Dwmac<H> {
    fn mac_address(&self) -> EthernetAddress {
        EthernetAddress(self.mac_address)
    }

    fn can_transmit(&self) -> bool {
        if !self.tx_busy.load(Ordering::Acquire) {
            return true;
        }

        let completed_index = (self.tx_index + TX_DESC_COUNT - 1) % TX_DESC_COUNT;
        H::dma_sync(self.tx_desc_paddr(completed_index), DESC_SIZE);
        fence(Ordering::Acquire);
        let desc = unsafe { DmaDesc::read(self.tx_desc_ptr(completed_index)) };
        if desc.owned_by_dma() {
            false
        } else {
            self.tx_busy.store(false, Ordering::Release);
            true
        }
    }

    fn can_receive(&self) -> bool {
        if self.rx_ready.load(Ordering::Acquire) {
            return true;
        }

        H::dma_sync(self.rx_desc_paddr(self.rx_index), DESC_SIZE);
        fence(Ordering::Acquire);
        let desc = unsafe { DmaDesc::read(self.rx_desc_ptr(self.rx_index)) };
        if desc.owned_by_dma() {
            false
        } else {
            self.rx_ready.store(true, Ordering::Release);
            true
        }
    }

    fn rx_queue_size(&self) -> usize {
        RX_DESC_COUNT
    }

    fn tx_queue_size(&self) -> usize {
        TX_DESC_COUNT
    }

    fn recycle_rx_buffer(&mut self, rx_buf: NetBufPtr) -> DevResult {
        drop(unsafe { NetBuf::from_buf_ptr(rx_buf) });
        Ok(())
    }

    fn recycle_tx_buffers(&mut self) -> DevResult {
        Ok(())
    }

    fn transmit(&mut self, tx_buf: NetBufPtr) -> DevResult {
        let packet_len = tx_buf.packet_len();
        if packet_len == 0 || packet_len > DMA_BUFFER_SIZE {
            drop(unsafe { NetBuf::from_buf_ptr(tx_buf) });
            return Err(DevError::InvalidParam);
        }
        if !self.can_transmit() {
            drop(unsafe { NetBuf::from_buf_ptr(tx_buf) });
            return Err(DevError::Again);
        }

        let index = self.tx_index;
        let buffer_paddr = self.tx_buffer_paddr(index);
        unsafe {
            core::ptr::copy_nonoverlapping(
                tx_buf.packet().as_ptr(),
                self.dma
                    .vaddr_at(TX_BUFFER_OFFSET + index * DMA_BUFFER_SIZE),
                packet_len,
            );
        }
        drop(unsafe { NetBuf::from_buf_ptr(tx_buf) });
        H::dma_sync(buffer_paddr, packet_len);
        unsafe { DmaDesc::tx(buffer_paddr, packet_len).write(self.tx_desc_ptr(index)) };
        fence(Ordering::Release);
        H::dma_sync(self.tx_desc_paddr(index), DESC_SIZE);
        self.tx_busy.store(true, Ordering::Release);

        self.tx_index = (index + 1) % TX_DESC_COUNT;
        self.write(DMA_CH0_TX_TAIL, self.tx_desc_paddr(self.tx_index) as u32);
        Ok(())
    }

    fn receive(&mut self) -> DevResult<NetBufPtr> {
        if !self.can_receive() {
            return Err(DevError::Again);
        }
        let index = self.rx_index;
        let desc_paddr = self.rx_desc_paddr(index);
        H::dma_sync(desc_paddr, DESC_SIZE);
        fence(Ordering::Acquire);
        let desc = unsafe { DmaDesc::read(self.rx_desc_ptr(index)) };
        if desc.owned_by_dma() {
            self.rx_ready.store(false, Ordering::Release);
            return Err(DevError::Again);
        }

        let received_len = desc.received_len().filter(|len| *len <= DMA_BUFFER_SIZE);
        let result = match received_len {
            Some(packet_len) => match self.buffer_pool.alloc_boxed() {
                Some(mut net_buf) => {
                    let buffer_paddr = self.rx_buffer_paddr(index);
                    H::dma_sync(buffer_paddr, packet_len);
                    fence(Ordering::Acquire);
                    net_buf.set_packet_len(packet_len);
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            self.dma
                                .vaddr_at(RX_BUFFER_OFFSET + index * DMA_BUFFER_SIZE),
                            net_buf.packet_mut().as_mut_ptr(),
                            packet_len,
                        );
                    }
                    Ok(net_buf.into_buf_ptr())
                }
                None => Err(DevError::NoMemory),
            },
            None => Err(DevError::Io),
        };

        let next_index = (index + 1) % RX_DESC_COUNT;
        let next_buffer_paddr = self.rx_buffer_paddr(next_index);
        H::dma_sync(next_buffer_paddr, DMA_BUFFER_SIZE);
        unsafe { DmaDesc::rx(next_buffer_paddr).write(self.rx_desc_ptr(next_index)) };
        fence(Ordering::Release);
        H::dma_sync(self.rx_desc_paddr(next_index), DESC_SIZE);
        self.rx_index = next_index;
        self.rx_ready.store(false, Ordering::Release);
        let tail_index = (next_index + 1) % RX_DESC_COUNT;
        self.write(DMA_CH0_RX_TAIL, self.rx_desc_paddr(tail_index) as u32);
        result
    }

    fn alloc_tx_buffer(&mut self, size: usize) -> DevResult<NetBufPtr> {
        if size == 0 || size > DMA_BUFFER_SIZE {
            return Err(DevError::InvalidParam);
        }
        let mut net_buf = self.buffer_pool.alloc_boxed().ok_or(DevError::NoMemory)?;
        net_buf.set_packet_len(size);
        Ok(net_buf.into_buf_ptr())
    }

    fn poll_interval(&self) -> Option<Duration> {
        Some(FALLBACK_POLL_INTERVAL)
    }
}

const fn dma_sys_bus_mode(extended_addressing: bool, axi: Jh7110AxiConfig) -> u32 {
    let write_limit = if axi.write_outstanding_limit > 0xf {
        0xf
    } else {
        axi.write_outstanding_limit
    };
    let read_limit = if axi.read_outstanding_limit > 0xf {
        0xf
    } else {
        axi.read_outstanding_limit
    };
    let mut value = DMA_SYS_BUS_FIXED_BURST
        | (((write_limit as u32) << 24) & DMA_SYS_BUS_AXI_WRITE_LIMIT_MASK)
        | (((read_limit as u32) << 16) & DMA_SYS_BUS_AXI_READ_LIMIT_MASK)
        | ((axi.burst_length_mask as u32) & DMA_SYS_BUS_AXI_BURST_MASK);
    if extended_addressing {
        value |= DMA_SYS_BUS_ENHANCED_ADDR;
    }
    if axi.low_power_idle {
        value |= DMA_SYS_BUS_AXI_LPI_ENABLE;
    }
    if axi.exit_on_frame {
        value |= DMA_SYS_BUS_AXI_EXIT_FRAME;
    }
    value
}

const fn valid_unicast_mac(address: &[u8; 6]) -> bool {
    address[0] & 1 == 0 && !all_equal(address, 0) && !all_equal(address, 0xff)
}

fn select_mac_address(configured: Option<[u8; 6]>, controller: [u8; 6]) -> Option<[u8; 6]> {
    configured
        .filter(valid_unicast_mac)
        .or_else(|| valid_unicast_mac(&controller).then_some(controller))
}

fn primary_mac_register_writes(address: [u8; 6]) -> [(usize, u32); 2] {
    let low = u32::from_le_bytes([address[0], address[1], address[2], address[3]]);
    let high = u16::from_le_bytes([address[4], address[5]]) as u32;
    [
        (GMAC_ADDR_HIGH0, high | GMAC_ADDR_HIGH_ENABLE),
        (GMAC_ADDR_LOW0, low),
    ]
}

const fn valid_phy_id(phy_id: u32) -> bool {
    phy_id & !0xf == YT8531_PHY_ID & !0xf
}

const fn mac_link_config(status: u16) -> Option<u32> {
    if status & ((1 << 11) | (1 << 10)) != (1 << 11) | (1 << 10) {
        return None;
    }
    let mut set = if status & (1 << 13) != 0 {
        GMAC_CONFIG_DM
    } else {
        0
    };
    match (status >> 14) & 0x3 {
        0 => set |= GMAC_CONFIG_PS,
        1 => set |= GMAC_CONFIG_PS | GMAC_CONFIG_FES,
        2 => {}
        _ => return None,
    }
    Some(set)
}

const fn all_equal(address: &[u8; 6], value: u8) -> bool {
    address[0] == value
        && address[1] == value
        && address[2] == value
        && address[3] == value
        && address[4] == value
        && address[5] == value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, align(64))]
    struct TestDmaStorage([u8; DMA_REGION_PAGES * PAGE_SIZE]);

    #[repr(C, align(64))]
    struct TestMmio([u8; 0x2000]);

    struct TestDmaOps;

    unsafe impl DmaOps for TestDmaOps {
        fn alloc_pages(_num_pages: usize) -> DevResult<(NonNull<u8>, u64)> {
            Err(DevError::Unsupported)
        }

        unsafe fn dealloc_pages(_vaddr: NonNull<u8>, _dma_addr: u64, _num_pages: usize) {}

        fn dma_sync(_paddr: u64, _size: usize) {}
    }

    struct TestDevice {
        device: Jh7110Dwmac<TestDmaOps>,
        _mmio: alloc::boxed::Box<TestMmio>,
        _dma: alloc::boxed::Box<TestDmaStorage>,
    }

    fn test_device() -> TestDevice {
        let mut mmio = alloc::boxed::Box::new(TestMmio([0; 0x2000]));
        let mut dma = alloc::boxed::Box::new(TestDmaStorage([0; DMA_REGION_PAGES * PAGE_SIZE]));
        let mmio_ptr = NonNull::new(mmio.0.as_mut_ptr()).unwrap();
        let dma_ptr = NonNull::new(dma.0.as_mut_ptr()).unwrap();
        let device = Jh7110Dwmac {
            mmio: mmio_ptr,
            dma: DmaRegion {
                vaddr: dma_ptr,
                paddr: 0x1000_0000,
                _hal: PhantomData,
            },
            buffer_pool: NetBufPool::new(RX_DESC_COUNT + TX_DESC_COUNT, DMA_BUFFER_SIZE).unwrap(),
            mac_address: [0x02, 1, 2, 3, 4, 5],
            phy_addr: 0,
            mdio_clock_range: 0,
            phy_id: 0,
            axi: Jh7110AxiConfig::default(),
            force_threshold_dma_mode: false,
            descriptor_cache_enable: true,
            promiscuous_mode: false,
            rx_index: 0,
            tx_index: 0,
            rx_ready: AtomicBool::new(false),
            tx_busy: AtomicBool::new(false),
        };
        TestDevice {
            device,
            _mmio: mmio,
            _dma: dma,
        }
    }

    #[test]
    fn interrupt_status_classifies_completions_and_errors() {
        let completion = Jh7110InterruptStatus {
            dma: DMA_STATUS_RX_INTERRUPT | (1 << 15),
            mac: 0,
        };
        assert!(completion.has_work());
        assert!(completion.has_completion());
        assert!(!completion.has_abnormal());

        let abnormal = Jh7110InterruptStatus {
            dma: (1 << 14) | (1 << 7),
            mac: 0,
        };
        assert!(abnormal.has_work());
        assert!(!abnormal.has_completion());
        assert!(abnormal.has_abnormal());
    }

    #[test]
    fn vf2_axi_settings_encode_into_dma_system_bus_mode() {
        let axi = Jh7110AxiConfig {
            write_outstanding_limit: 15,
            read_outstanding_limit: 15,
            burst_length_mask: 0xf0,
            low_power_idle: false,
            exit_on_frame: false,
        };
        assert_eq!(dma_sys_bus_mode(false, axi), 0x0f0f_00f1);
        assert_eq!(dma_sys_bus_mode(true, axi), 0x0f0f_08f1);
    }

    #[test]
    fn dma_configuration_enables_starfive_descriptor_cache() {
        let mut test = test_device();
        test.device.axi = Jh7110AxiConfig {
            write_outstanding_limit: 15,
            read_outstanding_limit: 15,
            burst_length_mask: 0xf0,
            low_power_idle: false,
            exit_on_frame: false,
        };
        test.device.configure_dma();
        assert_eq!(
            test.device.read(DMA_MODE) & DMA_MODE_DESCRIPTOR_CACHE_ENABLE,
            DMA_MODE_DESCRIPTOR_CACHE_ENABLE
        );
        assert_eq!(test.device.read(DMA_SYS_BUS_MODE), 0x0f0f_00f1);
        assert_eq!(
            test.device.read(DMA_CH0_TX_TAIL),
            test.device.tx_desc_paddr(0) as u32
        );

        let diagnostics = test.device.diagnostics();
        assert_eq!(
            diagnostics.dma_mode & DMA_MODE_DESCRIPTOR_CACHE_ENABLE,
            DMA_MODE_DESCRIPTOR_CACHE_ENABLE
        );
        assert_eq!(diagnostics.dma_sys_bus_mode, 0x0f0f_00f1);
        assert_eq!(diagnostics.dma_rx_tail, test.device.rx_desc_paddr(1) as u32);
    }

    #[test]
    fn diagnostics_reads_tx_mmc_error_counters() {
        let test = test_device();
        test.device.write(MMC_TX_UNDERFLOW_ERROR, 1);
        test.device.write(MMC_TX_SINGLE_COLLISION_GOOD, 2);
        test.device.write(MMC_TX_MULTI_COLLISION_GOOD, 3);
        test.device.write(MMC_TX_DEFERRED, 4);
        test.device.write(MMC_TX_LATE_COLLISION, 5);
        test.device.write(MMC_TX_EXCESSIVE_COLLISION, 6);
        test.device.write(MMC_TX_CARRIER_ERROR, 7);
        test.device.write(MMC_TX_EXCESSIVE_DEFERRAL, 8);

        let diagnostics = test.device.diagnostics();
        assert_eq!(diagnostics.mmc_tx_underflow_error, 1);
        assert_eq!(diagnostics.mmc_tx_single_collision_good, 2);
        assert_eq!(diagnostics.mmc_tx_multi_collision_good, 3);
        assert_eq!(diagnostics.mmc_tx_deferred, 4);
        assert_eq!(diagnostics.mmc_tx_late_collision, 5);
        assert_eq!(diagnostics.mmc_tx_excessive_collision, 6);
        assert_eq!(diagnostics.mmc_tx_carrier_error, 7);
        assert_eq!(diagnostics.mmc_tx_excessive_deferral, 8);
    }

    #[test]
    fn mac_configuration_enables_primary_perfect_address_filter() {
        let test = test_device();
        test.device.configure_mac();
        assert_eq!(test.device.read(GMAC_ADDR_LOW0), 0x0302_0102);
        assert_eq!(
            test.device.read(GMAC_ADDR_HIGH0),
            GMAC_ADDR_HIGH_ENABLE | 0x0504
        );
        assert_eq!(
            test.device.read(GMAC_PACKET_FILTER),
            GMAC_PACKET_FILTER_HASH_OR_PERFECT
        );
        let diagnostics = test.device.diagnostics();
        assert_eq!(diagnostics.mac_address_high, GMAC_ADDR_HIGH_ENABLE | 0x0504);
        assert_eq!(diagnostics.mac_address_low, 0x0302_0102);
        assert_eq!(
            diagnostics.mac_config
                & (GMAC_CONFIG_BE | GMAC_CONFIG_JD | GMAC_CONFIG_JE | GMAC_CONFIG_DCRS),
            GMAC_CONFIG_BE | GMAC_CONFIG_JD | GMAC_CONFIG_JE | GMAC_CONFIG_DCRS
        );
        assert_eq!(
            test.device.read(GMAC_RXQ_CTRL1)
                & (GMAC_RX_MCBC_QUEUE_MASK | GMAC_RX_MCBC_QUEUE_ENABLE),
            GMAC_RX_MCBC_QUEUE_ENABLE
        );
    }

    #[test]
    fn primary_mac_address_is_committed_high_word_first() {
        let writes = primary_mac_register_writes([0x02, 1, 2, 3, 4, 5]);

        assert_eq!(
            writes,
            [
                (GMAC_ADDR_HIGH0, GMAC_ADDR_HIGH_ENABLE | 0x0504),
                (GMAC_ADDR_LOW0, 0x0302_0102),
            ]
        );
    }

    #[test]
    fn mac_configuration_can_delegate_destination_filtering_to_stack() {
        let mut test = test_device();
        test.device.promiscuous_mode = true;
        test.device.configure_mac();

        assert_eq!(
            test.device.read(GMAC_PACKET_FILTER),
            GMAC_PACKET_FILTER_HASH_OR_PERFECT
                | GMAC_PACKET_FILTER_PROMISCUOUS
                | GMAC_PACKET_FILTER_PASS_CONTROL
        );
    }

    #[test]
    fn axi_settings_clamp_limits_and_mask_reserved_burst_bits() {
        let axi = Jh7110AxiConfig {
            write_outstanding_limit: u8::MAX,
            read_outstanding_limit: u8::MAX,
            burst_length_mask: u8::MAX,
            low_power_idle: true,
            exit_on_frame: true,
        };
        assert_eq!(dma_sys_bus_mode(false, axi), 0xcf0f_00ff);
    }

    #[test]
    fn dma_layout_is_aligned_and_fits_allocated_pages() {
        assert_eq!(RX_RING_OFFSET % 16, 0);
        assert_eq!(TX_RING_OFFSET % 16, 0);
        assert_ne!(
            RX_RING_OFFSET / CACHE_LINE_SIZE,
            TX_RING_OFFSET / CACHE_LINE_SIZE
        );
        assert_eq!(RX_BUFFER_OFFSET % 64, 0);
        assert_eq!(TX_BUFFER_OFFSET % 64, 0);
        assert!(DMA_REGION_SIZE <= DMA_REGION_PAGES * PAGE_SIZE);
    }

    #[test]
    fn mac_validation_accepts_only_unicast_addresses() {
        assert!(valid_unicast_mac(&[0x02, 1, 2, 3, 4, 5]));
        assert!(!valid_unicast_mac(&[0x01, 1, 2, 3, 4, 5]));
        assert!(!valid_unicast_mac(&[0; 6]));
        assert!(!valid_unicast_mac(&[0xff; 6]));
    }

    #[test]
    fn mac_selection_requires_a_valid_firmware_or_controller_address() {
        let configured = [0x02, 1, 2, 3, 4, 5];
        let controller = [0x02, 6, 7, 8, 9, 10];
        assert_eq!(
            select_mac_address(Some(configured), controller),
            Some(configured)
        );
        assert_eq!(
            select_mac_address(Some([0; 6]), controller),
            Some(controller)
        );
        assert_eq!(select_mac_address(Some([0; 6]), [0xff; 6]), None);
    }

    #[test]
    fn ring_indices_wrap_at_queue_size() {
        assert_eq!((RX_DESC_COUNT - 1 + 1) % RX_DESC_COUNT, 0);
        assert_eq!((TX_DESC_COUNT - 1 + 1) % TX_DESC_COUNT, 0);
    }

    #[test]
    fn polling_detects_rx_writeback_without_interrupt() {
        let test = test_device();
        unsafe { DmaDesc::rx(test.device.rx_buffer_paddr(0)).write(test.device.rx_desc_ptr(0)) };
        assert!(!test.device.can_receive());

        unsafe { DmaDesc::empty().write(test.device.rx_desc_ptr(0)) };
        assert!(test.device.can_receive());
        assert!(test.device.rx_ready.load(Ordering::Acquire));
        assert_eq!(test.device.poll_interval(), Some(FALLBACK_POLL_INTERVAL));
    }

    #[test]
    fn polling_reclaims_tx_without_interrupt() {
        let mut test = test_device();
        unsafe {
            DmaDesc::tx(test.device.tx_buffer_paddr(0), 64).write(test.device.tx_desc_ptr(0))
        };
        test.device.tx_index = 1;
        test.device.tx_busy.store(true, Ordering::Release);
        assert!(!test.device.can_transmit());

        unsafe { DmaDesc::empty().write(test.device.tx_desc_ptr(0)) };
        assert!(test.device.can_transmit());
        assert!(!test.device.tx_busy.load(Ordering::Acquire));
    }

    #[test]
    fn receive_delivers_dma_payload_and_advances_exclusive_tail() {
        let mut test = test_device();
        test.device.initialize_rings();
        let payload = [0xa5; 64];
        unsafe {
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                test.device.dma.vaddr_at(RX_BUFFER_OFFSET),
                payload.len(),
            );
            DmaDesc::rx_writeback(payload.len()).write(test.device.rx_desc_ptr(0));
        }

        let packet = test.device.receive().unwrap();
        assert_eq!(packet.packet(), &payload);
        assert_eq!(test.device.rx_index, 1);
        assert!(!test.device.rx_ready.load(Ordering::Acquire));
        let next_desc = unsafe { DmaDesc::read(test.device.rx_desc_ptr(1)) };
        assert!(next_desc.owned_by_dma());
        assert_eq!(
            test.device.read(DMA_CH0_RX_TAIL),
            test.device.rx_desc_paddr(2) as u32
        );
        test.device.recycle_rx_buffer(packet).unwrap();
    }

    #[test]
    fn transmit_copies_payload_and_advances_exclusive_tail() {
        let mut test = test_device();
        let payload = [0x5a; 64];
        let mut packet = test.device.alloc_tx_buffer(payload.len()).unwrap();
        packet.packet_mut().copy_from_slice(&payload);

        test.device.transmit(packet).unwrap();

        let dma_payload = unsafe {
            core::slice::from_raw_parts(test.device.dma.vaddr_at(TX_BUFFER_OFFSET), payload.len())
        };
        assert_eq!(dma_payload, &payload);
        let desc = unsafe { DmaDesc::read(test.device.tx_desc_ptr(0)) };
        assert!(desc.owned_by_dma());
        assert_eq!(desc.words()[2] & 0x3fff, payload.len() as u32);
        assert_eq!(desc.words()[3] & 0x7fff, payload.len() as u32);
        assert!(test.device.tx_busy.load(Ordering::Acquire));
        assert_eq!(test.device.tx_index, 1);
        assert_eq!(
            test.device.read(DMA_CH0_TX_TAIL),
            test.device.tx_desc_paddr(1) as u32
        );
    }

    #[test]
    fn phy_id_validation_rejects_empty_mdio_reads() {
        assert!(valid_phy_id(YT8531_PHY_ID));
        assert!(!valid_phy_id(0));
        assert!(!valid_phy_id(u32::MAX));
    }

    #[test]
    fn phy_status_maps_resolved_link_to_mac_speed_and_duplex() {
        const LINK_RESOLVED: u16 = (1 << 11) | (1 << 10);
        assert_eq!(mac_link_config(0), None);
        assert_eq!(
            mac_link_config(LINK_RESOLVED | (1 << 13)),
            Some(GMAC_CONFIG_DM | GMAC_CONFIG_PS)
        );
        assert_eq!(
            mac_link_config(LINK_RESOLVED | (1 << 13) | (1 << 14)),
            Some(GMAC_CONFIG_DM | GMAC_CONFIG_PS | GMAC_CONFIG_FES)
        );
        assert_eq!(
            mac_link_config(LINK_RESOLVED | (1 << 13) | (2 << 14)),
            Some(GMAC_CONFIG_DM)
        );
        assert_eq!(mac_link_config(LINK_RESOLVED | (3 << 14)), None);
    }
}
