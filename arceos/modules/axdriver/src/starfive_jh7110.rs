use alloc::sync::{Arc, Weak};
use core::{
    ptr::NonNull,
    sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering, fence},
    time::Duration,
};

use axalloc::global_allocator;
use axdriver_base::{BaseDriverOps, DevError, DevResult, DeviceType};
use axdriver_net::{
    EthernetAddress, NetBufPtr, NetDriverOps,
    starfive_jh7110::{
        DmaOps, Jh7110AxiConfig, Jh7110Config, Jh7110Dwmac, Jh7110InterruptEndpoint,
        Jh7110InterruptStatus,
    },
};
use axhal::mem::{PAGE_SIZE_4K, flush_dcache_range, phys_to_virt, virt_to_phys};
use axpoll::PollSet;
use fdt_raw::{Fdt, Node};
use kspin::{SpinNoIrq, SpinNoPreempt};

const GMAC0_PADDR: usize = 0x1603_0000;
const GMAC_MIN_SIZE: usize = 0x2000;
const SYS_CRG_PADDR: usize = 0x1302_0000;
const SYS_CRG_SIZE: usize = 0x1_0000;
const AON_CRG_PADDR: usize = 0x1700_0000;
const AON_CRG_SIZE: usize = 0x1_0000;
const AON_SYSCON_PADDR: usize = 0x1701_0000;
const AON_SYSCON_SIZE: usize = 0x1000;
const AON_SYSCON_GMAC0_OFFSET: usize = 0xc;
const AON_SYSCON_GMAC0_SHIFT: u32 = 18;
const CRG_CLK_ENABLE: u32 = 1 << 31;
const SYS_CRG_GMAC0_GTXCLK: usize = 0x1b0;
const SYS_CRG_GMAC0_PTP: usize = 0x1b4;
const SYS_CRG_GMAC0_GTXC: usize = 0x1bc;
const AON_CRG_GMAC0_AHB_CLK: usize = 0x8;
const AON_CRG_GMAC0_AXI_CLK: usize = 0xc;
const AON_CRG_RESET_ASSERT: usize = 0x38;
const AON_CRG_RESET_STATUS: usize = 0x3c;
const AON_CRG_GMAC0_AXI_RESET: u32 = 1 << 0;
const AON_CRG_GMAC0_AHB_RESET: u32 = 1 << 1;
const AON_CRG_GMAC0_RESET_MASK: u32 = AON_CRG_GMAC0_AXI_RESET | AON_CRG_GMAC0_AHB_RESET;
const AON_CRG_RESET_POLL_LIMIT: usize = 100_000;
const AON_CRG_RESET_SETTLE: Duration = Duration::from_micros(10);
const PHY_INTERFACE_MASK: u32 = 0x7;
const PHY_POLL_INTERVAL_NANOS: u64 = 1_000_000_000;
const PHY_STATUS_UNAVAILABLE: u32 = u32::MAX;
// VisionFive2's U-Boot EQoS driver also enables PR. The JH7110 exact-address
// filter drops ordinary unicast on the tested board, while smoltcp filters
// foreign destination MAC addresses before ARP/IP processing.
const SOFTWARE_DESTINATION_FILTERING: bool = true;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhyModeStatus {
    register_paddr: usize,
    old_value: u32,
    new_value: u32,
    select: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AonResourceStatus {
    clock_ahb: u32,
    clock_axi: u32,
    reset_status_before: u32,
    reset_status_asserted: u32,
    reset_status_after: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SysGmacClockStatus {
    gtxclk_before: u32,
    gtxclk_after: u32,
    ptp_before: u32,
    ptp_after: u32,
    gtxc_before: u32,
    gtxc_after: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MmioRange {
    base: usize,
    size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PhySysconConfig {
    range: MmioRange,
    offset: usize,
    shift: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DtbResource<T> {
    Missing,
    Invalid,
    Valid(T),
}

pub(crate) struct Jh7110Dma;

unsafe impl DmaOps for Jh7110Dma {
    fn alloc_pages(num_pages: usize) -> DevResult<(NonNull<u8>, u64)> {
        let vaddr = global_allocator()
            .alloc_pages(num_pages, PAGE_SIZE_4K)
            .map_err(|_| DevError::NoMemory)?;
        let ptr = NonNull::new(vaddr as *mut u8).ok_or(DevError::NoMemory)?;
        Ok((ptr, virt_to_phys(vaddr.into()).as_usize() as u64))
    }

    unsafe fn dealloc_pages(vaddr: NonNull<u8>, _dma_addr: u64, num_pages: usize) {
        global_allocator().dealloc_pages(vaddr.as_ptr() as usize, num_pages);
    }

    fn dma_sync(paddr: u64, size: usize) {
        if let Ok(paddr) = usize::try_from(paddr) {
            flush_dcache_range(paddr.into(), size);
        }
    }
}

type Dwmac = Jh7110Dwmac<Jh7110Dma>;

struct Jh7110DwmacInner {
    device: SpinNoPreempt<Dwmac>,
    irq_endpoint: Jh7110InterruptEndpoint,
    poll_set: PollSet,
    pending_irq_dma: AtomicU32,
    pending_irq_mac: AtomicU32,
    completion_logged: AtomicBool,
    abnormal_logged: AtomicBool,
    rx_packet_logged: AtomicBool,
    tx_submission_logged: AtomicBool,
    last_phy_status: AtomicU32,
    next_phy_poll_ns: AtomicU64,
}

struct IrqRegistration {
    irq: usize,
}

impl Drop for IrqRegistration {
    fn drop(&mut self) {
        axhal::irq::set_enable(self.irq, false);
        let _ = axhal::irq::unregister(self.irq);
        let mut slot = JH7110_DWMAC_IRQ.lock();
        if slot.as_ref().is_some_and(|(irq, _)| *irq == self.irq) {
            *slot = None;
        }
    }
}

static JH7110_DWMAC_IRQ: SpinNoIrq<Option<(usize, Weak<Jh7110DwmacInner>)>> = SpinNoIrq::new(None);

/// Network device wrapper that connects DWMAC completions to `axpoll`.
pub(crate) struct Jh7110DwmacDevice {
    inner: Arc<Jh7110DwmacInner>,
    _irq_registration: IrqRegistration,
}

impl Drop for Jh7110DwmacDevice {
    fn drop(&mut self) {
        self.inner.device.lock().disable_interrupts();
    }
}

pub(crate) fn probe() -> Option<Jh7110DwmacDevice> {
    let Some(fdt) = boot_fdt() else {
        warn!("JH7110 DWMAC: boot argument does not contain a valid DTB");
        return None;
    };
    let node = fdt.all_nodes().find(is_gmac0_node)?;
    let reg = node.reg()?.next()?;
    let paddr = usize::try_from(reg.address).ok()?;
    let size = usize::try_from(reg.size?).ok()?;
    if paddr != GMAC0_PADDR || size < GMAC_MIN_SIZE {
        warn!("JH7110 DWMAC: unexpected GMAC0 register range {paddr:#x}+{size:#x}");
        return None;
    }
    let fixed_resource_fallback = fixed_resource_fallback_allowed(&node, paddr, size);
    let irq = node.find_property("interrupts")?.as_u32_iter().next()? as usize;
    let mac_address = parse_mac_address(&node);
    let phy_addr = parse_phy_address(&fdt, &node).unwrap_or_else(|| {
        warn!("JH7110 DWMAC: DTB lacks a usable phy-handle; using GMAC0 PHY address 0");
        0
    });
    let axi = parse_axi_config(&fdt, &node);
    let force_threshold_dma_mode = node.find_property("snps,force_thresh_dma_mode").is_some();
    let sys_gmac_clock_status = configure_starfive_sys_gmac_clocks(&fdt, fixed_resource_fallback);
    let phy_mode_status = configure_starfive_phy_mode(&fdt, &node, fixed_resource_fallback);
    let aon_resource_status = configure_starfive_gmac_resources(&fdt, fixed_resource_fallback);
    let mmio_base = phys_to_virt(paddr.into()).as_usize();
    let config = Jh7110Config {
        mac_address,
        phy_addr,
        mdio_clock_range: 0xf,
        axi,
        force_threshold_dma_mode,
        descriptor_cache_enable: true,
        promiscuous_mode: SOFTWARE_DESTINATION_FILTERING,
    };
    let device = unsafe { Dwmac::try_new(mmio_base, config) }
        .inspect_err(|err| error!("JH7110 DWMAC: initialization failed: {err:?}"))
        .ok()?;
    let dma_width = device.dma_address_width();
    let phy_id = device.phy_id();
    let mdio_clock_range = device.mdio_clock_range();
    let phy_basic_status = device.phy_basic_status();
    let phy_status = device.phy_status();
    let phy_extended_status = device.phy_extended_status();
    let next_phy_poll_ns =
        axhal::time::monotonic_time_nanos().saturating_add(PHY_POLL_INTERVAL_NANOS);
    let irq_endpoint = device.irq_endpoint();
    let inner = Arc::new(Jh7110DwmacInner {
        device: SpinNoPreempt::new(device),
        irq_endpoint,
        poll_set: PollSet::new(),
        pending_irq_dma: AtomicU32::new(0),
        pending_irq_mac: AtomicU32::new(0),
        completion_logged: AtomicBool::new(false),
        abnormal_logged: AtomicBool::new(false),
        rx_packet_logged: AtomicBool::new(false),
        tx_submission_logged: AtomicBool::new(false),
        last_phy_status: AtomicU32::new(
            phy_status.map(u32::from).unwrap_or(PHY_STATUS_UNAVAILABLE),
        ),
        next_phy_poll_ns: AtomicU64::new(next_phy_poll_ns),
    });
    register_irq(irq, &inner)
        .inspect_err(|err| error!("JH7110 DWMAC: IRQ {irq} registration failed: {err:?}"))
        .ok()?;
    let device = inner.device.lock();
    let pending = device.enable_interrupts();
    record_dma_status(&inner, &device, pending, "initial");
    drop(device);
    if pending.has_work() {
        inner.poll_set.wake();
    }
    let device = inner.device.lock();
    let mac = device.mac_address().0;
    let diagnostics = device.diagnostics();
    drop(device);
    info!(
        "JH7110 DWMAC: GMAC0 at {paddr:#x}, IRQ {irq}, PHY {phy_addr}, DMA {dma_width}-bit, MAC \
         {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    info!(
        "JH7110 DWMAC: AXI WR {}, RD {}, BLEN {:#04x}, LPI {}, threshold DMA {}, descriptor cache \
         enabled",
        axi.write_outstanding_limit,
        axi.read_outstanding_limit,
        axi.burst_length_mask,
        axi.low_power_idle,
        force_threshold_dma_mode
    );
    if let Some(status) = phy_mode_status {
        info!(
            "JH7110 DWMAC: syscon {:#x} PHY select {}, {:#010x} -> {:#010x}",
            status.register_paddr, status.select, status.old_value, status.new_value
        );
    } else {
        warn!("JH7110 DWMAC: unable to apply starfive,syscon PHY interface mode");
    }
    match aon_resource_status {
        Some(status) => info!(
            "JH7110 DWMAC: AON CRG clocks AHB/AXI {:#010x}/{:#010x}, reset status {:#010x} -> \
             pulse {:#010x} -> release {:#010x}",
            status.clock_ahb,
            status.clock_axi,
            status.reset_status_before,
            status.reset_status_asserted,
            status.reset_status_after
        ),
        None => warn!("JH7110 DWMAC: AON CRG resources were not re-enabled"),
    }
    match sys_gmac_clock_status {
        Some(status) => info!(
            "JH7110 DWMAC: SYS CRG GMAC0 GTXCLK/PTP/GTXC {:#010x}/{:#010x}/{:#010x} -> \
             {:#010x}/{:#010x}/{:#010x}",
            status.gtxclk_before,
            status.ptp_before,
            status.gtxc_before,
            status.gtxclk_after,
            status.ptp_after,
            status.gtxc_after
        ),
        None => warn!("JH7110 DWMAC: SYS CRG GMAC0 GTX/PTP clocks were not re-enabled"),
    }
    if phy_id != 0 {
        info!("JH7110 DWMAC: PHY ID {phy_id:#010x}, MDIO CR {mdio_clock_range}");
    } else {
        warn!("JH7110 DWMAC: PHY ID unavailable, reusing firmware MDIO CR {mdio_clock_range}");
    }
    match phy_basic_status {
        Some(status) => info!(
            "JH7110 DWMAC: PHY BMCR/BMSR {:#06x}/{:#06x}",
            status.control, status.status
        ),
        None => warn!("JH7110 DWMAC: PHY BMCR/BMSR read timed out"),
    }
    match phy_status {
        Some(status) => info!("JH7110 DWMAC: PHY status {status:#06x}"),
        None => warn!("JH7110 DWMAC: PHY status read timed out"),
    }
    if let Some(status) = phy_extended_status {
        info!(
            "JH7110 DWMAC: PHY ext A001/A003/A010/A012 {:#06x}/{:#06x}/{:#06x}/{:#06x}",
            status.chip_config,
            status.rgmii_config1,
            status.pad_drive_strength,
            status.synce_config
        );
    } else {
        warn!("JH7110 DWMAC: YT8531 extended PHY status unavailable");
    }
    info!(
        "JH7110 DWMAC: initial DMA status {:#010x}, RX desc3 {:#010x}, TX desc3 {:#010x}",
        diagnostics.dma_status, diagnostics.rx_descriptor_status, diagnostics.tx_descriptor_status
    );
    debug!(
        "JH7110 DWMAC: DMA mode {:#010x}, sysbus {:#010x}, TX ctl {:#010x}, RX ctl {:#010x}",
        diagnostics.dma_mode,
        diagnostics.dma_sys_bus_mode,
        diagnostics.dma_tx_control,
        diagnostics.dma_rx_control
    );
    debug!(
        "JH7110 DWMAC: current TX/RX desc {:#010x}/{:#010x}, tail {:#010x}/{:#010x}",
        diagnostics.dma_current_tx_descriptor,
        diagnostics.dma_current_rx_descriptor,
        diagnostics.dma_tx_tail,
        diagnostics.dma_rx_tail
    );
    debug!(
        "JH7110 DWMAC: MAC cfg/filter/rxq1 {:#010x}/{:#010x}/{:#010x}, addr hi/lo \
         {:#010x}/{:#010x}, MTL TX/RX {:#010x}/{:#010x}",
        diagnostics.mac_config,
        diagnostics.mac_packet_filter,
        diagnostics.mac_rx_queue_control1,
        diagnostics.mac_address_high,
        diagnostics.mac_address_low,
        diagnostics.mtl_tx_operation_mode,
        diagnostics.mtl_rx_operation_mode
    );
    Some(Jh7110DwmacDevice {
        inner,
        _irq_registration: IrqRegistration { irq },
    })
}

fn boot_fdt() -> Option<Fdt<'static>> {
    let dtb_paddr = axhal::get_bootarg();
    if dtb_paddr == 0 {
        return None;
    }
    let dtb_vaddr = phys_to_virt(dtb_paddr.into()).as_mut_ptr();
    unsafe { Fdt::from_ptr(dtb_vaddr).ok() }
}

fn is_gmac0_node(node: &Node<'_>) -> bool {
    status_enabled(node.find_property_str("status"))
        && node.compatibles().any(is_jh7110_gmac_compatible)
        && node
            .reg()
            .and_then(|mut reg| reg.next())
            .is_some_and(|reg| reg.address == GMAC0_PADDR as u64)
}

fn is_jh7110_gmac_compatible(compatible: &str) -> bool {
    matches!(
        compatible,
        "starfive,jh7110-dwmac" | "starfive,jh7110-eqos-5.20"
    )
}

fn status_enabled(status: Option<&str>) -> bool {
    matches!(status, None | Some("okay") | Some("ok"))
}

fn fixed_resource_fallback_allowed(node: &Node<'_>, paddr: usize, size: usize) -> bool {
    is_gmac0_node(node) && gmac0_range_allows_fixed_resources(paddr, size)
}

const fn gmac0_range_allows_fixed_resources(paddr: usize, size: usize) -> bool {
    paddr == GMAC0_PADDR && size >= GMAC_MIN_SIZE
}

fn resolve_dtb_resource<T>(
    resource: DtbResource<T>,
    fixed_resource_fallback: bool,
    fallback: T,
) -> Option<(T, bool)> {
    match resource {
        DtbResource::Valid(value) => Some((value, false)),
        DtbResource::Missing if fixed_resource_fallback => Some((fallback, true)),
        DtbResource::Missing | DtbResource::Invalid => None,
    }
}

fn parse_mac_address(node: &Node<'_>) -> Option<[u8; 6]> {
    ["local-mac-address", "mac-address"]
        .into_iter()
        .find_map(|name| {
            let property = node.find_property(name)?;
            let bytes = property.as_slice();
            (bytes.len() == 6).then(|| bytes.try_into().ok()).flatten()
        })
}

fn parse_phy_address(fdt: &Fdt<'_>, gmac: &Node<'_>) -> Option<u8> {
    let phandle = gmac.find_property("phy-handle")?.as_u32()?;
    fdt.all_nodes()
        .find(|node| node_has_phandle(node, phandle))?
        .reg()?
        .next()
        .and_then(|reg| u8::try_from(reg.address).ok())
}

fn parse_axi_config(fdt: &Fdt<'_>, gmac: &Node<'_>) -> Jh7110AxiConfig {
    let mut config = Jh7110AxiConfig::default();
    let Some(phandle) = gmac
        .find_property("snps,axi-config")
        .and_then(|property| property.as_u32())
    else {
        return config;
    };
    let Some(node) = fdt.all_nodes().find(|node| node_has_phandle(node, phandle)) else {
        return config;
    };

    config.write_outstanding_limit = node
        .find_property("snps,wr_osr_lmt")
        .and_then(|property| property.as_u32())
        .unwrap_or(1)
        .min(0xf) as u8;
    config.read_outstanding_limit = node
        .find_property("snps,rd_osr_lmt")
        .and_then(|property| property.as_u32())
        .unwrap_or(1)
        .min(0xf) as u8;
    if let Some(property) = node.find_property("snps,blen") {
        config.burst_length_mask = axi_burst_mask(property.as_u32_iter());
    }
    config.low_power_idle = node.find_property("snps,lpi_en").is_some();
    config.exit_on_frame = node.find_property("snps,xit_frm").is_some();
    config
}

fn node_has_phandle(node: &Node<'_>, phandle: u32) -> bool {
    ["phandle", "linux,phandle"].into_iter().any(|name| {
        node.find_property(name)
            .and_then(|property| property.as_u32())
            == Some(phandle)
    })
}

fn parse_mmio_range(node: &Node<'_>) -> Option<MmioRange> {
    let reg = node.reg()?.next()?;
    Some(MmioRange {
        base: usize::try_from(reg.address).ok()?,
        size: usize::try_from(reg.size?).ok()?,
    })
}

fn axi_burst_mask(lengths: impl IntoIterator<Item = u32>) -> u8 {
    lengths.into_iter().fold(0, |mask, length| {
        mask | match length {
            4 => 1 << 1,
            8 => 1 << 2,
            16 => 1 << 3,
            32 => 1 << 4,
            64 => 1 << 5,
            128 => 1 << 6,
            256 => 1 << 7,
            _ => 0,
        }
    })
}

fn configure_starfive_gmac_resources(
    fdt: &Fdt<'_>,
    fixed_resource_fallback: bool,
) -> Option<AonResourceStatus> {
    let aoncrg = fdt.all_nodes().find(|node| {
        node.compatibles()
            .any(|compatible| compatible == "starfive,jh7110-aoncrg")
    });
    let resource = match aoncrg {
        Some(node) => parse_mmio_range(&node)
            .map(DtbResource::Valid)
            .unwrap_or(DtbResource::Invalid),
        None => DtbResource::Missing,
    };
    let (range, used_fallback) = resolve_dtb_resource(
        resource,
        fixed_resource_fallback,
        MmioRange {
            base: AON_CRG_PADDR,
            size: AON_CRG_SIZE,
        },
    )?;
    if used_fallback {
        warn!(
            "JH7110 DWMAC: DTB lacks starfive,jh7110-aoncrg; using verified GMAC0 fallback at \
             {AON_CRG_PADDR:#x}"
        );
    }
    let MmioRange { base, size } = range;
    if base != AON_CRG_PADDR || size < AON_CRG_SIZE {
        warn!("JH7110 DWMAC: unexpected AON CRG range {base:#x}+{size:#x}");
        return None;
    }

    let mmio_base = phys_to_virt(base.into()).as_mut_ptr();
    let (clock_ahb, clock_axi, reset_status_before, reset_status_asserted) = unsafe {
        let ahb = mmio_base.add(AON_CRG_GMAC0_AHB_CLK).cast::<u32>();
        let axi = mmio_base.add(AON_CRG_GMAC0_AXI_CLK).cast::<u32>();
        let reset = mmio_base.add(AON_CRG_RESET_ASSERT).cast::<u32>();
        let status = mmio_base.add(AON_CRG_RESET_STATUS).cast::<u32>();
        let clock_ahb = core::ptr::read_volatile(ahb) | CRG_CLK_ENABLE;
        let clock_axi = core::ptr::read_volatile(axi) | CRG_CLK_ENABLE;
        core::ptr::write_volatile(ahb, clock_ahb);
        core::ptr::write_volatile(axi, clock_axi);
        let reset_status_before = core::ptr::read_volatile(status);
        let reset_control = core::ptr::read_volatile(reset);
        core::ptr::write_volatile(reset, reset_control | AON_CRG_GMAC0_AXI_RESET);
        let reset_status_asserted = core::ptr::read_volatile(status);
        (
            clock_ahb,
            clock_axi,
            reset_status_before,
            reset_status_asserted,
        )
    };
    fence(Ordering::SeqCst);

    // Match stmmac: pulse AXI reset, then release both GMAC resets after all
    // clocks and the PHY interface mux have been configured.
    unsafe {
        let reset = mmio_base.add(AON_CRG_RESET_ASSERT).cast::<u32>();
        let reset_control = core::ptr::read_volatile(reset);
        core::ptr::write_volatile(reset, reset_control & !AON_CRG_GMAC0_RESET_MASK);
    }
    fence(Ordering::SeqCst);
    axhal::time::busy_wait(AON_CRG_RESET_SETTLE);

    let status_ptr = unsafe { mmio_base.add(AON_CRG_RESET_STATUS).cast::<u32>() };
    let mut reset_status_after = unsafe { core::ptr::read_volatile(status_ptr) };
    for _ in 0..AON_CRG_RESET_POLL_LIMIT {
        if aon_gmac_reset_deasserted(reset_status_after) {
            return Some(AonResourceStatus {
                clock_ahb,
                clock_axi,
                reset_status_before,
                reset_status_asserted,
                reset_status_after,
            });
        }
        core::hint::spin_loop();
        reset_status_after = unsafe { core::ptr::read_volatile(status_ptr) };
    }
    warn!("JH7110 DWMAC: AON CRG reset release timed out (status {reset_status_after:#010x})");
    None
}

const fn aon_gmac_reset_deasserted(status: u32) -> bool {
    status & AON_CRG_GMAC0_RESET_MASK == AON_CRG_GMAC0_RESET_MASK
}

fn configure_starfive_sys_gmac_clocks(
    fdt: &Fdt<'_>,
    fixed_resource_fallback: bool,
) -> Option<SysGmacClockStatus> {
    let syscrg = fdt.all_nodes().find(|node| {
        node.compatibles()
            .any(|compatible| compatible == "starfive,jh7110-syscrg")
    });
    let resource = match syscrg {
        Some(node) => parse_mmio_range(&node)
            .map(DtbResource::Valid)
            .unwrap_or(DtbResource::Invalid),
        None => DtbResource::Missing,
    };
    let (range, used_fallback) = resolve_dtb_resource(
        resource,
        fixed_resource_fallback,
        MmioRange {
            base: SYS_CRG_PADDR,
            size: SYS_CRG_SIZE,
        },
    )?;
    if used_fallback {
        warn!(
            "JH7110 DWMAC: DTB lacks starfive,jh7110-syscrg; using verified GMAC0 fallback at \
             {SYS_CRG_PADDR:#x}"
        );
    }
    let MmioRange { base, size } = range;
    if base != SYS_CRG_PADDR || size < SYS_CRG_SIZE {
        warn!("JH7110 DWMAC: unexpected SYS CRG range {base:#x}+{size:#x}");
        return None;
    }

    let mmio_base = phys_to_virt(base.into()).as_mut_ptr();
    let (gtxclk_before, gtxclk_after, ptp_before, ptp_after, gtxc_before, gtxc_after) = unsafe {
        let gtxclk = mmio_base.add(SYS_CRG_GMAC0_GTXCLK).cast::<u32>();
        let ptp = mmio_base.add(SYS_CRG_GMAC0_PTP).cast::<u32>();
        let gtxc = mmio_base.add(SYS_CRG_GMAC0_GTXC).cast::<u32>();
        let gtxclk_before = core::ptr::read_volatile(gtxclk);
        let ptp_before = core::ptr::read_volatile(ptp);
        let gtxc_before = core::ptr::read_volatile(gtxc);
        let gtxclk_after = enable_crg_clock(gtxclk_before);
        let ptp_after = enable_crg_clock(ptp_before);
        let gtxc_after = enable_crg_clock(gtxc_before);
        core::ptr::write_volatile(gtxclk, gtxclk_after);
        core::ptr::write_volatile(ptp, ptp_after);
        core::ptr::write_volatile(gtxc, gtxc_after);
        (
            gtxclk_before,
            gtxclk_after,
            ptp_before,
            ptp_after,
            gtxc_before,
            gtxc_after,
        )
    };
    fence(Ordering::SeqCst);
    Some(SysGmacClockStatus {
        gtxclk_before,
        gtxclk_after,
        ptp_before,
        ptp_after,
        gtxc_before,
        gtxc_after,
    })
}

const fn enable_crg_clock(value: u32) -> u32 {
    value | CRG_CLK_ENABLE
}

fn parse_starfive_phy_syscon(fdt: &Fdt<'_>, gmac: &Node<'_>) -> Option<PhySysconConfig> {
    let mut syscon_args = gmac.find_property("starfive,syscon")?.as_u32_iter();
    let phandle = syscon_args.next()?;
    let offset = usize::try_from(syscon_args.next()?).ok()?;
    let shift = syscon_args.next()?;
    let syscon = fdt
        .all_nodes()
        .find(|node| node_has_phandle(node, phandle))?;
    if !syscon
        .compatibles()
        .any(|compatible| compatible == "starfive,jh7110-aon-syscon")
    {
        return None;
    }
    Some(PhySysconConfig {
        range: parse_mmio_range(&syscon)?,
        offset,
        shift,
    })
}

fn configure_starfive_phy_mode(
    fdt: &Fdt<'_>,
    gmac: &Node<'_>,
    fixed_resource_fallback: bool,
) -> Option<PhyModeStatus> {
    let select = phy_interface_select(gmac.find_property_str("phy-mode")?)?;
    let resource = if gmac.find_property("starfive,syscon").is_some() {
        parse_starfive_phy_syscon(fdt, gmac)
            .map(DtbResource::Valid)
            .unwrap_or(DtbResource::Invalid)
    } else {
        DtbResource::Missing
    };
    let (config, used_fallback) = resolve_dtb_resource(
        resource,
        fixed_resource_fallback,
        PhySysconConfig {
            range: MmioRange {
                base: AON_SYSCON_PADDR,
                size: AON_SYSCON_SIZE,
            },
            offset: AON_SYSCON_GMAC0_OFFSET,
            shift: AON_SYSCON_GMAC0_SHIFT,
        },
    )?;
    if used_fallback {
        warn!(
            "JH7110 DWMAC: DTB lacks starfive,syscon; using verified GMAC0 fallback register \
             {:#x}, shift {}",
            AON_SYSCON_PADDR + AON_SYSCON_GMAC0_OFFSET,
            AON_SYSCON_GMAC0_SHIFT
        );
    }
    let PhySysconConfig {
        range: MmioRange { base, size },
        offset,
        shift,
    } = config;
    if shift > 29 {
        return None;
    }
    if base != AON_SYSCON_PADDR
        || size < AON_SYSCON_SIZE
        || offset.checked_add(core::mem::size_of::<u32>())? > size
    {
        return None;
    }

    let register_paddr = base.checked_add(offset)?;
    let register = phys_to_virt(register_paddr.into())
        .as_mut_ptr()
        .cast::<u32>();
    let old_value = unsafe { core::ptr::read_volatile(register) };
    let new_value = update_phy_interface(old_value, shift, select);
    unsafe { core::ptr::write_volatile(register, new_value) };
    Some(PhyModeStatus {
        register_paddr,
        old_value,
        new_value,
        select,
    })
}

fn phy_interface_select(mode: &str) -> Option<u32> {
    match mode {
        "rgmii" | "rgmii-id" | "rgmii-rxid" | "rgmii-txid" => Some(1),
        "rmii" => Some(4),
        _ => None,
    }
}

const fn update_phy_interface(value: u32, shift: u32, select: u32) -> u32 {
    let mask = PHY_INTERFACE_MASK << shift;
    (value & !mask) | ((select & PHY_INTERFACE_MASK) << shift)
}

fn register_irq(irq: usize, device: &Arc<Jh7110DwmacInner>) -> DevResult {
    if irq == 0 {
        return Err(DevError::BadState);
    }
    let mut slot = JH7110_DWMAC_IRQ.lock();
    if slot.is_some() {
        return Err(DevError::AlreadyExists);
    }
    *slot = Some((irq, Arc::downgrade(device)));
    if !axhal::irq::register(irq, dwmac_irq_handler) {
        *slot = None;
        return Err(DevError::AlreadyExists);
    }
    drop(slot);
    axhal::irq::set_enable(irq, true);
    Ok(())
}

fn record_dma_status(
    inner: &Jh7110DwmacInner,
    device: &Dwmac,
    status: Jh7110InterruptStatus,
    source: &str,
) {
    if status.has_completion() && !inner.completion_logged.swap(true, Ordering::Relaxed) {
        info!(
            "JH7110 DWMAC: first completion via {}: DMA {:#010x}, MAC {:#010x}",
            source, status.dma, status.mac
        );
    }
    if status.has_abnormal() && !inner.abnormal_logged.swap(true, Ordering::Relaxed) {
        let diagnostics = device.diagnostics();
        warn!(
            "JH7110 DWMAC: first abnormal status via {}: DMA {:#010x}, MAC {:#010x}, RX desc3 \
             {:#010x}, TX desc3 {:#010x}",
            source,
            status.dma,
            status.mac,
            diagnostics.rx_descriptor_status,
            diagnostics.last_tx_descriptor_status
        );
    }
}

fn defer_irq_status(inner: &Jh7110DwmacInner, status: Jh7110InterruptStatus) {
    inner
        .pending_irq_dma
        .fetch_or(status.dma, Ordering::Release);
    inner
        .pending_irq_mac
        .fetch_or(status.mac, Ordering::Release);
}

fn take_deferred_irq_status(
    inner: &Jh7110DwmacInner,
    current: Jh7110InterruptStatus,
) -> Jh7110InterruptStatus {
    Jh7110InterruptStatus {
        dma: current.dma | inner.pending_irq_dma.swap(0, Ordering::AcqRel),
        mac: current.mac | inner.pending_irq_mac.swap(0, Ordering::AcqRel),
    }
}

fn phy_link_speed_duplex(status: u16) -> Option<(u16, bool)> {
    if status & ((1 << 11) | (1 << 10)) != (1 << 11) | (1 << 10) {
        return None;
    }
    let speed = match (status >> 14) & 0x3 {
        0 => 10,
        1 => 100,
        2 => 1000,
        _ => return None,
    };
    Some((speed, status & (1 << 13) != 0))
}

fn refresh_phy_link(inner: &Jh7110DwmacInner, device: &Dwmac) {
    let now = axhal::time::monotonic_time_nanos();
    let deadline = inner.next_phy_poll_ns.load(Ordering::Relaxed);
    if now < deadline
        || inner
            .next_phy_poll_ns
            .compare_exchange(
                deadline,
                now.saturating_add(PHY_POLL_INTERVAL_NANOS),
                Ordering::Relaxed,
                Ordering::Relaxed,
            )
            .is_err()
    {
        return;
    }

    let status = device.refresh_link();
    let current = status.map(u32::from).unwrap_or(PHY_STATUS_UNAVAILABLE);
    let previous = inner.last_phy_status.swap(current, Ordering::Relaxed);
    if current == previous {
        return;
    }

    match status {
        Some(status) => {
            if let Some((speed, full_duplex)) = phy_link_speed_duplex(status) {
                let duplex = if full_duplex { "full" } else { "half" };
                info!(
                    "JH7110 DWMAC: PHY status changed {:#06x} -> {:#06x}, link {} Mbps {} duplex",
                    previous, status, speed, duplex
                );
                return;
            }
            info!(
                "JH7110 DWMAC: PHY status changed {:#06x} -> {:#06x}, link down, unresolved, or \
                 unsupported speed; preserving last MAC mode",
                previous, status
            );
        }
        None => warn!(
            "JH7110 DWMAC: PHY status changed from {:#06x} to unavailable; preserving last MAC \
             mode",
            previous
        ),
    }
}

fn dwmac_irq_handler(irq: usize) {
    let device = JH7110_DWMAC_IRQ
        .lock()
        .as_ref()
        .filter(|(registered_irq, _)| *registered_irq == irq)
        .map(|(_, device)| device.clone())
        .and_then(|device| device.upgrade());
    if let Some(device) = device {
        let status = device.irq_endpoint.handle_interrupt();
        defer_irq_status(&device, status);
        if status.has_work() {
            device.poll_set.wake();
        }
    }
}

impl BaseDriverOps for Jh7110DwmacDevice {
    fn device_name(&self) -> &str {
        "starfive-jh7110-dwmac"
    }

    fn device_type(&self) -> DeviceType {
        DeviceType::Net
    }
}

impl NetDriverOps for Jh7110DwmacDevice {
    fn mac_address(&self) -> EthernetAddress {
        self.inner.device.lock().mac_address()
    }

    fn can_transmit(&self) -> bool {
        let device = self.inner.device.lock();
        let status = take_deferred_irq_status(&self.inner, device.handle_interrupt());
        record_dma_status(&self.inner, &device, status, "poll");
        let ready = device.can_transmit();
        drop(device);
        if status.has_work() {
            self.inner.poll_set.wake();
        }
        ready
    }

    fn can_receive(&self) -> bool {
        let device = self.inner.device.lock();
        let status = take_deferred_irq_status(&self.inner, device.handle_interrupt());
        record_dma_status(&self.inner, &device, status, "poll");
        let ready = device.can_receive();
        drop(device);
        if status.has_work() {
            self.inner.poll_set.wake();
        }
        ready
    }

    fn rx_queue_size(&self) -> usize {
        self.inner.device.lock().rx_queue_size()
    }

    fn tx_queue_size(&self) -> usize {
        self.inner.device.lock().tx_queue_size()
    }

    fn recycle_rx_buffer(&mut self, rx_buf: NetBufPtr) -> DevResult {
        self.inner.device.lock().recycle_rx_buffer(rx_buf)
    }

    fn recycle_tx_buffers(&mut self) -> DevResult {
        self.inner.device.lock().recycle_tx_buffers()
    }

    fn transmit(&mut self, tx_buf: NetBufPtr) -> DevResult {
        let packet_len = tx_buf.packet_len();
        let mut device = self.inner.device.lock();
        let result = device.transmit(tx_buf);
        if result.is_ok()
            && !self
                .inner
                .tx_submission_logged
                .swap(true, Ordering::Relaxed)
        {
            let diagnostics = device.diagnostics();
            info!("JH7110 DWMAC: first TX submitted: {packet_len} bytes");
            info!(
                "JH7110 DWMAC: TX submit DMA {:#010x}, desc3 {:#010x}",
                diagnostics.dma_status, diagnostics.last_tx_descriptor_status
            );
            info!(
                "JH7110 DWMAC: TX submit current {:#010x}, tail {:#010x}",
                diagnostics.dma_current_tx_descriptor, diagnostics.dma_tx_tail
            );
            info!(
                "JH7110 DWMAC: TX submit MMC frames all/good {}/{}",
                diagnostics.mmc_tx_frame_count_good_bad, diagnostics.mmc_tx_frame_count_good
            );
            info!(
                "JH7110 DWMAC: TX submit MMC errors underflow/carrier {}/{}",
                diagnostics.mmc_tx_underflow_error, diagnostics.mmc_tx_carrier_error
            );
        }
        result
    }

    fn receive(&mut self) -> DevResult<NetBufPtr> {
        let mut device = self.inner.device.lock();
        let result = device.receive();
        if let Ok(buffer) = result.as_ref() {
            if !self.inner.rx_packet_logged.swap(true, Ordering::Relaxed) {
                let diagnostics = device.diagnostics();
                info!(
                    "JH7110 DWMAC: first RX delivered: {} bytes, status {:#010x}, current/tail \
                     {:#010x}/{:#010x}, next desc3 {:#010x}",
                    buffer.packet_len(),
                    diagnostics.dma_status,
                    diagnostics.dma_current_rx_descriptor,
                    diagnostics.dma_rx_tail,
                    diagnostics.rx_descriptor_status
                );
            }
        }
        result
    }

    fn alloc_tx_buffer(&mut self, size: usize) -> DevResult<NetBufPtr> {
        self.inner.device.lock().alloc_tx_buffer(size)
    }

    fn poll_device(&self) {
        let device = self.inner.device.lock();
        refresh_phy_link(&self.inner, &device);
        let status = take_deferred_irq_status(&self.inner, device.handle_interrupt());
        record_dma_status(&self.inner, &device, status, "maintenance");
        drop(device);
        if status.has_work() {
            self.inner.poll_set.wake();
        }
    }

    fn poll_set(&self) -> Option<&PollSet> {
        Some(&self.inner.poll_set)
    }

    fn poll_interval(&self) -> Option<core::time::Duration> {
        self.inner.device.lock().poll_interval()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_status_is_rejected() {
        assert!(status_enabled(None));
        assert!(status_enabled(Some("okay")));
        assert!(!status_enabled(Some("disabled")));
    }

    #[test]
    fn mainline_and_vendor_uboot_compatibles_are_accepted() {
        assert!(is_jh7110_gmac_compatible("starfive,jh7110-dwmac"));
        assert!(is_jh7110_gmac_compatible("starfive,jh7110-eqos-5.20"));
        assert!(!is_jh7110_gmac_compatible("snps,dwmac-5.20"));
    }

    #[test]
    fn gmac0_range_is_large_enough_for_dma_channel_registers() {
        assert!(GMAC_MIN_SIZE > 0x1160);
    }

    #[test]
    fn fixed_resource_constants_match_visionfive2_gmac0() {
        assert_eq!(AON_CRG_PADDR, 0x1700_0000);
        assert_eq!(SYS_CRG_PADDR, 0x1302_0000);
        assert_eq!(SYS_CRG_GMAC0_GTXCLK, 108 * core::mem::size_of::<u32>());
        assert_eq!(SYS_CRG_GMAC0_PTP, 109 * core::mem::size_of::<u32>());
        assert_eq!(SYS_CRG_GMAC0_GTXC, 111 * core::mem::size_of::<u32>());
        assert_eq!(enable_crg_clock(0x0123_4567), 0x8123_4567);
        assert_eq!(AON_SYSCON_PADDR + AON_SYSCON_GMAC0_OFFSET, 0x1701_000c);
        assert_eq!(AON_SYSCON_GMAC0_SHIFT, 18);
        assert_eq!(
            AON_CRG_GMAC0_RESET_MASK,
            AON_CRG_GMAC0_AXI_RESET | AON_CRG_GMAC0_AHB_RESET
        );
        assert!(gmac0_range_allows_fixed_resources(
            GMAC0_PADDR,
            GMAC_MIN_SIZE
        ));
        assert!(!gmac0_range_allows_fixed_resources(
            GMAC0_PADDR + 0x1_0000,
            GMAC_MIN_SIZE
        ));
        assert!(!gmac0_range_allows_fixed_resources(
            GMAC0_PADDR,
            GMAC_MIN_SIZE - 1
        ));
        assert!(aon_gmac_reset_deasserted(0x1f));
        assert!(!aon_gmac_reset_deasserted(0));
        assert!(!aon_gmac_reset_deasserted(0x1));
    }

    #[test]
    fn invalid_dtb_resources_do_not_use_fixed_fallback() {
        assert_eq!(
            resolve_dtb_resource(DtbResource::Missing, true, 7),
            Some((7, true))
        );
        assert_eq!(
            resolve_dtb_resource(DtbResource::Valid(3), true, 7),
            Some((3, false))
        );
        assert_eq!(resolve_dtb_resource(DtbResource::Invalid, true, 7), None);
        assert_eq!(resolve_dtb_resource(DtbResource::Missing, false, 7), None);
    }

    #[test]
    fn axi_burst_lengths_use_the_dwmac_register_bit_map() {
        assert_eq!(axi_burst_mask([256, 128, 64, 32, 0, 0, 0]), 0xf0);
        assert_eq!(axi_burst_mask([4, 8, 16, 3, 512]), 0x0e);
    }

    #[test]
    fn starfive_phy_interface_modes_match_linux_encoding() {
        assert_eq!(phy_interface_select("rgmii-id"), Some(1));
        assert_eq!(phy_interface_select("rmii"), Some(4));
        assert_eq!(phy_interface_select("sgmii"), None);
        assert_eq!(update_phy_interface(u32::MAX, 18, 1), 0xffe7_ffff);
    }

    #[test]
    fn phy_status_requires_resolved_link_and_maps_speed_and_duplex() {
        assert_eq!(phy_link_speed_duplex(0), None);
        assert_eq!(
            phy_link_speed_duplex((1 << 11) | (1 << 10) | (2 << 14) | (1 << 13)),
            Some((1000, true))
        );
        assert_eq!(
            phy_link_speed_duplex((1 << 11) | (1 << 10) | (1 << 14)),
            Some((100, false))
        );
        assert_eq!(
            phy_link_speed_duplex((1 << 11) | (1 << 10) | (3 << 14)),
            None
        );
    }
}
