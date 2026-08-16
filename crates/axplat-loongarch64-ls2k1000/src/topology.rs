use core::sync::atomic::{AtomicUsize, Ordering};

use fdt_raw::{Fdt, Header, Node};

use crate::{
    config::plat::MAX_CPU_NUM,
    cpu_topology::CpuTopology,
    mp_common::{DMW_PHYS_MASK, firmware_to_phys, phys_to_cached_dmw, phys_to_uncached_dmw},
};

const INVALID_ID: usize = usize::MAX;
const MAX_DTB_SIZE: usize = 16 * 1024 * 1024;
const MAX_UBOOT_GO_ARGS: usize = 16;
const MAX_UBOOT_GO_ARG_LEN: usize = 32;
const UHI_FDT_ARG0: usize = usize::MAX - 1;
const LIOINTC_REG_MIN_SIZE: usize = 0x38;
const LIOINTC_ISR_MIN_SIZE: usize = core::mem::size_of::<u32>();
const CPU_HWI_BASE_IRQ: usize = 2;
const LIOINTC_PARENT_COUNT: usize = 4;

static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
static HARDWARE_CPU_IDS: [AtomicUsize; MAX_CPU_NUM] =
    [const { AtomicUsize::new(INVALID_ID) }; MAX_CPU_NUM];
static LIOINTC_PADDR: AtomicUsize = AtomicUsize::new(crate::config::devices::LIOINTC_PADDR);
static LIOINTC_ISR_PADDR: AtomicUsize = AtomicUsize::new(crate::config::devices::LIOINTC_ISR_PADDR);
static LIOINTC_CASCADE_IRQ: AtomicUsize =
    AtomicUsize::new(crate::config::devices::LIOINTC_CASCADE_IRQ);

/// Resolves the physical FDT address from the supported firmware ABI.
///
/// U-Boot `go <entry> <fdt>` enters with `a0=argc`, `a1=argv`; direct firmware
/// handoff may use the UHI sentinel in `a0` and an FDT address in `a1`.
pub(super) fn boot_fdt_paddr(arg0: usize, arg1: usize) -> usize {
    let dtb_paddr = if arg0 == UHI_FDT_ARG0 {
        canonical_phys(arg1).unwrap_or_else(|| panic!("invalid direct FDT argument {arg1:#x}"))
    } else {
        uboot_go_fdt_arg(arg0, arg1).unwrap_or_else(|| {
            panic!("LS2K1000 requires U-Boot go <entry> <fdt> or the UHI FDT ABI")
        })
    };

    dtb_paddr
}

pub(super) fn init_from_dtb(boot_cpu_id: usize, dtb_paddr: usize) -> usize {
    let fdt = fdt_from_phys(dtb_paddr)
        .unwrap_or_else(|| panic!("invalid or unavailable LS2K1000 DTB at {dtb_paddr:#x}"));

    #[cfg(feature = "smp")]
    let topology = parse_cpu_topology(boot_cpu_id, &fdt)
        .unwrap_or_else(|| panic!("LS2K1000 DTB does not list boot CPU {boot_cpu_id}"));
    #[cfg(not(feature = "smp"))]
    let topology = single_cpu_topology(boot_cpu_id);
    let logical_cpu_id = topology
        .logical_cpu_id(boot_cpu_id)
        .expect("validated LS2K1000 topology lost its boot CPU");
    publish_topology(&topology);

    logical_cpu_id
}

pub(super) fn init_platform_from_dtb(dtb_paddr: usize) {
    let fdt = fdt_from_phys(dtb_paddr)
        .unwrap_or_else(|| panic!("invalid or unavailable LS2K1000 DTB at {dtb_paddr:#x}"));

    crate::mem::init_from_fdt(&fdt, dtb_paddr);

    let lio = parse_liointc_topology(&fdt)
        .unwrap_or_else(|| panic!("LS2K1000 DTB has no complete LIOINTC topology"));

    LIOINTC_PADDR.store(lio.reg_paddr, Ordering::Release);
    LIOINTC_ISR_PADDR.store(lio.isr_paddr, Ordering::Release);
    LIOINTC_CASCADE_IRQ.store(lio.cascade_irq, Ordering::Release);
}

pub(super) fn logical_cpu_id(hardware_cpu_id: usize) -> usize {
    try_logical_cpu_id(hardware_cpu_id)
        .unwrap_or_else(|| panic!("CPU {hardware_cpu_id} is absent from the LS2K1000 topology"))
}

pub(super) fn hardware_cpu_id(cpu_id: usize) -> Option<usize> {
    if cpu_id >= cpu_count() {
        return None;
    }
    let hardware_cpu_id = HARDWARE_CPU_IDS[cpu_id].load(Ordering::Acquire);
    (hardware_cpu_id != INVALID_ID).then_some(hardware_cpu_id)
}

pub(super) fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

pub(super) fn liointc_paddr() -> usize {
    LIOINTC_PADDR.load(Ordering::Acquire)
}

pub(super) fn liointc_isr_paddr() -> usize {
    LIOINTC_ISR_PADDR.load(Ordering::Acquire)
}

pub(super) fn liointc_cascade_irq() -> usize {
    LIOINTC_CASCADE_IRQ.load(Ordering::Acquire)
}

pub(super) fn fdt_from_phys(dtb_paddr: usize) -> Option<Fdt<'static>> {
    let dtb_paddr = canonical_phys(dtb_paddr)?;
    let header_end = dtb_paddr.checked_add(core::mem::size_of::<Header>())?;
    if header_end > DMW_PHYS_MASK {
        return None;
    }
    let cached_vaddr = phys_to_cached_dmw(dtb_paddr)?;
    let uncached_vaddr = phys_to_uncached_dmw(dtb_paddr)?;

    // U-Boot keeps the handoff DTB resident until PulseOS has copied its
    // memory contract into static storage. Prefer its normal cached mapping,
    // but accept the uncached alias when firmware left the cached view stale.
    let (dtb_vaddr, header) = match unsafe { Header::from_ptr(cached_vaddr as *mut u8) } {
        Ok(header) => (cached_vaddr, header),
        Err(_) => {
            let header = match unsafe { Header::from_ptr(uncached_vaddr as *mut u8) } {
                Ok(header) => header,
                Err(_) => {
                    return None;
                }
            };

            (uncached_vaddr, header)
        }
    };
    let total_size = header.totalsize as usize;

    let dtb_end = dtb_paddr.checked_add(total_size)?;
    if total_size < core::mem::size_of::<Header>()
        || total_size > MAX_DTB_SIZE
        || dtb_end > DMW_PHYS_MASK
    {
        return None;
    }

    let bytes = unsafe { core::slice::from_raw_parts(dtb_vaddr as *const u8, total_size) };
    match Fdt::from_bytes(bytes) {
        Ok(fdt) => Some(fdt),
        Err(_) => None,
    }
}

fn parse_cpu_topology(boot_cpu_id: usize, fdt: &Fdt<'_>) -> Option<CpuTopology<MAX_CPU_NUM>> {
    let mut topology = CpuTopology::empty();
    for node in fdt.find_children_by_path("/cpus") {
        if !is_available_cpu(&node) {
            continue;
        }
        let Some(hardware_cpu_id) = cpu_hardware_id(&node) else {
            continue;
        };
        if hardware_cpu_id == boot_cpu_id {
            if !topology.add_hardware_id(hardware_cpu_id) {
                return None;
            }
            break;
        }
    }
    if topology.logical_cpu_id(boot_cpu_id).is_none() {
        return None;
    }

    for node in fdt.find_children_by_path("/cpus") {
        if !is_available_cpu(&node) {
            continue;
        }
        let Some(hardware_cpu_id) = cpu_hardware_id(&node) else {
            continue;
        };
        if hardware_cpu_id != boot_cpu_id
            && !topology.add_hardware_id(hardware_cpu_id)
            && topology.cpu_count() == MAX_CPU_NUM
        {
            break;
        }
    }
    Some(topology)
}

#[cfg(not(feature = "smp"))]
fn single_cpu_topology(boot_cpu_id: usize) -> CpuTopology<MAX_CPU_NUM> {
    let mut topology = CpuTopology::empty();
    assert!(
        topology.add_hardware_id(boot_cpu_id),
        "LS2K1000 CPU topology must have room for the boot CPU"
    );
    topology
}

fn parse_liointc_topology(fdt: &Fdt<'_>) -> Option<LioIntcTopology> {
    let node = fdt.all_nodes().find(|node| {
        is_available(node)
            && node.compatibles().any(|compatible| {
                matches!(
                    compatible,
                    "loongson,2k1000-icu" | "loongson,ls2k1000-icu" | "loongson,liointc"
                )
            })
    })?;
    let mut regs = node.reg()?;
    let reg = regs.next()?;
    let isr = regs.next()?;
    let reg_paddr = firmware_to_phys(usize::try_from(reg.address).ok()?)?;
    let reg_size = usize::try_from(reg.size?).ok()?;
    let isr_paddr = firmware_to_phys(usize::try_from(isr.address).ok()?)?;
    let isr_size = usize::try_from(isr.size?).ok()?;
    let cascade_irq = node
        .find_property("interrupts")?
        .as_u32_iter()
        .next()
        .map(usize::try_from)
        .transpose()
        .ok()??;

    if reg_size < LIOINTC_REG_MIN_SIZE
        || isr_size < LIOINTC_ISR_MIN_SIZE
        || parent_index_from_cpu_irq(cascade_irq).is_none()
    {
        return None;
    }
    Some(LioIntcTopology {
        reg_paddr,
        isr_paddr,
        cascade_irq,
    })
}

fn is_available(node: &Node<'_>) -> bool {
    matches!(
        node.find_property_str("status"),
        None | Some("okay") | Some("ok")
    )
}

fn is_available_cpu(node: &Node<'_>) -> bool {
    node.name().starts_with("cpu@")
        && matches!(node.find_property_str("device_type"), None | Some("cpu"))
        && is_available(node)
}

fn cpu_hardware_id(node: &Node<'_>) -> Option<usize> {
    node.reg()
        .and_then(|mut regs| regs.next())
        .and_then(|reg| usize::try_from(reg.address).ok())
}

fn publish_topology(topology: &CpuTopology<MAX_CPU_NUM>) {
    for cpu_id in 0..topology.cpu_count() {
        HARDWARE_CPU_IDS[cpu_id].store(
            topology
                .hardware_id(cpu_id)
                .expect("published logical CPU must have a hardware CPU ID"),
            Ordering::Relaxed,
        );
    }
    CPU_COUNT.store(topology.cpu_count(), Ordering::Release);
}

fn try_logical_cpu_id(hardware_cpu_id: usize) -> Option<usize> {
    (0..cpu_count())
        .find(|cpu_id| HARDWARE_CPU_IDS[*cpu_id].load(Ordering::Acquire) == hardware_cpu_id)
}

fn canonical_phys(address: usize) -> Option<usize> {
    let phys = firmware_to_phys(address)?;
    (phys != 0).then_some(phys)
}

fn uboot_go_fdt_arg(argc: usize, argv: usize) -> Option<usize> {
    if !(1..=MAX_UBOOT_GO_ARGS).contains(&argc) || argv == 0 {
        return None;
    }
    let argv_paddr = canonical_phys(argv)?;
    let argv_vaddr = phys_to_cached_dmw(argv_paddr)?;

    let argv = argv_vaddr as *const usize;
    let entry = unsafe { argv.read() };

    parse_uboot_go_addr_arg(entry)?;

    for index in 1..argc {
        let arg = unsafe { argv.add(index).read() };

        if let Some(address) = parse_uboot_go_addr_arg(arg) {
            return canonical_phys(address);
        }
    }
    None
}

fn parse_uboot_go_addr_arg(arg: usize) -> Option<usize> {
    if arg == 0 {
        return None;
    }
    let ptr = phys_to_cached_dmw(canonical_phys(arg)?)? as *const u8;
    let mut index = 0;
    if unsafe { ptr.read() } == b'0' && matches!(unsafe { ptr.add(1).read() }, b'x' | b'X') {
        index = 2;
    }

    let mut value = 0usize;
    let mut has_digit = false;
    while index < MAX_UBOOT_GO_ARG_LEN {
        let byte = unsafe { ptr.add(index).read() };
        if byte == 0 {
            return has_digit.then_some(value);
        }
        let digit = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return None,
        } as usize;
        value = value.checked_mul(16)?.checked_add(digit)?;
        has_digit = true;
        index += 1;
    }
    None
}

const fn parent_index_from_cpu_irq(irq: usize) -> Option<usize> {
    match irq.checked_sub(CPU_HWI_BASE_IRQ) {
        Some(index) if index < LIOINTC_PARENT_COUNT => Some(index),
        _ => None,
    }
}

struct LioIntcTopology {
    reg_paddr: usize,
    isr_paddr: usize,
    cascade_irq: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_cached_uboot_addresses() {
        assert_eq!(canonical_phys(0x9000_0000_0a00_0000), Some(0x0a00_0000));
        assert_eq!(canonical_phys(0x0a00_0000), Some(0x0a00_0000));
    }

    #[test]
    fn preserves_the_reference_liointc_parent_line() {
        assert_eq!(parent_index_from_cpu_irq(3), Some(1));
        assert_eq!(parent_index_from_cpu_irq(2), Some(0));
        assert_eq!(parent_index_from_cpu_irq(6), None);
    }
}
