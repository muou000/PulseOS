use core::sync::atomic::{AtomicUsize, Ordering};

use fdt_raw::{Fdt, Header, Node};

use crate::{
    config::plat::{MAX_CPU_NUM, PHYS_MEMORY_BASE, PHYS_MEMORY_SIZE},
    cpu_topology::CpuTopology,
};

const INVALID_ID: usize = usize::MAX;
const MAX_DTB_SIZE: usize = 16 * 1024 * 1024;
const VF2_PLIC_BASE: usize = 0x0c00_0000;
const VF2_PLIC_SIZE: usize = 0x0400_0000;
const VF2_PLIC_NDEV: usize = 136;
const MAX_SUPPORTED_PLIC_NDEV: usize = 1023;
const SUPERVISOR_EXTERNAL_INTERRUPT: u32 = 9;
const VF2_FIRST_U74_HART_ID: usize = 1;
const VF2_LAST_U74_HART_ID: usize = 4;

static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
static HART_IDS: [AtomicUsize; MAX_CPU_NUM] = [const { AtomicUsize::new(INVALID_ID) }; MAX_CPU_NUM];
static PLIC_CONTEXTS: [AtomicUsize; MAX_CPU_NUM] =
    [const { AtomicUsize::new(INVALID_ID) }; MAX_CPU_NUM];
static PLIC_BASE: AtomicUsize = AtomicUsize::new(VF2_PLIC_BASE);
static PLIC_SIZE: AtomicUsize = AtomicUsize::new(VF2_PLIC_SIZE);
static PLIC_NDEV: AtomicUsize = AtomicUsize::new(VF2_PLIC_NDEV);

pub(super) fn init_from_dtb(boot_hart_id: usize, dtb_paddr: usize) -> usize {
    #[cfg(feature = "smp")]
    let topology = parse_cpu_topology(boot_hart_id, dtb_paddr)
        .unwrap_or_else(|| panic!("VisionFive 2 requires a DTB that lists the boot U74 hart"));
    #[cfg(not(feature = "smp"))]
    let topology = single_cpu_topology(boot_hart_id);

    publish_topology(&topology);
    0
}

pub(super) fn init_platform_from_dtb(dtb_paddr: usize) {
    let fdt = fdt_from_phys(dtb_paddr)
        .unwrap_or_else(|| panic!("invalid or unavailable VisionFive 2 DTB at {dtb_paddr:#x}"));

    #[cfg(feature = "smp")]
    {
        let boot_hart_id = hart_id(0)
            .unwrap_or_else(|| panic!("VisionFive 2 boot hart topology was not initialized"));
        let topology = parse_cpu_topology_from_fdt(boot_hart_id, &fdt)
            .unwrap_or_else(|| panic!("VisionFive 2 runtime DTB has no boot U74 hart"));
        publish_topology(&topology);
    }

    crate::mem::init_from_fdt(&fdt, dtb_paddr);
    let plic_ok = parse_plic_topology(&fdt);
    assert!(
        plic_ok,
        "VisionFive 2 DTB has no complete S-mode PLIC topology"
    );
}

pub(super) fn logical_cpu_id(hart_id: usize) -> usize {
    try_logical_cpu_id(hart_id)
        .unwrap_or_else(|| panic!("hart {hart_id} is absent from the CPU topology"))
}

pub(super) fn hart_id(cpu_id: usize) -> Option<usize> {
    load_cpu_value(&HART_IDS, cpu_id)
}

pub(super) fn plic_context(cpu_id: usize) -> Option<usize> {
    load_cpu_value(&PLIC_CONTEXTS, cpu_id)
}

pub(super) fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

pub(super) fn plic_base() -> usize {
    PLIC_BASE.load(Ordering::Acquire)
}

pub(super) fn plic_size() -> usize {
    PLIC_SIZE.load(Ordering::Acquire)
}

pub(super) fn plic_ndev() -> usize {
    PLIC_NDEV.load(Ordering::Acquire)
}

pub(super) fn fdt_from_phys(dtb_paddr: usize) -> Option<Fdt<'static>> {
    let memory_end = PHYS_MEMORY_BASE.checked_add(PHYS_MEMORY_SIZE)?;
    let header_end = dtb_paddr.checked_add(core::mem::size_of::<Header>())?;
    if dtb_paddr < PHYS_MEMORY_BASE || header_end > memory_end {
        return None;
    }

    // SAFETY: the header lies in the identity-mapped firmware RAM window, and
    // U-Boot/OpenSBI keeps the DTB resident while the kernel starts.
    let header = unsafe { Header::from_ptr(dtb_paddr as *mut u8).ok()? };
    let total_size = header.totalsize as usize;
    let dtb_end = dtb_paddr.checked_add(total_size)?;
    if total_size < core::mem::size_of::<Header>()
        || total_size > MAX_DTB_SIZE
        || dtb_end > memory_end
    {
        return None;
    }

    // SAFETY: both ends were checked against the identity-mapped RAM window.
    let bytes = unsafe { core::slice::from_raw_parts(dtb_paddr as *const u8, total_size) };
    Fdt::from_bytes(bytes).ok()
}

#[cfg(feature = "smp")]
fn parse_cpu_topology(boot_hart_id: usize, dtb_paddr: usize) -> Option<CpuTopology<MAX_CPU_NUM>> {
    let fdt = fdt_from_phys(dtb_paddr)?;
    parse_cpu_topology_from_fdt(boot_hart_id, &fdt)
}

#[cfg(feature = "smp")]
fn parse_cpu_topology_from_fdt(
    boot_hart_id: usize,
    fdt: &Fdt<'_>,
) -> Option<CpuTopology<MAX_CPU_NUM>> {
    let mut topology = CpuTopology::empty();
    let mut boot_hart_found = false;

    for node in fdt.find_children_by_path("/cpus") {
        if application_hart_id(&node) != Some(boot_hart_id) {
            continue;
        }
        boot_hart_found = topology.add_hart(boot_hart_id);
        break;
    }
    if !boot_hart_found {
        return None;
    }

    for node in fdt.find_children_by_path("/cpus") {
        let Some(hart_id) = application_hart_id(&node) else {
            continue;
        };
        if hart_id != boot_hart_id
            && !topology.add_hart(hart_id)
            && topology.cpu_count() == MAX_CPU_NUM
        {
            break;
        }
    }
    Some(topology)
}

fn parse_plic_topology(fdt: &Fdt<'_>) -> bool {
    let Some(plic) = fdt.all_nodes().find(|node| {
        is_available(node)
            && node.compatibles().any(|value| {
                value == "riscv,plic0"
                    || value == "sifive,plic-1.0.0"
                    || value == "starfive,jh7110-plic"
            })
    }) else {
        return false;
    };
    let Some(reg) = plic.reg().and_then(|mut values| values.next()) else {
        return false;
    };
    let Ok(base) = usize::try_from(reg.address) else {
        return false;
    };
    let Some(size) = reg.size.and_then(|size| usize::try_from(size).ok()) else {
        return false;
    };
    let Some(ndev) = plic
        .find_property("riscv,ndev")
        .and_then(|property| property.as_u32())
        .map(|value| value as usize)
        .filter(|value| *value > 0)
    else {
        return false;
    };

    let mut interrupt_phandles = [INVALID_ID; MAX_CPU_NUM];
    for node in fdt.find_children_by_path("/cpus") {
        let Some(hart_id) = cpu_hart_id(&node) else {
            continue;
        };
        let Some(cpu_id) = try_logical_cpu_id(hart_id) else {
            continue;
        };
        let path = node.path();
        let Some(controller) = fdt.find_children_by_path(path.as_str()).find(|child| {
            child.find_property("interrupt-controller").is_some()
                || child.compatibles().any(|value| value == "riscv,cpu-intc")
        }) else {
            continue;
        };
        interrupt_phandles[cpu_id] = controller
            .find_property("phandle")
            .or_else(|| controller.find_property("linux,phandle"))
            .and_then(|property| property.as_u32())
            .map(|value| value as usize)
            .unwrap_or(INVALID_ID);
    }

    let Some(interrupts) = plic.find_property("interrupts-extended") else {
        return false;
    };
    let mut contexts = [INVALID_ID; MAX_CPU_NUM];
    let mut cells = interrupts.as_u32_iter();
    let mut context_id = 0usize;
    while let Some(phandle) = cells.next() {
        let Some(cause) = cells.next() else {
            return false;
        };
        if cause == SUPERVISOR_EXTERNAL_INTERRUPT {
            for cpu_id in 0..cpu_count() {
                if interrupt_phandles[cpu_id] == phandle as usize {
                    contexts[cpu_id] = context_id;
                    break;
                }
            }
        }
        context_id += 1;
    }

    let contexts = &mut contexts[..cpu_count()];
    if contexts.iter().any(|context| *context == INVALID_ID)
        && base == VF2_PLIC_BASE
        && ndev == VF2_PLIC_NDEV
    {
        fill_missing_jh7110_contexts(contexts);
    }
    if contexts.iter().any(|context| *context == INVALID_ID) {
        return false;
    }
    if !plic_mmio_fits(size, ndev, contexts) {
        return false;
    }

    PLIC_BASE.store(base, Ordering::Release);
    PLIC_SIZE.store(size, Ordering::Release);
    PLIC_NDEV.store(ndev.min(MAX_SUPPORTED_PLIC_NDEV), Ordering::Release);
    for (cpu_id, context) in contexts.iter().copied().enumerate() {
        PLIC_CONTEXTS[cpu_id].store(context, Ordering::Release);
    }
    true
}

fn fill_missing_jh7110_contexts(contexts: &mut [usize]) {
    for (cpu_id, context) in contexts.iter_mut().enumerate() {
        if *context == INVALID_ID {
            *context = hart_id(cpu_id)
                .and_then(jh7110_supervisor_context)
                .unwrap_or(INVALID_ID);
        }
    }
}

// JH7110 context 0 belongs to the S7 M-mode hart. Each U74 then contributes
// an M-mode context followed by its S-mode context: hart 1..=4 maps to 2/4/6/8.
const fn jh7110_supervisor_context(hart_id: usize) -> Option<usize> {
    if hart_id >= 1 && hart_id <= 4 {
        hart_id.checked_mul(2)
    } else {
        None
    }
}

fn plic_mmio_fits(size: usize, ndev: usize, contexts: &[usize]) -> bool {
    let priority_end = ndev
        .checked_add(1)
        .and_then(|sources| sources.checked_mul(4));
    let enable_end = contexts
        .iter()
        .max()
        .and_then(|context| context.checked_mul(0x80))
        .and_then(|offset| offset.checked_add(0x2000 + (ndev / 32 + 1) * 4));
    let context_end = contexts
        .iter()
        .max()
        .and_then(|context| context.checked_mul(0x1000))
        .and_then(|offset| offset.checked_add(0x20_0008));
    priority_end.is_some_and(|end| end <= size)
        && enable_end.is_some_and(|end| end <= size)
        && context_end.is_some_and(|end| end <= size)
}

fn is_available_cpu(node: &Node<'_>) -> bool {
    node.name().starts_with("cpu@")
        && matches!(node.find_property_str("device_type"), None | Some("cpu"))
        && is_available(node)
}

fn application_hart_id(node: &Node<'_>) -> Option<usize> {
    is_available_cpu(node)
        .then(|| cpu_hart_id(node))
        .flatten()
        .filter(|hart_id| is_jh7110_u74_hart(*hart_id))
}

const fn is_jh7110_u74_hart(hart_id: usize) -> bool {
    // The U-Boot control DTB marks the management S7 at hart 0 as available,
    // even though it is not one of the four U74 application harts. Do not rely
    // on the DT status property alone when constructing the OS CPU topology.
    hart_id >= VF2_FIRST_U74_HART_ID && hart_id <= VF2_LAST_U74_HART_ID
}

pub(super) fn is_available(node: &Node<'_>) -> bool {
    matches!(
        node.find_property_str("status"),
        None | Some("okay") | Some("ok")
    )
}

fn cpu_hart_id(node: &Node<'_>) -> Option<usize> {
    node.reg()
        .and_then(|mut regs| regs.next())
        .and_then(|reg| usize::try_from(reg.address).ok())
}

#[cfg(not(feature = "smp"))]
fn single_cpu_topology(hart_id: usize) -> CpuTopology<MAX_CPU_NUM> {
    let mut topology = CpuTopology::empty();
    assert!(
        topology.add_hart(hart_id),
        "CPU capacity must be at least one"
    );
    topology
}

fn publish_topology(topology: &CpuTopology<MAX_CPU_NUM>) {
    for cpu_id in 0..topology.cpu_count() {
        HART_IDS[cpu_id].store(
            topology
                .hart_id(cpu_id)
                .expect("published logical CPU must have a hart ID"),
            Ordering::Relaxed,
        );
    }
    CPU_COUNT.store(topology.cpu_count(), Ordering::Release);
}

fn load_cpu_value(values: &[AtomicUsize; MAX_CPU_NUM], cpu_id: usize) -> Option<usize> {
    if cpu_id >= cpu_count() {
        return None;
    }
    let value = values[cpu_id].load(Ordering::Acquire);
    (value != INVALID_ID).then_some(value)
}

fn try_logical_cpu_id(hart_id: usize) -> Option<usize> {
    (0..cpu_count()).find(|cpu_id| HART_IDS[*cpu_id].load(Ordering::Acquire) == hart_id)
}

#[cfg(test)]
mod tests {
    use super::{is_jh7110_u74_hart, jh7110_supervisor_context};

    #[test]
    fn excludes_jh7110_management_hart_from_application_topology() {
        assert!(!is_jh7110_u74_hart(0));
        for hart_id in 1..=4 {
            assert!(is_jh7110_u74_hart(hart_id));
        }
        assert!(!is_jh7110_u74_hart(5));
    }

    #[test]
    fn maps_jh7110_u74_harts_to_supervisor_contexts() {
        assert_eq!(jh7110_supervisor_context(0), None);
        assert_eq!(jh7110_supervisor_context(1), Some(2));
        assert_eq!(jh7110_supervisor_context(2), Some(4));
        assert_eq!(jh7110_supervisor_context(3), Some(6));
        assert_eq!(jh7110_supervisor_context(4), Some(8));
        assert_eq!(jh7110_supervisor_context(5), None);
    }
}
