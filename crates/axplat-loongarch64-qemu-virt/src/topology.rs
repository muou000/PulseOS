use core::sync::atomic::{AtomicUsize, Ordering};

use fdt_raw::{Fdt, Header, Node};

#[cfg(feature = "smp")]
use crate::cpu_topology::QemuCpuMap;
use crate::{
    boot_common::{QEMU_BOOT_INFO_SIZE, QEMU_FDT_MAX_SIZE, QEMU_LOW_MEMORY_SIZE},
    config::plat::MAX_CPU_NUM,
    cpu_topology::CpuTopology,
    mp_common::phys_to_cached_dmw,
};

const INVALID_CPU_ID: usize = usize::MAX;
const MAX_DTB_SIZE: usize = QEMU_FDT_MAX_SIZE;

/// QEMU's LoongArch `virt` board maps its live FDT at this physical address.
pub(super) const QEMU_FDT_PADDR: usize = QEMU_BOOT_INFO_SIZE;

static CPU_COUNT: AtomicUsize = AtomicUsize::new(1);
static FIRMWARE_CPU_IDS: [AtomicUsize; MAX_CPU_NUM] =
    [const { AtomicUsize::new(INVALID_CPU_ID) }; MAX_CPU_NUM];
static IPI_CPU_IDS: [AtomicUsize; MAX_CPU_NUM] =
    [const { AtomicUsize::new(INVALID_CPU_ID) }; MAX_CPU_NUM];

pub(super) fn init_from_dtb(boot_cpu_id: usize) -> usize {
    #[cfg(feature = "smp")]
    let topology = fdt_from_phys(QEMU_FDT_PADDR)
        .and_then(|fdt| parse_cpu_topology(boot_cpu_id, &fdt))
        .unwrap_or_else(|| single_cpu_topology(boot_cpu_id));
    #[cfg(not(feature = "smp"))]
    let topology = single_cpu_topology(boot_cpu_id);

    publish_topology(&topology);
    0
}

pub(super) fn init_platform_from_dtb(dtb_paddr: usize) {
    let Some(fdt) = fdt_from_phys(dtb_paddr) else {
        warn!("invalid or unavailable DTB at {dtb_paddr:#x}; using QEMU virt defaults");
        crate::mem::init_fallback();
        return;
    };

    crate::mem::init_from_fdt(&fdt, dtb_paddr);
}

pub(super) fn logical_cpu_id(firmware_cpu_id: usize) -> usize {
    try_logical_cpu_id(firmware_cpu_id)
        .unwrap_or_else(|| panic!("CPU {firmware_cpu_id} is absent from the CPU topology"))
}

pub(super) fn ipi_cpu_id(cpu_id: usize) -> Option<usize> {
    if cpu_id >= cpu_count() {
        return None;
    }
    let ipi_cpu_id = IPI_CPU_IDS[cpu_id].load(Ordering::Acquire);
    (ipi_cpu_id != INVALID_CPU_ID).then_some(ipi_cpu_id)
}

pub(super) fn cpu_count() -> usize {
    CPU_COUNT.load(Ordering::Acquire)
}

pub(super) fn fdt_from_phys(dtb_paddr: usize) -> Option<Fdt<'static>> {
    let memory_end = QEMU_LOW_MEMORY_SIZE;
    let header_end = dtb_paddr.checked_add(core::mem::size_of::<Header>())?;
    if dtb_paddr >= memory_end || header_end > memory_end {
        return None;
    }

    // LoongArch keeps PGDL at the invalid PA-0 table while the kernel runs in
    // the higher half, so access the low-memory DTB through DMW1 instead of a
    // low virtual address. The physical address remains the DTB's identity for
    // reservation and range calculations.
    let dtb_vaddr = phys_to_cached_dmw(dtb_paddr)?;

    // SAFETY: the header lies in QEMU's low RAM window and the firmware keeps
    // the FDT resident throughout the kernel boot sequence.
    let header = unsafe { Header::from_ptr(dtb_vaddr as *mut u8).ok()? };
    let total_size = header.totalsize as usize;
    let dtb_end = dtb_paddr.checked_add(total_size)?;
    if total_size < core::mem::size_of::<Header>()
        || total_size > MAX_DTB_SIZE
        || dtb_end > memory_end
    {
        return None;
    }

    // SAFETY: both ends were checked against the low RAM window, and DMW1 maps
    // that physical range with a stable cached virtual alias.
    let bytes = unsafe { core::slice::from_raw_parts(dtb_vaddr as *const u8, total_size) };
    Fdt::from_bytes(bytes).ok()
}

#[cfg(feature = "smp")]
fn parse_cpu_topology(boot_cpu_id: usize, fdt: &Fdt<'_>) -> Option<CpuTopology<MAX_CPU_NUM>> {
    let cpu_map = parse_qemu_cpu_map(fdt);
    let mut topology = CpuTopology::empty();
    let mut boot_cpu_found = false;

    for node in fdt.find_children_by_path("/cpus") {
        if !is_available_cpu(&node) {
            continue;
        }
        let Some(firmware_cpu_id) = cpu_firmware_id(&node) else {
            continue;
        };
        if firmware_cpu_id != boot_cpu_id {
            continue;
        }

        let ipi_cpu_id = qemu_ipi_cpu_id(&node, &cpu_map).unwrap_or(firmware_cpu_id);
        if !topology.add_cpu(firmware_cpu_id, ipi_cpu_id) {
            return None;
        }
        boot_cpu_found = true;
        break;
    }
    if !boot_cpu_found {
        topology = single_cpu_topology(boot_cpu_id);
    }

    for node in fdt.find_children_by_path("/cpus") {
        if !is_available_cpu(&node) {
            continue;
        }
        let Some(firmware_cpu_id) = cpu_firmware_id(&node) else {
            continue;
        };
        if firmware_cpu_id != boot_cpu_id
            && !topology.add_cpu(
                firmware_cpu_id,
                qemu_ipi_cpu_id(&node, &cpu_map).unwrap_or(firmware_cpu_id),
            )
            && topology.cpu_count() == MAX_CPU_NUM
        {
            break;
        }
    }
    Some(topology)
}

fn is_available_cpu(node: &Node<'_>) -> bool {
    node.name().starts_with("cpu@")
        && matches!(node.find_property_str("device_type"), None | Some("cpu"))
        && matches!(
            node.find_property_str("status"),
            None | Some("okay") | Some("ok")
        )
}

fn cpu_firmware_id(node: &Node<'_>) -> Option<usize> {
    node.reg()
        .and_then(|mut regs| regs.next())
        .and_then(|reg| usize::try_from(reg.address).ok())
}

#[cfg(feature = "smp")]
fn parse_qemu_cpu_map(fdt: &Fdt<'_>) -> QemuCpuMap<MAX_CPU_NUM> {
    let mut cpu_map = QemuCpuMap::empty();
    for node in fdt.all_nodes() {
        let path = node.path();
        let Some((socket_id, core_id, thread_id)) = qemu_cpu_map_location(path.as_str()) else {
            continue;
        };
        let Some(phandle) = node
            .find_property("cpu")
            .and_then(|property| property.as_u32())
            .map(|value| value as usize)
        else {
            continue;
        };
        let _ = cpu_map.add(phandle, socket_id, core_id, thread_id);
    }
    cpu_map
}

#[cfg(feature = "smp")]
fn qemu_ipi_cpu_id(node: &Node<'_>, cpu_map: &QemuCpuMap<MAX_CPU_NUM>) -> Option<usize> {
    node.find_property("phandle")
        .or_else(|| node.find_property("linux,phandle"))
        .and_then(|property| property.as_u32())
        .and_then(|phandle| cpu_map.ipi_id(phandle as usize))
}

#[cfg(feature = "smp")]
fn qemu_cpu_map_location(path: &str) -> Option<(usize, usize, usize)> {
    let components = path.strip_prefix("/cpus/cpu-map/")?;
    let mut socket_id = None;
    let mut core_id = None;
    let mut thread_id = Some(0usize);

    for component in components.split('/') {
        if let Some(id) = qemu_cpu_map_component_id(component, "socket") {
            if socket_id.replace(id).is_some() {
                return None;
            }
        } else if let Some(id) = qemu_cpu_map_component_id(component, "core") {
            if core_id.replace(id).is_some() {
                return None;
            }
        } else if let Some(id) = qemu_cpu_map_component_id(component, "thread") {
            if thread_id.replace(id).is_some_and(|old_id| old_id != 0) {
                return None;
            }
        } else {
            return None;
        }
    }

    Some((socket_id?, core_id?, thread_id?))
}

#[cfg(feature = "smp")]
fn qemu_cpu_map_component_id(component: &str, prefix: &str) -> Option<usize> {
    let digits = component.strip_prefix(prefix)?;
    if digits.is_empty() {
        return None;
    }

    let mut value = 0usize;
    for digit in digits.bytes() {
        if !digit.is_ascii_digit() {
            return None;
        }
        value = value
            .checked_mul(10)?
            .checked_add((digit - b'0') as usize)?;
    }
    Some(value)
}

fn single_cpu_topology(firmware_cpu_id: usize) -> CpuTopology<MAX_CPU_NUM> {
    let mut topology = CpuTopology::empty();
    assert!(
        topology.add_cpu(firmware_cpu_id, firmware_cpu_id),
        "CPU capacity must be at least one"
    );
    topology
}

fn publish_topology(topology: &CpuTopology<MAX_CPU_NUM>) {
    for cpu_id in 0..topology.cpu_count() {
        FIRMWARE_CPU_IDS[cpu_id].store(
            topology
                .firmware_id(cpu_id)
                .expect("published logical CPU must have a firmware CPU ID"),
            Ordering::Relaxed,
        );
        IPI_CPU_IDS[cpu_id].store(
            topology
                .ipi_id(cpu_id)
                .expect("published logical CPU must have an IPI CPU ID"),
            Ordering::Relaxed,
        );
    }
    CPU_COUNT.store(topology.cpu_count(), Ordering::Release);
}

fn try_logical_cpu_id(firmware_cpu_id: usize) -> Option<usize> {
    (0..cpu_count())
        .find(|cpu_id| FIRMWARE_CPU_IDS[*cpu_id].load(Ordering::Acquire) == firmware_cpu_id)
}
