const INVALID_CPU_ID: usize = usize::MAX;
const INVALID_PHANDLE: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuTopology<const CAPACITY: usize> {
    firmware_ids: [usize; CAPACITY],
    ipi_ids: [usize; CAPACITY],
    cpu_count: usize,
}

impl<const CAPACITY: usize> CpuTopology<CAPACITY> {
    pub(crate) const fn empty() -> Self {
        Self {
            firmware_ids: [INVALID_CPU_ID; CAPACITY],
            ipi_ids: [INVALID_CPU_ID; CAPACITY],
            cpu_count: 0,
        }
    }

    pub(crate) fn add_cpu(&mut self, firmware_id: usize, ipi_id: usize) -> bool {
        if firmware_id == INVALID_CPU_ID
            || ipi_id == INVALID_CPU_ID
            || self.cpu_count == CAPACITY
            || self.logical_cpu_id(firmware_id).is_some()
        {
            return false;
        }

        self.firmware_ids[self.cpu_count] = firmware_id;
        self.ipi_ids[self.cpu_count] = ipi_id;
        self.cpu_count += 1;
        true
    }

    pub(crate) const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    pub(crate) fn logical_cpu_id(&self, firmware_id: usize) -> Option<usize> {
        self.firmware_ids[..self.cpu_count]
            .iter()
            .position(|candidate| *candidate == firmware_id)
    }

    pub(crate) fn firmware_id(&self, cpu_id: usize) -> Option<usize> {
        self.firmware_ids
            .get(cpu_id)
            .copied()
            .filter(|id| *id != INVALID_CPU_ID)
    }

    pub(crate) fn ipi_id(&self, cpu_id: usize) -> Option<usize> {
        self.ipi_ids
            .get(cpu_id)
            .copied()
            .filter(|id| *id != INVALID_CPU_ID)
    }
}

#[derive(Clone, Copy)]
struct QemuCpuMapEntry {
    phandle: usize,
    socket_id: usize,
    core_id: usize,
    thread_id: usize,
}

const EMPTY_QEMU_CPU_MAP_ENTRY: QemuCpuMapEntry = QemuCpuMapEntry {
    phandle: INVALID_PHANDLE,
    socket_id: 0,
    core_id: 0,
    thread_id: 0,
};

/// QEMU's `/cpus/cpu-map` associates CPU phandles with its topology slots.
/// The slots are needed because LoongArch QEMU uses an aligned topology ID for
/// IPI routing while the CPU CSR and `reg` property expose the CPU index.
#[derive(Clone, Copy)]
pub(crate) struct QemuCpuMap<const CAPACITY: usize> {
    entries: [QemuCpuMapEntry; CAPACITY],
    count: usize,
    max_core_id: usize,
    max_thread_id: usize,
}

impl<const CAPACITY: usize> QemuCpuMap<CAPACITY> {
    pub(crate) const fn empty() -> Self {
        Self {
            entries: [EMPTY_QEMU_CPU_MAP_ENTRY; CAPACITY],
            count: 0,
            max_core_id: 0,
            max_thread_id: 0,
        }
    }

    pub(crate) fn add(
        &mut self,
        phandle: usize,
        socket_id: usize,
        core_id: usize,
        thread_id: usize,
    ) -> bool {
        if phandle == INVALID_PHANDLE
            || self.count == CAPACITY
            || self.entries[..self.count]
                .iter()
                .any(|entry| entry.phandle == phandle)
        {
            return false;
        }

        self.entries[self.count] = QemuCpuMapEntry {
            phandle,
            socket_id,
            core_id,
            thread_id,
        };
        self.max_core_id = self.max_core_id.max(core_id);
        self.max_thread_id = self.max_thread_id.max(thread_id);
        self.count += 1;
        true
    }

    pub(crate) fn ipi_id(&self, phandle: usize) -> Option<usize> {
        let entry = self.entries[..self.count]
            .iter()
            .find(|entry| entry.phandle == phandle)?;
        let threads = qemu_topology_alignment(self.max_thread_id.checked_add(1)?)?;
        let cores = qemu_topology_alignment(self.max_core_id.checked_add(1)?)?;

        entry
            .socket_id
            .checked_mul(threads)?
            .checked_mul(cores)?
            .checked_add(entry.core_id.checked_mul(threads)?)?
            .checked_add(entry.thread_id)
    }
}

fn qemu_topology_alignment(count: usize) -> Option<usize> {
    let mut result = 1usize;
    while result < count {
        result = result.checked_mul(2)?;
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_firmware_and_ipi_ids_to_logical_cpus() {
        let mut topology = CpuTopology::<4>::empty();

        assert!(topology.add_cpu(1, 1));
        assert!(topology.add_cpu(3, 4));
        assert!(topology.add_cpu(7, 8));

        assert_eq!(topology.cpu_count(), 3);
        assert_eq!(topology.logical_cpu_id(1), Some(0));
        assert_eq!(topology.logical_cpu_id(3), Some(1));
        assert_eq!(topology.logical_cpu_id(7), Some(2));
        assert_eq!(topology.firmware_id(2), Some(7));
        assert_eq!(topology.ipi_id(1), Some(4));
        assert_eq!(topology.logical_cpu_id(2), None);
    }

    #[test]
    fn rejects_duplicate_ids_and_ids_beyond_capacity() {
        let mut topology = CpuTopology::<2>::empty();

        assert!(topology.add_cpu(2, 2));
        assert!(!topology.add_cpu(2, 4));
        assert!(topology.add_cpu(4, 6));
        assert!(!topology.add_cpu(6, 8));

        assert_eq!(topology.cpu_count(), 2);
        assert_eq!(topology.firmware_id(0), Some(2));
        assert_eq!(topology.ipi_id(1), Some(6));
    }

    #[test]
    fn derives_qemu_ipi_ids_from_cpu_map_topology() {
        let mut cpu_map = QemuCpuMap::<6>::empty();

        assert!(cpu_map.add(0x8000, 0, 0, 0));
        assert!(cpu_map.add(0x8001, 0, 1, 0));
        assert!(cpu_map.add(0x8002, 0, 2, 0));
        assert!(cpu_map.add(0x8003, 1, 0, 0));
        assert!(cpu_map.add(0x8004, 1, 1, 0));
        assert!(cpu_map.add(0x8005, 1, 2, 0));

        assert_eq!(cpu_map.ipi_id(0x8002), Some(2));
        assert_eq!(cpu_map.ipi_id(0x8003), Some(4));
        assert_eq!(cpu_map.ipi_id(0x8005), Some(6));
        assert_eq!(cpu_map.ipi_id(0xdead), None);
    }
}
