const INVALID_CPU_ID: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuTopology<const CAPACITY: usize> {
    hardware_ids: [usize; CAPACITY],
    cpu_count: usize,
}

impl<const CAPACITY: usize> CpuTopology<CAPACITY> {
    pub(crate) const fn empty() -> Self {
        Self {
            hardware_ids: [INVALID_CPU_ID; CAPACITY],
            cpu_count: 0,
        }
    }

    pub(crate) fn add_hardware_id(&mut self, hardware_id: usize) -> bool {
        if hardware_id == INVALID_CPU_ID
            || self.cpu_count == CAPACITY
            || self.logical_cpu_id(hardware_id).is_some()
        {
            return false;
        }

        self.hardware_ids[self.cpu_count] = hardware_id;
        self.cpu_count += 1;
        true
    }

    pub(crate) const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    pub(crate) fn logical_cpu_id(&self, hardware_id: usize) -> Option<usize> {
        self.hardware_ids[..self.cpu_count]
            .iter()
            .position(|candidate| *candidate == hardware_id)
    }

    pub(crate) fn hardware_id(&self, cpu_id: usize) -> Option<usize> {
        self.hardware_ids
            .get(cpu_id)
            .copied()
            .filter(|id| *id != INVALID_CPU_ID)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_non_dense_hardware_ids_to_logical_cpus() {
        let mut topology = CpuTopology::<4>::empty();

        assert!(topology.add_hardware_id(1));
        assert!(topology.add_hardware_id(3));
        assert!(topology.add_hardware_id(7));

        assert_eq!(topology.cpu_count(), 3);
        assert_eq!(topology.logical_cpu_id(1), Some(0));
        assert_eq!(topology.logical_cpu_id(3), Some(1));
        assert_eq!(topology.logical_cpu_id(7), Some(2));
        assert_eq!(topology.hardware_id(2), Some(7));
        assert_eq!(topology.logical_cpu_id(2), None);
    }

    #[test]
    fn rejects_duplicate_ids_and_ids_beyond_capacity() {
        let mut topology = CpuTopology::<2>::empty();

        assert!(topology.add_hardware_id(2));
        assert!(!topology.add_hardware_id(2));
        assert!(topology.add_hardware_id(4));
        assert!(!topology.add_hardware_id(6));

        assert_eq!(topology.cpu_count(), 2);
        assert_eq!(topology.hardware_id(0), Some(2));
        assert_eq!(topology.hardware_id(1), Some(4));
    }
}
