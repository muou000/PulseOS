const INVALID_HART_ID: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuTopology<const CAPACITY: usize> {
    hart_ids: [usize; CAPACITY],
    cpu_count: usize,
}

impl<const CAPACITY: usize> CpuTopology<CAPACITY> {
    pub(crate) const fn empty() -> Self {
        Self {
            hart_ids: [INVALID_HART_ID; CAPACITY],
            cpu_count: 0,
        }
    }

    pub(crate) fn add_hart(&mut self, hart_id: usize) -> bool {
        if hart_id == INVALID_HART_ID
            || self.cpu_count == CAPACITY
            || self.logical_cpu_id(hart_id).is_some()
        {
            return false;
        }

        self.hart_ids[self.cpu_count] = hart_id;
        self.cpu_count += 1;
        true
    }

    pub(crate) const fn cpu_count(&self) -> usize {
        self.cpu_count
    }

    pub(crate) fn logical_cpu_id(&self, hart_id: usize) -> Option<usize> {
        self.hart_ids[..self.cpu_count]
            .iter()
            .position(|candidate| *candidate == hart_id)
    }

    pub(crate) fn hart_id(&self, cpu_id: usize) -> Option<usize> {
        self.hart_ids
            .get(cpu_id)
            .copied()
            .filter(|id| *id != INVALID_HART_ID)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_non_dense_harts_to_logical_cpus() {
        let mut topology = CpuTopology::<4>::empty();

        assert!(topology.add_hart(1));
        assert!(topology.add_hart(3));
        assert!(topology.add_hart(7));

        assert_eq!(topology.cpu_count(), 3);
        assert_eq!(topology.logical_cpu_id(1), Some(0));
        assert_eq!(topology.logical_cpu_id(3), Some(1));
        assert_eq!(topology.logical_cpu_id(7), Some(2));
        assert_eq!(topology.hart_id(2), Some(7));
        assert_eq!(topology.logical_cpu_id(2), None);
    }

    #[test]
    fn rejects_duplicate_harts_and_harts_beyond_capacity() {
        let mut topology = CpuTopology::<2>::empty();

        assert!(topology.add_hart(2));
        assert!(!topology.add_hart(2));
        assert!(topology.add_hart(4));
        assert!(!topology.add_hart(6));

        assert_eq!(topology.cpu_count(), 2);
        assert_eq!(topology.hart_id(0), Some(2));
        assert_eq!(topology.hart_id(1), Some(4));
    }

    #[test]
    fn preserves_insertion_order_for_boot_hart_first_mapping() {
        let mut topology = CpuTopology::<4>::empty();
        topology.add_hart(7);
        topology.add_hart(1);
        topology.add_hart(3);

        assert_eq!(topology.logical_cpu_id(7), Some(0));
        assert_eq!(topology.logical_cpu_id(1), Some(1));
        assert_eq!(topology.logical_cpu_id(3), Some(2));
    }
}
