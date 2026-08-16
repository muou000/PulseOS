pub const L1_BLOCK_SIZE: usize = 0x4000_0000;

pub const fn l1_block_index(paddr: usize) -> usize {
    paddr / L1_BLOCK_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn places_kernel_in_the_third_one_gib_block() {
        assert_eq!(l1_block_index(0x9800_0000), 2);
    }

    #[test]
    fn keeps_ls2k1000_ahci_in_the_second_one_gib_block() {
        assert_eq!(l1_block_index(0x400e_0000), 1);
    }
}
