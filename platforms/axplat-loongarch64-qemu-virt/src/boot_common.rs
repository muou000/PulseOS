pub const L1_BLOCK_SIZE: usize = 0x4000_0000;
/// QEMU direct kernel boot maps its command line and system tables here.
pub const QEMU_BOOT_INFO_SIZE: usize = 0x0010_0000;
/// QEMU reserves this fixed-size slot for the `virt` machine's live FDT.
pub const QEMU_FDT_MAX_SIZE: usize = 0x0010_0000;
pub const QEMU_LOW_MEMORY_SIZE: usize = 0x1000_0000;

pub const fn l1_block_index(paddr: usize) -> usize {
    paddr / L1_BLOCK_SIZE
}

pub const fn high_memory_l1_blocks(total_memory_size: usize) -> usize {
    let high_memory_size = total_memory_size.saturating_sub(QEMU_LOW_MEMORY_SIZE);
    if high_memory_size == 0 {
        0
    } else {
        (high_memory_size - 1) / L1_BLOCK_SIZE + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locates_qemu_high_memory_in_l1() {
        assert_eq!(l1_block_index(0x8000_0000), 2);
    }

    #[test]
    fn covers_split_one_gib_memory_with_one_block() {
        assert_eq!(high_memory_l1_blocks(0x4000_0000), 1);
    }

    #[test]
    fn covers_split_eight_gib_memory_with_eight_blocks() {
        assert_eq!(high_memory_l1_blocks(0x2_0000_0000), 8);
    }

    #[test]
    fn does_not_map_high_memory_when_ram_fits_below_the_hole() {
        assert_eq!(high_memory_l1_blocks(QEMU_LOW_MEMORY_SIZE), 0);
    }
}
