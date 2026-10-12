pub const DMW_PHYS_MASK: usize = 0x0fff_ffff_ffff_ffff;
pub const DMW_CACHED_BASE: usize = 0x9000_0000_0000_0000;

pub const fn phys_to_cached_dmw(paddr: usize) -> Option<usize> {
    if paddr & !DMW_PHYS_MASK == 0 {
        Some(paddr | DMW_CACHED_BASE)
    } else {
        None
    }
}

pub const fn kernel_virt_to_cached_dmw(vaddr: usize, phys_virt_offset: usize) -> Option<usize> {
    match vaddr.checked_sub(phys_virt_offset) {
        Some(paddr) => phys_to_cached_dmw(paddr),
        None => None,
    }
}

pub const fn valid_stack_top(paddr: usize, ram_base: usize, ram_size: usize) -> bool {
    match ram_base.checked_add(ram_size) {
        Some(ram_end) => paddr > ram_base && paddr <= ram_end,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PHYS_VIRT_OFFSET: usize = 0xffff_8000_0000_0000;

    #[test]
    fn converts_kernel_entry_to_cached_dmw() {
        assert_eq!(
            kernel_virt_to_cached_dmw(0xffff_8000_8000_0000, PHYS_VIRT_OFFSET),
            Some(0x9000_0000_8000_0000)
        );
        assert_eq!(
            kernel_virt_to_cached_dmw(0x8000_0000, PHYS_VIRT_OFFSET),
            None
        );
    }

    #[test]
    fn converts_physical_stack_to_cached_dmw() {
        assert_eq!(
            phys_to_cached_dmw(0x27fff_0000),
            Some(0x9000_0002_7fff_0000)
        );
        assert_eq!(phys_to_cached_dmw(0x1000_0000_0000_0000), None);
    }

    #[test]
    fn checks_stack_top_against_ram_bounds() {
        let ram_base = 0x8000_0000;
        let ram_size = 0x2_0000_0000;

        assert!(!valid_stack_top(ram_base, ram_base, ram_size));
        assert!(valid_stack_top(ram_base + 0x4000, ram_base, ram_size));
        assert!(valid_stack_top(ram_base + ram_size, ram_base, ram_size));
        assert!(!valid_stack_top(
            ram_base + ram_size + 1,
            ram_base,
            ram_size
        ));
    }
}
