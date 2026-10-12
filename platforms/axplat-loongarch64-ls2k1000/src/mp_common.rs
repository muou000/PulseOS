pub const DMW_PHYS_MASK: usize = 0x0fff_ffff_ffff_ffff;
pub const DMW_UNCACHED_BASE: usize = 0x8000_0000_0000_0000;
pub const DMW_CACHED_BASE: usize = 0x9000_0000_0000_0000;

pub(super) const fn firmware_to_phys(address: usize) -> Option<usize> {
    let segment = address & !DMW_PHYS_MASK;
    if matches!(segment, 0 | DMW_UNCACHED_BASE | DMW_CACHED_BASE) {
        Some(address & DMW_PHYS_MASK)
    } else {
        None
    }
}

const _: () = assert!(matches!(firmware_to_phys(0x9000_0000_0000_0000), Some(0)));
const _: () = assert!(matches!(
    firmware_to_phys(0x9000_0000_9000_0000),
    Some(0x9000_0000)
));
const _: () = assert!(firmware_to_phys(0xa000_0000_0000_0000).is_none());

pub const fn phys_to_uncached_dmw(paddr: usize) -> Option<usize> {
    if paddr & !DMW_PHYS_MASK == 0 {
        Some(paddr | DMW_UNCACHED_BASE)
    } else {
        None
    }
}

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

    const PHYS_VIRT_OFFSET: usize = 0xffff_ffff_0000_0000;

    #[test]
    fn converts_kernel_entry_to_cached_dmw() {
        assert_eq!(
            kernel_virt_to_cached_dmw(0xffff_ffff_9800_0000, PHYS_VIRT_OFFSET),
            Some(0x9000_0000_9800_0000)
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
    fn converts_firmware_memory_to_uncached_dmw() {
        assert_eq!(
            phys_to_uncached_dmw(0x0a00_0000),
            Some(0x8000_0000_0a00_0000)
        );
        assert_eq!(phys_to_uncached_dmw(0x1000_0000_0000_0000), None);
    }

    #[test]
    fn converts_firmware_dmw_addresses_to_physical() {
        assert_eq!(firmware_to_phys(0x9000_0000_0000_0000), Some(0));
        assert_eq!(firmware_to_phys(0x9000_0000_9000_0000), Some(0x9000_0000));
        assert_eq!(firmware_to_phys(0x8000_0000_1fe0_1400), Some(0x1fe0_1400));
        assert_eq!(firmware_to_phys(0xa000_0000_0000_0000), None);
    }

    #[test]
    fn checks_stack_top_against_ram_bounds() {
        let ram_base = 0x9000_0000;
        let ram_size = 0x3000_0000;

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
