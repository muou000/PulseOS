pub const EIOINTC_VECTOR_COUNT: usize = 256;
pub const EIOINTC_CPU_IRQ: usize = 3;
pub const CPU_LOCAL_IRQ_FLAG: usize = 1 << (usize::BITS - 1);
pub const RAW_TIMER_IRQ: usize = 11;
pub const RAW_IPI_IRQ: usize = 12;
pub const TIMER_IRQ: usize = CPU_LOCAL_IRQ_FLAG | RAW_TIMER_IRQ;
pub const IPI_IRQ: usize = CPU_LOCAL_IRQ_FLAG | RAW_IPI_IRQ;

const EIOINTC_HWI_BASE: usize = 2;
const EIOINTC_CPU_PIN: usize = EIOINTC_CPU_IRQ - EIOINTC_HWI_BASE;

pub const EIOINTC_IPMAP_WORD: u32 = u32::from_le_bytes([1 << EIOINTC_CPU_PIN; 4]);
pub const EIOINTC_CPU0_ROUTE_BYTE: u8 = 0x01;
pub const EIOINTC_CPU0_ROUTE_WORD: u32 = u32::from_le_bytes([EIOINTC_CPU0_ROUTE_BYTE; 4]);

pub const fn eiointc_nodemap_word(word: usize) -> u32 {
    ((1 << (word * 2 + 1)) << 16) | (1 << (word * 2))
}

pub const fn eiointc_reg_bit(irq: usize) -> (usize, u64) {
    (irq / 64 * 8, 1u64 << (irq % 64))
}

pub const fn is_external_irq(irq: usize) -> bool {
    irq < EIOINTC_VECTOR_COUNT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_eiointc_to_cpu_hwi1() {
        assert_eq!(EIOINTC_CPU_IRQ, 3);
        assert_eq!(EIOINTC_IPMAP_WORD, 0x0202_0202);
        assert_eq!(EIOINTC_CPU0_ROUTE_BYTE, 0x01);
        assert_eq!(EIOINTC_CPU0_ROUTE_WORD, 0x0101_0101);
    }

    #[test]
    fn builds_eiointc_node_routes_for_all_vector_groups() {
        assert_eq!(eiointc_nodemap_word(0), 0x0002_0001);
        assert_eq!(eiointc_nodemap_word(7), 0x8000_4000);
    }

    #[test]
    fn splits_eiointc_vectors_into_64_bit_registers() {
        assert_eq!(eiointc_reg_bit(0), (0, 1));
        assert_eq!(eiointc_reg_bit(63), (0, 1u64 << 63));
        assert_eq!(eiointc_reg_bit(64), (8, 1));
        assert_eq!(eiointc_reg_bit(255), (24, 1u64 << 63));
    }

    #[test]
    fn keeps_cpu_local_irqs_out_of_external_vector_space() {
        assert_eq!(TIMER_IRQ, 0x8000_0000_0000_000b);
        assert_eq!(IPI_IRQ, 0x8000_0000_0000_000c);
        assert!(is_external_irq(RAW_TIMER_IRQ));
        assert!(is_external_irq(RAW_IPI_IRQ));
        assert!(!is_external_irq(TIMER_IRQ));
        assert!(!is_external_irq(IPI_IRQ));
    }
}
