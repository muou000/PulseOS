pub(crate) fn parse_id_arg(raw: usize) -> u32 {
    raw as u32
}

pub(crate) fn parse_optional_id_arg(raw: usize) -> Option<u32> {
    let id = parse_id_arg(raw);
    if id == u32::MAX { None } else { Some(id) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_abi_truncates_ids_to_32_bits() {
        assert_eq!(parse_id_arg(0), 0);
        assert_eq!(parse_id_arg(u32::MAX as usize), u32::MAX);
        if usize::BITS > 32 {
            assert_eq!(parse_id_arg((1usize << 32) | 7), 7);
        }
    }

    #[test]
    fn credential_optional_id_uses_all_ones_as_sentinel() {
        assert_eq!(parse_optional_id_arg(u32::MAX as usize), None);
        assert_eq!(parse_optional_id_arg(0), Some(0));
        assert_eq!(parse_optional_id_arg(42), Some(42));
    }
}
