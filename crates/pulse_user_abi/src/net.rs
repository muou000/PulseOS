//! Socket address input codecs. Protocol validation stays with each syscall.

use linux_raw_sys::net::{in_addr, in6_addr, in6_addr__bindgen_ty_1, sockaddr_in, sockaddr_in6};

use crate::{AbiDecodeError, AbiReader, FromUserAbi, UserAbiType, decode_field_at};

crate::impl_user_abi_struct! {
    for in_addr, size = 4 => {
        s_addr: u32,
    }
}

crate::impl_user_abi_struct! {
    for sockaddr_in, size = 16 => {
        sin_family: u16,
        sin_port: u16,
        sin_addr: in_addr,
        __pad: [u8; 8],
    }
}

const _: () = {
    assert!(core::mem::size_of::<sockaddr_in6>() == 28);
    assert!(core::mem::size_of::<in6_addr>() == 16);
};

impl UserAbiType for sockaddr_in6 {
    type Buffer = [u8; 28];
}

impl FromUserAbi for sockaddr_in6 {
    fn decode_abi(reader: &mut AbiReader<'_>) -> Result<Self, AbiDecodeError> {
        let raw = reader.take_exact(28)?;
        // Initialize the byte-array union member explicitly; no Rust value is
        // reconstructed by reinterpreting the user's bytes.
        Ok(Self {
            sin6_family: decode_field_at(raw, core::mem::offset_of!(Self, sin6_family))?,
            sin6_port: decode_field_at(raw, core::mem::offset_of!(Self, sin6_port))?,
            sin6_flowinfo: decode_field_at(raw, core::mem::offset_of!(Self, sin6_flowinfo))?,
            sin6_addr: in6_addr {
                in6_u: in6_addr__bindgen_ty_1 {
                    u6_addr8: decode_field_at(raw, core::mem::offset_of!(Self, sin6_addr))?,
                },
            },
            sin6_scope_id: decode_field_at(raw, core::mem::offset_of!(Self, sin6_scope_id))?,
        })
    }
}

#[cfg(test)]
mod tests {
    use axerrno::AxError;
    use linux_raw_sys::net::{sockaddr_in, sockaddr_in6};

    use crate::{decode_from_bytes, read_user_value_with};

    #[test]
    fn sockaddr_ipv4_preserves_network_bytes_and_arbitrary_padding() {
        let mut raw = [0xa5; 16];
        raw[..2].copy_from_slice(&2u16.to_ne_bytes());
        raw[2..4].copy_from_slice(&8080u16.to_be_bytes());
        raw[4..8].copy_from_slice(&[192, 0, 2, 1]);
        let addr = decode_from_bytes::<sockaddr_in>(&raw).unwrap();
        assert_eq!(addr.sin_family, 2);
        assert_eq!(u16::from_be(addr.sin_port), 8080);
        assert_eq!(addr.sin_addr.s_addr.to_ne_bytes(), [192, 0, 2, 1]);
        assert_eq!(addr.__pad, [0xa5; 8]);
    }

    #[test]
    fn sockaddr_ipv6_preserves_fields_and_defers_family_validation() {
        let mut raw = [0xff; 28];
        raw[2..4].copy_from_slice(&443u16.to_be_bytes());
        raw[4..8].copy_from_slice(&0x12345u32.to_be_bytes());
        raw[24..28].copy_from_slice(&7u32.to_ne_bytes());
        let addr = decode_from_bytes::<sockaddr_in6>(&raw).unwrap();
        assert_eq!(addr.sin6_family, u16::MAX);
        assert_eq!(u16::from_be(addr.sin6_port), 443);
        assert_eq!(u32::from_be(addr.sin6_flowinfo), 0x12345);
        assert_eq!(addr.sin6_scope_id, 7);
    }

    #[test]
    fn sockaddr_short_copy_reports_bad_address_before_protocol_validation() {
        for copied in [0, 1, 15, 27] {
            let result = read_user_value_with::<sockaddr_in6>(0x4000, |_, dst| {
                dst[..copied].fill(0xff);
                Ok(copied)
            });
            assert!(matches!(result, Err(AxError::BadAddress)));
        }
    }
}
