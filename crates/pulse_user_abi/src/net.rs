//! Socket ABI codecs. Protocol validation stays with each syscall.

use core::{ffi::c_void, net::SocketAddrV6};

use linux_raw_sys::net::{in_addr, in6_addr, in6_addr__bindgen_ty_1, sockaddr_in, sockaddr_in6};

use crate::{
    AbiDecodeError, AbiReader, AbiWriter, FromUserAbi, IntoUserAbi, UserAbiType, decode_field_at,
};

/// The 64-bit Linux userspace message header used by sendmsg/recvmsg.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct MessageHeader {
    pub msg_name: *mut c_void,
    pub msg_namelen: u32,
    pub msg_iov: *mut c_void,
    pub msg_iovlen: usize,
    pub msg_control: *mut c_void,
    pub msg_controllen: usize,
    pub msg_flags: u32,
}

crate::impl_user_abi_struct! {
    for MessageHeader, size = 56 => {
        msg_name: *mut c_void,
        msg_namelen: u32,
        msg_iov: *mut c_void,
        msg_iovlen: usize,
        msg_control: *mut c_void,
        msg_controllen: usize,
        msg_flags: u32,
    }
}

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

// Encode from the address's safe accessors so IPv6 output never reads the
// linux_raw_sys union or depends on SocketAddrV6's Rust memory layout.
impl UserAbiType for SocketAddrV6 {
    type Buffer = [u8; 28];
}

impl IntoUserAbi for SocketAddrV6 {
    fn encode_abi(&self, writer: &mut AbiWriter<'_>) {
        writer.write(&(linux_raw_sys::net::AF_INET6 as u16));
        writer.write(&self.port().to_be());
        writer.write(&self.flowinfo().to_be());
        writer.write(&self.ip().octets());
        writer.write(&self.scope_id());
    }
}

#[cfg(test)]
mod tests {
    use axerrno::AxError;
    use linux_raw_sys::net::{sockaddr_in, sockaddr_in6};

    use super::MessageHeader;
    use crate::{decode_from_bytes, encode_to_buffer, read_user_value_with, write_user_value_with};

    #[test]
    fn sockaddr_ipv6_output_preserves_network_bytes_and_native_scope() {
        let address = core::net::SocketAddrV6::new(
            core::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            443,
            0x12345,
            7,
        );
        let bytes = encode_to_buffer(&address);
        assert_eq!(bytes.len(), 28);
        assert_eq!(&bytes[..2], &10u16.to_ne_bytes());
        assert_eq!(&bytes[2..4], &[0x01, 0xbb]);
        assert_eq!(&bytes[4..8], &[0, 1, 0x23, 0x45]);
        assert_eq!(
            &bytes[8..24],
            &[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        );
        assert_eq!(&bytes[24..28], &7u32.to_ne_bytes());
    }

    #[test]
    fn message_header_output_clears_padding_and_preserves_fault_prefix() {
        let value = MessageHeader {
            msg_name: 0x4000usize as *mut _,
            msg_namelen: 28,
            msg_iov: 0x5000usize as *mut _,
            msg_iovlen: 2,
            msg_control: core::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0x20,
        };
        let bytes = encode_to_buffer(&value);
        assert_eq!(bytes.len(), 56);
        assert_eq!(&bytes[0..8], &0x4000u64.to_ne_bytes());
        assert_eq!(&bytes[8..12], &28u32.to_ne_bytes());
        assert_eq!(&bytes[12..16], &[0; 4]);
        assert_eq!(&bytes[16..24], &0x5000u64.to_ne_bytes());
        assert_eq!(&bytes[24..32], &2u64.to_ne_bytes());
        assert_eq!(&bytes[32..48], &[0; 16]);
        assert_eq!(&bytes[48..52], &0x20u32.to_ne_bytes());
        assert_eq!(&bytes[52..56], &[0; 4]);

        for available in [0, 1, 12, 14, 16, 52, 54, 55] {
            let mut output = [0xa5; 56];
            assert_eq!(
                write_user_value_with(0x4000, &value, |address, source| {
                    assert_eq!(address, 0x4000);
                    output[..available].copy_from_slice(&source[..available]);
                    Ok(available)
                }),
                Err(AxError::BadAddress),
            );
            assert_eq!(&output[..available], &bytes[..available]);
            assert!(output[available..].iter().all(|&byte| byte == 0xa5));
        }
    }

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
