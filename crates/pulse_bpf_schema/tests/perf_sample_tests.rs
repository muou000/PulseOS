use pulse_bpf_schema::{PerfEventContext, PerfSampleContext};

#[test]
fn v2_sample_keeps_v1_prefix_and_has_explicit_instruction_mode_version() {
    let base = PerfEventContext::new(123, 0, 456, 2, 7, 8, 9);
    let sample = PerfSampleContext { base, ip: 0x400100, mode: 2, version: 2 };
    let bytes = sample.to_bytes();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[..48], base.as_bytes());
    assert_eq!(&bytes[48..56], &0x400100u64.to_le_bytes());
    assert_eq!(&bytes[56..60], &2u32.to_le_bytes());
    assert_eq!(&bytes[60..64], &2u32.to_le_bytes());
    assert_eq!(&bytes[8..16], &[0;8]); // data address is not silently redefined
}
