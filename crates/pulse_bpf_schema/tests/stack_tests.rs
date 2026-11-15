use std::cell::Cell;

use pulse_bpf_schema::{
    FrozenStack, PerfEventContext, PerfSampleContext, PerfStackSampleContext, StackLimits,
    StackRegisters, StackStatus, walk_frame_pointers,
};

fn regs() -> StackRegisters {
    StackRegisters {
        ip: 0x400100,
        sp: 0x1000,
        fp: 0x1020,
        ra: 0x400200,
    }
}

fn frame(previous: u64, ra: u64) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..8].copy_from_slice(&previous.to_le_bytes());
    bytes[8..].copy_from_slice(&ra.to_le_bytes());
    bytes
}

fn executable(ip: u64) -> bool {
    (0x400000..0x401000).contains(&ip) && ip % 2 == 0
}

fn three_layers(limits: StackLimits) -> FrozenStack {
    walk_frame_pointers(
        regs(),
        limits,
        |address| match address {
            0x1010 => Ok(frame(0x1040, 0x400200)),
            0x1030 => Ok(frame(0, 0x400300)),
            _ => Err(StackStatus::ReadFault),
        },
        executable,
    )
}

#[test]
fn real_frame_layout_preserves_sampled_ip_and_saved_return_addresses() {
    let stack = three_layers(StackLimits::default());
    assert_eq!(stack.status, StackStatus::Complete);
    assert_eq!(
        &stack.ips[..stack.len as usize],
        &[0x400100, 0x400200, 0x400300]
    );
    assert_eq!(stack.registers, regs());
    assert_eq!(stack.bytes_read, 32);
    assert_eq!(stack.depth_limit, 32);
    assert_eq!(stack.byte_limit, 512);
    assert_eq!(stack.capture_ns, 0);
    assert!(stack.ips[3..].iter().all(|&ip| ip == 0));
}

#[test]
fn sampled_pc_uses_depth_budget_and_read_budget_is_independent() {
    let shallow = three_layers(StackLimits {
        depth: 1,
        bytes: 512,
    });
    assert_eq!(
        (shallow.status, shallow.len, shallow.bytes_read),
        (StackStatus::DepthLimit, 1, 0)
    );
    let shallow = three_layers(StackLimits {
        depth: 2,
        bytes: 512,
    });
    assert_eq!(
        (shallow.status, shallow.len, shallow.bytes_read),
        (StackStatus::DepthLimit, 2, 16)
    );
    let short = three_layers(StackLimits {
        depth: 64,
        bytes: 16,
    });
    assert_eq!(
        (short.status, short.len, short.bytes_read),
        (StackStatus::ByteLimit, 2, 16)
    );
    let short = three_layers(StackLimits {
        depth: 64,
        bytes: 15,
    });
    assert_eq!(
        (short.status, short.len, short.bytes_read),
        (StackStatus::ByteLimit, 1, 0)
    );
    assert_eq!(
        three_layers(StackLimits {
            depth: 3,
            bytes: 32
        })
        .status,
        StackStatus::Complete
    );
}

#[test]
fn hard_depth_cap_and_zero_depth_do_not_touch_memory() {
    for depth in [0, 65, u16::MAX] {
        let stack = walk_frame_pointers(
            regs(),
            StackLimits { depth, bytes: 512 },
            |_| panic!("invalid configuration must not read"),
            executable,
        );
        assert_eq!(stack.status, StackStatus::InvalidLimit);
        assert_eq!(stack.len, 0);
    }
    let calls = Cell::new(0);
    let stack = walk_frame_pointers(
        regs(),
        StackLimits {
            depth: 64,
            bytes: u32::MAX,
        },
        |address| {
            calls.set(calls.get() + 1);
            Ok(frame(address + 48, 0x400200))
        },
        executable,
    );
    assert_eq!(
        (stack.status, stack.len, calls.get()),
        (StackStatus::DepthLimit, 64, 63)
    );
}

#[test]
fn null_unaligned_below_sp_and_overflowing_frames_stop_before_reading() {
    for (fp, sp, expected) in [
        (0, 0x1000, StackStatus::NoFramePointer),
        (0x1028, 0x1000, StackStatus::InvalidFrame),
        (0x1000, 0x1000, StackStatus::InvalidFrame),
        (0x1000, u64::MAX - 7, StackStatus::AddressOverflow),
    ] {
        let registers = StackRegisters { fp, sp, ..regs() };
        let stack = walk_frame_pointers(
            registers,
            StackLimits::default(),
            |_| panic!("invalid frame must not read"),
            executable,
        );
        assert_eq!(
            (stack.status, stack.len, stack.bytes_read),
            (expected, 1, 0)
        );
    }
}

#[test]
fn loops_and_backwards_chains_preserve_only_valid_prefix() {
    for previous in [0x1020, 0x1000] {
        let stack = walk_frame_pointers(
            regs(),
            StackLimits::default(),
            |_| Ok(frame(previous, 0x400200)),
            executable,
        );
        assert_eq!(stack.status, StackStatus::NonMonotonicFrame);
        assert_eq!(&stack.ips[..stack.len as usize], &[0x400100, 0x400200]);
    }
    let stack = walk_frame_pointers(
        regs(),
        StackLimits::default(),
        |_| Ok(frame(0x1038, 0x400200)),
        executable,
    );
    assert_eq!((stack.status, stack.len), (StackStatus::InvalidFrame, 2));
}

#[test]
fn read_failures_and_invalid_return_addresses_are_diagnostic() {
    for status in [
        StackStatus::ReadFault,
        StackStatus::Busy,
        StackStatus::Unavailable,
    ] {
        let stack =
            walk_frame_pointers(regs(), StackLimits::default(), |_| Err(status), executable);
        assert_eq!((stack.status, stack.len, stack.bytes_read), (status, 1, 0));
    }
    for ra in [0, 0x900000, 0x400201] {
        let stack = walk_frame_pointers(
            regs(),
            StackLimits::default(),
            |_| Ok(frame(0, ra)),
            executable,
        );
        assert_eq!(
            (stack.status, stack.len, stack.bytes_read),
            (StackStatus::InvalidReturnAddress, 1, 16)
        );
    }
    let stack = walk_frame_pointers(
        StackRegisters { ip: 3, ..regs() },
        StackLimits::default(),
        |_| panic!("invalid IP must not read"),
        executable,
    );
    assert_eq!(
        (stack.status, stack.len, stack.bytes_read),
        (StackStatus::InvalidInstructionPointer, 0, 0)
    );
}

fn context() -> PerfStackSampleContext {
    let base = PerfSampleContext {
        base: PerfEventContext::new(1000, 0, 20, 3, 7, 8, 9),
        ip: regs().ip,
        mode: 2,
        version: 2,
    };
    let mut stack = three_layers(StackLimits::default());
    stack.capture_ns = 5;
    PerfStackSampleContext {
        base,
        source_id: 17,
        stack,
    }
}

#[test]
fn stack_extension_preserves_old_context_and_roundtrips_exact_layout() {
    let sample = context();
    let bytes = sample.to_bytes();
    assert_eq!(bytes.len(), 640);
    assert_eq!(&bytes[..64], &sample.base.to_bytes());
    assert_eq!(u64::from_le_bytes(bytes[64..72].try_into().unwrap()), 17);
    assert_eq!(
        u64::from_le_bytes(bytes[72..80].try_into().unwrap()),
        0x1000
    );
    assert_eq!(
        u64::from_le_bytes(bytes[80..88].try_into().unwrap()),
        0x1020
    );
    assert_eq!(
        u64::from_le_bytes(bytes[88..96].try_into().unwrap()),
        0x400200
    );
    assert_eq!(u64::from_le_bytes(bytes[96..104].try_into().unwrap()), 5);
    assert_eq!(&bytes[104..112], &[3, 0, 32, 0, 3, 0, 0, 0]);
    assert_eq!(&bytes[120..128], &[0; 8]);
    assert_eq!(PerfStackSampleContext::from_bytes(&bytes), Ok(sample));
}

#[test]
fn strict_decoder_rejects_unknown_extensions_and_corrupt_chains() {
    let valid = context().to_bytes();
    for (offset, value) in [
        (36, 1),
        (60, 3),
        (64, 0),
        (104, 4),
        (106, 65),
        (108, 65),
        (110, 255),
        (112, 15),
        (120, 1),
        (128, 1),
        (152, 1),
    ] {
        let mut bytes = valid;
        bytes[offset] = value;
        assert!(
            PerfStackSampleContext::from_bytes(&bytes).is_err(),
            "offset {offset}"
        );
    }
    assert!(PerfStackSampleContext::from_bytes(&valid[..639]).is_err());
}

#[test]
fn unavailable_keeps_a_real_ip_without_claiming_a_caller() {
    let stack = FrozenStack::unavailable(regs(), StackStatus::Busy);
    assert_eq!(
        (stack.status, stack.len, stack.bytes_read),
        (StackStatus::Busy, 1, 0)
    );
    assert_eq!(stack.ips[0], regs().ip);
    assert_eq!(stack.status.classification(), "unavailable");
    assert_eq!(StackStatus::DepthLimit.classification(), "partial");
    assert_eq!(StackStatus::Complete.classification(), "complete");
    for code in 0..=13 {
        let status = StackStatus::from_u16(code).unwrap();
        assert_eq!(status as u16, code);
        assert!(!status.as_str().is_empty());
    }
    assert!(StackStatus::from_u16(14).is_none());
}

#[test]
fn multi_frame_cycle_cannot_revisit_memory() {
    let calls = Cell::new(0);
    let stack = walk_frame_pointers(
        regs(),
        StackLimits::default(),
        |address| {
            calls.set(calls.get() + 1);
            match address {
                0x1010 => Ok(frame(0x1040, 0x400200)),
                0x1030 => Ok(frame(0x1020, 0x400300)),
                _ => panic!("must stop at cycle"),
            }
        },
        executable,
    );
    assert_eq!(
        (stack.status, stack.len, calls.get()),
        (StackStatus::NonMonotonicFrame, 3, 2)
    );
}

#[test]
fn kernel_identity_and_each_capture_outcome_roundtrip() {
    let cases = [
        three_layers(StackLimits::default()),
        three_layers(StackLimits { depth: 1, bytes: 0 }),
        three_layers(StackLimits {
            depth: 32,
            bytes: 16,
        }),
        walk_frame_pointers(
            StackRegisters { fp: 0, ..regs() },
            StackLimits::default(),
            |_| panic!("no FP"),
            executable,
        ),
        walk_frame_pointers(
            regs(),
            StackLimits::default(),
            |_| Ok(frame(0, 0xdead)),
            executable,
        ),
        walk_frame_pointers(
            regs(),
            StackLimits::default(),
            |_| Err(StackStatus::ReadFault),
            executable,
        ),
        FrozenStack::unavailable(regs(), StackStatus::Busy),
    ];
    for stack in cases {
        let mut sample = context();
        sample.base.mode = 1;
        sample.base.base.pid = 0;
        sample.base.base.tid = 0;
        sample.stack = stack;
        assert_eq!(
            PerfStackSampleContext::from_bytes(&sample.to_bytes()),
            Ok(sample)
        );
    }
    let mut bytes = context().to_bytes();
    bytes[112..116].copy_from_slice(&48u32.to_le_bytes());
    assert!(PerfStackSampleContext::from_bytes(&bytes).is_err());
}
