//! Deterministic fixture generator for BPF capture files.

use alloc::string::String;
use alloc::vec::Vec;
use crate::framing::{CaptureArch, CaptureError, SessionStatusCode};
use crate::record::NormalizedRecord;
use crate::schema::SchemaRegistry;
use crate::session::{CaptureScope, SessionConfig};
use crate::writer::CaptureWriter;
use pulse_bpf_schema::{ContextCommon, SchedSwitchContext, TaskBlockContext, TracepointId};

/// Generate a deterministic, reproducible BPF capture binary for testing and analyzer validation.
pub fn generate_deterministic_fixture(
    arch: CaptureArch,
    status: SessionStatusCode,
) -> Result<Vec<u8>, CaptureError> {
    let config = SessionConfig {
        pulse_commit: String::from("49ad1424deadbeef0123456789abcdef01234567"),
        target_arch: arch,
        kernel_elf_path: String::from(if arch == CaptureArch::LoongArch64 {
            "PulseOS_loongarch64-qemu-virt.elf"
        } else {
            "PulseOS_riscv64-qemu-virt.elf"
        }),
        kernel_elf_hash: String::from("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        image_path: String::from(if arch == CaptureArch::LoongArch64 {
            "sdcard-la.img"
        } else {
            "sdcard-rv.img"
        }),
        image_hash: String::from("sha256:ca978112ca1bbdcafac231b39a23dc4da7860814965409b5416f65f356071a14"),
        libbpf_fixture_version: String::from("v1.0.0-pulse-fixture"),
        prog_id: 10,
        map_id: 20,
        link_id: 30,
        perf_event_id: 40,
        output_path: String::from("records/deterministic_capture.bin"),
        scope: CaptureScope::AllCpus,
        sample_period: 100_000,
        buffer_pages: 4,
        clock_name: String::from("monotonic"),
        clock_res_ns: 1,
    };

    let registry = SchemaRegistry::default_pulse_registry();
    let mut writer = CaptureWriter::new(config, registry);
    writer.start(1_000_000_000)?;

    // 1. Sched switch sample on CPU 0
    let sched = SchedSwitchContext {
        common: ContextCommon::new(TracepointId::SchedSwitch, 1_000_100_000, 0, 100, 100, 1),
        prev_task_id: 1,
        next_task_id: 2,
        prev_state: 0,
        prev_prio: 120,
        next_prio: 120,
        _pad: 0,
    };
    let rec1 = NormalizedRecord::from_tracepoint_slice(TracepointId::SchedSwitch as u32, unsafe {
        core::slice::from_raw_parts(&sched as *const _ as *const u8, core::mem::size_of_val(&sched))
    })?;
    writer.write_record(rec1)?;

    // 2. Task block sample on CPU 1
    let block = TaskBlockContext {
        common: ContextCommon::new(TracepointId::TaskBlock, 1_000_200_000, 1, 200, 200, 2),
        block_sequence: 1,
        wait_reason: 3,
        _pad: 0,
        resource_id: 42,
        resource_detail: 100,
    };
    let rec2 = NormalizedRecord::from_tracepoint_slice(TracepointId::TaskBlock as u32, unsafe {
        core::slice::from_raw_parts(&block as *const _ as *const u8, core::mem::size_of_val(&block))
    })?;
    writer.write_record(rec2)?;

    // Apply loss or error if requested
    match status {
        SessionStatusCode::IncompleteLoss => {
            writer.ingest_perf_lost(0, 5);
            writer.ingest_perf_lost(1, 2);
        }
        SessionStatusCode::IncompleteError => {
            writer.ingest_perf_lost(0, 1);
            // Trigger consumer corruption error
            let _ = writer.ingest_perf_sample(0, &[]);
        }
        _ => {}
    }

    writer.finish(2_000_000_000)
}
