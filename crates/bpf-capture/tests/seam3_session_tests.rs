use bpf_capture::framing::{CaptureArch, SessionStatusCode};
use bpf_capture::session::{
    CaptureScope, LayeredLossCounters, SamplingSession, SessionConfig, SessionMetadata,
};

fn sample_config() -> SessionConfig {
    SessionConfig {
        pulse_commit: String::from("49ad1424deadbeef1234567890abcdef12345678"),
        target_arch: CaptureArch::Riscv64,
        kernel_elf_path: String::from("PulseOS_riscv64-qemu-virt.elf"),
        kernel_elf_hash: String::from("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        image_path: String::from("sdcard-rv.img"),
        image_hash: String::from("sha256:ca978112ca1bbdcafac231b39a23dc4da7860814965409b5416f65f356071a14"),
        libbpf_fixture_version: String::from("v1.0.0-pulse-fixture"),
        prog_id: 10,
        map_id: 20,
        link_id: 30,
        perf_event_id: 40,
        output_path: String::from("/tmp/bpf_capture.bin"),
        scope: CaptureScope::AllCpus,
        sample_period: 100_000,
        buffer_pages: 4,
        clock_name: String::from("monotonic"),
        clock_res_ns: 1,
    }
}

#[test]
fn test_layered_counters_accounting_and_loss_detection() {
    let mut counters = LayeredLossCounters::new();
    assert_eq!(counters.has_loss_or_error(), false);
    assert_eq!(counters.total_loss_and_error(), 0);

    counters.attempted += 100;
    counters.delivered += 90;
    counters.record_per_cpu_lost(0, 5);
    counters.record_per_cpu_lost(1, 3);
    counters.re_entry_drops += 1;
    counters.helper_failures += 1;

    assert_eq!(counters.lost_records_total, 8);
    assert_eq!(counters.get_cpu_lost(0), 5);
    assert_eq!(counters.get_cpu_lost(1), 3);
    assert_eq!(counters.get_cpu_lost(2), 0);
    assert_eq!(counters.has_loss(), true);
    assert_eq!(counters.has_error(), true);
    assert_eq!(counters.has_loss_or_error(), true);
    assert_eq!(counters.total_loss_and_error(), 10);
}

#[test]
fn test_layered_counters_serialization_round_trip() {
    let mut counters = LayeredLossCounters::new();
    counters.attempted = 1000;
    counters.delivered = 950;
    counters.record_per_cpu_lost(2, 40);
    counters.record_per_cpu_lost(3, 10);
    counters.ringbuf_lost = 5;
    counters.discarded_records = 3;
    counters.re_entry_drops = 2;
    counters.helper_failures = 1;
    counters.budget_failures = 4;
    counters.verifier_failures = 0;
    counters.load_failures = 0;
    counters.attach_failures = 0;
    counters.consumer_corrupt_records = 0;
    counters.consumer_out_of_bounds = 1;

    let bytes = counters.to_bytes();
    let (restored, consumed) =
        LayeredLossCounters::from_bytes(&bytes).expect("counters deserialization should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(restored, counters);
}

#[test]
fn test_session_metadata_serialization_round_trip() {
    let meta = SessionMetadata {
        config: sample_config(),
        start_ns: 1_000_000,
        stop_ns: 5_000_000,
        status: SessionStatusCode::Complete,
        counters: LayeredLossCounters::new(),
    };

    let bytes = meta.to_bytes();
    let (restored, consumed) =
        SessionMetadata::from_bytes(&bytes).expect("session metadata deserialization should succeed");
    assert_eq!(consumed, bytes.len());
    assert_eq!(restored, meta);
}

#[test]
fn test_sampling_session_lifecycle() {
    let mut config = sample_config();
    config.target_arch = CaptureArch::LoongArch64;
    config.scope = CaptureScope::PerCpu(1);
    config.sample_period = 50_000;
    config.buffer_pages = 2;

    let mut session = SamplingSession::new(config);
    assert_eq!(session.is_running(), false);
    assert_eq!(session.is_finished(), false);

    // Start
    session.start(10_000).expect("session start should succeed");
    assert_eq!(session.is_running(), true);

    // Cannot start again while running
    assert!(session.start(11_000).is_err());

    // Record sample and loss
    session.record_sample_delivered();
    session.record_perf_lost(1, 2);

    // Stop
    let final_meta = session.stop(20_000).expect("session stop should succeed");
    assert_eq!(session.is_running(), false);
    assert_eq!(session.is_finished(), true);
    assert_eq!(final_meta.start_ns, 10_000);
    assert_eq!(final_meta.stop_ns, 20_000);

    // Incomplete status preserved because of loss!
    assert_eq!(final_meta.status, SessionStatusCode::IncompleteLoss);
    assert_eq!(final_meta.counters.get_cpu_lost(1), 2);
}
