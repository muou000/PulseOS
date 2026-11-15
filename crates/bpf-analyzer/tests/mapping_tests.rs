use bpf_analyzer::mapping::MappingTimeline;
use bpf_capture::mapping::MappingMetadata;
fn metadata(rows: &str, dropped: u64) -> MappingMetadata {
    let count = rows
        .lines()
        .filter(|l| {
            l.starts_with("SPACE ")
                || l.starts_with("TASK ")
                || l.starts_with("OBJECT ")
                || l.starts_with("TLB ")
                || l.starts_with("MUTATION ")
        })
        .count();
    MappingMetadata {
        journal: format!(
            "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=1000 \
             dropped={dropped} records={count}\n{rows}END records={count} dropped={dropped} \
             snapshot_ns=1000\n"
        ),
        artifacts: vec![],
        kernel: None,
    }
}
fn object() -> String {
    format!(
        "OBJECT seq=1 ts=1 object=9 sha256={} path_hex=2f6f6c64\n",
        "a".repeat(64)
    )
}
fn space(
    seq: u64,
    time: u64,
    begin: u64,
    id: u64,
    revision: u64,
    start: u64,
    pgoff: u64,
) -> String {
    format!(
        "SPACE seq={seq} ts={time} begin_ns={begin} space={id} revision={revision} count=1\nMAP \
         start={start} len=4096 pgoff={pgoff} perms=5 object=9\nENDSPACE\n"
    )
}
fn task(seq: u64, time: u64, id: u64, pid: u32, space: u64, generation: u64, kind: &str) -> String {
    format!(
        "TASK seq={seq} ts={time} task={id} pid={pid} tid={pid} space={space} exec={generation} \
         kind={kind} parent=0 class=user comm_hex=6f6c64\n"
    )
}
fn initial() -> String {
    object() + &space(2, 10, 2, 100, 1, 4096, 8192) + &task(3, 20, 1, 5, 100, 0, "bind")
}
fn lookup(rows: &str, time: u64) -> Result<bpf_analyzer::mapping::ResolvedMapping, &'static str> {
    MappingTimeline::new(&metadata(rows, 0))
        .unwrap()
        .lookup(1, 5, 5, time, 4100)
}
#[test]
fn byte_offset_and_snapshot_lifetime() {
    let rows = initial() + &space(4, 100, 80, 100, 2, 8192, 4096);
    assert_eq!(lookup(&rows, 50).unwrap().file_offset, 8196);
    assert!(lookup(&rows, 90).is_err());
    assert!(lookup(&rows, 100).is_err());
    assert!(lookup(&rows, 101).is_err());
    assert!(lookup(&rows, 10).is_err());
    assert!(lookup(&rows, 1000).is_err());
}
#[test]
fn pid_tid_reuse_cannot_inherit_old_space() {
    let rows =
        initial() + &task(4, 100, 1, 5, 100, 0, "exit") + &task(5, 110, 2, 5, 200, 0, "bind");
    let t = MappingTimeline::new(&metadata(&rows, 0)).unwrap();
    assert!(t.lookup(2, 5, 5, 120, 4100).is_err());
    assert!(t.lookup(1, 5, 5, 120, 4100).is_err());
    assert!(t.lookup(1, 6, 6, 50, 4100).is_err());
}
#[test]
fn exec_replaces_space_and_generation_and_rename_is_temporal() {
    let rows = initial()
        + &space(4, 90, 80, 200, 1, 8192, 0)
        + &task(5, 100, 1, 5, 200, 1, "exec")
            .replace("comm_hex=6f6c64", "begin_ns=85 comm_hex=6e6577")
        + &task(6, 200, 1, 5, 200, 1, "rename")
            .replace("comm_hex=6f6c64", "comm_hex=72656e616d6564");
    let t = MappingTimeline::new(&metadata(&rows, 0)).unwrap();
    assert_eq!(t.lookup(1, 5, 5, 50, 4100).unwrap().comm, "old");
    assert!(t.lookup(1, 5, 5, 87, 4100).is_err());
    assert!(t.lookup(1, 5, 5, 101, 4100).is_err());
    let m = t.lookup(1, 5, 5, 101, 8192).unwrap();
    assert_eq!((m.space, m.exec, m.comm.as_str()), (200, 1, "new"));
    assert_eq!(t.lookup(1, 5, 5, 201, 8192).unwrap().comm, "renamed");
}
#[test]
fn fork_requires_explicit_child_snapshot_but_clone_vm_can_share() {
    let rows = initial()
        + &space(4, 30, 21, 200, 1, 4096, 8192)
        + &task(5, 40, 2, 6, 200, 0, "fork")
        + &task(6, 50, 3, 7, 100, 0, "bind")
        + &space(7, 100, 80, 100, 2, 8192, 0);
    let t = MappingTimeline::new(&metadata(&rows, 0)).unwrap();
    assert_eq!(t.lookup(2, 6, 6, 110, 4100).unwrap().space, 200);
    assert!(t.lookup(3, 7, 7, 110, 4100).is_err());
    assert!(t.lookup(2, 6, 6, 40, 4100).is_err());
}
#[test]
fn journal_loss_and_open_tlb_never_claim_a_mapping() {
    let rows = initial() + "TLB seq=4 ts=30 space=100 token=9 complete=0\n";
    let t = MappingTimeline::new(&metadata(&rows, 0)).unwrap();
    assert!(t.lookup(1, 5, 5, 50, 4100).unwrap_err().contains("TLB"));
    assert!(
        MappingTimeline::new(&metadata(&initial(), 1))
            .unwrap()
            .lookup(1, 5, 5, 50, 4100)
            .unwrap_err()
            .contains("loss")
    );
    let rows = rows + "TLB seq=5 ts=60 space=100 token=9 complete=1\n";
    assert!(lookup(&rows, 50).is_err());
    assert!(lookup(&rows, 61).is_ok());
}
#[test]
fn duplicate_stable_identity_and_snapshot_revision_fail_closed() {
    let rows = initial() + &task(4, 30, 1, 5, 200, 0, "bind");
    assert!(lookup(&rows, 50).is_err());
    let rows = initial() + &space(4, 30, 21, 100, 1, 4096, 8192);
    assert!(lookup(&rows, 50).is_err());
    let rows = initial() + &task(4, 30, 1, 5, 200, 1, "rename");
    assert!(lookup(&rows, 50).is_err());
}
#[test]
fn nonleader_exec_changes_tid_but_retains_stable_task_identity() {
    let rows = initial().replace("tid=5", "tid=8")
        + &space(4, 90, 80, 200, 1, 8192, 0)
        + &task(5, 100, 1, 5, 200, 1, "exec");
    let t = MappingTimeline::new(&metadata(&rows, 0)).unwrap();
    assert!(t.lookup(1, 5, 8, 50, 4100).is_ok());
    assert_eq!(t.lookup(1, 5, 5, 101, 8192).unwrap().exec, 1);
    assert!(t.lookup(1, 5, 8, 101, 8192).is_err());
}

#[test]
fn tlb_token_reuse_after_completion_fails_closed() {
    let rows = initial()
        + "TLB seq=4 ts=30 space=100 token=9 complete=0\nTLB seq=5 ts=40 space=100 token=9 \
           complete=1\nTLB seq=6 ts=50 space=100 token=9 complete=0\nTLB seq=7 ts=60 space=100 \
           token=9 complete=1\n";
    assert!(lookup(&rows, 70).unwrap_err().contains("duplicate TLB"));
}

#[test]
fn cut_during_space_or_task_mutation_never_uses_previous_snapshot() {
    for (target, id) in [("space", 100), ("task", 1)] {
        let rows = initial()
            + &format!("MUTATION seq=4 ts=30 target={target} id={id} token=7 complete=0\n");
        assert!(lookup(&rows, 29).is_ok());
        assert!(lookup(&rows, 30).unwrap_err().contains("mutation"));
        assert!(
            lookup(&rows, 999)
                .unwrap_err()
                .contains("incomplete at journal cut")
        );
        let rows =
            rows + &format!("MUTATION seq=5 ts=100 target={target} id={id} token=7 complete=1\n");
        assert!(lookup(&rows, 50).is_err());
        assert!(lookup(&rows, 100).is_err());
        assert!(lookup(&rows, 101).is_ok());
    }
}
#[test]
fn unrelated_mutation_cannot_poison_an_independent_address_space() {
    let rows = initial()
        + "MUTATION seq=4 ts=30 target=space id=200 token=7 complete=0\nMUTATION seq=5 ts=31 \
           target=task id=2 token=8 complete=0\n";
    assert!(lookup(&rows, 50).is_ok());
}
