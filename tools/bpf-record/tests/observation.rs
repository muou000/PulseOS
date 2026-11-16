use bpf_record::observation::Observation;
use sha2::{Digest, Sha256};

fn journal(cut: u64, extra: &str) -> String {
    let records = 1 + extra.lines().count();
    format!(
        "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns={cut} dropped=0 \
         records={records}\nKERNEL seq=1 ts=1 start=4096 len=4096 reference=4096 \
         symbol_hex=5f7374657874 build_id=unknown\n{extra}END records={records} dropped=0 \
         snapshot_ns={cut}\n"
    )
}

#[test]
fn failed_final_journal_retains_initial_facts_and_explicit_partial_boundary() {
    let initial = journal(10, "");
    let observer = Observation::begin(initial.clone(), None).unwrap();
    let result = observer.finish(Err("read failure".into()));
    assert_eq!(result.mappings.journal, initial);
    assert_eq!(result.errors, ["read failure"]);
    assert!(
        result
            .diagnostics
            .counters
            .iter()
            .any(|counter| counter.name == "mapping_final_snapshot_ns" && counter.value.is_none())
    );
    assert!(result.mappings.kernel.is_none());
    result.mappings.validate().unwrap();
}

fn kernel_elf() -> Vec<u8> {
    let mut bytes = vec![0; 512];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[52..54].copy_from_slice(&64u16.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&4u32.to_le_bytes());
    bytes[72..80].copy_from_slice(&256u64.to_le_bytes());
    bytes[96..104].copy_from_slice(&20u64.to_le_bytes());
    bytes[256..260].copy_from_slice(&4u32.to_le_bytes());
    bytes[260..264].copy_from_slice(&4u32.to_le_bytes());
    bytes[264..268].copy_from_slice(&3u32.to_le_bytes());
    bytes[268..272].copy_from_slice(b"GNU\0");
    bytes[272..276].copy_from_slice(&[1, 2, 3, 4]);
    bytes
}

#[test]
fn kernel_candidate_requires_boot_build_id_and_records_full_file_sha() {
    let initial = journal(10, "").replace("build_id=unknown", "build_id=01020304");
    let bytes = kernel_elf();
    let observer = Observation::begin(initial.clone(), Some(&bytes)).unwrap();
    assert_eq!(observer.kernel_build_id(), Some("01020304"));
    assert_eq!(
        observer.kernel_sha256(),
        Some(format!("{:x}", Sha256::digest(&bytes)).as_str())
    );
    let result = observer.finish(Ok(initial));
    assert!(result.errors.is_empty());
    assert_eq!(
        result.mappings.artifacts[0].gnu_build_id.as_deref(),
        Some("01020304")
    );
    result.mappings.validate().unwrap();
}

#[test]
fn final_protected_object_identity_needs_no_reopen_by_path() {
    let sha = "ab".repeat(32);
    let initial = journal(10, "");
    let final_journal = journal(
        20,
        &format!(
            "OBJECT seq=2 ts=12 object=1 sha256={sha} build_id=none \
             path_hex=2f72656e616d6564\nOBJECT seq=3 ts=13 object=2 sha256=unknown \
             build_id=unknown path_hex=2f6d757461626c65\n"
        ),
    );
    let result = Observation::begin(initial, None)
        .unwrap()
        .finish(Ok(final_journal.clone()));
    assert_eq!(result.mappings.journal, final_journal);
    assert_eq!(result.mappings.artifacts.len(), 1);
    assert_eq!(result.mappings.artifacts[0].sha256, sha);
    assert_eq!(result.mappings.artifacts[0].gnu_build_id, None);
    result.mappings.validate().unwrap();
}

#[test]
fn wrong_kernel_candidate_and_missing_snapshot_boundary_fail_before_enable() {
    let initial = journal(10, "").replace("build_id=unknown", "build_id=01020304");
    let mut wrong = kernel_elf();
    wrong[272] = 9;
    assert!(Observation::begin(initial.clone(), Some(&wrong)).is_err());
    assert!(Observation::begin(journal(10, ""), Some(&kernel_elf())).is_err());
    let incomplete = initial.split("END ").next().unwrap().to_owned();
    assert!(Observation::begin(incomplete, None).is_err());
}

#[test]
fn changed_final_history_cannot_replace_frozen_initial_facts() {
    let initial = journal(10, "");
    let final_journal = journal(20, "").replace("start=4096", "start=8192");
    let result = Observation::begin(initial.clone(), None)
        .unwrap()
        .finish(Ok(final_journal));
    assert_eq!(result.mappings.journal, initial);
    assert!(!result.errors.is_empty());
    assert!(
        result
            .diagnostics
            .counters
            .iter()
            .any(|counter| counter.name == "mapping_final_snapshot_ns" && counter.value.is_none())
    );
}

#[test]
fn journal_exhaustion_stays_loss_even_when_a_final_cut_exists() {
    let initial = journal(10, "");
    let final_journal = journal(20, "").replace("dropped=0", "dropped=7");
    let result = Observation::begin(initial, None)
        .unwrap()
        .finish(Ok(final_journal));
    assert!(result.errors.is_empty());
    assert!(
        result
            .diagnostics
            .counters
            .iter()
            .any(|counter| counter.name == "mapping_journal_dropped"
                && counter.value == Some(7)
                && counter.kind == bpf_capture::CounterKind::Loss)
    );
    assert!(result.diagnostics.counters.iter().any(|counter|
        counter.name == "mapping_final_snapshot_ns" && counter.value == Some(20)));
}

#[test]
fn invalid_mapping_semantics_are_rejected_before_sources_can_enable() {
    let invalid = "PULSE_BPF_MAPPINGS version=2 available=1 started_ns=0 snapshot_ns=10 dropped=0 \
                   records=1\nSPACE seq=1 ts=1 begin_ns=1 space=1 revision=1 count=1\nMAP \
                   start=4096 len=4096 pgoff=0 perms=16 object=0\nENDSPACE\nEND records=1 \
                   dropped=0 snapshot_ns=10\n";
    assert!(Observation::begin(invalid.into(), None).is_err());
    let initial = journal(10, "");
    let result = Observation::begin(initial.clone(), None)
        .unwrap()
        .finish(Ok(invalid.into()));
    assert_eq!(result.mappings.journal, initial);
    assert_eq!(result.errors.len(), 1);
}

#[test]
fn accepted_journal_whitespace_keeps_raw_boundaries_and_artifact_identity() {
    let sha = "ab".repeat(32);
    for newline in ["\n", "\r\n"] {
        for terminated in [false, true] {
            let style = |text: String| {
                let mut text = text.replace(' ', "\t").replace('\n', newline);
                if !terminated {
                    text.truncate(text.len() - newline.len());
                }
                text
            };
            let initial = style(journal(10, ""));
            let final_journal = style(journal(
                20,
                &format!(
                    "OBJECT seq=2 ts=12 object=1 sha256={sha} build_id=none \
                     path_hex=2f746172676574\n"
                ),
            ));
            let result = Observation::begin(initial, None)
                .unwrap()
                .finish(Ok(final_journal.clone()));
            assert!(result.errors.is_empty(), "{:?}", result.errors);
            assert_eq!(result.mappings.journal, final_journal);
            assert_eq!(result.mappings.artifacts[0].sha256, sha);

            let initial = style(journal(10, "").replace("build_id=unknown", "build_id=01020304"));
            assert_eq!(
                Observation::begin(initial, Some(&kernel_elf()))
                    .unwrap()
                    .kernel_build_id(),
                Some("01020304")
            );
        }
    }
}
