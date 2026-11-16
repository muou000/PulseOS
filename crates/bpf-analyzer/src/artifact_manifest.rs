//! Read-only collection manifest from the authoritative capture, never a host inventory.
use bpf_capture::mapping::{MappingEvent, MappingJournal};

use crate::{CaptureAnalyzer, emission::json_string as quote};

pub fn render(analyzer: &CaptureAnalyzer, capture: &[u8]) -> String {
    let metadata = analyzer.data().mappings.as_ref();
    let journal = metadata.and_then(|value| MappingJournal::parse(&value.journal).ok());
    let optional = |value: Option<&str>| value.map(quote).unwrap_or_else(|| "null".into());
    let artifacts = metadata.map_or_else(Vec::new, |value| {
        value
            .artifacts
            .iter()
            .map(|item| {
                format!(
                    "{{\"sha256\":{},\"gnu_build_id\":{},\"path\":{},\"debug_sha256\":{},\"\
                     debug_build_id\":{}}}",
                    quote(&item.sha256),
                    optional(item.gnu_build_id.as_deref()),
                    quote(&item.path),
                    optional(item.debug_sha256.as_deref()),
                    optional(item.debug_build_id.as_deref())
                )
            })
            .collect::<Vec<_>>()
    });
    let objects = journal.as_ref().map_or_else(Vec::new, |value| {
        value
            .entries
            .iter()
            .filter_map(|entry| {
                if let MappingEvent::Object {
                    object,
                    sha256,
                    path,
                } = &entry.event
                {
                    Some(format!(
                        "{{\"object\":{object},\"sha256\":{},\"path_label\":{}}}",
                        optional(sha256.as_deref()),
                        quote(path)
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>()
    });
    let kernel = metadata
        .and_then(|value| value.kernel.as_ref())
        .map_or_else(
            || "null".into(),
            |value| {
                format!(
                    "{{\"sha256\":{},\"reference_symbol\":{},\"reference_address\":{},\"\
                     text_start\":{},\"text_end\":{}}}",
                    quote(&value.sha256),
                    quote(&value.reference_symbol),
                    value.reference_address,
                    value.text_start,
                    value.text_end
                )
            },
        );
    let coverage = journal.map_or_else(
        || "null".into(),
        |value| {
            format!(
                "{{\"started_ns\":{},\"snapshot_ns\":{},\"dropped\":{},\"records\":{}}}",
                value.started_ns,
                value.snapshot_ns,
                value.dropped,
                value.entries.len()
            )
        },
    );
    format!(
        "{{\"capture_sha256\":{},\"arch\":{},\"mapping_metadata\":{},\"coverage\":{},\"kernel\":\
         {},\"artifacts\":[{}],\"objects\":[{}],\"journal\":{}}}",
        quote(&crate::artifact::sha256(capture)),
        quote(analyzer.target_arch().as_str()),
        metadata.is_some(),
        coverage,
        kernel,
        artifacts.join(","),
        objects.join(","),
        optional(metadata.map(|value| value.journal.as_str()))
    )
}
